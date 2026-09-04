//! Execute an approved proposal.
//!
//! A proposal that targets another program is invoked with the vault PDA as
//! signer, one inner instruction at a time, in message order. One that targets
//! this program is a config action, applied in place rather than through a CPI
//! back into ourselves.
//!
//! Staleness is deliberately not checked: a proposal that reached `Approved`
//! before the owner set changed stays executable, because it was approved under
//! the rules in force at the time.
//!
//! # Accounts
//!
//! 0. `executor`    - signer, must be an owner of `multisig`; writable, since
//!    a config action that closes the multisig pays its rent here
//! 1. `multisig`    - the configuration this proposal belongs to; writable when
//!    the proposal is a config action
//! 2. `transaction` - writable, the proposal being executed
//! 3. `remaining`   - and onward: the message's static account keys in order,
//!    then every lookup table's writable addresses, then every lookup table's
//!    readonly addresses, then the lookup table accounts themselves

use pinocchio::{
    AccountView, Address, ProgramResult,
    cpi::{Seed, Signer, invoke_signed_with_bounds},
    instruction::{InstructionAccount, InstructionView},
    sysvars::{Sysvar, clock::Clock},
};

use crate::{
    constants::{
        ADDRESS_LOOKUP_TABLE_ID, EPHEMERAL_SEED, LOOKUP_TABLE_DEACTIVATION_OFFSET,
        LOOKUP_TABLE_META_SIZE, MAX_CPI_ACCOUNTS, MAX_EPHEMERAL_SIGNERS, VAULT_SEED,
    },
    error::MultisigError,
    helper::{check_owner, check_signer, validate_eq},
    instruction::config_action::apply_config_action,
    state::{
        message::TransactionMessage,
        multisig::Multisig,
        permission::Permission,
        transaction::{Transaction, TransactionStatus},
    },
};

/// Invokes every instruction in the proposal's message, signed by its vault.
pub fn process_execute(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction: &[u8],
) -> ProgramResult {
    let [executor, multisig, transaction, remaining @ ..] = accounts else {
        return Err(MultisigError::NotEnoughAccounts.into());
    };

    if !instruction.is_empty() {
        return Err(MultisigError::InvalidInstructionData.into());
    }

    check_signer(executor, MultisigError::MissingSignature.into())?;
    check_owner(multisig, program_id, MultisigError::IllegalOwner.into())?;
    check_owner(transaction, program_id, MultisigError::IllegalOwner.into())?;

    let time_lock = {
        // SAFETY: read-only borrow, released with this scope.
        let multisig_data = unsafe { multisig.borrow_unchecked() };
        let ms = Multisig::load(multisig_data)?;

        if ms.is_owner(executor.address()).is_none() {
            return Err(MultisigError::NotAnOwner.into());
        }

        if !ms.has_permission(executor.address(), Permission::EXECUTE) {
            return Err(MultisigError::Unauthorized.into());
        }

        ms.time_lock
    };

    let vault_index: u8;
    let vault_bump: u8;
    let ephemeral_count: usize;
    let ephemeral_bumps: [u8; MAX_EPHEMERAL_SIGNERS];

    {
        // SAFETY: the multisig borrow ended with the scope above, so this is
        // the only live borrow.
        let transaction_data = unsafe { transaction.borrow_unchecked_mut() };
        let (state, _) = Transaction::load_mut(transaction_data)?;

        validate_eq(
            &state.multisig,
            multisig.address(),
            MultisigError::MultisigMismatch.into(),
        )?;

        if state.status()? != TransactionStatus::Approved {
            return Err(MultisigError::InvalidStatus.into());
        }

        // The delay gives honest owners a window to cancel a proposal that
        // was approved but should not run.
        if time_lock > 0 {
            let elapsed = Clock::get()?
                .unix_timestamp
                .checked_sub(state.approved_at)
                .ok_or(MultisigError::Overflow)?;

            if elapsed < i64::from(time_lock) {
                return Err(MultisigError::TimeLockNotReleased.into());
            }
        }

        vault_index = state.vault_index;
        vault_bump = state.vault_bump;
        ephemeral_count = state.ephemeral_count as usize;
        ephemeral_bumps = state.ephemeral_bumps;

        // Effects before interactions. A callee can invoke this program again,
        // and a proposal still marked `Approved` would execute twice.
        state.status = TransactionStatus::Executed as u8;
        state.invariant()?;
    }

    // Read the message in place rather than copying it to the stack: at
    // `MAX_MESSAGE_SIZE` a copy alone would overflow the 4 KB frame. The
    // borrow is safe to hold across the CPIs below because `transaction` is
    // never one of the accounts passed to them.
    let transaction_data = unsafe { transaction.borrow_unchecked() };
    let (_, stored_message) = Transaction::load(transaction_data)?;

    let message = TransactionMessage::parse(stored_message)?;

    let num_static = message.header.num_account_keys as usize;
    let num_all = message.num_all_keys();

    if remaining.len() < num_all {
        return Err(MultisigError::NotEnoughAccounts.into());
    }

    let views: &[AccountView] = remaining;

    // The owners approved these keys in this order. Without this an executor
    // could substitute accounts and spend the approvals on something else.
    for (i, key) in message.account_keys.iter().enumerate() {
        if views[i].address() != key {
            return Err(MultisigError::AccountMismatch.into());
        }
    }

    // Keys past the static ones come from lookup tables. Resolve them here
    // rather than trusting the runtime: the approved message names a table and
    // a set of indexes, and only the addresses those indexes actually hold may
    // take part.
    let num_lookups = message.header.num_lookups as usize;

    if remaining.len() < num_all + num_lookups {
        return Err(MultisigError::NotEnoughAccounts.into());
    }

    let mut writable_at = num_static;
    let mut readonly_at = num_static + message.num_writable_lookup_keys();

    for (i, lookup) in message.lookups().enumerate() {
        let lookup = lookup?;
        let table = &views[num_all + i];

        validate_eq(
            table.address(),
            lookup.account_key,
            MultisigError::AccountMismatch.into(),
        )?;

        validate_eq(
            table.owner(),
            &ADDRESS_LOOKUP_TABLE_ID,
            MultisigError::IllegalOwner.into(),
        )?;

        // SAFETY: read-only borrow of a lookup table, which is never one of the
        // accounts passed to the CPIs below.
        let table_data = unsafe { table.borrow_unchecked() };

        if table_data.len() < LOOKUP_TABLE_META_SIZE {
            return Err(MultisigError::InvalidLookupTable.into());
        }

        // An active table has no deactivation slot. The runtime refuses to load
        // a deactivated one when building the transaction, so this only ever
        // fires on a table deactivated in the same slot, but it costs nothing
        // to not depend on that.
        let deactivation =
            &table_data[LOOKUP_TABLE_DEACTIVATION_OFFSET..LOOKUP_TABLE_DEACTIVATION_OFFSET + 8];

        if u64::from_le_bytes(deactivation.try_into().unwrap()) != u64::MAX {
            return Err(MultisigError::InvalidLookupTable.into());
        }

        let addresses = &table_data[LOOKUP_TABLE_META_SIZE..];
        let num_addresses = addresses.len() / 32;

        for (indexes, cursor) in [
            (lookup.writable_indexes, &mut writable_at),
            (lookup.readonly_indexes, &mut readonly_at),
        ] {
            for index in indexes {
                let index = *index as usize;

                if index >= num_addresses {
                    return Err(MultisigError::InvalidLookupTable.into());
                }

                let expected = &addresses[index * 32..index * 32 + 32];

                if views[*cursor].address().as_array() != expected {
                    return Err(MultisigError::AccountMismatch.into());
                }

                *cursor += 1;
            }
        }
    }

    let index_byte = [vault_index];
    let bump_byte = [vault_bump];

    // Copied so the seeds hold no borrow of `multisig`, which a config action
    // in the loop below needs mutably.
    let multisig_key = *multisig.address();

    let vault_seeds = [
        Seed::from(VAULT_SEED),
        Seed::from(multisig_key.as_array()),
        Seed::from(&index_byte),
        Seed::from(&bump_byte),
    ];

    // Some instructions need a signature from something that is not the vault,
    // most often a newly created account. Those signers are PDAs of this
    // proposal, so only this proposal can produce them.
    let transaction_key = *transaction.address();

    let ephemeral_index: [[u8; 1]; MAX_EPHEMERAL_SIGNERS] = core::array::from_fn(|i| [i as u8]);
    let ephemeral_bump: [[u8; 1]; MAX_EPHEMERAL_SIGNERS] =
        core::array::from_fn(|i| [ephemeral_bumps[i]]);

    let ephemeral_seeds: [[Seed; 4]; MAX_EPHEMERAL_SIGNERS] = core::array::from_fn(|i| {
        [
            Seed::from(EPHEMERAL_SEED),
            Seed::from(transaction_key.as_array()),
            Seed::from(&ephemeral_index[i]),
            Seed::from(&ephemeral_bump[i]),
        ]
    });

    let signers: [Signer; 1 + MAX_EPHEMERAL_SIGNERS] = core::array::from_fn(|i| {
        if i == 0 {
            Signer::from(&vault_seeds[..])
        } else {
            Signer::from(&ephemeral_seeds[i - 1][..])
        }
    });

    let signers = &signers[..1 + ephemeral_count];

    for compiled in message.instructions() {
        let compiled = compiled?;

        let program_index = compiled.program_id_index as usize;
        let account_count = compiled.account_indexes.len();

        if account_count > MAX_CPI_ACCOUNTS {
            return Err(MultisigError::TooManyAccounts.into());
        }

        // A config action is applied in place; invoking ourselves would only
        // re-enter this handler.
        if views[program_index].address() == program_id {
            apply_config_action(multisig, executor, compiled.data)?;
            continue;
        }

        // Entries past `account_count` are never read; they only need a valid
        // value so the arrays can be built.
        let metas: [InstructionAccount; MAX_CPI_ACCOUNTS] = core::array::from_fn(|i| {
            let key_index = if i < account_count {
                compiled.account_indexes[i] as usize
            } else {
                0
            };

            InstructionAccount::new(
                views[key_index].address(),
                message.is_writable(key_index),
                message.is_signer(key_index),
            )
        });

        let cpi_views: [&AccountView; MAX_CPI_ACCOUNTS] = core::array::from_fn(|i| {
            let key_index = if i < account_count {
                compiled.account_indexes[i] as usize
            } else {
                0
            };

            &views[key_index]
        });

        let ix = InstructionView {
            program_id: views[program_index].address(),
            data: compiled.data,
            accounts: &metas[..account_count],
        };

        invoke_signed_with_bounds::<MAX_CPI_ACCOUNTS, &AccountView>(
            &ix,
            &cpi_views[..account_count],
            signers,
        )?;
    }

    Ok(())
}
