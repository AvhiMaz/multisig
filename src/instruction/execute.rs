//! Execute an approved proposal.
//!
//! A proposal that targets another program is invoked with the vault PDA as
//! signer. One that targets this program is a config action, applied in place
//! rather than through a CPI back into ourselves.
//!
//! Staleness is deliberately not checked: a proposal that reached `Approved`
//! before the owner set changed stays executable, because it was approved under
//! the rules in force at the time.
//!
//! # Accounts
//!
//! 0. `executor`    - signer, must be an owner of `multisig`
//! 1. `multisig`    - the configuration this proposal belongs to; writable when
//!    the proposal is a config action
//! 2. `transaction` - writable, the proposal being executed
//! 3. `remaining`   - and onward: exactly the accounts recorded in the
//!    proposal, in the same order. Empty for a config action.

use pinocchio::{
    AccountView, Address, ProgramResult,
    cpi::{Seed, Signer, invoke_signed_with_bounds},
    instruction::{InstructionAccount, InstructionView},
    sysvars::{Sysvar, clock::Clock},
};

use crate::{
    constants::{MAX_IX_ACCOUNTS, MAX_IX_DATA, VAULT_SEED},
    error::MultisigError,
    helper::{check_owner, check_signer, validate_eq},
    instruction::config_action::apply_config_action,
    state::{
        multisig::Multisig,
        transaction::{Transaction, TransactionStatus},
    },
};

/// Invokes the proposal's stored instruction, signed by its vault.
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

        ms.time_lock
    };

    let self_target: bool;
    let target_program: Address;
    let vault_index: u8;
    let vault_bump: u8;
    let account_count: usize;
    let ix_data_len: usize;
    let mut ix_data = [0u8; MAX_IX_DATA];
    let mut flags = [(false, false); MAX_IX_ACCOUNTS];

    {
        // SAFETY: the multisig borrow ended with the scope above, so this is
        // the only live borrow.
        let transaction_data = unsafe { transaction.borrow_unchecked_mut() };
        let state = Transaction::load_mut(transaction_data)?;

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

        // A proposal that targets this program is a config action, applied
        // directly rather than through a CPI back into ourselves.
        self_target = &state.target_program == program_id;

        account_count = state.account_count as usize;
        ix_data_len = state.ix_data_len as usize;

        if self_target {
            // A config action operates on the `multisig` account passed here,
            // so it must carry no accounts of its own.
            if account_count != 0 {
                return Err(MultisigError::InvalidInstructionData.into());
            }
        } else {
            if account_count == 0 || remaining.len() < account_count {
                return Err(MultisigError::NotEnoughAccounts.into());
            }

            // The owners approved these accounts in this order. Without this
            // check an executor could swap a destination and spend the
            // approvals on a different instruction than the one voted for.
            for (i, meta) in state.accounts().iter().enumerate() {
                if remaining[i].address() != &meta.address {
                    return Err(MultisigError::AccountMismatch.into());
                }
                flags[i] = (meta.is_writable != 0, meta.is_signer != 0);
            }
        }

        target_program = state.target_program;
        vault_index = state.vault_index;
        vault_bump = state.vault_bump;
        ix_data[..ix_data_len].copy_from_slice(state.ix_data());

        // Effects before interactions. The callee can invoke this program
        // again, and a proposal still marked `Approved` would execute twice.
        state.status = TransactionStatus::Executed as u8;
        state.invariant()?;
    }

    if self_target {
        return apply_config_action(multisig, &ix_data[..ix_data_len]);
    }

    let views: &[AccountView] = remaining;

    // Entries past `account_count` are never read; they only need a valid
    // address so the array can be built.
    let metas: [InstructionAccount; MAX_IX_ACCOUNTS] = core::array::from_fn(|i| {
        let idx = if i < account_count { i } else { 0 };
        InstructionAccount::new(views[idx].address(), flags[i].0, flags[i].1)
    });

    let ix = InstructionView {
        program_id: &target_program,
        data: &ix_data[..ix_data_len],
        accounts: &metas[..account_count],
    };

    let index_byte = [vault_index];
    let bump_byte = [vault_bump];

    let seeds = [
        Seed::from(VAULT_SEED),
        Seed::from(multisig.address().as_array()),
        Seed::from(&index_byte),
        Seed::from(&bump_byte),
    ];

    let signer = Signer::from(&seeds[..]);

    invoke_signed_with_bounds::<MAX_IX_ACCOUNTS, AccountView>(
        &ix,
        &views[..account_count],
        &[signer],
    )
}
