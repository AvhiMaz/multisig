//! Transaction proposal creation.
//!
//! Any owner may propose. The proposal starts with no votes; the proposer
//! approves separately if they want to.
//!
//! The payload is an eight-byte header followed by a compiled message, and the
//! account is sized to exactly that message. A proposal therefore costs rent
//! for what it carries rather than for a worst case.
//!
//! # Accounts
//!
//! 0. `creator`        - signer, must be an owner, pays rent
//! 1. `multisig`       - writable, supplies and bumps the transaction counter
//! 2. `transaction`    - PDA `["transaction", multisig, index]`, created here
//! 3. `system_program`

use pinocchio::{
    AccountView, Address, ProgramResult,
    cpi::{Seed, Signer},
    sysvars::{Sysvar, rent::Rent},
};
use pinocchio_system::{ID, instructions::CreateAccount};

use crate::{
    constants::{MAX_EPHEMERAL_SIGNERS, MAX_MESSAGE_SIZE, TRANSACTION_SEED},
    error::MultisigError,
    helper::{check_owner, check_signer, validate_eq},
    state::{
        bitmap,
        message::TransactionMessage,
        multisig::Multisig,
        permission::Permission,
        transaction::{Transaction, TransactionStatus},
    },
};

/// Fixed header of the [`process_create_transaction`] payload, followed by the
/// compiled message.
///
/// Packed so it parses at any alignment: instruction data is not guaranteed to
/// land on a word boundary.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct CreateTransactionHeader {
    /// Which vault signs the CPIs at execution.
    pub vault_index: u8,
    /// Bump for that vault PDA. Verified at execution, not here.
    pub vault_bump: u8,
    /// Bump for this transaction PDA. Unvalidated: `invoke_signed` rejects a wrong one.
    pub bump: u8,
    /// Ephemeral signer PDAs this proposal may sign with.
    pub ephemeral_count: u8,
    /// Cached bumps for those PDAs.
    pub ephemeral_bumps: [u8; MAX_EPHEMERAL_SIGNERS],
}

impl CreateTransactionHeader {
    /// Size of the header in bytes.
    pub const LEN: usize = core::mem::size_of::<Self>();
}

/// Creates a proposal against `multisig`.
pub fn process_create_transaction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction: &[u8],
) -> ProgramResult {
    let [
        creator,
        multisig,
        transaction,
        system_program,
        _remaining @ ..,
    ] = accounts
    else {
        return Err(MultisigError::NotEnoughAccounts.into());
    };

    check_signer(creator, MultisigError::MissingSignature.into())?;

    validate_eq(
        system_program.address(),
        &ID,
        MultisigError::InvalidProgramId.into(),
    )?;

    // First instruction to take a caller-supplied multisig, so this is where a
    // forged account would otherwise get in.
    check_owner(multisig, program_id, MultisigError::IllegalOwner.into())?;

    if !transaction.is_data_empty() || transaction.lamports() != 0 {
        return Err(MultisigError::AlreadyInitialized.into());
    }

    if instruction.len() < CreateTransactionHeader::LEN {
        return Err(MultisigError::InvalidInstructionData.into());
    }

    // SAFETY: length checked above, and every field is a byte.
    let header = unsafe { &*(instruction.as_ptr() as *const CreateTransactionHeader) };
    let message = &instruction[CreateTransactionHeader::LEN..];

    init_proposal(
        program_id,
        creator,
        multisig,
        transaction,
        message,
        header.vault_index,
        header.vault_bump,
        header.bump,
        header.ephemeral_count,
        header.ephemeral_bumps,
    )
}

/// Reserves the next transaction index, creates the proposal PDA sized to
/// `message`, and writes the header.
///
/// Shared with `create_from_buffer`, which supplies a message assembled across
/// several transactions rather than one carried in the instruction.
#[allow(clippy::too_many_arguments)]
pub(crate) fn init_proposal(
    program_id: &Address,
    creator: &AccountView,
    multisig: &mut AccountView,
    transaction: &mut AccountView,
    message: &[u8],
    vault_index: u8,
    vault_bump: u8,
    bump: u8,
    ephemeral_count: u8,
    ephemeral_bumps: [u8; MAX_EPHEMERAL_SIGNERS],
) -> ProgramResult {
    if ephemeral_count as usize > MAX_EPHEMERAL_SIGNERS {
        return Err(MultisigError::InvalidInstructionData.into());
    }

    if message.len() > MAX_MESSAGE_SIZE {
        return Err(MultisigError::InvalidMessage.into());
    }

    // Reject a malformed message now rather than mid-CPI at execution, when
    // some of its instructions may already have run.
    TransactionMessage::parse(message)?;

    // Reserve the index, in its own scope so the multisig borrow ends before
    // the transaction account is borrowed.
    let (index, owners_count) = {
        // SAFETY: the only live borrow at this point.
        let multisig_data = unsafe { multisig.borrow_unchecked_mut() };
        let (ms, owners, permissions) = Multisig::load_mut(multisig_data)?;

        let position =
            Multisig::is_owner(owners, creator.address()).ok_or(MultisigError::NotAnOwner)?;

        let mask = permissions[position];
        if mask != 0 && mask & Permission::INITIATE == 0 {
            return Err(MultisigError::Unauthorized.into());
        }

        // Index 0 means "no transactions yet", so the first proposal is 1.
        let index = ms
            .transaction_index
            .checked_add(1)
            .ok_or(MultisigError::Overflow)?;

        ms.transaction_index = index;
        (index, ms.owners_count)
    };

    let index_bytes = index.to_le_bytes();
    let bump_byte = [bump];

    let seeds = [
        Seed::from(TRANSACTION_SEED),
        Seed::from(multisig.address().as_array()),
        Seed::from(&index_bytes),
        Seed::from(&bump_byte),
    ];

    let signer_seeds = Signer::from(&seeds[..]);
    let space = Transaction::space(owners_count as usize, message.len());

    CreateAccount {
        from: creator,
        to: transaction,
        space: space as u64,
        lamports: Rent::get()?.minimum_balance_unchecked(space),
        owner: program_id,
    }
    .invoke_signed(&[signer_seeds])?;

    // SAFETY: just created by the CPI above, so no other borrow is live.
    let transaction_data = unsafe { transaction.borrow_unchecked_mut() };

    // The header has not been written yet, so `message_len` cannot be trusted
    // to split the account.
    let (state, tail) = Transaction::split_uninitialized(transaction_data)?;

    state.multisig = *multisig.address();
    state.creator = *creator.address();
    state.index = index;
    state.approved_at = 0;

    // No votes yet; the proposer approves separately if they want to.
    // No votes yet; the bitmaps start clear.
    state.owners_count = owners_count;
    state.approved_count = 0;
    state.rejected_count = 0;
    state.cancelled_count = 0;

    state.status = TransactionStatus::Active as u8;
    state.bump = bump;
    state.vault_index = vault_index;
    state.vault_bump = vault_bump;
    state.ephemeral_count = ephemeral_count;
    state.ephemeral_bumps = ephemeral_bumps;
    state.message_len = message.len() as u32;
    state._pad = [0u8; 3];

    let bits = bitmap::len_for(owners_count as usize);
    let (votes, stored_message) = tail.split_at_mut(3 * bits);
    votes.fill(0);
    stored_message.copy_from_slice(message);

    state.invariant()
}
