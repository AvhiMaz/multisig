//! Turns a completed buffer into a proposal.
//!
//! The buffer's contents must match the length and SHA-256 committed when it
//! was created, so a half-uploaded or tampered buffer cannot become a proposal.
//! The buffer is closed and its rent returned in the same instruction.
//!
//! # Accounts
//!
//! 0. `creator`        - signer, must be the buffer's creator, pays proposal rent
//! 1. `multisig`       - writable, supplies and bumps the transaction counter
//! 2. `transaction`    - PDA `["transaction", multisig, index]`, created here
//! 3. `buffer`         - writable, closed here
//! 4. `system_program`

use pinocchio::{AccountView, Address, ProgramResult};
use pinocchio_system::ID;
use solana_sha256_hasher::hashv;

use crate::{
    constants::MAX_EPHEMERAL_SIGNERS,
    error::MultisigError,
    helper::{check_owner, check_signer, validate_eq},
    instruction::{buffer::close_buffer, create_transaction::init_proposal},
    state::buffer::TransactionBuffer,
};

/// Payload for [`process_create_from_buffer`].
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct CreateFromBufferData {
    /// Bump for the transaction PDA.
    pub bump: u8,
    /// Bump for the vault the proposal will spend from.
    pub vault_bump: u8,
    /// Ephemeral signer PDAs the proposal may sign with.
    pub ephemeral_count: u8,
    /// Cached bumps for those PDAs.
    pub ephemeral_bumps: [u8; MAX_EPHEMERAL_SIGNERS],
}

impl CreateFromBufferData {
    /// Size of the payload in bytes.
    pub const LEN: usize = core::mem::size_of::<Self>();
}

/// Creates a proposal from a completed buffer.
pub fn process_create_from_buffer(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction: &[u8],
) -> ProgramResult {
    let [
        creator,
        multisig,
        transaction,
        buffer,
        system_program,
        _remaining @ ..,
    ] = accounts
    else {
        return Err(MultisigError::NotEnoughAccounts.into());
    };

    if instruction.len() != CreateFromBufferData::LEN {
        return Err(MultisigError::InvalidInstructionData.into());
    }

    // SAFETY: length checked above, and every field is a byte.
    let data = unsafe { &*(instruction.as_ptr() as *const CreateFromBufferData) };

    check_signer(creator, MultisigError::MissingSignature.into())?;

    validate_eq(
        system_program.address(),
        &ID,
        MultisigError::InvalidProgramId.into(),
    )?;

    check_owner(multisig, program_id, MultisigError::IllegalOwner.into())?;
    check_owner(buffer, program_id, MultisigError::IllegalOwner.into())?;

    if !transaction.is_data_empty() || transaction.lamports() != 0 {
        return Err(MultisigError::AlreadyInitialized.into());
    }

    {
        // SAFETY: an immutable reborrow, released before the buffer is closed.
        let buffer_data = unsafe { buffer.borrow_unchecked() };
        let (state, region) = TransactionBuffer::load(buffer_data)?;

        validate_eq(
            &state.creator,
            creator.address(),
            MultisigError::InvalidAccount.into(),
        )?;

        validate_eq(
            &state.multisig,
            multisig.address(),
            MultisigError::MultisigMismatch.into(),
        )?;

        if !state.is_complete() {
            return Err(MultisigError::BufferIncomplete.into());
        }

        // The creator committed to this content before uploading it. Without
        // the check, a buffer could be rewritten chunk by chunk into something
        // other than what was reviewed off-chain.
        if hashv(&[region]).to_bytes() != state.final_hash {
            return Err(MultisigError::BufferHashMismatch.into());
        }

        init_proposal(
            program_id,
            creator,
            multisig,
            transaction,
            region,
            state.vault_index,
            data.vault_bump,
            data.bump,
            data.ephemeral_count,
            data.ephemeral_bumps,
        )?;
    }

    close_buffer(buffer, creator)
}
