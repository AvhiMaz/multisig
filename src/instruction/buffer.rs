//! Chunked upload of a compiled message.
//!
//! A message larger than one Solana transaction cannot reach
//! `create_transaction` in a single call. It is uploaded here across several
//! transactions and then turned into a proposal by `create_from_buffer`.
//!
//! The buffer commits to the message's length and SHA-256 up front, so a
//! partially written or tampered buffer cannot become a proposal.

use pinocchio::{
    AccountView, Address, ProgramResult,
    cpi::{Seed, Signer},
    sysvars::{Sysvar, rent::Rent},
};
use pinocchio_system::{ID, instructions::CreateAccount};

use crate::{
    constants::{BUFFER_SEED, MAX_MESSAGE_SIZE},
    error::MultisigError,
    helper::{check_owner, check_signer, validate_eq},
    state::{buffer::TransactionBuffer, multisig::Multisig, permission::Permission},
};

/// Payload for [`process_buffer_create`], optionally followed by a first chunk.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BufferCreateData {
    /// SHA-256 the completed message must hash to.
    pub final_hash: [u8; 32],
    /// Length the completed message will have.
    pub final_size: u32,
    /// Distinguishes concurrent buffers from the same creator.
    pub buffer_index: u8,
    /// Which vault the eventual proposal will spend from.
    pub vault_index: u8,
    /// Bump for this buffer PDA. Unvalidated: `invoke_signed` rejects a wrong one.
    pub bump: u8,
    /// Reserved.
    pub _pad: u8,
}

impl BufferCreateData {
    /// Size of the payload header in bytes.
    pub const LEN: usize = core::mem::size_of::<Self>();
}

/// Creates a buffer and optionally writes its first chunk.
///
/// # Accounts
///
/// 0. `creator`        - signer, must be an owner, pays rent
/// 1. `multisig`       - the configuration the eventual proposal belongs to
/// 2. `buffer`         - PDA `["buffer", multisig, creator, buffer_index]`, created here
/// 3. `system_program`
pub fn process_buffer_create(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction: &[u8],
) -> ProgramResult {
    let [creator, multisig, buffer, system_program, _remaining @ ..] = accounts else {
        return Err(MultisigError::NotEnoughAccounts.into());
    };

    check_signer(creator, MultisigError::MissingSignature.into())?;

    validate_eq(
        system_program.address(),
        &ID,
        MultisigError::InvalidProgramId.into(),
    )?;

    check_owner(multisig, program_id, MultisigError::IllegalOwner.into())?;

    if !buffer.is_data_empty() || buffer.lamports() != 0 {
        return Err(MultisigError::AlreadyInitialized.into());
    }

    if instruction.len() < BufferCreateData::LEN {
        return Err(MultisigError::InvalidInstructionData.into());
    }

    // SAFETY: length checked above, and every field is byte-aligned under
    // `#[repr(C, packed)]`.
    let data = unsafe { &*(instruction.as_ptr() as *const BufferCreateData) };
    let chunk = &instruction[BufferCreateData::LEN..];

    let final_size = data.final_size as usize;

    if final_size > MAX_MESSAGE_SIZE || chunk.len() > final_size {
        return Err(MultisigError::InvalidMessage.into());
    }

    {
        // SAFETY: read-only borrow, released with this scope.
        let multisig_data = unsafe { multisig.borrow_unchecked() };
        let (_, owners, permissions) = Multisig::load(multisig_data)?;

        if Multisig::is_owner(owners, creator.address()).is_none() {
            return Err(MultisigError::NotAnOwner.into());
        }

        if !Multisig::has_permission(owners, permissions, creator.address(), Permission::INITIATE) {
            return Err(MultisigError::Unauthorized.into());
        }
    }

    let index_byte = [data.buffer_index];
    let bump = [data.bump];

    let seeds = [
        Seed::from(BUFFER_SEED),
        Seed::from(multisig.address().as_array()),
        Seed::from(creator.address().as_array()),
        Seed::from(&index_byte),
        Seed::from(&bump),
    ];

    let signer_seeds = Signer::from(&seeds[..]);
    let space = TransactionBuffer::space(final_size);

    CreateAccount {
        from: creator,
        to: buffer,
        space: space as u64,
        lamports: Rent::get()?.minimum_balance_unchecked(space),
        owner: program_id,
    }
    .invoke_signed(&[signer_seeds])?;

    // SAFETY: just created by the CPI above, so no other borrow is live.
    let buffer_data = unsafe { buffer.borrow_unchecked_mut() };
    let (state, region) = TransactionBuffer::split_uninitialized(buffer_data)?;

    state.multisig = *multisig.address();
    state.creator = *creator.address();
    state.final_hash = data.final_hash;
    state.final_size = data.final_size;
    state.written = chunk.len() as u32;
    state.buffer_index = data.buffer_index;
    state.vault_index = data.vault_index;
    state.bump = data.bump;
    state._pad = [0u8; 5];

    region[..chunk.len()].copy_from_slice(chunk);

    state.invariant()
}

/// Appends a chunk to a buffer.
///
/// # Accounts
///
/// 0. `creator` - signer, must be the account that created the buffer
/// 1. `buffer`  - writable
pub fn process_buffer_extend(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction: &[u8],
) -> ProgramResult {
    let [creator, buffer, _remaining @ ..] = accounts else {
        return Err(MultisigError::NotEnoughAccounts.into());
    };

    check_signer(creator, MultisigError::MissingSignature.into())?;
    check_owner(buffer, program_id, MultisigError::IllegalOwner.into())?;

    if instruction.is_empty() {
        return Err(MultisigError::InvalidInstructionData.into());
    }

    // SAFETY: the only live borrow in this instruction.
    let buffer_data = unsafe { buffer.borrow_unchecked_mut() };
    let (state, region) = TransactionBuffer::load_mut(buffer_data)?;

    validate_eq(
        &state.creator,
        creator.address(),
        MultisigError::InvalidAccount.into(),
    )?;

    let written = state.written as usize;

    let end = written
        .checked_add(instruction.len())
        .ok_or(MultisigError::Overflow)?;

    // Writing past the committed length would mean the buffer no longer
    // matches the hash it promised.
    if end > state.final_size as usize {
        return Err(MultisigError::InvalidMessage.into());
    }

    region[written..end].copy_from_slice(instruction);
    state.written = end as u32;

    state.invariant()
}

/// Closes a buffer and refunds its rent to the creator.
///
/// # Accounts
///
/// 0. `creator` - signer and rent destination, must be the buffer's creator
/// 1. `buffer`  - writable, closed here
pub fn process_buffer_close(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction: &[u8],
) -> ProgramResult {
    let [creator, buffer, _remaining @ ..] = accounts else {
        return Err(MultisigError::NotEnoughAccounts.into());
    };

    if !instruction.is_empty() {
        return Err(MultisigError::InvalidInstructionData.into());
    }

    check_signer(creator, MultisigError::MissingSignature.into())?;
    check_owner(buffer, program_id, MultisigError::IllegalOwner.into())?;

    {
        // SAFETY: read-only borrow, released before the account is closed.
        let buffer_data = unsafe { buffer.borrow_unchecked() };
        let (state, _) = TransactionBuffer::load(buffer_data)?;

        validate_eq(
            &state.creator,
            creator.address(),
            MultisigError::InvalidAccount.into(),
        )?;
    }

    close_buffer(buffer, creator)
}

/// Moves a buffer's lamports to `destination` and closes it.
///
/// Lamports must leave before the close, or the instruction ends unbalanced
/// and the runtime rejects it.
pub(crate) fn close_buffer(
    buffer: &mut AccountView,
    destination: &mut AccountView,
) -> ProgramResult {
    let refund = buffer.lamports();

    let credited = destination
        .lamports()
        .checked_add(refund)
        .ok_or(MultisigError::Overflow)?;

    destination.set_lamports(credited);
    buffer.set_lamports(0);
    buffer.close()
}
