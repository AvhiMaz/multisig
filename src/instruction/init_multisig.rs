//! Multisig initialization.
//!
//! Authorized by a plain wallet signature, since there is no owner set yet to
//! ask. Later changes go through propose, approve and execute, or through the
//! config authority named here if one is.
//!
//! The payload is a fixed header followed by the owner addresses, so a
//! multisig is created at exactly the size it needs. A transaction caps the
//! owners that fit here at roughly thirty; beyond that, create a small multisig
//! and grow it with `add_owner`.
//!
//! # Accounts
//!
//! 0. `creator`        - signer, pays rent
//! 1. `create_key`     - signer, ephemeral keypair seeding the PDA
//! 2. `multisig`       - PDA `["multisig", create_key]`, created here
//! 3. `system_program`

use pinocchio::{
    AccountView, Address, ProgramResult,
    cpi::{Seed, Signer},
    sysvars::{Sysvar, rent::Rent},
};
use pinocchio_system::{ID, instructions::CreateAccount};

use crate::{
    constants::{MAX_OWNER, MULTISIG_SEED},
    error::MultisigError,
    helper::{check_signer, validate_eq},
    state::multisig::Multisig,
};

/// Fixed header of the [`process_init_multisig`] payload, followed by the
/// owner addresses.
///
/// Packed so it parses at any alignment: instruction data is not guaranteed to
/// land on a word boundary.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct InitMultisigData {
    /// Approvals needed to execute, in `1..=owners_count`.
    pub threshold: u32,
    /// Owners to install, in `1..=MAX_OWNER`.
    pub owners_count: u32,
    /// PDA bump. Unvalidated: `invoke_signed` rejects a wrong one.
    pub bump: u8,
    /// Reserved.
    pub _pad: [u8; 3],
    /// Key permitted to change the configuration without a vote. The default
    /// address leaves the multisig autonomous.
    pub config_authority: [u8; 32],
}

impl InitMultisigData {
    /// Size of the payload header in bytes.
    pub const LEN: usize = core::mem::size_of::<Self>();
}

/// Creates and initializes a multisig configuration account.
pub fn process_init_multisig(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction: &[u8],
) -> ProgramResult {
    let [
        creator,
        create_key,
        multisig,
        system_program,
        _remaining @ ..,
    ] = accounts
    else {
        return Err(MultisigError::NotEnoughAccounts.into());
    };

    check_signer(creator, MultisigError::MissingSignature.into())?;

    // The create_key must sign so nobody can squat a PDA on someone else's key.
    check_signer(create_key, MultisigError::MissingSignature.into())?;

    validate_eq(
        system_program.address(),
        &ID,
        MultisigError::InvalidProgramId.into(),
    )?;

    // Pre-funded alone is enough to mean the address is already in use.
    if !multisig.is_data_empty() || multisig.lamports() != 0 {
        return Err(MultisigError::AlreadyInitialized.into());
    }

    if instruction.len() < InitMultisigData::LEN {
        return Err(MultisigError::InvalidInstructionData.into());
    }

    // SAFETY: length checked above, and every field is byte-aligned under
    // `#[repr(C, packed)]`.
    let data = unsafe { &*(instruction.as_ptr() as *const InitMultisigData) };
    let owner_bytes = &instruction[InitMultisigData::LEN..];

    let owners_count = data.owners_count as usize;

    if owners_count == 0 || owners_count > MAX_OWNER {
        return Err(MultisigError::InvalidOwnerCount.into());
    }

    if owner_bytes.len() != owners_count * 32 {
        return Err(MultisigError::InvalidInstructionData.into());
    }

    // SAFETY: `Address` is `#[repr(transparent)]` over `[u8; 32]` with
    // alignment 1, and the slice length was checked above.
    let owners = unsafe {
        core::slice::from_raw_parts(owner_bytes.as_ptr() as *const Address, owners_count)
    };

    // Strictly ascending proves sorted and duplicate-free in one pass. This is
    // the only place the whole set is scanned; later changes check locally.
    for i in 1..owners_count {
        if owners[i - 1] >= owners[i] {
            return Err(MultisigError::OwnersNotSorted.into());
        }
    }

    let bump = [data.bump];

    let seeds = [
        Seed::from(MULTISIG_SEED),
        Seed::from(create_key.address().as_array()),
        Seed::from(&bump),
    ];

    let signer_seeds = Signer::from(&seeds[..]);
    let space = Multisig::space(owners_count);

    CreateAccount {
        from: creator,
        to: multisig,
        space: space as u64,
        lamports: Rent::get()?.minimum_balance_unchecked(space),
        owner: program_id,
    }
    .invoke_signed(&[signer_seeds])?;

    // SAFETY: just created by the CPI above, so no other borrow is live.
    let multisig_data = unsafe { multisig.borrow_unchecked_mut() };

    // The header has not been written yet, so `owners_count` cannot be trusted
    // to split the account.
    let (state, tail) = Multisig::split_uninitialized(multisig_data)?;

    state.create_key = *create_key.address();
    state.config_authority = Address::new_from_array(data.config_authority);
    state.rent_collector = Address::default();
    state.transaction_index = 0;
    state.stale_transaction_index = 0;
    state.closed_transaction_count = 0;
    state.time_lock = 0;
    state.owners_count = data.owners_count;
    // Zero means every permission, so every owner starts able to vote.
    state.voter_count = data.owners_count;
    state.threshold = data.threshold;
    state.bump = data.bump;
    state._pad = [0u8; 7];

    let (stored_owners, permissions) = tail.split_at_mut(owners_count * 32);
    stored_owners.copy_from_slice(owner_bytes);
    permissions.fill(0);

    state.invariant()
}
