//! Multisig initialization.
//!
//! The only instruction authorized by a plain wallet signature. Later changes
//! to the owner set go through propose, approve, and execute.
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
    utils::{impl_len, impl_load},
};

/// Payload for [`process_init_multisig`].
///
/// `owners` is always sent at full width so the payload stays fixed-size and
/// parseable in place, and must be strictly ascending.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct InitMultisigData {
    /// Candidate owners, of which the first `owners_count` are installed.
    pub owners: [Address; MAX_OWNER],
    /// Owners to install, in `1..=MAX_OWNER`.
    pub owners_count: u8,
    /// Approvals needed to execute, in `1..=owners_count`.
    pub threshold: u8,
    /// PDA bump. Unvalidated: `invoke_signed` rejects a wrong one.
    pub bump: u8,
    /// Reserved.
    pub _pad: [u8; 1],
}

impl_len!(InitMultisigData);
impl_load!(InitMultisigData);

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

    let data = InitMultisigData::load(instruction)?;
    let owners_count = data.owners_count as usize;

    // Bounded here because the count indexes the array below. Every other rule
    // is left to `Multisig::invariant`.
    if owners_count == 0 || owners_count > MAX_OWNER {
        return Err(MultisigError::InvalidOwnerCount.into());
    }

    let bump = [data.bump];

    let seeds = [
        Seed::from(MULTISIG_SEED),
        Seed::from(create_key.address().as_array()),
        Seed::from(&bump),
    ];

    let signer_seeds = Signer::from(&seeds[..]);

    CreateAccount {
        from: creator,
        to: multisig,
        space: Multisig::LEN as u64,
        lamports: Rent::get()?.minimum_balance_unchecked(Multisig::LEN),
        owner: program_id,
    }
    .invoke_signed(&[signer_seeds])?;

    // SAFETY: just created by the CPI above, so no other borrow is live.
    let multisig_data = unsafe { multisig.borrow_unchecked_mut() };

    let state = Multisig::load_mut(multisig_data)?;

    state.create_key = *create_key.address();
    state.owners = data.owners;

    // Trailing slots are caller-controlled bytes; zero them so the stored owner
    // set is canonical and a later add_owner cannot promote leftover data.
    for slot in state.owners[owners_count..].iter_mut() {
        *slot = Address::default();
    }

    state.owners_count = data.owners_count;
    state.threshold = data.threshold;
    state.bump = data.bump;
    state._pad = [0u8; 1];
    state.time_lock = 0;
    state.transaction_index = 0;
    state.stale_transaction_index = 0;

    state.invariant()
}
