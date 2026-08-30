//! Multisig initialization.
//!
//! The only instruction authorized by a plain wallet signature. Later changes
//! to the owner set go through propose, approve, and execute.
//!
//! # Accounts
//!
//! 0. `creator`        - signer, pays rent, and is the PDA seed
//! 1. `multisig`       - PDA `["multisig", creator]`, created here
//! 2. `system_program`

use pinocchio::{
    AccountView, Address, ProgramResult,
    cpi::{Seed, Signer},
    error::ProgramError,
    sysvars::{Sysvar, rent::Rent},
};
use pinocchio_system::{ID, instructions::CreateAccount};

use crate::{
    constants::{MAX_OWNER, MULTISIG_SEED},
    state::multisig::Multisig,
};

/// Payload for [`process_init_multisig`].
///
/// `owners` is always sent at full width so the payload stays fixed-size and
/// parseable in place.
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
    /// Reserved, must be zero.
    pub _pad: [u8; 1],
}

impl InitMultisigData {
    /// Size of the payload in bytes.
    pub const LEN: usize = core::mem::size_of::<Self>();

    /// Reads instruction data as [`InitMultisigData`], checking length.
    fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() != Self::LEN {
            Err(ProgramError::InvalidInstructionData)
        } else {
            // SAFETY: length checked above; every field is byte-aligned.
            Ok(unsafe { &*(data.as_ptr() as *const Self) })
        }
    }
}

/// Creates and initializes a multisig configuration account.
pub fn process_init_multisig(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction: &[u8],
) -> ProgramResult {
    let [creator, multisig, system_program, _remaining @ ..] = accounts else {
        return Err(ProgramError::NotEnoughAccountKeys);
    };

    if !creator.is_signer() {
        return Err(ProgramError::MissingRequiredSignature);
    }

    if system_program.address() != &ID {
        return Err(ProgramError::IncorrectProgramId);
    }

    // Pre-funded alone is enough to mean the address is already in use.
    if !multisig.is_data_empty() || multisig.lamports() != 0 {
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    let data = InitMultisigData::load(instruction)?;
    let owners_count = data.owners_count as usize;

    if owners_count == 0 || owners_count > MAX_OWNER {
        return Err(ProgramError::InvalidInstructionData);
    }

    // Unanimous is valid; only an unreachable threshold is rejected.
    if data.threshold == 0 || data.threshold > data.owners_count {
        return Err(ProgramError::InvalidInstructionData);
    }

    // A repeated key would take two bitmap positions, letting one signer meet a
    // threshold of two alone.
    for i in 0..owners_count {
        for j in (i + 1)..owners_count {
            if data.owners[i] == data.owners[j] {
                return Err(ProgramError::InvalidInstructionData);
            }
        }
    }

    let bump = [data.bump];

    let seeds = [
        Seed::from(MULTISIG_SEED),
        Seed::from(creator.address().as_array()),
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

    state.creator = *creator.address();
    state.owners = data.owners;

    // Trailing slots are caller-controlled bytes; zero them so a later
    // add_owner cannot promote leftover data.
    for slot in state.owners[owners_count..].iter_mut() {
        *slot = Address::default();
    }

    state.owners_count = data.owners_count;
    state.threshold = data.threshold;
    state.bump = data.bump;
    state._pad = [0u8; 5];
    state.transaction_index = 0;

    Ok(())
}
