//! Configuration changes made by a config authority, without a vote.
//!
//! A multisig whose `config_authority` is the default address is autonomous:
//! this instruction is refused and every change goes through propose, approve,
//! execute. Set to anything else, that key alone decides the configuration.
//!
//! The action payload is identical to the one a proposal carries, so both paths
//! run the same code and cannot drift apart.
//!
//! # Accounts
//!
//! 0. `authority`      - signer, must match `config_authority`; pays or
//!    receives rent when the owner set resizes
//! 1. `multisig`       - writable
//! 2. `system_program` - required when adding an owner grows the account

use pinocchio::{AccountView, Address, ProgramResult};

use crate::{
    error::MultisigError,
    helper::{check_owner, check_signer, validate_eq},
    instruction::config_action::apply_config_action,
    state::multisig::Multisig,
};

/// Applies a config action on the authority's say-so.
pub fn process_set_config(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction: &[u8],
) -> ProgramResult {
    let [authority, multisig, _remaining @ ..] = accounts else {
        return Err(MultisigError::NotEnoughAccounts.into());
    };

    check_signer(authority, MultisigError::MissingSignature.into())?;
    check_owner(multisig, program_id, MultisigError::IllegalOwner.into())?;

    {
        // SAFETY: read-only borrow, released before the action runs.
        let multisig_data = unsafe { multisig.borrow_unchecked() };
        let (ms, _, _) = Multisig::load(multisig_data)?;

        // An autonomous multisig has no authority to appeal to, and treating
        // the default address as one would let anybody who can produce it take
        // control.
        if !ms.is_controlled() {
            return Err(MultisigError::NotControlled.into());
        }

        validate_eq(
            &ms.config_authority,
            authority.address(),
            MultisigError::Unauthorized.into(),
        )?;
    }

    apply_config_action(multisig, authority, instruction, false)
}
