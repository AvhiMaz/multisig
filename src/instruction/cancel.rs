//! Cancel a proposal.
//!
//! Only the creator, and only while the proposal is still `Active`. Once a
//! proposal is `Approved` the owners have committed to it, and withdrawing that
//! would need consensus of its own rather than one person's say-so.
//!
//! # Accounts
//!
//! 0. `creator`     - signer, must be the account that proposed it
//! 1. `multisig`    - the configuration this proposal belongs to
//! 2. `transaction` - writable, the proposal being cancelled

use pinocchio::{AccountView, Address, ProgramResult};

use crate::{
    error::MultisigError,
    helper::{check_owner, check_signer, validate_eq},
    state::transaction::{Transaction, TransactionStatus},
};

/// Marks an active proposal `Cancelled`.
pub fn process_cancel(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction: &[u8],
) -> ProgramResult {
    let [creator, multisig, transaction, _remaining @ ..] = accounts else {
        return Err(MultisigError::NotEnoughAccounts.into());
    };

    if !instruction.is_empty() {
        return Err(MultisigError::InvalidInstructionData.into());
    }

    check_signer(creator, MultisigError::MissingSignature.into())?;
    check_owner(multisig, program_id, MultisigError::IllegalOwner.into())?;
    check_owner(transaction, program_id, MultisigError::IllegalOwner.into())?;

    // SAFETY: the only live borrow in this instruction.
    let transaction_data = unsafe { transaction.borrow_unchecked_mut() };
    let state = Transaction::load_mut(transaction_data)?;

    validate_eq(
        &state.multisig,
        multisig.address(),
        MultisigError::MultisigMismatch.into(),
    )?;

    validate_eq(
        &state.creator,
        creator.address(),
        MultisigError::InvalidAccount.into(),
    )?;

    if state.status()? != TransactionStatus::Active {
        return Err(MultisigError::InvalidStatus.into());
    }

    state.status = TransactionStatus::Cancelled as u8;

    state.invariant()
}
