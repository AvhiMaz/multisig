//! Close a finished proposal and reclaim its rent.
//!
//! Permitted for any caller, because the outcome is fixed: the account is
//! closed and its lamports go to the creator who paid for it. Leaving finished
//! proposals open would strand their rent forever.
//!
//! # Accounts
//!
//! 0. `transaction` - writable, the proposal being closed
//! 1. `creator`     - writable, receives the rent; must be the proposer

use pinocchio::{AccountView, Address, ProgramResult};

use crate::{
    error::MultisigError,
    helper::{check_owner, validate_eq},
    state::transaction::{Transaction, TransactionStatus},
};

/// Closes a terminal proposal, refunding rent to its creator.
pub fn process_close_transaction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction: &[u8],
) -> ProgramResult {
    let [transaction, creator, _remaining @ ..] = accounts else {
        return Err(MultisigError::NotEnoughAccounts.into());
    };

    if !instruction.is_empty() {
        return Err(MultisigError::InvalidInstructionData.into());
    }

    check_owner(transaction, program_id, MultisigError::IllegalOwner.into())?;

    {
        // SAFETY: read-only borrow, released with this scope so `close` below
        // does not see the account as borrowed.
        let transaction_data = unsafe { transaction.borrow_unchecked() };
        let state = Transaction::load(transaction_data)?;

        validate_eq(
            &state.creator,
            creator.address(),
            MultisigError::InvalidAccount.into(),
        )?;

        // Only a proposal that can never run again.
        match state.status()? {
            TransactionStatus::Executed
            | TransactionStatus::Rejected
            | TransactionStatus::Cancelled => {}
            _ => return Err(MultisigError::InvalidStatus.into()),
        }
    }

    // Lamports must leave the account before it is closed, or the instruction
    // ends unbalanced and the runtime rejects it.
    let refund = transaction.lamports();

    let credited = creator
        .lamports()
        .checked_add(refund)
        .ok_or(MultisigError::Overflow)?;

    creator.set_lamports(credited);
    transaction.set_lamports(0);
    transaction.close()
}
