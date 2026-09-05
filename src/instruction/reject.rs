//! Reject a proposal.
//!
//! Once enough owners reject that the threshold can no longer be reached, the
//! proposal latches to `Rejected` rather than sitting `Active` forever.
//!
//! # Accounts
//!
//! 0. `owner`       - signer, must be an owner permitted to vote
//! 1. `multisig`    - supplies the cutoff and the staleness marker
//! 2. `transaction` - writable, the proposal being voted on

use pinocchio::{AccountView, Address, ProgramResult};

use crate::{
    error::MultisigError,
    instruction::vote::{check_votable, prepare},
    state::{
        bitmap,
        transaction::{Transaction, TransactionStatus},
    },
};

/// Records a rejection from `owner`.
pub fn process_reject(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction: &[u8],
) -> ProgramResult {
    let [owner, multisig, transaction, _remaining @ ..] = accounts else {
        return Err(MultisigError::NotEnoughAccounts.into());
    };

    let voter = prepare(program_id, owner, multisig, transaction, instruction, true)?;

    // SAFETY: the multisig borrow ended inside `prepare`.
    let transaction_data = unsafe { transaction.borrow_unchecked_mut() };
    let (state, votes, _) = Transaction::load_mut(transaction_data)?;

    check_votable(state, multisig, &voter, TransactionStatus::Active)?;

    if votes.has_voted(voter.index) {
        return Err(MultisigError::AlreadyVoted.into());
    }

    if !bitmap::set(votes.rejected, voter.index) {
        return Err(MultisigError::AlreadyVoted.into());
    }

    state.rejected_count += 1;

    // Latch once approval has become arithmetically impossible.
    if state.rejected_count >= voter.cutoff {
        state.status = TransactionStatus::Rejected as u8;
    }

    state.invariant()
}
