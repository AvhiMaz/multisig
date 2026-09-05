//! Approve a proposal.
//!
//! The vote is a bit at the owner's position. The proposal latches to
//! `Approved` the moment the count reaches the threshold, and execution never
//! recounts.
//!
//! # Accounts
//!
//! 0. `owner`       - signer, must be an owner permitted to vote
//! 1. `multisig`    - supplies the threshold and the staleness marker
//! 2. `transaction` - writable, the proposal being voted on

use pinocchio::{
    AccountView, Address, ProgramResult,
    sysvars::{Sysvar, clock::Clock},
};

use crate::{
    error::MultisigError,
    instruction::vote::{check_votable, latch_approved, prepare},
    state::{
        bitmap,
        transaction::{Transaction, TransactionStatus},
    },
};

/// Records an approval from `owner`.
pub fn process_approve(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction: &[u8],
) -> ProgramResult {
    let [owner, multisig, transaction, _remaining @ ..] = accounts else {
        return Err(MultisigError::NotEnoughAccounts.into());
    };

    let voter = prepare(program_id, owner, multisig, transaction, instruction, true)?;

    // SAFETY: the multisig borrow ended inside `prepare`, so this is the only
    // live borrow.
    let transaction_data = unsafe { transaction.borrow_unchecked_mut() };
    let (state, votes, _) = Transaction::load_mut(transaction_data)?;

    check_votable(state, multisig, &voter, TransactionStatus::Active)?;

    if votes.has_voted(voter.index) {
        return Err(MultisigError::AlreadyVoted.into());
    }

    if !bitmap::set(votes.approved, voter.index) {
        return Err(MultisigError::AlreadyVoted.into());
    }

    state.approved_count += 1;

    if state.approved_count >= voter.threshold {
        latch_approved(state, Clock::get()?.unix_timestamp);
    }

    state.invariant()
}
