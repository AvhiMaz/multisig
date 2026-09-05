//! Cancel a proposal.
//!
//! Two paths, because the two situations are not the same decision.
//!
//! While a proposal is `Active` nobody has committed to it, so its creator may
//! withdraw it alone. Once it is `Approved` the owners have collectively agreed,
//! and undoing that takes the same threshold that made it. Without the second
//! path a time lock would be half a feature, giving owners a window to notice a
//! bad proposal but no way to stop it.
//!
//! # Accounts
//!
//! 0. `signer`      - the creator while `Active`, or a voting owner while `Approved`
//! 1. `multisig`    - supplies the threshold and the owner set
//! 2. `transaction` - writable, the proposal being cancelled

use pinocchio::{AccountView, Address, ProgramResult};

use crate::{
    error::MultisigError,
    helper::validate_eq,
    instruction::vote::{check_votable, prepare},
    state::{
        bitmap,
        transaction::{Transaction, TransactionStatus},
    },
};

/// Cancels an active proposal, or records a vote to cancel an approved one.
pub fn process_cancel(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction: &[u8],
) -> ProgramResult {
    let [signer, multisig, transaction, _remaining @ ..] = accounts else {
        return Err(MultisigError::NotEnoughAccounts.into());
    };

    // The creator path does not require the vote permission, so it is checked
    // only on the branch that needs it.
    let voter = prepare(
        program_id,
        signer,
        multisig,
        transaction,
        instruction,
        false,
    )?;

    // SAFETY: the multisig borrow ended inside `prepare`.
    let transaction_data = unsafe { transaction.borrow_unchecked_mut() };
    let (state, votes, _) = Transaction::load_mut(transaction_data)?;

    match state.status()? {
        TransactionStatus::Active => {
            check_votable(state, multisig, &voter, TransactionStatus::Active)?;

            validate_eq(
                &state.creator,
                signer.address(),
                MultisigError::InvalidAccount.into(),
            )?;

            state.status = TransactionStatus::Cancelled as u8;
        }

        TransactionStatus::Approved => {
            check_votable(state, multisig, &voter, TransactionStatus::Approved)?;

            if !voter.can_vote {
                return Err(MultisigError::Unauthorized.into());
            }

            if bitmap::get(votes.cancelled, voter.index) {
                return Err(MultisigError::AlreadyVoted.into());
            }

            if !bitmap::set(votes.cancelled, voter.index) {
                return Err(MultisigError::AlreadyVoted.into());
            }

            state.cancelled_count += 1;

            if state.cancelled_count >= voter.threshold {
                state.status = TransactionStatus::Cancelled as u8;
            }
        }

        _ => return Err(MultisigError::InvalidStatus.into()),
    }

    state.invariant()
}
