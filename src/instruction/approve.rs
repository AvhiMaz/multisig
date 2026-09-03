//! Approve a proposal.
//!
//! Votes are recorded as keys, and the proposal latches to `Approved` the
//! moment the count reaches the threshold. Execution never recounts.
//!
//! # Accounts
//!
//! 0. `owner`       - signer, must be an owner of `multisig`
//! 1. `multisig`    - supplies the threshold and the staleness marker
//! 2. `transaction` - writable, the proposal being voted on

use pinocchio::{AccountView, Address, ProgramResult};

use crate::{
    constants::MAX_OWNER,
    error::MultisigError,
    helper::{check_owner, check_signer, validate_eq},
    state::{
        multisig::Multisig,
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

    if !instruction.is_empty() {
        return Err(MultisigError::InvalidInstructionData.into());
    }

    check_signer(owner, MultisigError::MissingSignature.into())?;
    check_owner(multisig, program_id, MultisigError::IllegalOwner.into())?;
    check_owner(transaction, program_id, MultisigError::IllegalOwner.into())?;

    let (threshold, stale_index) = {
        // SAFETY: read-only borrow, released with this scope.
        let multisig_data = unsafe { multisig.borrow_unchecked() };
        let ms = Multisig::load(multisig_data)?;

        if ms.is_owner(owner.address()).is_none() {
            return Err(MultisigError::NotAnOwner.into());
        }

        (ms.threshold, ms.stale_transaction_index)
    };

    // SAFETY: the multisig borrow ended with the scope above, so this is the
    // only live borrow.
    let transaction_data = unsafe { transaction.borrow_unchecked_mut() };
    let state = Transaction::load_mut(transaction_data)?;

    validate_eq(
        &state.multisig,
        multisig.address(),
        MultisigError::MultisigMismatch.into(),
    )?;

    if state.status()? != TransactionStatus::Active {
        return Err(MultisigError::InvalidStatus.into());
    }

    // Votes cast under an older owner set or threshold must not be extended
    // under the new ones.
    if state.index <= stale_index {
        return Err(MultisigError::StaleTransaction.into());
    }

    if state.rejecters().binary_search(owner.address()).is_ok() {
        return Err(MultisigError::AlreadyVoted.into());
    }

    let pos = match state.approvers().binary_search(owner.address()) {
        Ok(_) => return Err(MultisigError::AlreadyVoted.into()),
        Err(pos) => pos,
    };

    let count = state.approved_count as usize;
    if count >= MAX_OWNER {
        return Err(MultisigError::InvalidAccountData.into());
    }

    // Shift right to keep `approved` ascending, so `binary_search` stays valid.
    let mut i = count;
    while i > pos {
        state.approved[i] = state.approved[i - 1];
        i -= 1;
    }
    state.approved[pos] = *owner.address();
    state.approved_count += 1;

    // Latch at the vote that crosses the threshold.
    if state.approved_count >= threshold {
        state.status = TransactionStatus::Approved as u8;
    }

    state.invariant()
}
