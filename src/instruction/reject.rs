//! Reject a proposal.
//!
//! Once enough owners reject that the threshold can no longer be reached, the
//! proposal latches to `Rejected` rather than sitting `Active` forever.
//!
//! # Accounts
//!
//! 0. `owner`       - signer, must be an owner of `multisig`
//! 1. `multisig`    - supplies the cutoff and the staleness marker
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

/// Records a rejection from `owner`.
pub fn process_reject(
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

    let (cutoff, stale_index) = {
        // SAFETY: read-only borrow, released with this scope.
        let multisig_data = unsafe { multisig.borrow_unchecked() };
        let ms = Multisig::load(multisig_data)?;

        if ms.is_owner(owner.address()).is_none() {
            return Err(MultisigError::NotAnOwner.into());
        }

        (ms.cutoff(), ms.stale_transaction_index)
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

    if state.index <= stale_index {
        return Err(MultisigError::StaleTransaction.into());
    }

    if state.approvers().binary_search(owner.address()).is_ok() {
        return Err(MultisigError::AlreadyVoted.into());
    }

    let pos = match state.rejecters().binary_search(owner.address()) {
        Ok(_) => return Err(MultisigError::AlreadyVoted.into()),
        Err(pos) => pos,
    };

    let count = state.rejected_count as usize;
    if count >= MAX_OWNER {
        return Err(MultisigError::InvalidAccountData.into());
    }

    // Shift right to keep `rejected` ascending, so `binary_search` stays valid.
    let mut i = count;
    while i > pos {
        state.rejected[i] = state.rejected[i - 1];
        i -= 1;
    }
    state.rejected[pos] = *owner.address();
    state.rejected_count += 1;

    // Latch once approval has become arithmetically impossible.
    if state.rejected_count >= cutoff {
        state.status = TransactionStatus::Rejected as u8;
    }

    state.invariant()
}
