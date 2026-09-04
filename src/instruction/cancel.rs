//! Cancel a proposal.
//!
//! Two paths, because the two situations are not the same decision.
//!
//! While a proposal is `Active` nobody has committed to it, so its creator may
//! withdraw it alone. Once it is `Approved` the owners have collectively agreed,
//! and undoing that takes the same threshold that made it: each vote is
//! recorded, and the proposal cancels when they reach the threshold. Without
//! this second path a time lock would be half a feature, giving owners a window
//! to notice a bad proposal but no way to stop it.
//!
//! # Accounts
//!
//! 0. `signer`      - the creator while `Active`, or a voting owner while `Approved`
//! 1. `multisig`    - supplies the threshold and the owner set
//! 2. `transaction` - writable, the proposal being cancelled

use pinocchio::{AccountView, Address, ProgramResult};

use crate::{
    constants::MAX_OWNER,
    error::MultisigError,
    helper::{check_owner, check_signer, validate_eq},
    state::{
        multisig::Multisig,
        permission::Permission,
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

    if !instruction.is_empty() {
        return Err(MultisigError::InvalidInstructionData.into());
    }

    check_signer(signer, MultisigError::MissingSignature.into())?;
    check_owner(multisig, program_id, MultisigError::IllegalOwner.into())?;
    check_owner(transaction, program_id, MultisigError::IllegalOwner.into())?;

    let (threshold, is_voter) = {
        // SAFETY: read-only borrow, released with this scope.
        let multisig_data = unsafe { multisig.borrow_unchecked() };
        let ms = Multisig::load(multisig_data)?;

        (
            ms.threshold,
            ms.has_permission(signer.address(), Permission::VOTE),
        )
    };

    // SAFETY: the multisig borrow ended with the scope above.
    let transaction_data = unsafe { transaction.borrow_unchecked_mut() };
    let (state, _) = Transaction::load_mut(transaction_data)?;

    validate_eq(
        &state.multisig,
        multisig.address(),
        MultisigError::MultisigMismatch.into(),
    )?;

    match state.status()? {
        TransactionStatus::Active => {
            validate_eq(
                &state.creator,
                signer.address(),
                MultisigError::InvalidAccount.into(),
            )?;

            state.status = TransactionStatus::Cancelled as u8;
        }

        TransactionStatus::Approved => {
            if !is_voter {
                return Err(MultisigError::Unauthorized.into());
            }

            let pos = match state.cancellers().binary_search(signer.address()) {
                Ok(_) => return Err(MultisigError::AlreadyVoted.into()),
                Err(pos) => pos,
            };

            let count = state.cancelled_count as usize;
            if count >= MAX_OWNER {
                return Err(MultisigError::InvalidAccountData.into());
            }

            // Shift right to keep `cancelled` ascending, so `binary_search`
            // stays valid.
            let mut i = count;
            while i > pos {
                state.cancelled[i] = state.cancelled[i - 1];
                i -= 1;
            }
            state.cancelled[pos] = *signer.address();
            state.cancelled_count += 1;

            if state.cancelled_count >= threshold {
                state.status = TransactionStatus::Cancelled as u8;
            }
        }

        _ => return Err(MultisigError::InvalidStatus.into()),
    }

    state.invariant()
}
