//! Close a finished proposal and reclaim its rent.
//!
//! Permitted for any caller, because the outcome is fixed by stored state:
//! the account is closed and its lamports go to the multisig's rent collector,
//! or to whoever paid when none is set. Leaving finished proposals open would
//! strand their rent forever.
//!
//! # Accounts
//!
//! 0. `transaction` - writable, the proposal being closed
//! 1. `multisig`    - writable; names the rent collector and counts closures
//! 2. `destination` - writable, receives the rent

use pinocchio::{AccountView, Address, ProgramResult};

use crate::{
    error::MultisigError,
    helper::{check_owner, validate_eq},
    state::{
        multisig::Multisig,
        transaction::{Transaction, TransactionStatus},
    },
};

/// Closes a terminal proposal, refunding its rent to `destination`.
pub fn process_close_transaction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction: &[u8],
) -> ProgramResult {
    let [transaction, multisig, destination, _remaining @ ..] = accounts else {
        return Err(MultisigError::NotEnoughAccounts.into());
    };

    if !instruction.is_empty() {
        return Err(MultisigError::InvalidInstructionData.into());
    }

    check_owner(transaction, program_id, MultisigError::IllegalOwner.into())?;
    check_owner(multisig, program_id, MultisigError::IllegalOwner.into())?;

    let rent_collector = {
        // SAFETY: the only live borrow at this point.
        let multisig_data = unsafe { multisig.borrow_unchecked_mut() };
        let (ms, _, _) = Multisig::load_mut(multisig_data)?;

        // Counting closures is what lets `close_multisig` know later that
        // nothing is left outstanding.
        ms.closed_transaction_count = ms
            .closed_transaction_count
            .checked_add(1)
            .ok_or(MultisigError::Overflow)?;

        ms.invariant()?;

        ms.rent_collector
    };

    {
        // SAFETY: read-only borrow, released before the account is closed so
        // `close` does not see it as borrowed.
        let transaction_data = unsafe { transaction.borrow_unchecked() };
        let (state, _, _) = Transaction::load(transaction_data)?;

        validate_eq(
            &state.multisig,
            multisig.address(),
            MultisigError::MultisigMismatch.into(),
        )?;

        // Rent goes where the multisig says, and to whoever paid when it says
        // nothing. Either way the destination is fixed by stored state, which
        // is why this instruction needs no signer.
        let expected = if rent_collector == Address::default() {
            state.creator
        } else {
            rent_collector
        };

        validate_eq(
            &expected,
            destination.address(),
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

    let credited = destination
        .lamports()
        .checked_add(refund)
        .ok_or(MultisigError::Overflow)?;

    destination.set_lamports(credited);
    transaction.set_lamports(0);
    transaction.close()
}
