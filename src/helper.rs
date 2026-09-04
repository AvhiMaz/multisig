//! Checks shared across instructions.

use pinocchio::{AccountView, Address, error::ProgramError};

/// Returns `err` if `a` and `b` differ.
pub fn validate_eq<T: PartialEq>(a: T, b: T, err: ProgramError) -> Result<(), ProgramError> {
    if a != b { Err(err) } else { Ok(()) }
}

/// Returns `err` if the account did not sign.
pub fn check_signer(a: &AccountView, err: ProgramError) -> Result<(), ProgramError> {
    if !a.is_signer() { Err(err) } else { Ok(()) }
}

/// Returns `err` if the account is not owned by `program_id`.
///
/// Every caller-supplied state account needs this. Without it a forged account
/// created under another program parses as valid state.
pub fn check_owner(
    a: &AccountView,
    program_id: &Address,
    err: ProgramError,
) -> Result<(), ProgramError> {
    if a.owner() != program_id {
        Err(err)
    } else {
        Ok(())
    }
}
