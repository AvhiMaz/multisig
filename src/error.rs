//! Program error codes.

use pinocchio::error::ProgramError;

/// Errors returned by the multisig program.
#[repr(u8)]
#[derive(Clone, Copy)]
pub enum MultisigError {
    /// Fewer accounts were passed than the instruction requires.
    NotEnoughAccounts = 0,
    /// Account data has the wrong length or alignment for its layout.
    InvalidAccountData = 1,
    /// An account is not owned by this program.
    IllegalOwner = 2,
    /// A required signature is missing.
    MissingSignature = 3,
    /// An account is not the one the instruction expected.
    InvalidAccount = 4,
    /// A program account is not the program it should be.
    InvalidProgramId = 5,
    /// The account already holds data or lamports.
    AlreadyInitialized = 6,
    /// The instruction payload is malformed.
    InvalidInstructionData = 7,
    /// Owner count is zero or above `MAX_OWNER`.
    InvalidOwnerCount = 8,
    /// Threshold is zero or exceeds the owner count.
    InvalidThreshold = 9,
    /// The owner list is not strictly ascending, so it is unsorted or has a duplicate.
    OwnersNotSorted = 10,
    /// The signer is not an owner of this multisig.
    NotAnOwner = 11,
    /// This owner has already voted on the transaction.
    AlreadyVoted = 12,
    /// The transaction predates the last owner or threshold change.
    StaleTransaction = 13,
    /// The transaction's status does not permit this action.
    InvalidStatus = 14,
    /// A stored status byte does not decode to a known variant.
    UnknownStatus = 15,
    /// The transaction does not belong to the given multisig.
    MultisigMismatch = 16,
    /// The accounts passed do not match those recorded in the transaction.
    AccountMismatch = 17,
    /// An arithmetic operation overflowed.
    Overflow = 18,
    /// The address is already an owner of this multisig.
    OwnerAlreadyExists = 19,
    /// A self-targeted proposal carries an unknown config action byte.
    UnknownConfigAction = 20,
    /// The time lock exceeds `MAX_TIME_LOCK`.
    InvalidTimeLock = 21,
    /// The multisig's time lock has not elapsed since approval.
    TimeLockNotReleased = 22,
}

impl From<MultisigError> for ProgramError {
    fn from(e: MultisigError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
