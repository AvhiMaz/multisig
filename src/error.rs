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
    /// Threshold is zero or exceeds the number of owners permitted to vote.
    InvalidThreshold = 9,
    /// The owner list is not strictly ascending, so it is unsorted or has a duplicate.
    OwnersNotSorted = 10,
    /// The signer is not an owner of this multisig.
    NotAnOwner = 11,
    /// This owner has already voted on the transaction.
    AlreadyVoted = 12,
    /// The transaction predates the last change to the owner set, the
    /// permissions or the threshold.
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
    /// The compiled transaction message is malformed or references an
    /// out-of-range account index.
    InvalidMessage = 23,
    /// An inner instruction references more accounts than a CPI may carry.
    TooManyAccounts = 24,
    /// The buffer has not received every byte it committed to.
    BufferIncomplete = 25,
    /// The buffer's contents do not match the hash committed at creation.
    BufferHashMismatch = 26,
    /// A lookup table account is malformed or an index runs past its addresses.
    InvalidLookupTable = 27,
    /// An owner carries a permission bit this program does not define.
    UnknownPermission = 28,
    /// No owner is permitted to vote, which would brick the multisig.
    NoVoters = 29,
    /// The signer lacks the permission this instruction requires.
    Unauthorized = 30,
    /// Proposals remain unclosed, so closing the multisig would strand them.
    TransactionsOutstanding = 31,
    /// The multisig is autonomous, so it has no config authority to act on.
    NotControlled = 32,
}

impl From<MultisigError> for ProgramError {
    fn from(e: MultisigError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
