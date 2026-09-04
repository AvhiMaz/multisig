//! Transaction proposal account.
//!
//! The account is a fixed header followed by a variable-length compiled
//! message, so a proposal costs rent for exactly the message it carries. That
//! rules out the `impl_load!` pattern the other state structs use, which
//! requires `data.len() == size_of::<Self>()`.

use pinocchio::{Address, error::ProgramError};

use crate::{
    constants::{MAX_EPHEMERAL_SIGNERS, MAX_MESSAGE_SIZE, MAX_OWNER},
    error::MultisigError,
};

/// Lifecycle of a proposal.
///
/// `Approved` is latched by the vote that crosses the threshold; execution
/// never recounts. Only `Active -> Approved | Rejected | Cancelled` and
/// `Approved -> Executed | Cancelled` are legal.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum TransactionStatus {
    /// Collecting votes.
    Active = 0,
    /// Threshold met; awaiting execution.
    Approved = 1,
    /// Enough rejections that approval is unreachable.
    Rejected = 2,
    /// Executed exactly once.
    Executed = 3,
    /// Abandoned before execution.
    Cancelled = 4,
}

impl TransactionStatus {
    /// Decodes a stored status byte, rejecting unknown values.
    ///
    /// Never transmute here: an out-of-range byte would be an invalid enum
    /// value and undefined behaviour.
    pub fn from_u8(v: u8) -> Result<Self, ProgramError> {
        match v {
            0 => Ok(Self::Active),
            1 => Ok(Self::Approved),
            2 => Ok(Self::Rejected),
            3 => Ok(Self::Executed),
            4 => Ok(Self::Cancelled),
            _ => Err(MultisigError::UnknownStatus.into()),
        }
    }
}

/// Fixed header of a proposal account. The compiled message follows it.
///
/// Stored at the PDA `["transaction", multisig, index]`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Transaction {
    /// Multisig this proposal belongs to. Checked on every vote and execution.
    pub multisig: Address,
    /// Owner who proposed it.
    pub creator: Address,
    /// Position in the multisig's transaction sequence, and its PDA seed.
    pub index: u64,
    /// Unix time the proposal latched to `Approved`, or zero while `Active`.
    /// The multisig's time lock is measured from here.
    pub approved_at: i64,
    /// Owners who approved, strictly ascending. Keys, not bit positions, so a
    /// later change to the owner set cannot reassign a vote.
    pub approved: [Address; MAX_OWNER],
    /// Owners who rejected, strictly ascending.
    pub rejected: [Address; MAX_OWNER],
    /// Owners who voted to cancel after approval, strictly ascending.
    pub cancelled: [Address; MAX_OWNER],
    /// Live entries in `approved`.
    pub approved_count: u8,
    /// Live entries in `rejected`.
    pub rejected_count: u8,
    /// Live entries in `cancelled`.
    pub cancelled_count: u8,
    /// Current [`TransactionStatus`], decoded via `from_u8`.
    pub status: u8,
    /// Cached PDA bump for this account.
    pub bump: u8,
    /// Which vault signs the CPIs.
    pub vault_index: u8,
    /// Cached bump for that vault PDA.
    pub vault_bump: u8,
    /// Ephemeral signer PDAs this proposal may sign with.
    pub ephemeral_count: u8,
    /// Cached bumps for those PDAs, positionally by index.
    pub ephemeral_bumps: [u8; MAX_EPHEMERAL_SIGNERS],
    /// Length of the compiled message following this header.
    pub message_len: u32,
}

impl Transaction {
    /// Size of the header in bytes. The account is this plus `message_len`.
    pub const LEN: usize = core::mem::size_of::<Self>();

    /// Account size needed to hold a message of `message_len` bytes.
    pub fn space(message_len: usize) -> usize {
        Self::LEN + message_len
    }

    /// Splits account data into the header and the message blob.
    ///
    /// # Errors
    ///
    /// Returns [`MultisigError::InvalidAccountData`] if the data is too short,
    /// misaligned, or its length disagrees with the header's `message_len`.
    pub fn load(data: &[u8]) -> Result<(&Self, &[u8]), ProgramError> {
        if data.len() < Self::LEN
            || !(data.as_ptr() as usize).is_multiple_of(core::mem::align_of::<Self>())
        {
            return Err(MultisigError::InvalidAccountData.into());
        }

        let (header_bytes, message) = data.split_at(Self::LEN);

        // SAFETY: length and alignment checked above; all padding is explicit.
        let header = unsafe { &*(header_bytes.as_ptr() as *const Self) };

        if header.message_len as usize != message.len() {
            return Err(MultisigError::InvalidAccountData.into());
        }

        Ok((header, message))
    }

    /// Mutable counterpart of [`Self::load`].
    ///
    /// # Errors
    ///
    /// Same conditions as [`Self::load`].
    pub fn load_mut(data: &mut [u8]) -> Result<(&mut Self, &mut [u8]), ProgramError> {
        if data.len() < Self::LEN
            || !(data.as_mut_ptr() as usize).is_multiple_of(core::mem::align_of::<Self>())
        {
            return Err(MultisigError::InvalidAccountData.into());
        }

        let (header_bytes, message) = data.split_at_mut(Self::LEN);

        // SAFETY: as in `load`; the exclusive reference rules out other borrows.
        let header = unsafe { &mut *(header_bytes.as_mut_ptr() as *mut Self) };

        if header.message_len as usize != message.len() {
            return Err(MultisigError::InvalidAccountData.into());
        }

        Ok((header, message))
    }

    /// Splits data whose header has not been written yet.
    ///
    /// Used only by `create_transaction`, between creating the account and
    /// filling it in, when `message_len` cannot yet be trusted.
    pub fn split_uninitialized(data: &mut [u8]) -> Result<(&mut Self, &mut [u8]), ProgramError> {
        if data.len() < Self::LEN
            || !(data.as_mut_ptr() as usize).is_multiple_of(core::mem::align_of::<Self>())
        {
            return Err(MultisigError::InvalidAccountData.into());
        }

        let (header_bytes, message) = data.split_at_mut(Self::LEN);

        // SAFETY: as in `load_mut`.
        let header = unsafe { &mut *(header_bytes.as_mut_ptr() as *mut Self) };

        Ok((header, message))
    }

    /// Decoded status.
    pub fn status(&self) -> Result<TransactionStatus, ProgramError> {
        TransactionStatus::from_u8(self.status)
    }

    /// Owners who have approved.
    pub fn approvers(&self) -> &[Address] {
        &self.approved[..self.approved_count as usize]
    }

    /// Owners who have rejected.
    pub fn rejecters(&self) -> &[Address] {
        &self.rejected[..self.rejected_count as usize]
    }

    /// Owners who have voted to cancel.
    pub fn cancellers(&self) -> &[Address] {
        &self.cancelled[..self.cancelled_count as usize]
    }

    /// Cached bumps for this proposal's ephemeral signers.
    pub fn ephemeral_bumps(&self) -> &[u8] {
        &self.ephemeral_bumps[..self.ephemeral_count as usize]
    }

    /// Whether `owner` has already voted either way.
    pub fn has_voted(&self, owner: &Address) -> bool {
        self.approvers().binary_search(owner).is_ok()
            || self.rejecters().binary_search(owner).is_ok()
    }

    /// Asserts every rule the header must satisfy. Call after any mutation.
    pub fn invariant(&self) -> Result<(), ProgramError> {
        self.status()?;

        let approved = self.approved_count as usize;
        let rejected = self.rejected_count as usize;

        // A voter appears in at most one list, so the two together cannot
        // exceed the owner cap.
        if approved > MAX_OWNER || rejected > MAX_OWNER || approved + rejected > MAX_OWNER {
            return Err(MultisigError::InvalidAccountData.into());
        }

        if self.cancelled_count as usize > MAX_OWNER
            || self.ephemeral_count as usize > MAX_EPHEMERAL_SIGNERS
        {
            return Err(MultisigError::InvalidAccountData.into());
        }

        if self.message_len as usize > MAX_MESSAGE_SIZE {
            return Err(MultisigError::InvalidMessage.into());
        }

        // Strictly ascending proves sorted and duplicate-free in one pass, and
        // duplicates would let one owner count twice toward the threshold.
        for i in 1..approved {
            if self.approved[i - 1] >= self.approved[i] {
                return Err(MultisigError::AlreadyVoted.into());
            }
        }
        for i in 1..rejected {
            if self.rejected[i - 1] >= self.rejected[i] {
                return Err(MultisigError::AlreadyVoted.into());
            }
        }
        for i in 1..self.cancelled_count as usize {
            if self.cancelled[i - 1] >= self.cancelled[i] {
                return Err(MultisigError::AlreadyVoted.into());
            }
        }

        Ok(())
    }
}
