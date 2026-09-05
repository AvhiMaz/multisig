//! Transaction proposal account.
//!
//! A fixed header, three vote bitmaps sized to the owner count at creation,
//! then the compiled message.
//!
//! # Layout
//!
//! ```text
//! header       112 bytes
//! approved     ceil(owners_count / 8)
//! rejected     ceil(owners_count / 8)
//! cancelled    ceil(owners_count / 8)
//! message      message_len
//! ```
//!
//! A vote is a bit at the owner's position. That names a voter safely because
//! a proposal only accepts votes while the owner set it was created against is
//! still current: any change to that set moves `stale_transaction_index` past
//! the proposal. `owners_count` is the snapshot the bitmaps are sized to.

use pinocchio::{Address, error::ProgramError};

use crate::{
    constants::{MAX_EPHEMERAL_SIGNERS, MAX_MESSAGE_SIZE, MAX_OWNER},
    error::MultisigError,
    state::bitmap,
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

/// The three vote bitmaps of a proposal.
pub struct Votes<'a> {
    /// Owners who approved.
    pub approved: &'a [u8],
    /// Owners who rejected.
    pub rejected: &'a [u8],
    /// Owners who voted to cancel after approval.
    pub cancelled: &'a [u8],
}

impl Votes<'_> {
    /// Whether the owner at `index` has voted any way.
    pub fn has_voted(&self, index: usize) -> bool {
        bitmap::get(self.approved, index)
            || bitmap::get(self.rejected, index)
            || bitmap::get(self.cancelled, index)
    }
}

/// Mutable counterpart of [`Votes`].
pub struct VotesMut<'a> {
    /// Owners who approved.
    pub approved: &'a mut [u8],
    /// Owners who rejected.
    pub rejected: &'a mut [u8],
    /// Owners who voted to cancel after approval.
    pub cancelled: &'a mut [u8],
}

impl VotesMut<'_> {
    /// Whether the owner at `index` has voted any way.
    pub fn has_voted(&self, index: usize) -> bool {
        bitmap::get(self.approved, index)
            || bitmap::get(self.rejected, index)
            || bitmap::get(self.cancelled, index)
    }
}

/// Fixed header of a proposal account.
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
    /// Owner count when this proposal was created, which sizes the bitmaps.
    pub owners_count: u32,
    /// Bits set in `approved`.
    pub approved_count: u32,
    /// Bits set in `rejected`.
    pub rejected_count: u32,
    /// Bits set in `cancelled`.
    pub cancelled_count: u32,
    /// Length of the compiled message.
    pub message_len: u32,
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
    /// Pads the header to a multiple of 8 bytes.
    pub _pad: [u8; 3],
}

impl Transaction {
    /// Size of the header in bytes.
    pub const LEN: usize = core::mem::size_of::<Self>();

    /// Account size for `owners` owners and a message of `message_len` bytes.
    pub fn space(owners: usize, message_len: usize) -> usize {
        Self::LEN + 3 * bitmap::len_for(owners) + message_len
    }

    fn check(data: &[u8]) -> Result<(), ProgramError> {
        if data.len() < Self::LEN
            || !(data.as_ptr() as usize).is_multiple_of(core::mem::align_of::<Self>())
        {
            return Err(MultisigError::InvalidAccountData.into());
        }

        Ok(())
    }

    /// Splits account data into the header, the vote bitmaps, and the message.
    pub fn load(data: &[u8]) -> Result<(&Self, Votes<'_>, &[u8]), ProgramError> {
        Self::check(data)?;

        let (header_bytes, tail) = data.split_at(Self::LEN);

        // SAFETY: length and alignment checked above; all padding is explicit.
        let header = unsafe { &*(header_bytes.as_ptr() as *const Self) };

        let bits = bitmap::len_for(header.owners_count as usize);

        if tail.len() != 3 * bits + header.message_len as usize {
            return Err(MultisigError::InvalidAccountData.into());
        }

        let (approved, rest) = tail.split_at(bits);
        let (rejected, rest) = rest.split_at(bits);
        let (cancelled, message) = rest.split_at(bits);

        Ok((
            header,
            Votes {
                approved,
                rejected,
                cancelled,
            },
            message,
        ))
    }

    /// Mutable counterpart of [`Self::load`].
    pub fn load_mut(data: &mut [u8]) -> Result<(&mut Self, VotesMut<'_>, &mut [u8]), ProgramError> {
        if data.len() < Self::LEN
            || !(data.as_mut_ptr() as usize).is_multiple_of(core::mem::align_of::<Self>())
        {
            return Err(MultisigError::InvalidAccountData.into());
        }

        let (header_bytes, tail) = data.split_at_mut(Self::LEN);

        // SAFETY: as in `load`; the exclusive reference rules out other borrows.
        let header = unsafe { &mut *(header_bytes.as_mut_ptr() as *mut Self) };

        let bits = bitmap::len_for(header.owners_count as usize);

        if tail.len() != 3 * bits + header.message_len as usize {
            return Err(MultisigError::InvalidAccountData.into());
        }

        let (approved, rest) = tail.split_at_mut(bits);
        let (rejected, rest) = rest.split_at_mut(bits);
        let (cancelled, message) = rest.split_at_mut(bits);

        Ok((
            header,
            VotesMut {
                approved,
                rejected,
                cancelled,
            },
            message,
        ))
    }

    /// Splits data whose header has not been written yet.
    ///
    /// Used only between creating the account and filling it in, when neither
    /// `owners_count` nor `message_len` can be trusted to describe the tail.
    pub fn split_uninitialized(data: &mut [u8]) -> Result<(&mut Self, &mut [u8]), ProgramError> {
        if data.len() < Self::LEN
            || !(data.as_mut_ptr() as usize).is_multiple_of(core::mem::align_of::<Self>())
        {
            return Err(MultisigError::InvalidAccountData.into());
        }

        let (header_bytes, tail) = data.split_at_mut(Self::LEN);

        // SAFETY: as in `load_mut`.
        let header = unsafe { &mut *(header_bytes.as_mut_ptr() as *mut Self) };

        Ok((header, tail))
    }

    /// Decoded status.
    pub fn status(&self) -> Result<TransactionStatus, ProgramError> {
        TransactionStatus::from_u8(self.status)
    }

    /// Cached bumps for this proposal's ephemeral signers.
    pub fn ephemeral_bumps(&self) -> &[u8] {
        &self.ephemeral_bumps[..self.ephemeral_count as usize]
    }

    /// Asserts every rule the header must satisfy. Constant time.
    pub fn invariant(&self) -> Result<(), ProgramError> {
        self.status()?;

        let owners = self.owners_count as usize;

        if owners == 0 || owners > MAX_OWNER {
            return Err(MultisigError::InvalidOwnerCount.into());
        }

        // Approving and rejecting are exclusive, so those two together cannot
        // exceed the owner count. Cancelling is counted apart, because an owner
        // who approved may later vote to cancel what they approved.
        let votes = self.approved_count as usize + self.rejected_count as usize;

        if votes > owners || self.cancelled_count as usize > owners {
            return Err(MultisigError::InvalidAccountData.into());
        }

        if self.message_len as usize > MAX_MESSAGE_SIZE {
            return Err(MultisigError::InvalidMessage.into());
        }

        if self.ephemeral_count as usize > MAX_EPHEMERAL_SIGNERS {
            return Err(MultisigError::InvalidAccountData.into());
        }

        Ok(())
    }
}
