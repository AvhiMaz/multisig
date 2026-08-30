//! Multisig configuration account.

use pinocchio::Address;
use pinocchio::error::ProgramError;

use crate::constants::MAX_OWNER;

/// Owner set, threshold, and transaction counter for one multisig.
///
/// Stored at the PDA `["multisig", creator]`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Multisig {
    /// Creator, and the PDA seed, so a wallet owns at most one multisig.
    pub creator: Address,
    /// Owner set. Only the first `owners_count` entries are live; the rest are zeroed.
    pub owners: [Address; MAX_OWNER],
    /// Live entries in `owners`, in `1..=MAX_OWNER`.
    pub owners_count: u8,
    /// Approvals needed to execute, in `1..=owners_count`.
    pub threshold: u8,
    /// Cached PDA bump.
    pub bump: u8,
    /// Aligns `transaction_index` to 8 bytes.
    pub _pad: [u8; 5],
    /// Seeds the next transaction PDA. Never reused.
    pub transaction_index: u64,
}

impl Multisig {
    /// Size of the account in bytes.
    pub const LEN: usize = core::mem::size_of::<Self>();

    /// Reads account data as a [`Multisig`], checking length and alignment.
    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() != Self::LEN
            || !(data.as_ptr() as usize).is_multiple_of(core::mem::align_of::<Self>())
        {
            Err(ProgramError::AccountDataTooSmall)
        } else {
            // SAFETY: length and alignment checked above; all padding is explicit.
            Ok(unsafe { &*(data.as_ptr() as *const Self) })
        }
    }

    /// Mutable counterpart of [`Self::load`].
    pub fn load_mut(data: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if data.len() != Self::LEN
            || !(data.as_mut_ptr() as usize).is_multiple_of(core::mem::align_of::<Self>())
        {
            Err(ProgramError::AccountDataTooSmall)
        } else {
            // SAFETY: as in `load`; the exclusive reference rules out other borrows.
            Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
        }
    }

    /// Live owners, excluding zeroed trailing slots.
    pub fn owners(&self) -> &[Address] {
        &self.owners[..self.owners_count as usize]
    }
}
