//! Transaction buffer account.
//!
//! A compiled message larger than one Solana transaction is uploaded in chunks
//! into a buffer, then turned into a proposal in a final step. The buffer
//! commits up front to the message's length and hash, so the content that
//! becomes a proposal is the content the creator intended.

use pinocchio::{Address, error::ProgramError};

use crate::{constants::MAX_MESSAGE_SIZE, error::MultisigError};

/// Fixed header of a buffer account. The partial message follows it.
///
/// Stored at the PDA `["buffer", multisig, creator, buffer_index]`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TransactionBuffer {
    /// Multisig the eventual proposal will belong to.
    pub multisig: Address,
    /// Owner uploading the message, and the only account that may extend or
    /// close this buffer.
    pub creator: Address,
    /// SHA-256 of the completed message, committed at creation.
    pub final_hash: [u8; 32],
    /// Length the completed message will have.
    pub final_size: u32,
    /// Bytes written so far.
    pub written: u32,
    /// Distinguishes concurrent buffers from the same creator.
    pub buffer_index: u8,
    /// Which vault the eventual proposal will spend from.
    pub vault_index: u8,
    /// Cached PDA bump for this account.
    pub bump: u8,
    /// Pads the header to a 4-byte boundary.
    pub _pad: [u8; 5],
}

impl TransactionBuffer {
    /// Size of the header in bytes. The account is this plus `final_size`.
    pub const LEN: usize = core::mem::size_of::<Self>();

    /// Account size needed to hold a message of `final_size` bytes.
    pub fn space(final_size: usize) -> usize {
        Self::LEN + final_size
    }

    /// Splits account data into the header and the message region.
    pub fn load(data: &[u8]) -> Result<(&Self, &[u8]), ProgramError> {
        if data.len() < Self::LEN
            || !(data.as_ptr() as usize).is_multiple_of(core::mem::align_of::<Self>())
        {
            return Err(MultisigError::InvalidAccountData.into());
        }

        let (header_bytes, buffer) = data.split_at(Self::LEN);

        // SAFETY: length and alignment checked above; all padding is explicit.
        let header = unsafe { &*(header_bytes.as_ptr() as *const Self) };

        if header.final_size as usize != buffer.len() {
            return Err(MultisigError::InvalidAccountData.into());
        }

        Ok((header, buffer))
    }

    /// Mutable counterpart of [`Self::load`].
    pub fn load_mut(data: &mut [u8]) -> Result<(&mut Self, &mut [u8]), ProgramError> {
        if data.len() < Self::LEN
            || !(data.as_mut_ptr() as usize).is_multiple_of(core::mem::align_of::<Self>())
        {
            return Err(MultisigError::InvalidAccountData.into());
        }

        let (header_bytes, buffer) = data.split_at_mut(Self::LEN);

        // SAFETY: as in `load`; the exclusive reference rules out other borrows.
        let header = unsafe { &mut *(header_bytes.as_mut_ptr() as *mut Self) };

        if header.final_size as usize != buffer.len() {
            return Err(MultisigError::InvalidAccountData.into());
        }

        Ok((header, buffer))
    }

    /// Splits data whose header has not been written yet.
    pub fn split_uninitialized(data: &mut [u8]) -> Result<(&mut Self, &mut [u8]), ProgramError> {
        if data.len() < Self::LEN
            || !(data.as_mut_ptr() as usize).is_multiple_of(core::mem::align_of::<Self>())
        {
            return Err(MultisigError::InvalidAccountData.into());
        }

        let (header_bytes, buffer) = data.split_at_mut(Self::LEN);

        // SAFETY: as in `load_mut`.
        let header = unsafe { &mut *(header_bytes.as_mut_ptr() as *mut Self) };

        Ok((header, buffer))
    }

    /// Whether every byte the buffer promised has been written.
    pub fn is_complete(&self) -> bool {
        self.written == self.final_size
    }

    /// Asserts every rule the header must satisfy. Call after any mutation.
    pub fn invariant(&self) -> Result<(), ProgramError> {
        if self.final_size as usize > MAX_MESSAGE_SIZE || self.written > self.final_size {
            return Err(MultisigError::InvalidMessage.into());
        }

        Ok(())
    }
}
