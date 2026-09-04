//! Multisig configuration account.

use pinocchio::{Address, error::ProgramError};

use crate::{
    constants::{MAX_OWNER, MAX_TIME_LOCK},
    error::MultisigError,
    utils::{impl_len, impl_load},
};

/// Owner set, threshold, and transaction counters for one multisig.
///
/// Stored at the PDA `["multisig", create_key]`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Multisig {
    /// Ephemeral key seeding the PDA, so one wallet can create many multisigs.
    pub create_key: Address,
    /// Owner set, strictly ascending. Only the first `owners_count` entries are
    /// live; the rest are zeroed.
    pub owners: [Address; MAX_OWNER],
    /// Live entries in `owners`, in `1..=MAX_OWNER`.
    pub owners_count: u8,
    /// Approvals needed to execute, in `1..=owners_count`.
    pub threshold: u8,
    /// Cached PDA bump.
    pub bump: u8,
    /// Aligns `time_lock` to 4 bytes.
    pub _pad: [u8; 1],
    /// Seconds that must pass between a proposal being approved and executed.
    /// Zero disables the delay.
    pub time_lock: u32,
    /// Seeds the next transaction PDA. Never reused.
    pub transaction_index: u64,
    /// Transactions at or below this index predate the last change to the owner
    /// set or threshold, so they may no longer be voted on.
    pub stale_transaction_index: u64,
}

impl_len!(Multisig);
impl_load!(Multisig);

impl Multisig {
    /// Live owners, excluding zeroed trailing slots.
    pub fn owners(&self) -> &[Address] {
        &self.owners[..self.owners_count as usize]
    }

    /// Index of `owner` in [`Self::owners`], or `None` if not an owner.
    ///
    /// Relies on the ascending invariant, so it is a binary search.
    pub fn is_owner(&self, owner: &Address) -> Option<usize> {
        self.owners().binary_search(owner).ok()
    }

    /// Rejections that make approval unreachable.
    ///
    /// With `n` owners and threshold `t`, once `n - t + 1` have rejected, the
    /// owners left cannot reach `t`.
    pub fn cutoff(&self) -> u8 {
        self.owners_count.saturating_sub(self.threshold) + 1
    }

    /// Marks every existing transaction stale.
    ///
    /// Must be called by anything that changes `owners`, `owners_count`, or
    /// `threshold`, so approvals collected under the old rules cannot be
    /// extended under the new ones.
    pub fn invalidate_prior_transactions(&mut self) {
        self.stale_transaction_index = self.transaction_index;
    }

    /// Asserts every rule the account must satisfy. Call after any mutation.
    pub fn invariant(&self) -> Result<(), ProgramError> {
        let count = self.owners_count as usize;

        if count == 0 || count > MAX_OWNER {
            return Err(MultisigError::InvalidOwnerCount.into());
        }

        if self.threshold == 0 || self.threshold > self.owners_count {
            return Err(MultisigError::InvalidThreshold.into());
        }

        // Strictly ascending proves sorted and duplicate-free in one pass.
        for i in 1..count {
            if self.owners[i - 1] >= self.owners[i] {
                return Err(MultisigError::OwnersNotSorted.into());
            }
        }

        if self.stale_transaction_index > self.transaction_index {
            return Err(MultisigError::InvalidAccountData.into());
        }

        if self.time_lock > MAX_TIME_LOCK {
            return Err(MultisigError::InvalidTimeLock.into());
        }

        Ok(())
    }
}
