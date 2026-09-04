//! Multisig configuration account.

use pinocchio::{Address, error::ProgramError};

use crate::{
    constants::{MAX_OWNER, MAX_TIME_LOCK},
    error::MultisigError,
    state::permission::Permission,
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
    /// Where reclaimed rent goes when a proposal or buffer is closed. The
    /// default address means "refund whoever paid".
    pub rent_collector: Address,
    /// Owner set, strictly ascending. Only the first `owners_count` entries are
    /// live; the rest are zeroed.
    pub owners: [Address; MAX_OWNER],
    /// Permission mask per owner, positionally matching `owners`.
    pub permissions: [u8; MAX_OWNER],
    /// Live entries in `owners`, in `1..=MAX_OWNER`.
    pub owners_count: u8,
    /// Approvals needed to execute, in `1..=owners_count`.
    pub threshold: u8,
    /// Cached PDA bump.
    pub bump: u8,
    /// Aligns `time_lock` to 4 bytes.
    pub _pad: [u8; 3],
    /// Seconds that must pass between a proposal being approved and executed.
    /// Zero disables the delay.
    pub time_lock: u32,
    /// Aligns `transaction_index` to 8 bytes.
    pub _pad2: [u8; 4],
    /// Seeds the next transaction PDA. Never reused.
    pub transaction_index: u64,
    /// Transactions at or below this index predate the last change to the owner
    /// set or threshold, so they may no longer be voted on.
    pub stale_transaction_index: u64,
    /// Proposals closed so far. When this reaches `transaction_index` every
    /// proposal ever created has been reclaimed, which is the only way to know
    /// on-chain that closing the multisig strands nothing.
    pub closed_transaction_count: u64,
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

    /// Whether `owner` holds `permission`.
    ///
    /// A mask of zero is read as full permission, so a multisig created before
    /// permissions existed, or one that simply does not use them, behaves as
    /// every owner being able to do everything.
    pub fn has_permission(&self, owner: &Address, permission: u8) -> bool {
        match self.is_owner(owner) {
            Some(index) => {
                let mask = self.permissions[index];
                mask == 0 || mask & permission != 0
            }
            None => false,
        }
    }

    /// Whether the only proposal still open is the one currently executing.
    ///
    /// A close action rides inside a proposal, and that proposal is necessarily
    /// still open while it runs, so it is excluded from the count. Comparing
    /// against `transaction_index` directly would never hold and would make
    /// closing impossible.
    pub fn only_executing_transaction_open(&self) -> bool {
        self.closed_transaction_count.checked_add(1) == Some(self.transaction_index)
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

        if self.stale_transaction_index > self.transaction_index
            || self.closed_transaction_count > self.transaction_index
        {
            return Err(MultisigError::InvalidAccountData.into());
        }

        if self.time_lock > MAX_TIME_LOCK {
            return Err(MultisigError::InvalidTimeLock.into());
        }

        // Permissions live outside the enum's bits only if a client invented
        // one, which would silently grant nothing.
        for mask in &self.permissions[..count] {
            if *mask > Permission::ALL {
                return Err(MultisigError::UnknownPermission.into());
            }
        }

        // A multisig nobody can vote in is bricked.
        if !self
            .owners()
            .iter()
            .any(|o| self.has_permission(o, Permission::VOTE))
        {
            return Err(MultisigError::NoVoters.into());
        }

        Ok(())
    }
}
