//! Multisig configuration account.
//!
//! A fixed header followed by the owner set, so the account is exactly as large
//! as the number of owners it holds and grows as owners are added. That rules
//! out the `impl_load!` pattern, which requires a size known at compile time.
//!
//! # Layout
//!
//! ```text
//! header        144 bytes
//! owners        32 * owners_count, strictly ascending
//! permissions   1 * owners_count, positionally matching owners
//! ```

use pinocchio::{Address, error::ProgramError};

use crate::{
    constants::{MAX_OWNER, MAX_TIME_LOCK},
    error::MultisigError,
    state::permission::Permission,
};

/// Fixed header of a multisig account. The owner set follows it.
///
/// Stored at the PDA `["multisig", create_key]`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Multisig {
    /// Ephemeral key seeding the PDA, so one wallet can create many multisigs.
    pub create_key: Address,
    /// Key permitted to change the configuration without a vote.
    ///
    /// The default address means the multisig is autonomous: every change goes
    /// through propose, approve, execute like any spend. Set to anything else
    /// it is controlled, and that key alone decides its configuration. That is
    /// a large amount of trust, and the field exists so a dao or another
    /// program can hold it, not so a person can shortcut their own multisig.
    pub config_authority: Address,
    /// Where reclaimed rent goes when a proposal or buffer is closed. The
    /// default address means "refund whoever paid".
    pub rent_collector: Address,
    /// Seeds the next transaction PDA. Never reused.
    pub transaction_index: u64,
    /// Transactions at or below this index predate the last change to the owner
    /// set or threshold, so they may no longer be voted on.
    pub stale_transaction_index: u64,
    /// Proposals closed so far. When this is one behind `transaction_index`,
    /// the only proposal still open is the one currently executing.
    pub closed_transaction_count: u64,
    /// Seconds that must pass between a proposal being approved and executed.
    /// Zero disables the delay.
    pub time_lock: u32,
    /// Live entries in the owner set.
    pub owners_count: u32,
    /// Owners permitted to vote. Kept in step as owners and permissions change,
    /// so no operation has to walk the set to learn it.
    pub voter_count: u32,
    /// Approvals needed to execute, in `1..=voter_count`.
    pub threshold: u32,
    /// Cached PDA bump.
    pub bump: u8,
    /// Pads the header to a multiple of 8 bytes.
    pub _pad: [u8; 7],
}

impl Multisig {
    /// Size of the header in bytes.
    pub const LEN: usize = core::mem::size_of::<Self>();

    /// Account size needed to hold `owners` owners.
    pub fn space(owners: usize) -> usize {
        Self::LEN + owners * 33
    }

    fn split_parts(data: &[u8]) -> Result<(&Self, &[u8]), ProgramError> {
        if data.len() < Self::LEN
            || !(data.as_ptr() as usize).is_multiple_of(core::mem::align_of::<Self>())
        {
            return Err(MultisigError::InvalidAccountData.into());
        }

        let (header_bytes, tail) = data.split_at(Self::LEN);

        // SAFETY: length and alignment checked above; all padding is explicit.
        let header = unsafe { &*(header_bytes.as_ptr() as *const Self) };

        if tail.len() != header.owners_count as usize * 33 {
            return Err(MultisigError::InvalidAccountData.into());
        }

        Ok((header, tail))
    }

    /// Splits account data into the header, the owner addresses, and the
    /// permission bytes.
    pub fn load(data: &[u8]) -> Result<(&Self, &[Address], &[u8]), ProgramError> {
        let (header, tail) = Self::split_parts(data)?;
        let count = header.owners_count as usize;

        let (owner_bytes, permissions) = tail.split_at(count * 32);

        // SAFETY: `Address` is `#[repr(transparent)]` over `[u8; 32]`, so it
        // has alignment 1 and every byte pattern is valid. The slice length was
        // checked to be exactly `count * 32`.
        let owners =
            unsafe { core::slice::from_raw_parts(owner_bytes.as_ptr() as *const Address, count) };

        Ok((header, owners, permissions))
    }

    /// Mutable counterpart of [`Self::load`].
    pub fn load_mut(
        data: &mut [u8],
    ) -> Result<(&mut Self, &mut [Address], &mut [u8]), ProgramError> {
        if data.len() < Self::LEN
            || !(data.as_mut_ptr() as usize).is_multiple_of(core::mem::align_of::<Self>())
        {
            return Err(MultisigError::InvalidAccountData.into());
        }

        let (header_bytes, tail) = data.split_at_mut(Self::LEN);

        // SAFETY: as in `load`; the exclusive reference rules out other borrows.
        let header = unsafe { &mut *(header_bytes.as_mut_ptr() as *mut Self) };

        let count = header.owners_count as usize;

        if tail.len() != count * 33 {
            return Err(MultisigError::InvalidAccountData.into());
        }

        let (owner_bytes, permissions) = tail.split_at_mut(count * 32);

        // SAFETY: as above.
        let owners = unsafe {
            core::slice::from_raw_parts_mut(owner_bytes.as_mut_ptr() as *mut Address, count)
        };

        Ok((header, owners, permissions))
    }

    /// Splits data whose header has not been written yet.
    ///
    /// Used between creating or resizing an account and filling it in, when
    /// `owners_count` cannot yet be trusted to describe the tail.
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

    /// Index of `owner` in the owner set, or `None`.
    ///
    /// Relies on the ascending invariant, so it is a binary search: twelve
    /// comparisons at the maximum owner count.
    pub fn is_owner(owners: &[Address], owner: &Address) -> Option<usize> {
        owners.binary_search(owner).ok()
    }

    /// Whether `owner` holds `permission`.
    ///
    /// A mask of zero is read as full permission, so a multisig that does not
    /// use permissions behaves as every owner being able to do everything.
    pub fn has_permission(
        owners: &[Address],
        permissions: &[u8],
        owner: &Address,
        permission: u8,
    ) -> bool {
        match Self::is_owner(owners, owner) {
            Some(index) => {
                let mask = permissions[index];
                mask == 0 || mask & permission != 0
            }
            None => false,
        }
    }

    /// Whether a permission mask permits voting.
    pub fn mask_can_vote(mask: u8) -> bool {
        mask == 0 || mask & Permission::VOTE != 0
    }

    /// Rejections that make approval unreachable.
    ///
    /// With `n` voters and threshold `t`, once `n - t + 1` have rejected, the
    /// voters left cannot reach `t`.
    pub fn cutoff(&self) -> u32 {
        self.voter_count.saturating_sub(self.threshold) + 1
    }

    /// Whether every proposal ever created has been closed.
    ///
    /// The condition for closing through the config authority, where no
    /// proposal is executing to be excluded.
    pub fn all_transactions_closed(&self) -> bool {
        self.closed_transaction_count == self.transaction_index
    }

    /// Whether this multisig answers to a config authority.
    pub fn is_controlled(&self) -> bool {
        self.config_authority != Address::default()
    }

    /// Whether the only proposal still open is the one currently executing.
    ///
    /// A close action rides inside a proposal, and that proposal is necessarily
    /// still open while it runs, so it is excluded from the count.
    pub fn only_executing_transaction_open(&self) -> bool {
        self.closed_transaction_count.checked_add(1) == Some(self.transaction_index)
    }

    /// Marks every existing transaction stale.
    ///
    /// Must be called by anything that changes the owner set, the permissions
    /// or the threshold. Votes are recorded by owner position, so a proposal
    /// carried across such a change would read its bitmap against a different
    /// set of people.
    pub fn invalidate_prior_transactions(&mut self) {
        self.stale_transaction_index = self.transaction_index;
    }

    /// Asserts every rule the header must satisfy.
    ///
    /// Constant time, because it runs on every mutation and the owner set can
    /// hold thousands. Ordering is not checked here for the same reason: it is
    /// verified at the one or two positions an insertion or removal disturbs.
    pub fn invariant(&self) -> Result<(), ProgramError> {
        let count = self.owners_count as usize;

        if count == 0 || count > MAX_OWNER {
            return Err(MultisigError::InvalidOwnerCount.into());
        }

        if self.voter_count == 0 {
            return Err(MultisigError::NoVoters.into());
        }

        if self.voter_count > self.owners_count {
            return Err(MultisigError::InvalidAccountData.into());
        }

        if self.threshold == 0 || self.threshold > self.voter_count {
            return Err(MultisigError::InvalidThreshold.into());
        }

        if self.stale_transaction_index > self.transaction_index
            || self.closed_transaction_count > self.transaction_index
        {
            return Err(MultisigError::InvalidAccountData.into());
        }

        if self.time_lock > MAX_TIME_LOCK {
            return Err(MultisigError::InvalidTimeLock.into());
        }

        Ok(())
    }
}
