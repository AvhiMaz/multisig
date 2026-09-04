//! Transaction proposal account.

use pinocchio::{Address, error::ProgramError};

use crate::{
    constants::{MAX_IX_ACCOUNTS, MAX_IX_DATA, MAX_OWNER},
    error::MultisigError,
    utils::{impl_len, impl_load},
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

/// One entry of the target instruction's account list.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct TxAccountMeta {
    /// Account address.
    pub address: Address,
    /// Non-zero if the target instruction needs this account to sign.
    pub is_signer: u8,
    /// Non-zero if the target instruction writes to this account.
    pub is_writable: u8,
}

impl_len!(TxAccountMeta);

/// A proposed instruction, its votes, and its lifecycle state.
///
/// Stored at the PDA `["transaction", multisig, index]`.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Transaction {
    /// Multisig this proposal belongs to. Checked on every vote and execution.
    pub multisig: Address,
    /// Owner who proposed it.
    pub creator: Address,
    /// Program the stored instruction invokes.
    pub target_program: Address,
    /// Position in the multisig's transaction sequence, and its PDA seed.
    pub index: u64,
    /// Owners who approved, strictly ascending. Keys, not bit positions, so a
    /// later change to the owner set cannot reassign a vote.
    pub approved: [Address; MAX_OWNER],
    /// Owners who rejected, strictly ascending.
    pub rejected: [Address; MAX_OWNER],
    /// Live entries in `approved`.
    pub approved_count: u8,
    /// Live entries in `rejected`.
    pub rejected_count: u8,
    /// Current [`TransactionStatus`], decoded via `from_u8`.
    pub status: u8,
    /// Cached PDA bump for this account.
    pub bump: u8,
    /// Live entries in `accounts`.
    pub account_count: u8,
    /// Which vault signs the CPI.
    pub vault_index: u8,
    /// Cached bump for that vault PDA.
    pub vault_bump: u8,
    /// Aligns `ix_data_len` to 4 bytes.
    pub _pad: [u8; 1],
    /// Live length of `ix_data`.
    pub ix_data_len: u32,
    /// Account list the target instruction expects, in order. Execution must
    /// match the passed accounts against this exactly.
    pub accounts: [TxAccountMeta; MAX_IX_ACCOUNTS],
    /// Target instruction payload, of which the first `ix_data_len` bytes are live.
    pub ix_data: [u8; MAX_IX_DATA],
    /// Unix time the proposal latched to `Approved`, or zero while `Active`.
    /// The multisig's time lock is measured from here.
    pub approved_at: i64,
}

impl_len!(Transaction);
impl_load!(Transaction);

impl Transaction {
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

    /// Whether `owner` has already voted either way.
    pub fn has_voted(&self, owner: &Address) -> bool {
        self.approvers().binary_search(owner).is_ok()
            || self.rejecters().binary_search(owner).is_ok()
    }

    /// Account list the target instruction expects.
    pub fn accounts(&self) -> &[TxAccountMeta] {
        &self.accounts[..self.account_count as usize]
    }

    /// Live target instruction payload.
    pub fn ix_data(&self) -> &[u8] {
        &self.ix_data[..self.ix_data_len as usize]
    }

    /// Asserts every rule the account must satisfy. Call after any mutation.
    pub fn invariant(&self) -> Result<(), ProgramError> {
        self.status()?;

        let approved = self.approved_count as usize;
        let rejected = self.rejected_count as usize;

        // A voter appears in at most one list, so the two together cannot
        // exceed the owner cap.
        if approved > MAX_OWNER || rejected > MAX_OWNER || approved + rejected > MAX_OWNER {
            return Err(MultisigError::InvalidAccountData.into());
        }

        // These bound the slices in `accounts` and `ix_data`, which would
        // otherwise panic on a corrupted account.
        if self.account_count as usize > MAX_IX_ACCOUNTS || self.ix_data_len as usize > MAX_IX_DATA
        {
            return Err(MultisigError::InvalidAccountData.into());
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

        Ok(())
    }
}
