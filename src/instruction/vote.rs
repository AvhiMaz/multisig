//! Shared vote plumbing.
//!
//! `approve`, `reject` and `cancel` differ only in which bitmap they set and
//! what latches the status, so the accounts, the guards and the lookup of the
//! voter's position live here.

use pinocchio::{AccountView, Address, ProgramResult};

use crate::{
    error::MultisigError,
    helper::{check_owner, check_signer, validate_eq},
    state::{
        multisig::Multisig,
        permission::Permission,
        transaction::{Transaction, TransactionStatus},
    },
};

/// What a vote handler needs from the multisig.
pub struct Voter {
    /// The voter's position in the owner set, which is its bit index.
    pub index: usize,
    /// Approvals needed to execute.
    pub threshold: u32,
    /// Rejections that make approval unreachable.
    pub cutoff: u32,
    /// Owner count, which must match the proposal's snapshot.
    pub owners_count: u32,
    /// Proposals at or below this index may no longer be voted on.
    pub stale_index: u64,
    /// Whether this owner holds the vote permission.
    pub can_vote: bool,
}

/// Validates the accounts common to every vote and locates the voter.
///
/// `require_vote_permission` is false for the creator-cancel path, which is
/// authorized by having created the proposal rather than by holding the vote
/// permission.
pub fn prepare(
    program_id: &Address,
    signer: &AccountView,
    multisig: &AccountView,
    transaction: &AccountView,
    instruction: &[u8],
    require_vote_permission: bool,
) -> Result<Voter, pinocchio::error::ProgramError> {
    if !instruction.is_empty() {
        return Err(MultisigError::InvalidInstructionData.into());
    }

    check_signer(signer, MultisigError::MissingSignature.into())?;
    check_owner(multisig, program_id, MultisigError::IllegalOwner.into())?;
    check_owner(transaction, program_id, MultisigError::IllegalOwner.into())?;

    // SAFETY: read-only borrow, released with this scope.
    let multisig_data = unsafe { multisig.borrow_unchecked() };
    let (ms, owners, permissions) = Multisig::load(multisig_data)?;

    let index = Multisig::is_owner(owners, signer.address()).ok_or(MultisigError::NotAnOwner)?;

    if require_vote_permission && !Multisig::mask_can_vote(permissions[index]) {
        return Err(MultisigError::Unauthorized.into());
    }

    Ok(Voter {
        index,
        can_vote: Multisig::mask_can_vote(permissions[index]),
        threshold: ms.threshold,
        cutoff: ms.cutoff(),
        owners_count: ms.owners_count,
        stale_index: ms.stale_transaction_index,
    })
}

/// Checks a proposal belongs to this multisig, is still votable, and was
/// created against the same owner set the voter was found in.
pub fn check_votable(
    state: &Transaction,
    multisig: &AccountView,
    voter: &Voter,
    expected: TransactionStatus,
) -> ProgramResult {
    validate_eq(
        &state.multisig,
        multisig.address(),
        MultisigError::MultisigMismatch.into(),
    )?;

    if state.status()? != expected {
        return Err(MultisigError::InvalidStatus.into());
    }

    // Votes are bits at an owner's position, so a proposal gathered against a
    // different owner set must not accept more.
    if state.index <= voter.stale_index {
        return Err(MultisigError::StaleTransaction.into());
    }

    if state.owners_count != voter.owners_count {
        return Err(MultisigError::StaleTransaction.into());
    }

    Ok(())
}

/// Marks a proposal `Approved` and stamps when the time lock starts running.
pub fn latch_approved(state: &mut Transaction, now: i64) {
    state.status = TransactionStatus::Approved as u8;
    state.approved_at = now;
}

/// Convenience for the permission a vote handler requires.
pub const VOTE: u8 = Permission::VOTE;
