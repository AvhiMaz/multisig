//! Owner-management actions.
//!
//! Not reachable from the entrypoint. They ride inside `ix_data` on a proposal
//! targeting this program, so changing the owner set costs the same threshold
//! of approvals as spending from the vault.

use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};

use crate::{
    constants::MAX_OWNER, error::MultisigError, helper::validate_eq, state::multisig::Multisig,
};

/// Action encoded in the first byte of a self-targeted proposal's `ix_data`.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ConfigAction {
    /// Add an owner. Payload is the 32-byte address.
    AddOwner = 0,
    /// Remove an owner. Payload is the 32-byte address.
    RemoveOwner = 1,
    /// Change the approval threshold. Payload is one byte.
    ChangeThreshold = 2,
    /// Change the execution delay. Payload is a little-endian `u32`.
    ChangeTimeLock = 3,
    /// Set where reclaimed rent goes. Payload is the 32-byte address; the
    /// default address restores "refund whoever paid".
    SetRentCollector = 4,
    /// Set one owner's permission mask. Payload is the 32-byte address followed
    /// by the mask byte.
    SetPermission = 5,
    /// Close the multisig and reclaim its rent. No payload.
    CloseMultisig = 6,
}

impl ConfigAction {
    /// Decodes an action byte, rejecting unknown values.
    pub fn from_u8(v: u8) -> Result<Self, ProgramError> {
        match v {
            0 => Ok(Self::AddOwner),
            1 => Ok(Self::RemoveOwner),
            2 => Ok(Self::ChangeThreshold),
            3 => Ok(Self::ChangeTimeLock),
            4 => Ok(Self::SetRentCollector),
            5 => Ok(Self::SetPermission),
            6 => Ok(Self::CloseMultisig),
            _ => Err(MultisigError::UnknownConfigAction.into()),
        }
    }
}

/// Applies a config action to `multisig`.
pub fn apply_config_action(
    multisig: &mut AccountView,
    destination: &mut AccountView,
    data: &[u8],
) -> ProgramResult {
    let (tag, payload) = data
        .split_first()
        .ok_or(MultisigError::InvalidInstructionData)?;

    let action = ConfigAction::from_u8(*tag)?;

    // Closing ends the account, so it cannot run the invalidate-and-check tail
    // the other actions share: there would be nothing left to check.
    if action == ConfigAction::CloseMultisig {
        return close_multisig(multisig, destination, payload);
    }

    // SAFETY: the transaction account's borrow was released before this call,
    // so this is the only live borrow.
    let multisig_data = unsafe { multisig.borrow_unchecked_mut() };
    let ms = Multisig::load_mut(multisig_data)?;

    match action {
        ConfigAction::AddOwner => add_owner(ms, payload)?,
        ConfigAction::RemoveOwner => remove_owner(ms, payload)?,
        ConfigAction::ChangeThreshold => change_threshold(ms, payload)?,
        ConfigAction::ChangeTimeLock => change_time_lock(ms, payload)?,
        ConfigAction::SetRentCollector => set_rent_collector(ms, payload)?,
        ConfigAction::SetPermission => set_permission(ms, payload)?,
        ConfigAction::CloseMultisig => unreachable!("handled above"),
    }

    // Approvals gathered under the old rules must not carry over to the new
    // ones. Shared here so no action can forget it.
    ms.invalidate_prior_transactions();
    ms.invariant()
}

/// Reads a 32-byte address payload.
fn payload_address(payload: &[u8]) -> Result<Address, ProgramError> {
    let bytes: [u8; 32] = payload
        .try_into()
        .map_err(|_| MultisigError::InvalidInstructionData)?;

    Ok(Address::new_from_array(bytes))
}

/// Inserts a new owner, keeping `owners` ascending.
fn add_owner(ms: &mut Multisig, payload: &[u8]) -> ProgramResult {
    let owner = payload_address(payload)?;

    let count = ms.owners_count as usize;
    if count >= MAX_OWNER {
        return Err(MultisigError::InvalidOwnerCount.into());
    }

    // A duplicate would occupy two slots and let one signer count twice
    // toward the threshold.
    let pos = match ms.owners().binary_search(&owner) {
        Ok(_) => return Err(MultisigError::OwnerAlreadyExists.into()),
        Err(pos) => pos,
    };

    let mut i = count;
    while i > pos {
        ms.owners[i] = ms.owners[i - 1];
        ms.permissions[i] = ms.permissions[i - 1];
        i -= 1;
    }
    ms.owners[pos] = owner;
    // Zero reads as every permission, which is the sensible default for a
    // multisig that does not use them.
    ms.permissions[pos] = 0;
    ms.owners_count += 1;

    Ok(())
}

/// Removes an owner, keeping `owners` ascending.
///
/// A removal leaving `threshold` above the remaining count is refused by
/// `invariant`: lower the threshold in its own proposal first, since relaxing
/// it here would make future spends easier to approve as a side effect.
fn remove_owner(ms: &mut Multisig, payload: &[u8]) -> ProgramResult {
    let owner = payload_address(payload)?;

    let pos = ms
        .owners()
        .binary_search(&owner)
        .map_err(|_| MultisigError::NotAnOwner)?;

    let count = ms.owners_count as usize;

    // Shift left rather than swap with the last entry, which would break the
    // ascending order `is_owner` binary-searches.
    let mut i = pos;
    while i + 1 < count {
        ms.owners[i] = ms.owners[i + 1];
        ms.permissions[i] = ms.permissions[i + 1];
        i += 1;
    }

    ms.owners[count - 1] = Address::default();
    ms.permissions[count - 1] = 0;
    ms.owners_count -= 1;

    Ok(())
}

/// Sets a new approval threshold. Range is checked by `invariant`.
fn change_threshold(ms: &mut Multisig, payload: &[u8]) -> ProgramResult {
    let [threshold] = payload else {
        return Err(MultisigError::InvalidInstructionData.into());
    };

    ms.threshold = *threshold;

    Ok(())
}

/// Sets a new execution delay. Range is checked by `invariant`.
fn change_time_lock(ms: &mut Multisig, payload: &[u8]) -> ProgramResult {
    let bytes: [u8; 4] = payload
        .try_into()
        .map_err(|_| MultisigError::InvalidInstructionData)?;

    ms.time_lock = u32::from_le_bytes(bytes);

    Ok(())
}

/// Sets where reclaimed rent goes.
fn set_rent_collector(ms: &mut Multisig, payload: &[u8]) -> ProgramResult {
    ms.rent_collector = payload_address(payload)?;

    Ok(())
}

/// Sets one owner's permission mask. Range is checked by `invariant`.
fn set_permission(ms: &mut Multisig, payload: &[u8]) -> ProgramResult {
    if payload.len() != 33 {
        return Err(MultisigError::InvalidInstructionData.into());
    }

    let owner = payload_address(&payload[..32])?;

    let index = ms.is_owner(&owner).ok_or(MultisigError::NotAnOwner)?;

    ms.permissions[index] = payload[32];

    Ok(())
}

/// Closes the multisig and returns its rent.
///
/// Refuses unless the only proposal still open is the one carrying this
/// action. A `Transaction` names its multisig and every instruction that
/// touches one checks that account, so closing the config while other
/// proposals remain would strand their rent permanently.
fn close_multisig(
    multisig: &mut AccountView,
    destination: &mut AccountView,
    payload: &[u8],
) -> ProgramResult {
    if !payload.is_empty() {
        return Err(MultisigError::InvalidInstructionData.into());
    }

    {
        // SAFETY: read-only borrow, released before the account is closed so
        // `close` does not see it as borrowed.
        let multisig_data = unsafe { multisig.borrow_unchecked() };
        let ms = Multisig::load(multisig_data)?;

        if !ms.only_executing_transaction_open() {
            return Err(MultisigError::TransactionsOutstanding.into());
        }

        // Rent goes where the multisig says, when it says anything.
        if ms.rent_collector != Address::default() {
            validate_eq(
                &ms.rent_collector,
                destination.address(),
                MultisigError::InvalidAccount.into(),
            )?;
        }
    }

    // Lamports must leave the account before it is closed, or the instruction
    // ends unbalanced and the runtime rejects it.
    let refund = multisig.lamports();

    let credited = destination
        .lamports()
        .checked_add(refund)
        .ok_or(MultisigError::Overflow)?;

    destination.set_lamports(credited);
    multisig.set_lamports(0);
    multisig.close()
}
