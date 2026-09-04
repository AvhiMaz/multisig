//! Owner-management actions.
//!
//! Not reachable from the entrypoint. They ride inside `ix_data` on a proposal
//! targeting this program, so changing the owner set costs the same threshold
//! of approvals as spending from the vault.

use pinocchio::{AccountView, Address, ProgramResult, error::ProgramError};

use crate::{constants::MAX_OWNER, error::MultisigError, state::multisig::Multisig};

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
}

impl ConfigAction {
    /// Decodes an action byte, rejecting unknown values.
    pub fn from_u8(v: u8) -> Result<Self, ProgramError> {
        match v {
            0 => Ok(Self::AddOwner),
            1 => Ok(Self::RemoveOwner),
            2 => Ok(Self::ChangeThreshold),
            _ => Err(MultisigError::UnknownConfigAction.into()),
        }
    }
}

/// Applies a config action to `multisig`.
pub fn apply_config_action(multisig: &mut AccountView, data: &[u8]) -> ProgramResult {
    let (tag, payload) = data
        .split_first()
        .ok_or(MultisigError::InvalidInstructionData)?;

    let action = ConfigAction::from_u8(*tag)?;

    // SAFETY: the transaction account's borrow was released before this call,
    // so this is the only live borrow.
    let multisig_data = unsafe { multisig.borrow_unchecked_mut() };
    let ms = Multisig::load_mut(multisig_data)?;

    match action {
        ConfigAction::AddOwner => add_owner(ms, payload)?,
        ConfigAction::RemoveOwner => remove_owner(ms, payload)?,
        ConfigAction::ChangeThreshold => change_threshold(ms, payload)?,
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
        i -= 1;
    }
    ms.owners[pos] = owner;
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
        i += 1;
    }

    ms.owners[count - 1] = Address::default();
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
