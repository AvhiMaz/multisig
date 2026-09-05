//! Owner-management actions.
//!
//! Two paths reach these. On an autonomous multisig they ride inside `ix_data`
//! on a proposal targeting this program, so changing the owner set costs the
//! same threshold of approvals as spending from the vault. On a controlled one
//! `set_config` applies them on the config authority's signature alone.
//!
//! Both paths run the code here, so they cannot drift apart. `via_proposal`
//! marks which one is calling, because closing the multisig has to account for
//! the proposal carrying the action being open.
//!
//! The owner set is a variable-length tail, so adding or removing an owner
//! resizes the account and moves rent between it and the executor.

use pinocchio::{
    AccountView, Address, ProgramResult, Resize,
    error::ProgramError,
    sysvars::{Sysvar, rent::Rent},
};
use pinocchio_system::instructions::Transfer;

use crate::{
    constants::MAX_OWNER, error::MultisigError, helper::validate_eq, state::multisig::Multisig,
    state::permission::Permission,
};

/// Action encoded in the first byte of a self-targeted proposal's `ix_data`.
#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ConfigAction {
    /// Add an owner. Payload is the 32-byte address.
    AddOwner = 0,
    /// Remove an owner. Payload is the 32-byte address.
    RemoveOwner = 1,
    /// Change the approval threshold. Payload is a little-endian `u32`.
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
    /// Hand configuration control to a key, or return it to the owners by
    /// setting the default address. Payload is the 32-byte address.
    SetConfigAuthority = 7,
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
            7 => Ok(Self::SetConfigAuthority),
            _ => Err(MultisigError::UnknownConfigAction.into()),
        }
    }
}

/// Applies a config action to `multisig`.
///
/// `payer` funds a growing owner set and receives the refund from a shrinking
/// one. It is the executor, which `execute` has already checked signed.
pub fn apply_config_action(
    multisig: &mut AccountView,
    payer: &mut AccountView,
    data: &[u8],
    via_proposal: bool,
) -> ProgramResult {
    let (tag, payload) = data
        .split_first()
        .ok_or(MultisigError::InvalidInstructionData)?;

    let action = ConfigAction::from_u8(*tag)?;

    // Closing ends the account, so it cannot run the invalidate-and-check tail
    // the other actions share: there would be nothing left to check.
    if action == ConfigAction::CloseMultisig {
        return close_multisig(multisig, payer, payload, via_proposal);
    }

    // Adding and removing change the account's size, so they own their own
    // resize and cannot borrow the data across it.
    match action {
        ConfigAction::AddOwner => return add_owner(multisig, payer, payload),
        ConfigAction::RemoveOwner => return remove_owner(multisig, payer, payload),
        _ => {}
    }

    // SAFETY: the transaction account's borrow was released before this call,
    // so this is the only live borrow.
    let multisig_data = unsafe { multisig.borrow_unchecked_mut() };
    let (ms, owners, permissions) = Multisig::load_mut(multisig_data)?;

    match action {
        ConfigAction::ChangeThreshold => change_threshold(ms, payload)?,
        ConfigAction::ChangeTimeLock => change_time_lock(ms, payload)?,
        ConfigAction::SetRentCollector => set_rent_collector(ms, payload)?,
        ConfigAction::SetPermission => set_permission(ms, owners, permissions, payload)?,
        ConfigAction::SetConfigAuthority => ms.config_authority = payload_address(payload)?,
        _ => unreachable!("handled above"),
    }

    // Every proposal in flight was voted on against the configuration that
    // stood a moment ago, so none of them may be voted on further. Shared here
    // so no action can forget it.
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

/// Moves lamports so `multisig` is rent exempt at its new size.
///
/// Growing pulls from the payer through the system program, since the payer is
/// not ours to debit. Shrinking pushes the excess back directly, which is
/// permitted because the account being debited is ours.
fn settle_rent(
    multisig: &mut AccountView,
    payer: &mut AccountView,
    new_space: usize,
) -> ProgramResult {
    let required = Rent::get()?.minimum_balance_unchecked(new_space);
    let held = multisig.lamports();

    if held < required {
        Transfer {
            from: payer,
            to: multisig,
            lamports: required - held,
        }
        .invoke()?;
    } else if held > required {
        let refund = held - required;

        let credited = payer
            .lamports()
            .checked_add(refund)
            .ok_or(MultisigError::Overflow)?;

        payer.set_lamports(credited);
        multisig.set_lamports(required);
    }

    Ok(())
}

/// Inserts a new owner, keeping the set ascending.
///
/// The tail is owners followed by permissions, so making room for an address
/// also moves the permissions. Both regions are shifted as raw bytes, in the
/// one order that never writes over data still to be read.
fn add_owner(multisig: &mut AccountView, payer: &mut AccountView, payload: &[u8]) -> ProgramResult {
    let owner = payload_address(payload)?;

    let (count, pos) = {
        // SAFETY: read-only borrow, released before the resize below.
        let data = unsafe { multisig.borrow_unchecked() };
        let (ms, owners, _) = Multisig::load(data)?;

        let pos = match owners.binary_search(&owner) {
            Ok(_) => return Err(MultisigError::OwnerAlreadyExists.into()),
            Err(pos) => pos,
        };

        (ms.owners_count as usize, pos)
    };

    if count >= MAX_OWNER {
        return Err(MultisigError::InvalidOwnerCount.into());
    }

    let new_space = Multisig::space(count + 1);

    multisig.resize(new_space)?;
    settle_rent(multisig, payer, new_space)?;

    // SAFETY: the resize is complete and nothing else holds a borrow.
    let data = unsafe { multisig.borrow_unchecked_mut() };
    let (ms, tail) = Multisig::split_uninitialized(data)?;

    let old_permissions = count * 32;
    let new_permissions = (count + 1) * 32;

    // Move the permissions clear of the owner region before it grows into
    // them, then open the gap for the new owner.
    tail.copy_within(old_permissions..old_permissions + count, new_permissions);
    tail.copy_within(pos * 32..count * 32, (pos + 1) * 32);
    tail[pos * 32..(pos + 1) * 32].copy_from_slice(owner.as_array());

    tail.copy_within(
        new_permissions + pos..new_permissions + count,
        new_permissions + pos + 1,
    );
    // Zero reads as every permission, the sensible default.
    tail[new_permissions + pos] = 0;

    ms.owners_count = (count + 1) as u32;
    ms.voter_count += 1;

    // Only the neighbours can have been disturbed, so ordering is checked there
    // rather than across the whole set, which would be linear.
    let (_, owners, _) = Multisig::load(data_of(multisig))?;

    if pos > 0 && owners[pos - 1] >= owners[pos] {
        return Err(MultisigError::OwnersNotSorted.into());
    }
    if pos + 1 < owners.len() && owners[pos] >= owners[pos + 1] {
        return Err(MultisigError::OwnersNotSorted.into());
    }

    // SAFETY: the borrow above is read-only and ends here.
    let data = unsafe { multisig.borrow_unchecked_mut() };
    let (ms, _) = Multisig::split_uninitialized(data)?;

    ms.invalidate_prior_transactions();
    ms.invariant()
}

/// Reads a multisig account's data.
///
/// Callers must hold no other borrow of the account, which is why this is
/// private to this module rather than a general helper.
fn data_of(multisig: &AccountView) -> &[u8] {
    // SAFETY: the caller guarantees exclusivity.
    unsafe { multisig.borrow_unchecked() }
}

/// Removes an owner, keeping the set ascending.
///
/// A removal that would leave `threshold` above the remaining voters is
/// refused by `invariant`: lower the threshold in its own proposal first, since
/// relaxing it here would make future spends easier to approve as a side
/// effect.
fn remove_owner(
    multisig: &mut AccountView,
    payer: &mut AccountView,
    payload: &[u8],
) -> ProgramResult {
    let owner = payload_address(payload)?;

    let (count, pos, was_voter) = {
        // SAFETY: read-only borrow, released with this scope.
        let data = unsafe { multisig.borrow_unchecked() };
        let (ms, owners, permissions) = Multisig::load(data)?;

        let pos = Multisig::is_owner(owners, &owner).ok_or(MultisigError::NotAnOwner)?;

        (
            ms.owners_count as usize,
            pos,
            Multisig::mask_can_vote(permissions[pos]),
        )
    };

    {
        // SAFETY: the read-only borrow above is released.
        let data = unsafe { multisig.borrow_unchecked_mut() };
        let (ms, tail) = Multisig::split_uninitialized(data)?;

        let old_permissions = count * 32;
        let new_permissions = (count - 1) * 32;

        // Close the gap in each region, then pull the permissions back over the
        // space the removed owner left. This has to happen before the shrink,
        // which would truncate the bytes still being moved.
        tail.copy_within((pos + 1) * 32..count * 32, pos * 32);
        tail.copy_within(
            old_permissions + pos + 1..old_permissions + count,
            old_permissions + pos,
        );
        tail.copy_within(
            old_permissions..old_permissions + count - 1,
            new_permissions,
        );

        ms.owners_count = (count - 1) as u32;

        if was_voter {
            ms.voter_count -= 1;
        }

        ms.invalidate_prior_transactions();
        ms.invariant()?;
    }

    let new_space = Multisig::space(count - 1);

    multisig.resize(new_space)?;
    settle_rent(multisig, payer, new_space)
}

/// Sets a new approval threshold. Range is checked by `invariant`.
fn change_threshold(ms: &mut Multisig, payload: &[u8]) -> ProgramResult {
    let bytes: [u8; 4] = payload
        .try_into()
        .map_err(|_| MultisigError::InvalidInstructionData)?;

    ms.threshold = u32::from_le_bytes(bytes);

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

/// Sets one owner's permission mask, keeping `voter_count` in step.
fn set_permission(
    ms: &mut Multisig,
    owners: &[Address],
    permissions: &mut [u8],
    payload: &[u8],
) -> ProgramResult {
    if payload.len() != 33 {
        return Err(MultisigError::InvalidInstructionData.into());
    }

    let owner = payload_address(&payload[..32])?;
    let mask = payload[32];

    if mask > Permission::ALL {
        return Err(MultisigError::UnknownPermission.into());
    }

    let index = Multisig::is_owner(owners, &owner).ok_or(MultisigError::NotAnOwner)?;

    let was_voter = Multisig::mask_can_vote(permissions[index]);
    let is_voter = Multisig::mask_can_vote(mask);

    permissions[index] = mask;

    // Maintained rather than recounted; scanning would be linear in the owner
    // count and this runs on every change.
    match (was_voter, is_voter) {
        (false, true) => ms.voter_count += 1,
        (true, false) => ms.voter_count -= 1,
        _ => {}
    }

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
    via_proposal: bool,
) -> ProgramResult {
    if !payload.is_empty() {
        return Err(MultisigError::InvalidInstructionData.into());
    }

    {
        // SAFETY: read-only borrow, released before the account is closed so
        // `close` does not see it as borrowed.
        let data = unsafe { multisig.borrow_unchecked() };
        let (ms, _, _) = Multisig::load(data)?;

        // Reached through a proposal, the proposal carrying this action is
        // itself open and is excluded. Reached through the config authority,
        // nothing is executing, so everything must already be closed.
        let clear = if via_proposal {
            ms.only_executing_transaction_open()
        } else {
            ms.all_transactions_closed()
        };

        if !clear {
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
