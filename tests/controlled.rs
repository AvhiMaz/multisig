//! Controlled multisigs, where a config authority changes the configuration
//! without a vote.

mod common;

use common::{err, multisig_offset as ms_off, *};
use mollusk_svm::result::Check;
use solana_account::Account;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

/// Creates a multisig, optionally controlled by `authority`.
fn open(
    mollusk: &mollusk_svm::Mollusk,
    owners: &[Pubkey],
    authority: &Pubkey,
) -> (Pubkey, Vec<(Pubkey, Account)>) {
    let creator = Pubkey::new_unique();
    let create_key = Pubkey::new_unique();
    let (multisig, bump) = multisig_pda(&create_key);

    let ix = init_multisig_ix_with_authority(
        &creator,
        &create_key,
        &multisig,
        owners,
        2,
        bump,
        authority,
    );

    let result = mollusk.process_and_validate_instruction(
        &ix,
        &[
            (creator, funded(10_000_000_000)),
            (create_key, funded(0)),
            (multisig, empty()),
            system_account(),
        ],
        &[Check::success()],
    );

    let accounts = vec![
        (multisig, result.get_account(&multisig).unwrap().clone()),
        (*authority, funded(10_000_000_000)),
        system_account(),
    ];

    (multisig, accounts)
}

#[test]
fn an_authority_changes_the_threshold_alone() {
    let mollusk = setup();
    let owners = sorted_owners(3);
    let authority = Pubkey::new_unique();

    let (multisig, accounts) = open(&mollusk, &owners, &authority);

    let created = accounts[0].1.clone();
    assert_eq!(
        &created.data[ms_off::CONFIG_AUTHORITY..ms_off::CONFIG_AUTHORITY + 32],
        authority.as_ref(),
        "born controlled"
    );

    let ix = set_config_ix(&authority, &multisig, 2, &3u32.to_le_bytes());

    let result = mollusk.process_and_validate_instruction(&ix, &accounts, &[Check::success()]);

    let ms = result.get_account(&multisig).unwrap();
    assert_eq!(u32_at(&ms.data, ms_off::THRESHOLD), 3, "no vote needed");
    assert_eq!(
        u64_at(&ms.data, ms_off::STALE_TRANSACTION_INDEX),
        0,
        "nothing to invalidate yet"
    );
}

#[test]
fn an_authority_adds_and_removes_owners() {
    let mollusk = setup();
    let owners = sorted_owners(3);
    let authority = Pubkey::new_unique();

    let (multisig, accounts) = open(&mollusk, &owners, &authority);

    let mut bytes = [0u8; 32];
    bytes[31] = 1;
    let newcomer = Pubkey::new_from_array(bytes);

    let add = set_config_ix(&authority, &multisig, 0, newcomer.as_ref());
    let after_add = mollusk.process_and_validate_instruction(&add, &accounts, &[Check::success()]);

    let ms = after_add.get_account(&multisig).unwrap();
    assert_eq!(u32_at(&ms.data, ms_off::OWNERS_COUNT), 4);
    assert_eq!(u32_at(&ms.data, ms_off::VOTER_COUNT), 4);
    assert_eq!(
        owner_at(&ms.data, 0),
        newcomer.as_ref(),
        "inserted in order"
    );
    assert_eq!(ms.data.len(), ms_off::HEADER_LEN + 4 * 33, "account grew");

    let mut next = accounts.clone();
    next[0] = (multisig, ms.clone());
    next[1] = (
        authority,
        after_add.get_account(&authority).unwrap().clone(),
    );

    let remove = set_config_ix(&authority, &multisig, 1, newcomer.as_ref());
    let after_remove =
        mollusk.process_and_validate_instruction(&remove, &next, &[Check::success()]);

    let ms = after_remove.get_account(&multisig).unwrap();
    assert_eq!(u32_at(&ms.data, ms_off::OWNERS_COUNT), 3);
    assert_eq!(ms.data.len(), ms_off::HEADER_LEN + 3 * 33, "account shrank");
    assert_eq!(owner_at(&ms.data, 0), owners[0].as_ref());
}

#[test]
fn an_autonomous_multisig_has_no_authority_to_appeal_to() {
    let mollusk = setup();
    let owners = sorted_owners(3);
    let stranger = Pubkey::new_unique();

    // Created with the default address, so it is autonomous.
    let (multisig, accounts) = open(&mollusk, &owners, &Pubkey::default());

    let mut accounts = accounts;
    accounts[1] = (stranger, funded(10_000_000_000));

    let ix = set_config_ix(&stranger, &multisig, 2, &3u32.to_le_bytes());

    mollusk.process_and_validate_instruction(
        &ix,
        &accounts,
        &[Check::err(ProgramError::Custom(err::NOT_CONTROLLED))],
    );
}

#[test]
fn only_the_named_authority_is_obeyed() {
    let mollusk = setup();
    let owners = sorted_owners(3);
    let authority = Pubkey::new_unique();
    let impostor = Pubkey::new_unique();

    let (multisig, accounts) = open(&mollusk, &owners, &authority);

    let mut accounts = accounts;
    accounts.push((impostor, funded(10_000_000_000)));

    let ix = set_config_ix(&impostor, &multisig, 2, &3u32.to_le_bytes());

    mollusk.process_and_validate_instruction(
        &ix,
        &accounts,
        &[Check::err(ProgramError::Custom(err::UNAUTHORIZED))],
    );
}

#[test]
fn an_authority_can_release_control_to_the_owners() {
    let mollusk = setup();
    let owners = sorted_owners(3);
    let authority = Pubkey::new_unique();

    let (multisig, accounts) = open(&mollusk, &owners, &authority);

    // Setting the default address hands the multisig back to its owners.
    let release = set_config_ix(&authority, &multisig, 7, Pubkey::default().as_ref());
    let result = mollusk.process_and_validate_instruction(&release, &accounts, &[Check::success()]);

    let ms = result.get_account(&multisig).unwrap();
    assert_eq!(
        &ms.data[ms_off::CONFIG_AUTHORITY..ms_off::CONFIG_AUTHORITY + 32],
        &[0u8; 32],
        "autonomous again"
    );

    // And the authority no longer has a say.
    let mut next = accounts.clone();
    next[0] = (multisig, ms.clone());

    let again = set_config_ix(&authority, &multisig, 2, &3u32.to_le_bytes());

    mollusk.process_and_validate_instruction(
        &again,
        &next,
        &[Check::err(ProgramError::Custom(err::NOT_CONTROLLED))],
    );
}

#[test]
fn an_unsigned_authority_is_refused() {
    let mollusk = setup();
    let owners = sorted_owners(3);
    let authority = Pubkey::new_unique();

    let (multisig, accounts) = open(&mollusk, &owners, &authority);

    let mut ix = set_config_ix(&authority, &multisig, 2, &3u32.to_le_bytes());
    ix.accounts[0].is_signer = false;

    mollusk.process_and_validate_instruction(
        &ix,
        &accounts,
        &[Check::err(ProgramError::Custom(err::MISSING_SIGNATURE))],
    );
}

#[test]
fn the_authority_still_cannot_break_the_invariants() {
    let mollusk = setup();
    let owners = sorted_owners(3);
    let authority = Pubkey::new_unique();

    let (multisig, accounts) = open(&mollusk, &owners, &authority);

    // Control over configuration is not permission to leave it unusable.
    let ix = set_config_ix(&authority, &multisig, 2, &9u32.to_le_bytes());

    mollusk.process_and_validate_instruction(
        &ix,
        &accounts,
        &[Check::err(ProgramError::Custom(err::INVALID_THRESHOLD))],
    );
}
