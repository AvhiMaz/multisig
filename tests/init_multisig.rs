//! `init_multisig` end to end.

mod common;

use common::{multisig_offset as off, *};
use mollusk_svm::result::Check;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

fn init(owners: &[Pubkey], threshold: u32) -> (Pubkey, Pubkey, Pubkey, u8) {
    let creator = Pubkey::new_unique();
    let create_key = Pubkey::new_unique();
    let (multisig, bump) = multisig_pda(&create_key);

    let _ = owners;
    let _ = threshold;

    (creator, create_key, multisig, bump)
}

#[test]
fn creates_a_multisig() {
    let mollusk = setup();

    let owners = sorted_owners(3);
    let (creator, create_key, multisig, bump) = init(&owners, 2);

    let ix = init_multisig_ix(&creator, &create_key, &multisig, &owners, 2, bump);

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

    let account = result.get_account(&multisig).expect("multisig account");
    let data = &account.data;

    // Header plus three owners at 33 bytes each.
    assert_eq!(data.len(), off::HEADER_LEN + 3 * 33, "account size");

    assert_eq!(
        &data[off::CREATE_KEY..off::CREATE_KEY + 32],
        create_key.as_ref()
    );
    assert_eq!(
        &data[off::RENT_COLLECTOR..off::RENT_COLLECTOR + 32],
        &[0u8; 32],
        "rent collector defaults to unset"
    );
    assert_eq!(
        &data[off::CONFIG_AUTHORITY..off::CONFIG_AUTHORITY + 32],
        &[0u8; 32],
        "autonomous unless a config authority is given"
    );

    for (i, owner) in owners.iter().enumerate() {
        assert_eq!(owner_at(data, i), owner.as_ref(), "owner {i}");
    }

    for i in 0..owners.len() {
        assert_eq!(
            permission_at(data, i, 3),
            0,
            "permission {i} defaults to all"
        );
    }

    assert_eq!(u32_at(data, off::OWNERS_COUNT), 3);
    assert_eq!(u32_at(data, off::THRESHOLD), 2);
    assert_eq!(u32_at(data, off::VOTER_COUNT), 3, "every owner can vote");
    assert_eq!(u32_at(data, off::TIME_LOCK), 0);
    assert_eq!(data[off::BUMP], bump);
    assert_eq!(u64_at(data, off::TRANSACTION_INDEX), 0);
    assert_eq!(u64_at(data, off::STALE_TRANSACTION_INDEX), 0);
    assert_eq!(u64_at(data, off::CLOSED_TRANSACTION_COUNT), 0);

    assert_eq!(account.owner, PROGRAM_ID, "owned by this program");
}

#[test]
fn the_account_is_sized_to_the_owner_set() {
    let mollusk = setup();

    for count in [1usize, 5, 20] {
        let owners = sorted_owners(count);
        let (creator, create_key, multisig, bump) = init(&owners, 1);

        let ix = init_multisig_ix(&creator, &create_key, &multisig, &owners, 1, bump);

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

        let data = &result.get_account(&multisig).unwrap().data;

        assert_eq!(
            data.len(),
            off::HEADER_LEN + count * 33,
            "{count} owners should occupy {} bytes",
            off::HEADER_LEN + count * 33
        );
        assert_eq!(u32_at(data, off::OWNERS_COUNT), count as u32);
    }
}

#[test]
fn rejects_unsorted_owners() {
    let mollusk = setup();

    let mut owners = sorted_owners(3);
    owners.reverse();

    let (creator, create_key, multisig, bump) = init(&owners, 2);
    let ix = init_multisig_ix(&creator, &create_key, &multisig, &owners, 2, bump);

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (creator, funded(10_000_000_000)),
            (create_key, funded(0)),
            (multisig, empty()),
            system_account(),
        ],
        &[Check::err(ProgramError::Custom(err::OWNERS_NOT_SORTED))],
    );
}

#[test]
fn rejects_threshold_above_owner_count() {
    let mollusk = setup();

    let owners = sorted_owners(3);
    let (creator, create_key, multisig, bump) = init(&owners, 4);
    let ix = init_multisig_ix(&creator, &create_key, &multisig, &owners, 4, bump);

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (creator, funded(10_000_000_000)),
            (create_key, funded(0)),
            (multisig, empty()),
            system_account(),
        ],
        &[Check::err(ProgramError::Custom(err::INVALID_THRESHOLD))],
    );
}

#[test]
fn rejects_a_zero_threshold() {
    let mollusk = setup();

    let owners = sorted_owners(3);
    let (creator, create_key, multisig, bump) = init(&owners, 0);
    let ix = init_multisig_ix(&creator, &create_key, &multisig, &owners, 0, bump);

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (creator, funded(10_000_000_000)),
            (create_key, funded(0)),
            (multisig, empty()),
            system_account(),
        ],
        &[Check::err(ProgramError::Custom(err::INVALID_THRESHOLD))],
    );
}

#[test]
fn rejects_an_empty_owner_set() {
    let mollusk = setup();

    let (creator, create_key, multisig, bump) = init(&[], 1);
    let ix = init_multisig_ix(&creator, &create_key, &multisig, &[], 1, bump);

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (creator, funded(10_000_000_000)),
            (create_key, funded(0)),
            (multisig, empty()),
            system_account(),
        ],
        &[Check::err(ProgramError::Custom(err::INVALID_OWNER_COUNT))],
    );
}

#[test]
fn rejects_a_payload_that_disagrees_with_its_count() {
    let mollusk = setup();

    let owners = sorted_owners(3);
    let (creator, create_key, multisig, bump) = init(&owners, 2);

    // Claims four owners but supplies three.
    let mut ix = init_multisig_ix(&creator, &create_key, &multisig, &owners, 2, bump);
    ix.data[5..9].copy_from_slice(&4u32.to_le_bytes());

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (creator, funded(10_000_000_000)),
            (create_key, funded(0)),
            (multisig, empty()),
            system_account(),
        ],
        &[Check::err(ProgramError::Custom(
            err::INVALID_INSTRUCTION_DATA,
        ))],
    );
}

#[test]
fn rejects_unsigned_create_key() {
    let mollusk = setup();

    let owners = sorted_owners(3);
    let (creator, create_key, multisig, bump) = init(&owners, 2);

    let mut ix = init_multisig_ix(&creator, &create_key, &multisig, &owners, 2, bump);
    ix.accounts[1].is_signer = false;

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (creator, funded(10_000_000_000)),
            (create_key, funded(0)),
            (multisig, empty()),
            system_account(),
        ],
        &[Check::err(ProgramError::Custom(err::MISSING_SIGNATURE))],
    );
}
