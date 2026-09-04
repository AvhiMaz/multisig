//! `init_multisig` end to end.

mod common;

use common::{multisig_offset as off, *};
use mollusk_svm::result::Check;
use solana_pubkey::Pubkey;

#[test]
fn creates_a_multisig() {
    let mollusk = setup();

    let creator = Pubkey::new_unique();
    let create_key = Pubkey::new_unique();
    let (multisig, bump) = multisig_pda(&create_key);
    let owners = sorted_owners(3);

    let ix = init_multisig_ix(&creator, &create_key, &multisig, &owners, 2, bump);

    let result = mollusk.process_and_validate_instruction(
        &ix,
        &[
            (creator, funded(10_000_000_000)),
            (create_key, funded(0)),
            (multisig, empty()),
            mollusk_svm::program::keyed_account_for_system_program(),
        ],
        &[Check::success()],
    );

    let account = result.get_account(&multisig).expect("multisig account");
    let data = &account.data;

    assert_eq!(data.len(), off::LEN, "account size");
    assert_eq!(
        &data[off::CREATE_KEY..off::CREATE_KEY + 32],
        create_key.as_ref()
    );
    assert_eq!(
        &data[off::RENT_COLLECTOR..off::RENT_COLLECTOR + 32],
        &[0u8; 32],
        "rent collector defaults to unset"
    );

    for (i, owner) in owners.iter().enumerate() {
        let at = off::OWNERS + i * 32;
        assert_eq!(&data[at..at + 32], owner.as_ref(), "owner {i}");
    }

    // Trailing owner slots are zeroed so the stored set is canonical.
    assert_eq!(
        &data[off::OWNERS + 3 * 32..off::PERMISSIONS],
        &[0u8; 7 * 32][..]
    );

    assert_eq!(&data[off::PERMISSIONS..off::OWNERS_COUNT], &[0u8; 10]);
    assert_eq!(data[off::OWNERS_COUNT], 3);
    assert_eq!(data[off::THRESHOLD], 2);
    assert_eq!(data[off::BUMP], bump);
    assert_eq!(
        &data[off::TIME_LOCK..off::TIME_LOCK + 4],
        &0u32.to_le_bytes()
    );
    assert_eq!(
        &data[off::TRANSACTION_INDEX..off::TRANSACTION_INDEX + 8],
        &0u64.to_le_bytes()
    );
    assert_eq!(
        &data[off::STALE_TRANSACTION_INDEX..off::STALE_TRANSACTION_INDEX + 8],
        &0u64.to_le_bytes()
    );
    assert_eq!(
        &data[off::CLOSED_TRANSACTION_COUNT..off::CLOSED_TRANSACTION_COUNT + 8],
        &0u64.to_le_bytes()
    );

    assert_eq!(account.owner, PROGRAM_ID, "owned by this program");
}

#[test]
fn rejects_unsorted_owners() {
    let mollusk = setup();

    let creator = Pubkey::new_unique();
    let create_key = Pubkey::new_unique();
    let (multisig, bump) = multisig_pda(&create_key);

    let mut owners = sorted_owners(3);
    owners.reverse();

    let ix = init_multisig_ix(&creator, &create_key, &multisig, &owners, 2, bump);

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (creator, funded(10_000_000_000)),
            (create_key, funded(0)),
            (multisig, empty()),
            mollusk_svm::program::keyed_account_for_system_program(),
        ],
        &[Check::err(solana_program_error::ProgramError::Custom(10))],
    );
}

#[test]
fn rejects_threshold_above_owner_count() {
    let mollusk = setup();

    let creator = Pubkey::new_unique();
    let create_key = Pubkey::new_unique();
    let (multisig, bump) = multisig_pda(&create_key);
    let owners = sorted_owners(3);

    let ix = init_multisig_ix(&creator, &create_key, &multisig, &owners, 4, bump);

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (creator, funded(10_000_000_000)),
            (create_key, funded(0)),
            (multisig, empty()),
            mollusk_svm::program::keyed_account_for_system_program(),
        ],
        &[Check::err(solana_program_error::ProgramError::Custom(9))],
    );
}

#[test]
fn rejects_unsigned_create_key() {
    let mollusk = setup();

    let creator = Pubkey::new_unique();
    let create_key = Pubkey::new_unique();
    let (multisig, bump) = multisig_pda(&create_key);
    let owners = sorted_owners(3);

    let mut ix = init_multisig_ix(&creator, &create_key, &multisig, &owners, 2, bump);
    ix.accounts[1].is_signer = false;

    mollusk.process_and_validate_instruction(
        &ix,
        &[
            (creator, funded(10_000_000_000)),
            (create_key, funded(0)),
            (multisig, empty()),
            mollusk_svm::program::keyed_account_for_system_program(),
        ],
        &[Check::err(solana_program_error::ProgramError::Custom(3))],
    );
}
