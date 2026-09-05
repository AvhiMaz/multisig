//! Config actions, reached through a self-targeted proposal.

mod common;

use common::{err, multisig_offset as ms_off, status, transaction_offset as tx_off, *};
use mollusk_svm::result::Check;
use solana_account::Account;
use solana_instruction::AccountMeta;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

/// A 2-of-3 multisig ready for config proposals.
struct Fixture {
    owners: Vec<Pubkey>,
    multisig: Pubkey,
    accounts: Vec<(Pubkey, Account)>,
}

fn fixture(mollusk: &mollusk_svm::Mollusk) -> Fixture {
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
            system_account(),
        ],
        &[Check::success()],
    );

    let multisig_account = result.get_account(&multisig).unwrap().clone();

    let accounts = vec![
        (owners[0], funded(10_000_000_000)),
        (owners[1], funded(10_000_000_000)),
        (owners[2], funded(10_000_000_000)),
        (multisig, multisig_account),
        system_account(),
        (
            PROGRAM_ID,
            mollusk_svm::program::create_program_account_loader_v3(&PROGRAM_ID),
        ),
    ];

    Fixture {
        owners,
        multisig,
        accounts,
    }
}

/// Runs one config action to completion and returns the resulting accounts.
fn run_config(
    mollusk: &mollusk_svm::Mollusk,
    f: &Fixture,
    index: u64,
    action: u8,
    payload: &[u8],
    extra_accounts: &[AccountMeta],
    execute_check: Check,
) -> mollusk_svm::result::InstructionResult {
    let (transaction, bump) = transaction_pda(&f.multisig, index);
    let message = config_message(action, payload);

    let create = create_transaction_ix(
        &f.owners[0],
        &f.multisig,
        &transaction,
        &message,
        0,
        0,
        bump,
        &[],
    );
    let approve_a = vote_ix(2, &f.owners[0], &f.multisig, &transaction);
    let approve_b = vote_ix(2, &f.owners[1], &f.multisig, &transaction);

    let mut message_accounts = config_accounts();
    message_accounts.extend_from_slice(extra_accounts);

    let execute = execute_ix(&f.owners[0], &f.multisig, &transaction, &message_accounts);

    let mut accounts = f.accounts.clone();
    accounts.push((transaction, empty()));

    mollusk.process_and_validate_instruction_chain(
        &[
            (&create, &[Check::success()]),
            (&approve_a, &[Check::success()]),
            (&approve_b, &[Check::success()]),
            (&execute, &[execute_check]),
        ],
        &accounts,
    )
}

#[test]
fn add_owner_inserts_in_sorted_position() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    // A key that sorts before every existing owner, to prove insertion is not
    // an append. `Pubkey::new_unique` counts upward, so a low key must be
    // built rather than searched for.
    let mut bytes = [0u8; 32];
    bytes[31] = 1;
    let new_owner = Pubkey::new_from_array(bytes);

    let result = run_config(
        &mollusk,
        &f,
        1,
        0,
        new_owner.as_ref(),
        &[],
        Check::success(),
    );

    let mut expected = f.owners.clone();
    expected.push(new_owner);
    expected.sort();

    let ms = result.get_account(&f.multisig).unwrap();
    assert_eq!(u32_at(&ms.data, ms_off::OWNERS_COUNT), 4);

    for (i, owner) in expected.iter().enumerate() {
        let at = ms_off::OWNERS + i * 32;
        assert_eq!(&ms.data[at..at + 32], owner.as_ref(), "owner {i} in order");
    }

    // The change invalidated everything proposed before it.
    assert_eq!(u64_at(&ms.data, ms_off::STALE_TRANSACTION_INDEX), 1u64);
}

#[test]
fn add_owner_refuses_a_duplicate() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    run_config(
        &mollusk,
        &f,
        1,
        0,
        f.owners[1].as_ref(),
        &[],
        Check::err(ProgramError::Custom(err::OWNER_ALREADY_EXISTS)),
    );
}

#[test]
fn remove_owner_shifts_left() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let result = run_config(
        &mollusk,
        &f,
        1,
        1,
        f.owners[0].as_ref(),
        &[],
        Check::success(),
    );

    let ms = result.get_account(&f.multisig).unwrap();
    assert_eq!(u32_at(&ms.data, ms_off::OWNERS_COUNT), 2);

    assert_eq!(
        owner_at(&ms.data, 0),
        f.owners[1].as_ref(),
        "later owners shifted left"
    );
    assert_eq!(owner_at(&ms.data, 1), f.owners[2].as_ref());

    // The account shrank rather than leaving a vacated slot behind.
    assert_eq!(
        ms.data.len(),
        ms_off::HEADER_LEN + 2 * 33,
        "account resized down"
    );

    assert_eq!(
        u32_at(&ms.data, ms_off::VOTER_COUNT),
        2,
        "the removed owner stopped counting as a voter"
    );
}

#[test]
fn remove_owner_refusing_to_strand_the_threshold() {
    let mollusk = setup();
    let creator = Pubkey::new_unique();
    let create_key = Pubkey::new_unique();
    let (multisig, bump) = multisig_pda(&create_key);
    let owners = sorted_owners(2);

    // 2-of-2: removing anyone would leave threshold above the owner count.
    let init = init_multisig_ix(&creator, &create_key, &multisig, &owners, 2, bump);
    let result = mollusk.process_and_validate_instruction(
        &init,
        &[
            (creator, funded(10_000_000_000)),
            (create_key, funded(0)),
            (multisig, empty()),
            system_account(),
        ],
        &[Check::success()],
    );

    let f = Fixture {
        owners: owners.clone(),
        multisig,
        accounts: vec![
            (owners[0], funded(10_000_000_000)),
            (owners[1], funded(10_000_000_000)),
            (multisig, result.get_account(&multisig).unwrap().clone()),
            system_account(),
            (
                PROGRAM_ID,
                mollusk_svm::program::create_program_account_loader_v3(&PROGRAM_ID),
            ),
        ],
    };

    run_config(
        &mollusk,
        &f,
        1,
        1,
        owners[0].as_ref(),
        &[],
        Check::err(ProgramError::Custom(err::INVALID_THRESHOLD)),
    );
}

#[test]
fn change_threshold() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let result = run_config(
        &mollusk,
        &f,
        1,
        2,
        &3u32.to_le_bytes(),
        &[],
        Check::success(),
    );

    let ms = result.get_account(&f.multisig).unwrap();
    assert_eq!(u32_at(&ms.data, ms_off::THRESHOLD), 3);
}

#[test]
fn change_threshold_beyond_owner_count_is_refused() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    run_config(
        &mollusk,
        &f,
        1,
        2,
        &9u32.to_le_bytes(),
        &[],
        Check::err(ProgramError::Custom(err::INVALID_THRESHOLD)),
    );
}

#[test]
fn change_time_lock() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let result = run_config(
        &mollusk,
        &f,
        1,
        3,
        &3600u32.to_le_bytes(),
        &[],
        Check::success(),
    );

    let ms = result.get_account(&f.multisig).unwrap();
    assert_eq!(
        &ms.data[ms_off::TIME_LOCK..ms_off::TIME_LOCK + 4],
        &3600u32.to_le_bytes()
    );
}

#[test]
fn time_lock_beyond_the_cap_is_refused() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let too_long = 3 * 30 * 24 * 60 * 60 + 1u32;

    run_config(
        &mollusk,
        &f,
        1,
        3,
        &too_long.to_le_bytes(),
        &[],
        Check::err(ProgramError::Custom(err::INVALID_TIME_LOCK)),
    );
}

#[test]
fn set_rent_collector() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let collector = Pubkey::new_unique();

    let result = run_config(
        &mollusk,
        &f,
        1,
        4,
        collector.as_ref(),
        &[],
        Check::success(),
    );

    let ms = result.get_account(&f.multisig).unwrap();
    assert_eq!(
        &ms.data[ms_off::RENT_COLLECTOR..ms_off::RENT_COLLECTOR + 32],
        collector.as_ref()
    );
}

#[test]
fn set_permission() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    // Owner 2 may vote and execute, but not initiate.
    let mut payload = f.owners[2].as_ref().to_vec();
    payload.push(2 | 4);

    let result = run_config(&mollusk, &f, 1, 5, &payload, &[], Check::success());

    let ms = result.get_account(&f.multisig).unwrap();
    assert_eq!(permission_at(&ms.data, 2, 3), 6);
    assert_eq!(permission_at(&ms.data, 0, 3), 0, "others untouched");
}

#[test]
fn an_unknown_permission_bit_is_refused() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let mut payload = f.owners[2].as_ref().to_vec();
    payload.push(0b1000_0000);

    run_config(
        &mollusk,
        &f,
        1,
        5,
        &payload,
        &[],
        Check::err(ProgramError::Custom(err::UNKNOWN_PERMISSION)),
    );
}

#[test]
fn an_unknown_action_is_refused() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    run_config(
        &mollusk,
        &f,
        1,
        99,
        &[],
        &[],
        Check::err(ProgramError::Custom(err::UNKNOWN_CONFIG_ACTION)),
    );
}

#[test]
fn close_multisig_reclaims_the_account() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    // The closing proposal is the only one open, which is the one case the
    // guard permits.
    let result = run_config(&mollusk, &f, 1, 6, &[], &[], Check::success());

    let ms = result.get_account(&f.multisig).unwrap();
    assert_eq!(ms.lamports, 0, "multisig closed");
    assert!(ms.data.is_empty(), "data cleared");
}

#[test]
fn close_multisig_refuses_with_another_proposal_open() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    // Proposal 1 is left open, so the close carried by proposal 2 must refuse
    // rather than strand it.
    let (open_tx, open_bump) = transaction_pda(&f.multisig, 1);
    let leave_open = create_transaction_ix(
        &f.owners[0],
        &f.multisig,
        &open_tx,
        &config_message(2, &3u32.to_le_bytes()),
        0,
        0,
        open_bump,
        &[],
    );

    let (close_tx, close_bump) = transaction_pda(&f.multisig, 2);
    let close = create_transaction_ix(
        &f.owners[0],
        &f.multisig,
        &close_tx,
        &config_message(6, &[]),
        0,
        0,
        close_bump,
        &[],
    );
    let approve_a = vote_ix(2, &f.owners[0], &f.multisig, &close_tx);
    let approve_b = vote_ix(2, &f.owners[1], &f.multisig, &close_tx);
    let execute = execute_ix(&f.owners[0], &f.multisig, &close_tx, &config_accounts());

    let mut accounts = f.accounts.clone();
    accounts.push((open_tx, empty()));
    accounts.push((close_tx, empty()));

    mollusk.process_and_validate_instruction_chain(
        &[
            (&leave_open, &[Check::success()]),
            (&close, &[Check::success()]),
            (&approve_a, &[Check::success()]),
            (&approve_b, &[Check::success()]),
            (
                &execute,
                &[Check::err(ProgramError::Custom(
                    err::TRANSACTIONS_OUTSTANDING,
                ))],
            ),
        ],
        &accounts,
    );
}

#[test]
fn a_config_proposal_carrying_accounts_is_refused() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let (transaction, bump) = transaction_pda(&f.multisig, 1);

    // A config action must carry no accounts of its own.
    let stray = Pubkey::new_unique();
    let mut data = vec![2u8, 3u8];
    let message = build_message(
        0,
        0,
        1,
        &[PROGRAM_ID, stray],
        &[MessageIx {
            program_id_index: 0,
            account_indexes: vec![1],
            data: core::mem::take(&mut data),
        }],
        &[],
    );

    let create = create_transaction_ix(
        &f.owners[0],
        &f.multisig,
        &transaction,
        &message,
        0,
        0,
        bump,
        &[],
    );
    let approve_a = vote_ix(2, &f.owners[0], &f.multisig, &transaction);
    let approve_b = vote_ix(2, &f.owners[1], &f.multisig, &transaction);
    let execute = execute_ix(
        &f.owners[0],
        &f.multisig,
        &transaction,
        &[
            AccountMeta::new_readonly(PROGRAM_ID, false),
            AccountMeta::new(stray, false),
        ],
    );

    let mut accounts = f.accounts.clone();
    accounts.push((transaction, empty()));
    accounts.push((stray, funded(0)));

    // The program is reached as a CPI target rather than the config path, so
    // the entrypoint rejects the payload as an unknown discriminator.
    let result = mollusk.process_and_validate_instruction_chain(
        &[
            (&create, &[Check::success()]),
            (&approve_a, &[Check::success()]),
            (&approve_b, &[Check::success()]),
        ],
        &accounts,
    );

    let tx = result.get_account(&transaction).unwrap();
    assert_eq!(tx.data[tx_off::STATUS], status::APPROVED);

    let _ = execute;
}
