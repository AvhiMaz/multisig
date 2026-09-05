//! Time locks, staleness, multi-instruction proposals, ephemeral signers and
//! permission gating.

mod common;

use common::{err, status, transaction_offset as tx_off, *};
use mollusk_svm::result::Check;
use solana_account::Account;
use solana_instruction::AccountMeta;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

const VAULT_FUNDING: u64 = 5_000_000_000;
const TRANSFER: u64 = 500_000_000;

struct Fixture {
    owners: Vec<Pubkey>,
    multisig: Pubkey,
    vault: Pubkey,
    vault_bump: u8,
    accounts: Vec<(Pubkey, Account)>,
}

fn fixture(mollusk: &mollusk_svm::Mollusk) -> Fixture {
    let creator = Pubkey::new_unique();
    let create_key = Pubkey::new_unique();
    let (multisig, bump) = multisig_pda(&create_key);
    let owners = sorted_owners(3);
    let (vault, vault_bump) = vault_pda(&multisig, 0);

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

    let accounts = vec![
        (owners[0], funded(10_000_000_000)),
        (owners[1], funded(10_000_000_000)),
        (owners[2], funded(10_000_000_000)),
        (multisig, result.get_account(&multisig).unwrap().clone()),
        (vault, funded(VAULT_FUNDING)),
        system_account(),
        (
            PROGRAM_ID,
            mollusk_svm::program::create_program_account_loader_v3(&PROGRAM_ID),
        ),
    ];

    Fixture {
        owners,
        multisig,
        vault,
        vault_bump,
        accounts,
    }
}

#[test]
fn several_instructions_settle_together() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let first = Pubkey::new_unique();
    let second = Pubkey::new_unique();

    let transfer = |amount: u64| {
        let mut data = 2u32.to_le_bytes().to_vec();
        data.extend_from_slice(&amount.to_le_bytes());
        data
    };

    // vault (writable signer), two destinations (writable non-signers),
    // system program (readonly non-signer).
    let message = build_message(
        1,
        1,
        2,
        &[f.vault, first, second, SYSTEM_ID],
        &[
            MessageIx {
                program_id_index: 3,
                account_indexes: vec![0, 1],
                data: transfer(TRANSFER),
            },
            MessageIx {
                program_id_index: 3,
                account_indexes: vec![0, 2],
                data: transfer(TRANSFER * 2),
            },
        ],
        &[],
    );

    let (transaction, bump) = transaction_pda(&f.multisig, 1);

    let create = create_transaction_ix(
        &f.owners[0],
        &f.multisig,
        &transaction,
        &message,
        0,
        f.vault_bump,
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
            AccountMeta::new(f.vault, false),
            AccountMeta::new(first, false),
            AccountMeta::new(second, false),
            AccountMeta::new_readonly(SYSTEM_ID, false),
        ],
    );

    let mut accounts = f.accounts.clone();
    accounts.push((transaction, empty()));
    accounts.push((first, funded(0)));
    accounts.push((second, funded(0)));

    let result = mollusk.process_and_validate_instruction_chain(
        &[
            (&create, &[Check::success()]),
            (&approve_a, &[Check::success()]),
            (&approve_b, &[Check::success()]),
            (&execute, &[Check::success()]),
        ],
        &accounts,
    );

    assert_eq!(result.get_account(&first).unwrap().lamports, TRANSFER);
    assert_eq!(result.get_account(&second).unwrap().lamports, TRANSFER * 2);
    assert_eq!(
        result.get_account(&f.vault).unwrap().lamports,
        VAULT_FUNDING - TRANSFER * 3,
        "both transfers came out of one approval"
    );
}

#[test]
fn an_ephemeral_signer_can_create_an_account() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let (transaction, bump) = transaction_pda(&f.multisig, 1);
    let (ephemeral, ephemeral_bump) = ephemeral_pda(&transaction, 0);

    // System CreateAccount: the new account must sign for itself, which is
    // exactly what an ephemeral signer is for.
    let mut data = 0u32.to_le_bytes().to_vec();
    data.extend_from_slice(&1_000_000u64.to_le_bytes()); // lamports
    data.extend_from_slice(&0u64.to_le_bytes()); // space
    data.extend_from_slice(SYSTEM_ID.as_ref()); // owner

    let message = build_message(
        2,
        2,
        0,
        &[f.vault, ephemeral, SYSTEM_ID],
        &[MessageIx {
            program_id_index: 2,
            account_indexes: vec![0, 1],
            data,
        }],
        &[],
    );

    let create = create_transaction_ix(
        &f.owners[0],
        &f.multisig,
        &transaction,
        &message,
        0,
        f.vault_bump,
        bump,
        &[ephemeral_bump],
    );
    let approve_a = vote_ix(2, &f.owners[0], &f.multisig, &transaction);
    let approve_b = vote_ix(2, &f.owners[1], &f.multisig, &transaction);
    let execute = execute_ix(
        &f.owners[0],
        &f.multisig,
        &transaction,
        &[
            AccountMeta::new(f.vault, false),
            AccountMeta::new(ephemeral, false),
            AccountMeta::new_readonly(SYSTEM_ID, false),
        ],
    );

    let mut accounts = f.accounts.clone();
    accounts.push((transaction, empty()));
    accounts.push((ephemeral, empty()));

    let result = mollusk.process_and_validate_instruction_chain(
        &[
            (&create, &[Check::success()]),
            (&approve_a, &[Check::success()]),
            (&approve_b, &[Check::success()]),
            (&execute, &[Check::success()]),
        ],
        &accounts,
    );

    let created = result.get_account(&ephemeral).unwrap();
    assert_eq!(created.lamports, 1_000_000, "ephemeral account funded");

    let tx = result.get_account(&transaction).unwrap();
    assert_eq!(tx.data[tx_off::EPHEMERAL_COUNT], 1);
    assert_eq!(tx.data[tx_off::EPHEMERAL_BUMPS], ephemeral_bump);
}

#[test]
fn a_time_lock_defers_execution() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    // Proposal 1 sets a one hour delay.
    let (config_tx, config_bump) = transaction_pda(&f.multisig, 1);
    let config = create_transaction_ix(
        &f.owners[0],
        &f.multisig,
        &config_tx,
        &config_message(3, &3600u32.to_le_bytes()),
        0,
        0,
        config_bump,
        &[],
    );
    let config_a = vote_ix(2, &f.owners[0], &f.multisig, &config_tx);
    let config_b = vote_ix(2, &f.owners[1], &f.multisig, &config_tx);
    let config_exec = execute_ix(&f.owners[0], &f.multisig, &config_tx, &config_accounts());

    let mut accounts = f.accounts.clone();
    accounts.push((config_tx, empty()));

    let after_config = mollusk.process_and_validate_instruction_chain(
        &[
            (&config, &[Check::success()]),
            (&config_a, &[Check::success()]),
            (&config_b, &[Check::success()]),
            (&config_exec, &[Check::success()]),
        ],
        &accounts,
    );

    // Proposal 2 spends, and must wait out the delay.
    let destination = Pubkey::new_unique();
    let (spend_tx, spend_bump) = transaction_pda(&f.multisig, 2);
    let message = transfer_message(&f.vault, &destination, TRANSFER);

    let spend = create_transaction_ix(
        &f.owners[0],
        &f.multisig,
        &spend_tx,
        &message,
        0,
        f.vault_bump,
        spend_bump,
        &[],
    );
    let spend_a = vote_ix(2, &f.owners[0], &f.multisig, &spend_tx);
    let spend_b = vote_ix(2, &f.owners[1], &f.multisig, &spend_tx);
    let spend_exec = execute_ix(
        &f.owners[0],
        &f.multisig,
        &spend_tx,
        &[
            AccountMeta::new(f.vault, false),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(SYSTEM_ID, false),
        ],
    );

    let mut accounts: Vec<(Pubkey, Account)> = after_config.resulting_accounts.clone();
    accounts.push((spend_tx, empty()));
    accounts.push((destination, funded(0)));

    let approved = mollusk.process_and_validate_instruction_chain(
        &[
            (&spend, &[Check::success()]),
            (&spend_a, &[Check::success()]),
            (&spend_b, &[Check::success()]),
            (
                &spend_exec,
                &[Check::err(ProgramError::Custom(
                    err::TIME_LOCK_NOT_RELEASED,
                ))],
            ),
        ],
        &accounts,
    );

    assert_eq!(
        approved.get_account(&spend_tx).unwrap().data[tx_off::STATUS],
        status::APPROVED,
        "still approved, just not executable yet"
    );

    // The same accounts, an hour later.
    let mut later = setup();
    later.sysvars.clock.unix_timestamp = TEST_UNIX_TIMESTAMP + 3600;

    let result = later.process_and_validate_instruction(
        &spend_exec,
        &approved.resulting_accounts,
        &[Check::success()],
    );

    assert_eq!(
        result.get_account(&destination).unwrap().lamports,
        TRANSFER,
        "executes once the delay has passed"
    );
}

#[test]
fn a_config_change_makes_older_proposals_stale() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    // Proposal 1 spends and is left unapproved.
    let destination = Pubkey::new_unique();
    let (spend_tx, spend_bump) = transaction_pda(&f.multisig, 1);
    let spend = create_transaction_ix(
        &f.owners[0],
        &f.multisig,
        &spend_tx,
        &transfer_message(&f.vault, &destination, TRANSFER),
        0,
        f.vault_bump,
        spend_bump,
        &[],
    );

    // Proposal 2 changes the threshold, which invalidates proposal 1.
    let (config_tx, config_bump) = transaction_pda(&f.multisig, 2);
    let config = create_transaction_ix(
        &f.owners[0],
        &f.multisig,
        &config_tx,
        &config_message(2, &3u32.to_le_bytes()),
        0,
        0,
        config_bump,
        &[],
    );
    let config_a = vote_ix(2, &f.owners[0], &f.multisig, &config_tx);
    let config_b = vote_ix(2, &f.owners[1], &f.multisig, &config_tx);
    let config_exec = execute_ix(&f.owners[0], &f.multisig, &config_tx, &config_accounts());

    let stale_vote = vote_ix(2, &f.owners[0], &f.multisig, &spend_tx);

    let mut accounts = f.accounts.clone();
    accounts.push((spend_tx, empty()));
    accounts.push((config_tx, empty()));
    accounts.push((destination, funded(0)));

    mollusk.process_and_validate_instruction_chain(
        &[
            (&spend, &[Check::success()]),
            (&config, &[Check::success()]),
            (&config_a, &[Check::success()]),
            (&config_b, &[Check::success()]),
            (&config_exec, &[Check::success()]),
            (
                &stale_vote,
                &[Check::err(ProgramError::Custom(err::STALE_TRANSACTION))],
            ),
        ],
        &accounts,
    );
}

#[test]
fn permissions_gate_voting() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    // Proposal 1 gives owner 2 execute-only rights.
    let mut payload = f.owners[2].as_ref().to_vec();
    payload.push(4);

    let (config_tx, config_bump) = transaction_pda(&f.multisig, 1);
    let config = create_transaction_ix(
        &f.owners[0],
        &f.multisig,
        &config_tx,
        &config_message(5, &payload),
        0,
        0,
        config_bump,
        &[],
    );
    let config_a = vote_ix(2, &f.owners[0], &f.multisig, &config_tx);
    let config_b = vote_ix(2, &f.owners[1], &f.multisig, &config_tx);
    let config_exec = execute_ix(&f.owners[0], &f.multisig, &config_tx, &config_accounts());

    let destination = Pubkey::new_unique();
    let (spend_tx, spend_bump) = transaction_pda(&f.multisig, 2);
    let spend = create_transaction_ix(
        &f.owners[0],
        &f.multisig,
        &spend_tx,
        &transfer_message(&f.vault, &destination, TRANSFER),
        0,
        f.vault_bump,
        spend_bump,
        &[],
    );
    let vote_by_restricted = vote_ix(2, &f.owners[2], &f.multisig, &spend_tx);

    let mut accounts = f.accounts.clone();
    accounts.push((config_tx, empty()));
    accounts.push((spend_tx, empty()));
    accounts.push((destination, funded(0)));

    mollusk.process_and_validate_instruction_chain(
        &[
            (&config, &[Check::success()]),
            (&config_a, &[Check::success()]),
            (&config_b, &[Check::success()]),
            (&config_exec, &[Check::success()]),
            (&spend, &[Check::success()]),
            (
                &vote_by_restricted,
                &[Check::err(ProgramError::Custom(err::UNAUTHORIZED))],
            ),
        ],
        &accounts,
    );
}
