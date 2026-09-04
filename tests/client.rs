//! End to end through the client API only.
//!
//! Every instruction here is built by `multisig::client`, so this is the path a
//! real consumer takes. Nothing hand-rolls a byte layout.

mod common;

use common::{multisig_offset as ms_off, setup, status, transaction_offset as tx_off};
use mollusk_svm::result::Check;
use multisig::client::{self, Message, MessageInstruction, action, permission};
use solana_account::Account;
use solana_pubkey::Pubkey;

const FUNDING: u64 = 10_000_000_000;
const VAULT_FUNDING: u64 = 5_000_000_000;
const TRANSFER: u64 = 1_000_000_000;

fn funded(lamports: u64) -> Account {
    Account::new(lamports, 0, &client::SYSTEM_PROGRAM)
}

fn empty() -> Account {
    Account::default()
}

/// A 2-of-3 multisig with a funded vault, built entirely through the client.
struct Wallet {
    owners: Vec<Pubkey>,
    multisig: Pubkey,
    vault: Pubkey,
    accounts: Vec<(Pubkey, Account)>,
}

fn open_wallet(mollusk: &mollusk_svm::Mollusk) -> Wallet {
    let payer = Pubkey::new_unique();
    let create_key = Pubkey::new_unique();

    let mut owners: Vec<Pubkey> = (0..3).map(|_| Pubkey::new_unique()).collect();
    owners.sort();

    let (multisig, _) = client::multisig_address(&create_key);
    let (vault, _) = client::vault_address(&multisig, 0);

    let ix = client::init_multisig(&payer, &create_key, &owners, 2);

    let result = mollusk.process_and_validate_instruction(
        &ix,
        &[
            (payer, funded(FUNDING)),
            (create_key, funded(0)),
            (multisig, empty()),
            mollusk_svm::program::keyed_account_for_system_program(),
        ],
        &[Check::success()],
    );

    let mut accounts: Vec<(Pubkey, Account)> =
        owners.iter().map(|o| (*o, funded(FUNDING))).collect();

    accounts.push((multisig, result.get_account(&multisig).unwrap().clone()));
    accounts.push((vault, funded(VAULT_FUNDING)));
    accounts.push(mollusk_svm::program::keyed_account_for_system_program());
    accounts.push((
        client::program_id(),
        mollusk_svm::program::create_program_account_loader_v3(&client::program_id()),
    ));

    Wallet {
        owners,
        multisig,
        vault,
        accounts,
    }
}

#[test]
fn a_spend_from_proposal_to_reclaimed_rent() {
    let mollusk = setup();
    let w = open_wallet(&mollusk);

    let destination = Pubkey::new_unique();
    let (transaction, _) = client::transaction_address(&w.multisig, 1);

    let message = client::transfer(&w.vault, &destination, TRANSFER);

    let create = client::create_transaction(&w.owners[0], &w.multisig, 1, &message, 0, &[]);
    let approve_a = client::approve(&w.owners[0], &w.multisig, &transaction);
    let approve_b = client::approve(&w.owners[1], &w.multisig, &transaction);
    let execute = client::execute(
        &w.owners[0],
        &w.multisig,
        &transaction,
        &message.execute_accounts(&[]),
    );
    let close = client::close_transaction(&transaction, &w.multisig, &w.owners[0]);

    let mut accounts = w.accounts.clone();
    accounts.push((transaction, empty()));
    accounts.push((destination, funded(0)));

    let result = mollusk.process_and_validate_instruction_chain(
        &[
            (&create, &[Check::success()]),
            (&approve_a, &[Check::success()]),
            (&approve_b, &[Check::success()]),
            (&execute, &[Check::success()]),
            (&close, &[Check::success()]),
        ],
        &accounts,
    );

    assert_eq!(
        result.get_account(&destination).unwrap().lamports,
        TRANSFER,
        "destination credited"
    );
    assert_eq!(
        result.get_account(&w.vault).unwrap().lamports,
        VAULT_FUNDING - TRANSFER,
        "vault debited"
    );
    assert_eq!(
        result.get_account(&transaction).unwrap().lamports,
        0,
        "proposal closed"
    );

    let ms = result.get_account(&w.multisig).unwrap();
    assert_eq!(
        &ms.data[ms_off::CLOSED_TRANSACTION_COUNT..ms_off::CLOSED_TRANSACTION_COUNT + 8],
        &1u64.to_le_bytes()
    );
}

#[test]
fn two_transfers_under_one_approval() {
    let mollusk = setup();
    let w = open_wallet(&mollusk);

    let first = Pubkey::new_unique();
    let second = Pubkey::new_unique();
    let (transaction, _) = client::transaction_address(&w.multisig, 1);

    let transfer_data = |amount: u64| {
        let mut data = 2u32.to_le_bytes().to_vec();
        data.extend_from_slice(&amount.to_le_bytes());
        data
    };

    let message = Message {
        num_signers: 1,
        num_writable_signers: 1,
        num_writable_non_signers: 2,
        account_keys: vec![w.vault, first, second, client::SYSTEM_PROGRAM],
        instructions: vec![
            MessageInstruction {
                program_id_index: 3,
                account_indexes: vec![0, 1],
                data: transfer_data(TRANSFER),
            },
            MessageInstruction {
                program_id_index: 3,
                account_indexes: vec![0, 2],
                data: transfer_data(TRANSFER),
            },
        ],
        lookups: vec![],
    };

    let create = client::create_transaction(&w.owners[0], &w.multisig, 1, &message, 0, &[]);
    let approve_a = client::approve(&w.owners[0], &w.multisig, &transaction);
    let approve_b = client::approve(&w.owners[1], &w.multisig, &transaction);
    let execute = client::execute(
        &w.owners[0],
        &w.multisig,
        &transaction,
        &message.execute_accounts(&[]),
    );

    let mut accounts = w.accounts.clone();
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
    assert_eq!(result.get_account(&second).unwrap().lamports, TRANSFER);
}

#[test]
fn an_owner_is_added_by_vote() {
    let mollusk = setup();
    let w = open_wallet(&mollusk);

    let newcomer = Pubkey::new_unique();
    let (transaction, _) = client::transaction_address(&w.multisig, 1);

    let message = client::config_action(action::ADD_OWNER, newcomer.as_ref());

    let create = client::create_transaction(&w.owners[0], &w.multisig, 1, &message, 0, &[]);
    let approve_a = client::approve(&w.owners[0], &w.multisig, &transaction);
    let approve_b = client::approve(&w.owners[1], &w.multisig, &transaction);
    let execute = client::execute(
        &w.owners[0],
        &w.multisig,
        &transaction,
        &message.execute_accounts(&[]),
    );

    let mut accounts = w.accounts.clone();
    accounts.push((transaction, empty()));

    let result = mollusk.process_and_validate_instruction_chain(
        &[
            (&create, &[Check::success()]),
            (&approve_a, &[Check::success()]),
            (&approve_b, &[Check::success()]),
            (&execute, &[Check::success()]),
        ],
        &accounts,
    );

    let ms = result.get_account(&w.multisig).unwrap();
    assert_eq!(ms.data[ms_off::OWNERS_COUNT], 4);

    let mut expected = w.owners.clone();
    expected.push(newcomer);
    expected.sort();

    for (i, owner) in expected.iter().enumerate() {
        let at = ms_off::OWNERS + i * 32;
        assert_eq!(&ms.data[at..at + 32], owner.as_ref(), "owner {i}");
    }
}

#[test]
fn a_permission_is_set_by_vote() {
    let mollusk = setup();
    let w = open_wallet(&mollusk);

    let (transaction, _) = client::transaction_address(&w.multisig, 1);

    let mut payload = w.owners[2].as_ref().to_vec();
    payload.push(permission::VOTE | permission::EXECUTE);

    let message = client::config_action(action::SET_PERMISSION, &payload);

    let create = client::create_transaction(&w.owners[0], &w.multisig, 1, &message, 0, &[]);
    let approve_a = client::approve(&w.owners[0], &w.multisig, &transaction);
    let approve_b = client::approve(&w.owners[1], &w.multisig, &transaction);
    let execute = client::execute(
        &w.owners[0],
        &w.multisig,
        &transaction,
        &message.execute_accounts(&[]),
    );

    let mut accounts = w.accounts.clone();
    accounts.push((transaction, empty()));

    let result = mollusk.process_and_validate_instruction_chain(
        &[
            (&create, &[Check::success()]),
            (&approve_a, &[Check::success()]),
            (&approve_b, &[Check::success()]),
            (&execute, &[Check::success()]),
        ],
        &accounts,
    );

    let ms = result.get_account(&w.multisig).unwrap();
    assert_eq!(
        ms.data[ms_off::PERMISSIONS + 2],
        permission::VOTE | permission::EXECUTE
    );
}

#[test]
fn a_message_uploaded_in_chunks_executes() {
    let mollusk = setup();
    let w = open_wallet(&mollusk);

    let destination = Pubkey::new_unique();
    let message = client::transfer(&w.vault, &destination, TRANSFER);
    let encoded = message.encode();
    let hash = solana_sha256_hasher::hashv(&[&encoded]).to_bytes();

    let (buffer, _) = client::buffer_address(&w.multisig, &w.owners[0], 0);
    let (transaction, _) = client::transaction_address(&w.multisig, 1);

    let split = encoded.len() / 3;

    let open = client::buffer_create(
        &w.owners[0],
        &w.multisig,
        0,
        0,
        hash,
        encoded.len() as u32,
        &encoded[..split],
    );
    let extend = client::buffer_extend(&w.owners[0], &buffer, &encoded[split..]);
    let promote = client::create_from_buffer(&w.owners[0], &w.multisig, 1, &buffer, 0, &[]);
    let approve_a = client::approve(&w.owners[0], &w.multisig, &transaction);
    let approve_b = client::approve(&w.owners[1], &w.multisig, &transaction);
    let execute = client::execute(
        &w.owners[0],
        &w.multisig,
        &transaction,
        &message.execute_accounts(&[]),
    );

    let mut accounts = w.accounts.clone();
    accounts.push((buffer, empty()));
    accounts.push((transaction, empty()));
    accounts.push((destination, funded(0)));

    let result = mollusk.process_and_validate_instruction_chain(
        &[
            (&open, &[Check::success()]),
            (&extend, &[Check::success()]),
            (&promote, &[Check::success()]),
            (&approve_a, &[Check::success()]),
            (&approve_b, &[Check::success()]),
            (&execute, &[Check::success()]),
        ],
        &accounts,
    );

    assert_eq!(result.get_account(&destination).unwrap().lamports, TRANSFER);
    assert_eq!(
        result.get_account(&transaction).unwrap().data[tx_off::STATUS],
        status::EXECUTED
    );
}

#[test]
fn a_rejected_proposal_never_runs() {
    let mollusk = setup();
    let w = open_wallet(&mollusk);

    let destination = Pubkey::new_unique();
    let (transaction, _) = client::transaction_address(&w.multisig, 1);
    let message = client::transfer(&w.vault, &destination, TRANSFER);

    let create = client::create_transaction(&w.owners[0], &w.multisig, 1, &message, 0, &[]);
    let reject_a = client::reject(&w.owners[0], &w.multisig, &transaction);
    let reject_b = client::reject(&w.owners[1], &w.multisig, &transaction);

    let mut accounts = w.accounts.clone();
    accounts.push((transaction, empty()));
    accounts.push((destination, funded(0)));

    let result = mollusk.process_and_validate_instruction_chain(
        &[
            (&create, &[Check::success()]),
            (&reject_a, &[Check::success()]),
            (&reject_b, &[Check::success()]),
        ],
        &accounts,
    );

    assert_eq!(
        result.get_account(&transaction).unwrap().data[tx_off::STATUS],
        status::REJECTED
    );
    assert_eq!(result.get_account(&destination).unwrap().lamports, 0);
}
