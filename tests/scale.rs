//! Scale: many accounts, many instructions, several lookup tables, several
//! ephemeral signers, and a message big enough to need chunked upload.

mod common;

use common::{err, status, transaction_offset as tx_off, *};
use mollusk_svm::result::Check;
use solana_account::Account;
use solana_instruction::AccountMeta;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

const VAULT_FUNDING: u64 = 20_000_000_000;
const TRANSFER: u64 = 1_000_000;

const LOOKUP_TABLE_PROGRAM: Pubkey =
    solana_pubkey::pubkey!("AddressLookupTab1e1111111111111111111111111");

fn lookup_table(addresses: &[Pubkey]) -> Account {
    let mut data = Vec::with_capacity(56 + addresses.len() * 32);

    data.extend_from_slice(&1u32.to_le_bytes());
    data.extend_from_slice(&u64::MAX.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes());
    data.push(0);
    data.push(0);
    data.extend_from_slice(&[0u8; 32]);
    data.extend_from_slice(&[0u8; 2]);

    for address in addresses {
        data.extend_from_slice(address.as_ref());
    }

    Account {
        lamports: 1_000_000,
        data,
        owner: LOOKUP_TABLE_PROGRAM,
        executable: false,
        rent_epoch: 0,
    }
}

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
            (creator, funded(100_000_000_000)),
            (create_key, funded(0)),
            (multisig, empty()),
            system_account(),
        ],
        &[Check::success()],
    );

    let accounts = vec![
        (owners[0], funded(100_000_000_000)),
        (owners[1], funded(100_000_000_000)),
        (owners[2], funded(100_000_000_000)),
        (multisig, result.get_account(&multisig).unwrap().clone()),
        (vault, funded(VAULT_FUNDING)),
        system_account(),
    ];

    Fixture {
        owners,
        multisig,
        vault,
        vault_bump,
        accounts,
    }
}

fn transfer_data(lamports: u64) -> Vec<u8> {
    let mut data = 2u32.to_le_bytes().to_vec();
    data.extend_from_slice(&lamports.to_le_bytes());
    data
}

/// Runs create, both approvals and execute.
fn run(
    mollusk: &mollusk_svm::Mollusk,
    f: &Fixture,
    message: &[u8],
    execute_accounts: &[AccountMeta],
    extra: &[(Pubkey, Account)],
    ephemeral_bumps: &[u8],
    check: Check,
) -> mollusk_svm::result::InstructionResult {
    let (transaction, bump) = transaction_pda(&f.multisig, 1);

    let create = create_transaction_ix(
        &f.owners[0],
        &f.multisig,
        &transaction,
        message,
        0,
        f.vault_bump,
        bump,
        ephemeral_bumps,
    );
    let approve_a = vote_ix(2, &f.owners[0], &f.multisig, &transaction);
    let approve_b = vote_ix(2, &f.owners[1], &f.multisig, &transaction);
    let execute = execute_ix(&f.owners[0], &f.multisig, &transaction, execute_accounts);

    let mut accounts = f.accounts.clone();
    accounts.push((transaction, empty()));
    accounts.extend_from_slice(extra);

    mollusk.process_and_validate_instruction_chain(
        &[
            (&create, &[Check::success()]),
            (&approve_a, &[Check::success()]),
            (&approve_b, &[Check::success()]),
            (&execute, &[check]),
        ],
        &accounts,
    )
}

#[test]
fn thirty_account_keys_and_ten_instructions() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    // vault, 28 destinations, system program.
    let destinations: Vec<Pubkey> = (0..28).map(|_| Pubkey::new_unique()).collect();

    let mut keys = vec![f.vault];
    keys.extend_from_slice(&destinations);
    keys.push(SYSTEM_ID);

    assert_eq!(keys.len(), 30);

    let system_index = 29u8;

    let instructions: Vec<MessageIx> = (0..10)
        .map(|i| MessageIx {
            program_id_index: system_index,
            account_indexes: vec![0, (i + 1) as u8],
            data: transfer_data(TRANSFER),
        })
        .collect();

    let message = build_message(1, 1, 28, &keys, &instructions, &[]);

    let mut execute_accounts = vec![AccountMeta::new(f.vault, false)];
    for destination in &destinations {
        execute_accounts.push(AccountMeta::new(*destination, false));
    }
    execute_accounts.push(AccountMeta::new_readonly(SYSTEM_ID, false));

    let extra: Vec<(Pubkey, Account)> = destinations.iter().map(|d| (*d, funded(0))).collect();

    let result = run(
        &mollusk,
        &f,
        &message,
        &execute_accounts,
        &extra,
        &[],
        Check::success(),
    );

    for destination in destinations.iter().take(10) {
        assert_eq!(
            result.get_account(destination).unwrap().lamports,
            TRANSFER,
            "each of the ten instructions ran"
        );
    }

    assert_eq!(
        result.get_account(&destinations[10]).unwrap().lamports,
        0,
        "keys past the instructions were verified but untouched"
    );

    assert_eq!(
        result.get_account(&f.vault).unwrap().lamports,
        VAULT_FUNDING - TRANSFER * 10
    );
}

#[test]
fn an_instruction_over_the_cpi_account_cap_is_refused() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    // 33 account indexes against a cap of 32.
    let others: Vec<Pubkey> = (0..33).map(|_| Pubkey::new_unique()).collect();

    let mut keys = vec![f.vault];
    keys.extend_from_slice(&others);
    keys.push(SYSTEM_ID);

    let message = build_message(
        1,
        1,
        33,
        &keys,
        &[MessageIx {
            program_id_index: 34,
            account_indexes: (1..=33).collect(),
            data: transfer_data(TRANSFER),
        }],
        &[],
    );

    let mut execute_accounts = vec![AccountMeta::new(f.vault, false)];
    for other in &others {
        execute_accounts.push(AccountMeta::new(*other, false));
    }
    execute_accounts.push(AccountMeta::new_readonly(SYSTEM_ID, false));

    let extra: Vec<(Pubkey, Account)> = others.iter().map(|o| (*o, funded(0))).collect();

    run(
        &mollusk,
        &f,
        &message,
        &execute_accounts,
        &extra,
        &[],
        Check::err(ProgramError::Custom(err::TOO_MANY_ACCOUNTS)),
    );
}

#[test]
fn two_tables_with_writable_and_readonly_entries() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let first = Pubkey::new_unique();
    let second = Pubkey::new_unique();
    let readonly_a = Pubkey::new_unique();
    let readonly_b = Pubkey::new_unique();

    let table_a = Pubkey::new_unique();
    let table_b = Pubkey::new_unique();

    // Table A holds the first destination and a readonly account; table B holds
    // the second destination and another readonly account.
    let table_a_account = lookup_table(&[first, readonly_a]);
    let table_b_account = lookup_table(&[readonly_b, second]);

    // Static keys are the vault and the system program. The runtime appends
    // every table's writables first, then every table's readonlys, so the
    // resolved order is first(2), second(3), readonly_a(4), readonly_b(5).
    let message = build_message(
        1,
        1,
        0,
        &[f.vault, SYSTEM_ID],
        &[
            MessageIx {
                program_id_index: 1,
                account_indexes: vec![0, 2],
                data: transfer_data(TRANSFER),
            },
            MessageIx {
                program_id_index: 1,
                account_indexes: vec![0, 3],
                data: transfer_data(TRANSFER * 2),
            },
        ],
        &[
            MessageLookup {
                account_key: table_a,
                writable_indexes: vec![0],
                readonly_indexes: vec![1],
            },
            MessageLookup {
                account_key: table_b,
                writable_indexes: vec![1],
                readonly_indexes: vec![0],
            },
        ],
    );

    let execute_accounts = vec![
        AccountMeta::new(f.vault, false),
        AccountMeta::new_readonly(SYSTEM_ID, false),
        AccountMeta::new(first, false),
        AccountMeta::new(second, false),
        AccountMeta::new_readonly(readonly_a, false),
        AccountMeta::new_readonly(readonly_b, false),
        AccountMeta::new_readonly(table_a, false),
        AccountMeta::new_readonly(table_b, false),
    ];

    let extra = vec![
        (first, funded(0)),
        (second, funded(0)),
        (readonly_a, funded(0)),
        (readonly_b, funded(0)),
        (table_a, table_a_account),
        (table_b, table_b_account),
    ];

    let result = run(
        &mollusk,
        &f,
        &message,
        &execute_accounts,
        &extra,
        &[],
        Check::success(),
    );

    assert_eq!(result.get_account(&first).unwrap().lamports, TRANSFER);
    assert_eq!(result.get_account(&second).unwrap().lamports, TRANSFER * 2);
    assert_eq!(
        result.get_account(&readonly_a).unwrap().lamports,
        0,
        "readonly entries were resolved and verified, not spent"
    );
}

#[test]
fn a_readonly_entry_in_the_wrong_position_is_refused() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let writable = Pubkey::new_unique();
    let readonly = Pubkey::new_unique();
    let table = Pubkey::new_unique();

    let message = build_message(
        1,
        1,
        0,
        &[f.vault, SYSTEM_ID],
        &[MessageIx {
            program_id_index: 1,
            account_indexes: vec![0, 2],
            data: transfer_data(TRANSFER),
        }],
        &[MessageLookup {
            account_key: table,
            writable_indexes: vec![0],
            readonly_indexes: vec![1],
        }],
    );

    // The writable and readonly accounts are passed the wrong way round.
    let execute_accounts = vec![
        AccountMeta::new(f.vault, false),
        AccountMeta::new_readonly(SYSTEM_ID, false),
        AccountMeta::new(readonly, false),
        AccountMeta::new_readonly(writable, false),
        AccountMeta::new_readonly(table, false),
    ];

    let extra = vec![
        (writable, funded(0)),
        (readonly, funded(0)),
        (table, lookup_table(&[writable, readonly])),
    ];

    run(
        &mollusk,
        &f,
        &message,
        &execute_accounts,
        &extra,
        &[],
        Check::err(ProgramError::Custom(err::ACCOUNT_MISMATCH)),
    );
}

#[test]
fn four_ephemeral_signers_each_create_an_account() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let (transaction, _) = transaction_pda(&f.multisig, 1);

    let ephemerals: Vec<(Pubkey, u8)> = (0..4).map(|i| ephemeral_pda(&transaction, i)).collect();

    let mut keys = vec![f.vault];
    for (address, _) in &ephemerals {
        keys.push(*address);
    }
    keys.push(SYSTEM_ID);

    let create_account_data = || {
        let mut data = 0u32.to_le_bytes().to_vec();
        data.extend_from_slice(&1_000_000u64.to_le_bytes());
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(SYSTEM_ID.as_ref());
        data
    };

    // All five signers: the vault plus four ephemeral pdas.
    let instructions: Vec<MessageIx> = (0..4)
        .map(|i| MessageIx {
            program_id_index: 5,
            account_indexes: vec![0, (i + 1) as u8],
            data: create_account_data(),
        })
        .collect();

    let message = build_message(5, 5, 0, &keys, &instructions, &[]);

    let mut execute_accounts = vec![AccountMeta::new(f.vault, false)];
    for (address, _) in &ephemerals {
        execute_accounts.push(AccountMeta::new(*address, false));
    }
    execute_accounts.push(AccountMeta::new_readonly(SYSTEM_ID, false));

    let extra: Vec<(Pubkey, Account)> = ephemerals.iter().map(|(a, _)| (*a, empty())).collect();

    let bumps: Vec<u8> = ephemerals.iter().map(|(_, b)| *b).collect();

    let result = run(
        &mollusk,
        &f,
        &message,
        &execute_accounts,
        &extra,
        &bumps,
        Check::success(),
    );

    for (address, _) in &ephemerals {
        assert_eq!(
            result.get_account(address).unwrap().lamports,
            1_000_000,
            "each ephemeral signer created its account"
        );
    }

    let tx = result.get_account(&transaction).unwrap();
    assert_eq!(tx.data[tx_off::EPHEMERAL_COUNT], 4);
}

#[test]
fn a_large_message_uploaded_across_four_chunks() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    // 60 static keys and 20 instructions puts the message past 2 KB, well
    // beyond what one transaction could carry.
    let destinations: Vec<Pubkey> = (0..58).map(|_| Pubkey::new_unique()).collect();

    let mut keys = vec![f.vault];
    keys.extend_from_slice(&destinations);
    keys.push(SYSTEM_ID);

    let system_index = 59u8;

    let instructions: Vec<MessageIx> = (0..20)
        .map(|i| MessageIx {
            program_id_index: system_index,
            account_indexes: vec![0, (i + 1) as u8],
            data: transfer_data(TRANSFER),
        })
        .collect();

    let message = build_message(1, 1, 58, &keys, &instructions, &[]);
    assert!(message.len() > 2000, "message is {} bytes", message.len());

    let hash = solana_sha256_hasher::hashv(&[&message]).to_bytes();

    let (buffer, buffer_bump) = buffer_pda(&f.multisig, &f.owners[0], 0);
    let (transaction, tx_bump) = transaction_pda(&f.multisig, 1);

    let quarter = message.len() / 4;

    let open = buffer_create_ix(
        &f.owners[0],
        &f.multisig,
        &buffer,
        hash,
        message.len() as u32,
        0,
        0,
        buffer_bump,
        &message[..quarter],
    );
    let extend_two = buffer_extend_ix(&f.owners[0], &buffer, &message[quarter..quarter * 2]);
    let extend_three = buffer_extend_ix(&f.owners[0], &buffer, &message[quarter * 2..quarter * 3]);
    let extend_four = buffer_extend_ix(&f.owners[0], &buffer, &message[quarter * 3..]);
    let promote = create_from_buffer_ix(
        &f.owners[0],
        &f.multisig,
        &transaction,
        &buffer,
        tx_bump,
        f.vault_bump,
        &[],
    );
    let approve_a = vote_ix(2, &f.owners[0], &f.multisig, &transaction);
    let approve_b = vote_ix(2, &f.owners[1], &f.multisig, &transaction);

    let mut execute_accounts = vec![AccountMeta::new(f.vault, false)];
    for destination in &destinations {
        execute_accounts.push(AccountMeta::new(*destination, false));
    }
    execute_accounts.push(AccountMeta::new_readonly(SYSTEM_ID, false));

    let execute = execute_ix(&f.owners[0], &f.multisig, &transaction, &execute_accounts);

    let mut accounts = f.accounts.clone();
    accounts.push((buffer, empty()));
    accounts.push((transaction, empty()));
    for destination in &destinations {
        accounts.push((*destination, funded(0)));
    }

    let result = mollusk.process_and_validate_instruction_chain(
        &[
            (&open, &[Check::success()]),
            (&extend_two, &[Check::success()]),
            (&extend_three, &[Check::success()]),
            (&extend_four, &[Check::success()]),
            (&promote, &[Check::success()]),
            (&approve_a, &[Check::success()]),
            (&approve_b, &[Check::success()]),
            (&execute, &[Check::success()]),
        ],
        &accounts,
    );

    let tx = result.get_account(&transaction).unwrap();
    assert_eq!(tx.data[tx_off::STATUS], status::EXECUTED);
    assert_eq!(
        stored_message(&tx.data, 3),
        &message[..],
        "the reassembled message is byte identical"
    );

    for destination in destinations.iter().take(20) {
        assert_eq!(result.get_account(destination).unwrap().lamports, TRANSFER);
    }
}
