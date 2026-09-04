//! Address lookup table resolution.
//!
//! The approved message names a table and a set of indexes. Execution reads the
//! table and checks that every account passed is the address the named index
//! actually holds, so an executor cannot substitute accounts in those
//! positions.

mod common;

use common::{err, *};
use mollusk_svm::result::Check;
use solana_account::Account;
use solana_instruction::AccountMeta;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

const VAULT_FUNDING: u64 = 5_000_000_000;
const TRANSFER: u64 = 500_000_000;

const LOOKUP_TABLE_PROGRAM: Pubkey =
    solana_pubkey::pubkey!("AddressLookupTab1e1111111111111111111111111");

/// Builds a lookup table account holding `addresses`.
///
/// The meta region is 56 bytes: a discriminator, the deactivation slot, the
/// last extended slot and its start index, an optional authority, and padding.
fn lookup_table(addresses: &[Pubkey], deactivation_slot: u64) -> Account {
    let mut data = Vec::with_capacity(56 + addresses.len() * 32);

    data.extend_from_slice(&1u32.to_le_bytes()); // discriminator
    data.extend_from_slice(&deactivation_slot.to_le_bytes());
    data.extend_from_slice(&0u64.to_le_bytes()); // last_extended_slot
    data.push(0); // last_extended_slot_start_index
    data.push(0); // authority: None
    data.extend_from_slice(&[0u8; 32]);
    data.extend_from_slice(&[0u8; 2]); // padding

    assert_eq!(data.len(), 56);

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
    ];

    Fixture {
        owners,
        multisig,
        vault,
        vault_bump,
        accounts,
    }
}

/// A message whose destination comes from a lookup table rather than the
/// static keys.
///
/// Static keys are the vault and the system program. The destination is index
/// 2, supplied as a writable address by the table.
fn lookup_message(vault: &Pubkey, table: &Pubkey, table_index: u8, lamports: u64) -> Vec<u8> {
    let mut data = 2u32.to_le_bytes().to_vec();
    data.extend_from_slice(&lamports.to_le_bytes());

    build_message(
        1,
        1,
        0,
        &[*vault, SYSTEM_ID],
        &[MessageIx {
            program_id_index: 1,
            account_indexes: vec![0, 2],
            data,
        }],
        &[MessageLookup {
            account_key: *table,
            writable_indexes: vec![table_index],
            readonly_indexes: vec![],
        }],
    )
}

/// Runs create, approve, approve and execute with the given execute accounts.
fn run(
    mollusk: &mollusk_svm::Mollusk,
    f: &Fixture,
    message: &[u8],
    execute_accounts: &[AccountMeta],
    extra: &[(Pubkey, Account)],
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
        &[],
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
fn an_account_from_a_lookup_table_is_usable() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let destination = Pubkey::new_unique();
    let table = Pubkey::new_unique();
    let other = Pubkey::new_unique();

    // The destination sits at index 1 of the table, to prove the index is read
    // rather than assumed.
    let table_account = lookup_table(&[other, destination], u64::MAX);

    let message = lookup_message(&f.vault, &table, 1, TRANSFER);

    let result = run(
        &mollusk,
        &f,
        &message,
        &[
            AccountMeta::new(f.vault, false),
            AccountMeta::new_readonly(SYSTEM_ID, false),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(table, false),
        ],
        &[(destination, funded(0)), (table, table_account)],
        Check::success(),
    );

    assert_eq!(
        result.get_account(&destination).unwrap().lamports,
        TRANSFER,
        "the lookup-supplied account was writable and credited"
    );
    assert_eq!(
        result.get_account(&f.vault).unwrap().lamports,
        VAULT_FUNDING - TRANSFER
    );
}

#[test]
fn substituting_a_lookup_account_is_refused() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let destination = Pubkey::new_unique();
    let attacker = Pubkey::new_unique();
    let table = Pubkey::new_unique();

    let table_account = lookup_table(&[destination], u64::MAX);
    let message = lookup_message(&f.vault, &table, 0, TRANSFER);

    // The table says index 0 is `destination`; the executor passes someone else.
    run(
        &mollusk,
        &f,
        &message,
        &[
            AccountMeta::new(f.vault, false),
            AccountMeta::new_readonly(SYSTEM_ID, false),
            AccountMeta::new(attacker, false),
            AccountMeta::new_readonly(table, false),
        ],
        &[
            (destination, funded(0)),
            (attacker, funded(0)),
            (table, table_account),
        ],
        Check::err(ProgramError::Custom(err::ACCOUNT_MISMATCH)),
    );
}

#[test]
fn a_substituted_table_is_refused() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let destination = Pubkey::new_unique();
    let table = Pubkey::new_unique();
    let other_table = Pubkey::new_unique();

    let message = lookup_message(&f.vault, &table, 0, TRANSFER);

    // A different table, even one holding the right address.
    run(
        &mollusk,
        &f,
        &message,
        &[
            AccountMeta::new(f.vault, false),
            AccountMeta::new_readonly(SYSTEM_ID, false),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(other_table, false),
        ],
        &[
            (destination, funded(0)),
            (other_table, lookup_table(&[destination], u64::MAX)),
        ],
        Check::err(ProgramError::Custom(err::ACCOUNT_MISMATCH)),
    );
}

#[test]
fn a_table_owned_by_the_wrong_program_is_refused() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let destination = Pubkey::new_unique();
    let table = Pubkey::new_unique();

    let mut forged = lookup_table(&[destination], u64::MAX);
    forged.owner = SYSTEM_ID;

    let message = lookup_message(&f.vault, &table, 0, TRANSFER);

    run(
        &mollusk,
        &f,
        &message,
        &[
            AccountMeta::new(f.vault, false),
            AccountMeta::new_readonly(SYSTEM_ID, false),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(table, false),
        ],
        &[(destination, funded(0)), (table, forged)],
        Check::err(ProgramError::Custom(err::ILLEGAL_OWNER)),
    );
}

#[test]
fn a_deactivated_table_is_refused() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let destination = Pubkey::new_unique();
    let table = Pubkey::new_unique();

    // Any deactivation slot other than u64::MAX means the table is going away.
    let table_account = lookup_table(&[destination], 42);
    let message = lookup_message(&f.vault, &table, 0, TRANSFER);

    run(
        &mollusk,
        &f,
        &message,
        &[
            AccountMeta::new(f.vault, false),
            AccountMeta::new_readonly(SYSTEM_ID, false),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(table, false),
        ],
        &[(destination, funded(0)), (table, table_account)],
        Check::err(ProgramError::Custom(err::INVALID_LOOKUP_TABLE)),
    );
}

#[test]
fn an_index_past_the_table_is_refused() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let destination = Pubkey::new_unique();
    let table = Pubkey::new_unique();

    // The table holds one address; the message names index 5.
    let table_account = lookup_table(&[destination], u64::MAX);
    let message = lookup_message(&f.vault, &table, 5, TRANSFER);

    run(
        &mollusk,
        &f,
        &message,
        &[
            AccountMeta::new(f.vault, false),
            AccountMeta::new_readonly(SYSTEM_ID, false),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(table, false),
        ],
        &[(destination, funded(0)), (table, table_account)],
        Check::err(ProgramError::Custom(err::INVALID_LOOKUP_TABLE)),
    );
}

#[test]
fn a_truncated_table_is_refused() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let destination = Pubkey::new_unique();
    let table = Pubkey::new_unique();

    // Shorter than the meta region, so there is nowhere for addresses to be.
    let mut stub = lookup_table(&[destination], u64::MAX);
    stub.data.truncate(20);

    let message = lookup_message(&f.vault, &table, 0, TRANSFER);

    run(
        &mollusk,
        &f,
        &message,
        &[
            AccountMeta::new(f.vault, false),
            AccountMeta::new_readonly(SYSTEM_ID, false),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(table, false),
        ],
        &[(destination, funded(0)), (table, stub)],
        Check::err(ProgramError::Custom(err::INVALID_LOOKUP_TABLE)),
    );
}
