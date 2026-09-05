//! The owner set at its ceiling. A multisig of this size cannot be born in one
//! transaction, so the account is composed directly and driven from there.

mod common;

use common::{err, multisig_offset as ms_off, status, transaction_offset as tx_off, *};
use mollusk_svm::result::Check;
use solana_account::Account;
use solana_instruction::AccountMeta;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

const MAX_OWNER: usize = 4096;
const VAULT_FUNDING: u64 = 5_000_000_000;
const TRANSFER: u64 = 1_000_000_000;
const THRESHOLD: u32 = 3;

/// A multisig account holding `n` owners, all with every permission.
fn compose(create_key: &Pubkey, bump: u8, owners: &[Pubkey], threshold: u32) -> Account {
    let mut data = vec![0u8; ms_off::HEADER_LEN + owners.len() * 33];

    data[ms_off::CREATE_KEY..ms_off::CREATE_KEY + 32].copy_from_slice(create_key.as_ref());
    data[ms_off::OWNERS_COUNT..ms_off::OWNERS_COUNT + 4]
        .copy_from_slice(&(owners.len() as u32).to_le_bytes());
    data[ms_off::VOTER_COUNT..ms_off::VOTER_COUNT + 4]
        .copy_from_slice(&(owners.len() as u32).to_le_bytes());
    data[ms_off::THRESHOLD..ms_off::THRESHOLD + 4].copy_from_slice(&threshold.to_le_bytes());
    data[ms_off::BUMP] = bump;

    for (i, owner) in owners.iter().enumerate() {
        let at = ms_off::OWNERS + i * 32;
        data[at..at + 32].copy_from_slice(owner.as_ref());
    }

    Account {
        lamports: 10_000_000_000,
        data,
        owner: PROGRAM_ID,
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

/// A `threshold`-of-`n` multisig with a funded vault.
fn fixture(n: usize) -> Fixture {
    let create_key = Pubkey::new_unique();
    let (multisig, bump) = multisig_pda(&create_key);
    let owners = sorted_owners(n);
    let (vault, vault_bump) = vault_pda(&multisig, 0);

    let mut accounts = vec![
        (multisig, compose(&create_key, bump, &owners, THRESHOLD)),
        (vault, funded(VAULT_FUNDING)),
        system_account(),
        program_account(),
    ];

    // The owners that actually sign below, plus the two at the extremes of the
    // sorted set, which is where a binary search is most likely to go wrong.
    for owner in [owners[0], owners[1], owners[2], owners[n - 1]] {
        accounts.push((owner, funded(100_000_000_000)));
    }

    Fixture {
        owners,
        multisig,
        vault,
        vault_bump,
        accounts,
    }
}

#[test]
fn account_size_at_the_ceiling() {
    let f = fixture(MAX_OWNER);
    let data = &f.accounts[0].1.data;

    assert_eq!(data.len(), 144 + MAX_OWNER * 33);
    assert_eq!(data.len(), 135_312);
    assert_eq!(u32_at(data, ms_off::OWNERS_COUNT), MAX_OWNER as u32);
}

#[test]
fn full_set_creates_approves_and_executes() {
    let mollusk = setup();
    let f = fixture(MAX_OWNER);

    let destination = Pubkey::new_unique();
    let (transaction, bump) = transaction_pda(&f.multisig, 1);
    let message = transfer_message(&f.vault, &destination, TRANSFER);

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
    // The last owner in the set, the far end of every binary search.
    let approve_c = vote_ix(2, &f.owners[MAX_OWNER - 1], &f.multisig, &transaction);
    let execute = execute_ix(
        &f.owners[0],
        &f.multisig,
        &transaction,
        &[
            AccountMeta::new(f.vault, false),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(SYSTEM_ID, false),
        ],
    );

    let mut accounts = f.accounts.clone();
    accounts.push((transaction, empty()));
    accounts.push((destination, funded(0)));
    accounts.push((f.owners[MAX_OWNER - 1], funded(100_000_000_000)));

    let result = mollusk.process_and_validate_instruction_chain(
        &[
            (&create, &[Check::success()]),
            (&approve_a, &[Check::success()]),
            (&approve_b, &[Check::success()]),
            (&approve_c, &[Check::success()]),
            (&execute, &[Check::success()]),
        ],
        &accounts,
    );

    let data = &result.get_account(&transaction).unwrap().data;

    assert_eq!(data[tx_off::STATUS], status::EXECUTED);
    assert_eq!(u32_at(data, tx_off::OWNERS_COUNT), MAX_OWNER as u32);
    assert_eq!(u32_at(data, tx_off::APPROVED_COUNT), THRESHOLD);

    let (approved, rejected, cancelled) = votes(data, MAX_OWNER);

    assert_eq!(approved.len(), 512);
    assert!(bit(approved, 0));
    assert!(bit(approved, 1));
    assert!(bit(approved, MAX_OWNER - 1));
    assert!(!bit(approved, 2));
    assert!(rejected.iter().all(|b| *b == 0));
    assert!(cancelled.iter().all(|b| *b == 0));

    assert_eq!(result.get_account(&destination).unwrap().lamports, TRANSFER);
}

#[test]
fn a_proposal_stays_small_at_the_ceiling() {
    let mollusk = setup();
    let f = fixture(MAX_OWNER);

    let destination = Pubkey::new_unique();
    let (transaction, bump) = transaction_pda(&f.multisig, 1);
    let message = transfer_message(&f.vault, &destination, TRANSFER);

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

    let mut accounts = f.accounts.clone();
    accounts.push((transaction, empty()));

    let result = mollusk.process_and_validate_instruction(&create, &accounts, &[Check::success()]);

    let data = &result.get_account(&transaction).unwrap().data;

    // A vote is a bit, so 4096 owners cost 512 bytes per bitmap and no more.
    assert_eq!(data.len(), 112 + 3 * 512 + message.len());
    assert!(data.len() < 1_800);
}

#[test]
fn a_stranger_is_refused_against_the_full_set() {
    let mollusk = setup();
    let f = fixture(MAX_OWNER);

    let destination = Pubkey::new_unique();
    let (transaction, bump) = transaction_pda(&f.multisig, 1);
    let message = transfer_message(&f.vault, &destination, TRANSFER);
    let stranger = Pubkey::new_unique();

    let create = create_transaction_ix(
        &stranger,
        &f.multisig,
        &transaction,
        &message,
        0,
        f.vault_bump,
        bump,
        &[],
    );

    let mut accounts = f.accounts.clone();
    accounts.push((transaction, empty()));
    accounts.push((stranger, funded(100_000_000_000)));

    mollusk.process_and_validate_instruction(
        &create,
        &accounts,
        &[Check::err(ProgramError::Custom(err::NOT_AN_OWNER))],
    );
}

#[test]
fn the_ceiling_holds() {
    let mollusk = setup();
    let f = fixture(MAX_OWNER);

    let (transaction, bump) = transaction_pda(&f.multisig, 1);
    let newcomer = Pubkey::new_unique();
    let message = config_message(0, newcomer.as_ref());

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
    let approve_c = vote_ix(2, &f.owners[2], &f.multisig, &transaction);
    let execute = execute_ix(&f.owners[0], &f.multisig, &transaction, &config_accounts());

    let mut accounts = f.accounts.clone();
    accounts.push((transaction, empty()));

    mollusk.process_and_validate_instruction_chain(
        &[
            (&create, &[Check::success()]),
            (&approve_a, &[Check::success()]),
            (&approve_b, &[Check::success()]),
            (&approve_c, &[Check::success()]),
            (
                &execute,
                &[Check::err(ProgramError::Custom(err::INVALID_OWNER_COUNT))],
            ),
        ],
        &accounts,
    );
}

#[test]
fn one_below_the_ceiling_still_admits_an_owner() {
    let mollusk = setup();
    let f = fixture(MAX_OWNER - 1);

    let (transaction, bump) = transaction_pda(&f.multisig, 1);
    let newcomer = Pubkey::new_unique();
    let message = config_message(0, newcomer.as_ref());

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
    let approve_c = vote_ix(2, &f.owners[2], &f.multisig, &transaction);
    let execute = execute_ix(&f.owners[0], &f.multisig, &transaction, &config_accounts());

    let mut accounts = f.accounts.clone();
    accounts.push((transaction, empty()));

    let result = mollusk.process_and_validate_instruction_chain(
        &[
            (&create, &[Check::success()]),
            (&approve_a, &[Check::success()]),
            (&approve_b, &[Check::success()]),
            (&approve_c, &[Check::success()]),
            (&execute, &[Check::success()]),
        ],
        &accounts,
    );

    let data = &result.get_account(&f.multisig).unwrap().data;

    assert_eq!(u32_at(data, ms_off::OWNERS_COUNT), MAX_OWNER as u32);
    assert_eq!(u32_at(data, ms_off::VOTER_COUNT), MAX_OWNER as u32);
    assert_eq!(data.len(), 144 + MAX_OWNER * 33);

    // The set is still sorted across the seam the insert opened.
    let mut previous = owner_at(data, 0);
    for i in 1..MAX_OWNER {
        let current = owner_at(data, i);
        assert!(previous < current, "owners unsorted at {i}");
        previous = current;
    }
}
