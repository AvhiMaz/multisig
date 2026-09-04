//! Boundaries and the checks that only matter under abuse.

mod common;

use common::{err, status, transaction_offset as tx_off, *};
use mollusk_svm::result::Check;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
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

fn fixture_with(mollusk: &mollusk_svm::Mollusk, owner_count: usize, threshold: u8) -> Fixture {
    let creator = Pubkey::new_unique();
    let create_key = Pubkey::new_unique();
    let (multisig, bump) = multisig_pda(&create_key);
    let owners = sorted_owners(owner_count);
    let (vault, vault_bump) = vault_pda(&multisig, 0);

    let ix = init_multisig_ix(&creator, &create_key, &multisig, &owners, threshold, bump);

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

    let mut accounts: Vec<(Pubkey, Account)> = owners
        .iter()
        .map(|o| (*o, funded(10_000_000_000)))
        .collect();

    accounts.push((multisig, result.get_account(&multisig).unwrap().clone()));
    accounts.push((vault, funded(VAULT_FUNDING)));
    accounts.push(system_account());

    Fixture {
        owners,
        multisig,
        vault,
        vault_bump,
        accounts,
    }
}

fn fixture(mollusk: &mollusk_svm::Mollusk) -> Fixture {
    fixture_with(mollusk, 3, 2)
}

#[test]
fn a_proposal_executes_only_once() {
    let mollusk = setup();
    let f = fixture(&mollusk);

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

    // The status is written before the CPI precisely so a second run finds a
    // spent proposal, whether it comes from a caller or a re-entering callee.
    let result = mollusk.process_and_validate_instruction_chain(
        &[
            (&create, &[Check::success()]),
            (&approve_a, &[Check::success()]),
            (&approve_b, &[Check::success()]),
            (&execute, &[Check::success()]),
            (
                &execute,
                &[Check::err(ProgramError::Custom(err::INVALID_STATUS))],
            ),
        ],
        &accounts,
    );

    assert_eq!(
        result.get_account(&destination).unwrap().lamports,
        TRANSFER,
        "credited once, not twice"
    );
}

#[test]
fn a_full_owner_set_works() {
    let mollusk = setup();
    let f = fixture_with(&mollusk, 10, 10);

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

    let approvals: Vec<Instruction> = f
        .owners
        .iter()
        .map(|o| vote_ix(2, o, &f.multisig, &transaction))
        .collect();

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

    let ok: [Check; 1] = [Check::success()];

    let mut chain: Vec<(&Instruction, &[Check])> = vec![(&create, &ok)];
    for approval in &approvals {
        chain.push((approval, &ok));
    }
    chain.push((&execute, &ok));

    let mut accounts = f.accounts.clone();
    accounts.push((transaction, empty()));
    accounts.push((destination, funded(0)));

    let result = mollusk.process_and_validate_instruction_chain(&chain, &accounts);

    let tx = result.get_account(&transaction).unwrap();
    assert_eq!(tx.data[tx_off::APPROVED_COUNT], 10, "all ten voted");
    assert_eq!(tx.data[tx_off::STATUS], status::EXECUTED);
}

#[test]
fn more_owners_than_the_cap_is_refused() {
    let mollusk = setup();

    let creator = Pubkey::new_unique();
    let create_key = Pubkey::new_unique();
    let (multisig, bump) = multisig_pda(&create_key);
    let owners = sorted_owners(11);

    // The payload only has room for ten, so the count is what is rejected.
    let mut data = vec![0u8];
    let mut payload = [0u8; 324];
    for (i, owner) in owners.iter().take(10).enumerate() {
        payload[i * 32..(i + 1) * 32].copy_from_slice(owner.as_ref());
    }
    payload[320] = 11;
    payload[321] = 2;
    payload[322] = bump;
    data.extend_from_slice(&payload);

    let ix = Instruction::new_with_bytes(
        PROGRAM_ID,
        &data,
        vec![
            AccountMeta::new(creator, true),
            AccountMeta::new_readonly(create_key, true),
            AccountMeta::new(multisig, false),
            AccountMeta::new_readonly(SYSTEM_ID, false),
        ],
    );

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
fn a_zero_threshold_is_refused() {
    let mollusk = setup();

    let creator = Pubkey::new_unique();
    let create_key = Pubkey::new_unique();
    let (multisig, bump) = multisig_pda(&create_key);
    let owners = sorted_owners(3);

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
fn a_message_over_the_cap_is_refused() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let (transaction, bump) = transaction_pda(&f.multisig, 1);

    // Larger than MAX_MESSAGE_SIZE, rejected before anything is parsed.
    let oversized = vec![0u8; 4097];

    let create = create_transaction_ix(
        &f.owners[0],
        &f.multisig,
        &transaction,
        &oversized,
        0,
        f.vault_bump,
        bump,
        &[],
    );

    let mut accounts = f.accounts.clone();
    accounts.push((transaction, empty()));

    mollusk.process_and_validate_instruction_chain(
        &[(
            &create,
            &[Check::err(ProgramError::Custom(err::INVALID_MESSAGE))],
        )],
        &accounts,
    );
}

#[test]
fn a_malformed_message_is_refused_at_proposal_time() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let (transaction, bump) = transaction_pda(&f.multisig, 1);

    // One static key, but the instruction names index 7.
    let message = build_message(
        1,
        1,
        0,
        &[f.vault],
        &[MessageIx {
            program_id_index: 7,
            account_indexes: vec![],
            data: vec![],
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
        &[],
    );

    let mut accounts = f.accounts.clone();
    accounts.push((transaction, empty()));

    // Rejected now rather than mid-execution, when earlier instructions of the
    // same message might already have run.
    mollusk.process_and_validate_instruction_chain(
        &[(
            &create,
            &[Check::err(ProgramError::Custom(err::INVALID_MESSAGE))],
        )],
        &accounts,
    );
}

#[test]
fn a_proposal_from_another_multisig_is_refused() {
    let mollusk = setup();
    let a = fixture(&mollusk);
    let b = fixture(&mollusk);

    let destination = Pubkey::new_unique();
    let (transaction, bump) = transaction_pda(&a.multisig, 1);
    let message = transfer_message(&a.vault, &destination, TRANSFER);

    let create = create_transaction_ix(
        &a.owners[0],
        &a.multisig,
        &transaction,
        &message,
        0,
        a.vault_bump,
        bump,
        &[],
    );

    // A proposal belonging to multisig A, voted on against multisig B.
    let cross_vote = vote_ix(2, &b.owners[0], &b.multisig, &transaction);

    let mut accounts = a.accounts.clone();
    accounts.extend(b.accounts.iter().cloned());
    accounts.push((transaction, empty()));
    accounts.push((destination, funded(0)));

    mollusk.process_and_validate_instruction_chain(
        &[
            (&create, &[Check::success()]),
            (
                &cross_vote,
                &[Check::err(ProgramError::Custom(err::MULTISIG_MISMATCH))],
            ),
        ],
        &accounts,
    );
}

#[test]
fn an_unknown_discriminator_is_refused() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let ix = Instruction::new_with_bytes(
        PROGRAM_ID,
        &[200u8],
        vec![AccountMeta::new_readonly(f.multisig, false)],
    );

    mollusk.process_and_validate_instruction(
        &ix,
        &f.accounts,
        &[Check::err(ProgramError::InvalidInstructionData)],
    );
}

#[test]
fn an_empty_instruction_is_refused() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let ix = Instruction::new_with_bytes(
        PROGRAM_ID,
        &[],
        vec![AccountMeta::new_readonly(f.multisig, false)],
    );

    mollusk.process_and_validate_instruction(
        &ix,
        &f.accounts,
        &[Check::err(ProgramError::InvalidInstructionData)],
    );
}

#[test]
fn a_vote_instruction_rejects_trailing_data() {
    let mollusk = setup();
    let f = fixture(&mollusk);

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

    let approve_with_junk = Instruction::new_with_bytes(
        PROGRAM_ID,
        &[2u8, 0xff],
        vec![
            AccountMeta::new_readonly(f.owners[0], true),
            AccountMeta::new(f.multisig, false),
            AccountMeta::new(transaction, false),
        ],
    );

    let mut accounts = f.accounts.clone();
    accounts.push((transaction, empty()));
    accounts.push((destination, funded(0)));

    mollusk.process_and_validate_instruction_chain(
        &[
            (&create, &[Check::success()]),
            (
                &approve_with_junk,
                &[Check::err(ProgramError::Custom(
                    err::INVALID_INSTRUCTION_DATA,
                ))],
            ),
        ],
        &accounts,
    );
}
