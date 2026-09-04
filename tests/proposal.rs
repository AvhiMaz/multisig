//! The proposal lifecycle: create, vote, execute, cancel, close.

mod common;

use common::{err, status, transaction_offset as tx_off, *};
use mollusk_svm::result::Check;
use solana_account::Account;
use solana_instruction::AccountMeta;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

const VAULT_FUNDING: u64 = 5_000_000_000;
const TRANSFER: u64 = 1_000_000_000;

/// A 2-of-3 multisig with a funded vault, ready for proposals.
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

    let multisig_account = result.get_account(&multisig).unwrap().clone();

    let mut accounts = vec![
        (owners[0], funded(10_000_000_000)),
        (owners[1], funded(10_000_000_000)),
        (owners[2], funded(10_000_000_000)),
        (multisig, multisig_account),
        (vault, funded(VAULT_FUNDING)),
        system_account(),
    ];
    accounts.push((Pubkey::new_unique(), funded(0)));

    Fixture {
        owners,
        multisig,
        vault,
        vault_bump,
        accounts,
    }
}

#[test]
fn create_approve_execute_moves_lamports() {
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

    let result = mollusk.process_and_validate_instruction_chain(
        &[
            (&create, &[Check::success()]),
            (&approve_a, &[Check::success()]),
            (&approve_b, &[Check::success()]),
            (&execute, &[Check::success()]),
        ],
        &accounts,
    );

    let tx = result.get_account(&transaction).unwrap();
    assert_eq!(tx.data[tx_off::STATUS], status::EXECUTED, "status");
    assert_eq!(tx.data[tx_off::APPROVED_COUNT], 2, "approvals");
    assert_eq!(tx.data[tx_off::VAULT_BUMP], f.vault_bump);
    assert_ne!(
        &tx.data[tx_off::APPROVED_AT..tx_off::APPROVED_AT + 8],
        &0u64.to_le_bytes(),
        "approval timestamp stamped"
    );

    assert_eq!(
        result.get_account(&destination).unwrap().lamports,
        TRANSFER,
        "destination credited"
    );
    assert_eq!(
        result.get_account(&f.vault).unwrap().lamports,
        VAULT_FUNDING - TRANSFER,
        "vault debited"
    );

    let ms = result.get_account(&f.multisig).unwrap();
    assert_eq!(
        &ms.data[multisig_offset::TRANSACTION_INDEX..multisig_offset::TRANSACTION_INDEX + 8],
        &1u64.to_le_bytes(),
        "counter advanced"
    );
}

#[test]
fn execute_below_threshold_is_refused() {
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
    let approve = vote_ix(2, &f.owners[0], &f.multisig, &transaction);
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

    mollusk.process_and_validate_instruction_chain(
        &[
            (&create, &[Check::success()]),
            (&approve, &[Check::success()]),
            (
                &execute,
                &[Check::err(ProgramError::Custom(err::INVALID_STATUS))],
            ),
        ],
        &accounts,
    );
}

#[test]
fn substituted_account_is_refused() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let destination = Pubkey::new_unique();
    let attacker = Pubkey::new_unique();
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

    // Same shape, different destination than the one that was approved.
    let execute = execute_ix(
        &f.owners[0],
        &f.multisig,
        &transaction,
        &[
            AccountMeta::new(f.vault, false),
            AccountMeta::new(attacker, false),
            AccountMeta::new_readonly(SYSTEM_ID, false),
        ],
    );

    let mut accounts = f.accounts.clone();
    accounts.push((transaction, empty()));
    accounts.push((destination, funded(0)));
    accounts.push((attacker, funded(0)));

    mollusk.process_and_validate_instruction_chain(
        &[
            (&create, &[Check::success()]),
            (&approve_a, &[Check::success()]),
            (&approve_b, &[Check::success()]),
            (
                &execute,
                &[Check::err(ProgramError::Custom(err::ACCOUNT_MISMATCH))],
            ),
        ],
        &accounts,
    );
}

#[test]
fn double_approval_is_refused() {
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
    let approve = vote_ix(2, &f.owners[0], &f.multisig, &transaction);

    let mut accounts = f.accounts.clone();
    accounts.push((transaction, empty()));
    accounts.push((destination, funded(0)));

    mollusk.process_and_validate_instruction_chain(
        &[
            (&create, &[Check::success()]),
            (&approve, &[Check::success()]),
            (
                &approve,
                &[Check::err(ProgramError::Custom(err::ALREADY_VOTED))],
            ),
        ],
        &accounts,
    );
}

#[test]
fn a_non_owner_cannot_propose_or_vote() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let stranger = Pubkey::new_unique();
    let destination = Pubkey::new_unique();
    let (transaction, bump) = transaction_pda(&f.multisig, 1);
    let message = transfer_message(&f.vault, &destination, TRANSFER);

    let create_by_stranger = create_transaction_ix(
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
    accounts.push((destination, funded(0)));
    accounts.push((stranger, funded(10_000_000_000)));

    mollusk.process_and_validate_instruction_chain(
        &[(
            &create_by_stranger,
            &[Check::err(ProgramError::Custom(err::NOT_AN_OWNER))],
        )],
        &accounts,
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
    let vote_by_stranger = vote_ix(2, &stranger, &f.multisig, &transaction);

    mollusk.process_and_validate_instruction_chain(
        &[
            (&create, &[Check::success()]),
            (
                &vote_by_stranger,
                &[Check::err(ProgramError::Custom(err::NOT_AN_OWNER))],
            ),
        ],
        &accounts,
    );
}

#[test]
fn rejections_reach_the_cutoff() {
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

    // 3 owners, threshold 2, so the cutoff is 2 rejections.
    let reject_a = vote_ix(3, &f.owners[0], &f.multisig, &transaction);
    let reject_b = vote_ix(3, &f.owners[1], &f.multisig, &transaction);

    let mut accounts = f.accounts.clone();
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

    let tx = result.get_account(&transaction).unwrap();
    assert_eq!(tx.data[tx_off::STATUS], status::REJECTED);
    assert_eq!(tx.data[tx_off::REJECTED_COUNT], 2);
}

#[test]
fn creator_cancels_an_active_proposal() {
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
    let cancel_by_other = vote_ix(5, &f.owners[1], &f.multisig, &transaction);
    let cancel = vote_ix(5, &f.owners[0], &f.multisig, &transaction);

    let mut accounts = f.accounts.clone();
    accounts.push((transaction, empty()));
    accounts.push((destination, funded(0)));

    // A chain stops at its first error, so the refusal is its own run.
    mollusk.process_and_validate_instruction_chain(
        &[
            (&create, &[Check::success()]),
            (
                &cancel_by_other,
                &[Check::err(ProgramError::Custom(err::INVALID_ACCOUNT))],
            ),
        ],
        &accounts,
    );

    let result = mollusk.process_and_validate_instruction_chain(
        &[
            (&create, &[Check::success()]),
            (&cancel, &[Check::success()]),
        ],
        &accounts,
    );

    let tx = result.get_account(&transaction).unwrap();
    assert_eq!(tx.data[tx_off::STATUS], status::CANCELLED);
}

#[test]
fn approved_proposal_needs_consensus_to_cancel() {
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
    let cancel_a = vote_ix(5, &f.owners[0], &f.multisig, &transaction);
    let cancel_b = vote_ix(5, &f.owners[1], &f.multisig, &transaction);

    let mut accounts = f.accounts.clone();
    accounts.push((transaction, empty()));
    accounts.push((destination, funded(0)));

    let result = mollusk.process_and_validate_instruction_chain(
        &[
            (&create, &[Check::success()]),
            (&approve_a, &[Check::success()]),
            (&approve_b, &[Check::success()]),
            (&cancel_a, &[Check::success()]),
            (&cancel_b, &[Check::success()]),
        ],
        &accounts,
    );

    let tx = result.get_account(&transaction).unwrap();
    assert_eq!(tx.data[tx_off::CANCELLED_COUNT], 2);
    assert_eq!(tx.data[tx_off::STATUS], status::CANCELLED);
}

#[test]
fn closing_a_finished_proposal_refunds_rent() {
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
    let cancel = vote_ix(5, &f.owners[0], &f.multisig, &transaction);
    let close = close_transaction_ix(&transaction, &f.multisig, &f.owners[0]);

    let mut accounts = f.accounts.clone();
    accounts.push((transaction, empty()));
    accounts.push((destination, funded(0)));

    let result = mollusk.process_and_validate_instruction_chain(
        &[
            (&create, &[Check::success()]),
            (&cancel, &[Check::success()]),
            (&close, &[Check::success()]),
        ],
        &accounts,
    );

    assert_eq!(
        result.get_account(&transaction).unwrap().lamports,
        0,
        "proposal closed"
    );

    let ms = result.get_account(&f.multisig).unwrap();
    assert_eq!(
        &ms.data[multisig_offset::CLOSED_TRANSACTION_COUNT
            ..multisig_offset::CLOSED_TRANSACTION_COUNT + 8],
        &1u64.to_le_bytes(),
        "closure counted"
    );
}

#[test]
fn an_active_proposal_cannot_be_closed() {
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
    let close = close_transaction_ix(&transaction, &f.multisig, &f.owners[0]);

    let mut accounts = f.accounts.clone();
    accounts.push((transaction, empty()));
    accounts.push((destination, funded(0)));

    mollusk.process_and_validate_instruction_chain(
        &[
            (&create, &[Check::success()]),
            (
                &close,
                &[Check::err(ProgramError::Custom(err::INVALID_STATUS))],
            ),
        ],
        &accounts,
    );
}
