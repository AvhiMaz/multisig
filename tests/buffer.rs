//! Chunked message upload and turning a buffer into a proposal.

mod common;

use common::{err, status, transaction_offset as tx_off, *};
use mollusk_svm::result::Check;
use solana_account::Account;
use solana_instruction::AccountMeta;
use solana_program_error::ProgramError;
use solana_pubkey::Pubkey;

const VAULT_FUNDING: u64 = 5_000_000_000;
const TRANSFER: u64 = 1_000_000_000;

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

fn sha256(data: &[u8]) -> [u8; 32] {
    solana_sha256_hasher::hashv(&[data]).to_bytes()
}

#[test]
fn upload_in_chunks_then_execute() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let destination = Pubkey::new_unique();
    let message = transfer_message(&f.vault, &destination, TRANSFER);
    let hash = sha256(&message);

    let (buffer, buffer_bump) = buffer_pda(&f.multisig, &f.owners[0], 0);
    let (transaction, tx_bump) = transaction_pda(&f.multisig, 1);

    let split = message.len() / 2;

    let create_buffer = buffer_create_ix(
        &f.owners[0],
        &f.multisig,
        &buffer,
        hash,
        message.len() as u32,
        0,
        0,
        buffer_bump,
        &message[..split],
    );
    let extend = buffer_extend_ix(&f.owners[0], &buffer, &message[split..]);
    let from_buffer = create_from_buffer_ix(
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
    accounts.push((buffer, empty()));
    accounts.push((transaction, empty()));
    accounts.push((destination, funded(0)));

    let result = mollusk.process_and_validate_instruction_chain(
        &[
            (&create_buffer, &[Check::success()]),
            (&extend, &[Check::success()]),
            (&from_buffer, &[Check::success()]),
            (&approve_a, &[Check::success()]),
            (&approve_b, &[Check::success()]),
            (&execute, &[Check::success()]),
        ],
        &accounts,
    );

    let tx = result.get_account(&transaction).unwrap();
    assert_eq!(tx.data[tx_off::STATUS], status::EXECUTED);
    assert_eq!(
        &tx.data[tx_off::MESSAGE_LEN..tx_off::MESSAGE_LEN + 4],
        &(message.len() as u32).to_le_bytes(),
        "message length recorded"
    );
    assert_eq!(
        &tx.data[tx_off::HEADER_LEN..],
        &message[..],
        "message stored verbatim"
    );

    assert_eq!(
        result.get_account(&buffer).unwrap().lamports,
        0,
        "buffer closed after use"
    );
    assert_eq!(result.get_account(&destination).unwrap().lamports, TRANSFER);
}

#[test]
fn an_incomplete_buffer_cannot_become_a_proposal() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let destination = Pubkey::new_unique();
    let message = transfer_message(&f.vault, &destination, TRANSFER);
    let hash = sha256(&message);

    let (buffer, buffer_bump) = buffer_pda(&f.multisig, &f.owners[0], 0);
    let (transaction, tx_bump) = transaction_pda(&f.multisig, 1);

    let create_buffer = buffer_create_ix(
        &f.owners[0],
        &f.multisig,
        &buffer,
        hash,
        message.len() as u32,
        0,
        0,
        buffer_bump,
        &message[..4],
    );
    let from_buffer = create_from_buffer_ix(
        &f.owners[0],
        &f.multisig,
        &transaction,
        &buffer,
        tx_bump,
        f.vault_bump,
        &[],
    );

    let mut accounts = f.accounts.clone();
    accounts.push((buffer, empty()));
    accounts.push((transaction, empty()));

    mollusk.process_and_validate_instruction_chain(
        &[
            (&create_buffer, &[Check::success()]),
            (
                &from_buffer,
                &[Check::err(ProgramError::Custom(err::BUFFER_INCOMPLETE))],
            ),
        ],
        &accounts,
    );
}

#[test]
fn tampered_content_fails_the_hash() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let destination = Pubkey::new_unique();
    let message = transfer_message(&f.vault, &destination, TRANSFER);

    // Commit to one message, then upload a different one of the same length.
    let mut other = message.clone();
    let last = other.len() - 1;
    other[last] ^= 0xff;

    let hash = sha256(&message);

    let (buffer, buffer_bump) = buffer_pda(&f.multisig, &f.owners[0], 0);
    let (transaction, tx_bump) = transaction_pda(&f.multisig, 1);

    let create_buffer = buffer_create_ix(
        &f.owners[0],
        &f.multisig,
        &buffer,
        hash,
        other.len() as u32,
        0,
        0,
        buffer_bump,
        &other,
    );
    let from_buffer = create_from_buffer_ix(
        &f.owners[0],
        &f.multisig,
        &transaction,
        &buffer,
        tx_bump,
        f.vault_bump,
        &[],
    );

    let mut accounts = f.accounts.clone();
    accounts.push((buffer, empty()));
    accounts.push((transaction, empty()));

    mollusk.process_and_validate_instruction_chain(
        &[
            (&create_buffer, &[Check::success()]),
            (
                &from_buffer,
                &[Check::err(ProgramError::Custom(err::BUFFER_HASH_MISMATCH))],
            ),
        ],
        &accounts,
    );
}

#[test]
fn writing_past_the_committed_length_is_refused() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let destination = Pubkey::new_unique();
    let message = transfer_message(&f.vault, &destination, TRANSFER);
    let hash = sha256(&message);

    let (buffer, buffer_bump) = buffer_pda(&f.multisig, &f.owners[0], 0);

    let create_buffer = buffer_create_ix(
        &f.owners[0],
        &f.multisig,
        &buffer,
        hash,
        message.len() as u32,
        0,
        0,
        buffer_bump,
        &message,
    );
    let extend = buffer_extend_ix(&f.owners[0], &buffer, &[0u8]);

    let mut accounts = f.accounts.clone();
    accounts.push((buffer, empty()));

    mollusk.process_and_validate_instruction_chain(
        &[
            (&create_buffer, &[Check::success()]),
            (
                &extend,
                &[Check::err(ProgramError::Custom(err::INVALID_MESSAGE))],
            ),
        ],
        &accounts,
    );
}

#[test]
fn only_the_creator_may_extend() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let destination = Pubkey::new_unique();
    let message = transfer_message(&f.vault, &destination, TRANSFER);
    let hash = sha256(&message);

    let (buffer, buffer_bump) = buffer_pda(&f.multisig, &f.owners[0], 0);

    let create_buffer = buffer_create_ix(
        &f.owners[0],
        &f.multisig,
        &buffer,
        hash,
        message.len() as u32,
        0,
        0,
        buffer_bump,
        &message[..4],
    );
    let extend_by_other = buffer_extend_ix(&f.owners[1], &buffer, &message[4..]);

    let mut accounts = f.accounts.clone();
    accounts.push((buffer, empty()));

    mollusk.process_and_validate_instruction_chain(
        &[
            (&create_buffer, &[Check::success()]),
            (
                &extend_by_other,
                &[Check::err(ProgramError::Custom(err::INVALID_ACCOUNT))],
            ),
        ],
        &accounts,
    );
}

#[test]
fn abandoning_a_buffer_refunds_it() {
    let mollusk = setup();
    let f = fixture(&mollusk);

    let destination = Pubkey::new_unique();
    let message = transfer_message(&f.vault, &destination, TRANSFER);
    let hash = sha256(&message);

    let (buffer, buffer_bump) = buffer_pda(&f.multisig, &f.owners[0], 0);

    let create_buffer = buffer_create_ix(
        &f.owners[0],
        &f.multisig,
        &buffer,
        hash,
        message.len() as u32,
        0,
        0,
        buffer_bump,
        &message[..4],
    );
    let close = buffer_close_ix(&f.owners[0], &buffer);

    let mut accounts = f.accounts.clone();
    accounts.push((buffer, empty()));

    let result = mollusk.process_and_validate_instruction_chain(
        &[
            (&create_buffer, &[Check::success()]),
            (&close, &[Check::success()]),
        ],
        &accounts,
    );

    assert_eq!(result.get_account(&buffer).unwrap().lamports, 0);
}
