//! Compute unit benchmarks for every instruction.
//!
//! Each bench needs its accounts in the right pre-state, so the earlier steps
//! of a flow are run first and their resulting accounts fed to the bench.

#[path = "../tests/common/mod.rs"]
mod common;

use common::*;
use mollusk_svm::Mollusk;
use mollusk_svm_bencher::MolluskComputeUnitBencher;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

const VAULT_FUNDING: u64 = 5_000_000_000;
const TRANSFER: u64 = 500_000_000;

/// Runs `chain` and returns the accounts it produced.
fn advance(
    mollusk: &Mollusk,
    chain: &[&Instruction],
    accounts: &[(Pubkey, Account)],
) -> Vec<(Pubkey, Account)> {
    let checks: Vec<_> = chain
        .iter()
        .map(|ix| (*ix, &[] as &[mollusk_svm::result::Check]))
        .collect();

    mollusk
        .process_and_validate_instruction_chain(&checks, accounts)
        .resulting_accounts
}

fn main() {
    let mollusk = setup();

    let creator = Pubkey::new_unique();
    let create_key = Pubkey::new_unique();
    let (multisig, ms_bump) = multisig_pda(&create_key);
    let owners = sorted_owners(3);
    let (vault, vault_bump) = vault_pda(&multisig, 0);

    let init_ix = init_multisig_ix(&creator, &create_key, &multisig, &owners, 2, ms_bump);
    let init_accounts = vec![
        (creator, funded(10_000_000_000)),
        (create_key, funded(0)),
        (multisig, empty()),
        system_account(),
    ];

    let after_init = advance(&mollusk, &[&init_ix], &init_accounts);
    let multisig_account = after_init
        .iter()
        .find(|(k, _)| *k == multisig)
        .unwrap()
        .1
        .clone();

    let destination = Pubkey::new_unique();
    let (transaction, tx_bump) = transaction_pda(&multisig, 1);
    let message = transfer_message(&vault, &destination, TRANSFER);

    let base = vec![
        (owners[0], funded(10_000_000_000)),
        (owners[1], funded(10_000_000_000)),
        (owners[2], funded(10_000_000_000)),
        (multisig, multisig_account),
        (vault, funded(VAULT_FUNDING)),
        system_account(),
        (
            PROGRAM_ID,
            mollusk_svm::program::create_program_account_loader_v3(&PROGRAM_ID),
        ),
        (transaction, empty()),
        (destination, funded(0)),
    ];

    let create_ix = create_transaction_ix(
        &owners[0],
        &multisig,
        &transaction,
        &message,
        0,
        vault_bump,
        tx_bump,
        &[],
    );
    let approve_a = vote_ix(2, &owners[0], &multisig, &transaction);
    let approve_b = vote_ix(2, &owners[1], &multisig, &transaction);
    let reject_ix = vote_ix(3, &owners[1], &multisig, &transaction);
    let cancel_ix = vote_ix(5, &owners[0], &multisig, &transaction);
    let execute_ix_transfer = execute_ix(
        &owners[0],
        &multisig,
        &transaction,
        &[
            AccountMeta::new(vault, false),
            AccountMeta::new(destination, false),
            AccountMeta::new_readonly(SYSTEM_ID, false),
        ],
    );
    let close_ix = close_transaction_ix(&transaction, &multisig, &owners[0]);

    let after_create = advance(&mollusk, &[&create_ix], &base);
    let after_one_approval = advance(&mollusk, &[&create_ix, &approve_a], &base);
    let after_approved = advance(&mollusk, &[&create_ix, &approve_a, &approve_b], &base);
    let after_cancel = advance(&mollusk, &[&create_ix, &cancel_ix], &base);

    let (config_tx, config_bump) = transaction_pda(&multisig, 1);
    let config_msg = config_message(2, &[3u8]);
    let config_create = create_transaction_ix(
        &owners[0],
        &multisig,
        &config_tx,
        &config_msg,
        0,
        0,
        config_bump,
        &[],
    );
    let config_execute = execute_ix(
        &owners[0],
        &multisig,
        &config_tx,
        &[AccountMeta::new_readonly(PROGRAM_ID, false)],
    );
    let after_config_approved = advance(&mollusk, &[&config_create, &approve_a, &approve_b], &base);

    let (buffer, buffer_bump) = buffer_pda(&multisig, &owners[0], 0);
    let hash = solana_sha256_hasher::hashv(&[&message]).to_bytes();
    let split = message.len() / 2;

    let mut buffer_base = base.clone();
    buffer_base.push((buffer, empty()));

    let buffer_create = buffer_create_ix(
        &owners[0],
        &multisig,
        &buffer,
        hash,
        message.len() as u32,
        0,
        0,
        buffer_bump,
        &message[..split],
    );
    let buffer_extend = buffer_extend_ix(&owners[0], &buffer, &message[split..]);
    let from_buffer = create_from_buffer_ix(
        &owners[0],
        &multisig,
        &transaction,
        &buffer,
        tx_bump,
        vault_bump,
        &[],
    );

    let after_buffer_create = advance(&mollusk, &[&buffer_create], &buffer_base);
    let after_buffer_full = advance(&mollusk, &[&buffer_create, &buffer_extend], &buffer_base);

    let second = Pubkey::new_unique();
    let transfer_data = |amount: u64| {
        let mut data = 2u32.to_le_bytes().to_vec();
        data.extend_from_slice(&amount.to_le_bytes());
        data
    };
    let (multi_tx, multi_bump) = transaction_pda(&multisig, 1);
    let multi_msg = build_message(
        1,
        1,
        2,
        &[vault, destination, second, SYSTEM_ID],
        &[
            MessageIx {
                program_id_index: 3,
                account_indexes: vec![0, 1],
                data: transfer_data(TRANSFER),
            },
            MessageIx {
                program_id_index: 3,
                account_indexes: vec![0, 2],
                data: transfer_data(TRANSFER),
            },
        ],
        &[],
    );
    let multi_create = create_transaction_ix(
        &owners[0],
        &multisig,
        &multi_tx,
        &multi_msg,
        0,
        vault_bump,
        multi_bump,
        &[],
    );
    let multi_execute = execute_ix(
        &owners[0],
        &multisig,
        &multi_tx,
        &[
            AccountMeta::new(vault, false),
            AccountMeta::new(destination, false),
            AccountMeta::new(second, false),
            AccountMeta::new_readonly(SYSTEM_ID, false),
        ],
    );

    let mut multi_base = base.clone();
    multi_base.push((second, funded(0)));
    let after_multi_approved = advance(
        &mollusk,
        &[&multi_create, &approve_a, &approve_b],
        &multi_base,
    );

    MolluskComputeUnitBencher::new(mollusk)
        .must_pass(true)
        .bench(("init_multisig", &init_ix, &init_accounts))
        .bench(("create_transaction", &create_ix, &base))
        .bench(("approve", &approve_a, &after_create))
        .bench(("approve_latching", &approve_b, &after_one_approval))
        .bench(("reject", &reject_ix, &after_create))
        .bench(("cancel_active", &cancel_ix, &after_create))
        .bench(("execute_transfer", &execute_ix_transfer, &after_approved))
        .bench(("execute_config", &config_execute, &after_config_approved))
        .bench((
            "execute_two_transfers",
            &multi_execute,
            &after_multi_approved,
        ))
        .bench(("close_transaction", &close_ix, &after_cancel))
        .bench(("buffer_create", &buffer_create, &buffer_base))
        .bench(("buffer_extend", &buffer_extend, &after_buffer_create))
        .bench(("create_from_buffer", &from_buffer, &after_buffer_full))
        .execute();
}
