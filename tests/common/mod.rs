//! Shared helpers for the integration tests.
#![allow(dead_code)]

use mollusk_svm::Mollusk;
use solana_account::Account;
use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

/// The program under test.
pub const PROGRAM_ID: Pubkey =
    solana_pubkey::pubkey!("4X5zUZ8apTxg8XJSwyxCR6TpDbLFBxm9TjECocLTKpAm");

/// The system program.
pub const SYSTEM_ID: Pubkey = solana_pubkey::pubkey!("11111111111111111111111111111111");

/// Offsets into a `Multisig` header. The owner set follows it.
pub mod multisig_offset {
    pub const CREATE_KEY: usize = 0;
    pub const CONFIG_AUTHORITY: usize = 32;
    pub const RENT_COLLECTOR: usize = 64;
    pub const TRANSACTION_INDEX: usize = 96;
    pub const STALE_TRANSACTION_INDEX: usize = 104;
    pub const CLOSED_TRANSACTION_COUNT: usize = 112;
    pub const TIME_LOCK: usize = 120;
    pub const OWNERS_COUNT: usize = 124;
    pub const VOTER_COUNT: usize = 128;
    pub const THRESHOLD: usize = 132;
    pub const BUMP: usize = 136;
    pub const HEADER_LEN: usize = 144;
    /// The owner set begins immediately after the header.
    pub const OWNERS: usize = HEADER_LEN;
}

/// Offsets into a `Transaction` header. The vote bitmaps and message follow it.
pub mod transaction_offset {
    pub const MULTISIG: usize = 0;
    pub const CREATOR: usize = 32;
    pub const INDEX: usize = 64;
    pub const APPROVED_AT: usize = 72;
    pub const OWNERS_COUNT: usize = 80;
    pub const APPROVED_COUNT: usize = 84;
    pub const REJECTED_COUNT: usize = 88;
    pub const CANCELLED_COUNT: usize = 92;
    pub const MESSAGE_LEN: usize = 96;
    pub const STATUS: usize = 100;
    pub const BUMP: usize = 101;
    pub const VAULT_INDEX: usize = 102;
    pub const VAULT_BUMP: usize = 103;
    pub const EPHEMERAL_COUNT: usize = 104;
    pub const EPHEMERAL_BUMPS: usize = 105;
    pub const HEADER_LEN: usize = 112;
}

/// Status byte values.
pub mod status {
    pub const ACTIVE: u8 = 0;
    pub const APPROVED: u8 = 1;
    pub const REJECTED: u8 = 2;
    pub const EXECUTED: u8 = 3;
    pub const CANCELLED: u8 = 4;
}

/// Error codes, matching `MultisigError`.
pub mod err {
    pub const NOT_ENOUGH_ACCOUNTS: u32 = 0;
    pub const INVALID_ACCOUNT_DATA: u32 = 1;
    pub const ILLEGAL_OWNER: u32 = 2;
    pub const MISSING_SIGNATURE: u32 = 3;
    pub const INVALID_ACCOUNT: u32 = 4;
    pub const INVALID_PROGRAM_ID: u32 = 5;
    pub const ALREADY_INITIALIZED: u32 = 6;
    pub const INVALID_INSTRUCTION_DATA: u32 = 7;
    pub const INVALID_OWNER_COUNT: u32 = 8;
    pub const INVALID_THRESHOLD: u32 = 9;
    pub const OWNERS_NOT_SORTED: u32 = 10;
    pub const NOT_AN_OWNER: u32 = 11;
    pub const ALREADY_VOTED: u32 = 12;
    pub const STALE_TRANSACTION: u32 = 13;
    pub const INVALID_STATUS: u32 = 14;
    pub const UNKNOWN_STATUS: u32 = 15;
    pub const MULTISIG_MISMATCH: u32 = 16;
    pub const ACCOUNT_MISMATCH: u32 = 17;
    pub const OVERFLOW: u32 = 18;
    pub const OWNER_ALREADY_EXISTS: u32 = 19;
    pub const UNKNOWN_CONFIG_ACTION: u32 = 20;
    pub const INVALID_TIME_LOCK: u32 = 21;
    pub const TIME_LOCK_NOT_RELEASED: u32 = 22;
    pub const INVALID_MESSAGE: u32 = 23;
    pub const TOO_MANY_ACCOUNTS: u32 = 24;
    pub const BUFFER_INCOMPLETE: u32 = 25;
    pub const BUFFER_HASH_MISMATCH: u32 = 26;
    pub const INVALID_LOOKUP_TABLE: u32 = 27;
    pub const UNKNOWN_PERMISSION: u32 = 28;
    pub const NO_VOTERS: u32 = 29;
    pub const UNAUTHORIZED: u32 = 30;
    pub const TRANSACTIONS_OUTSTANDING: u32 = 31;
    pub const NOT_CONTROLLED: u32 = 32;
}

/// A wall-clock time for the test SVM. Mollusk defaults to zero, which would
/// make timestamp assertions vacuous and time locks impossible to exercise.
pub const TEST_UNIX_TIMESTAMP: i64 = 1_700_000_000;

/// The compiled program, read from the path cargo already knows.
fn program_elf() -> Vec<u8> {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/target/deploy/multisig.so");

    std::fs::read(path)
        .unwrap_or_else(|e| panic!("could not read {path}: {e}. Run `cargo build-sbf` first."))
}

/// A fresh SVM with the program loaded.
pub fn setup() -> Mollusk {
    let mut mollusk = Mollusk::default();

    mollusk.add_program_with_loader_and_elf(
        &PROGRAM_ID,
        &mollusk_svm::program::loader_keys::LOADER_V3,
        &program_elf(),
    );

    mollusk.sysvars.clock.unix_timestamp = TEST_UNIX_TIMESTAMP;
    mollusk
}

/// Bytes the three vote bitmaps occupy for a given owner count.
pub fn bitmap_len(owners: usize) -> usize {
    owners.div_ceil(8)
}

/// Whether the bit at `index` is set.
pub fn bit(bits: &[u8], index: usize) -> bool {
    bits[index / 8] & (1 << (index % 8)) != 0
}

/// The three vote bitmaps of a proposal account.
pub fn votes(data: &[u8], owners: usize) -> (&[u8], &[u8], &[u8]) {
    let n = bitmap_len(owners);
    let tail = &data[transaction_offset::HEADER_LEN..];

    (&tail[..n], &tail[n..2 * n], &tail[2 * n..3 * n])
}

/// The message stored after the bitmaps.
pub fn stored_message(data: &[u8], owners: usize) -> &[u8] {
    &data[transaction_offset::HEADER_LEN + 3 * bitmap_len(owners)..]
}

/// A `u32` field of a header.
pub fn u32_at(data: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(data[at..at + 4].try_into().unwrap())
}

/// A `u64` field of a header.
pub fn u64_at(data: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(data[at..at + 8].try_into().unwrap())
}

/// An owner address stored in a multisig account.
pub fn owner_at(data: &[u8], index: usize) -> &[u8] {
    let at = multisig_offset::HEADER_LEN + index * 32;
    &data[at..at + 32]
}

/// An owner's permission mask.
pub fn permission_at(data: &[u8], index: usize, owners: usize) -> u8 {
    data[multisig_offset::HEADER_LEN + owners * 32 + index]
}

/// The multisig PDA for a create key.
pub fn multisig_pda(create_key: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"multisig", create_key.as_ref()], &PROGRAM_ID)
}

/// The proposal PDA for a multisig and index.
pub fn transaction_pda(multisig: &Pubkey, index: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[b"transaction", multisig.as_ref(), &index.to_le_bytes()],
        &PROGRAM_ID,
    )
}

/// The vault PDA for a multisig and vault index.
pub fn vault_pda(multisig: &Pubkey, vault_index: u8) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"vault", multisig.as_ref(), &[vault_index]], &PROGRAM_ID)
}

/// The buffer PDA for a multisig, creator and buffer index.
pub fn buffer_pda(multisig: &Pubkey, creator: &Pubkey, buffer_index: u8) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            b"buffer",
            multisig.as_ref(),
            creator.as_ref(),
            &[buffer_index],
        ],
        &PROGRAM_ID,
    )
}

/// An ephemeral signer PDA for a proposal.
pub fn ephemeral_pda(transaction: &Pubkey, index: u8) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[b"ephemeral", transaction.as_ref(), &[index]], &PROGRAM_ID)
}

/// A funded, system-owned account.
pub fn funded(lamports: u64) -> Account {
    Account::new(lamports, 0, &SYSTEM_ID)
}

/// An account that does not exist yet.
pub fn empty() -> Account {
    Account::default()
}

/// The system program's keyed account.
pub fn system_account() -> (Pubkey, Account) {
    mollusk_svm::program::keyed_account_for_system_program()
}

/// This program's account, needed when a proposal targets it.
pub fn program_account() -> (Pubkey, Account) {
    (
        PROGRAM_ID,
        mollusk_svm::program::create_program_account_loader_v3(&PROGRAM_ID),
    )
}

/// Distinct pubkeys, sorted ascending as the program requires.
pub fn sorted_owners(n: usize) -> Vec<Pubkey> {
    let mut owners: Vec<Pubkey> = (0..n).map(|_| Pubkey::new_unique()).collect();
    owners.sort();
    owners
}

/// `init_multisig`, whose payload is a header followed by the owner addresses.
pub fn init_multisig_ix(
    creator: &Pubkey,
    create_key: &Pubkey,
    multisig: &Pubkey,
    owners: &[Pubkey],
    threshold: u32,
    bump: u8,
) -> Instruction {
    init_multisig_ix_with_authority(
        creator,
        create_key,
        multisig,
        owners,
        threshold,
        bump,
        &Pubkey::default(),
    )
}

/// `init_multisig`, born controlled by `config_authority`.
#[allow(clippy::too_many_arguments)]
pub fn init_multisig_ix_with_authority(
    creator: &Pubkey,
    create_key: &Pubkey,
    multisig: &Pubkey,
    owners: &[Pubkey],
    threshold: u32,
    bump: u8,
    config_authority: &Pubkey,
) -> Instruction {
    let mut data = vec![0u8];
    data.extend_from_slice(&threshold.to_le_bytes());
    data.extend_from_slice(&(owners.len() as u32).to_le_bytes());
    data.push(bump);
    data.extend_from_slice(&[0u8; 3]);
    data.extend_from_slice(config_authority.as_ref());

    for owner in owners {
        data.extend_from_slice(owner.as_ref());
    }

    Instruction::new_with_bytes(
        PROGRAM_ID,
        &data,
        vec![
            AccountMeta::new(*creator, true),
            AccountMeta::new_readonly(*create_key, true),
            AccountMeta::new(*multisig, false),
            AccountMeta::new_readonly(SYSTEM_ID, false),
        ],
    )
}

/// One instruction inside a compiled message.
pub struct MessageIx {
    pub program_id_index: u8,
    pub account_indexes: Vec<u8>,
    pub data: Vec<u8>,
}

/// One address lookup table reference inside a compiled message.
pub struct MessageLookup {
    pub account_key: Pubkey,
    pub writable_indexes: Vec<u8>,
    pub readonly_indexes: Vec<u8>,
}

/// Builds a compiled message blob.
pub fn build_message(
    num_signers: u8,
    num_writable_signers: u8,
    num_writable_non_signers: u8,
    keys: &[Pubkey],
    instructions: &[MessageIx],
    lookups: &[MessageLookup],
) -> Vec<u8> {
    let mut blob = vec![
        num_signers,
        num_writable_signers,
        num_writable_non_signers,
        keys.len() as u8,
        instructions.len() as u8,
        lookups.len() as u8,
    ];

    for key in keys {
        blob.extend_from_slice(key.as_ref());
    }

    for ix in instructions {
        blob.push(ix.program_id_index);
        blob.push(ix.account_indexes.len() as u8);
        blob.extend_from_slice(&ix.account_indexes);
        blob.extend_from_slice(&(ix.data.len() as u16).to_le_bytes());
        blob.extend_from_slice(&ix.data);
    }

    for lookup in lookups {
        blob.extend_from_slice(lookup.account_key.as_ref());
        blob.push(lookup.writable_indexes.len() as u8);
        blob.extend_from_slice(&lookup.writable_indexes);
        blob.push(lookup.readonly_indexes.len() as u8);
        blob.extend_from_slice(&lookup.readonly_indexes);
    }

    blob
}

/// A message transferring `lamports` from the vault to `destination`.
pub fn transfer_message(vault: &Pubkey, destination: &Pubkey, lamports: u64) -> Vec<u8> {
    let mut data = 2u32.to_le_bytes().to_vec();
    data.extend_from_slice(&lamports.to_le_bytes());

    build_message(
        1,
        1,
        1,
        &[*vault, *destination, SYSTEM_ID],
        &[MessageIx {
            program_id_index: 2,
            account_indexes: vec![0, 1],
            data,
        }],
        &[],
    )
}

/// A message calling this program with a config action payload.
pub fn config_message(action: u8, payload: &[u8]) -> Vec<u8> {
    let mut data = vec![action];
    data.extend_from_slice(payload);

    build_message(
        0,
        0,
        0,
        &[PROGRAM_ID, SYSTEM_ID],
        &[MessageIx {
            program_id_index: 0,
            account_indexes: vec![],
            data,
        }],
        &[],
    )
}

/// The accounts `execute` expects for a config action.
pub fn config_accounts() -> Vec<AccountMeta> {
    vec![
        AccountMeta::new_readonly(PROGRAM_ID, false),
        AccountMeta::new_readonly(SYSTEM_ID, false),
    ]
}

/// `create_transaction`.
#[allow(clippy::too_many_arguments)]
pub fn create_transaction_ix(
    creator: &Pubkey,
    multisig: &Pubkey,
    transaction: &Pubkey,
    message: &[u8],
    vault_index: u8,
    vault_bump: u8,
    bump: u8,
    ephemeral_bumps: &[u8],
) -> Instruction {
    let mut data = vec![
        1u8,
        vault_index,
        vault_bump,
        bump,
        ephemeral_bumps.len() as u8,
    ];
    let mut bumps = [0u8; 4];
    bumps[..ephemeral_bumps.len()].copy_from_slice(ephemeral_bumps);
    data.extend_from_slice(&bumps);
    data.extend_from_slice(message);

    Instruction::new_with_bytes(
        PROGRAM_ID,
        &data,
        vec![
            AccountMeta::new(*creator, true),
            AccountMeta::new(*multisig, false),
            AccountMeta::new(*transaction, false),
            AccountMeta::new_readonly(SYSTEM_ID, false),
        ],
    )
}

/// A vote instruction: `approve` (2), `reject` (3) or `cancel` (5).
pub fn vote_ix(tag: u8, signer: &Pubkey, multisig: &Pubkey, transaction: &Pubkey) -> Instruction {
    Instruction::new_with_bytes(
        PROGRAM_ID,
        &[tag],
        vec![
            AccountMeta::new_readonly(*signer, true),
            AccountMeta::new(*multisig, false),
            AccountMeta::new(*transaction, false),
        ],
    )
}

/// `execute`, with the message's accounts appended in order.
pub fn execute_ix(
    executor: &Pubkey,
    multisig: &Pubkey,
    transaction: &Pubkey,
    message_accounts: &[AccountMeta],
) -> Instruction {
    // Writable because a config action can move rent to or from the executor.
    let mut accounts = vec![
        AccountMeta::new(*executor, true),
        AccountMeta::new(*multisig, false),
        AccountMeta::new(*transaction, false),
    ];
    accounts.extend_from_slice(message_accounts);

    Instruction::new_with_bytes(PROGRAM_ID, &[4u8], accounts)
}

/// `set_config`, the config authority's direct path.
pub fn set_config_ix(
    authority: &Pubkey,
    multisig: &Pubkey,
    action: u8,
    payload: &[u8],
) -> Instruction {
    let mut data = vec![11u8, action];
    data.extend_from_slice(payload);

    Instruction::new_with_bytes(
        PROGRAM_ID,
        &data,
        vec![
            AccountMeta::new(*authority, true),
            AccountMeta::new(*multisig, false),
            AccountMeta::new_readonly(SYSTEM_ID, false),
        ],
    )
}

/// `close_transaction`.
pub fn close_transaction_ix(
    transaction: &Pubkey,
    multisig: &Pubkey,
    destination: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        PROGRAM_ID,
        &[6u8],
        vec![
            AccountMeta::new(*transaction, false),
            AccountMeta::new(*multisig, false),
            AccountMeta::new(*destination, false),
        ],
    )
}

/// `buffer_create`.
#[allow(clippy::too_many_arguments)]
pub fn buffer_create_ix(
    creator: &Pubkey,
    multisig: &Pubkey,
    buffer: &Pubkey,
    final_hash: [u8; 32],
    final_size: u32,
    buffer_index: u8,
    vault_index: u8,
    bump: u8,
    chunk: &[u8],
) -> Instruction {
    let mut data = vec![7u8];
    data.extend_from_slice(&final_hash);
    data.extend_from_slice(&final_size.to_le_bytes());
    data.push(buffer_index);
    data.push(vault_index);
    data.push(bump);
    data.push(0);
    data.extend_from_slice(chunk);

    Instruction::new_with_bytes(
        PROGRAM_ID,
        &data,
        vec![
            AccountMeta::new(*creator, true),
            AccountMeta::new_readonly(*multisig, false),
            AccountMeta::new(*buffer, false),
            AccountMeta::new_readonly(SYSTEM_ID, false),
        ],
    )
}

/// `buffer_extend`.
pub fn buffer_extend_ix(creator: &Pubkey, buffer: &Pubkey, chunk: &[u8]) -> Instruction {
    let mut data = vec![8u8];
    data.extend_from_slice(chunk);

    Instruction::new_with_bytes(
        PROGRAM_ID,
        &data,
        vec![
            AccountMeta::new_readonly(*creator, true),
            AccountMeta::new(*buffer, false),
        ],
    )
}

/// `buffer_close`.
pub fn buffer_close_ix(creator: &Pubkey, buffer: &Pubkey) -> Instruction {
    Instruction::new_with_bytes(
        PROGRAM_ID,
        &[9u8],
        vec![
            AccountMeta::new(*creator, true),
            AccountMeta::new(*buffer, false),
        ],
    )
}

/// `create_from_buffer`.
#[allow(clippy::too_many_arguments)]
pub fn create_from_buffer_ix(
    creator: &Pubkey,
    multisig: &Pubkey,
    transaction: &Pubkey,
    buffer: &Pubkey,
    bump: u8,
    vault_bump: u8,
    ephemeral_bumps: &[u8],
) -> Instruction {
    let mut data = vec![10u8, bump, vault_bump, ephemeral_bumps.len() as u8];
    let mut bumps = [0u8; 4];
    bumps[..ephemeral_bumps.len()].copy_from_slice(ephemeral_bumps);
    data.extend_from_slice(&bumps);

    Instruction::new_with_bytes(
        PROGRAM_ID,
        &data,
        vec![
            AccountMeta::new(*creator, true),
            AccountMeta::new(*multisig, false),
            AccountMeta::new(*transaction, false),
            AccountMeta::new(*buffer, false),
            AccountMeta::new_readonly(SYSTEM_ID, false),
        ],
    )
}
