//! Off-chain instruction builders.
//!
//! Enabled by the `client` feature, so nothing here is linked into the program
//! itself, which has no allocator and cannot use `Vec`.
//!
//! Every byte layout the program parses is produced here, so a consumer never
//! hand-rolls one and the two cannot drift apart.

use solana_instruction::{AccountMeta, Instruction};
use solana_pubkey::Pubkey;

use crate::constants::{
    BUFFER_SEED, EPHEMERAL_SEED, MAX_EPHEMERAL_SIGNERS, MAX_OWNER, MULTISIG_SEED, TRANSACTION_SEED,
    VAULT_SEED,
};

/// The system program.
pub const SYSTEM_PROGRAM: Pubkey = solana_pubkey::pubkey!("11111111111111111111111111111111");

/// This program's address, as a `Pubkey`.
pub fn program_id() -> Pubkey {
    Pubkey::new_from_array(*crate::ID.as_array())
}

/// Instruction discriminators.
pub mod tag {
    /// `init_multisig`.
    pub const INIT_MULTISIG: u8 = 0;
    /// `create_transaction`.
    pub const CREATE_TRANSACTION: u8 = 1;
    /// `approve`.
    pub const APPROVE: u8 = 2;
    /// `reject`.
    pub const REJECT: u8 = 3;
    /// `execute`.
    pub const EXECUTE: u8 = 4;
    /// `cancel`.
    pub const CANCEL: u8 = 5;
    /// `close_transaction`.
    pub const CLOSE_TRANSACTION: u8 = 6;
    /// `buffer_create`.
    pub const BUFFER_CREATE: u8 = 7;
    /// `buffer_extend`.
    pub const BUFFER_EXTEND: u8 = 8;
    /// `buffer_close`.
    pub const BUFFER_CLOSE: u8 = 9;
    /// `create_from_buffer`.
    pub const CREATE_FROM_BUFFER: u8 = 10;
    /// `set_config`.
    pub const SET_CONFIG: u8 = 11;
}

/// Config action discriminators, used as the first byte of a self-targeted
/// proposal's instruction data.
pub mod action {
    /// Add an owner.
    pub const ADD_OWNER: u8 = 0;
    /// Remove an owner.
    pub const REMOVE_OWNER: u8 = 1;
    /// Change the approval threshold.
    pub const CHANGE_THRESHOLD: u8 = 2;
    /// Change the execution delay.
    pub const CHANGE_TIME_LOCK: u8 = 3;
    /// Set where reclaimed rent goes.
    pub const SET_RENT_COLLECTOR: u8 = 4;
    /// Set one owner's permission mask.
    pub const SET_PERMISSION: u8 = 5;
    /// Close the multisig.
    pub const CLOSE_MULTISIG: u8 = 6;
    /// Hand configuration control to a key, or return it to the owners.
    pub const SET_CONFIG_AUTHORITY: u8 = 7;
}

/// Encodes a `u32` payload for `change_threshold` and `change_time_lock`.
pub fn u32_payload(value: u32) -> [u8; 4] {
    value.to_le_bytes()
}

/// Permission bits.
pub mod permission {
    /// May create proposals.
    pub const INITIATE: u8 = 1;
    /// May approve and reject.
    pub const VOTE: u8 = 2;
    /// May execute.
    pub const EXECUTE: u8 = 4;
}

/// The multisig account for a create key.
pub fn multisig_address(create_key: &Pubkey) -> (Pubkey, u8) {
    Pubkey::find_program_address(&[MULTISIG_SEED, create_key.as_ref()], &program_id())
}

/// The proposal account for a multisig and index.
pub fn transaction_address(multisig: &Pubkey, index: u64) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[TRANSACTION_SEED, multisig.as_ref(), &index.to_le_bytes()],
        &program_id(),
    )
}

/// The vault a proposal spends from.
pub fn vault_address(multisig: &Pubkey, vault_index: u8) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[VAULT_SEED, multisig.as_ref(), &[vault_index]],
        &program_id(),
    )
}

/// The buffer account for a creator's upload.
pub fn buffer_address(multisig: &Pubkey, creator: &Pubkey, buffer_index: u8) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[
            BUFFER_SEED,
            multisig.as_ref(),
            creator.as_ref(),
            &[buffer_index],
        ],
        &program_id(),
    )
}

/// An ephemeral signer belonging to a proposal.
pub fn ephemeral_address(transaction: &Pubkey, index: u8) -> (Pubkey, u8) {
    Pubkey::find_program_address(
        &[EPHEMERAL_SEED, transaction.as_ref(), &[index]],
        &program_id(),
    )
}

/// One instruction inside a compiled message.
#[derive(Clone)]
pub struct MessageInstruction {
    /// Index into `account_keys` naming the program to invoke.
    pub program_id_index: u8,
    /// Indexes into `account_keys`, in the order the program expects.
    pub account_indexes: Vec<u8>,
    /// Instruction payload.
    pub data: Vec<u8>,
}

/// One address lookup table a message loads accounts from.
#[derive(Clone)]
pub struct MessageLookup {
    /// The lookup table account.
    pub account_key: Pubkey,
    /// Table indexes to load as writable.
    pub writable_indexes: Vec<u8>,
    /// Table indexes to load as readonly.
    pub readonly_indexes: Vec<u8>,
}

/// A compiled message, before serialization.
///
/// `account_keys` must be ordered writable signers, readonly signers, writable
/// non-signers, readonly non-signers: an index alone determines an account's
/// privileges, so the order is the encoding.
#[derive(Clone)]
pub struct Message {
    /// Signer keys, which come first in `account_keys`.
    pub num_signers: u8,
    /// Of the signers, how many are writable.
    pub num_writable_signers: u8,
    /// Of the non-signers, how many are writable.
    pub num_writable_non_signers: u8,
    /// Deduplicated account keys, including program ids.
    pub account_keys: Vec<Pubkey>,
    /// Instructions to invoke, in order.
    pub instructions: Vec<MessageInstruction>,
    /// Lookup tables supplying further accounts.
    pub lookups: Vec<MessageLookup>,
}

impl Message {
    /// Serializes the message into the layout the program parses.
    pub fn encode(&self) -> Vec<u8> {
        let mut blob = vec![
            self.num_signers,
            self.num_writable_signers,
            self.num_writable_non_signers,
            self.account_keys.len() as u8,
            self.instructions.len() as u8,
            self.lookups.len() as u8,
        ];

        for key in &self.account_keys {
            blob.extend_from_slice(key.as_ref());
        }

        for instruction in &self.instructions {
            blob.push(instruction.program_id_index);
            blob.push(instruction.account_indexes.len() as u8);
            blob.extend_from_slice(&instruction.account_indexes);
            blob.extend_from_slice(&(instruction.data.len() as u16).to_le_bytes());
            blob.extend_from_slice(&instruction.data);
        }

        for lookup in &self.lookups {
            blob.extend_from_slice(lookup.account_key.as_ref());
            blob.push(lookup.writable_indexes.len() as u8);
            blob.extend_from_slice(&lookup.writable_indexes);
            blob.push(lookup.readonly_indexes.len() as u8);
            blob.extend_from_slice(&lookup.readonly_indexes);
        }

        blob
    }

    /// The accounts `execute` expects for this message, in order: the static
    /// keys, then each table's writable addresses, then each table's readonly
    /// addresses, then the tables themselves.
    ///
    /// `resolved` supplies the addresses the tables will yield, in that same
    /// order.
    pub fn execute_accounts(&self, resolved: &[Pubkey]) -> Vec<AccountMeta> {
        let mut metas = Vec::with_capacity(self.account_keys.len() + resolved.len());

        for (i, key) in self.account_keys.iter().enumerate() {
            // A signer here signs as a PDA, so it is never a signer of the
            // outer transaction.
            if self.is_writable(i) {
                metas.push(AccountMeta::new(*key, false));
            } else {
                metas.push(AccountMeta::new_readonly(*key, false));
            }
        }

        let writable_from_lookups: usize =
            self.lookups.iter().map(|l| l.writable_indexes.len()).sum();

        for (i, key) in resolved.iter().enumerate() {
            if i < writable_from_lookups {
                metas.push(AccountMeta::new(*key, false));
            } else {
                metas.push(AccountMeta::new_readonly(*key, false));
            }
        }

        for lookup in &self.lookups {
            metas.push(AccountMeta::new_readonly(lookup.account_key, false));
        }

        metas
    }

    /// Whether the static key at `index` was requested writable.
    fn is_writable(&self, index: usize) -> bool {
        let num_signers = self.num_signers as usize;

        if index < self.num_writable_signers as usize {
            return true;
        }

        if index < num_signers {
            return false;
        }

        index - num_signers < self.num_writable_non_signers as usize
    }
}

/// A message transferring lamports from `vault` to `destination`.
pub fn transfer(vault: &Pubkey, destination: &Pubkey, lamports: u64) -> Message {
    let mut data = 2u32.to_le_bytes().to_vec();
    data.extend_from_slice(&lamports.to_le_bytes());

    Message {
        num_signers: 1,
        num_writable_signers: 1,
        num_writable_non_signers: 1,
        account_keys: vec![*vault, *destination, SYSTEM_PROGRAM],
        instructions: vec![MessageInstruction {
            program_id_index: 2,
            account_indexes: vec![0, 1],
            data,
        }],
        lookups: vec![],
    }
}

/// A message carrying a config action, which targets this program and so
/// carries no accounts of its own.
pub fn config_action(action: u8, payload: &[u8]) -> Message {
    let mut data = vec![action];
    data.extend_from_slice(payload);

    Message {
        num_signers: 0,
        num_writable_signers: 0,
        num_writable_non_signers: 0,
        // The system program is named so a resize can pay rent through it. The
        // instruction still references no accounts, which is what marks this a
        // config action.
        account_keys: vec![program_id(), SYSTEM_PROGRAM],
        instructions: vec![MessageInstruction {
            program_id_index: 0,
            account_indexes: vec![],
            data,
        }],
        lookups: vec![],
    }
}

/// Creates a multisig.
///
/// `owners` must be sorted ascending and free of duplicates. A transaction
/// caps how many fit here at roughly thirty; beyond that, create a small
/// multisig and grow it with `add_owner`.
pub fn init_multisig(
    creator: &Pubkey,
    create_key: &Pubkey,
    owners: &[Pubkey],
    threshold: u32,
) -> Instruction {
    init_multisig_controlled(creator, create_key, owners, threshold, &Pubkey::default())
}

/// Creates a multisig controlled by `config_authority`, which may change its
/// configuration without a vote. The default address leaves it autonomous.
pub fn init_multisig_controlled(
    creator: &Pubkey,
    create_key: &Pubkey,
    owners: &[Pubkey],
    threshold: u32,
    config_authority: &Pubkey,
) -> Instruction {
    let (multisig, bump) = multisig_address(create_key);

    let mut data = vec![tag::INIT_MULTISIG];
    data.extend_from_slice(&threshold.to_le_bytes());
    data.extend_from_slice(&(owners.len() as u32).to_le_bytes());
    data.push(bump);
    data.extend_from_slice(&[0u8; 3]);
    data.extend_from_slice(config_authority.as_ref());

    for owner in owners.iter().take(MAX_OWNER) {
        data.extend_from_slice(owner.as_ref());
    }

    Instruction::new_with_bytes(
        program_id(),
        &data,
        vec![
            AccountMeta::new(*creator, true),
            AccountMeta::new_readonly(*create_key, true),
            AccountMeta::new(multisig, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ],
    )
}

/// Proposes a message.
pub fn create_transaction(
    creator: &Pubkey,
    multisig: &Pubkey,
    index: u64,
    message: &Message,
    vault_index: u8,
    ephemeral_bumps: &[u8],
) -> Instruction {
    let (transaction, bump) = transaction_address(multisig, index);
    let (_, vault_bump) = vault_address(multisig, vault_index);

    let mut data = vec![
        tag::CREATE_TRANSACTION,
        vault_index,
        vault_bump,
        bump,
        ephemeral_bumps.len() as u8,
    ];

    let mut bumps = [0u8; MAX_EPHEMERAL_SIGNERS];
    bumps[..ephemeral_bumps.len()].copy_from_slice(ephemeral_bumps);
    data.extend_from_slice(&bumps);
    data.extend_from_slice(&message.encode());

    Instruction::new_with_bytes(
        program_id(),
        &data,
        vec![
            AccountMeta::new(*creator, true),
            AccountMeta::new(*multisig, false),
            AccountMeta::new(transaction, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ],
    )
}

fn vote(tag: u8, signer: &Pubkey, multisig: &Pubkey, transaction: &Pubkey) -> Instruction {
    Instruction::new_with_bytes(
        program_id(),
        &[tag],
        vec![
            AccountMeta::new_readonly(*signer, true),
            AccountMeta::new(*multisig, false),
            AccountMeta::new(*transaction, false),
        ],
    )
}

/// Approves a proposal.
pub fn approve(owner: &Pubkey, multisig: &Pubkey, transaction: &Pubkey) -> Instruction {
    vote(tag::APPROVE, owner, multisig, transaction)
}

/// Rejects a proposal.
pub fn reject(owner: &Pubkey, multisig: &Pubkey, transaction: &Pubkey) -> Instruction {
    vote(tag::REJECT, owner, multisig, transaction)
}

/// Cancels a proposal, or votes to cancel an approved one.
pub fn cancel(signer: &Pubkey, multisig: &Pubkey, transaction: &Pubkey) -> Instruction {
    vote(tag::CANCEL, signer, multisig, transaction)
}

/// Executes an approved proposal.
///
/// `message_accounts` comes from [`Message::execute_accounts`].
pub fn execute(
    executor: &Pubkey,
    multisig: &Pubkey,
    transaction: &Pubkey,
    message_accounts: &[AccountMeta],
) -> Instruction {
    let mut accounts = vec![
        AccountMeta::new(*executor, true),
        AccountMeta::new(*multisig, false),
        AccountMeta::new(*transaction, false),
    ];

    accounts.extend_from_slice(message_accounts);

    Instruction::new_with_bytes(program_id(), &[tag::EXECUTE], accounts)
}

/// Closes a finished proposal, refunding rent to `destination`.
pub fn close_transaction(
    transaction: &Pubkey,
    multisig: &Pubkey,
    destination: &Pubkey,
) -> Instruction {
    Instruction::new_with_bytes(
        program_id(),
        &[tag::CLOSE_TRANSACTION],
        vec![
            AccountMeta::new(*transaction, false),
            AccountMeta::new(*multisig, false),
            AccountMeta::new(*destination, false),
        ],
    )
}

/// Opens a buffer, committing to the message's length and hash.
pub fn buffer_create(
    creator: &Pubkey,
    multisig: &Pubkey,
    buffer_index: u8,
    vault_index: u8,
    final_hash: [u8; 32],
    final_size: u32,
    chunk: &[u8],
) -> Instruction {
    let (buffer, bump) = buffer_address(multisig, creator, buffer_index);

    let mut data = vec![tag::BUFFER_CREATE];
    data.extend_from_slice(&final_hash);
    data.extend_from_slice(&final_size.to_le_bytes());
    data.push(buffer_index);
    data.push(vault_index);
    data.push(bump);
    data.push(0);
    data.extend_from_slice(chunk);

    Instruction::new_with_bytes(
        program_id(),
        &data,
        vec![
            AccountMeta::new(*creator, true),
            AccountMeta::new_readonly(*multisig, false),
            AccountMeta::new(buffer, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ],
    )
}

/// Appends a chunk to a buffer.
pub fn buffer_extend(creator: &Pubkey, buffer: &Pubkey, chunk: &[u8]) -> Instruction {
    let mut data = vec![tag::BUFFER_EXTEND];
    data.extend_from_slice(chunk);

    Instruction::new_with_bytes(
        program_id(),
        &data,
        vec![
            AccountMeta::new_readonly(*creator, true),
            AccountMeta::new(*buffer, false),
        ],
    )
}

/// Abandons a buffer, refunding its rent.
pub fn buffer_close(creator: &Pubkey, buffer: &Pubkey) -> Instruction {
    Instruction::new_with_bytes(
        program_id(),
        &[tag::BUFFER_CLOSE],
        vec![
            AccountMeta::new(*creator, true),
            AccountMeta::new(*buffer, false),
        ],
    )
}

/// Turns a completed buffer into a proposal.
pub fn create_from_buffer(
    creator: &Pubkey,
    multisig: &Pubkey,
    index: u64,
    buffer: &Pubkey,
    vault_index: u8,
    ephemeral_bumps: &[u8],
) -> Instruction {
    let (transaction, bump) = transaction_address(multisig, index);
    let (_, vault_bump) = vault_address(multisig, vault_index);

    let mut data = vec![
        tag::CREATE_FROM_BUFFER,
        bump,
        vault_bump,
        ephemeral_bumps.len() as u8,
    ];

    let mut bumps = [0u8; MAX_EPHEMERAL_SIGNERS];
    bumps[..ephemeral_bumps.len()].copy_from_slice(ephemeral_bumps);
    data.extend_from_slice(&bumps);

    Instruction::new_with_bytes(
        program_id(),
        &data,
        vec![
            AccountMeta::new(*creator, true),
            AccountMeta::new(*multisig, false),
            AccountMeta::new(transaction, false),
            AccountMeta::new(*buffer, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ],
    )
}

/// Applies a config action directly, on a controlled multisig.
///
/// Refused unless the multisig names `authority` as its config authority.
pub fn set_config(
    authority: &Pubkey,
    multisig: &Pubkey,
    action: u8,
    payload: &[u8],
) -> Instruction {
    let mut data = vec![tag::SET_CONFIG, action];
    data.extend_from_slice(payload);

    Instruction::new_with_bytes(
        program_id(),
        &data,
        vec![
            AccountMeta::new(*authority, true),
            AccountMeta::new(*multisig, false),
            AccountMeta::new_readonly(SYSTEM_PROGRAM, false),
        ],
    )
}
