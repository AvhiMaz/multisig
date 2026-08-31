//! Transaction proposal creation.
//!
//! Any owner may propose. The proposal starts with no votes; the proposer
//! approves separately if they want to.
//!
//! # Accounts
//!
//! 0. `creator`        - signer, must be an owner, pays rent
//! 1. `multisig`       - writable, supplies and bumps the transaction counter
//! 2. `transaction`    - PDA `["transaction", multisig, index]`, created here
//! 3. `system_program`

use pinocchio::{
    AccountView, Address, ProgramResult,
    cpi::{Seed, Signer},
    sysvars::{Sysvar, rent::Rent},
};
use pinocchio_system::{ID, instructions::CreateAccount};

use crate::{
    constants::{MAX_IX_ACCOUNTS, MAX_IX_DATA, MAX_OWNER, TRANSACTION_SEED},
    error::MultisigError,
    helper::{check_owner, check_signer, validate_eq},
    state::{
        multisig::Multisig,
        transaction::{Transaction, TransactionStatus, TxAccountMeta},
    },
    utils::{impl_len, impl_load},
};

/// Payload for [`process_create_transaction`].
///
/// `accounts` and `ix_data` are sent at full width so the payload stays
/// fixed-size and parseable in place; trailing entries are zeroed on write.
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct CreateTransactionData {
    /// Program the proposed instruction invokes.
    pub target_program: Address,
    /// Account list the proposed instruction expects, in order.
    pub accounts: [TxAccountMeta; MAX_IX_ACCOUNTS],
    /// Proposed instruction payload.
    pub ix_data: [u8; MAX_IX_DATA],
    /// Live length of `ix_data`.
    pub ix_data_len: u32,
    /// Live entries in `accounts`.
    pub account_count: u8,
    /// Which vault signs the CPI at execution.
    pub vault_index: u8,
    /// Bump for that vault PDA. Verified at execution, not here.
    pub vault_bump: u8,
    /// Bump for this transaction PDA. Unvalidated: `invoke_signed` rejects a wrong one.
    pub bump: u8,
}

impl_len!(CreateTransactionData);
impl_load!(CreateTransactionData);

/// Creates a proposal against `multisig`.
pub fn process_create_transaction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction: &[u8],
) -> ProgramResult {
    let [
        creator,
        multisig,
        transaction,
        system_program,
        _remaining @ ..,
    ] = accounts
    else {
        return Err(MultisigError::NotEnoughAccounts.into());
    };

    check_signer(creator, MultisigError::MissingSignature.into())?;

    validate_eq(
        system_program.address(),
        &ID,
        MultisigError::InvalidProgramId.into(),
    )?;

    // First instruction to take a caller-supplied multisig, so this is where a
    // forged account would otherwise get in.
    check_owner(multisig, program_id, MultisigError::IllegalOwner.into())?;

    if !transaction.is_data_empty() || transaction.lamports() != 0 {
        return Err(MultisigError::AlreadyInitialized.into());
    }

    let data = CreateTransactionData::load(instruction)?;

    let account_count = data.account_count as usize;
    let ix_data_len = data.ix_data_len as usize;

    // Bounded here because both index the arrays below.
    if account_count > MAX_IX_ACCOUNTS || ix_data_len > MAX_IX_DATA {
        return Err(MultisigError::InvalidInstructionData.into());
    }

    // Reserve the index, in its own scope so the multisig borrow ends before
    // the transaction account is borrowed.
    let index = {
        let multisig_data = unsafe { multisig.borrow_unchecked_mut() };
        let ms = Multisig::load_mut(multisig_data)?;

        if ms.is_owner(creator.address()).is_none() {
            return Err(MultisigError::NotAnOwner.into());
        }

        // Index 0 means "no transactions yet", so the first proposal is 1.
        let index = ms
            .transaction_index
            .checked_add(1)
            .ok_or(MultisigError::Overflow)?;

        ms.transaction_index = index;
        index
    };

    let index_bytes = index.to_le_bytes();
    let bump = [data.bump];

    let seeds = [
        Seed::from(TRANSACTION_SEED),
        Seed::from(multisig.address().as_array()),
        Seed::from(&index_bytes),
        Seed::from(&bump),
    ];

    let signer_seeds = Signer::from(&seeds[..]);

    CreateAccount {
        from: creator,
        to: transaction,
        space: Transaction::LEN as u64,
        lamports: Rent::get()?.minimum_balance_unchecked(Transaction::LEN),
        owner: program_id,
    }
    .invoke_signed(&[signer_seeds])?;

    // SAFETY: just created by the CPI above, so no other borrow is live.
    let transaction_data = unsafe { transaction.borrow_unchecked_mut() };

    let state = Transaction::load_mut(transaction_data)?;

    state.multisig = *multisig.address();
    state.creator = *creator.address();
    state.target_program = data.target_program;
    state.index = index;

    // No votes yet; the proposer approves separately if they want to.
    state.approved = [Address::default(); MAX_OWNER];
    state.rejected = [Address::default(); MAX_OWNER];
    state.approved_count = 0;
    state.rejected_count = 0;

    state.status = TransactionStatus::Active as u8;
    state.bump = data.bump;
    state.account_count = data.account_count;
    state.vault_index = data.vault_index;
    state.vault_bump = data.vault_bump;
    state._pad = [0u8; 1];
    state.ix_data_len = data.ix_data_len;

    state.accounts = data.accounts;
    state.ix_data = data.ix_data;

    // Trailing entries are caller-controlled bytes; zero them so the stored
    // proposal is canonical and execution cannot read leftover data.
    for slot in state.accounts[account_count..].iter_mut() {
        *slot = TxAccountMeta {
            address: Address::default(),
            is_signer: 0,
            is_writable: 0,
        };
    }
    for byte in state.ix_data[ix_data_len..].iter_mut() {
        *byte = 0;
    }

    state.invariant()
}
