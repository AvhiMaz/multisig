//! Program entrypoint.

#![allow(unexpected_cfgs)]

use pinocchio::{
    AccountView, Address, ProgramResult, default_panic_handler, error::ProgramError, no_allocator,
    program_entrypoint,
};

use crate::instruction::{
    process_approve, process_create_transaction, process_execute, process_init_multisig,
    process_reject,
};

program_entrypoint!(process_instruction);
no_allocator!();
default_panic_handler!();

/// Routes an instruction by its leading discriminator byte.
///
/// | Byte | Instruction |
/// |------|-------------|
/// | `0`  | [`process_init_multisig`] |
/// | `1`  | [`process_create_transaction`] |
/// | `2`  | [`process_approve`] |
/// | `3`  | [`process_reject`] |
/// | `4`  | [`process_execute`] |
pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    match instruction_data.split_first() {
        Some((0, rest)) => process_init_multisig(program_id, accounts, rest),
        Some((1, rest)) => process_create_transaction(program_id, accounts, rest),
        Some((2, rest)) => process_approve(program_id, accounts, rest),
        Some((3, rest)) => process_reject(program_id, accounts, rest),
        Some((4, rest)) => process_execute(program_id, accounts, rest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
