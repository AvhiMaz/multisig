//! Program entrypoint.

#![allow(unexpected_cfgs)]

use pinocchio::{
    AccountView, Address, ProgramResult, default_panic_handler, error::ProgramError, no_allocator,
    program_entrypoint,
};

use crate::instruction::{
    process_approve, process_buffer_close, process_buffer_create, process_buffer_extend,
    process_cancel, process_close_transaction, process_create_from_buffer,
    process_create_transaction, process_execute, process_init_multisig, process_reject,
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
/// | `5`  | [`process_cancel`] |
/// | `6`  | [`process_close_transaction`] |
/// | `7`  | [`process_buffer_create`] |
/// | `8`  | [`process_buffer_extend`] |
/// | `9`  | [`process_buffer_close`] |
/// | `10` | [`process_create_from_buffer`] |
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
        Some((5, rest)) => process_cancel(program_id, accounts, rest),
        Some((6, rest)) => process_close_transaction(program_id, accounts, rest),
        Some((7, rest)) => process_buffer_create(program_id, accounts, rest),
        Some((8, rest)) => process_buffer_extend(program_id, accounts, rest),
        Some((9, rest)) => process_buffer_close(program_id, accounts, rest),
        Some((10, rest)) => process_create_from_buffer(program_id, accounts, rest),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}
