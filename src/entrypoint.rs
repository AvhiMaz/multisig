use pinocchio::{AccountView, Address, ProgramResult, default_panic_handler, no_allocator};

no_allocator!();
default_panic_handler!();

pub fn process_instruction(
    program_id: &Address,
    accounts: &mut [AccountView],
    instruction_data: &[u8],
) -> ProgramResult {
    Ok(())
}
