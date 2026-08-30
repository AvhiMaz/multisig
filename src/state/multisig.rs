use pinocchio::Address;
use pinocchio::error::ProgramError;

use crate::constants::MAX_OWNER;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Multisig {
    pub creator: Address,
    pub owners: [Address; MAX_OWNER],
    pub owners_count: u8,
    pub threshold: u8,
    pub bump: u8,
    pub _padding: [u8; 5],
    pub transaction_index: u64,
}

impl Multisig {
    pub const LEN: usize = core::mem::size_of::<Self>();

    pub fn load(data: &[u8]) -> Result<&Self, ProgramError> {
        if data.len() != Self::LEN
            || !(data.as_ptr() as usize).is_multiple_of(core::mem::align_of::<Self>())
        {
            Err(ProgramError::AccountDataTooSmall)
        } else {
            Ok(unsafe { &*(data.as_ptr() as *const Self) })
        }
    }

    pub fn load_mut(data: &mut [u8]) -> Result<&mut Self, ProgramError> {
        if data.len() != Self::LEN
            || !(data.as_mut_ptr() as usize).is_multiple_of(core::mem::align_of::<Self>())
        {
            Err(ProgramError::AccountDataTooSmall)
        } else {
            Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
        }
    }
}
