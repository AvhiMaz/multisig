//! Macros for zero-copy account structs.

/// Implements a `LEN` constant equal to the struct's size in bytes.
macro_rules! impl_len {
    ($t:ty) => {
        impl $t {
            /// Size of the account in bytes.
            #[allow(dead_code)]
            pub const LEN: usize = core::mem::size_of::<Self>();
        }
    };
}

/// Implements zero-copy `load` and `load_mut`, casting account bytes directly
/// into the struct after checking length and alignment.
macro_rules! impl_load {
    ($t:ty) => {
        impl $t {
            /// Reads account data as this struct.
            #[allow(dead_code)]
            pub fn load(data: &[u8]) -> Result<&Self, pinocchio::error::ProgramError> {
                if data.len() != core::mem::size_of::<$t>()
                    || !(data.as_ptr() as usize).is_multiple_of(core::mem::align_of::<$t>())
                {
                    Err(crate::error::MultisigError::InvalidAccountData.into())
                } else {
                    // SAFETY: length and alignment checked above.
                    Ok(unsafe { &*(data.as_ptr() as *const Self) })
                }
            }

            /// Mutable counterpart of `load`.
            #[allow(dead_code)]
            pub fn load_mut(data: &mut [u8]) -> Result<&mut Self, pinocchio::error::ProgramError> {
                if data.len() != core::mem::size_of::<$t>()
                    || !(data.as_mut_ptr() as usize).is_multiple_of(core::mem::align_of::<$t>())
                {
                    Err(crate::error::MultisigError::InvalidAccountData.into())
                } else {
                    // SAFETY: length and alignment checked above; the exclusive
                    // reference rules out other borrows.
                    Ok(unsafe { &mut *(data.as_mut_ptr() as *mut Self) })
                }
            }
        }
    };
}

pub(crate) use impl_len;
pub(crate) use impl_load;
