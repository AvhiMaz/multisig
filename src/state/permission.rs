//! Per-owner permissions.
//!
//! An owner's mask says which of the three actions they may take. A mask of
//! zero means all three, so a multisig that does not care about permissions
//! behaves as every owner being able to do everything.

/// Bit flags for what an owner may do.
pub struct Permission;

impl Permission {
    /// May create proposals.
    pub const INITIATE: u8 = 1;
    /// May approve and reject proposals.
    pub const VOTE: u8 = 2;
    /// May execute approved proposals.
    pub const EXECUTE: u8 = 4;
    /// Every permission set.
    pub const ALL: u8 = Self::INITIATE | Self::VOTE | Self::EXECUTE;
}
