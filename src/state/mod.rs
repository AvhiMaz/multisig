//! On-chain account layouts.
//!
//! State structs are read in place from account data, so field order is part of
//! the wire format.

pub mod buffer;
pub mod message;
pub mod multisig;
pub mod permission;
pub mod transaction;
