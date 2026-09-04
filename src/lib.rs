#![deny(missing_docs)]
//! A multisig program.
//!
//! An owner proposes a transaction, owners approve it, and once the threshold
//! is met anyone may execute it. Owner-set changes are ordinary proposals
//! targeting this program, so they need no separate authorization path.

/// This program's address.
pub const ID: pinocchio::Address = pinocchio::Address::new_from_array(pinocchio_pubkey::pubkey!(
    "8jmCwrtrrogXTGYi9HijeaFSPbQYAhf5TD4NT6Fy1GS2"
));

pub mod constants;
pub mod error;
pub mod instruction;
pub mod state;

mod entrypoint;
mod helper;
mod utils;
