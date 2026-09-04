#![deny(missing_docs)]
//! A multisig program.
//!
//! An owner proposes a transaction, owners approve it, and once the threshold
//! is met anyone may execute it. Owner-set changes are ordinary proposals
//! targeting this program, so they need no separate authorization path.

#[cfg(feature = "client")]
pub mod client;
pub mod constants;
pub mod error;
pub mod instruction;
pub mod state;

mod entrypoint;
mod helper;
mod utils;

pub use entrypoint::{ID, check_id, id};
