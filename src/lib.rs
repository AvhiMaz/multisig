#![deny(missing_docs)]
//! A multisig program.
//!
//! An owner proposes a transaction, owners approve it, and once the threshold
//! is met anyone may execute it. Owner-set changes are ordinary proposals
//! targeting this program, so they cost the same threshold as a spend.
//!
//! A multisig may instead name a `config_authority` at creation, which changes
//! the configuration without a vote. Left unset, the multisig is autonomous and
//! nothing outside the owner set can alter it.

#[cfg(feature = "client")]
pub mod client;
pub mod constants;
pub mod error;
pub mod instruction;
pub mod state;

mod entrypoint;
mod helper;

pub use entrypoint::{ID, check_id, id};
