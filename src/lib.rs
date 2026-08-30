#![deny(missing_docs)]
//! A Squads-style multisig program for the Solana.
//!
//! An owner proposes a transaction, owners approve it, and once the threshold
//! is met anyone may execute it. Owner-set changes are ordinary proposals
//! targeting this program, so they need no separate authorization path.

pub mod constants;
pub mod instruction;
pub mod state;

mod entrypoint;
