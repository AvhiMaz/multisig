//! Compile-time limits and PDA seed prefixes.

/// Maximum owners per multisig. Baked into [`Multisig::LEN`], so changing it
/// breaks existing accounts.
///
/// [`Multisig::LEN`]: crate::state::multisig::Multisig::LEN
pub const MAX_OWNER: usize = 10;

/// Seed prefix for the multisig PDA, derived as `["multisig", creator]`.
pub const MULTISIG_SEED: &[u8] = b"multisig";
