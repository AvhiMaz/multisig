//! Compile-time limits and PDA seed prefixes.

/// Maximum owners per multisig. Baked into [`Multisig::LEN`], so changing it
/// breaks existing accounts.
///
/// [`Multisig::LEN`]: crate::state::multisig::Multisig::LEN
pub const MAX_OWNER: usize = 10;

/// Longest permitted delay between approval and execution, in seconds.
///
/// Capped at three months so a config change cannot brick a multisig by
/// putting its funds beyond reach.
pub const MAX_TIME_LOCK: u32 = 3 * 30 * 24 * 60 * 60;

/// Maximum accounts the target instruction may reference.
pub const MAX_IX_ACCOUNTS: usize = 10;

/// Maximum instruction data the target instruction may carry, in bytes.
pub const MAX_IX_DATA: usize = 256;

/// Seed prefix for the multisig PDA, derived as `["multisig", create_key]`.
pub const MULTISIG_SEED: &[u8] = b"multisig";

/// Seed prefix for a transaction PDA, `["transaction", multisig, index]`.
pub const TRANSACTION_SEED: &[u8] = b"transaction";

/// Seed prefix for a vault PDA, `["vault", multisig, vault_index]`.
pub const VAULT_SEED: &[u8] = b"vault";
