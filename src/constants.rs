//! Compile-time limits and PDA seed prefixes.

/// Maximum owners per multisig.
///
/// Not a storage limit: the owner set is a variable-length tail and the account
/// grows as it fills. The cap bounds the account at 135_312 bytes and the vote
/// bitmaps at 512 bytes each, and keeps the binary search over the owner set to
/// twelve comparisons.
pub const MAX_OWNER: usize = 4096;

/// Longest permitted delay between approval and execution, in seconds.
///
/// Capped at three months so a config change cannot brick a multisig by
/// putting its funds beyond reach.
pub const MAX_TIME_LOCK: u32 = 3 * 30 * 24 * 60 * 60;

/// Seed prefix for the multisig PDA, derived as `["multisig", create_key]`.
pub const MULTISIG_SEED: &[u8] = b"multisig";

/// Seed prefix for a transaction PDA, `["transaction", multisig, index]`.
pub const TRANSACTION_SEED: &[u8] = b"transaction";

/// Seed prefix for a vault PDA, `["vault", multisig, vault_index]`.
pub const VAULT_SEED: &[u8] = b"vault";

/// Largest compiled message a proposal may hold, in bytes.
///
/// Reachable only through the chunked buffer upload; a single
/// `create_transaction` is still bounded by Solana's 1232-byte transaction.
pub const MAX_MESSAGE_SIZE: usize = 4096;

/// Largest number of accounts a single inner instruction may reference.
///
/// Sizes the arrays `execute` builds a CPI from. Those live on the stack, which
/// an SBF frame limits to 4 KB, so this is well below the runtime's own cap.
pub const MAX_CPI_ACCOUNTS: usize = 32;

/// Seed prefix for a transaction buffer PDA, `["buffer", multisig, creator, index]`.
pub const BUFFER_SEED: &[u8] = b"buffer";

/// Seed prefix for an ephemeral signer PDA, `["ephemeral", transaction, index]`.
pub const EPHEMERAL_SEED: &[u8] = b"ephemeral";

/// Most ephemeral signers a single proposal may derive.
pub const MAX_EPHEMERAL_SIGNERS: usize = 4;

/// The Address Lookup Table program, which owns every lookup table account.
pub const ADDRESS_LOOKUP_TABLE_ID: pinocchio::Address = pinocchio::Address::new_from_array(
    pinocchio_pubkey::pubkey!("AddressLookupTab1e1111111111111111111111111"),
);

/// Bytes of a lookup table account before its addresses begin.
pub const LOOKUP_TABLE_META_SIZE: usize = 56;

/// Offset of `deactivation_slot` within a lookup table account.
pub const LOOKUP_TABLE_DEACTIVATION_OFFSET: usize = 4;
