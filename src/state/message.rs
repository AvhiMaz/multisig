//! Compiled transaction message.
//!
//! Mirrors Solana's own wire format: a deduplicated list of account keys
//! ordered by privilege, followed by instructions that reference those keys by
//! one-byte index rather than repeating 32-byte addresses.
//!
//! With no allocator the message is kept as a flat byte blob and read with a
//! cursor. Nothing is copied out; every accessor borrows from the blob.
//!
//! # Layout
//!
//! ```text
//! header            6 bytes
//! account_keys      32 * num_account_keys
//! instructions      num_instructions * { program_id_index: u8,
//!                                        account_indexes_len: u8,
//!                                        account_indexes: [u8],
//!                                        data_len: u16 (le),
//!                                        data: [u8] }
//! lookups           num_lookups * { account_key: [u8; 32],
//!                                   writable_len: u8, writable: [u8],
//!                                   readonly_len: u8, readonly: [u8] }
//! ```
//!
//! Account keys are ordered writable signers, readonly signers, writable
//! non-signers, readonly non-signers, so an index alone determines an account's
//! privileges.

use pinocchio::{Address, error::ProgramError};

use crate::error::MultisigError;

/// Fixed prefix of a compiled message.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MessageHeader {
    /// Signer keys, which come first in `account_keys`.
    pub num_signers: u8,
    /// Of the signers, how many are writable.
    pub num_writable_signers: u8,
    /// Of the non-signers, how many are writable.
    pub num_writable_non_signers: u8,
    /// Entries in `account_keys`.
    pub num_account_keys: u8,
    /// Instructions making up this message.
    pub num_instructions: u8,
    /// Address lookup tables this message loads accounts from.
    pub num_lookups: u8,
}

impl MessageHeader {
    /// Size of the header in bytes.
    pub const LEN: usize = 6;
}

/// One instruction within a message, borrowed from the blob.
pub struct CompiledInstruction<'a> {
    /// Index into the message's account keys naming the program to invoke.
    pub program_id_index: u8,
    /// Indexes into the message's account keys, in the order the program expects.
    pub account_indexes: &'a [u8],
    /// Instruction payload.
    pub data: &'a [u8],
}

/// One address lookup table reference, borrowed from the blob.
pub struct MessageLookup<'a> {
    /// The lookup table account.
    pub account_key: &'a Address,
    /// Indexes into the table naming accounts to load as writable.
    pub writable_indexes: &'a [u8],
    /// Indexes into the table naming accounts to load as readonly.
    pub readonly_indexes: &'a [u8],
}

/// A parsed, validated compiled message.
pub struct TransactionMessage<'a> {
    /// Counts and privilege boundaries.
    pub header: MessageHeader,
    /// Deduplicated account keys, ordered by privilege.
    pub account_keys: &'a [Address],
    instructions: &'a [u8],
    lookups: &'a [u8],
    num_all_keys: usize,
    num_writable_lookup_keys: usize,
}

/// Reads little-endian values out of a byte blob without copying.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], ProgramError> {
        if self.remaining() < len {
            return Err(MultisigError::InvalidMessage.into());
        }

        let out = &self.data[self.pos..self.pos + len];
        self.pos += len;

        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, ProgramError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ProgramError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }
}

impl<'a> TransactionMessage<'a> {
    /// Parses and validates a message blob.
    ///
    /// Validation is total: every index is checked against the account count,
    /// every length against the bytes actually present, and the blob must be
    /// consumed exactly. `execute` can then index without bounds checks of its
    /// own, and a malformed message is rejected at proposal time rather than
    /// discovered mid-CPI.
    pub fn parse(blob: &'a [u8]) -> Result<Self, ProgramError> {
        let mut cursor = Cursor::new(blob);

        let header = MessageHeader {
            num_signers: cursor.u8()?,
            num_writable_signers: cursor.u8()?,
            num_writable_non_signers: cursor.u8()?,
            num_account_keys: cursor.u8()?,
            num_instructions: cursor.u8()?,
            num_lookups: cursor.u8()?,
        };

        let num_account_keys = header.num_account_keys as usize;

        if header.num_signers as usize > num_account_keys
            || header.num_writable_signers > header.num_signers
        {
            return Err(MultisigError::InvalidMessage.into());
        }

        let num_non_signers = num_account_keys - header.num_signers as usize;
        if header.num_writable_non_signers as usize > num_non_signers {
            return Err(MultisigError::InvalidMessage.into());
        }

        let keys_bytes = cursor.take(num_account_keys * 32)?;

        // SAFETY: `Address` is `#[repr(transparent)]` over `[u8; 32]`, so it
        // has alignment 1 and every byte pattern is a valid value. The slice
        // length was checked to be exactly `num_account_keys * 32`.
        let account_keys = unsafe {
            core::slice::from_raw_parts(keys_bytes.as_ptr() as *const Address, num_account_keys)
        };

        // Instructions may reference accounts loaded from lookup tables, which
        // sit past the static keys, so bounds are the total of both.
        let instructions_start = cursor.pos;
        let mut num_lookup_keys = 0usize;
        let mut num_writable_lookup_keys = 0usize;

        // Walk the instructions once to find where they end, deferring index
        // validation until the lookup count is known.
        for _ in 0..header.num_instructions {
            cursor.u8()?;
            let indexes_len = cursor.u8()? as usize;
            cursor.take(indexes_len)?;
            let data_len = cursor.u16()? as usize;
            cursor.take(data_len)?;
        }

        let instructions = &blob[instructions_start..cursor.pos];

        let lookups_start = cursor.pos;

        for _ in 0..header.num_lookups {
            cursor.take(32)?;
            let writable_len = cursor.u8()? as usize;
            cursor.take(writable_len)?;
            let readonly_len = cursor.u8()? as usize;
            cursor.take(readonly_len)?;
            num_lookup_keys += writable_len + readonly_len;
            num_writable_lookup_keys += writable_len;
        }

        let lookups = &blob[lookups_start..cursor.pos];

        // Trailing bytes would mean the blob does not say what it claims.
        if cursor.remaining() != 0 {
            return Err(MultisigError::InvalidMessage.into());
        }

        let num_all_keys = num_account_keys + num_lookup_keys;

        let message = Self {
            header,
            account_keys,
            instructions,
            lookups,
            num_all_keys,
            num_writable_lookup_keys,
        };

        for instruction in message.instructions() {
            let instruction = instruction?;

            if instruction.program_id_index as usize >= num_all_keys {
                return Err(MultisigError::InvalidMessage.into());
            }

            for index in instruction.account_indexes {
                if *index as usize >= num_all_keys {
                    return Err(MultisigError::InvalidMessage.into());
                }
            }
        }

        Ok(message)
    }

    /// Total accounts the message references, static keys plus any loaded from
    /// lookup tables.
    pub fn num_all_keys(&self) -> usize {
        self.num_all_keys
    }

    /// Accounts the lookup tables supply as writable.
    ///
    /// The runtime orders resolved keys as all writables across every table,
    /// then all readonlys, so this is the boundary between the two.
    pub fn num_writable_lookup_keys(&self) -> usize {
        self.num_writable_lookup_keys
    }

    /// Iterates the message's instructions.
    pub fn instructions(&self) -> InstructionIter<'a> {
        InstructionIter {
            cursor: Cursor::new(self.instructions),
        }
    }

    /// Iterates the message's address lookup table references.
    pub fn lookups(&self) -> LookupIter<'a> {
        LookupIter {
            cursor: Cursor::new(self.lookups),
        }
    }

    /// Whether the key at `index` was requested writable.
    ///
    /// Static keys are grouped writable signers, readonly signers, writable
    /// non-signers, readonly non-signers, so position alone decides them. Keys
    /// past the static ones come from lookup tables, where the runtime puts
    /// every table's writables before every table's readonlys.
    pub fn is_writable(&self, index: usize) -> bool {
        let num_static = self.header.num_account_keys as usize;

        if index >= num_static {
            return index - num_static < self.num_writable_lookup_keys;
        }

        let num_signers = self.header.num_signers as usize;

        if index < self.header.num_writable_signers as usize {
            return true;
        }

        if index < num_signers {
            return false;
        }

        index - num_signers < self.header.num_writable_non_signers as usize
    }

    /// Whether the key at `index` was requested as a signer.
    ///
    /// Only static keys can sign: a lookup table cannot confer signing.
    pub fn is_signer(&self, index: usize) -> bool {
        index < self.header.num_signers as usize
    }
}

/// Iterator over a message's instructions.
pub struct InstructionIter<'a> {
    cursor: Cursor<'a>,
}

impl<'a> Iterator for InstructionIter<'a> {
    type Item = Result<CompiledInstruction<'a>, ProgramError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor.remaining() == 0 {
            return None;
        }

        Some(self.read())
    }
}

impl<'a> InstructionIter<'a> {
    fn read(&mut self) -> Result<CompiledInstruction<'a>, ProgramError> {
        let program_id_index = self.cursor.u8()?;
        let indexes_len = self.cursor.u8()? as usize;
        let account_indexes = self.cursor.take(indexes_len)?;
        let data_len = self.cursor.u16()? as usize;
        let data = self.cursor.take(data_len)?;

        Ok(CompiledInstruction {
            program_id_index,
            account_indexes,
            data,
        })
    }
}

/// Iterator over a message's address lookup table references.
pub struct LookupIter<'a> {
    cursor: Cursor<'a>,
}

impl<'a> Iterator for LookupIter<'a> {
    type Item = Result<MessageLookup<'a>, ProgramError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.cursor.remaining() == 0 {
            return None;
        }

        Some(self.read())
    }
}

impl<'a> LookupIter<'a> {
    fn read(&mut self) -> Result<MessageLookup<'a>, ProgramError> {
        let key_bytes = self.cursor.take(32)?;

        // SAFETY: `Address` is `#[repr(transparent)]` over `[u8; 32]` with
        // alignment 1, and the slice is exactly 32 bytes.
        let account_key = unsafe { &*(key_bytes.as_ptr() as *const Address) };

        let writable_len = self.cursor.u8()? as usize;
        let writable_indexes = self.cursor.take(writable_len)?;
        let readonly_len = self.cursor.u8()? as usize;
        let readonly_indexes = self.cursor.take(readonly_len)?;

        Ok(MessageLookup {
            account_key,
            writable_indexes,
            readonly_indexes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a message blob: keys, then instructions, then lookups.
    fn build(
        num_signers: u8,
        num_writable_signers: u8,
        num_writable_non_signers: u8,
        keys: &[[u8; 32]],
        instructions: &[(u8, &[u8], &[u8])],
        lookups: &[([u8; 32], &[u8], &[u8])],
    ) -> Vec<u8> {
        let mut blob = vec![
            num_signers,
            num_writable_signers,
            num_writable_non_signers,
            keys.len() as u8,
            instructions.len() as u8,
            lookups.len() as u8,
        ];

        for key in keys {
            blob.extend_from_slice(key);
        }

        for (program_id_index, indexes, data) in instructions {
            blob.push(*program_id_index);
            blob.push(indexes.len() as u8);
            blob.extend_from_slice(indexes);
            blob.extend_from_slice(&(data.len() as u16).to_le_bytes());
            blob.extend_from_slice(data);
        }

        for (key, writable, readonly) in lookups {
            blob.extend_from_slice(key);
            blob.push(writable.len() as u8);
            blob.extend_from_slice(writable);
            blob.push(readonly.len() as u8);
            blob.extend_from_slice(readonly);
        }

        blob
    }

    fn key(n: u8) -> [u8; 32] {
        [n; 32]
    }

    #[test]
    fn parses_a_simple_message() {
        let blob = build(
            1,
            1,
            1,
            &[key(1), key(2), key(3)],
            &[(2, &[0, 1], &[7, 8, 9])],
            &[],
        );

        let message = TransactionMessage::parse(&blob).unwrap();

        assert_eq!(message.header.num_account_keys, 3);
        assert_eq!(message.account_keys.len(), 3);
        assert_eq!(message.num_all_keys(), 3);

        let instructions: Vec<_> = message.instructions().map(|i| i.unwrap()).collect();
        assert_eq!(instructions.len(), 1);
        assert_eq!(instructions[0].program_id_index, 2);
        assert_eq!(instructions[0].account_indexes, &[0, 1]);
        assert_eq!(instructions[0].data, &[7, 8, 9]);
    }

    #[test]
    fn parses_several_instructions() {
        let blob = build(
            1,
            1,
            0,
            &[key(1), key(2)],
            &[(1, &[0], &[1]), (1, &[0, 1], &[]), (1, &[], &[2, 3])],
            &[],
        );

        let message = TransactionMessage::parse(&blob).unwrap();
        let instructions: Vec<_> = message.instructions().map(|i| i.unwrap()).collect();

        assert_eq!(instructions.len(), 3);
        assert_eq!(instructions[1].account_indexes, &[0, 1]);
        assert!(instructions[1].data.is_empty());
        assert!(instructions[2].account_indexes.is_empty());
        assert_eq!(instructions[2].data, &[2, 3]);
    }

    #[test]
    fn privilege_boundaries_follow_key_order() {
        // 3 signers (2 writable), 4 keys total, 1 writable non-signer.
        let blob = build(3, 2, 1, &[key(1), key(2), key(3), key(4)], &[], &[]);
        let message = TransactionMessage::parse(&blob).unwrap();

        assert!(message.is_signer(0) && message.is_writable(0));
        assert!(message.is_signer(1) && message.is_writable(1));
        assert!(message.is_signer(2) && !message.is_writable(2));
        assert!(!message.is_signer(3) && message.is_writable(3));
    }

    #[test]
    fn lookups_extend_the_index_space() {
        let blob = build(
            1,
            1,
            0,
            &[key(1)],
            &[(0, &[1, 2], &[])],
            &[(key(9), &[4], &[5])],
        );

        let message = TransactionMessage::parse(&blob).unwrap();

        // One static key plus two loaded from the table.
        assert_eq!(message.num_all_keys(), 3);

        let lookups: Vec<_> = message.lookups().map(|l| l.unwrap()).collect();
        assert_eq!(lookups.len(), 1);
        assert_eq!(lookups[0].account_key.as_array(), &key(9));
        assert_eq!(lookups[0].writable_indexes, &[4]);
        assert_eq!(lookups[0].readonly_indexes, &[5]);
    }

    #[test]
    fn rejects_trailing_bytes() {
        let mut blob = build(1, 1, 0, &[key(1)], &[(0, &[0], &[])], &[]);
        blob.push(0);

        assert!(TransactionMessage::parse(&blob).is_err());
    }

    #[test]
    fn rejects_truncated_blob() {
        let blob = build(1, 1, 0, &[key(1)], &[(0, &[0], &[1, 2, 3])], &[]);

        for len in 0..blob.len() {
            assert!(
                TransactionMessage::parse(&blob[..len]).is_err(),
                "accepted a blob truncated to {len} bytes"
            );
        }
    }

    #[test]
    fn rejects_out_of_range_account_index() {
        let blob = build(1, 1, 0, &[key(1)], &[(0, &[1], &[])], &[]);
        assert!(TransactionMessage::parse(&blob).is_err());
    }

    #[test]
    fn rejects_out_of_range_program_id_index() {
        let blob = build(1, 1, 0, &[key(1)], &[(5, &[0], &[])], &[]);
        assert!(TransactionMessage::parse(&blob).is_err());
    }

    #[test]
    fn rejects_inconsistent_signer_counts() {
        // More signers than keys.
        assert!(TransactionMessage::parse(&build(2, 0, 0, &[key(1)], &[], &[])).is_err());

        // More writable signers than signers.
        assert!(TransactionMessage::parse(&build(1, 2, 0, &[key(1)], &[], &[])).is_err());

        // More writable non-signers than non-signers.
        assert!(TransactionMessage::parse(&build(1, 1, 1, &[key(1)], &[], &[])).is_err());
    }

    #[test]
    fn an_index_into_lookup_space_is_accepted() {
        // Index 1 is not a static key, but the lookup table supplies it.
        let blob = build(
            1,
            1,
            0,
            &[key(1)],
            &[(0, &[1], &[])],
            &[(key(9), &[3], &[])],
        );
        assert!(TransactionMessage::parse(&blob).is_ok());
    }
}
