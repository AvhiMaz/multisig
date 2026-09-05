//! Fixed-width bit sets, which record votes by owner position.
//!
//! A vote is a bit rather than the voter's 32-byte address, so a proposal costs
//! a byte per eight owners instead of thirty-two per voter. Positions are a
//! safe way to name a voter because a proposal only accepts votes while the
//! owner set it was created against is still current: any change to that set
//! moves `stale_transaction_index` past the proposal, and a stale proposal
//! accepts no further votes.

/// Bytes needed to hold `count` bits.
pub const fn len_for(count: usize) -> usize {
    count.div_ceil(8)
}

/// Whether the bit at `index` is set.
///
/// Returns `false` for an index past the end rather than panicking, so a
/// corrupted count cannot take the program down.
pub fn get(bits: &[u8], index: usize) -> bool {
    match bits.get(index / 8) {
        Some(byte) => byte & (1 << (index % 8)) != 0,
        None => false,
    }
}

/// Sets the bit at `index`, returning whether it was previously clear.
pub fn set(bits: &mut [u8], index: usize) -> bool {
    match bits.get_mut(index / 8) {
        Some(byte) => {
            let mask = 1 << (index % 8);
            let was_clear = *byte & mask == 0;
            *byte |= mask;
            was_clear
        }
        None => false,
    }
}

/// Number of bits set.
pub fn count(bits: &[u8]) -> u32 {
    bits.iter().map(|byte| byte.count_ones()).sum()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_rounds_up() {
        assert_eq!(len_for(0), 0);
        assert_eq!(len_for(1), 1);
        assert_eq!(len_for(8), 1);
        assert_eq!(len_for(9), 2);
        assert_eq!(len_for(4096), 512);
    }

    #[test]
    fn set_and_read_back() {
        let mut bits = [0u8; 2];

        assert!(!get(&bits, 0));
        assert!(set(&mut bits, 0));
        assert!(get(&bits, 0));

        // Setting an already-set bit reports it was not clear.
        assert!(!set(&mut bits, 0));

        assert!(set(&mut bits, 15));
        assert!(get(&bits, 15));
        assert!(!get(&bits, 14));

        assert_eq!(count(&bits), 2);
    }

    #[test]
    fn an_index_past_the_end_is_not_a_panic() {
        let mut bits = [0u8; 1];

        assert!(!get(&bits, 64));
        assert!(!set(&mut bits, 64));
        assert_eq!(count(&bits), 0);
    }

    #[test]
    fn every_bit_in_a_byte_is_distinct() {
        let mut bits = [0u8; 1];

        for i in 0..8 {
            assert!(set(&mut bits, i), "bit {i} was already set");
        }

        assert_eq!(bits[0], 0xff);
        assert_eq!(count(&bits), 8);
    }
}
