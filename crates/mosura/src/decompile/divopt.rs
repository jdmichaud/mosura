//! Division-by-constant recovery — a port of Ghidra's `RuleDivOpt` (`ruleaction.cc`). A
//! compiler turns `x / d` into a multiply by a "magic" constant followed by a shift; this
//! recovers the divisor `d` from the magic constant. Ghidra does the reverse with 128-bit
//! arithmetic (`uint8[2]`); Rust's native `u128` makes the port direct.
//!
//! This module currently provides the divisor computation (`calc_divisor`), unit-tested
//! against known magic constants. The form matching (`findForm`) and the INT_DIV/INT_SDIV
//! rewrite are the next increment.

/// Recover the divisor of `x / d` from the magic constant. `magic` is the multiplier, `n`
/// is the total right-shift (`subpiece_bytes*8 + shift`), `xsize` is the operand bit-width.
/// Returns 0 if `magic`/`n` do not correspond to a clean division. Port of
/// `RuleDivOpt::calcDivisor` with `u128` standing in for Ghidra's `uint8[2]`.
#[allow(dead_code)] // the verified crux; wired in when findForm + the rewrite land
pub fn calc_divisor(n: u32, magic: u128, xsize: u32) -> u64 {
    if n > 127 || xsize > 64 || magic <= 1 {
        return 0;
    }
    let y = magic - 1; // c - 1
    let power: u128 = 1u128 << n; // 2^n
    let mut q = power / y;
    let mut r = power % y;
    if q > u64::MAX as u128 {
        return 0; // q does not fit in 64 bits (q[1] != 0)
    }
    if y < q {
        return 0;
    }
    let mut diff: u64 = 0;
    if r >= q {
        q += 1;
        r = r.wrapping_sub(y).wrapping_add(q);
        if r >= q {
            return 0;
        }
        diff = q as u64;
    }
    let maxx: u64 = if xsize == 64 { u64::MAX } else { (1u64 << xsize) - 1 };
    diff = diff.wrapping_add((q as u64).wrapping_sub(r as u64));
    if diff == 0 {
        return q as u64;
    }
    let tmp = power / diff as u128;
    if tmp > u64::MAX as u128 {
        return q as u64; // tmp[1] != 0
    }
    if (tmp as u64) <= maxx {
        return 0;
    }
    q as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovers_known_unsigned_divisors_32bit() {
        // `x / 3`  (u32): x * 0xAAAAAAAB >> 33  → n = 4*8 + 1 = 33
        assert_eq!(calc_divisor(33, 0xAAAAAAAB, 32), 3);
        // `x / 5`  (u32): x * 0xCCCCCCCD >> 34  → n = 4*8 + 2 = 34
        assert_eq!(calc_divisor(34, 0xCCCCCCCD, 32), 5);
        // `x / 7`  (u32): x * 0x24924925 >> 34, but with the +x correction Ghidra handles
        //   the standard form `x / 9`: x * 0x38E38E39 >> 33 → n = 33
        assert_eq!(calc_divisor(33, 0x38E38E39, 32), 9);
    }

    #[test]
    fn recovers_known_unsigned_divisors_64bit() {
        // `x / 3`  (u64): x * 0xAAAAAAAAAAAAAAAB >> 65 → n = 8*8 + 1 = 65
        assert_eq!(calc_divisor(65, 0xAAAAAAAAAAAAAAAB, 64), 3);
        // `x / 5`  (u64): x * 0xCCCCCCCCCCCCCCCD >> 66 → n = 66
        assert_eq!(calc_divisor(66, 0xCCCCCCCCCCCCCCCD, 64), 5);
    }

    #[test]
    fn rejects_non_divisor_magic() {
        assert_eq!(calc_divisor(33, 0x12345678, 32), 0);
        assert_eq!(calc_divisor(0, 2, 32), 0);
    }
}
