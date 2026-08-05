//! `DittedBitSequence` — a port of
//! `Features/Base/.../ghidra/util/bytesearch/DittedBitSequence.java`.
//!
//! A byte pattern with per-bit don't-cares. `bits` holds the required values, `dits` the mask
//! (a 1 bit means "this bit is checked"), so a byte `v` matches position `p` iff
//! `v & dits[p] == bits[p]` (`isMatch`, :217).

/// A pattern of bits/mask to match against a stream of bytes (`DittedBitSequence`, :37).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DittedBitSequence {
    /// Value bits contained in the sequence (`bits`, :59).
    bits: Vec<u8>,
    /// A 1 indicates the bit is **not** ditted (`dits`, :60).
    dits: Vec<u8>,
    /// Unique index assigned to this sequence (`index`, :58) — its position in the pattern list,
    /// which is also the DFA's tie-break order.
    index: usize,
}

impl DittedBitSequence {
    /// An empty sequence (`DittedBitSequence()`, :62).
    pub fn empty() -> DittedBitSequence {
        DittedBitSequence { bits: Vec::new(), dits: Vec::new(), index: 0 }
    }

    /// Parse a ditted sequence from a string (`initFromDittedStringData`, :363), returning the
    /// sequence and the `*` **mark offset** in bytes (`-1` when the string carries no `*`).
    ///
    /// Modes mirror the Java state machine exactly: `-1` looking for a start, `-2` skipping to
    /// end of line after `#`, `0` hex, `1` binary. Note the shape at :386-405 — a `0` that is
    /// not followed by `x` leaves `mode` at `-1` and therefore falls into the *binary* arm,
    /// which is how a group like `01010...` starting with `0` is read.
    pub fn parse(text: &str) -> Result<(DittedBitSequence, i32), String> {
        let chars: Vec<char> = text.chars().collect();
        let mut mark_offset: i32 = -1;
        let mut mode: i32 = -1;
        let mut bitarray: Vec<u8> = Vec::new();
        let mut ditarray: Vec<u8> = Vec::new();
        let mut i = 0usize;
        while i < chars.len() {
            let c1 = chars[i];
            if mode == -2 && c1 != '\n' {
                i += 1;
                continue;
            }
            if c1.is_whitespace() {
                mode = -1;
                i += 1;
                continue;
            }
            if c1 == '#' {
                // start comment - skip remainder of line
                mode = -2;
                i += 1;
                continue;
            }
            if mode == -1 {
                if c1 == '0' {
                    if chars.get(i + 1) == Some(&'x') {
                        mode = 0; // Normal hexadecimal mode
                        i += 2;
                        continue;
                    }
                } else if c1 == '*' {
                    // Set mark at current number of bytes specified
                    mark_offset = ditarray.len() as i32;
                    i += 1;
                    continue;
                } else if c1 == '1' || c1 == '.' {
                    mode = 1;
                } else {
                    return Err(format!("Bad ditted bit sequence: {text:?}"));
                }
            }
            if mode == 0 {
                let c2 = *chars.get(i + 1).ok_or("Bad ditted bit sequence: truncated hex byte")?;
                i += 2;
                let mut val: u8 = 0;
                let mut mask: u8 = 0xff;
                if c1 == '.' {
                    mask ^= 0xf0;
                } else {
                    val = (c1.to_digit(16).ok_or("Bad ditted hex nibble")? as u8) << 4;
                }
                if c2 == '.' {
                    mask ^= 0x0f;
                } else {
                    val |= c2.to_digit(16).ok_or("Bad ditted hex nibble")? as u8;
                }
                bitarray.push(val);
                ditarray.push(mask);
            } else {
                let mut val: u8 = 0;
                let mut mask: u8 = 0;
                for j in 0..8 {
                    let c = *chars.get(i + j).ok_or("Bad ditted bit sequence: truncated group")?;
                    match c {
                        '0' => {
                            val <<= 1;
                            mask = (mask << 1) | 1;
                        }
                        '.' => {
                            val <<= 1;
                            mask <<= 1;
                        }
                        _ => {
                            val = (val << 1) | 1;
                            mask = (mask << 1) | 1;
                        }
                    }
                }
                i += 8;
                bitarray.push(val);
                ditarray.push(mask);
            }
        }
        Ok((DittedBitSequence { bits: bitarray, dits: ditarray, index: 0 }, mark_offset))
    }

    /// `isMatch(pos, val)` (:217) — does `val` match this sequence at byte position `pos`?
    pub fn is_match(&self, pos: usize, val: u8) -> bool {
        match self.bits.get(pos) {
            None => false,
            Some(b) => (val & self.dits[pos]) == *b,
        }
    }

    /// `getSize()` (:247) — size in bytes.
    pub fn size(&self) -> usize {
        self.bits.len()
    }

    /// `setIndex(index)` (:229).
    pub fn set_index(&mut self, index: usize) {
        self.index = index;
    }

    /// `getIndex()` (:238).
    pub fn index(&self) -> usize {
        self.index
    }

    /// `getNumFixedBits()` (:256) — the number of bits that must be 0/1.
    pub fn num_fixed_bits(&self) -> u32 {
        self.dits.iter().map(|d| d.count_ones()).sum()
    }

    /// `concatenate(toConcat)` (:191) — a new sequence with `other` appended.
    pub fn concatenate(&self, other: &DittedBitSequence) -> DittedBitSequence {
        let mut bits = self.bits.clone();
        let mut dits = self.dits.clone();
        bits.extend_from_slice(&other.bits);
        dits.extend_from_slice(&other.dits);
        DittedBitSequence { bits, dits, index: 0 }
    }

    /// `toString()` (:293) — the bit-group rendering, for diagnostics.
    pub fn to_bit_string(&self) -> String {
        let mut out = String::new();
        for chunk in 0..self.bits.len() {
            out.push(' ');
            let dchomp = self.dits[chunk];
            let bchomp = self.bits[chunk];
            let mut pos: u16 = 128;
            while pos > 0 {
                let p = pos as u8;
                if dchomp & p == 0 {
                    out.push('.');
                } else {
                    out.push(if bchomp & p != 0 { '1' } else { '0' });
                }
                pos >>= 1;
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_and_binary_groups_parse_to_the_same_mask() {
        // `0x5.` is "0101 xxxx" — high nibble fixed, low nibble ditted.
        let (hex, mark) = DittedBitSequence::parse("0x5.").unwrap();
        assert_eq!(mark, -1);
        assert_eq!(hex.size(), 1);
        for v in 0x50..=0x5fu8 {
            assert!(hex.is_match(0, v), "0x5. must match {v:02x}");
        }
        assert!(!hex.is_match(0, 0x4f));
        assert_eq!(hex.num_fixed_bits(), 4);

        // `01010...` is the PUSH-register opcode range 0x50..0x57 only — the discrimination the
        // gcc pattern file relies on, since `0x5.` also covers POP (0x58..0x5f).
        let (bin, _) = DittedBitSequence::parse("01010...").unwrap();
        for v in 0x50..=0x57u8 {
            assert!(bin.is_match(0, v), "01010... must match push {v:02x}");
        }
        for v in 0x58..=0x5fu8 {
            assert!(!bin.is_match(0, v), "01010... must NOT match pop {v:02x}");
        }
        assert_eq!(bin.num_fixed_bits(), 5);
    }

    #[test]
    fn mixed_string_with_mark_and_whitespace() {
        // The shape used by `patternpairs`-free files: hex bytes, a binary group, and a `*` mark.
        let (seq, mark) = DittedBitSequence::parse("0x55 *0x89 100000.1").unwrap();
        assert_eq!(mark, 1, "the * marks a one-byte prefix");
        assert_eq!(seq.size(), 3);
        assert!(seq.is_match(0, 0x55) && seq.is_match(1, 0x89));
        // `100000.1` covers both `sub esp,imm8` (0x83) and `sub esp,imm32` (0x81).
        assert!(seq.is_match(2, 0x83) && seq.is_match(2, 0x81));
        assert!(!seq.is_match(2, 0x89));
        assert!(!seq.is_match(3, 0x00), "past the end never matches");
    }

    #[test]
    fn concatenate_joins_bits_and_mask() {
        let (pre, _) = DittedBitSequence::parse("0xc3").unwrap();
        let (post, _) = DittedBitSequence::parse("0x5589e5").unwrap();
        let both = pre.concatenate(&post);
        assert_eq!(both.size(), 4);
        assert!(both.is_match(0, 0xc3) && both.is_match(1, 0x55) && both.is_match(3, 0xe5));
        assert_eq!(both.num_fixed_bits(), pre.num_fixed_bits() + post.num_fixed_bits());
    }
}
