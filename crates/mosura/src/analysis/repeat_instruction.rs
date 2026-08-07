//! `RepeatInstructionByteTracker` — a port of Ghidra's
//! `app/util/RepeatInstructionByteTracker.java`, the bound that stops a disassembly block running
//! away through filler.
//!
//! A run of identical filler bytes decodes perfectly well as instructions — 50 bytes of `00` are
//! 25 valid `ADD byte ptr [BX+SI],AL` on 16-bit x86 — so nothing about the decode itself ends the
//! walk. Ghidra counts consecutive instructions whose bytes are **all the same value** and
//! terminates the block once the run exceeds
//! [`MAX_REPEAT_PATTERN_LENGTH`](crate::analysis::analyzers::MAX_REPEAT_PATTERN_LENGTH).
//!
//! ⚠️ **The instruction that trips the limit is KEPT.** `Disassembler.java:1067` calls this, and on
//! `true` it only records a parse conflict; `processInstruction` (:1073) still runs and
//! `block.addInstruction(inst)` (:1254) still adds it. The block ends afterwards, on
//! `block.hasInstructionError()` (:1076). So a limit of 16 admits **17** instructions — which is
//! exactly what the committed war2 golden shows, and getting it backwards would leave the last
//! filler instruction undecoded on every such run.

/// The byte value repeated across every byte of `bytes`, or `None` if they vary
/// (`PseudoInstruction.getRepeatedByte`, PseudoInstruction.java:149). A one-byte instruction
/// always repeats — so a run of 17 `NOP`s trips the limit just as a run of `00 00` does.
pub fn repeated_byte(bytes: &[u8]) -> Option<u8> {
    let first = *bytes.first()?;
    bytes.iter().all(|&b| b == first).then_some(first)
}

/// Tracks runs of same-repeated-byte instructions within one disassembly block.
pub struct RepeatInstructionByteTracker {
    limit: i32,
    count: i32,
    byte_value: u8,
}

impl RepeatInstructionByteTracker {
    /// `limit` is the maximum run length; `<= 0` disables the check entirely, as in Ghidra.
    pub fn new(limit: i32) -> RepeatInstructionByteTracker {
        RepeatInstructionByteTracker { limit, count: 0, byte_value: 0 }
    }

    /// `reset()` — call at the start of each block of instructions.
    ///
    /// Ghidra resets the **counter only**, deliberately leaving `repeatByteValue` alone. Mirrored
    /// rather than tidied: with the counter at 0 both branches below produce `count == 1`, so the
    /// stale value changes no answer, and matching the field-for-field state keeps it that way if
    /// the arms ever diverge.
    pub fn reset(&mut self) {
        self.count = 0;
    }

    /// `exceedsRepeatBytePattern(inst)` — true once this instruction takes the run past the limit.
    /// The caller keeps this instruction and ends the block after it.
    pub fn exceeds_repeat_byte_pattern(&mut self, bytes: &[u8]) -> bool {
        if self.limit <= 0 {
            return false;
        }
        // Ghidra also exempts a `repeatPatternLimitIgnoredRegion` set here; nothing in mosura
        // sets one (it exists for the pseudo-disassembler's caller to suppress bad bookmarks).
        match repeated_byte(bytes) {
            None => self.count = 0,
            Some(b) if b == self.byte_value => {
                self.count += 1;
                if self.count > self.limit {
                    self.count = 0;
                    return true;
                }
            }
            Some(b) => {
                self.byte_value = b;
                self.count = 1;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_byte_is_all_bytes_equal() {
        assert_eq!(repeated_byte(&[0x00, 0x00]), Some(0x00));
        assert_eq!(repeated_byte(&[0x90]), Some(0x90)); // one byte always repeats
        assert_eq!(repeated_byte(&[0xff, 0xff, 0xff]), Some(0xff));
        assert_eq!(repeated_byte(&[0x81, 0x90, 0x00, 0x00, 0x00, 0x00]), None);
        assert_eq!(repeated_byte(&[]), None);
    }

    /// ⭐ THE OFF-BY-ONE THAT MATTERS. A limit of 16 admits SEVENTEEN instructions, because the
    /// counter is pre-incremented and compared with `>`, and because the tripping instruction is
    /// still added to the block by the caller. Measured against the committed war2 golden: the
    /// zero-fill run starting at `00018f04` keeps `00018f04`..`00018f24` — 17 instructions — and
    /// `00018f26` is the first address Ghidra does not decode.
    #[test]
    fn a_limit_of_sixteen_admits_seventeen_instructions() {
        let mut t = RepeatInstructionByteTracker::new(16);
        t.reset();
        for i in 0..16 {
            assert!(!t.exceeds_repeat_byte_pattern(&[0x00, 0x00]), "instruction {i} must pass");
        }
        assert!(t.exceeds_repeat_byte_pattern(&[0x00, 0x00]), "the 17th trips the limit");
    }

    /// A non-repeating instruction zeroes the counter, so a run only counts while it is unbroken.
    #[test]
    fn a_varying_instruction_breaks_the_run() {
        let mut t = RepeatInstructionByteTracker::new(16);
        t.reset();
        for _ in 0..16 {
            assert!(!t.exceeds_repeat_byte_pattern(&[0x00, 0x00]));
        }
        assert!(!t.exceeds_repeat_byte_pattern(&[0x8b, 0x76])); // varies -> count = 0
        for i in 0..16 {
            assert!(!t.exceeds_repeat_byte_pattern(&[0x00, 0x00]), "the run restarts ({i})");
        }
        assert!(t.exceeds_repeat_byte_pattern(&[0x00, 0x00]));
    }

    /// Switching to a *different* repeated byte restarts the count at 1 rather than continuing it.
    #[test]
    fn a_different_repeated_byte_restarts_the_count() {
        let mut t = RepeatInstructionByteTracker::new(16);
        t.reset();
        for _ in 0..16 {
            assert!(!t.exceeds_repeat_byte_pattern(&[0x00, 0x00]));
        }
        assert!(!t.exceeds_repeat_byte_pattern(&[0xff, 0xff])); // new value -> count = 1
        for i in 0..15 {
            assert!(!t.exceeds_repeat_byte_pattern(&[0xff, 0xff]), "ff run continues ({i})");
        }
        assert!(t.exceeds_repeat_byte_pattern(&[0xff, 0xff]));
    }

    /// `limit <= 0` disables the check (Ghidra's documented way to turn it off).
    #[test]
    fn a_non_positive_limit_disables_the_check() {
        let mut t = RepeatInstructionByteTracker::new(-1);
        for _ in 0..1000 {
            assert!(!t.exceeds_repeat_byte_pattern(&[0x00, 0x00]));
        }
    }
}
