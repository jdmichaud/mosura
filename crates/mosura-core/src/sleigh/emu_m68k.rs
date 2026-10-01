//! The 68000 family's emulator state modifier: the hardware rules the SLEIGH spec does not carry.
//!
//! Ghidra gives a language's emulation its own Java class, named by the processor spec's
//! `emulateInstructionStateModifierClass` property: the 68000's is
//! `m68kEmulateInstructionStateModifier` (68000.pspec), shared by every 680x0 and ColdFire
//! variant. Its job is to give the language's `define pcodeop`s a behaviour
//! (`registerPcodeOpBehavior`) and to adjust the state after an instruction
//! (`postExecuteCallback`). Ghidra's own 68000 class registers nothing, so its emulator stops on
//! the first `abcd` ("unimplemented CALLOTHER"); this module is the same hook with the entries a
//! 68000 program needs.
//!
//! What 68000.sinc leaves out, and what is done here instead:
//!
//! - `abcd` and `sbcd` add or subtract in binary and hand the result to `bcdAdjust`, a
//!   `pcodeop` with no definition; in `abcd` its output even lands in `XF`, which the next line
//!   overwrites, so the stored sum stays binary. The decimal adjust needs the operands as they
//!   were before the add, which the p-code has already overwritten when `bcdAdjust` runs, so the
//!   two instructions are executed here whole. Their only operand forms are `Dy,Dx` and
//!   `-(Ay),-(Ax)`, fixed by the instruction word (M68000PRM 4-3, 4-170).
//! - `nbcd <ea>` computes `0 - d - X` in binary and stores `bcdAdjust` of it through the
//!   instruction's own addressing, with `X` still unchanged when `bcdAdjust` runs. That is enough
//!   to recover `d`, so `nbcd` keeps its p-code: `bcdAdjust` returns the decimal result and the
//!   flags are set once the instruction's own flag code has run.
//! - `divu.w` and `divs.w` store `(remainder << 16) | quotient` whatever the quotient. A 68000
//!   whose quotient does not fit 16 bits leaves the destination unchanged and sets V
//!   (M68000PRM 4-93, 4-97). The p-code's own division is kept and its full quotient decides.
//! - The shift and rotate macros (`logicalShiftLeft`, `rotateLeft`, …) set V to the MSB before
//!   XOR the MSB after, where the 68000 clears it for all but ASL, and ASL sets it if the MSB
//!   changes at ANY point; a rotate by a count past the width shifts by a negative amount and
//!   yields zero. The register forms are executed here whole (their operands are fixed by the
//!   instruction word: M68000PRM 4-22, 4-113, 4-160, 4-163); the memory forms, a shift by one
//!   through any addressing mode, keep their p-code and get V afterwards.
//!
//! Every rule was checked against an independent 68000 model, BlastEm's (cycle-accurate,
//! hardware-verified), over every byte pair for each BCD instruction and condition-code input,
//! 4000 division vectors and every shift and rotate form over 20 values and counts 0-69. The flags the manual calls undefined (N and V after a BCD operation, N
//! and Z after a division overflow) follow the hardware as BlastEm measures it.

use super::emu::Machine;
use super::engine::Spec;

/// The four shift and rotate families of the 68000, by the instruction word's type field.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ShiftKind {
    /// `asl`/`asr`.
    Arithmetic,
    /// `lsl`/`lsr`.
    Logical,
    /// `roxl`/`roxr`: through X.
    RotateExtended,
    /// `rol`/`ror`.
    Rotate,
}

/// One instruction this modifier executes or adjusts, from its mnemonic and instruction word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Insn {
    /// `abcd` (`add`) or `sbcd`: destination register `rx`, source `ry`, `-(An)` forms when `memory`.
    Bcd { add: bool, rx: usize, ry: usize, memory: bool },
    /// `nbcd <ea>`.
    Nbcd,
    /// `divu.w` / `divs.w <ea>,Dn`.
    DivW { signed: bool, dn: usize },
    /// A shift or rotate of data register `dy` by `bits` (8, 16, 32): by the immediate `count`
    /// (1-8), or by data register `count` modulo 64 when `by_register`.
    Shift { kind: ShiftKind, left: bool, bits: u32, count: usize, by_register: bool, dy: usize },
    /// A shift or rotate of a memory word by one.
    ShiftMemory { kind: ShiftKind, left: bool },
}

/// The registers the rules read and write, resolved by name from the language.
#[derive(Clone, Debug)]
pub(crate) struct M68k {
    d: [u64; 8],
    a: [u64; 8],
    x: u64,
    n: u64,
    z: u64,
    v: u64,
    c: u64,
    /// The memory space, by name.
    ram: String,
}

/// What an adjusted instruction needs from the state before it ran.
#[derive(Clone, Debug, Default)]
pub(crate) struct Before {
    /// The division's destination register, which an overflow leaves unchanged.
    dividend: u64,
    /// Z, which a BCD result of zero leaves unchanged.
    z: u64,
    /// The flags `bcdAdjust` computed for this `nbcd`: (X/C, V, N, result non-zero).
    pub(crate) nbcd_flags: Option<(bool, bool, bool, bool)>,
    /// The full quotient of the division the instruction's p-code ran.
    pub(crate) quotient: Option<u64>,
}

impl M68k {
    /// The modifier for `spec`, when its processor spec names the 68000's
    /// (`m68kEmulateInstructionStateModifier`) and every register the rules use exists.
    pub(crate) fn for_spec(spec: &Spec) -> Option<Self> {
        if !spec.emulate_modifier.as_deref()?.ends_with(".m68kEmulateInstructionStateModifier") {
            return None;
        }
        let reg = |name: &str| spec.register_offset(name);
        let mut d = [0u64; 8];
        let mut a = [0u64; 8];
        for i in 0..8 {
            d[i] = reg(&format!("D{i}"))?;
            // A7 is spelled `SP` at its 4-byte width (68000.sinc:12).
            a[i] = reg(&if i == 7 { "SP".to_string() } else { format!("A{i}") })?;
        }
        Some(Self {
            d,
            a,
            x: reg("XF")?,
            n: reg("NF")?,
            z: reg("ZF")?,
            v: reg("VF")?,
            c: reg("CF")?,
            ram: spec.spaces[spec.default_space].name.clone(),
        })
    }

    /// Which instruction this is, if it is one this modifier handles.
    pub(crate) fn classify(&self, mnemonic: &str, bytes: &[u8]) -> Option<Insn> {
        let word = u16::from_be_bytes([*bytes.first()?, *bytes.get(1)?]);
        let rx = usize::from((word >> 9) & 7);
        let ry = usize::from(word & 7);
        let memory = word & 0x8 != 0;
        match mnemonic.to_ascii_lowercase().as_str() {
            "abcd" => Some(Insn::Bcd { add: true, rx, ry, memory }),
            "sbcd" => Some(Insn::Bcd { add: false, rx, ry, memory }),
            "nbcd" => Some(Insn::Nbcd),
            "divu.w" => Some(Insn::DivW { signed: false, dn: rx }),
            "divs.w" => Some(Insn::DivW { signed: true, dn: rx }),
            name => {
                let base = name.split('.').next().unwrap_or(name);
                if word & 0xf000 != 0xe000
                    || !matches!(base, "asl" | "asr" | "lsl" | "lsr" | "roxl" | "roxr" | "rol" | "ror")
                {
                    return None;
                }
                // 1110 ccc d ss i tt yyy for a register, 1110 0tt d 11 <ea> for memory
                // (M68000PRM 4-22, 4-113, 4-160, 4-163).
                let kinds = [ShiftKind::Arithmetic, ShiftKind::Logical, ShiftKind::RotateExtended, ShiftKind::Rotate];
                let left = word & 0x100 != 0;
                let size = (word >> 6) & 3;
                if size == 3 {
                    return Some(Insn::ShiftMemory { kind: kinds[usize::from((word >> 9) & 3)], left });
                }
                Some(Insn::Shift {
                    kind: kinds[usize::from((word >> 3) & 3)],
                    left,
                    bits: 8 << size,
                    count: rx,
                    by_register: word & 0x20 != 0,
                    dy: ry,
                })
            }
        }
    }

    /// Execute `insn` in place of its p-code, when this modifier replaces it: `true` when it did.
    pub(crate) fn execute(&self, m: &mut Machine, insn: Insn) -> bool {
        if let Insn::Shift { kind, left, bits, count, by_register, dy } = insn {
            // An immediate count of 0 encodes 8; a register count is taken modulo 64.
            let n = if by_register { (m.read("register", self.d[count], 4) & 63) as u32 } else if count == 0 { 8 } else { count as u32 };
            let old = m.read("register", self.d[dy], 4);
            let x = m.read("register", self.x, 1) & 1 != 0;
            let r = shift(kind, left, bits, old, n, x);
            let keep = if bits == 32 { 0 } else { 0xffff_ffff & !((1u64 << bits) - 1) };
            m.write("register", self.d[dy], 4, (old & keep) | r.value);
            if let Some(x) = r.x {
                m.write("register", self.x, 1, u64::from(x));
            }
            m.write("register", self.n, 1, (r.value >> (bits - 1)) & 1);
            m.write("register", self.z, 1, u64::from(r.value == 0));
            m.write("register", self.v, 1, u64::from(r.overflow));
            m.write("register", self.c, 1, u64::from(r.carry));
            return true;
        }
        let Insn::Bcd { add, rx, ry, memory } = insn else { return false };
        let x = m.read("register", self.x, 1) & 1 != 0;
        let (src, dst, at) = if memory {
            // Source first, then destination, each predecremented by the operand size — by two
            // for A7, which the 68000 keeps word-aligned (M68000PRM 2-7).
            let step = |r: usize| if r == 7 { 2 } else { 1 };
            let ay = m.read("register", self.a[ry], 4).wrapping_sub(step(ry)) & 0xffff_ffff;
            m.write("register", self.a[ry], 4, ay);
            let src = m.read(&self.ram, ay, 1) as u8;
            let ax = m.read("register", self.a[rx], 4).wrapping_sub(step(rx)) & 0xffff_ffff;
            m.write("register", self.a[rx], 4, ax);
            (src, m.read(&self.ram, ax, 1) as u8, Some(ax))
        } else {
            (m.read("register", self.d[ry], 4) as u8, m.read("register", self.d[rx], 4) as u8, None)
        };
        let r = if add { bcd_add(dst, src, x) } else { bcd_sub(dst, src, x) };
        match at {
            Some(ax) => m.write(&self.ram, ax, 1, u64::from(r.value)),
            None => {
                let dx = m.read("register", self.d[rx], 4);
                m.write("register", self.d[rx], 4, (dx & !0xff) | u64::from(r.value));
            }
        }
        let z = m.read("register", self.z, 1);
        self.set_bcd_flags(m, (r.carry, r.overflow, r.value & 0x80 != 0, r.value != 0), z);
        true
    }

    /// What `insn` needs from the state before its p-code runs.
    pub(crate) fn before(&self, m: &Machine, insn: Insn) -> Before {
        let dividend = match insn {
            Insn::DivW { dn, .. } => m.read("register", self.d[dn], 4),
            _ => 0,
        };
        Before { dividend, z: m.read("register", self.z, 1), ..Before::default() }
    }

    /// The X flag, as `bcdAdjust` inside `nbcd` reads it (still the instruction's input).
    pub(crate) fn x_flag(&self, m: &Machine) -> bool {
        m.read("register", self.x, 1) & 1 != 0
    }

    /// Adjust the state once `insn`'s p-code has run.
    pub(crate) fn after(&self, m: &mut Machine, insn: Insn, before: &Before) {
        match insn {
            Insn::Nbcd => {
                if let Some(flags) = before.nbcd_flags {
                    self.set_bcd_flags(m, flags, before.z);
                }
            }
            Insn::DivW { signed, dn } => {
                let Some(q) = before.quotient else { return };
                let fits = if signed { (-0x8000..=0x7fff).contains(&(q as i64)) } else { q <= 0xffff };
                // C is always cleared and X is not affected.
                m.write("register", self.c, 1, 0);
                if fits {
                    m.write("register", self.n, 1, (q >> 15) & 1);
                    m.write("register", self.z, 1, u64::from(q & 0xffff == 0));
                    m.write("register", self.v, 1, 0);
                } else {
                    m.write("register", self.d[dn], 4, before.dividend);
                    m.write("register", self.n, 1, 1);
                    m.write("register", self.z, 1, 0);
                    m.write("register", self.v, 1, 1);
                }
            }
            // The sinc's V is the MSB before XOR the MSB after, which is ASL's for a shift by
            // one; every other shift and rotate clears V (M68000PRM 4-113, 4-160, 4-163).
            Insn::ShiftMemory { kind, left } => {
                if !(kind == ShiftKind::Arithmetic && left) {
                    m.write("register", self.v, 1, 0);
                }
            }
            Insn::Bcd { .. } | Insn::Shift { .. } => {}
        }
    }

    /// X and C from the decimal carry; Z cleared by a non-zero result and otherwise unchanged
    /// from `z`, so a multi-byte chain ends with Z telling whether the whole number is zero.
    fn set_bcd_flags(&self, m: &mut Machine, (carry, overflow, negative, nonzero): (bool, bool, bool, bool), z: u64) {
        m.write("register", self.x, 1, u64::from(carry));
        m.write("register", self.c, 1, u64::from(carry));
        m.write("register", self.v, 1, u64::from(overflow));
        m.write("register", self.n, 1, u64::from(negative));
        m.write("register", self.z, 1, if nonzero { 0 } else { z });
    }
}

/// `bcdAdjust(tmp)` inside `nbcd`: `tmp` is `0 - d - X` in binary and `x` is still the
/// instruction's input, so `d` is recovered and negated in decimal. Returns the byte the p-code
/// stores and the flags (X/C, V, N, result non-zero) to set once its own flag code has run.
pub(crate) fn nbcd_adjust(tmp: u64, x: bool) -> (u64, (bool, bool, bool, bool)) {
    let d = (tmp as u8).wrapping_neg().wrapping_sub(u8::from(x));
    let r = bcd_sub(0, d, x);
    (u64::from(r.value), (r.carry, r.overflow, r.value & 0x80 != 0, r.value != 0))
}

/// A shifted or rotated value: the result, X when the instruction sets it, V and C.
#[derive(Debug, PartialEq, Eq)]
struct Shifted {
    value: u64,
    x: Option<bool>,
    overflow: bool,
    carry: bool,
}

/// `value`'s low `bits` shifted or rotated by `n` (0-63) as the 68000 does (M68000PRM 4-22, 4-113,
/// 4-160, 4-163). A count of 0 changes nothing but the flags: C cleared (X's value for `roxd`), X
/// unaffected. A shift moves the last bit out into C and X, all of them out once `n` reaches the
/// width; ASL sets V when the MSB changes at any point of the shift, every other kind clears it.
/// `rod` rotates by `n` modulo the width with X unaffected and C the last bit rotated; `roxd`
/// rotates the width plus X by `n` modulo width + 1, C and X the bit that ends up in X.
fn shift(kind: ShiftKind, left: bool, bits: u32, value: u64, n: u32, x: bool) -> Shifted {
    let mask = (1u64 << bits) - 1;
    let v = value & mask;
    let msb = |r: u64| (r >> (bits - 1)) & 1 != 0;
    if n == 0 {
        let carry = kind == ShiftKind::RotateExtended && x;
        return Shifted { value: v, x: None, overflow: false, carry };
    }
    match (kind, left) {
        (ShiftKind::Arithmetic | ShiftKind::Logical, true) => {
            let value = if n < bits { (v << n) & mask } else { 0 };
            let carry = n <= bits && (v >> (bits - n)) & 1 != 0;
            let overflow = kind == ShiftKind::Arithmetic
                && if n >= bits {
                    v != 0
                } else {
                    // The n+1 bits that pass through the MSB are not all equal.
                    let top = v >> (bits - n - 1);
                    top != 0 && top != (1u64 << (n + 1)) - 1
                };
            Shifted { value, x: Some(carry), overflow, carry }
        }
        (ShiftKind::Logical, false) => {
            let value = if n < bits { v >> n } else { 0 };
            let carry = n <= bits && (v >> (n - 1)) & 1 != 0;
            Shifted { value, x: Some(carry), overflow: false, carry }
        }
        (ShiftKind::Arithmetic, false) => {
            let signed = ((v << (64 - bits)) as i64) >> (64 - bits);
            let value = (signed >> n.min(bits)) as u64 & mask;
            let carry = if n <= bits { (signed >> (n - 1)) & 1 != 0 } else { msb(v) };
            Shifted { value, x: Some(carry), overflow: false, carry }
        }
        (ShiftKind::Rotate, _) => {
            let k = n % bits;
            let value = if k == 0 {
                v
            } else if left {
                ((v << k) | (v >> (bits - k))) & mask
            } else {
                ((v >> k) | (v << (bits - k))) & mask
            };
            let carry = if left { value & 1 != 0 } else { msb(value) };
            Shifted { value, x: None, overflow: false, carry }
        }
        (ShiftKind::RotateExtended, _) => {
            let width = bits + 1;
            let k = n % width;
            let all = (u64::from(x) << bits) | v;
            let wide = (1u64 << width) - 1;
            let rotated = if k == 0 {
                all
            } else if left {
                ((all << k) | (all >> (width - k))) & wide
            } else {
                ((all >> k) | (all << (width - k))) & wide
            };
            let carry = rotated >> bits != 0;
            Shifted { value: rotated & mask, x: Some(carry), overflow: false, carry }
        }
    }
}

/// A decimal result: the byte, the decimal carry (X and C), and V.
#[derive(Debug, PartialEq, Eq)]
struct Decimal {
    value: u8,
    carry: bool,
    overflow: bool,
}

/// `dst + src + x` in decimal, as the 68000 computes it for every byte pair, valid BCD or not:
/// the binary sum, then a correction of 6 when the low digits carried past 9 and of 0x60 when
/// the sum carried or reached the threshold the low correction leaves. V is the signed overflow of
/// adding the correction.
fn bcd_add(dst: u8, src: u8, x: bool) -> Decimal {
    let low = (dst & 0xf) + (src & 0xf) + u8::from(x);
    let mut correction = if low >= 0xa { 6 } else { 0 };
    let threshold = if correction != 0 { 0x9a } else { 0xa0 };
    let (sum, c1) = dst.overflowing_add(src);
    let (sum, c2) = sum.overflowing_add(u8::from(x));
    let mut carry = c1 || c2;
    if carry || sum >= threshold {
        carry = true;
        correction |= 0x60;
    }
    let (value, c3) = sum.overflowing_add(correction);
    Decimal { value, carry: carry || c3, overflow: !sum & value & 0x80 != 0 }
}

/// `dst - src - x` in decimal: the binary difference, then a correction of 6 when the low digit
/// borrowed and of 0x60 when the byte borrowed. V is the signed overflow of subtracting it.
fn bcd_sub(dst: u8, src: u8, x: bool) -> Decimal {
    let low = (dst & 0xf).wrapping_sub(src & 0xf).wrapping_sub(u8::from(x));
    let mut correction = if low >= 0x10 { 6 } else { 0 };
    let (diff, b1) = dst.overflowing_sub(src);
    let (diff, b2) = diff.overflowing_sub(u8::from(x));
    let borrow = b1 || b2;
    if borrow {
        correction |= 0x60;
    }
    let (value, b3) = diff.overflowing_sub(correction);
    Decimal { value, carry: borrow || b3, overflow: diff & !value & 0x80 != 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shifts_and_rotates() {
        use ShiftKind::*;
        // lsr.w #1 of 0x838a clears V whatever the MSB does.
        assert_eq!(shift(Logical, false, 16, 0x838a, 1, false), Shifted { value: 0x41c5, x: Some(false), overflow: false, carry: false });
        // asl: V when the MSB changes at any point, not only between first and last.
        assert!(shift(Arithmetic, true, 8, 0x60, 2, false).overflow);
        assert!(!shift(Arithmetic, true, 8, 0xe0, 2, false).overflow);
        // rol.b by 12 is rol.b by 4, C the last bit rotated out.
        assert_eq!(shift(Rotate, true, 8, 0x81, 12, false), Shifted { value: 0x18, x: None, overflow: false, carry: false });
        assert_eq!(shift(Rotate, true, 8, 0x81, 4, false).value, 0x18);
        // roxl.b by 9 brings the byte back with X through it.
        assert_eq!(shift(RotateExtended, true, 8, 0x5a, 9, true).value, 0x5a);
        // A count of 0: C cleared, or X for roxd; X unaffected.
        assert_eq!(shift(RotateExtended, false, 8, 0x5a, 0, true), Shifted { value: 0x5a, x: None, overflow: false, carry: true });
        assert_eq!(shift(Arithmetic, false, 32, 0x8000_0000, 40, false), Shifted { value: 0xffff_ffff, x: Some(true), overflow: false, carry: true });
    }

    #[test]
    fn decimal_add_and_subtract() {
        // The cases a binary add gets wrong, and the carry out of 99.
        assert_eq!(bcd_add(0x09, 0x01, false), Decimal { value: 0x10, carry: false, overflow: false });
        assert_eq!(bcd_add(0x0f, 0x0f, false).value, 0x24);
        assert_eq!(bcd_add(0x99, 0x01, false), Decimal { value: 0x00, carry: true, overflow: false });
        assert_eq!(bcd_add(0x45, 0x54, true), Decimal { value: 0x00, carry: true, overflow: false });
        assert_eq!(bcd_sub(0x10, 0x01, false), Decimal { value: 0x09, carry: false, overflow: false });
        assert_eq!(bcd_sub(0x00, 0x01, false), Decimal { value: 0x99, carry: true, overflow: false });
        assert_eq!(bcd_sub(0x00, 0x00, true), Decimal { value: 0x99, carry: true, overflow: false });
        // nbcd of 0x99 with X set is 0 - 99 - 1 = 00, borrowing.
        assert_eq!(bcd_sub(0x00, 0x99, true), Decimal { value: 0x00, carry: true, overflow: false });
    }
}
