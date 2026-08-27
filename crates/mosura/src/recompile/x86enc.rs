//! x86 (IA-32) encoding facts for the recompile witnesses (review R3): the few instruction FORMS
//! the `*_from_evidence` readers need, decoded once here from the instruction bytes and unit-tested
//! against hand-assembled encodings, instead of re-implemented inside each witness (two of the
//! 2026-08-26/27 defects were decoder-level). SLEIGH already decodes every instruction's semantics
//! into [`crate::recompile::insn::NormInsn`]; what a witness needs beyond that is the ENCODING —
//! which opcode form, which immediate width, which condition nibble — and that lives here.
//!
//! Scope is deliberately small: the legacy prefixes, ModRM, the conditional jumps, the ALU
//! immediates (`3C/3D` and group 1 `80/81/83`), `TEST r,r`, the shift-by-immediate group, `SBB r,r`,
//! the string instructions, `PUSH r32`, `SUB ESP,imm`. Every reader returns `None` on any other byte
//! sequence — a witness never guesses. `LOCK` (`F0`) is not treated as a prefix, so every reader
//! returns `None` on a LOCK-prefixed instruction. Readers whose form the compiler only ever emits
//! bare — a `Jcc`, the division template's `SBB`, the prologue's `SUB ESP`, a plain `MOVSD`,
//! `PUSH r32` — decode the raw bytes and refuse any prefix, so their domain is exactly the raw
//! first-byte match the witnesses had; `alu_imm` and `test_rr` skip the legacy prefixes as the
//! sparse-switch witness did. Each reader's doc cites the encoding the way the manual
//! does (`CMP r/m32, imm8 = 83 /7 ib`), and every immediate is read as the LAST n bytes of the
//! instruction — the property that makes the decode independent of ModRM/SIB/displacement.
//! `tests/x86enc.rs` pins each form on hand-assembled bytes (both operand sizes, with prefixes,
//! with a displacement before the immediate) and cross-checks the readers against SLEIGH's decode
//! of the committed oracle fixtures on what both assert: the mnemonic, and the decoded immediate
//! being a member of `NormInsn::consts`.
//!
//! Only the five BYTE-level witnesses (`sparse_cmps`, `sdiv_pow2`, `movsd_runs`, `frame`,
//! `string_ops`) read through this module. The thirteen witnesses that parse `NormInsn::text`
//! (documented "for reports only, never compared") are a separate debt — R3b: an operands view
//! over the SLEIGH facts (`sem`/`regs`/`consts`/`form`), one witness per commit under the same
//! census-identity acceptance. R3 does not make those clean.

/// The legacy prefixes in front of an opcode.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Prefixes {
    /// `66`: 16-bit operand size.
    pub opsize16: bool,
    /// `67`: 16-bit address size.
    pub addrsize16: bool,
    /// `F3` (REP / REPE).
    pub rep: bool,
    /// `F2` (REPNE).
    pub repne: bool,
    /// A segment override (`26 2E 36 3E 64 65`), if any.
    pub segment: Option<u8>,
    /// Prefix bytes consumed — the opcode starts here.
    pub len: usize,
}

/// The legacy prefixes at the front of `bytes`, in any order: operand size `66`, address size
/// `67`, `F3` (REP/REPE), `F2` (REPNE), segment overrides `26 2E 36 3E 64 65`.
pub fn prefixes(bytes: &[u8]) -> Prefixes {
    let mut p = Prefixes::default();
    for &b in bytes {
        match b {
            0x66 => p.opsize16 = true,
            0x67 => p.addrsize16 = true,
            0xf3 => p.rep = true,
            0xf2 => p.repne = true,
            0x26 | 0x2e | 0x36 | 0x3e | 0x64 | 0x65 => p.segment = Some(b),
            _ => break,
        }
        p.len += 1;
    }
    p
}

/// The operand size (bits) an `iz`-form instruction uses under `prefixes`.
fn opsize(p: &Prefixes) -> u32 {
    if p.opsize16 {
        16
    } else {
        32
    }
}

/// A ModRM byte: `mod` (bits 7:6), `reg` (5:3), `rm` (2:0).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModRm {
    pub mod_: u8,
    pub reg: u8,
    pub rm: u8,
}

impl ModRm {
    pub fn of(b: u8) -> Self {
        ModRm { mod_: b >> 6, reg: (b >> 3) & 7, rm: b & 7 }
    }
    /// `mod` = 11: the r/m operand is a register, no displacement follows.
    pub fn is_register_direct(&self) -> bool {
        self.mod_ == 3
    }
}

/// A conditional jump's condition, as the flags it reads spell it — the `tttn` field's kind:
/// `Overflow` = OF, `Below` = CF (unsigned), `Equal` = ZF, `BelowOrEqual` = CF|ZF (unsigned),
/// `Sign` = SF, `Parity` = PF, `Less` = SF≠OF (signed), `LessOrEqual` = ZF|SF≠OF (signed); the
/// low bit of the nibble negates it (`JNE`, `JAE` = not below, `JA` = not below-or-equal, `JGE`,
/// `JG`). The whole fact is exposed; a witness maps what it needs (the sparse-switch witness folds
/// the signed and unsigned orderings together, in the witness).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cond {
    Overflow,
    Below,
    Equal,
    BelowOrEqual,
    Sign,
    Parity,
    Less,
    LessOrEqual,
}

/// A `Jcc`: `7x cb` (short) or `0F 8x cd` (near).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Jcc {
    pub cond: Cond,
    pub negated: bool,
    pub near: bool,
    /// The encoded displacement, sign-extended.
    pub rel: i32,
}

impl Cond {
    /// `Less` / `LessOrEqual` read SF≠OF — the signed orderings; `Below` / `BelowOrEqual` read CF.
    pub fn is_signed(self) -> bool {
        matches!(self, Cond::Less | Cond::LessOrEqual)
    }
}

const CONDS: [Cond; 8] = [
    Cond::Overflow,
    Cond::Below,
    Cond::Equal,
    Cond::BelowOrEqual,
    Cond::Sign,
    Cond::Parity,
    Cond::Less,
    Cond::LessOrEqual,
];

/// `Jcc rel8 = 7x cb` (short) and `Jcc rel32 = 0F 8x cd` (near), `x` = the `tttn` nibble, with no
/// prefix: a `66` would make the near displacement 16 bits (`0F 8x cw`) and `2E`/`3E` are branch
/// hints — 32-bit compilers emit neither, and a prefixed jump is `None` (the raw two- and six-byte
/// matches the witnesses had).
pub fn jcc(bytes: &[u8]) -> Option<Jcc> {
    let (nibble, near, rel) = match bytes {
        [op, cb] if (0x70..=0x7f).contains(op) => (op & 0xf, false, *cb as i8 as i32),
        [0x0f, op, d0, d1, d2, d3] if (0x80..=0x8f).contains(op) => {
            (op & 0xf, true, i32::from_le_bytes([*d0, *d1, *d2, *d3]))
        }
        _ => return None,
    };
    Some(Jcc { cond: CONDS[(nibble >> 1) as usize], negated: nibble & 1 == 1, near, rel })
}

/// An immediate operand and the operand size it was encoded for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Imm {
    /// The value as the instruction uses it: an `ib` of an `83` form sign-extended to the operand
    /// size and then zero-extended into the `u64`.
    pub value: u64,
    /// 8, 16 or 32.
    pub opsize: u32,
}

/// The last `n` bytes of `bytes` as a little-endian value, when the instruction is at least
/// `min_len` long — EVERY immediate sits at the tail of its instruction, after any
/// ModRM/SIB/displacement, so the readers never have to decode the addressing form.
fn tail(bytes: &[u8], n: usize, min_len: usize) -> Option<u64> {
    (bytes.len() >= min_len).then(|| bytes[bytes.len() - n..].iter().rev().fold(0u64, |a, &x| (a << 8) | x as u64))
}

/// The immediate of an ALU instruction for the operation `/reg` (0 ADD, 1 OR, 2 ADC, 3 SBB, 4 AND,
/// 5 SUB, 6 XOR, 7 CMP), in the manual's forms — for CMP: `CMP AL, imm8 = 3C ib`;
/// `CMP eAX, imm32 = 3D id` (`3D iw` under `66`); `CMP r/m8, imm8 = 80 /7 ib`;
/// `CMP r/m32, imm32 = 81 /7 id` (`81 /7 iw` under `66`); `CMP r/m32, imm8 = 83 /7 ib`, the imm8
/// sign-extended to the operand size. The other operations are the same forms with their own
/// `/reg` and accumulator opcode (`04+8·reg ib`, `05+8·reg iz`). `None` for any other instruction
/// or another `/reg`; the immediate is read from the tail, whatever the addressing form.
pub fn alu_imm(bytes: &[u8], reg: u8) -> Option<Imm> {
    let p = prefixes(bytes);
    let b = &bytes[p.len..];
    let size = opsize(&p);
    let iz = (size / 8) as usize;
    let op = *b.first()?;
    if op == 0x04 + 8 * reg {
        return tail(b, 1, 2).map(|v| Imm { value: v, opsize: 8 });
    }
    if op == 0x05 + 8 * reg {
        return tail(b, iz, 1 + iz).map(|v| Imm { value: v, opsize: size });
    }
    let modrm = ModRm::of(*b.get(1)?);
    if modrm.reg != reg {
        return None;
    }
    match op {
        0x80 => tail(b, 1, 3).map(|v| Imm { value: v, opsize: 8 }),
        0x81 => tail(b, iz, 2 + iz).map(|v| Imm { value: v, opsize: size }),
        0x83 => tail(b, 1, 3).map(|v| Imm { value: (v as u8 as i8 as i64 as u64) & ((1u64 << size) - 1), opsize: size }),
        _ => None,
    }
}

/// `TEST r/m8, r8 = 84 /r` and `TEST r/m32, r32 = 85 /r` with `mod` = 11 and `reg` = `rm` — a
/// register tested against itself, the compare against zero. The register number and the operand
/// size (8, or 16 under `66`, else 32).
pub fn test_rr(bytes: &[u8]) -> Option<(u8, u32)> {
    let p = prefixes(bytes);
    let b = &bytes[p.len..];
    match b {
        [0x84, m] | [0x85, m] => {
            let modrm = ModRm::of(*m);
            (modrm.is_register_direct() && modrm.reg == modrm.rm)
                .then(|| (modrm.reg, if b[0] == 0x84 { 8 } else { opsize(&p) }))
        }
        _ => None,
    }
}

/// The shift/rotate group (`/reg` of `C0/C1/D0/D1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shift {
    Rol,
    Ror,
    Rcl,
    Rcr,
    Shl,
    Shr,
    Sal,
    Sar,
}

const SHIFTS: [Shift; 8] = [Shift::Rol, Shift::Ror, Shift::Rcl, Shift::Rcr, Shift::Shl, Shift::Shr, Shift::Sal, Shift::Sar];

/// A shift of the group-2 form, with the operand size the opcode selects.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShiftImm {
    pub kind: Shift,
    pub count: u8,
    pub modrm: ModRm,
    /// 8 for `C0`/`D0`; 16 under `66`, else 32 for `C1`/`D1`.
    pub opsize: u32,
}

/// The shift group by an immediate count — `SAR r/m32, imm8 = C1 /7 ib` (`C0 /7 ib` byte-sized) —
/// or by one — `SAR r/m32, 1 = D1 /7` (`D0 /7`); `/reg` selects ROL ROR RCL RCR SHL SHR SAL SAR.
/// The kind, the count, the ModRM (a witness checks `is_register_direct`) and the operand size.
pub fn shift_imm(bytes: &[u8]) -> Option<ShiftImm> {
    let p = prefixes(bytes);
    let b = &bytes[p.len..];
    let op = *b.first()?;
    let modrm = ModRm::of(*b.get(1)?);
    let kind = SHIFTS[modrm.reg as usize];
    let size = if op & 1 == 0 { 8 } else { opsize(&p) };
    match op {
        0xc0 | 0xc1 => tail(b, 1, 3).map(|v| ShiftImm { kind, count: v as u8, modrm, opsize: size }),
        0xd0 | 0xd1 => Some(ShiftImm { kind, count: 1, modrm, opsize: size }),
        _ => None,
    }
}

/// `SBB r/m32, r32 = 19 /r` or `SBB r32, r/m32 = 1B /r` as the FIRST byte — the bare dword forms
/// Watcom's signed power-of-two division template emits before its `SAR`; a prefixed `SBB`
/// (`66 19` = the word form) is not the template.
pub fn is_sbb_rr(bytes: &[u8]) -> bool {
    matches!(bytes.first(), Some(0x19 | 0x1b))
}

/// The string instructions: `MOVS = A4/A5`, `CMPS = A6/A7`, `STOS = AA/AB`, `LODS = AC/AD`,
/// `SCAS = AE/AF` (the even opcode is the byte form, the odd one the word/dword form).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringOp {
    Movs,
    Cmps,
    Stos,
    Lods,
    Scas,
}

/// One string instruction with its element size (1, 2 under `66`, else 4) and its prefixes
/// (`rep`/`repne` for the `F3`/`F2`; the whole set in `prefixes`, so a witness can require the
/// REP to be the only one).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StringInsn {
    pub op: StringOp,
    pub elem: u32,
    pub rep: bool,
    pub repne: bool,
    pub prefixes: Prefixes,
}

/// The string instruction `bytes` encode, with its element size (1 for the even opcode; 2 under
/// `66`, else 4 for the odd one) and its `F3`/`F2` prefixes; `None` unless the opcode is the last
/// byte.
pub fn string_insn(bytes: &[u8]) -> Option<StringInsn> {
    let p = prefixes(bytes);
    let b = &bytes[p.len..];
    let [op] = b else { return None };
    let kind = match op {
        0xa4 | 0xa5 => StringOp::Movs,
        0xa6 | 0xa7 => StringOp::Cmps,
        0xaa | 0xab => StringOp::Stos,
        0xac | 0xad => StringOp::Lods,
        0xae | 0xaf => StringOp::Scas,
        _ => return None,
    };
    let elem = if op & 1 == 0 { 1 } else { opsize(&p) / 8 };
    Some(StringInsn { op: kind, elem, rep: p.rep, repne: p.repne, prefixes: p })
}

/// A PLAIN `MOVSD` — the one-byte `A5`, no REP, no operand-size prefix: Watcom's struct assignment
/// at or below its unroll threshold is a run of these.
pub fn is_plain_movsd(bytes: &[u8]) -> bool {
    bytes == [0xa5]
}

/// `PUSH r32 = 50+rd`, the one-byte form; a prefixed form (`66 50+rw` = `PUSH r16`) is not one.
pub fn push_r32(bytes: &[u8]) -> Option<u8> {
    match bytes {
        [op] if (0x50..=0x57).contains(op) => Some(op - 0x50),
        _ => None,
    }
}

/// The frame a prologue opens with a bare `SUB ESP, imm`: `SUB r/m32, imm8 = 83 /5 ib` with ModRM
/// `EC` (`mod` 11, `/5`, `rm` = ESP) or `SUB r/m32, imm32 = 81 /5 id` with ModRM `EC`, no prefix
/// (the raw `83 EC` / `81 EC` match the frame witness had). The `ib` is sign-extended like any imm8
/// — no behavior change in practice: a positive frame of 0x80 or more is always encoded
/// `81 EC id`, so `83 EC ib` only ever carries 0..0x7f.
pub fn sub_esp_imm(bytes: &[u8]) -> Option<u32> {
    if bytes.get(1) != Some(&0xec) || prefixes(bytes).len != 0 {
        return None;
    }
    alu_imm(bytes, 5).filter(|i| i.opsize == 32).map(|i| i.value as u32)
}
