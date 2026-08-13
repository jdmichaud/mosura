//! Normalized instructions: the unit the aligner compares.
//!
//! Two instruction streams cannot be compared as text (arch-specific, and a register rename
//! changes every column) nor as bytes (one inserted byte desynchronizes the rest — which is
//! exactly why the byte-percentage instrument reported 3% on functions that were structurally
//! almost right). What survives both problems is the **lifted p-code**: it is produced by the
//! same SLEIGH engine for every architecture, it names registers and sizes explicitly, and it
//! is unaffected by encoding choices.
//!
//! So each instruction carries three keys, from most to least strict:
//!
//! | key | equal when | a difference means |
//! | --- | --- | --- |
//! | bytes | identical encoding | — |
//! | [`NormInsn::sem`] | identical semantics | encoding choice only (`8b ec` vs `89 e5`) |
//! | [`NormInsn::shape`] | identical semantics up to which registers and constants | register allocation / immediate |
//!
//! `unique`-space offsets are renumbered per instruction: the lifter allocates them from a
//! running counter, so the same instruction lifted at two different addresses would otherwise
//! carry different temporaries and never compare equal.

use crate::sleigh::pcode::{PArg, PcodeOp, Varnode};
use crate::sleigh::Instruction;
use std::collections::HashMap;

/// Resolves the placeholder operands a not-yet-linked object carries.
///
/// A one-function translation unit cannot know where its callees and globals will live, so the
/// compiler writes a placeholder and records a fixup. Comparing those placeholders against the
/// original's resolved addresses would report a divergence at every call and every global — the
/// failure that made 2377 of 3023 WAR2 functions structurally unmatchable under byte comparison.
///
/// The honest repair is not to mask those bytes but to **resolve them**: ask what address the
/// fixup's symbol denotes, substitute it, and let a wrong target stay a real difference. The
/// scope is per instruction, so a placeholder value that also occurs as a genuine constant
/// elsewhere in the function is not rewritten by accident.
pub trait Relocator {
    /// Value this operand takes once linked at the original's addresses, or `None` to keep it.
    ///
    /// `insn_addr`/`insn_len` bound the instruction the operand was decoded from; `value` is the
    /// decoded operand (already absolute for pc-relative branch targets) and `size` its width.
    fn resolve(&self, insn_addr: u64, insn_len: usize, value: u64, size: u32) -> Option<u64>;
}

/// The identity relocator — for the original side, which is already linked.
pub struct NoReloc;
impl Relocator for NoReloc {
    fn resolve(&self, _: u64, _: usize, _: u64, _: u32) -> Option<u64> {
        None
    }
}

/// A p-code operand, canonicalized for comparison.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum SemArg {
    /// A register-space location: `(offset, size)`. Two registers are the same iff both agree,
    /// so `AL` and `EAX` (offset 0, sizes 1 and 4) stay distinct.
    Reg(u64, u32),
    /// A constant. Branch/call targets are *not* constants here — see [`NormInsn::target`].
    Const(u64, u32),
    /// A memory location in a real address space (absolute operands).
    Mem(String, u64, u32),
    /// A lifter temporary, renumbered per instruction in order of first appearance.
    Temp(u32, u32),
    /// The address-space operand of LOAD/STORE.
    Space(String),
    /// The branch/call destination, held out of the comparison keys because it is a function of
    /// code layout: it differs whenever anything before it changed size, which would make every
    /// branch in a shifted function look like a divergence. Verified separately, after the
    /// alignment establishes which instruction the original's target corresponds to.
    Target,
}

/// One canonicalized p-code operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SemOp {
    pub opcode: u32,
    pub out: Option<SemArg>,
    pub ins: Vec<SemArg>,
}

/// An instruction, normalized for comparison.
#[derive(Debug, Clone)]
pub struct NormInsn {
    pub addr: u64,
    pub bytes: Vec<u8>,
    /// Human-readable form, for reports only — never compared.
    pub text: String,
    pub mnemonic: String,
    /// Canonical semantics: equality means the two instructions compute the same thing.
    pub sem: Vec<SemOp>,
    /// Semantics with registers and constants erased to positional placeholders: equality means
    /// the two instructions do the same *kind* of thing, differing only in allocation/immediates.
    pub shape: Vec<SemOp>,
    /// Register-space operands in order of first appearance (offset, size).
    pub regs: Vec<(u64, u32)>,
    /// Constant operands in order of first appearance, branch targets excluded.
    pub consts: Vec<u64>,
    /// Branch/call destination, if this instruction has one.
    pub target: Option<u64>,
    /// True when this instruction transfers control (its `target` is layout-dependent).
    pub is_branch: bool,
    pub is_call: bool,
    /// The **encoding form**: the instruction's bytes with every operand-value bit cleared, so
    /// only the opcode and addressing-mode bits chosen by the encoder remain. Two spellings of
    /// one operation (`8b ec` and `89 e5` for `MOV EBP,ESP`) have different forms; the same
    /// spelling with other registers has the same form. Paired with [`Self::shape`] this is what
    /// a compiler's instruction-selection vocabulary is made of.
    pub form: Vec<u8>,
}

impl NormInsn {
    /// True when this instruction leaves every architectural location holding what it already
    /// held — a no-op, however it is spelled.
    ///
    /// Padding cannot be recognized by mnemonic: Watcom pads with `LEA EAX,[EAX]` and
    /// `XCHG EBX,EBX`, Microsoft with `NOP` and `XCHG AX,AX`, and each lifts differently
    /// (`XCHG r,r` becomes a three-COPY round trip through a temporary). Deciding it on the
    /// lifted semantics instead covers every spelling, including ones nobody has enumerated,
    /// and stays correct on architectures whose padding we have never seen.
    ///
    /// The evaluation is a symbolic COPY-propagation: each location starts holding itself, COPYs
    /// move those values around, and the instruction is a no-op iff every non-temporary location
    /// ends holding its own initial value. Any op that is not a COPY can have an effect, so it
    /// disqualifies immediately.
    pub fn is_nop(&self) -> bool {
        let mut state: Vec<(SemArg, SemArg)> = Vec::new();
        let get = |state: &Vec<(SemArg, SemArg)>, k: &SemArg| -> SemArg {
            state.iter().find(|(a, _)| a == k).map(|(_, v)| v.clone()).unwrap_or_else(|| k.clone())
        };
        for op in &self.sem {
            if op.opcode != CPUI_COPY {
                return false;
            }
            let (Some(out), Some(src)) = (op.out.as_ref(), op.ins.first()) else { return false };
            let val = get(&state, src);
            match state.iter_mut().find(|(a, _)| a == out) {
                Some(slot) => slot.1 = val,
                None => state.push((out.clone(), val)),
            }
        }
        state.iter().all(|(loc, val)| matches!(loc, SemArg::Temp(..)) || loc == val)
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
    /// End address (exclusive).
    pub fn end(&self) -> u64 {
        self.addr + self.bytes.len() as u64
    }
}

// CPUI opcodes we must recognize structurally. Kept as constants rather than a dependency on the
// decompiler's `OpCode` enum so this module needs only the lifter.
const CPUI_COPY: u32 = 1;
const CPUI_BRANCH: u32 = 4;
const CPUI_CBRANCH: u32 = 5;
const CPUI_BRANCHIND: u32 = 6;
const CPUI_CALL: u32 = 7;
const CPUI_CALLIND: u32 = 8;

fn is_branchish(opcode: u32) -> bool {
    matches!(opcode, CPUI_BRANCH | CPUI_CBRANCH | CPUI_BRANCHIND | CPUI_CALL | CPUI_CALLIND)
}

/// Normalize one lifted instruction.
///
/// `reloc` is the relocation hook (see [`Relocator`]): it rewrites the placeholder operands an
/// unlinked object carries into the addresses they will hold once linked, which is what makes
/// the two sides comparable at all.
pub fn normalize_one(insn: &Instruction, reloc: &dyn Relocator) -> NormInsn {
    normalize_one_with_mask(insn, reloc, None)
}

/// As [`normalize_one`], with the instruction mask supplied by the caller (from
/// [`crate::sleigh::disassemble_fingerprint`]) so [`NormInsn::form`] can be filled in.
pub fn normalize_one_with_mask(
    insn: &Instruction,
    reloc: &dyn Relocator,
    mask: Option<&[u8]>,
) -> NormInsn {
    let ilen = insn.bytes.len();
    let resolve_const = |v: u64, sz: u32| reloc.resolve(insn.address, ilen, v, sz);
    let mut temps: HashMap<u64, u32> = HashMap::new();
    let mut regs: Vec<(u64, u32)> = Vec::new();
    let mut consts: Vec<u64> = Vec::new();
    let mut target: Option<u64> = None;

    // The destination of a branch/call is the *first* input of the branch op when it lives in a
    // real address space; an indirect branch's input is a computed value and stays a normal
    // operand.
    let mut target_arg: Option<(usize, usize)> = None; // (op index, input index)
    for (oi, op) in insn.ops.iter().enumerate() {
        if is_branchish(op.opcode) {
            if let Some(PArg::Var(v)) = op.ins.first() {
                if !v.is_const() && v.space != "register" && v.space != "unique" {
                    target_arg = Some((oi, 0));
                    target = Some(v.offset);
                }
            }
        }
    }

    let mut conv = |v: &Varnode, is_target: bool, temps: &mut HashMap<u64, u32>| -> SemArg {
        if is_target {
            return SemArg::Target;
        }
        match v.space.as_str() {
            "unique" => {
                let n = temps.len() as u32;
                let id = *temps.entry(v.offset).or_insert(n);
                SemArg::Temp(id, v.size)
            }
            "register" => {
                let key = (v.offset, v.size);
                if !regs.contains(&key) {
                    regs.push(key);
                }
                SemArg::Reg(v.offset, v.size)
            }
            "const" => {
                let val = resolve_const(v.offset, v.size).unwrap_or(v.offset);
                if !consts.contains(&val) {
                    consts.push(val);
                }
                SemArg::Const(val, v.size)
            }
            other => {
                let val = resolve_const(v.offset, v.size).unwrap_or(v.offset);
                SemArg::Mem(other.to_string(), val, v.size)
            }
        }
    };

    let mut sem = Vec::with_capacity(insn.ops.len());
    for (oi, op) in insn.ops.iter().enumerate() {
        let out = op.out.as_ref().map(|v| conv(v, false, &mut temps));
        let mut ins = Vec::with_capacity(op.ins.len());
        for (ii, a) in op.ins.iter().enumerate() {
            ins.push(match a {
                PArg::Space(s) => SemArg::Space(s.clone()),
                PArg::Var(v) => conv(v, target_arg == Some((oi, ii)), &mut temps),
            });
        }
        sem.push(SemOp { opcode: op.opcode, out, ins });
    }

    // The shape key: erase *which* register and *which* constant, keep that there is one, in
    // positional order. `EAX` vs `ESI` and `+4` vs `+8` collapse to the same shape; a different
    // operation, a different operand count, or an operand becoming memory does not.
    let shape = sem
        .iter()
        .map(|op| SemOp {
            opcode: op.opcode,
            out: op.out.as_ref().map(erase),
            ins: op.ins.iter().map(erase).collect(),
        })
        .collect();

    let is_branch = insn.ops.iter().any(|o| matches!(o.opcode, CPUI_BRANCH | CPUI_CBRANCH | CPUI_BRANCHIND));
    let is_call = insn.ops.iter().any(|o| matches!(o.opcode, CPUI_CALL | CPUI_CALLIND));
    // A resolved relocation renames the target too: an unlinked `call rel32` points at itself.
    if let Some(t) = target {
        target = Some(resolve_const(t, 4).unwrap_or(t));
    }

    NormInsn {
        addr: insn.address,
        bytes: insn.bytes.clone(),
        text: if insn.body.is_empty() {
            insn.mnemonic.clone()
        } else {
            format!("{} {}", insn.mnemonic, insn.body)
        },
        mnemonic: insn.mnemonic.clone(),
        sem,
        shape,
        regs,
        consts,
        target,
        is_branch,
        is_call,
        form: match mask {
            Some(m) => insn.bytes.iter().zip(m.iter()).map(|(b, m)| b & m).collect(),
            None => insn.bytes.clone(),
        },
    }
}

fn erase(a: &SemArg) -> SemArg {
    match a {
        SemArg::Reg(_, sz) => SemArg::Reg(u64::MAX, *sz),
        SemArg::Const(_, sz) => SemArg::Const(u64::MAX, *sz),
        SemArg::Mem(sp, _, sz) => SemArg::Mem(sp.clone(), u64::MAX, *sz),
        other => other.clone(),
    }
}

/// Disassemble a byte range and normalize every instruction in it.
///
/// Decoding stops at the first byte that does not decode, or at `bytes.len()`. A truncated
/// stream is reported by the returned instruction coverage, not by an error: a candidate whose
/// tail fails to decode is itself a finding.
pub fn normalize(
    lang_id: &str,
    bytes: &[u8],
    base: u64,
    reloc: &dyn Relocator,
) -> Result<Vec<NormInsn>, crate::Unimplemented> {
    let insns = crate::sleigh::disassemble(lang_id, bytes, base)?;
    // The fingerprints are for exactly these instructions at these addresses, so the two lists
    // are zipped positionally rather than re-derived.
    let fps = crate::sleigh::disassemble_fingerprint(lang_id, bytes, base)?;
    Ok(insns
        .iter()
        .enumerate()
        .map(|(i, x)| normalize_one_with_mask(x, reloc, fps.get(i).map(|f| f.instruction_mask.as_slice())))
        .collect())
}

/// Render a p-code op sequence for reports.
pub fn render_sem(ops: &[PcodeOp]) -> String {
    ops.iter().map(|o| o.render()).collect::<Vec<_>>().join("; ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lift(hex: &str) -> Vec<NormInsn> {
        let bytes: Vec<u8> = (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        normalize("x86:LE:32:default", &bytes, 0x1000, &NoReloc).expect("language tables")
    }

    /// Every padding spelling Watcom and Microsoft emit is a no-op, whatever it lifts to —
    /// `XCHG r,r` goes through a temporary and `NOP` lifts to nothing at all.
    #[test]
    fn recognizes_padding_by_semantics_not_mnemonic() {
        // xchg ebx,ebx / xchg ecx,ecx / lea eax,[eax] (two encodings) / nop / mov esi,esi
        for i in lift("87db87c98d40008d4420009089f6") {
            assert!(i.is_nop(), "expected no-op: {} ({:02x?})", i.text, i.bytes);
        }
    }

    /// …and an instruction that does something is not padding, including the near misses: a LEA
    /// with a real displacement, and an XCHG of two different registers.
    #[test]
    fn real_work_is_not_padding() {
        // lea eax,[eax+1] / xchg ebx,ecx / mov eax,ebx / add eax,eax
        for i in lift("8d40018bd98bc301c0") {
            assert!(!i.is_nop(), "expected real work: {} ({:02x?})", i.text, i.bytes);
        }
    }

    /// The semantic key ignores encoding: the two encodings of `mov ebp,esp` differ in bytes and
    /// agree in p-code, which is exactly the distinction the `encoding` class rests on.
    #[test]
    fn same_semantics_different_encoding() {
        let a = lift("8bec"); // mov ebp,esp  (r32, r/m32)
        let b = lift("89e5"); // mov ebp,esp  (r/m32, r32)
        assert_eq!(a[0].sem, b[0].sem, "{} vs {}", a[0].text, b[0].text);
        assert_ne!(a[0].bytes, b[0].bytes);
    }

    /// The shape key ignores *which* register and *which* constant, and nothing else.
    #[test]
    fn shape_erases_allocation_but_not_operation() {
        let a = lift("83c001"); // add eax,1
        let b = lift("83c302"); // add ebx,2
        let c = lift("83e801"); // sub eax,1
        assert_eq!(a[0].shape, b[0].shape);
        assert_ne!(a[0].sem, b[0].sem);
        assert_ne!(a[0].shape, c[0].shape);
    }

    /// A branch's destination is layout-dependent, so it is held out of the comparison keys:
    /// two jumps of the same kind to different places compare equal on `sem` and are separated
    /// afterwards by target verification, not by their operands.
    #[test]
    fn branch_target_is_not_part_of_the_key() {
        let a = lift("eb10");
        let b = lift("eb20");
        assert_eq!(a[0].sem, b[0].sem);
        assert_ne!(a[0].target, b[0].target);
    }
}
