//! Aligning two instruction streams, and naming why they differ.
//!
//! The question this answers is not "how many bytes agree" but "what would have to change for
//! them to agree". A byte comparison cannot answer that: insert one byte and every later byte
//! disagrees, so a function that is one register-allocation choice away from exact and a function
//! written in hand assembler both score near zero. That is the state the WAR2 census was in —
//! 2074 of 2552 mismatches under 25% byte agreement, and 96% of them attributed to
//! "unclassified".
//!
//! So the two streams are aligned first (Needleman–Wunsch over the normalized instructions from
//! [`super::insn`]), and only then is each aligned pair classified. Alignment absorbs the
//! insertions and deletions that desynchronize byte comparison, leaving divergences that are
//! individually meaningful:
//!
//! - [`DivergenceClass::Encoding`] — identical semantics, different bytes. The compiler picked
//!   the other encoding of the same instruction. Reachable only by changing compiler or flags.
//! - [`DivergenceClass::RegisterAlloc`] — identical operation, different registers. A codegen
//!   choice; reachable by changing the C we emit, since allocation follows source structure.
//! - [`DivergenceClass::Immediate`] / [`DivergenceClass::OperandForm`] — same operation, different
//!   constant or operand shape. Usually a type-recovery or stack-layout difference: ours.
//! - [`DivergenceClass::Selection`] — a different instruction entirely.
//! - [`DivergenceClass::Extra`] / [`DivergenceClass::Missing`] — a computation one side has and
//!   the other does not. **Missing is a wrong-code bug**: the emitted C does less than the
//!   original. It has to be separated from everything else, and byte comparison never could.
//! - [`DivergenceClass::BranchTarget`] — the streams align but a branch goes somewhere else.

use super::insn::NormInsn;
use std::collections::BTreeMap;

/// Why one aligned pair of instructions differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DivergenceClass {
    /// Same semantics, same bytes.
    Equal,
    /// Same semantics, different bytes: the other encoding of the same instruction.
    Encoding,
    /// Same operation and constants, different registers.
    RegisterAlloc,
    /// Same operation and registers, different constant.
    Immediate,
    /// Same operation, but both registers and constants differ, or the operand form changed
    /// (register where the other has memory, a different displacement base).
    OperandForm,
    /// A different instruction.
    Selection,
    /// The candidate computes something the original does not.
    Extra,
    /// The original computes something the candidate does not — the candidate does *less*.
    Missing,
    /// Aligned, same instruction, but the control transfer lands somewhere else.
    BranchTarget,
    /// Same semantics, same encoding form, different bytes: the instruction sits at a different
    /// address, so a layout-dependent operand — a branch displacement, a pushed return address —
    /// encodes differently.
    ///
    /// **This is a consequence, never a cause.** Something upstream changed size, and that change
    /// is reported where it happened; this row only records that the shift propagated here.
    /// Counting it as [`DivergenceClass::Encoding`] said the opposite — `encoding` means "not
    /// reachable from C, do not work on this function" — and would have written 109 WAR2 functions
    /// off the work-list for a difference that is entirely downstream of a fixable one.
    LayoutShift,
}

impl DivergenceClass {
    pub fn as_str(self) -> &'static str {
        match self {
            DivergenceClass::Equal => "equal",
            DivergenceClass::Encoding => "encoding",
            DivergenceClass::RegisterAlloc => "regalloc",
            DivergenceClass::Immediate => "immediate",
            DivergenceClass::OperandForm => "operand-form",
            DivergenceClass::Selection => "selection",
            DivergenceClass::Extra => "extra",
            DivergenceClass::Missing => "missing",
            DivergenceClass::BranchTarget => "branch-target",
            DivergenceClass::LayoutShift => "layout-shift",
        }
    }
    /// True for classes that mean the candidate does not compute what the original computes —
    /// as opposed to computing it differently. These are correctness defects, not form defects.
    pub fn is_semantic(self) -> bool {
        matches!(self, DivergenceClass::Missing | DivergenceClass::Extra | DivergenceClass::BranchTarget)
    }

    /// True when a row of this class exists only because some *other* divergence exists. Derived
    /// rows are excluded from the dominant cause, because a work-list headed by a consequence
    /// sends the work to the wrong place.
    pub fn is_derived(self) -> bool {
        matches!(self, DivergenceClass::LayoutShift)
    }
}

/// One step of the alignment script.
#[derive(Debug, Clone)]
pub enum AlignOp {
    /// Original instruction `oi` corresponds to candidate instruction `ci`.
    Pair { oi: usize, ci: usize, class: DivergenceClass },
    /// The original has an instruction with no counterpart.
    OrigOnly { oi: usize },
    /// The candidate has an instruction with no counterpart.
    CandOnly { ci: usize },
}

/// A single attributed difference, in reportable form.
#[derive(Debug, Clone)]
pub struct Divergence {
    pub class: DivergenceClass,
    /// Address in the original's coordinate system.
    pub addr: u64,
    pub orig: Option<String>,
    pub cand: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Byte-identical once the candidate is linked at the original's addresses.
    Exact,
    /// Every instruction agrees semantically; only encodings differ. The compiler produced the
    /// same program, spelled differently — no C change can close this, only flags or compiler.
    SameCode,
    /// Aligned, and every difference is a codegen-form choice (registers, immediates, selection)
    /// with nothing missing or extra: the candidate computes the same thing, differently.
    SameShape,
    /// The candidate computes something different from the original.
    Mismatch,
}

impl Verdict {
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Exact => "EXACT",
            Verdict::SameCode => "SAME_CODE",
            Verdict::SameShape => "SAME_SHAPE",
            Verdict::Mismatch => "MISMATCH",
        }
    }
}

/// The result of comparing one function.
#[derive(Debug, Clone)]
pub struct FnDiff {
    pub verdict: Verdict,
    pub orig_insns: usize,
    pub cand_insns: usize,
    pub orig_bytes: usize,
    pub cand_bytes: usize,
    /// Aligned pairs that are byte-identical.
    pub equal_insns: usize,
    pub ops: Vec<AlignOp>,
    pub divergences: Vec<Divergence>,
    pub class_counts: BTreeMap<DivergenceClass, usize>,
    /// The dominant non-equal class, which is what a census should group on.
    pub primary: Option<DivergenceClass>,
    /// Register substitution observed across the whole function, when consistent: reading it as
    /// a map says "the same program, allocated differently", which is a different problem from
    /// registers differing at random.
    pub reg_subst: Vec<((u64, u32), (u64, u32))>,
    pub reg_subst_consistent: bool,
    /// Fraction of instructions that aligned and agreed, over the larger stream. Unlike a byte
    /// percentage this degrades smoothly: one extra instruction costs one instruction.
    ///
    /// **Structural fidelity**: a [`DivergenceClass::LayoutShift`] pair counts as agreement. It is
    /// the same instruction with the same logical target, differing only in a value that is a
    /// function of where the code sits — so one inserted instruction upstream would otherwise be
    /// charged again for every later call's return address and every later branch displacement in
    /// the function. The comparison key already holds those two operands out for exactly this
    /// reason ([`super::insn::SemArg::PcRef`] records that keeping one of them cost 5741 spurious
    /// rows across 1722 functions); this extends the same decision from the key to the score.
    ///
    /// This is NOT byte fidelity and does not move the byte-exact verdict: a layout-shifted
    /// function is not byte-identical and stays [`Verdict::SameCode`], never [`Verdict::Exact`].
    /// Use [`Self::byte_similarity`] for the strict measure.
    pub similarity: f64,
    /// Fraction of instructions that aligned and agreed **byte-for-byte** — the strict measure,
    /// which charges a layout shift like any other difference. Kept alongside
    /// [`Self::similarity`] so both fidelities stay visible in one pass.
    pub byte_similarity: f64,
}

const GAP: u32 = 7;

fn sub_cost(a: &NormInsn, b: &NormInsn) -> (u32, DivergenceClass) {
    if a.sem == b.sem {
        if a.bytes == b.bytes {
            return (0, DivergenceClass::Equal);
        }
        // Same semantics AND the same encoding form. `form` is the bytes with every operand-value
        // bit cleared, and `sem` equality already established that every operand in the key
        // agrees — so the bytes can only differ in an operand the key deliberately holds out,
        // which is the layout-dependent one. The instruction moved; it did not change.
        if a.form == b.form {
            return (1, DivergenceClass::LayoutShift);
        }
        return (1, DivergenceClass::Encoding);
    }
    if a.shape == b.shape && a.mnemonic == b.mnemonic {
        let regs_differ = a.regs != b.regs;
        let consts_differ = a.consts != b.consts;
        return match (regs_differ, consts_differ) {
            (true, false) => (3, DivergenceClass::RegisterAlloc),
            (false, true) => (3, DivergenceClass::Immediate),
            _ => (4, DivergenceClass::OperandForm),
        };
    }
    if a.mnemonic == b.mnemonic {
        return (6, DivergenceClass::OperandForm);
    }
    (9, DivergenceClass::Selection)
}

/// Align and attribute. `orig` and `cand` must already be in the same address coordinate system
/// (see [`super::candidate`]).
pub fn compare(orig: &[NormInsn], cand: &[NormInsn]) -> FnDiff {
    let (n, m) = (orig.len(), cand.len());
    // Needleman–Wunsch. n*m stays small — the largest WAR2 function is ~1500 instructions, so
    // the table is a few million cells at worst and the whole census runs in seconds.
    let mut dp = vec![u32::MAX; (n + 1) * (m + 1)];
    let idx = |i: usize, j: usize| i * (m + 1) + j;
    dp[idx(0, 0)] = 0;
    for i in 1..=n {
        dp[idx(i, 0)] = i as u32 * GAP;
    }
    for j in 1..=m {
        dp[idx(0, j)] = j as u32 * GAP;
    }
    for i in 1..=n {
        for j in 1..=m {
            let (c, _) = sub_cost(&orig[i - 1], &cand[j - 1]);
            let best = (dp[idx(i - 1, j - 1)].saturating_add(c))
                .min(dp[idx(i - 1, j)].saturating_add(GAP))
                .min(dp[idx(i, j - 1)].saturating_add(GAP));
            dp[idx(i, j)] = best;
        }
    }

    // Trace back, preferring the diagonal on ties so a pair that merely differs is reported as a
    // difference rather than as an unrelated deletion plus insertion.
    let mut ops = Vec::new();
    let (mut i, mut j) = (n, m);
    while i > 0 || j > 0 {
        if i > 0 && j > 0 {
            let (c, class) = sub_cost(&orig[i - 1], &cand[j - 1]);
            if dp[idx(i, j)] == dp[idx(i - 1, j - 1)].saturating_add(c) {
                ops.push(AlignOp::Pair { oi: i - 1, ci: j - 1, class });
                i -= 1;
                j -= 1;
                continue;
            }
        }
        if i > 0 && dp[idx(i, j)] == dp[idx(i - 1, j)].saturating_add(GAP) {
            ops.push(AlignOp::OrigOnly { oi: i - 1 });
            i -= 1;
            continue;
        }
        ops.push(AlignOp::CandOnly { ci: j - 1 });
        j -= 1;
    }
    ops.reverse();

    // Branch targets: the streams are aligned, so the original's target names an original
    // instruction, and the candidate's must name the instruction aligned with it. A branch that
    // survives alignment but lands elsewhere is a control-flow defect, and it is invisible to
    // any comparison that masks layout-dependent operands.
    let mut orig_to_cand: BTreeMap<usize, usize> = BTreeMap::new();
    for op in &ops {
        if let AlignOp::Pair { oi, ci, .. } = op {
            orig_to_cand.insert(*oi, *ci);
        }
    }
    let orig_at: BTreeMap<u64, usize> = orig.iter().enumerate().map(|(k, x)| (x.addr, k)).collect();
    let cand_at: BTreeMap<u64, usize> = cand.iter().enumerate().map(|(k, x)| (x.addr, k)).collect();
    let mut ops = ops;
    for op in ops.iter_mut() {
        let AlignOp::Pair { oi, ci, class } = op else { continue };
        // Only pairs that are the same instruction are worth asking "does it still go to the
        // same place" — and a layout shift is exactly that: the same instruction, moved. Omitting
        // it here would let a jump to the WRONG place hide behind "it only moved", which is the
        // one thing this check exists to prevent.
        if !matches!(
            *class,
            DivergenceClass::Equal | DivergenceClass::Encoding | DivergenceClass::LayoutShift
        ) {
            continue;
        }
        let (o, c) = (&orig[*oi], &cand[*ci]);
        let (Some(ot), Some(ct)) = (o.target, c.target) else { continue };
        if o.is_call || c.is_call {
            // A call's target is an address in both coordinate systems once relinked, so it is
            // compared directly rather than through the alignment.
            if ot != ct {
                *class = DivergenceClass::BranchTarget;
            }
            continue;
        }
        match (orig_at.get(&ot), cand_at.get(&ct)) {
            (Some(oi_t), Some(ci_t)) => {
                if orig_to_cand.get(oi_t) != Some(ci_t) {
                    *class = DivergenceClass::BranchTarget;
                }
            }
            // A target outside its own function (a tail call, a jump into a neighbour) is
            // compared as a plain address.
            _ => {
                if ot != ct {
                    *class = DivergenceClass::BranchTarget;
                }
            }
        }
    }

    let mut class_counts: BTreeMap<DivergenceClass, usize> = BTreeMap::new();
    let mut divergences = Vec::new();
    let mut equal_insns = 0usize;
    let mut subst: Vec<((u64, u32), (u64, u32))> = Vec::new();
    let mut subst_consistent = true;
    for op in &ops {
        match op {
            AlignOp::Pair { oi, ci, class } => {
                *class_counts.entry(*class).or_default() += 1;
                if *class == DivergenceClass::Equal {
                    equal_insns += 1;
                } else {
                    divergences.push(Divergence {
                        class: *class,
                        addr: orig[*oi].addr,
                        orig: Some(orig[*oi].text.clone()),
                        cand: Some(cand[*ci].text.clone()),
                    });
                }
                if *class == DivergenceClass::RegisterAlloc {
                    let (o, c) = (&orig[*oi], &cand[*ci]);
                    for (a, b) in o.regs.iter().zip(c.regs.iter()) {
                        if a == b {
                            continue;
                        }
                        if let Some((_, prev)) = subst.iter().find(|(x, _)| x == a) {
                            if prev != b {
                                subst_consistent = false;
                            }
                        } else {
                            subst.push((*a, *b));
                        }
                    }
                }
            }
            AlignOp::OrigOnly { oi } => {
                *class_counts.entry(DivergenceClass::Missing).or_default() += 1;
                divergences.push(Divergence {
                    class: DivergenceClass::Missing,
                    addr: orig[*oi].addr,
                    orig: Some(orig[*oi].text.clone()),
                    cand: None,
                });
            }
            AlignOp::CandOnly { ci } => {
                *class_counts.entry(DivergenceClass::Extra).or_default() += 1;
                divergences.push(Divergence {
                    class: DivergenceClass::Extra,
                    addr: cand[*ci].addr,
                    orig: None,
                    cand: Some(cand[*ci].text.clone()),
                });
            }
        }
    }

    let primary = class_counts
        .iter()
        .filter(|(c, _)| **c != DivergenceClass::Equal && !c.is_derived())
        // Rank by population, but let a semantic class win a tie: "one instruction is missing"
        // is the finding, even alongside three register differences.
        .max_by_key(|(c, n)| (**n, c.is_semantic()))
        .map(|(c, _)| *c);

    let verdict = if divergences.is_empty() {
        Verdict::Exact
    } else if divergences
        .iter()
        .all(|d| matches!(d.class, DivergenceClass::Encoding | DivergenceClass::LayoutShift))
    {
        Verdict::SameCode
    } else if divergences.iter().all(|d| !d.class.is_semantic()) {
        Verdict::SameShape
    } else {
        Verdict::Mismatch
    };

    let denom = n.max(m).max(1) as f64;
    // A layout shift is the same instruction at a different position: `sem` equality has already
    // established that every operand outside `SemArg::Target`/`SemArg::PcRef` agrees, and the
    // target check above has demoted any pair whose control transfer lands somewhere else. What
    // remains differs only in a value that is a function of where the code sits.
    let shifted = class_counts.get(&DivergenceClass::LayoutShift).copied().unwrap_or(0);
    FnDiff {
        verdict,
        orig_insns: n,
        cand_insns: m,
        orig_bytes: orig.iter().map(|x| x.len()).sum(),
        cand_bytes: cand.iter().map(|x| x.len()).sum(),
        equal_insns,
        ops,
        divergences,
        class_counts,
        primary,
        reg_subst: subst,
        reg_subst_consistent: subst_consistent,
        byte_similarity: equal_insns as f64 / denom,
        similarity: (equal_insns + shifted) as f64 / denom,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recompile::insn::{NoReloc, normalize};

    /// Lift a two-instruction stream given as separate encodings, so a test can state the pair
    /// it means rather than one concatenated hex blob.
    fn lift2(a: &str, b: &str) -> Vec<NormInsn> {
        lift1(&format!("{a}{b}"))
    }

    fn lift1(hex: &str) -> Vec<NormInsn> {
        lift1_at(hex, 0x1000)
    }

    /// Lift at a chosen address, so a test can place the same instruction somewhere else — which
    /// is the only way to produce a layout shift with nothing else differing.
    fn lift1_at(hex: &str, at: u64) -> Vec<NormInsn> {
        let bytes: Vec<u8> = (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        normalize("x86:LE:32:default", &bytes, at, &NoReloc).expect("language tables")
    }

    // push ebp; mov ebp,esp; mov eax,[ebp+8]; pop ebp; ret
    const FRAME: &str = "5589e58b45085dc3";

    #[test]
    fn identical_streams_are_exact() {
        let d = compare(&lift1(FRAME), &lift1(FRAME));
        assert_eq!(d.verdict, Verdict::Exact);
        assert!(d.divergences.is_empty());
        assert_eq!(d.similarity, 1.0);
    }

    /// The instrument must be able to FAIL. An unrelated function is not "almost exact" —
    /// this is the check that a comparison reporting EXACT means something.
    #[test]
    fn an_unrelated_function_is_a_mismatch() {
        // xor eax,eax; inc eax; ret  — nothing to do with FRAME
        let d = compare(&lift1(FRAME), &lift1("31c040c3"));
        assert_eq!(d.verdict, Verdict::Mismatch);
        assert!(d.similarity < 0.5, "similarity {} too high", d.similarity);
    }

    /// The same program in the other encoding of `mov ebp,esp` is SAME_CODE, not EXACT: the
    /// difference is real, it is just not one the emitted C can influence.
    #[test]
    fn encoding_choice_is_its_own_verdict() {
        let d = compare(&lift1(FRAME), &lift1("558bec8b45085dc3"));
        assert_eq!(d.verdict, Verdict::SameCode);
        assert_eq!(d.class_counts.get(&DivergenceClass::Encoding), Some(&1));
    }

    /// A dropped instruction reads as `missing` — the wrong-code class — and not as a form
    /// difference. Separating these two is the whole point of the taxonomy: one is our bug,
    /// the other is a codegen choice.
    #[test]
    fn a_dropped_instruction_is_missing_not_form() {
        // the same frame without the `mov eax,[ebp+8]`
        let d = compare(&lift1(FRAME), &lift1("5589e55dc3"));
        assert_eq!(d.verdict, Verdict::Mismatch);
        assert_eq!(d.class_counts.get(&DivergenceClass::Missing), Some(&1));
        assert_eq!(d.primary, Some(DivergenceClass::Missing));
    }

    /// A call that moved is not a call that changed.
    ///
    /// Both streams call `0x2000`; the candidate's `CMP EBX,-1` is one byte longer than the
    /// original's `TEST EBX,EBX`, so the call sits one byte later and its `rel32` — and the
    /// return address it pushes — encode differently. The finding is the `TEST`/`CMP` choice;
    /// the call is a consequence of it, and must not be reported as a second, independent one.
    #[test]
    fn a_call_displaced_by_an_upstream_size_change_is_derived_not_a_cause() {
        let orig = lift2("85db" /* test ebx,ebx */ , "e8f90f0000" /* call 0x2000 from 0x1002 */);
        let cand = lift2("83fbff" /* cmp ebx,-1 */ , "e8f80f0000" /* call 0x2000 from 0x1003 */);
        let d = compare(&orig, &cand);
        assert_eq!(orig[1].target, cand[1].target, "both call the same place");
        assert_eq!(d.class_counts.get(&DivergenceClass::LayoutShift), Some(&1));
        assert_eq!(
            d.primary,
            Some(DivergenceClass::Selection),
            "the dominant cause is the instruction that changed, not the one that moved"
        );
        assert!(DivergenceClass::LayoutShift.is_derived());
    }

    /// A program that only moved is the same program: with nothing but layout shifts, the verdict
    /// is SAME_CODE — no C change can close it, and none is needed.
    #[test]
    fn layout_shift_alone_reads_as_the_same_code() {
        let orig = lift2("90", "e8fa0f0000"); // nop; call 0x2000 from 0x1001
        let cand = lift2("6690", "e8f90f0000"); // 66 nop (2 bytes); call 0x2000 from 0x1002
        let d = compare(&orig, &cand);
        assert_eq!(d.verdict, Verdict::SameCode, "{:?}", d.class_counts);
    }

    /// The two fidelities on the one stream that isolates them: the SAME call to the SAME place,
    /// sitting one byte later, so a layout shift is the only divergence there is. It agrees
    /// structurally and not byte-for-byte, and the VERDICT stays `SameCode` — masking the shift in
    /// the score must never promote anything to `Exact`.
    #[test]
    fn a_layout_shift_agrees_structurally_and_not_byte_for_byte() {
        let orig = lift1_at("e8fb0f0000", 0x1000); // call 0x2000 from 0x1000
        let cand = lift1_at("e8fa0f0000", 0x1001); // call 0x2000 from 0x1001
        assert_eq!(orig[0].target, cand[0].target, "the same destination");
        assert_ne!(orig[0].bytes, cand[0].bytes, "encoded differently because it moved");
        let d = compare(&orig, &cand);
        assert_eq!(d.class_counts.get(&DivergenceClass::LayoutShift), Some(&1));
        assert_eq!(d.similarity, 1.0, "the same program, moved, agrees structurally");
        assert_eq!(d.byte_similarity, 0.0, "and agrees on no byte-identical instruction");
        assert_eq!(d.verdict, Verdict::SameCode, "still not byte-exact");
    }

    /// The masking must not reach a branch that goes somewhere else. `a_branch_to_the_wrong_place`
    /// pins the classification; this pins the SCORE, which is the number the masking changes —
    /// a wrong target is demoted to `BranchTarget` before the score is taken, so it is charged
    /// in both fidelities and neither reads as agreement.
    #[test]
    fn a_wrong_branch_target_is_charged_in_both_fidelities() {
        // jmp +2; nop; nop; ret   vs   jmp +3; nop; nop; ret — same form, different destination
        let orig = lift1("eb029090c3");
        let cand = lift1("eb039090c3");
        let d = compare(&orig, &cand);
        assert_eq!(d.class_counts.get(&DivergenceClass::BranchTarget), Some(&1));
        assert_eq!(d.class_counts.get(&DivergenceClass::LayoutShift), None);
        assert_eq!(d.similarity, d.byte_similarity, "no masking is available to it");
        assert!(d.similarity < 1.0, "similarity {} must charge the wrong target", d.similarity);
    }

    /// Different register, same program: SAME_SHAPE, and the substitution is reported as a
    /// consistent map rather than as noise.
    #[test]
    fn a_register_rename_is_shape_not_semantics() {
        // mov eax,[ebp+8] -> mov edx,[ebp+8]
        let d = compare(&lift1(FRAME), &lift1("5589e58b55085dc3"));
        assert_eq!(d.verdict, Verdict::SameShape);
        assert_eq!(d.class_counts.get(&DivergenceClass::RegisterAlloc), Some(&1));
        assert!(d.reg_subst_consistent);
        assert_eq!(d.reg_subst.len(), 1);
    }

    /// Two streams that differ only in where a jump lands must NOT compare equal. The jump's
    /// target is deliberately excluded from the comparison keys (it moves whenever code sizes
    /// change), so this is the check that excluding it did not create a blind spot.
    #[test]
    fn a_branch_to_the_wrong_place_is_caught() {
        // jmp +2; nop; nop; ret      vs      jmp +3; nop; nop; ret
        let a = lift1("eb029090c3");
        let b = lift1("eb039090c3");
        let d = compare(&a, &b);
        assert_eq!(d.class_counts.get(&DivergenceClass::BranchTarget), Some(&1));
        assert_eq!(d.verdict, Verdict::Mismatch);
    }

    /// An extra instruction on the candidate side is `extra`, distinct from `missing`: the
    /// direction matters, because only one of the two means we lost a computation.
    #[test]
    fn direction_of_a_gap_is_preserved() {
        let d = compare(&lift1(FRAME), &lift1("5589e58b450840405dc3"));
        assert_eq!(d.class_counts.get(&DivergenceClass::Extra), Some(&2));
        assert_eq!(d.class_counts.get(&DivergenceClass::Missing), None);
    }
}
