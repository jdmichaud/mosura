//! A model of the ORIGINAL COMPILER's instruction scheduler — Open Watcom 1.0
//! `bld/cg/c/inssched.c`, the surviving source of the 10.0-line code generator WAR2 was
//! built with — used by evidence rules to answer the question black-box calibration
//! could not: WOULD the scheduler have reordered these instructions?
//!
//! NOT part of the Ghidra port. CLAUDE.md's "only port Ghidra" rule governs `decompile/`;
//! this module models the TARGET TOOLCHAIN, beside `buildconfig`'s profile, and is placed
//! here by design: it consumes the original's decoded instructions and answers
//! recompile-layer questions.
//!
//! The recovered profile's `-onatx` carries `x` = `Set_OX`, which sets `INS_SCHEDULING`
//! (OW 1.0 `cc/c/coptions.c:1236`), so `Schedule()` runs on every function this project
//! compiles — and ran on every function of the original. That makes the original's
//! instruction order (per basic block) a FIXED POINT of the scheduler under whatever
//! constraints the original source imposed. Re-simulating WITHOUT a constraint and
//! getting a different order is evidence the constraint existed; re-adding one candidate
//! constraint and reproducing the original identifies it. The volatile rule below is the
//! first consumer.
//!
//! What is ported faithfully (file:line = OW 1.0):
//! * the dependency DAG and its ordering predicate — `InsOrderDependant`
//!   (inssched.c:419): later jumps depend on everything; a call cannot rise above an
//!   instruction whose result is visible to it; two stack ops never reorder; data
//!   dependence in both directions;
//! * `volatile` as a full barrier — `ReDefinedBy` answers TRUE for a volatile memory
//!   operand against every result-carrying instruction (redefby.c:144);
//! * the aliasing model under the recovered flags — `ZapsMemory` (redefby.c:70): two
//!   named globals alias only when their ranges overlap, and a register-addressed access
//!   does NOT alias a named global under `RELAX_ALIAS` (`-oa`, which `-onatx` carries);
//! * the bottom-up list walk and its priority chain — `ScheduleIns` (inssched.c:766):
//!   minimum `StallCost` first, then greatest height, then greatest `InsStallable`, then
//!   latest source id (ties preserve source order);
//! * `StallCost`'s operand-stall countdown (inssched.c:616) and `AnnointADag`'s height
//!   (inssched.c:580), with the 486/586 operand-stall values from `386funit.c` (ALU 2,
//!   IMUL 11, IDIV 24, moves and calls 0 — the integer rows are identical at both CPU
//!   levels, so the model is CPU-digit-independent, matching the measurement that the
//!   motion appears at `-4r` and `-5r` alike).
//!
//! Documented approximations — each degrades toward ABSTENTION, never toward a wrong
//! mark, because the consumer only acts when one candidate constraint EXACTLY explains
//! the original:
//! * functional-unit CLASS per instruction comes from Watcom's generate-table rows
//!   (`gen_table->func_unit`), which classify its own IR pre-encoding; at the decoded
//!   level the model classes by mnemonic (moves/pushes/leas/setcc = no stall, integer
//!   ALU = the ALU row, IMUL/IDIV their rows) and skips `unit_stall`/pairing-unit overlap
//!   (the ALU1-vs-ALUX split is invisible in machine code);
//! * `USE_ADDRESS` (a global whose address is taken may alias pointer accesses even
//!   under `-oa`) is unknowable from bytes — named globals are modeled as
//!   not-address-taken;
//! * a call's register effects are the watcall caller-saved set (EAX ECX EDX + flags);
//! * windows containing instructions the model cannot class (x87, string ops, prefixes,
//!   segment loads) abstain wholesale.

use super::insn::{NormInsn, SemArg};

const CPUI_INT_XOR: u32 = 26;
use std::collections::{HashMap, HashSet};

const CPUI_LOAD: u32 = 2;
const CPUI_STORE: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq)]
enum MemRef {
    /// An absolute-address access: `[addr, addr+size)`.
    Abs { addr: u64, size: u32 },
    /// A register-addressed access (Watcom's `N_INDEXED` with no named base).
    Indexed,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum Fu {
    /// Calls: the `386funit.c` CALL row (0,0). (`FU_NO` in the gen tables marks
    /// NON-EMITTING reduction rows, not real moves — every emitted integer instruction,
    /// MOVs included, carries an ALU row: see `Move1[]`, whose `G_MOV*` rows are all
    /// `FU_ALUX`. The first model classed MOV as no-stall from the reduction rows and
    /// mis-predicted every materialization placement.)
    No,
    /// Integer ALU (moves included): the ALU1/ALUX rows — `opnd_stall` 2.
    Alu,
    Imul,
    Idiv,
}

impl Fu {
    fn opnd_stall(self) -> i32 {
        match self {
            Fu::No => 0,
            Fu::Alu => 2,
            Fu::Imul => 11,
            Fu::Idiv => 24,
        }
    }
}

#[derive(Debug, Clone)]
struct Facts {
    reg_reads: Vec<(u64, u32)>,
    reg_writes: Vec<(u64, u32)>,
    /// `(ref, is_write)`
    mem: Vec<(MemRef, bool)>,
    is_call: bool,
    fu: Fu,
    stallable: u32,
    /// Touches an address in the barrier set (the volatile candidate under test).
    barrier: bool,
    modeled: bool,
}

fn overlap(a: (u64, u32), b: (u64, u32)) -> bool {
    a.0 < b.0 + b.1 as u64 && b.0 < a.0 + a.1 as u64
}

fn regs_conflict(a: &[(u64, u32)], b: &[(u64, u32)]) -> bool {
    a.iter().any(|&x| b.iter().any(|&y| overlap(x, y)))
}

/// `ZapsMemory` under the recovered flags (redefby.c:70): absolute-vs-absolute alias by
/// range overlap; absolute-vs-indexed does NOT alias (`RELAX_ALIAS`; the `USE_ADDRESS`
/// escape is the documented approximation); indexed-vs-indexed conservatively aliases.
fn mems_conflict(a: &[(MemRef, bool)], b: &[(MemRef, bool)]) -> bool {
    for &(ma, wa) in a {
        for &(mb, wb) in b {
            if !wa && !wb {
                continue;
            }
            let hit = match (ma, mb) {
                (MemRef::Abs { addr: x, size: sx }, MemRef::Abs { addr: y, size: sy }) => {
                    overlap((x, sx), (y, sy))
                }
                (MemRef::Indexed, MemRef::Indexed) => true,
                _ => false,
            };
            if hit {
                return true;
            }
        }
    }
    false
}

fn classify(insn: &NormInsn) -> Fu {
    let m = insn.mnemonic.as_str();
    if insn.is_call {
        return Fu::No;
    }
    match m {
        "IMUL" | "MUL" => Fu::Imul,
        "IDIV" | "DIV" => Fu::Idiv,
        "NOP" => Fu::No,
        _ => Fu::Alu,
    }
}

fn modelable(insn: &NormInsn) -> bool {
    let m = insn.mnemonic.as_str();
    if insn.is_call || insn.is_branch {
        return true;
    }
    matches!(
        m,
        "MOV" | "MOVZX" | "MOVSX" | "LEA" | "PUSH" | "POP" | "NOP" | "IMUL" | "MUL"
            | "IDIV" | "DIV" | "ADD" | "SUB" | "AND" | "OR" | "XOR" | "CMP" | "TEST"
            | "INC" | "DEC" | "NEG" | "NOT" | "SHL" | "SHR" | "SAR" | "SAL" | "ROL"
            | "ROR" | "ADC" | "SBB" | "CWDE" | "CDQ" | "CBW" | "CWD"
    ) || m.starts_with("SET")
}

/// Per-call register-effect overrides for the model — the PER-SITE ZAP CHECKER's knob.
/// Keyed by the CALL instruction's address: `(reads, writes)` as `(offset, size)` register
/// lists, the candidate declarations' implied effects (OW `CallZap`, i86reg.c:256:
/// writes = kill set ∪ parm.used ∪ EAX unless `exact`; reads = parm.used). A call with no
/// entry keeps the conservative fixed model below.
pub type CallEffects = HashMap<u64, (Vec<(u64, u32)>, Vec<(u64, u32)>)>;

fn facts(insn: &NormInsn, barriers: &HashSet<u64>) -> Facts {
    facts_with(insn, barriers, &HashMap::new())
}

fn facts_with(insn: &NormInsn, barriers: &HashSet<u64>, effects: &CallEffects) -> Facts {
    let mut f = Facts {
        reg_reads: Vec::new(),
        reg_writes: Vec::new(),
        mem: Vec::new(),
        is_call: insn.is_call,
        fu: classify(insn),
        stallable: 0,
        barrier: false,
        modeled: modelable(insn),
    };
    // The zero idiom's reads are formal: Watcom's IR holds `MOV r,0` (the XOR spelling is
    // the encoder's), so the register is written, never read — a formal read both blocked
    // the materialization fold and manufactured false edges to earlier writers.
    let self_xor_zero = insn.mnemonic == "XOR"
        && insn.sem.iter().any(|o| {
            o.opcode == CPUI_INT_XOR
                && matches!(o.out, Some(SemArg::Reg(o2, _)) if o2 < 0x20)
                && matches!(o.ins.as_slice(),
                    [SemArg::Reg(a2, s1), SemArg::Reg(b2, s2)] if a2 == b2 && s1 == s2)
        });
    for op in &insn.sem {
        match op.out {
            Some(SemArg::Reg(o, s)) => f.reg_writes.push((o, s)),
            Some(SemArg::Mem(_, a, s)) => f.mem.push((MemRef::Abs { addr: a, size: s }, true)),
            _ => {}
        }
        if op.opcode == CPUI_LOAD {
            f.mem.push((MemRef::Indexed, false));
        }
        if op.opcode == CPUI_STORE {
            f.mem.push((MemRef::Indexed, true));
        }
        for a in &op.ins {
            match *a {
                SemArg::Reg(o, s) => {
                    if !(self_xor_zero && o < 0x20) {
                        f.reg_reads.push((o, s));
                    }
                }
                SemArg::Mem(_, a2, s) => f.mem.push((MemRef::Abs { addr: a2, size: s }, false)),
                _ => {}
            }
        }
    }
    if insn.is_call {
        if let Some((reads, writes)) = effects.get(&insn.addr) {
            // The checker's candidate declarations for THIS call (see [`CallEffects`]).
            f.reg_reads.extend(reads.iter().copied());
            f.reg_writes.extend(writes.iter().copied());
        } else {
            // watcall caller-saved effects: EAX, ECX, EDX (+ flags are written by nearly
            // every instruction and read only by Jcc/ADC-class, which the reg model covers).
            f.reg_writes.push((0x0, 4));
            f.reg_writes.push((0x4, 4));
            f.reg_writes.push((0x8, 4));
            // ...and a call READS its argument registers: Watcom's own IR makes the parm
            // union an operand of the call instruction (`LinkParms` / CALL_OP_USED,
            // bldcall.c), so argument materializations pin between their call and the
            // previous one. Which registers are live arguments is invisible in machine
            // code — conservatively, all four watcall argument registers.
            f.reg_reads.push((0x0, 4));
            f.reg_reads.push((0x4, 4));
            f.reg_reads.push((0x8, 4));
            f.reg_reads.push((0xc, 4));
        }
    }
    // InsStallable (inssched.c:125): +3 per indexed operand, +2 per register operand,
    // +1 per named-memory operand; +3 for an indexed result.
    for &(m, _) in &f.mem {
        f.stallable += match m {
            MemRef::Indexed => 3,
            MemRef::Abs { .. } => 1,
        };
    }
    f.stallable += 2 * f.reg_reads.iter().filter(|&&(o, _)| o < 0x20).count() as u32;
    f.barrier = f.mem.iter().any(|&(m, _)| match m {
        MemRef::Abs { addr, size } => barriers.iter().any(|&b| overlap((addr, size), (b, 1))),
        MemRef::Indexed => false,
    });
    f
}

/// `InsOrderDependant` (inssched.c:419) for `i` LATER than `j`, over decoded facts.
fn depends(i: &Facts, j: &Facts) -> bool {
    // volatile: a full barrier both ways (redefby.c:144 — a volatile operand is
    // "redefined by" every result-carrying instruction).
    if i.barrier || j.barrier {
        return true;
    }
    // a later call cannot rise above an instruction whose (memory) result it can see
    if i.is_call && j.mem.iter().any(|&(_, w)| w) {
        return true;
    }
    // nothing that touches memory crosses an earlier call (the call may read or write
    // any visible memory), and the call's register effects conflict like any writes
    if j.is_call && !i.mem.is_empty() {
        return true;
    }
    if regs_conflict(&i.reg_writes, &j.reg_writes)
        || regs_conflict(&i.reg_writes, &j.reg_reads)
        || regs_conflict(&i.reg_reads, &j.reg_writes)
    {
        return true;
    }
    mems_conflict(&i.mem, &j.mem)
}

/// `StallCost` (inssched.c:616), operand-stall half: if `ins` were placed above the
/// current block top, how long would the instructions below wait on its result?
fn stall_cost(ins: &Facts, below: &[&Facts]) -> i32 {
    let mut opnd = ins.fu.opnd_stall();
    if opnd == 0 {
        return 0;
    }
    for cur in below {
        if opnd == 0 {
            return 0;
        }
        opnd -= 1;
        // DataDependant(ins, curr): curr consumes what ins defines
        if regs_conflict(&ins.reg_writes, &cur.reg_reads)
            || regs_conflict(&ins.reg_writes, &cur.reg_writes)
            || mems_conflict(
                &ins.mem.iter().copied().filter(|&(_, w)| w).collect::<Vec<_>>(),
                &cur.mem,
            )
        {
            return opnd * 2;
        }
    }
    0
}

/// Reduce a machine-instruction window to Watcom-IR-granularity scheduling atoms.
///
/// The scheduler runs on the cg's IR; the encoder splits some IR instructions into
/// several machine instructions AFTERWARD, and those pieces never move independently:
///
/// * a read-modify-write on one address (`MOV r,[m] ; ALU r,x ; MOV [m],r`) is ONE IR
///   instruction (`OP_OR mem,x` — the `G_MC` rows); the model folds the triple into the
///   store, which inherits the load's read and the ALU's operands (measured:
///   `FUN_0002911c`'s split RMW scheduled piecewise and self-marked volatile);
/// * a constant materialized into a register only to be stored (`MOV r,imm ; .. ;
///   MOV [m],r`, every use of `r` a store source) is the encoder/scoreboard's artifact
///   of `MOV mem,C` rows; the materialization is dropped and the stores keep their
///   register read (measured: `FUN_00030e08`'s shared `MOV EDX,imm` for three stores).
///
/// Returns kept indices plus per-kept extra facts merged from folded pieces.
fn reduce(win: &[NormInsn], facts: &[Facts]) -> (Vec<usize>, Vec<Facts>) {
    let n = win.len();
    let mut drop = vec![false; n];
    let mut merged: Vec<Facts> = facts.to_vec();
    // RMW triples (contiguous)
    for i in 0..n.saturating_sub(2) {
        let (a, b, c) = (&win[i], &win[i + 1], &win[i + 2]);
        let load_abs = |x: &NormInsn| -> Option<(u64, u32, (u64, u32))> {
            if x.mnemonic != "MOV" {
                return None;
            }
            let mut abs = None;
            let mut reg = None;
            for op in &x.sem {
                if let (Some(SemArg::Reg(o, s)), [SemArg::Mem(_, a2, s2)]) =
                    (&op.out, op.ins.as_slice())
                {
                    abs = Some((*a2, *s2));
                    reg = Some((*o, *s));
                }
            }
            abs.map(|m| (m.0, m.1, reg.unwrap()))
        };
        let store_abs = |x: &NormInsn| -> Option<(u64, u32, (u64, u32))> {
            if x.mnemonic != "MOV" {
                return None;
            }
            for op in &x.sem {
                if let (Some(SemArg::Mem(_, a2, s2)), [SemArg::Reg(o, s)]) =
                    (&op.out, op.ins.as_slice())
                {
                    return Some((*a2, *s2, (*o, *s)));
                }
            }
            None
        };
        if let (Some((la, ls, lr)), Some((sa, ss, sr))) = (load_abs(a), store_abs(c)) {
            let alu_on_r = facts[i + 1].fu == Fu::Alu
                && facts[i + 1].reg_writes.iter().any(|&w| overlap(w, lr))
                && !b.is_call
                && b.sem.iter().all(|op| !matches!(op.out, Some(SemArg::Mem(..))))
                && facts[i + 1].mem.is_empty();
            if la == sa && ls == ss && lr == sr && alu_on_r {
                drop[i] = true;
                drop[i + 1] = true;
                let mut f = merged[i + 2].clone();
                f.mem.push((MemRef::Abs { addr: la, size: ls }, false));
                f.reg_reads.extend(facts[i + 1].reg_reads.iter().copied());
                f.reg_writes.extend(facts[i + 1].reg_writes.iter().copied());
                f.fu = Fu::Alu;
                merged[i + 2] = f;
            }
        }
    }
    // store-value materializations: MOV r,imm / XOR r,r(zero) whose every use of r,
    // until r is rewritten or the window ends, is as a store SOURCE
    for i in 0..n {
        if drop[i] {
            continue;
        }
        let x = &win[i];
        let mat_reg = (|| -> Option<(u64, u32)> {
            let imm = x.mnemonic == "MOV"
                && x.sem.len() == 1
                && matches!(x.sem[0].ins.as_slice(), [SemArg::Const(..)]);
            // the value op specifically — the lifter's FLAG writes are also Reg outs
            // and sit first in `sem`, which hid every zero idiom from the first cut
            let zero = x.mnemonic == "XOR"
                && x.sem.iter().any(|o| {
                    o.opcode == CPUI_INT_XOR
                        && matches!(o.out, Some(SemArg::Reg(o2, _)) if o2 < 0x20)
                        && matches!(o.ins.as_slice(),
                            [SemArg::Reg(a2, s1), SemArg::Reg(b2, s2)] if a2 == b2 && s1 == s2)
                });
            if !imm && !zero {
                return None;
            }
            x.sem.iter().find_map(|o| match o.out {
                Some(SemArg::Reg(o2, s2)) if o2 < 0x20 => Some((o2, s2)),
                _ => None,
            })
        })();
        let Some(r) = mat_reg else { continue };
        let mut used_as_store_source = false;
        let mut ok = true;
        for j in i + 1..n {
            let fj = &facts[j];
            let reads = fj.reg_reads.iter().any(|&x2| overlap(x2, r));
            if reads {
                let is_plain_store = win[j].mnemonic == "MOV"
                    && win[j].sem.iter().any(|op| matches!(op.out, Some(SemArg::Mem(..))))
                    && fj.reg_writes.iter().all(|&w| !overlap(w, r));
                if is_plain_store {
                    used_as_store_source = true;
                } else {
                    ok = false;
                    break;
                }
            }
            if fj.reg_writes.iter().any(|&w| overlap(w, r)) {
                break;
            }
        }
        if ok && used_as_store_source {
            drop[i] = true;
        }
    }
    let kept: Vec<usize> = (0..n).filter(|&i| !drop[i]).collect();
    let kept_facts: Vec<Facts> = kept.iter().map(|&i| merged[i].clone()).collect();
    (kept, kept_facts)
}

/// Schedule one window bottom-up (`ScheduleIns`, inssched.c:766) and return the
/// predicted order of the REDUCED atoms as indices into the original window (folded
/// encoder artifacts are absent), or `None` when the window contains instructions the
/// model cannot class. The original is scheduler-stable iff the returned order is
/// ascending.
pub fn schedule(insns: &[NormInsn], barriers: &HashSet<u64>) -> Option<Vec<usize>> {
    schedule_with(insns, barriers, &HashMap::new())
}

/// [`schedule`] with per-call effect overrides — the checker's entry.
pub fn schedule_with(
    insns: &[NormInsn],
    barriers: &HashSet<u64>,
    effects: &CallEffects,
) -> Option<Vec<usize>> {
    if insns.is_empty() {
        return Some(Vec::new());
    }
    let raw: Vec<Facts> = insns.iter().map(|x| facts_with(x, barriers, effects)).collect();
    if raw.iter().any(|f| !f.modeled) {
        return None;
    }
    let (kept, facts) = reduce(insns, &raw);
    let n = kept.len();
    if n == 0 {
        return Some(Vec::new());
    }
    // deps[i] = set of earlier j that i is order-dependent on (BuildDag, both loops)
    let mut deps: Vec<Vec<usize>> = vec![Vec::new(); n];
    for i in 0..n {
        for j in 0..i {
            if depends(&facts[i], &facts[j]) {
                deps[i].push(j);
            }
        }
    }
    // heights (AnnointADag): longest chain above, weighted by operand stalls
    let mut height = vec![0i32; n];
    for i in 0..n {
        let mut h = 0;
        for &j in &deps[i] {
            h = h.max(height[j]);
        }
        height[i] = h + facts[i].fu.opnd_stall();
    }
    // succ counts: how many later instructions depend on j (the walk frees j when all
    // its dependents are placed)
    let mut succ = vec![0usize; n];
    for i in 0..n {
        for &j in &deps[i] {
            succ[j] += 1;
        }
    }
    let mut placed = vec![false; n];
    let mut order_rev: Vec<usize> = Vec::with_capacity(n);
    let mut below: Vec<&Facts> = Vec::new();
    for _ in 0..n {
        // ready = unplaced with no unplaced dependents
        let mut best: Option<(usize, i32)> = None;
        for c in 0..n {
            if placed[c] || succ[c] != 0 {
                continue;
            }
            let cost = stall_cost(&facts[c], &below);
            let better = match best {
                None => true,
                Some((b, bc)) => {
                    cost < bc
                        || (cost == bc
                            && (height[c] > height[b]
                                || (height[c] == height[b]
                                    && (facts[c].stallable > facts[b].stallable
                                        || (facts[c].stallable == facts[b].stallable
                                            && c > b)))))
                }
            };
            if better {
                best = Some((c, cost));
            }
        }
        let (b, _) = best?;
        if std::env::var_os("MOSURA_SCHED_DEBUG").is_some() {
            let ready: Vec<String> = (0..n)
                .filter(|&c| !placed[c] && succ[c] == 0)
                .map(|c| {
                    format!(
                        "{}(c{},h{},s{})",
                        kept[c],
                        stall_cost(&facts[c], &below),
                        height[c],
                        facts[c].stallable
                    )
                })
                .collect();
            eprintln!("[pick] {} from {}", kept[b], ready.join(" "));
        }
        placed[b] = true;
        order_rev.push(b);
        below.insert(0, &facts[b]);
        for &j in &deps[b] {
            succ[j] -= 1;
        }
    }
    order_rev.reverse();
    Some(order_rev.into_iter().map(|k| kept[k]).collect())
}

/// Split a function's instructions into scheduler windows: maximal runs broken at
/// control transfers and at branch TARGETS (block leaders). Calls stay inside — the
/// scheduler moves independent instructions across them. The PROLOGUE and EPILOGUE are
/// excluded: Watcom attaches them at encoding time, after `Schedule()` has run, so the
/// scheduler never sees the saves, the frame setup, or the teardown (measured: with them
/// included the model hoisted body loads above `PUSH`es the real compiler never touches).
pub fn windows(insns: &[NormInsn]) -> Vec<std::ops::Range<usize>> {
    let mut leaders: HashSet<u64> = HashSet::new();
    for x in insns {
        if x.is_branch {
            if let Some(t) = x.target {
                leaders.insert(t);
            }
        }
    }
    let mut out = Vec::new();
    let mut start = 0usize;
    for (i, x) in insns.iter().enumerate() {
        if i > start && leaders.contains(&x.addr) {
            out.push(start..i);
            start = i;
        }
        if x.is_branch || x.mnemonic.starts_with("RET") {
            out.push(start..i);
            start = i + 1;
        }
    }
    if start < insns.len() {
        out.push(start..insns.len());
    }
    // Trim the unscheduled frame code. Entry: leading register saves and frame setup
    // (`PUSH r`*, `MOV EBP,ESP`, `SUB ESP,imm`). Every RET-adjacent window: trailing
    // restores and teardown (`POP r`*, `MOV ESP,EBP`, `LEA ESP,[..]`).
    for r in &mut out {
        if r.start == 0 {
            while r.start < r.end {
                let t = &insns[r.start].text;
                if t.starts_with("PUSH ")
                    || t.starts_with("MOV EBP,ESP")
                    || (t.starts_with("SUB ESP,") && insns[r.start].mnemonic == "SUB")
                {
                    r.start += 1;
                } else {
                    break;
                }
            }
        }
        let after = r.end;
        if insns.get(after).is_some_and(|x| x.mnemonic.starts_with("RET")) {
            while r.end > r.start {
                let t = &insns[r.end - 1].text;
                if t.starts_with("POP ") || t.starts_with("MOV ESP,EBP") || t.starts_with("LEA ESP,")
                {
                    r.end -= 1;
                } else {
                    break;
                }
            }
        }
    }
    out.retain(|r| r.len() >= 2);
    out
}

/// The volatile readout, rebuilt on the model: per window, the original's order is a
/// fixed point of its own scheduler. If re-simulating with NO barriers reproduces the
/// original, its order carries no information. If it does NOT, every stored global whose
/// barrier ALONE reproduces it is marked — several can (a pinned load may be explained by
/// the store above it or by its own source global's store below; barriers are monotone
/// for order and the both-marked probe on FUN_00034590 measured EXACT). No explanation,
/// or unmodeled content, abstains.
/// THE PER-SITE ZAP CHECKER (the contract design's verifier): would the CANDIDATE per-call
/// declarations make the scheduler model REORDER a window that the conservative baseline
/// model keeps in the original's order? COMPARATIVE by design: a window the baseline
/// already fails to keep ascending carries no signal (the model's own imprecision — the
/// volatile machinery's territory), so only a candidate-caused regression refuses. A
/// window containing a candidate call the model cannot handle at all (`schedule_with` =
/// `None` under the candidate but not the baseline) also refuses, conservatively.
///
/// `true` = the candidate breaks at least one window: DO NOT emit these declarations for
/// this TU; fall back to the landed rendering (zero-regression by construction).
pub fn order_regressed(insns: &[NormInsn], candidate: &CallEffects) -> bool {
    let none = HashSet::new();
    let baseline = HashMap::new();
    let ascending = |v: &[usize]| v.windows(2).all(|p| p[0] < p[1]);
    for w in windows(insns) {
        let win = &insns[w.clone()];
        if !win.iter().any(|x| x.is_call && candidate.contains_key(&x.addr)) {
            continue; // the candidate does not touch this window
        }
        let base_ok = schedule_with(win, &none, &baseline).as_deref().map(|v| ascending(v));
        if base_ok != Some(true) {
            continue; // no baseline signal here
        }
        match schedule_with(win, &none, candidate).as_deref().map(|v| ascending(v)) {
            Some(true) => {}
            other => {
                if std::env::var_os("MOSURA_ZAP_DEBUG").is_some() {
                    let calls: Vec<String> = win
                        .iter()
                        .filter(|x| x.is_call && candidate.contains_key(&x.addr))
                        .map(|x| format!("{:#x}", x.addr))
                        .collect();
                    eprintln!(
                        "[zapcheck]   window {:#x}..{:#x} verdict={:?} candidate-calls=[{}]",
                        win.first().map(|x| x.addr).unwrap_or(0),
                        win.last().map(|x| x.addr).unwrap_or(0),
                        other,
                        calls.join(",")
                    );
                }
                return true;
            }
        }
    }
    false
}

pub fn volatile_globals(insns: &[NormInsn]) -> HashSet<u64> {
    let mut marked = HashSet::new();
    let none = HashSet::new();
    // Blast-radius scope: the model validates ONE window's order, but the per-TU
    // `volatile` declaration reaches every access of the global in the TU, and each
    // unvalidated access is a scoreboard/selection site a wrong mark can flip (measured:
    // a dozen deep-MISMATCH functions lost up to 0.32 alignment to marks whose globals
    // they access many times; every probe-proven win accesses its global at most twice —
    // the ISR pattern's store and re-test).
    let access_count = |g: u64| -> usize {
        insns
            .iter()
            .flat_map(|x| x.sem.iter())
            .filter(|op| {
                matches!(op.out, Some(SemArg::Mem(_, a, _)) if a == g)
                    || op.ins.iter().any(|i| matches!(i, SemArg::Mem(_, a, _) if *a == g))
            })
            .count()
    };
    for w in windows(insns) {
        let win = &insns[w.clone()];
        let ascending = |v: &[usize]| v.windows(2).all(|p| p[0] < p[1]);
        let Some(base) = schedule(win, &none) else { continue };
        if ascending(&base) {
            continue;
        }
        // CONFIDENCE gate: the model's priority approximations (mnemonic-level FU
        // classes, no unit-stall pairing) accumulate error with the amount of predicted
        // motion. A small perturbation — the measured true positives displace one or two
        // atoms — is high-confidence; a long dependent-chain window predicting four or
        // more displaced atoms is where the residue lives (FUN_00019344's LEA/ADD chain,
        // whose order even a faithful cost hand-computation cannot reproduce — plausibly
        // the interim build's own scheduler priority, the pile-B leg).
        let moved = base
            .iter()
            .enumerate()
            .filter(|&(pos, &orig)| {
                base[..pos].iter().any(|&o| o > orig) || base[pos + 1..].iter().any(|&o| o < orig)
            })
            .count();
        if moved > 3 {
            continue;
        }
        // candidate barriers: the absolute store targets in this window, with the store's
        // window index — the CAUSAL gate below needs it
        let mut cands: Vec<(u64, usize)> = Vec::new();
        for (i, x) in win.iter().enumerate() {
            for op in &x.sem {
                if let Some(SemArg::Mem(_, a, _)) = op.out {
                    if !cands.iter().any(|&(c, _)| c == a) {
                        cands.push((a, i));
                    }
                }
            }
        }
        for &(g, gi) in &cands {
            // SELECTION veto, byte-readable and measured four ways (FUN_000121e8/5ea54/
            // 5ed78/2d60c): a NON-ZERO byte constant stored through a register proves the
            // global was not volatile — under `volatile` this compiler selects the
            // immediate-form store (`MOV [g],0x11`), never the register pair, because the
            // scoreboard may not cache a volatile location's value (scinfo.c N_VOLATILE).
            // The ZERO idiom is exempt: `XOR r,r ; MOV [g],r` survives a volatile probe
            // byte-exactly (FUN_00034590).
            let reg_const_store = (|| {
                let x = &win[gi];
                if x.mnemonic != "MOV" {
                    return false;
                }
                let src = x.sem.iter().find_map(|op| match (&op.out, op.ins.as_slice()) {
                    (Some(SemArg::Mem(_, _, 1)), [SemArg::Reg(o, 1)]) => Some(*o),
                    _ => None,
                });
                let Some(r) = src else { return false };
                // the register's materialization above: an immediate MOV (veto) — a zero
                // XOR or a computed value is not this shape
                win[..gi].iter().rev().any(|y| {
                    y.mnemonic == "MOV"
                        && y.sem.len() == 1
                        && matches!(y.sem[0].out, Some(SemArg::Reg(o, _)) if overlap((o, 1), (r, 1)))
                        && matches!(y.sem[0].ins.as_slice(), [SemArg::Const(..)])
                })
            })();
            if reg_const_store {
                continue;
            }
            // CAUSAL gate: a barrier is depends-on-everything, so it dampens ANY motion —
            // it explains the original only if the base prediction's motion actually
            // CROSSES this store (an atom on one side of it predicted onto the other).
            // Measured: without this, an unrelated register swap at a window's top marked
            // the store at its bottom (FUN_00012840's true-volatile sibling global,
            // marked here for the wrong reason and breaking an EXACT function).
            let crosses = {
                // an atom originally BELOW the store predicted ABOVE it, or vice versa
                let store_pos = base.iter().position(|&o| o == gi);
                match store_pos {
                    None => false, // the store itself folded away — no crossing readable
                    Some(sp) => base.iter().enumerate().any(|(pos, &orig)| {
                        (orig > gi && pos < sp) || (orig < gi && pos > sp)
                    }),
                }
            };
            if !crosses {
                continue;
            }
            if access_count(g) > 2 {
                continue;
            }
            let mut b = HashSet::new();
            b.insert(g);
            if schedule(win, &b).is_some_and(|o| ascending(&o)) {
                marked.insert(g);
            }
        }
    }
    marked
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recompile::insn::{normalize, NoReloc};

    fn lift(hex: &str) -> Vec<NormInsn> {
        let bytes: Vec<u8> = (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        normalize("x86:LE:32:default", &bytes, 0x1000, &NoReloc).expect("language tables")
    }

    /// FUN_00034590's real window. Non-volatile, the model must predict the compiler's
    /// measured output — the argument load pulled between `XOR EDX,EDX` and its dependent
    /// store to fill the ALU stall slot — and with the store's global barriered it must
    /// keep program order, identifying the volatile.
    #[test]
    fn the_flagship_window_identifies_its_volatile() {
        // xor edx,edx ; mov [0x95090],edx ; mov eax,[0x84618] ; call ; mov [0x84618],edx
        // ; pop ebp ; pop edx ; ret
        let insns = lift("31d2891590500900a118460800e8001000008915184608005d5ac3");
        // mirror windows()' framing: the RET splits and the epilogue POPs are trimmed
        let win: Vec<NormInsn> = insns[..insns.len() - 3].to_vec();
        let ascending = |v: &[usize]| v.windows(2).all(|p| p[0] < p[1]);
        let base = schedule(&win, &HashSet::new()).expect("modelable");
        assert!(!ascending(&base), "non-volatile simulation must move the load: {base:?}");
        // the load (index 2) rises above the store (index 1) — the compiler's measured choice
        let pos = |v: &[usize], i: usize| v.iter().position(|&x| x == i).unwrap();
        assert!(pos(&base, 2) < pos(&base, 1), "{base:?}");
        let mut b = HashSet::new();
        b.insert(0x95090u64);
        assert!(schedule(&win, &b).is_some_and(|o| ascending(&o)));
        let v = volatile_globals(&insns);
        assert!(v.contains(&0x95090), "{v:x?}");
    }

    /// FUN_000125bc's real window: the model must hoist the next store's constant
    /// materialization above the first store (the compiler's measured output), mark
    /// `0x8032c`, and NOT mark `0x8032e` — whose barrier leaves the hoist legal.
    #[test]
    fn the_sibling_global_is_not_marked() {
        // mov [0x8032c],al ; mov dl,1 ; and eax,0xff ; mov [0x8032e],dl
        // ; mov [eax+0x802c8],dl ; ret
        let insns = lift("a22c030800b20125ff0000008815 2e030800 8890c8020800 c3".replace(' ', "").as_str());
        let v = volatile_globals(&insns);
        assert!(v.contains(&0x8032c), "{v:x?}");
        assert!(!v.contains(&0x8032e), "{v:x?}");
    }

    /// FUN_00010d40's class: the original ALREADY shows the scheduler's work (the shared
    /// materialization hoisted above the store run), so the window is a fixed point and
    /// carries no information — the blanket rule's −28 disaster class must stay unmarked.
    #[test]
    fn a_scheduled_original_is_a_fixed_point_and_proves_nothing() {
        // mov ah,0xff ; mov [0x99581],ah ; mov [0x99582],ah ; mov [0x99583],ah ; ret
        let insns = lift("b4ff882581950900882582950900882583950900c3");
        assert!(volatile_globals(&insns).is_empty());
        // FUN_000121e8's shape: constant materializations interleaved by the scheduler
        // mov ah,1 ; mov edx,0xfffffffd ; mov [0x8efe6],ah ; mov eax,[0x81288] ; call ; ret
        let insns = lift("b401bafdffffff8825e68e0800a188120800e800100000c3");
        assert!(volatile_globals(&insns).is_empty());
    }
}
