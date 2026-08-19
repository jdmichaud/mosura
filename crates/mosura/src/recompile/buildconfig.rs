//! Recovering the BUILD, not just the code: which compiler options each function was compiled with.
//!
//! A byte-exact claim is a claim about a specific compiler invoked a specific way. Two of WAR2's
//! options are visible in its own bytes and change the emitted function completely — whether a BP
//! frame is built at all, and whether callee-saved registers are pushed before or after it — so
//! compiling every function one way guarantees a mismatch on most of them, however good the
//! decompilation is.
//!
//! The evidence is read from the ORIGINAL function's decoded instructions rather than from a byte
//! pattern. A frame prologue is "push the frame-pointer register, then copy the stack pointer into
//! it" — a statement about what the instructions do, which holds for every encoding of it and for
//! architectures whose spellings nobody here has seen. Matching hex, the way the WAR2-specific
//! script this replaces does, misses the second encoding of the same instruction: WAR2 contains
//! both `55 89 e5` and `55 8b ec`, and a scan written for one silently mis-flags 84 functions.
//!
//! What stays outside: which flags a *profile* maps evidence to is toolchain knowledge, and it
//! belongs in a profile rather than in the decompiler. And a project that has independent ground
//! truth about its build (a recovered makefile, per-file options) supplies it as an override —
//! this module consumes such an answer, never invents one.

use super::insn::{NormInsn, SemArg, SemOp};
use std::collections::HashMap;

/// What the original function's own code says about how it was compiled.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Evidence {
    /// The function builds a frame: the frame-pointer register is pushed, then the stack pointer
    /// is copied into it.
    pub frame_prologue: bool,
    /// Callee-saved registers are pushed BEFORE the frame is built.
    ///
    /// This separates the compiler's two prologue paths. Building the frame first requires
    /// restoring the stack pointer from it at the end (`lea esp,[ebp-N]`); saving first does not,
    /// and the epilogue is bare pops. A function whose original saves first was not compiled the
    /// other way, and compiling it that way costs at least three bytes no matter what the C says.
    pub saves_before_frame: bool,
    /// The body contains an in-place scaled LEA (`LEA EAX,[EAX*4]`-family — the destination is
    /// its own index register). Under `-5r` the code generator never selects this form: the
    /// CPU_586 arm of the LEA verifier (Open Watcom `i86ver.c`, `V_LEA_GOOD`/`OP_LSHIFT`,
    /// `op1 == result && _CPULevel( CPU_586 )`) rewrites in-place scaling to `SHL`. So its
    /// presence PROVES the function was compiled with pre-Pentium tuning; the evidence is
    /// one-sided — absence proves nothing, and the default stays the profile's `-5r`.
    ///
    /// Measured on WAR2 (docs/war2-toolchain-synthesis.md): exactly one contiguous module —
    /// 9 functions, 0x69fb0..0x6e6e0, 18 sites — carries the form inside an otherwise
    /// Pentium-tuned build. A per-module CFLAGS difference in the original Makefile, which is
    /// why the CPU digit is per-function evidence and not only a profile constant.
    pub in_place_scaled_lea: bool,
}

/// A rule mapping evidence to option changes, for one toolchain.
#[derive(Debug, Clone)]
pub struct Rule {
    pub when_frame_prologue: Option<bool>,
    pub when_saves_before_frame: Option<bool>,
    pub when_in_place_scaled_lea: Option<bool>,
    pub add: Vec<String>,
    pub remove: Vec<String>,
}

/// One toolchain's base options and evidence rules.
#[derive(Debug, Clone)]
pub struct Profile {
    pub name: String,
    pub base: Vec<String>,
    pub rules: Vec<Rule>,
}

impl Profile {
    /// Options for a function with this evidence.
    pub fn flags_for(&self, ev: &Evidence) -> Vec<String> {
        let mut out = self.base.clone();
        for r in &self.rules {
            if r.when_frame_prologue.is_some_and(|w| w != ev.frame_prologue) {
                continue;
            }
            if r.when_saves_before_frame.is_some_and(|w| w != ev.saves_before_frame) {
                continue;
            }
            if r.when_in_place_scaled_lea.is_some_and(|w| w != ev.in_place_scaled_lea) {
                continue;
            }
            out.retain(|f| !r.remove.contains(f));
            for a in &r.add {
                if !out.contains(a) {
                    out.push(a.clone());
                }
            }
        }
        out
    }
}

/// Decide the `local-width` axis PER SITE from the original's bytes — the corrected form of
/// the first (per-function) calibration, built from inspecting the searched arm's actual
/// winners: every true widening site shows the container register PRE-ZEROED near a narrow
/// write into its low part (`XOR EBX,EBX ; MOV BX,[m]` — sometimes with an unrelated
/// instruction between, which strict adjacency missed), and wide-established values show a
/// full-register write at the def. Candidates are the axis's own
/// ([`crate::decompile::printc::EmitReport::local_width_candidates`] — DECLARED locals only —
/// and `tier2_candidates`); the same classifier scores both.
///
/// Target-specific throughout (x86 register structure, this compiler's widening idiom).
pub fn widened_sites_from_evidence(
    local_candidates: &[(u32, u64)],
    tier2_candidates: &[(crate::decompile::varnode::VarnodeId, u64)],
    insns: &[NormInsn],
) -> (std::collections::HashSet<u32>, std::collections::HashSet<crate::decompile::varnode::VarnodeId>) {
    let widened_at = |pc: u64| -> bool {
        let Some(i) = insns.iter().position(|x| x.addr == pc) else { return false };
        let t = &insns[i].text;
        if t.starts_with("CALL") {
            // A call defines the full return register because the ABI says so — it is NOT
            // evidence about the source variable's width (measured false positive: a byte
            // local holding a call result, EXACT at its reference width, regressed when
            // this arm of the rule widened it). The readout for call results is at the
            // USES, which this def-site rule does not model — abstain.
            return false;
        }
        let Some(dst) = t.split_whitespace().nth(1).and_then(|r| r.split(',').next()) else {
            return false;
        };
        if dst.starts_with('E') && dst.len() == 3 {
            return true; // full-register write at the def (MOV EAX,imm / AND EAX,.. / ..)
        }
        let container = match dst {
            "AL" | "AH" | "AX" => "EAX",
            "BL" | "BH" | "BX" => "EBX",
            "CL" | "CH" | "CX" => "ECX",
            "DL" | "DH" | "DX" => "EDX",
            _ => return false,
        };
        // The widening pre-zero, allowing unrelated instructions between (measured: the
        // scheduler interleaves — FUN_00045440's `XOR EDX,EDX ; MOV AL,.. ; MOV DL,..`) —
        // but an intervening write to the SAME container consumes the zero, so the scan
        // stops there (measured false positive: `XOR EAX,EAX ; MOV AL,a ; MOV AL,b` — the
        // zero belongs to the FIRST load; the second value's widening is a mask AFTER it,
        // which the reference rendering already reproduces).
        let zero = format!("XOR {container},{container}");
        let subs: [&str; 4] = match container {
            "EAX" => ["AL", "AH", "AX", "EAX"],
            "EBX" => ["BL", "BH", "BX", "EBX"],
            "ECX" => ["CL", "CH", "CX", "ECX"],
            _ => ["DL", "DH", "DX", "EDX"],
        };
        for x in insns[i.saturating_sub(3)..i].iter().rev() {
            if x.text == zero {
                return true;
            }
            let d = x.text.split_whitespace().nth(1).and_then(|r| r.split(',').next());
            if x.text.starts_with("CALL") || d.is_some_and(|d| subs.contains(&d)) {
                return false; // the container was redefined between — the zero is not ours
            }
        }
        false
    };
    let reps = local_candidates.iter().filter(|&&(_, pc)| widened_at(pc)).map(|&(r, _)| r).collect();
    let sites =
        tier2_candidates.iter().filter(|&&(_, pc)| widened_at(pc)).map(|&(v, _)| v).collect();
    (reps, sites)
}

/// Decide the `compare-form` axis PER SITE from the original's bytes — the second recovered
/// choice, and a determinate one: at each candidate comparison the ORIGINAL's own `CMP`/`TEST`
/// immediate says which spelling the source used. Returns the site addresses to complement.
///
/// Target-specific (x86 compare mnemonics and the Watcom-era flag-then-branch shape), hence
/// here rather than in `decompile::emit`. The flag-setting compare sits at the site's address
/// or a few instructions before it — the IR op's address is usually the `Jcc` that consumes
/// the flags — so the scan walks back a short window.
///
/// Measured on WAR2: 452 sites want the complement, 749 want the rendering as-is, and 101
/// functions want BOTH at different sites, which is why this is per site where the axis is
/// per function.
pub fn complement_compares_from_evidence(
    sites: &[(u64, u64, u64)],
    insns: &[NormInsn],
) -> std::collections::HashSet<u64> {
    let mut out = std::collections::HashSet::new();
    for &(pc, ours, complemented) in sites {
        let Some(i) = insns.iter().position(|x| x.addr == pc) else { continue };
        let cmp = (i.saturating_sub(3)..=i).rev().find_map(|j| {
            let t = &insns[j].text;
            (t.starts_with("CMP ") || t.starts_with("TEST ")).then_some(&insns[j])
        });
        let Some(cmp) = cmp else { continue };
        let Some(k) = cmp.text.rsplit(',').next().map(str::trim).and_then(|last| {
            let neg = last.starts_with('-');
            let v = u64::from_str_radix(last.trim_start_matches('-').strip_prefix("0x")?, 16).ok()?;
            Some(if neg { v.wrapping_neg() } else { v })
        }) else {
            continue;
        };
        // only act on an unambiguous readout: the original's immediate is one spelling or the
        // other, never both (they differ by one, so equality decides)
        if k == complemented && k != ours {
            out.insert(pc);
        }
    }
    // The NO-IMMEDIATE form: a comparison against 0/-1 on a register-computed value compiles
    // to `TEST r,r` + a sign-family branch when the source spelled the ZERO constant, and to
    // `CMP r,-1` when it spelled the -1 form (measured on FUN_00012ca0: original
    // `TEST EBX,EBX ; JL` = `0 <= x`; ours `CMP EBX,-1 ; JLE` = `-1 < x`). A self-TEST at the
    // site therefore says the source used the zero spelling: complement iff OUR rendering is
    // the -1 form (the complemented one is 0), keep iff ours already is.
    for &(pc, ours, complemented) in sites {
        if out.contains(&pc) || (ours != 0 && complemented != 0) {
            continue;
        }
        let Some(i) = insns.iter().position(|x| x.addr == pc) else { continue };
        let self_test = (i.saturating_sub(3)..=i).rev().any(|j| {
            let t = &insns[j].text;
            t.strip_prefix("TEST ")
                .and_then(|r| r.split_once(','))
                .is_some_and(|(a, b)| a.trim() == b.trim())
        });
        if self_test && complemented == 0 {
            out.insert(pc);
        }
    }
    out
}

/// Decide the `return-split` axis PER SITE from the original's bytes. The candidate is a tail
/// pair `if (B) {body} return B;` keyed by the guarding branch's address
/// ([`crate::decompile::printc::EmitReport::return_split_candidates`]); the readout is whether
/// the ORIGINAL materialized the tail boolean or stayed branch-only:
///
/// - branch-only (no `SETcc` from the branch to the function's end) — the source returned
///   constants inside the branch, which is exactly what the split rendering compiles to;
/// - a `SETcc` in that region — the source really computed a boolean value, keep the merged
///   `return B;`.
///
/// Target-specific (x86 `SETcc` mnemonics and this compiler family's materialization shape),
/// hence beside the Watcom profile.
pub fn split_returns_from_evidence(
    candidates: &[u64],
    insns: &[NormInsn],
) -> std::collections::HashSet<u64> {
    let mut out = std::collections::HashSet::new();
    for &pc in candidates {
        let Some(i) = insns.iter().position(|x| x.addr >= pc) else { continue };
        let materialized = insns[i..].iter().any(|x| x.text.starts_with("SET"));
        if !materialized {
            out.insert(pc);
        }
    }
    out
}

/// Decide the `cond-form` axis PER SITE from the original's bytes. The candidate is a
/// statement-carrying short-circuit keyed by its first clause's branch address, with every
/// clause's branch address supplied as the span to scan
/// ([`crate::decompile::printc::EmitReport::cond_nest_candidates`]). The readout: a `SETcc`
/// inside the clause span means the original materialized a clause boolean — the collapsed
/// comma form compiles to exactly that — while a branch-only span means nested ifs.
pub fn nested_conds_from_evidence(
    candidates: &[(u64, Vec<u64>)],
    insns: &[NormInsn],
) -> std::collections::HashSet<u64> {
    let mut out = std::collections::HashSet::new();
    for (key, span) in candidates {
        let (Some(&lo), Some(&hi)) = (span.iter().min(), span.iter().max()) else { continue };
        let materialized = insns
            .iter()
            .filter(|x| x.addr >= lo && x.addr <= hi)
            .any(|x| x.text.starts_with("SET"));
        if !materialized {
            out.insert(*key);
        }
    }
    out
}

/// Decide the `return-width` axis PER FUNCTION from the original's bytes. The candidates are
/// the RETURN sites where the value is narrower than the recovered storage
/// ([`crate::decompile::printc::EmitReport::return_width_candidates`]); the readout is the
/// ORIGINAL's last write to the A-register family before each RET:
///
/// - a narrow write (`MOV AL,..`, `SETcc AL`, `MOV AX,..`) — the original returns with the
///   high bytes untouched, so the source's return type was narrow: declare at the VALUE's
///   width (the reference decompiler's own rendering);
/// - a full-register write (`AND EAX,0xff`, `MOVZX EAX,..`, `XOR EAX,EAX`, a `CALL`) — the
///   original materializes the widening, which is what the widened declaration compiles to.
///
/// Narrow only when EVERY return site reads narrow — one declaration covers all of them.
pub fn narrow_return_from_evidence(candidates: &[(u64, u32, u32)], insns: &[NormInsn]) -> bool {
    if candidates.is_empty() {
        return false;
    }
    let writes_a = |t: &str| -> Option<bool> {
        // Some(narrow?) when the instruction writes the A register family
        let dst = t.split_whitespace().nth(1)?.split(',').next()?;
        match dst {
            "AL" | "AH" | "AX" => Some(true),
            "EAX" => Some(false),
            _ => {
                if t.starts_with("CALL") {
                    Some(false) // a call defines the full return register
                } else {
                    None
                }
            }
        }
    };
    candidates.iter().all(|&(ret_pc, _, _)| {
        let Some(end) = insns.iter().position(|x| x.addr >= ret_pc) else { return false };
        let Some(last) = insns[..end].iter().rposition(|x| writes_a(&x.text).is_some()) else {
            return false;
        };
        if writes_a(&insns[last].text) != Some(true) {
            return false; // full-register write — the widened declaration is right
        }
        // A narrow last write PRECEDED by the container zero is the WIDENING IDIOM
        // (`XOR EAX,EAX ; MOV AL,[m] ; RET` — measured on FUN_00031044): the function
        // returns the zero-extended value in full EAX, so the contract is wide. Same
        // consumed-zero scan as `widened_sites_from_evidence`: stop if anything between
        // writes the A family.
        for x in insns[last.saturating_sub(3)..last].iter().rev() {
            if x.text == "XOR EAX,EAX" {
                return false; // wide: the narrow write completes a widening
            }
            if writes_a(&x.text).is_some() {
                break;
            }
        }
        true
    })
}

/// Decide the entry-snapshot rendering PER VALUE from the original's bytes. The candidate is
/// an input-flagged narrow RAM value used as a call argument
/// ([`crate::decompile::printc::EmitReport::snapshot_candidates`]); the readout is whether
/// the ORIGINAL loads that global into a narrow register EXACTLY ONCE (`MOV AL,[0x8032c]` —
/// the snapshot the source's local produced; probe-validated EXACT rendered as
/// `uint1 uVarN = xRamX;` at body top) or references the address per use / not at all as a
/// plain narrow load. More than one such load means per-use re-reads — not a snapshot.
/// Returns `value → declared width`: the value's own size for a bare narrow load
/// (`MOV AL,[g]` — the byte-typed local, high bytes untouched), or the int width when the
/// container is PRE-ZEROED at the load (`XOR EAX,EAX ; MOV AL,[g]` — the widening idiom on
/// a global; measured regression: declaring those `uint1` made the call re-widen with an
/// `AND EAX,0xff` the original never has). Same consumed-zero scan as everywhere else.
pub fn entry_snapshots_from_evidence(
    candidates: &[(crate::decompile::varnode::VarnodeId, u64, u32)],
    insns: &[NormInsn],
) -> std::collections::HashMap<crate::decompile::varnode::VarnodeId, u32> {
    let mut out = std::collections::HashMap::new();
    for &(v, addr, sz) in candidates {
        let pat = format!(",[0x{addr:x}]");
        let matches_load = |x: &&NormInsn| {
            x.text.ends_with(&pat)
                && x.text.strip_prefix("MOV ").is_some_and(|r| {
                    matches!(
                        r.split(',').next().unwrap_or(""),
                        "AL" | "BL" | "CL" | "DL" | "AX" | "BX" | "CX" | "DX"
                    )
                })
        };
        if insns.iter().filter(matches_load).count() != 1 {
            continue;
        }
        let i = insns.iter().position(|x| matches_load(&x)).unwrap();
        // POSITION gate (the last measured false-positive class): the snapshot shape loads in
        // the ENTRY REGION — before the function's first branch (`MOV AL,[g]` above the
        // `CMP/JZ`, the probe family). A single load sitting AT the use (just before the call,
        // past branches) is the inline shape; hoisting it to body top MOVES the instruction
        // and diverges (measured: FUN_0002ba30's load right before its CALL).
        // Stricter than "before the first branch": a straight-line prefix can defer the load
        // many instructions in (measured: FUN_0002ba30 loads 7 deep, mid-computation), and
        // our snapshot prints at BODY TOP — so the original's load must sit right after the
        // prologue, allowing only the container zero between (the probe family's shape).
        let prologue_end = insns
            .iter()
            .position(|x| {
                !(x.text.starts_with("PUSH ") || x.text == "MOV EBP,ESP")
            })
            .unwrap_or(0);
        if i > prologue_end + 1 {
            continue;
        }
        let dst = insns[i].text.strip_prefix("MOV ").unwrap().split(',').next().unwrap();
        let container = match dst {
            "AL" | "AH" | "AX" => "EAX",
            "BL" | "BH" | "BX" => "EBX",
            "CL" | "CH" | "CX" => "ECX",
            _ => "EDX",
        };
        let zero = format!("XOR {container},{container}");
        let subs: [&str; 4] = match container {
            "EAX" => ["AL", "AH", "AX", "EAX"],
            "EBX" => ["BL", "BH", "BX", "EBX"],
            "ECX" => ["CL", "CH", "CX", "ECX"],
            _ => ["DL", "DH", "DX", "EDX"],
        };
        let mut widened = false;
        for x in insns[i.saturating_sub(3)..i].iter().rev() {
            if x.text == zero {
                widened = true;
                break;
            }
            let d = x.text.split_whitespace().nth(1).and_then(|r| r.split(',').next());
            if x.text.starts_with("CALL") || d.is_some_and(|d| subs.contains(&d)) {
                break;
            }
        }
        out.insert(v, if widened { 4 } else { sz });
    }
    out
}

/// Decide the testmem rendering PER LOAD from the original's bytes — the self-announcing
/// readout: a memory-direct `TEST ... ptr [..],imm` at the load's address means the SOURCE
/// read the wider element and masked (this compiler compiles `(*(int*)T & 8)` to the byte
/// `TEST` and a narrow-typed access to load+AND — measured battery, 15 shapes), so the deref
/// renders at int width. A `MOV`-then-`AND` at the site means the source really read narrow.
pub fn testmem_from_evidence(
    candidates: &[(crate::decompile::varnode::VarnodeId, u64)],
    insns: &[NormInsn],
) -> std::collections::HashSet<crate::decompile::varnode::VarnodeId> {
    let mut out = std::collections::HashSet::new();
    for &(v, pc) in candidates {
        let Some(i) = insns.iter().position(|x| x.addr == pc) else { continue };
        // the flag-setting instruction sits at the load's address or a couple later (the IR
        // op's address is the load; the original's TEST replaces load+and+test entirely)
        let window = &insns[i..(i + 3).min(insns.len())];
        if window.iter().any(|x| x.text.starts_with("TEST ") && x.text.contains("ptr [")) {
            out.insert(v);
        }
    }
    out
}

/// Does this function contain instructions PLAIN C cannot produce under this toolchain?
///
/// Deliberately NOT a claim of "hand-written assembly": Watcom's `#pragma aux ... = <bytes>`
/// embeds machine code inline into compiled C (per JD — and the corpus's `INT 0x21` wrapper
/// singletons may well be exactly that), and this detector cannot tell an .asm module from
/// aux-pragma-carrying C. It does not need to: either way the function is un-recompilable
/// from the plain C the emitter produces, which is what the `asm` manifest class excludes.
/// Revival condition: if the emitter ever renders aux-pragma inlines, the embedded-C subset
/// comes back in scope and this classification must be revisited.
///
/// The trigger census on WAR2 (63 functions): 32 software interrupts (`INT 0x21`/`0x31`/
/// `0x10` — DOS, DPMI, BIOS), 20 port I/O, 7 `PUSHFD`, plus CPUID and the CALL-CS
/// dispatcher — the DOS-extender support layer, in 35 runs of which 5 are 3+ contiguous
/// functions (module-granular).
///
/// Signature instructions no PLAIN wcc386-compiled C contains under the recovered profile:
///
/// - `PUSHFD`/`POPFD` — direct EFLAGS manipulation (the CPU-detection modules);
/// - `CPUID` — no intrinsic in this compiler generation;
/// - `IN`/`OUT` — port I/O;
/// - `INT n` — software interrupts issued inline;
/// - a `CALL` through a `CS:`-override table (the hand dispatcher idiom).
///
/// Deliberately NOT signatures, both measured: `ES:` (the compiler's inlined memcpy is
/// `REP MOVSD ES:EDI,ESI`) and `JMP CS:[..]` (the compiler's OWN switch tables carry the
/// CS override — two SAME_SHAPE functions tripped the first draft through their compiled
/// switches; `CALL CS:[..]` appears in exactly two functions corpus-wide, neither of them
/// verified-compiled). Calibration requirement: ZERO functions that recompile
/// EXACT/SAME_SHAPE from C may trip this — a compiled function flagged hand-asm would
/// silently shrink the denominator.
pub fn looks_hand_written(insns: &[NormInsn]) -> bool {
    insns.iter().any(|x| {
        let t = &x.text;
        t.starts_with("PUSHFD")
            || t.starts_with("POPFD")
            || t.starts_with("CPUID")
            || t.starts_with("IN ")
            || t.starts_with("OUT ")
            || t.starts_with("INT ")
            || (t.starts_with("CALL") && t.contains("CS:["))
    })
}

/// Decide persist-store EMISSION ORDER per run from the original's bytes. The candidates
/// are runs of consecutive pure global-store statements
/// ([`crate::decompile::printc::EmitReport::store_runs`], in our statement order); the
/// readout is the ORIGINAL's own store instruction for each address (`MOV [0xADDR],..` /
/// `MOV .. ptr [0xADDR],..` — the DESTINATION operand), ordered by instruction position.
/// Only a complete, unambiguous readout acts: every address found exactly once, and the
/// resulting order differing from ours. Returns `first-op → ops in emission order`.
pub fn store_orders_from_evidence(
    runs: &[Vec<(crate::decompile::op::OpId, u64, u32)>],
    insns: &[NormInsn],
) -> std::collections::HashMap<crate::decompile::op::OpId, Vec<crate::decompile::op::OpId>> {
    let mut out = std::collections::HashMap::new();
    for run in runs {
        let mut order: Vec<(usize, crate::decompile::op::OpId)> = Vec::new();
        let mut ok = true;
        for &(op, addr, _sz) in run {
            let dest = format!("[0x{addr:x}],");
            let hits: Vec<usize> = insns
                .iter()
                .enumerate()
                .filter(|(_, x)| x.text.starts_with("MOV ") && x.text.contains(&dest))
                .map(|(i, _)| i)
                .collect();
            if hits.len() != 1 {
                ok = false;
                break;
            }
            order.push((hits[0], op));
        }
        if !ok {
            continue;
        }
        order.sort_by_key(|&(i, _)| i);
        let ops: Vec<_> = order.iter().map(|&(_, op)| op).collect();
        let ours: Vec<_> = run.iter().map(|r| r.0).collect();
        if ops != ours {
            out.insert(ours[0], ops);
        }
    }
    out
}

/// Watcom C/C++32 10.0a as WAR2 was built with it.
///
/// The base options are the register calling convention (`-4r`), inline 387 (`-fpi87`), no stack
/// checking (`-s`) and the measured optimization set (`-onatx`). The one evidence rule is `-d1+`:
/// line-number debug information, which is what makes this compiler emit a BP frame on the path
/// WAR2 was built with. Adding it to a frameless function adds four bytes that are not there, so
/// it is applied only where the original has a frame.
///
/// Deliberately NOT here: `-of`/`-of+`. Both force the other prologue path, and every WAR2
/// function that saves registers before its frame is evidence against them.
/// `-5r`, not `-4r`: the CPU digit is a TUNING level, not a convention change, and WAR2 was
/// tuned for Pentium. Measured 2026-08-18 (docs/war2-toolchain-synthesis.md): 10.0a's code
/// generator carries a CPU_586 gate that suppresses the in-place scaled-LEA selection
/// (`SHL EAX,2` instead of `LEA EAX,[EAX*4]` — the gate survives into Open Watcom source as
/// the `op1 == result && _CPULevel( CPU_586 )` arm of V_LEA_GOOD's OP_LSHIFT case). WAR2
/// uses the SHL form everywhere. Corpus-wide on sb43 sources: SHL>LEA divergence rows
/// 157 -> 12, EXACT 586 -> 591 (+6/-1). `-4r` had itself replaced `-3r` on the same kind of
/// evidence (V_GOOD_CLR needs CPU_486 — the warcraft2-re byte-zero-store finding).
pub fn watcom_10_0a() -> Profile {
    Profile {
        name: "watcom-10.0a".into(),
        base: ["-5r", "-fpi87", "-s", "-onatx"].iter().map(|s| s.to_string()).collect(),
        rules: vec![
            Rule {
                when_frame_prologue: Some(true),
                when_saves_before_frame: None,
                when_in_place_scaled_lea: None,
                add: vec!["-d1+".into()],
                remove: vec!["-of".into(), "-of+".into()],
            },
            // The per-function CPU-digit downgrade: see `Evidence::in_place_scaled_lea`.
            Rule {
                when_frame_prologue: None,
                when_saves_before_frame: None,
                when_in_place_scaled_lea: Some(true),
                add: vec!["-4r".into()],
                remove: vec!["-5r".into()],
            },
        ],
    }
}

/// Read the evidence out of a function's decoded prologue.
///
/// `sp` and `fp` are the stack- and frame-pointer registers as `(register-space offset, size)`;
/// the caller resolves them from the language rather than this module assuming an architecture.
pub fn detect(insns: &[NormInsn], sp: (u64, u32), fp: (u64, u32)) -> Evidence {
    let mut ev = Evidence::default();
    let mut pushes_before = 0usize;
    for (i, insn) in insns.iter().enumerate().take(PROLOGUE_WINDOW) {
        if is_frame_setup(insn, sp, fp) {
            ev.frame_prologue = true;
            // A push of the frame pointer itself is part of the frame setup, not a callee-saved
            // register save, so it does not count as saving first.
            ev.saves_before_frame = pushes_before > 0;
            break;
        }
        match push_of(insn, sp) {
            Some(reg) if reg != fp => pushes_before += 1,
            Some(_) => {}
            None => break, // anything else ends the prologue
        }
        let _ = i;
    }
    // Body evidence (whole function, not just the prologue): an in-place scaled LEA — the
    // destination register is its own index. `LEA EAX,[EAX*0x4 + 0x0]` matches;
    // `LEA EAX,[EDX*0x4 + 0x0]` (cross-register, legal at every CPU level) does not.
    for insn in insns {
        if let Some(rest) = insn.text.strip_prefix("LEA ") {
            if let Some((dest, addr)) = rest.split_once(',') {
                if addr.contains(&format!("[{dest}*0x")) {
                    ev.in_place_scaled_lea = true;
                    break;
                }
            }
        }
    }
    ev
}

/// How many instructions into the function a frame setup may appear. Registers are saved first on
/// one of the two paths, so the window has to cover a realistic save list.
const PROLOGUE_WINDOW: usize = 12;

/// `fp = sp`, however it is spelled: a single COPY of the stack pointer into the frame pointer.
fn is_frame_setup(insn: &NormInsn, sp: (u64, u32), fp: (u64, u32)) -> bool {
    matches!(
        insn.sem.as_slice(),
        [SemOp { opcode: CPUI_COPY, out: Some(SemArg::Reg(o, osz)), ins }]
            if (*o, *osz) == fp && matches!(ins.as_slice(), [SemArg::Reg(i, isz)] if (*i, *isz) == sp)
    )
}

/// A push: the stack pointer is decremented and a register is stored at the new top. Returns the
/// pushed register.
///
/// The stored value is a lifter TEMPORARY, not the register itself — `PUSH EBP` becomes
/// `t = COPY EBP ; ESP = INT_SUB ESP,4 ; STORE ram ESP t` — so the store's operand is resolved
/// back through the copies inside the instruction. Matching the register directly finds nothing,
/// which made this return `None` for every push and stop the prologue scan at its first
/// instruction.
fn push_of(insn: &NormInsn, sp: (u64, u32)) -> Option<(u64, u32)> {
    let mut decremented = false;
    let mut stored: Option<&SemArg> = None;
    // Temporary -> what was copied into it, within this instruction.
    let mut origin: Vec<(&SemArg, &SemArg)> = Vec::new();
    for op in &insn.sem {
        match op.opcode {
            CPUI_COPY => {
                if let (Some(out @ SemArg::Temp(..)), [src]) = (&op.out, op.ins.as_slice()) {
                    origin.push((out, src));
                }
            }
            CPUI_INT_SUB | CPUI_INT_ADD => {
                if matches!(&op.out, Some(SemArg::Reg(o, s)) if (*o, *s) == sp) {
                    decremented = true;
                }
            }
            CPUI_STORE => {
                if let [_, _, value] = op.ins.as_slice() {
                    stored = Some(value);
                }
            }
            _ => {}
        }
    }
    if !decremented {
        return None;
    }
    let mut value = stored?;
    for _ in 0..4 {
        match value {
            SemArg::Reg(r, s) => return Some((*r, *s)),
            _ => match origin.iter().find(|(t, _)| *t == value) {
                Some((_, src)) => value = src,
                None => return None,
            },
        }
    }
    None
}

const CPUI_COPY: u32 = 1;
const CPUI_STORE: u32 = 3;
const CPUI_INT_ADD: u32 = 19;
const CPUI_INT_SUB: u32 = 20;

/// Per-function options for a whole program.
#[derive(Debug, Default, Clone)]
pub struct BuildConfig {
    /// Keyed by function entry address.
    pub flags: HashMap<u64, Vec<String>>,
    pub profile: String,
}

impl BuildConfig {
    pub fn get(&self, entry: u64) -> Option<&Vec<String>> {
        self.flags.get(&entry)
    }
}

/// Recover per-function options for every function whose original instructions are supplied.
///
/// `overrides` carries independent ground truth about the build, keyed by entry address; where it
/// speaks, it wins, because it is evidence this module cannot derive. Everything else comes from
/// the profile's rules applied to the function's own prologue.
pub fn recover(
    profile: &Profile,
    functions: &[(u64, Vec<NormInsn>)],
    sp: (u64, u32),
    fp: (u64, u32),
    overrides: &HashMap<u64, Vec<String>>,
) -> BuildConfig {
    let mut flags = HashMap::with_capacity(functions.len());
    for (entry, insns) in functions {
        let ev = detect(insns, sp, fp);
        let mut f = match overrides.get(entry) {
            // An override states the build, not the evidence, so the evidence rules still apply on
            // top: the two answer different questions and the override does not know this
            // function's prologue.
            Some(o) => o.clone(),
            None => profile.base.clone(),
        };
        for r in &profile.rules {
            if r.when_frame_prologue.is_some_and(|w| w != ev.frame_prologue) {
                continue;
            }
            if r.when_saves_before_frame.is_some_and(|w| w != ev.saves_before_frame) {
                continue;
            }
            f.retain(|x| !r.remove.contains(x));
            for a in &r.add {
                if !f.contains(a) {
                    f.push(a.clone());
                }
            }
        }
        flags.insert(*entry, f);
    }
    BuildConfig { flags, profile: profile.name.clone() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recompile::insn::{NoReloc, normalize};

    const ESP: (u64, u32) = (0x10, 4);
    const EBP: (u64, u32) = (0x14, 4);

    fn lift(hex: &str) -> Vec<NormInsn> {
        let bytes: Vec<u8> = (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        normalize("x86:LE:32:default", &bytes, 0x1000, &NoReloc).expect("language tables")
    }

    /// BOTH encodings of `mov ebp,esp` are a frame setup. The script this replaces matched hex, and
    /// WAR2 contains both spellings — 261 functions use one and 84 the other.
    #[test]
    fn a_frame_is_recognized_in_either_encoding() {
        for hex in ["5589e58b45085dc3", "558bec8b45085dc3"] {
            let ev = detect(&lift(hex), ESP, EBP);
            assert!(ev.frame_prologue, "{hex}");
            assert!(!ev.saves_before_frame, "{hex}");
        }
    }

    /// Registers pushed BEFORE the frame is the other prologue path, and the frame-pointer's own
    /// push does not count as one.
    #[test]
    fn saving_before_the_frame_is_distinguished() {
        // push edx; push ebp; mov ebp,esp; pop ebp; pop edx; ret
        let ev = detect(&lift("52558 9e55d5ac3".replace(' ', "").as_str()), ESP, EBP);
        assert!(ev.frame_prologue);
        assert!(ev.saves_before_frame);
    }

    /// A function with no frame at all reports neither.
    #[test]
    fn a_frameless_function_reports_no_frame() {
        // mov eax,edx; add eax,1; ret
        let ev = detect(&lift("89d083c001c3"), ESP, EBP);
        assert!(!ev.frame_prologue);
        assert!(!ev.saves_before_frame);
    }

    /// The Watcom profile adds the frame flag only where there is a frame — on a frameless
    /// function it would add four bytes the original does not have.
    #[test]
    fn the_frame_flag_is_applied_only_where_there_is_a_frame() {
        let p = watcom_10_0a();
        assert!(p
            .flags_for(&Evidence { frame_prologue: true, ..Evidence::default() })
            .contains(&"-d1+".to_string()));
        assert!(!p.flags_for(&Evidence::default()).contains(&"-d1+".to_string()));
    }

    /// An in-place scaled LEA in the body is proof of pre-Pentium tuning — `-5r` can never
    /// emit the form — so the profile downgrades that function's CPU digit to `-4r`.
    /// Cross-register scaled LEAs are legal at every level and must not trigger it.
    #[test]
    fn in_place_scaled_lea_downgrades_the_cpu_digit() {
        // lea eax,[eax*4+0]; ret  — the -4r signature (WAR2's 0x69fb0..0x6e6e0 module)
        let ev = detect(&lift("8d048500000000c3"), ESP, EBP);
        assert!(ev.in_place_scaled_lea);
        // lea eax,[edx*4+0]; ret  — cross-register, non-evidence
        let ev2 = detect(&lift("8d049500000000c3"), ESP, EBP);
        assert!(!ev2.in_place_scaled_lea);

        let p = watcom_10_0a();
        let f = p.flags_for(&ev);
        assert!(f.contains(&"-4r".to_string()) && !f.contains(&"-5r".to_string()));
        let f2 = p.flags_for(&ev2);
        assert!(f2.contains(&"-5r".to_string()) && !f2.contains(&"-4r".to_string()));
    }
}
