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
use super::x86enc;
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

/// Decide the `unsigned-cmp` sites from the original's own compare immediate
/// ([`crate::decompile::printc::EmitReport::allones_cmp_candidates`]): at the site, an
/// original `CMP`/`TEST` whose FIRST operand is a 32-bit register and whose immediate
/// equals the candidate's width-mask (`CMP EDX,0xff` for a 1-byte constant,
/// `CMP EDX,0xffff` for 2) is the ZERO-EXTENDED spelling — the source compared an
/// unsigned narrow value, and the recovered rendering prints `(uintN)x == 0xffN`. A
/// compare at the CONSTANT'S OWN width (`CMP DL,0xff`) is ambiguous — the imm8 encodes
/// both spellings — and recovers nothing. Target-specific (x86 text forms, this
/// compiler's immediate-width selection), hence beside the Watcom profile.
pub fn unsigned_cmps_from_evidence(
    candidates: &[(u64, u32)],
    insns: &[NormInsn],
) -> std::collections::HashSet<u64> {
    let mut out = std::collections::HashSet::new();
    for &(pc, size) in candidates {
        let mask = (1u64 << (u64::from(size) * 8)) - 1;
        let Some(i) = insns.iter().position(|x| x.addr == pc) else { continue };
        let Some(cmp) = (i.saturating_sub(3)..=i).rev().find_map(|j| {
            let t = &insns[j].text;
            (t.starts_with("CMP ") || t.starts_with("TEST ")).then_some(&insns[j])
        }) else {
            continue;
        };
        // The compared register must be WIDER than the constant for the immediate's value
        // to disambiguate the spelling.
        let wide_reg = cmp
            .text
            .split_whitespace()
            .nth(1)
            .and_then(|ops| ops.split(',').next())
            .is_some_and(|r| r.starts_with('E'));
        if !wide_reg {
            continue;
        }
        let Some(k) = cmp.text.rsplit(',').next().map(str::trim).and_then(|last| {
            let neg = last.starts_with('-');
            let v = u64::from_str_radix(last.trim_start_matches('-').strip_prefix("0x")?, 16).ok()?;
            Some(if neg { v.wrapping_neg() } else { v })
        }) else {
            continue;
        };
        if k == mask {
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

/// The return-declaration witness's verdict: whether the declaration follows the VALUE's width,
/// and whether the evidence says that narrow value is SIGNED.
///
/// `signed` is set ONLY by the sign-extended-constant path ([`sext_narrow_const`]). A function
/// whose every return site writes narrow keeps `signed: false` and therefore exactly today's
/// rendering, so signedness carries no change into any firing that already existed. It matters
/// because the two spellings compile to different code: a signed narrow return sign-extends into
/// the full register (`MOV EAX,0xffff8000`), an unsigned one zero-extends (`MOV EAX,0x8000`), and
/// only the first reproduces what the original hands back to its callers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NarrowReturn {
    /// Declare the return at the value's width instead of the recovered storage width.
    pub narrow: bool,
    /// That narrow declaration is SIGNED (witnessed by a sign-extended constant return).
    pub signed: bool,
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
///   original materializes the widening, which is what the widened declaration compiles to;
/// - EXCEPT a **sign-extended narrow constant** (`MOV EAX,0xffff8000` returning 2 bytes), which
///   is how a signed narrow return carries a constant rather than a widening — it declines to
///   veto and reports [`NarrowReturn::signed`] ([`sext_narrow_const`]).
///
/// Narrow only when every return site reads narrow OR is that constant idiom, AND at least one
/// site is a genuine narrow write — the ANCHOR. Anchoring is what keeps the constant arm honest:
/// a constant alone can look sign-extended at any width, so it may never make a return narrow by
/// itself, and an all-constant-returning function stays wide.
pub fn narrow_return_from_evidence(candidates: &[(u64, u32, u32)], insns: &[NormInsn]) -> NarrowReturn {
    let wide = NarrowReturn::default();
    if candidates.is_empty() {
        return wide;
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
    // ANCHORED-ONLY (the sign-extended-constant arm below): a genuine narrow write must be seen at
    // some return site before a sext-looking constant at another site is read as narrowness.
    let mut anchored = false;
    let mut sext_seen = false;
    for &(ret_pc, narrow_w, _) in candidates {
        let Some(end) = insns.iter().position(|x| x.addr >= ret_pc) else { return wide };
        let Some(last) = insns[..end].iter().rposition(|x| writes_a(&x.text).is_some()) else {
            return wide;
        };
        if writes_a(&insns[last].text) != Some(true) {
            // Full-register write. The widened declaration is right for all but ONE idiom: a
            // SIGN-EXTENDED NARROW CONSTANT, which is how a signed narrow return carries a
            // constant. It never anchors — it can only decline to veto.
            if !sext_narrow_const(&insns[last].text, narrow_w) {
                return wide;
            }
            sext_seen = true;
            continue;
        }
        // A narrow last write PRECEDED by the container zero is the WIDENING IDIOM
        // (`XOR EAX,EAX ; MOV AL,[m] ; RET` — measured on FUN_00031044): the function
        // returns the zero-extended value in full EAX, so the contract is wide. Same
        // consumed-zero scan as `widened_sites_from_evidence`: stop if anything between
        // writes the A family.
        let mut widening = false;
        for x in insns[last.saturating_sub(3)..last].iter().rev() {
            if x.text == "XOR EAX,EAX" {
                widening = true; // wide: the narrow write completes a widening
                break;
            }
            if writes_a(&x.text).is_some() {
                break;
            }
        }
        if widening {
            return wide;
        }
        anchored = true; // a real narrow write, surviving the widening carve-out: this site anchors
    }
    if !anchored {
        return wide;
    }
    // SIGNEDNESS comes only from the sext-constant path. A function whose every return site writes
    // narrow keeps exactly today's rendering (`signed: false`), so this carries no change into any
    // firing that already existed.
    NarrowReturn { narrow: true, signed: sext_seen }
}

/// Whether a full-register A-family write is Watcom's **sign-extended narrow constant** idiom:
/// `MOV EAX,0xffff8000` is the 32-bit sign-extension of the 2-byte `0x8000`, which Watcom
/// materialises in the whole register because `b8 imm32` (5 bytes) beats `66 b8 imm16` (4 bytes
/// plus the operand-size prefix). It is how a SIGNED narrow return carries a constant — the twin
/// of the `XOR EAX,EAX` widening idiom above, read in the other direction (measured on
/// FUN_00043ddc, whose `return -0x8000` path is exactly this).
///
/// **This never makes a return narrow on its own, and that is load-bearing.** `MOV EAX,0xffffffff`
/// is arithmetically the sign-extension of -1 at *every* narrow width, so an unanchored reading
/// would misfire on every `return -1` int function in the corpus. The caller only consults this to
/// decide whether a full-register write VETOES narrowness; a genuine narrow write at some other
/// return site is what anchors the width, so an all-constant-returning function stays wide by
/// construction.
///
/// Only a parseable hex immediate qualifies — never `MOV EAX,[mem]`, whose value is unknown here.
fn sext_narrow_const(text: &str, narrow_w: u32) -> bool {
    if !(1..=3).contains(&narrow_w) {
        return false; // not narrower than the 4-byte container; the shift below would be UB anyway
    }
    let mut it = text.split_whitespace();
    if it.next() != Some("MOV") {
        return false;
    }
    let mut halves = it.next().unwrap_or("").split(',');
    if halves.next() != Some("EAX") {
        return false;
    }
    let Some(src) = halves.next() else { return false };
    if halves.next().is_some() {
        return false; // more than two operands — not the simple constant load
    }
    let Some(hex) = src.strip_prefix("0x") else { return false };
    let Ok(v) = u32::from_str_radix(hex, 16) else { return false };
    let bits = narrow_w * 8;
    let sext = (((v << (32 - bits)) as i32) >> (32 - bits)) as u32;
    sext == v
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
        t.starts_with("PUSHF")
            || t.starts_with("POPF")
            || t.starts_with("CPUID")
            || t.starts_with("IN ")
            || t.starts_with("OUT ")
            // `INT ` with the space: `INT 0x21` (a DOS call) is hand-assembly; a bare `INT3`
            // is not — WAR2's compiled C carries it as the retail assert-trap idiom
            // (`TEST EAX,EAX ; JNZ over ; INT3`: 0x2a4f0, 0x2d7fc, 0x592d8, 0x59344), as
            // alignment padding after a jump-table dispatch (0x484b4), and as `app_fatal`'s
            // own trap body (0x5cf88). All six audited rows emit clean C (no placeholder
            // reaches the TU), so keeping the bare form here silently shrank the recompile
            // denominator by six genuinely compiled functions (wc2src-reconciliation D5;
            // 0x2d7fc is upacket_dispatch, source-matched, MISMATCH 0.336 via --only).
            || t.starts_with("INT ")
            || (t.starts_with("CALL") && t.contains("CS:["))
            // segment-register saves/loads: flat-model compiled C never touches them (the
            // hand-optimized blitters open with PUSH ES — FUN_0007a5b0). EXACT matches:
            // a prefix test here matched PUSH ESI/ESP and flagged 47 verified-compiled
            // functions — the calibration bar caught it before adoption.
            || t == "PUSH ES"
            || t == "PUSH DS"
            || t == "PUSH FS"
            || t == "PUSH GS"
            || t == "POP ES"
            || t == "POP DS"
            || t == "POP FS"
            || t == "POP GS"
            || t.starts_with("MOV ES,")
            || t.starts_with("MOV DS,")
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

/// N1 (wc2src-reconciliation-3): which constant-materialization pcs load the constant into an
/// 8-bit sub-register (`MOV r8,imm8`) — the sites where declaring a constant-join local at its
/// consumer's byte width matches the original (do_unit_move's `MOV DL,9`), vs a 32-bit `MOV
/// EDX,9` where the wide declaration must stay (0x2c9a8). The witness: the instruction at the pc
/// has a p-code op writing a 1-byte register from a constant.
pub fn join_narrow_sites_from_evidence(
    cands: &[u64],
    insns: &[NormInsn],
) -> std::collections::HashSet<u64> {
    let mut out = std::collections::HashSet::new();
    for &pc in cands {
        let Some(insn) = insns.iter().find(|x| x.addr == pc) else { continue };
        let byte_reg_const = insn.sem.iter().any(|op| {
            matches!(op.out, Some(SemArg::Reg(_, 1)))
                && op.ins.iter().any(|a| matches!(a, SemArg::Const(_, _)))
        });
        if byte_reg_const {
            out.insert(pc);
        }
    }
    out
}

/// N3 (wc2src-reconciliation-3): which scaled-index access sites the ORIGINAL addresses with a
/// scaled-index (SIB) operand `[reg*sz + base]` — those are spelled as array subscripts; the rest
/// (the original computed the address into a register with SHL/ADD) keep the pointer arithmetic.
/// Per candidate `(access pc, element size)`: find the instruction at that pc and look for a
/// `*0x<sz> +` / `*0x<sz>]` scaled-operand token in its disassembly (the same text-witness the
/// store-order reader uses). count_remove's `DEC word ptr [EAX*0x2 + 0x8fa50]` matches; 0x19280's
/// `CMP EBX,[EAX + 0x801c8]` (the *4 is a separate instruction) does not.
pub fn array_index_sites_from_evidence(
    cands: &[(u64, u32)],
    insns: &[NormInsn],
) -> std::collections::HashSet<u64> {
    let mut out = std::collections::HashSet::new();
    for &(pc, sz) in cands {
        let Some(insn) = insns.iter().find(|x| x.addr == pc) else { continue };
        let scaled = format!("*0x{sz:x} ");
        let scaled_end = format!("*0x{sz:x}]");
        if insn.text.contains('[') && (insn.text.contains(&scaled) || insn.text.contains(&scaled_end)) {
            out.insert(pc);
        }
    }
    out
}

/// `string-ops` (docs/rep-string-intrinsic-arm.md): which recognized copy/set loops the ORIGINAL
/// actually implements as a repeated string instruction — the byte-exact witness that keeps a
/// hand-written loop of the same shape from being collapsed to a `memcpy`/`memset` call. Per
/// candidate `(REP MOVS pc, element size)`: the instruction at that pc must be `REP`-prefixed
/// (`0xF3`) `MOVS`/`STOS`/`CMPS`/`SCAS` (`0xA4`/`0xA5` = movsb/movsd, `0xA6`/`0xA7` = cmpsb/cmpsd,
/// `0xAA`/`0xAB` = stosb/stosd, `0xAE`/`0xAF` = scasb/scasd).
pub fn string_ops_from_evidence(
    cands: &[(u64, u32)],
    insns: &[NormInsn],
) -> std::collections::HashSet<u64> {
    let mut out = std::collections::HashSet::new();
    for &(pc, _sz) in cands {
        let Some(insn) = insns.iter().find(|x| x.addr == pc) else { continue };
        // a MOVS/CMPS/STOS/SCAS whose ONLY prefix is the `REP`/`REPNE` (`x86enc::string_insn`; LODS
        // is never a candidate) — the raw `F2|F3` + opcode match this witness always had
        if matches!(x86enc::string_insn(&insn.bytes), Some(s) if (s.rep || s.repne) && s.prefixes.len == 1 && s.op != x86enc::StringOp::Lods)
        {
            out.insert(pc);
        }
    }
    out
}

/// Decide the printed arm order of two-arm constant joins from the ORIGINAL's own layout
/// (wc2src D3b). For each candidate `(branch pc, then k, else k)`: find the conditional jump
/// at that address and scan forward a short window for the first instruction materializing
/// either constant. The compiler lays the arm it compiles FIRST directly after the jump, so
/// the else constant appearing first means the original's true-arm is our else-arm — swap.
/// No decision without the witness: an absent or ambiguous readout leaves the site alone.
pub fn arm_swaps_from_evidence(
    cands: &[(u64, u64, u64)],
    insns: &[NormInsn],
) -> std::collections::HashSet<u64> {
    let mut out = std::collections::HashSet::new();
    for &(pc, then_k, else_k) in cands {
        let Some(j) = insns.iter().position(|x| x.addr == pc && x.is_branch) else { continue };
        let first = insns[j + 1..]
            .iter()
            .take(8)
            .take_while(|x| !x.is_call)
            .flat_map(|x| x.consts.iter())
            .find(|&&k| k == then_k || k == else_k);
        if first == Some(&else_k) && then_k != else_k {
            out.insert(pc);
        }
    }
    out
}

/// One ORIGINAL call site's argument-register setup window.
///
/// For each direct CALL, the LAST write to each watcall argument register before the call,
/// in instruction order — the readout for [`param_orders_from_evidence`]. `const_class` is
/// whether every observed setup is a register materialization the source can reorder
/// (`MOV reg,imm`, `MOV reg,reg`, the self-`XOR` zero); a memory LOAD in the window makes
/// the site unusable, because the compiler schedules parameter loads by its own policy
/// (measured: `FUN_00073328` — no pragma order, argument order, or temp materialization
/// moves the `[EBP+8]`/`[EBP+0xc]` load pair; that sub-shape is the parked load-scheduling
/// residual, docs/war2-toolchain-synthesis.md).
#[derive(Debug, Clone)]
pub struct CallSetupSite {
    pub callee: u64,
    pub call_addr: u64,
    /// `(argument-register offset, setup instruction index)` in instruction order.
    pub setups: Vec<(u64, usize)>,
    pub const_class: bool,
}

/// Scan one function's ORIGINAL instructions for direct-call argument-setup windows.
///
/// `arg_regs` is the target's argument-register bases in convention order (watcall:
/// EAX, EDX, EBX, ECX), each owning the 4-byte container `[base, base+4)` so partial
/// writes (`DL`, `AH`) attribute to their register. The backward walk stops at control
/// transfers; instructions that only read (compares, stores) are stepped over — the
/// original interleaves independent statements with argument setup.
pub fn call_setup_sites(insns: &[NormInsn], arg_regs: &[u64]) -> Vec<CallSetupSite> {
    const WINDOW: usize = 16;
    let family = |off: u64, sz: u32| -> Option<u64> {
        arg_regs.iter().copied().find(|&b| off >= b && off + sz as u64 <= b + 4)
    };
    // Which argument register this instruction WRITES, if any: any semantic op whose output
    // lands inside an argument register's container. Flag registers live outside them.
    let writes = |insn: &NormInsn| -> Option<u64> {
        insn.sem.iter().find_map(|op| match op.out {
            Some(SemArg::Reg(o, sz)) => family(o, sz),
            _ => None,
        })
    };
    // A setup the SOURCE can reorder: a constant materialization, a register-to-register
    // copy, or the self-XOR zero. A LOAD (or any arithmetic) is the compiler's scheduling.
    let const_class = |insn: &NormInsn| -> bool {
        match insn.sem.as_slice() {
            [SemOp { opcode: CPUI_COPY, out: Some(SemArg::Reg(..)), ins }] => {
                matches!(ins.as_slice(), [SemArg::Const(..)] | [SemArg::Reg(..)])
            }
            _ => {
                insn.mnemonic == "XOR"
                    && insn.sem.iter().any(|op| {
                        op.opcode == CPUI_INT_XOR
                            && matches!(op.out, Some(SemArg::Reg(..)))
                            && matches!(op.ins.as_slice(),
                                [SemArg::Reg(a, s1), SemArg::Reg(b, s2)] if a == b && s1 == s2)
                    })
            }
        }
    };
    let mut out = Vec::new();
    for (i, call) in insns.iter().enumerate() {
        if !call.is_call {
            continue;
        }
        let Some(callee) = call.target else { continue };
        let mut seen: Vec<(u64, usize, bool)> = Vec::new();
        for j in (i.saturating_sub(WINDOW)..i).rev() {
            let insn = &insns[j];
            if insn.is_call || insn.is_branch {
                break;
            }
            if let Some(reg) = writes(insn) {
                if !seen.iter().any(|&(r, ..)| r == reg) {
                    seen.push((reg, j, const_class(insn)));
                }
            }
        }
        if seen.len() < 2 {
            continue;
        }
        let all_const = seen.iter().all(|&(.., c)| c);
        seen.sort_by_key(|&(_, j, _)| j);
        out.push(CallSetupSite {
            callee,
            call_addr: call.addr,
            setups: seen.iter().map(|&(r, j, _)| (r, j)).collect(),
            const_class: all_const,
        });
    }
    out
}

/// Decide each SITE's declared parameter order from its own setup sequence.
///
/// The compiler generates register-parameter materializations in REVERSE declared order
/// (Open Watcom `bldcall.c`: `AssgnParms` reverses the parm list before `ParmIns`;
/// probe-verified three ways on `FUN_0004d0f8` — `parm [edx] [ebx] [eax]` with arguments
/// permuted to keep every value in its original register reproduces the original's
/// `MOV EAX / MOV EBX / MOV EDX` sequence byte-exactly). So the original's setup order at a
/// call site is the reverse of the parameter order its source declared, and our slot-order
/// rendering diverges exactly where the source's order was not storage order.
///
/// PER SITE, not per callee — measured (sb94 first cut): a per-callee two-thirds consensus
/// broke two EXACT callers whose own sites read slot order, because other sites' majority
/// overrode a direct readout that was sitting right there. Different TUs may carry
/// different declaration orders for one callee without inconsistency: the pragma and the
/// argument permutation are emitted together per TU, so every TU's bindings are internally
/// correct, exactly like the caller-side register contracts. (Why one callee's sites can
/// disagree at all — `FUN_00058bec`: eight sites read `EAX,EBX,EDX`, two read `EAX,EDX,EBX`
/// — is unresolved; per-site follows the bytes either way.) Returns
/// `call address → declared parameter order` (register offsets) for const-class sites.
pub fn param_orders_from_evidence(
    sites: &[CallSetupSite],
) -> std::collections::HashMap<u64, Vec<u64>> {
    sites
        .iter()
        .filter(|s| s.const_class)
        .map(|s| (s.call_addr, s.setups.iter().rev().map(|&(r, _)| r).collect()))
        .collect()
}

/// Decide which globals were declared VOLATILE, from the original's instruction order at
/// each store site.
///
/// Which globals were declared VOLATILE — decided by the scheduler MODEL
/// ([`super::watsched`]), not by calibrated order-heuristics.
///
/// The original's per-block instruction order is a fixed point of its own compiler's
/// scheduler under the constraints the source imposed. Re-simulating a window with NO
/// barriers and getting a DIFFERENT order proves a constraint existed; a stored global
/// whose barrier alone reproduces the original identifies it as volatile (redefby.c:144
/// — volatile is a full ordering barrier — plus scinfo.c's scoreboard, which is why a
/// SPURIOUS volatile also flips register-reuse stores to immediate forms). Several
/// barriers can each singly explain one window (a load pinned by the store above it and
/// by its own source global below); barriers are monotone for order, and the both-marked
/// probe on FUN_00034590 measured EXACT, so every single-barrier explanation is marked.
///
/// This replaced a five-round calibrated gate stack (trajectory −28 → −8 → −5 → +2 → +1
/// EXACT, byte-exact-status.md sb95) whose gates were each approximations of the one
/// question the model answers directly: WOULD the scheduler have moved anything here?
pub fn volatile_globals_from_evidence(insns: &[NormInsn]) -> std::collections::HashSet<u64> {
    super::watsched::volatile_globals(insns)
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
const CPUI_INT_XOR: u32 = 26;

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
    /// N1 witness: `MOV DL,9` (8-bit) is a narrow site; `MOV EDX,9` (32-bit) is not.
    #[test]
    fn join_narrow_witness_reads_the_register_width() {
        // b209 = MOV DL,9 (8-bit imm to sub-register); ba09000000 = MOV EDX,9 (32-bit)
        let dl = lift("b209");   // one insn at 0x1000
        let edx = lift("ba09000000");
        assert_eq!(join_narrow_sites_from_evidence(&[0x1000], &dl), std::collections::HashSet::from([0x1000]));
        assert!(join_narrow_sites_from_evidence(&[0x1000], &edx).is_empty());
    }

    /// The sign-extended-constant arm is ANCHORED-ONLY: it neutralises a full-register write's veto
    /// when another return site writes narrow, and never creates narrowness by itself.
    #[test]
    fn sext_constant_return_site_does_not_veto_when_another_site_writes_narrow() {
        // b80080ffff MOV EAX,0xffff8000 ; c3 RET ; 668b4002 MOV AX,[EAX+2] ; c3 RET
        let ev = lift("b80080ffffc3668b4002c3");
        // both RETURN sites, logical width 2, recovered storage 4 (FUN_00043ddc's shape)
        let v = narrow_return_from_evidence(&[(0x1005, 2, 4), (0x100a, 2, 4)], &ev);
        assert!(v.narrow, "the sext constant must not veto when another site writes narrow");
        assert!(v.signed, "the sext-constant path witnesses a SIGNED narrow return");
    }

    /// The control that makes the arm safe: with NO narrow write anywhere, sign-extended constants
    /// alone leave the return WIDE. `MOV EAX,0xffffffff` is the sext of -1 at every width, so an
    /// unanchored reading would narrow every `return -1` int function in the corpus.
    #[test]
    fn sext_constants_alone_never_narrow_a_return() {
        // b80080ffff MOV EAX,0xffff8000 ; c3 ; b8ffffffff MOV EAX,0xffffffff ; c3
        let ev = lift("b80080ffffc3b8ffffffffc3");
        assert!(!narrow_return_from_evidence(&[(0x1005, 2, 4), (0x100b, 2, 4)], &ev).narrow);
    }

    /// A full-register constant that is NOT the sign-extension at the anchored width still vetoes:
    /// `MOV EAX,0x8000` zero-extends the same 2 bytes, which is the widening the declaration keeps.
    #[test]
    fn a_non_sext_full_register_constant_still_vetoes() {
        // b800800000 MOV EAX,0x8000 ; c3 ; 668b4002 MOV AX,[EAX+2] ; c3
        let ev = lift("b800800000c3668b4002c3");
        assert!(!narrow_return_from_evidence(&[(0x1005, 2, 4), (0x100a, 2, 4)], &ev).narrow);
    }

    /// Only a parseable immediate qualifies — a full-register load from memory has no known value
    /// and keeps its veto.
    #[test]
    fn a_full_register_memory_load_is_not_a_sext_constant() {
        // a134120000 MOV EAX,[0x1234] ; c3 ; 668b4002 MOV AX,[EAX+2] ; c3
        let ev = lift("a134120000c3668b4002c3");
        assert!(!narrow_return_from_evidence(&[(0x1005, 2, 4), (0x100a, 2, 4)], &ev).narrow);
    }

    /// Signedness comes ONLY from the sext-constant path: a return narrowed on narrow-write
    /// evidence alone keeps today's rendering (`signed: false`), so no pre-existing firing changes
    /// spelling when the signed half lands.
    #[test]
    fn narrow_writes_alone_witness_no_signedness() {
        // 668b4002 MOV AX,[EAX+2] ; c3 ; 668b4004 MOV AX,[EAX+4] ; c3
        let ev = lift("668b4002c3668b4004c3");
        let v = narrow_return_from_evidence(&[(0x1004, 2, 4), (0x1009, 2, 4)], &ev);
        assert!(v.narrow, "two narrow writes still narrow the return");
        assert!(!v.signed, "narrow writes alone say nothing about signedness");
    }

    /// N3 witness: a `*0x4` scaled-index operand is a subscript site; a plain `[reg + const]` is not.
    #[test]
    fn array_index_witness_reads_the_scaled_operand() {
        // ff048500900000 = INC dword ptr [EAX*4 + 0x9000] (SIB, scale 4)
        let sib = lift("ff048500900000");
        assert_eq!(array_index_sites_from_evidence(&[(0x1000, 4)], &sib), std::collections::HashSet::from([0x1000]));
        // wrong element size (2) does not match a *0x4 operand
        assert!(array_index_sites_from_evidence(&[(0x1000, 2)], &sib).is_empty());
        // ff80c8010800 = INC dword ptr [EAX + 0x801c8] (no scale)
        let plain = lift("ff80c8010800");
        assert!(array_index_sites_from_evidence(&[(0x1000, 4)], &plain).is_empty());
    }

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

    /// Watcall argument-register bases (x86:LE:32 register-space offsets), convention order.
    const ARG_REGS: [u64; 4] = [0x0, 0x8, 0xc, 0x4];

    /// The FUN_0004d0f8 shape: three constant materializations before a call are read in
    /// instruction order, and the declared parameter order is their REVERSE (the compiler
    /// generates register parameters back-to-front).
    #[test]
    fn call_setup_order_reads_and_reverses_into_a_declaration_order() {
        // mov eax,0xbe2 ; mov ebx,0x4d08c ; mov edx,3 ; call 0x2000 ; ret
        let insns = lift("b8e20b0000bb8cd00400ba03000000e8ec0f0000c3");
        let sites = call_setup_sites(&insns, &ARG_REGS);
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].callee, 0x2000);
        assert!(sites[0].const_class);
        let order: Vec<u64> = sites[0].setups.iter().map(|&(r, _)| r).collect();
        assert_eq!(order, vec![0x0, 0xc, 0x8]); // EAX, EBX, EDX — the original's setup order
        let p = param_orders_from_evidence(&sites);
        assert_eq!(p[&sites[0].call_addr], vec![0x8, 0xc, 0x0]); // parm [edx] [ebx] [eax]
    }

    /// A memory load in the window makes the site unusable: parameter-load scheduling is the
    /// compiler's own policy (the parked residual), not a source-order readout.
    #[test]
    fn a_load_in_the_window_disqualifies_the_site() {
        // mov edx,[0x11f18] ; mov eax,5 ; call 0x2000
        let insns = lift("8b1518f10100b805000000e8f00f0000");
        let sites = call_setup_sites(&insns, &ARG_REGS);
        assert_eq!(sites.len(), 1);
        assert!(!sites[0].const_class);
        assert!(param_orders_from_evidence(&sites).is_empty());
    }

    /// The window stops at an intervening call — a register set up before it belongs to that
    /// call's own site, not this one's. The self-XOR zero counts as a reorderable setup.
    #[test]
    fn an_intervening_call_bars_the_window_and_self_xor_is_a_setup() {
        // xor ebx,ebx ; call 0x2000 ; xor edx,edx ; mov eax,3 ; call 0x3000 ; ret
        let insns = lift("31dbe8f90f000031d2b803000000e8ed1f0000c3");
        let sites = call_setup_sites(&insns, &ARG_REGS);
        // the 0x2000 site has only one visible setup — no order information, dropped
        assert_eq!(sites.len(), 1);
        assert_eq!(sites[0].callee, 0x3000);
        assert!(sites[0].const_class);
        let order: Vec<u64> = sites[0].setups.iter().map(|&(r, _)| r).collect();
        assert_eq!(order, vec![0x8, 0x0]); // EDX, EAX
    }

    /// Each site is its own direct readout — sites of ONE callee may legitimately derive
    /// different orders (measured: a per-callee majority broke two EXACT callers whose own
    /// sites read slot order), and a non-const site derives nothing.
    #[test]
    fn each_site_is_its_own_readout() {
        let site = |addr: u64, order: &[u64], cc: bool| CallSetupSite {
            callee: 0x2000,
            call_addr: addr,
            setups: order.iter().map(|&r| (r, 0)).collect(),
            const_class: cc,
        };
        let sites = vec![
            site(0x1000, &[0x0, 0xc, 0x8], true),
            site(0x1100, &[0x0, 0x8, 0xc], true),
            site(0x1200, &[0x0, 0x8, 0xc], false),
        ];
        let p = param_orders_from_evidence(&sites);
        assert_eq!(p[&0x1000], vec![0x8, 0xc, 0x0]);
        assert_eq!(p[&0x1100], vec![0xc, 0x8, 0x0]);
        assert!(!p.contains_key(&0x1200));
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

/// `sdiv-pow2` (docs/sdiv-pow2-arm.md): keep the candidate shift pcs whose ORIGINAL instruction is
/// `SAR r/m32, imm8` (`C1 /7 ib`; `D1 /7` for a count of 1) by the candidate's count, immediately
/// preceded by an `SBB` (`1B /r` or `19 /r`) — Watcom 10.0a's signed power-of-two division
/// template. A plain arithmetic shift in the source has no `SBB` before it.
pub fn sdiv_pow2_from_evidence(cands: &[(u64, u32)], insns: &[NormInsn]) -> std::collections::HashSet<u64> {
    let mut out = std::collections::HashSet::new();
    for &(pc, n) in cands {
        let Some(i) = insns.iter().position(|x| x.addr == pc) else { continue };
        let b = &insns[i].bytes;
        // `SAR r32, imm8 = C1 /7 ib` or `SAR r32, 1 = D1 /7` (dword, register-direct) by exactly `n`.
        // `shift_imm` skips the legacy prefixes, so a segment-prefixed SAR (`2E C1 F8 ib`) decodes
        // here where the raw first-byte match this witness had refused it — Watcom never emits one
        // (identity diff clean at R3); the operand-size check keeps the word form out.
        let is_sar = matches!(
            x86enc::shift_imm(b),
            Some(sh) if sh.kind == x86enc::Shift::Sar && sh.opsize == 32 && sh.modrm.is_register_direct() && sh.count as u32 == n
        );
        let prev_sbb = i > 0 && x86enc::is_sbb_rr(&insns[i - 1].bytes);
        if is_sar && prev_sbb {
            out.insert(pc);
        }
    }
    out
}

/// `frame-fill` (docs/compilable-c-remediation.md Phase 10b): the original prologue's frame —
/// `(the SUB ESP immediate, the number of PUSHes before it)` — read from the first instructions.
/// `None` when no `SUB ESP,imm` opens the frame within the first eight instructions (a
/// frameless function, or one whose frame is built otherwise).
/// `sparse-switch`: the compare witness — for every conditional jump, the immediate of the CMP
/// (or `TEST r,r` = 0) whose flags it consumes and the jump's kind in the `x OP imm` orientation:
/// JB/JAE (`CF`) = `CMP_LT`, JBE/JA (`CF|ZF`) = `CMP_LE`, JE/JNE (`ZF`) = `CMP_EQ`, with the signed
/// JL/JGE and JLE/JG alike. Keyed by the jump's pc and, for the first jump after a CMP, by the
/// CMP's pc as well (Ghidra puts the flag compare at the CMP and a derived compare at the jump).
pub fn sparse_cmps_from_evidence(insns: &[NormInsn]) -> std::collections::HashMap<u64, (u64, u8, (u64, u32))> {
    const LT: u8 = 0;
    const LE: u8 = 1;
    const EQ: u8 = 2;
    let mut out = std::collections::HashMap::new();
    let mut last: Option<(u64, u64, bool, (u64, u32))> = None; // (cmp pc, imm, first jump seen, compared register)
    let dbg = crate::debug::on(crate::debug::Topic::SparseSwitch);
    debug!(crate::debug::Topic::SparseSwitch, "witness: {} insns; first: {:?}", insns.len(), insns.iter().take(6).map(|i| (format!("{:#x}", i.addr), i.mnemonic.clone(), i.bytes.clone(), i.consts.clone())).collect::<Vec<_>>());
    for insn in insns {
        let b = &insn.bytes;
        let m = insn.mnemonic.to_ascii_uppercase();
        if dbg && (m == "CMP" || m == "TEST" || b.first().is_some_and(|&x| (0x70..=0x7f).contains(&x)) || b.first() == Some(&0x0f)) {
            debug!(crate::debug::Topic::SparseSwitch, "witness:   {:#x} {m} bytes {:02x?} consts {:?} regs {:?}", insn.addr, b, insn.consts, insn.regs);
        }
        // the jump's kind from its encoding (`x86enc::jcc`): JB/JAE and JL/JGE fold to LT, JBE/JA
        // and JLE/JG to LE, JE/JNE to EQ — the signed/unsigned distinction is not this witness's
        if let Some(j) = x86enc::jcc(b) {
            let kind = match j.cond {
                x86enc::Cond::Below | x86enc::Cond::Less => LT,
                x86enc::Cond::BelowOrEqual | x86enc::Cond::LessOrEqual => LE,
                x86enc::Cond::Equal => EQ,
                _ => continue,
            };
            if let Some((cpc, imm, seen, reg)) = last {
                out.insert(insn.addr, (imm, kind, reg));
                if !seen {
                    out.insert(cpc, (imm, kind, reg));
                    last = Some((cpc, imm, true, reg));
                }
            }
            continue;
        }
        // the CMP's immediate from its encoding (`x86enc::alu_imm` `/7`: `3C ib`, `3D iz`,
        // `80/81/83 /7`, the `83` imm8 sign-extended to the operand size, `iz` = 16 bits under
        // `66`) — the SLEIGH constant list also carries the flag arithmetic's constants and a
        // memory operand's displacement; `TEST r,r` (`x86enc::test_rr`) compares against 0
        let cmp_imm = x86enc::alu_imm(b, 7).map(|imm| imm.value);
        let test_rr = x86enc::test_rr(b).is_some();
        // the compared operand: the first general register the instruction names (x86's flag
        // registers sit at offsets 0x200+); a memory operand leaves it unnamed
        let reg = insn.regs.iter().copied().find(|&(off, _)| off < 0x100).unwrap_or((u64::MAX, 0));
        if m == "CMP" && cmp_imm.is_some() {
            last = Some((insn.addr, cmp_imm.unwrap(), false, reg));
        } else if m == "TEST" && test_rr {
            last = Some((insn.addr, 0, false, reg));
        } else if !matches!(m.as_str(), "MOV" | "MOVZX" | "MOVSX" | "LEA" | "JMP" | "PUSH" | "POP" | "NOP") {
            last = None; // anything that may write flags ends the compare's reach
        }
        if dbg {
            if let Some((cpc, imm, _, reg)) = last {
                if cpc == insn.addr { debug!(crate::debug::Topic::SparseSwitch, "witness:   -> compare at {:#x} imm {imm:#x} reg {reg:?}", insn.addr); }
            }
        }
    }
    out
}

/// `struct-copy`: runs of PLAIN `MOVSD` (opcode A5 with no REP prefix, one byte each) — Watcom's
/// struct assignment at or below its unroll threshold. Start pc → run length k (k >= 2).
pub fn movsd_runs_from_evidence(insns: &[NormInsn]) -> std::collections::HashMap<u64, u32> {
    let mut out = std::collections::HashMap::new();
    let mut start: Option<(u64, u32)> = None;
    for insn in insns {
        let plain = x86enc::is_plain_movsd(&insn.bytes);
        match (plain, start) {
            (true, Some((pc, k))) if insn.addr == pc + k as u64 => start = Some((pc, k + 1)),
            (true, _) => {
                if let Some((pc, k)) = start.filter(|&(_, k)| k >= 2) {
                    out.insert(pc, k);
                }
                start = Some((insn.addr, 1));
            }
            (false, Some((pc, k))) => {
                if k >= 2 {
                    out.insert(pc, k);
                }
                start = None;
            }
            (false, None) => {}
        }
    }
    if let Some((pc, k)) = start.filter(|&(_, k)| k >= 2) {
        out.insert(pc, k);
    }
    out
}

pub fn frame_from_evidence(insns: &[NormInsn]) -> Option<(u32, u32)> {
    let mut pushes = 0u32;
    for insn in insns.iter().take(8) {
        let b = &insn.bytes;
        if x86enc::push_r32(b).is_some() {
            pushes += 1;
            continue;
        }
        if let Some(frame) = x86enc::sub_esp_imm(b) {
            return Some((frame, pushes));
        }
    }
    None
}
