//! Watcom codegen **matcher** — identifies the compiler revision from codegen signals extracted
//! from a binary's disassembly (via mosura's own SLEIGH engine — dogfooding). Where the runtime
//! banner gives only an era and no header field carries the release for DOS/4GW LE output, the
//! generated code does: revisions differ in instruction / register choices for the same source.
//! The `version → fingerprint` table is **measured** from self-compiled ground truth (we know
//! which `wcc386` built each probe; see `docs/watcom-codegen-fingerprint.md`).
//!
//! Two matchers, because the signals behave differently at two scales:
//!
//! - [`identify_watcom`] / [`extract_signals`] — a **single, known** region (the committed probe
//!   artefacts). Here every signal is two-sided and diagnostic: you *know* the region is the
//!   discriminating construct, so byte-form-vs-promoted, loop register, and switch order all
//!   count, and the four revisions classify uniquely.
//!
//! - [`identify_watcom_program`] — a **whole unknown binary**. Instrumenting real code shows the
//!   quirks are *construct*-specific, not compiler-wide: one `wcc386` emits both the promoting
//!   form (for `unsigned char == const`) and plain byte compares (for other shapes), and register
//!   choice varies per site. So at this scale the matcher (a) locates constructs with anchors so
//!   look-alikes (a switch's `CMP EAX,1`) don't fire, and (b) treats the strategy patterns as
//!   **one-sided positive evidence** — the *presence* of `AND EAX,0xff ; CMP EAX,imm` indicates
//!   the 10.0 line, and either `SETcc ; MOVZX` or the inline constant division `MOV r,imm ; CDQ ;
//!   IDIV r` (the `cdq` sign-extension, where the classic 10.0a-11.0 line uses `SAR`) indicates a
//!   revision outside that interior — **9.01 or Open Watcom, not Open Watcom alone**; *absence* is
//!   inconclusive, never a wrong exclusion. It reports a class (often the era, which is what WAR2
//!   needs), not always a single revision. Honest by construction.
//!
//! Signals are `Option` — `None` = "not observed", never contradicts a revision.

use crate::sleigh::Instruction;

/// Codegen signals read from a function/region's disassembly.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Signals {
    /// A byte/`char` comparison: `Some(true)` = promoted to a 32-bit compare (`CMP EAX,imm`),
    /// `Some(false)` = a byte compare (`CMP AL,imm`). The 10.0a→10.6 boundary.
    pub byte_compare_promoted: Option<bool>,
    /// A `setcc`-into-`int` result is zero-extended **with `MOVZX`**: observed at the `SETcc`
    /// site — `Some(true)` when a `MOVZX dword,byte` follows (9.01 and Open Watcom), `Some(false)`
    /// when the `SETcc` result flows on without one.
    ///
    /// ⚠️ READ THE NAME NARROWLY: this is `MOVZX`-specifically, not zero-extension in general.
    /// 10.0a and 10.6 *do* zero-extend the `setcc` result — with `AND EAX,0xff`
    /// (`sete al ; and eax,0ffH`, verbatim from `wdis` on the committed objects). Broadening this
    /// detector to accept the `AND` form would flip both to `Some(true)` and collapse the table's
    /// only discriminator between the classic interior and `{9.01, open}`. The signal is the
    /// *choice of instruction*, which is what varies by revision; whether the value ends up
    /// zero-extended does not.
    ///
    /// 11.0 answers `None` here rather than `Some(false)`: its `cmpbyte` uses a branch
    /// (`cmp al,5 ; jne ; mov eax,1`) and emits no `SETcc` at all, so there is no site to ask.
    pub result_zero_extended: Option<bool>,
    /// The register a counted loop compares its counter against (the loop bound), e.g. `EBX` /
    /// `ECX`. The 10.6→11.0 boundary (`ebx`→`ecx`).
    pub loop_bound_reg: Option<String>,
    /// A switch's compare chain tests its small case constants in **ascending** order
    /// (`CMP r,1 … CMP r,2` = classic) vs descending (`CMP r,2 … CMP r,1` = Open Watcom). The
    /// classic → Open Watcom boundary, independent of the `MOVZX` signal.
    pub sw_cmp_ascending: Option<bool>,
}

const DWORD_REGS: [&str; 8] = ["EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "EBP", "ESP"];
const BYTE_REGS: [&str; 8] = ["AL", "BL", "CL", "DL", "AH", "BH", "CH", "DH"];

fn split2(body: &str) -> (&str, &str) {
    match body.split_once(',') {
        Some((a, b)) => (a.trim(), b.trim()),
        None => (body.trim(), ""),
    }
}
fn is_dword_reg(op: &str) -> bool {
    DWORD_REGS.contains(&op)
}
fn is_byte_reg(op: &str) -> bool {
    BYTE_REGS.contains(&op)
}
/// Parse a small immediate operand (`0x5`, `5`), else `None`.
fn parse_imm(op: &str) -> Option<u64> {
    op.strip_prefix("0x")
        .and_then(|h| u64::from_str_radix(h, 16).ok())
        .or_else(|| op.parse::<u64>().ok())
}
fn is_cond_jump(mnem: &str) -> bool {
    // Signed/unsigned conditional branches SLEIGH renders as J<cc>.
    matches!(mnem, "JL" | "JLE" | "JG" | "JGE" | "JB" | "JBE" | "JA" | "JAE" | "JNZ" | "JZ" | "JNS" | "JS")
}

/// Every construct site's vote, before consensus. A real binary has *many* sites; a
/// codegen-**strategy** signal (byte-compare promotion, setcc zero-extension) is the same at
/// every site, while a register-allocation **artifact** (which register a given loop happens to
/// use) varies site to site. [`consensus`] keeps a signal only when its votes are unanimous, so
/// strategy signals survive and artifact signals self-cancel to `None` instead of corrupting the
/// result — the mechanism that lets the same code match a clean probe *and* a whole binary.
#[derive(Default)]
struct Votes {
    promoted: Vec<bool>,
    zero_extended: Vec<bool>,
    loop_bound: Vec<String>,
    sw_ascending: Vec<bool>,
    /// One entry per **inline constant-divisor signed division** site (`MOV r,imm ; CDQ ; IDIV r`)
    /// — Open Watcom's `cdq` sign-extension idiom, which the 10.x/11.0 line never emits (it uses
    /// `MOV EDX,EAX ; SAR EDX,0x1f`). Purely one-sided positive evidence, so only observed sites
    /// are recorded (there is no "not a division" vote); consumed only by the whole-binary matcher
    /// as additional Open-Watcom evidence, never by the two-sided isolated-probe `consensus`.
    inline_const_div: Vec<bool>,
}

/// A signal is trusted only when every site that observed it agrees; any disagreement (or no
/// observation) yields `None`, which never contradicts a revision.
fn consensus(v: &Votes) -> Signals {
    fn unanimous<T: Clone + PartialEq>(votes: &[T]) -> Option<T> {
        let first = votes.first()?;
        votes.iter().all(|x| x == first).then(|| first.clone())
    }
    Signals {
        byte_compare_promoted: unanimous(&v.promoted),
        result_zero_extended: unanimous(&v.zero_extended),
        loop_bound_reg: unanimous(&v.loop_bound),
        sw_cmp_ascending: unanimous(&v.sw_ascending),
    }
}

/// Scan one disassembled instruction stream and record a vote at **every anchored construct
/// site** — the "construct location" pass. Each signal is anchored so a look-alike does not fire:
/// a byte compare needs a byte register or a preceding byte-mask (a plain int `CMP EAX,1` is
/// ignored), a loop needs a *backward* conditional branch. Accumulates into `v` so a whole binary
/// aggregates across functions.
fn scan_into(instrs: &[Instruction], v: &mut Votes) {
    // Pass 1: addresses that are the target of a backward branch — a loop-header test lands here
    // (the loop's back-edge jumps to it). Covers both loop shapes: bottom-test (the test's own
    // `Jcc` goes backward) and top-test (a later `JMP`/`Jcc` jumps back up to the test).
    let back_targets: std::collections::HashSet<u64> = instrs
        .iter()
        .filter(|ins| ins.mnemonic == "JMP" || is_cond_jump(&ins.mnemonic))
        .filter_map(|ins| parse_imm(&ins.body).filter(|&t| t < ins.address))
        .collect();
    // Per dword-register, the address of the first `CMP reg,1` / `CMP reg,2` (switch discriminator).
    let mut cmp1: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    let mut cmp2: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for (i, ins) in instrs.iter().enumerate() {
        // Open Watcom's inline constant-divisor signed division — anchored, one-sided (see
        // [`inline_const_idiv_at`]). A positive site is Open-Watcom evidence for the whole-binary
        // matcher; never a false vote, so nothing is pushed on the (overwhelmingly common) miss.
        if inline_const_idiv_at(instrs, i) {
            v.inline_const_div.push(true);
        }
        let (op1, op2) = split2(&ins.body);
        match ins.mnemonic.as_str() {
            "CMP" => {
                if let Some(imm) = parse_imm(op2) {
                    if imm <= 0xff {
                        // Byte compare, ANCHORED so an int compare (`CMP EAX,1`) is not counted:
                        //  - a byte register is itself the anchor (byte form);
                        //  - a dword register only counts when the previous instruction masks it
                        //    to a byte (`AND reg,0xff` / `MOVZX reg,byte`), proving a byte value
                        //    is being compared 32-bit-wide (the promotion).
                        if is_byte_reg(op1) {
                            v.promoted.push(false);
                        } else if is_dword_reg(op1) && byte_masked_into(instrs, i, op1) {
                            v.promoted.push(true);
                        }
                    }
                    if is_dword_reg(op1) {
                        if imm == 1 {
                            cmp1.entry(op1.to_string()).or_insert(ins.address);
                        } else if imm == 2 {
                            cmp2.entry(op1.to_string()).or_insert(ins.address);
                        }
                    }
                }
                // Loop bound: a `CMP reg,reg` that is a loop test — its own successor branches
                // backward (bottom-test) OR the compare is itself a backward-branch target
                // (top-test). op2 is the limit the counter is tested against.
                if is_dword_reg(op1) && is_dword_reg(op2) {
                    let bottom_test = instrs.get(i + 1).is_some_and(|n| {
                        is_cond_jump(&n.mnemonic) && parse_imm(&n.body).is_some_and(|t| t <= n.address)
                    });
                    if bottom_test || back_targets.contains(&ins.address) {
                        v.loop_bound.push(op2.to_string());
                    }
                }
            }
            // setcc zero-extension: a `MOVZX dword,byte` right after `SETcc` = extended (Open
            // Watcom); any other successor = not extended (classic).
            m if m.starts_with("SET") => {
                if let Some(next) = instrs.get(i + 1) {
                    let (n1, n2) = split2(&next.body);
                    v.zero_extended
                        .push(next.mnemonic == "MOVZX" && is_dword_reg(n1) && is_byte_reg(n2));
                }
            }
            _ => {}
        }
    }
    // Switch order: a register compared against both 1 and 2 → ascending iff `CMP r,1` precedes.
    for (reg, &a1) in &cmp1 {
        if let Some(&a2) = cmp2.get(reg) {
            v.sw_ascending.push(a1 < a2);
        }
    }
}

/// True iff instruction `i` begins Open Watcom's **inline constant-divisor signed division** —
/// the three-instruction window `MOV reg,imm ; CDQ ; IDIV reg` (same `reg`). This is ow2's
/// sign-extension idiom (`cdq`); the classic 10.x/11.0 line emits the *same* `x/const` construct
/// as `MOV EDX,EAX ; MOV reg,imm ; SAR EDX,0x1f ; IDIV reg` — never `cdq` — so the window is
/// diagnostic of the Open Watcom line (measured across 10.0a/10.6/11.0/ow2, all four **inline**
/// the divide; only the sign-extension differs — see `docs/watcom-codegen-fingerprint.md`).
///
/// The immediate-load guard is what makes it *constant* division and blocks the obvious false
/// positive: ow2's *variable* division is `MOV reg,<reg> ; CDQ ; IDIV reg`, whose pre-`CDQ` move
/// is register-to-register (no immediate), so it does not match. The unsigned constant form
/// (`MOV reg,imm ; XOR EDX,EDX ; DIV reg`) is emitted **identically by every revision** and is
/// deliberately not matched (its `xor edx,edx`/`div` is neither `cdq` nor `idiv`).
fn inline_const_idiv_at(instrs: &[Instruction], i: usize) -> bool {
    let (Some(load), Some(cdq), Some(idiv)) =
        (instrs.get(i), instrs.get(i + 1), instrs.get(i + 2))
    else {
        return false;
    };
    let (dst, src) = split2(&load.body);
    load.mnemonic == "MOV"
        && is_dword_reg(dst)
        && parse_imm(src).is_some()
        && cdq.mnemonic == "CDQ"
        && idiv.mnemonic == "IDIV"
        && idiv.body.trim() == dst
}

/// True iff the dword register `reg` is masked to its low byte immediately before instruction
/// `i` — `AND reg,0xff` or `MOVZX reg,<byte reg>` — i.e. a byte value is about to be compared.
fn byte_masked_into(instrs: &[Instruction], i: usize, reg: &str) -> bool {
    let Some(prev) = i.checked_sub(1).and_then(|p| instrs.get(p)) else { return false };
    let (p1, p2) = split2(&prev.body);
    p1 == reg
        && ((prev.mnemonic == "AND" && parse_imm(p2) == Some(0xff))
            || (prev.mnemonic == "MOVZX" && is_byte_reg(p2)))
}

/// Extract the codegen signals from a disassembled instruction stream (single region). Anchored
/// and unanimity-gated — see [`scan_into`] / [`consensus`].
pub fn extract_signals(instrs: &[Instruction]) -> Signals {
    let mut v = Votes::default();
    scan_into(instrs, &mut v);
    consensus(&v)
}

/// One Watcom revision's measured fingerprint (`None` = the construct was not measured / does not
/// discriminate for that revision).
struct Fp {
    revision: &'static str,
    promoted: Option<bool>,
    zero_extended: Option<bool>,
    loop_bound: Option<&'static str>,
    sw_ascending: Option<bool>,
}

/// The measured `version → fingerprint` table (see `docs/watcom-codegen-fingerprint.md`).
///
/// ⚠️ **9.01 IS NOT AN EXTRAPOLATION OF THE CLASSIC LINE.** It emits the `SETcc ; MOVZX`
/// zero-extension and the `MOV r,imm ; CDQ ; IDIV r` division idiom that 10.0a/10.6/11.0 do not —
/// the same two shapes Open Watcom emits. Those two markers therefore bracket the OUTER ENDS of
/// the lineage, and the interior (10.0a-11.0) is what is unusual, not 9.01. Measured on
/// `oracle/codegen-probes/watcom/9.01.obj`; before this row it classified as **no known revision**
/// (an empty result), which reads as "not Watcom".
const TABLE: &[Fp] = &[
    Fp { revision: "watcom:9.01", promoted: Some(false), zero_extended: Some(true), loop_bound: Some("EBX"), sw_ascending: Some(true) },
    Fp { revision: "watcom:10.0/10.0a", promoted: Some(true), zero_extended: Some(false), loop_bound: Some("EBX"), sw_ascending: Some(true) },
    Fp { revision: "watcom:10.5/10.6", promoted: Some(false), zero_extended: Some(false), loop_bound: Some("EBX"), sw_ascending: Some(true) },
    Fp { revision: "watcom:11.0", promoted: Some(false), zero_extended: Some(false), loop_bound: Some("ECX"), sw_ascending: Some(true) },
    Fp { revision: "watcom:open", promoted: Some(false), zero_extended: Some(true), loop_bound: Some("ECX"), sw_ascending: Some(false) },
];

/// An observed signal contradicts a table value only when both are present and differ; an
/// unobserved (`None`) signal never rules a revision out.
fn consistent<T: PartialEq + ?Sized>(observed: Option<&T>, table: Option<&T>) -> bool {
    match (observed, table) {
        (Some(o), Some(t)) => o == t,
        _ => true,
    }
}

/// The Watcom revision(s) whose fingerprint is consistent with the observed signals. Narrows to a
/// single revision once enough constructs are seen; an empty result means the signals match no
/// known Watcom revision (not Watcom, or a revision outside the table).
pub fn classify(sig: &Signals) -> Vec<&'static str> {
    TABLE
        .iter()
        .filter(|fp| {
            consistent(sig.byte_compare_promoted.as_ref(), fp.promoted.as_ref())
                && consistent(sig.result_zero_extended.as_ref(), fp.zero_extended.as_ref())
                && consistent(sig.loop_bound_reg.as_deref(), fp.loop_bound)
                && consistent(sig.sw_cmp_ascending.as_ref(), fp.sw_ascending.as_ref())
        })
        .map(|fp| fp.revision)
        .collect()
}

/// Disassemble one region with mosura's engine and classify it. `lang_id` is e.g.
/// `x86:LE:32:default`. Used for a single known region (the committed probe artefacts); for a
/// whole binary use [`identify_watcom_program`], which locates the constructs across its functions.
pub fn identify_watcom(lang_id: &str, code: &[u8], base: u64) -> Vec<&'static str> {
    let instrs = crate::sleigh::disassemble(lang_id, code, base).unwrap_or_default();
    classify(&extract_signals(&instrs))
}

/// Identify the Watcom revision that built a whole analyzed [`Program`] — the real matcher. It
/// disassembles each discovered function with mosura's own engine, locates the fingerprint
/// constructs across all of them, and aggregates by unanimity (see [`Votes`]). On a real binary
/// the strategy signals (byte-compare promotion, setcc zero-extension) are consistent and survive,
/// while register-allocation artifacts (the loop-bound register) vary and drop out — so the result
/// is honest: often a *class* (e.g. the promoting 10.0 line = WAR2's era) rather than always a
/// single revision. An empty result means "no Watcom fingerprint found" (not Watcom, or stripped
/// of the constructs).
pub fn identify_watcom_program(program: &crate::analysis::program::Program) -> Vec<&'static str> {
    use crate::decompile::space::Address;
    let mut entries: Vec<u64> =
        program.function_manager.functions().map(|f| f.entry_point().offset).collect();
    entries.sort_unstable();
    let mut votes = Votes::default();
    for (i, &entry) in entries.iter().enumerate() {
        // Window: to the next function, capped (a function rarely exceeds this; the cap bounds
        // stray linear disassembly past the end into padding/data).
        let end = entries.get(i + 1).copied().unwrap_or(entry + 4096).min(entry + 4096);
        let Some(len) = end.checked_sub(entry).map(|n| n as usize).filter(|&n| n > 0) else { continue };
        let code = program.memory.read_window(Address::new(program.default_space, entry), len);
        let instrs = crate::sleigh::disassemble(&program.language_id, &code, entry).unwrap_or_default();
        scan_into(&instrs, &mut votes);
    }
    // Whole-binary evidence is **one-sided**, not the two-sided exclusion the isolated-probe
    // matcher uses. Instrumenting real binaries shows the fingerprint quirks are *construct*-
    // specific, not compiler-wide: a given `wcc386` emits BOTH the promoting form (`AND EAX,0xff ;
    // CMP EAX,imm`, for the `unsigned char == const` shape) AND plain byte compares (`CMP AL,imm`,
    // for other shapes) — real 10.0a code (watcom_hello) is full of the latter. So a byte-form
    // compare is *non-diagnostic* (every version emits it) and must not exclude the promoting
    // line; only the diagnostic PATTERNS count as evidence:
    //   - any `AND EAX,0xff ; CMP EAX,imm` present → evidence of the 10.0 line;
    //   - any `SETcc ; MOVZX`           present → evidence of a revision OUTSIDE the classic
    //                                             10.0a-11.0 interior, i.e. {9.01, open}.
    // Absence of a pattern is inconclusive (returns the un-narrowed set), never a wrong exclusion.
    // The register/loop/switch artifacts are dropped entirely at this scale (see above).
    let promoted = votes.promoted.iter().any(|&p| p).then_some(true);
    // The zero-extension evidence is one-sided and comes from TWO independent, mutually-
    // corroborating constructs — either suffices. The setcc zero-extension (`SETcc ; MOVZX`) and
    // the inline constant-divisor division (`MOV r,imm ; CDQ ; IDIV r` — the `cdq` sign-extension,
    // where the 10.x/11.0 line uses `SAR`) both mark a revision OUTSIDE the classic 10.0a-11.0
    // interior, so either present sets `result_zero_extended` and the table narrows accordingly;
    // neither present leaves it `None` (inconclusive, never a wrong exclusion). The division anchor
    // adds no finer classification — it draws the same boundary the `movzx` signal draws — but
    // division is far more common than the setcc-int construct in a real binary, so it is a more
    // reliably-present anchor when scanning an arbitrary program (robustness).
    //
    // ⚠️ THIS IS NOT AN "OPEN WATCOM" ANCHOR, and calling it one was wrong: **9.01 emits both
    // shapes too** (measured on `9.01.obj` — `cmp al,5 ; sete al ; movzx eax,al` and
    // `mov ebx,7 ; cdq ; idiv ebx`). What separates 9.01 from Open Watcom is the loop-bound
    // register (EBX vs ECX) and the switch compare order — precisely the two register-allocation
    // artifacts this scale drops. So on a whole binary the honest answer is the PAIR
    // `{watcom:9.01, watcom:open}`; narrowing to `watcom:open` alone would be a wrong exclusion of
    // exactly the kind this matcher exists to avoid. See `docs/watcom-codegen-fingerprint.md`.
    let cdq_or_movzx =
        votes.zero_extended.iter().any(|&z| z) || votes.inline_const_div.iter().any(|&d| d);
    let zero_extended = cdq_or_movzx.then_some(true);
    classify(&Signals { byte_compare_promoted: promoted, result_zero_extended: zero_extended, ..Default::default() })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The five measured fingerprints each classify to their revision (self-compiled ground
    /// truth — see `docs/watcom-codegen-fingerprint.md`).
    #[test]
    fn measured_fingerprints_classify_uniquely() {
        let cases: &[(&str, Signals)] = &[
            ("watcom:9.01", Signals { byte_compare_promoted: Some(false), result_zero_extended: Some(true), loop_bound_reg: Some("EBX".into()), sw_cmp_ascending: Some(true) }),
            ("watcom:10.0/10.0a", Signals { byte_compare_promoted: Some(true), result_zero_extended: Some(false), loop_bound_reg: Some("EBX".into()), sw_cmp_ascending: Some(true) }),
            ("watcom:10.5/10.6", Signals { byte_compare_promoted: Some(false), result_zero_extended: Some(false), loop_bound_reg: Some("EBX".into()), sw_cmp_ascending: Some(true) }),
            ("watcom:11.0", Signals { byte_compare_promoted: Some(false), result_zero_extended: Some(false), loop_bound_reg: Some("ECX".into()), sw_cmp_ascending: Some(true) }),
            ("watcom:open", Signals { byte_compare_promoted: Some(false), result_zero_extended: Some(true), loop_bound_reg: Some("ECX".into()), sw_cmp_ascending: Some(false) }),
        ];
        for (rev, sig) in cases {
            assert_eq!(classify(sig), vec![*rev], "signals {sig:?}");
        }
    }

    /// Partial signals narrow but don't over-commit: `cmpbyte` alone (promoted) isolates the
    /// early 10.0 line; without it, the byte-compare revisions all remain candidates.
    #[test]
    fn partial_signals_narrow() {
        let promoted_only = Signals { byte_compare_promoted: Some(true), ..Default::default() };
        assert_eq!(classify(&promoted_only), vec!["watcom:10.0/10.0a"]);
        let byte_only = Signals { byte_compare_promoted: Some(false), ..Default::default() };
        assert_eq!(
            classify(&byte_only),
            vec!["watcom:9.01", "watcom:10.5/10.6", "watcom:11.0", "watcom:open"]
        );
    }

    /// Self-compiled ground truth, committed so the matcher runs without the historical compiler:
    /// each `<rev>.code` is the machine code our probe (`watcom_cg.c`) compiled to under a **known**
    /// Watcom revision (extracted from the OMF object — our own functions, no proprietary runtime).
    /// mosura disassembles the committed bytes and the matcher must classify the known revision.
    #[test]
    fn matches_committed_self_compiled_probes() {
        if crate::lang::load_cached("x86:LE:32:default").is_none() {
            return; // SLEIGH tables unavailable
        }
        let dir = crate::paths::codegen_probes_dir().join("watcom");
        let load = |rev: &str| {
            let code = std::fs::read(dir.join(format!("{rev}.code")))
                .unwrap_or_else(|e| panic!("codegen artefact {rev}.code: {e}"));
            identify_watcom("x86:LE:32:default", &code, 0x1000)
        };
        // Each probe classifies UNIQUELY — the three *discriminating* constructs' signals (compare
        // width, loop register, switch order, zero-extension) draw boundaries at different
        // revisions. (The two appended division constructs contribute no isolated-probe signal —
        // they add a whole-binary anchor only — so appending them leaves these classifications
        // unchanged; that append-only invariant is exactly what this test guards.)
        //
        // 9.01 is the reason uniqueness has to be RE-checked rather than assumed: it shares the
        // `movzx` with ow2 and the `EBX` loop bound + ascending switch with the classic line, so it
        // is separated from every other row by exactly one signal — ow2 by the loop register and
        // the switch order, 10.6 by the `movzx`. Adding it collapsed nothing, but a sixth revision
        // easily could, and an empty or two-element result here is what that would look like.
        assert_eq!(load("9.01"), vec!["watcom:9.01"]); // CMP AL,5 + MOVZX + EBX + ascending
        assert_eq!(load("10.0a"), vec!["watcom:10.0/10.0a"]); // CMP EAX,5 + EBX + ascending
        assert_eq!(load("10.6"), vec!["watcom:10.5/10.6"]); // CMP AL,5 + EBX + ascending
        assert_eq!(load("10.5"), vec!["watcom:10.5/10.6"]); // 10.5 measured, not inferred
        assert_eq!(load("11.0"), vec!["watcom:11.0"]); // CMP AL,5 + ECX + ASCENDING switch (vs open's descending)
        assert_eq!(load("ow2"), vec!["watcom:open"]); // CMP AL,5 + ECX + MOVZX + descending
    }

    /// Why `watcom:10.5/10.6` is ONE row and not two: 10.5 and 10.6 emit **byte-identical code**
    /// for the probe. Not "no signal separates them" — the same 156 bytes.
    ///
    /// This row used to be an *inference*: 10.5's compiler could not be run, so it was bracketed
    /// between the measured 10.0a and 10.6 and the pair was labelled together on the assumption
    /// that nothing changed across it. That assumption is the exact shape this file warns about
    /// elsewhere ("a boundary inferred from the ends of the version set you happen to have is a
    /// boundary of your corpus, not of the compiler"), so it was settled by measurement instead:
    /// `10.5.obj` is compiled by Watcom 10.5's own `wcc386` (see
    /// `docs/watcom-codegen-fingerprint.md` for the recipe — the compiler had to be unpacked from
    /// the install media's `wpack` archives first). The inference happened to be right.
    ///
    /// The two OBJ *containers* do differ, so this is a real second artefact rather than a copy;
    /// only the emitted code coincides. A future revision that splits the row must therefore
    /// produce a probe whose code actually differs — this test says what that would take.
    #[test]
    fn watcom_10_5_and_10_6_emit_identical_probe_code() {
        let dir = crate::paths::codegen_probes_dir().join("watcom");
        let read = |rev: &str| std::fs::read(dir.join(format!("{rev}.code"))).unwrap();
        let (a, b) = (read("10.5"), read("10.6"));
        assert_eq!(a, b, "10.5 and 10.6 probe code diverged — the combined row must be split");
        // The containers are distinct artefacts (version records differ), so the identity above
        // is a fact about codegen, not an accidentally duplicated file.
        assert_ne!(
            std::fs::read(dir.join("10.5.obj")).unwrap(),
            std::fs::read(dir.join("10.6.obj")).unwrap(),
            "10.5.obj is a copy of 10.6.obj — the code identity would then prove nothing"
        );
        // ...and it is not identical to its OTHER neighbours, so "all probes are the same" is not
        // the reason this passes.
        for other in ["10.0a", "11.0", "9.01", "ow2"] {
            assert_ne!(a, read(other), "10.5 probe code matches {other} too");
        }
    }

    /// End-to-end on real encodings mosura's engine decodes. 10.0a's *promoting* cmpbyte is the
    /// anchored pattern `AND EAX,0xff ; CMP EAX,5` (the mask proves a byte is compared 32-bit);
    /// Open Watcom's is `CMP AL,5 ; SETZ AL ; MOVZX EAX,AL`.
    #[test]
    fn disassembles_and_classifies_real_encodings() {
        if crate::lang::load_cached("x86:LE:32:default").is_none() {
            return; // SLEIGH tables unavailable
        }
        // 10.0a promoting cmpbyte: AND EAX,0xff ; CMP EAX,5 ; SETZ AL ; RET → uniquely 10.0 line.
        let v10a = identify_watcom(
            "x86:LE:32:default",
            &[0x25, 0xff, 0, 0, 0, 0x83, 0xF8, 0x05, 0x0F, 0x94, 0xC0, 0xC3],
            0x1000,
        );
        assert_eq!(v10a, vec!["watcom:10.0/10.0a"], "masked promoting compare → {v10a:?}");
        // Byte compare + zero-extend: CMP AL,0x5 ; SETZ AL ; MOVZX EAX,AL ; RET. This is BOTH
        // 9.01's and Open Watcom's `cmpbyte`, and this snippet carries no loop and no switch, so
        // the pair is the correct answer — the two are separated only by the loop-bound register
        // and the switch compare order, neither of which is present here.
        let vmovzx = identify_watcom("x86:LE:32:default", &[0x3C, 0x05, 0x0F, 0x94, 0xC0, 0x0F, 0xB6, 0xC0, 0xC3], 0x1000);
        assert_eq!(
            vmovzx,
            vec!["watcom:9.01", "watcom:open"],
            "byte compare + movzx cannot select between 9.01 and open on its own → {vmovzx:?}"
        );
    }

    /// The construct-location anchoring (the C1 fix): a plain int `CMP EAX,1` — a switch case or
    /// an integer comparison — is **not** read as a promoted byte compare. Without a byte anchor
    /// (byte register, or a preceding `AND reg,0xff` / `MOVZX`) it yields no byte-compare signal,
    /// so it can never falsely narrow (or exclude) a revision.
    #[test]
    fn int_compare_is_not_a_byte_compare() {
        if crate::lang::load_cached("x86:LE:32:default").is_none() {
            return;
        }
        // CMP EAX,0x1 ; RET — a bare int compare.
        let bytes = [0x83, 0xF8, 0x01, 0xC3];
        let ins = crate::sleigh::disassemble("x86:LE:32:default", &bytes, 0x1000).unwrap();
        assert_eq!(extract_signals(&ins).byte_compare_promoted, None, "int compare must not read as a byte compare");
        assert_eq!(identify_watcom("x86:LE:32:default", &bytes, 0x1000).len(), TABLE.len(), "no signal → nothing narrowed/excluded");
    }

    /// The whole-binary matcher over a real analyzed program. `watcom_hello.exe` is genuine 10.0a
    /// but a tiny CRT stub *without* the diagnostic promoting/`movzx` constructs, so the one-sided
    /// matcher is honestly **inconclusive** (the un-narrowed set) — it must never WRONGLY EXCLUDE
    /// the true revision (the earlier two-sided logic did, on a non-diagnostic byte-form compare).
    #[test]
    fn whole_program_matcher_never_wrongly_excludes() {
        if crate::lang::load_cached("x86:LE:32:default").is_none() {
            return;
        }
        let path = crate::paths::analysis_corpus_dir().join("watcom_hello.exe");
        let program = crate::analysis::analyze_file(&path).expect("analyze watcom_hello");
        let cls = identify_watcom_program(&program);
        assert!(
            cls.contains(&"watcom:10.0/10.0a"),
            "real 10.0a binary must not be excluded by a non-diagnostic byte-form compare; got {cls:?}"
        );
    }

    /// Count the inline constant-division anchor sites [`scan_into`] records over a byte stream.
    fn div_anchor_hits(bytes: &[u8]) -> usize {
        let instrs = crate::sleigh::disassemble("x86:LE:32:default", bytes, 0x1000).unwrap();
        let mut v = Votes::default();
        scan_into(&instrs, &mut v);
        v.inline_const_div.iter().filter(|&&d| d).count()
    }

    /// The division anchor fires on the revisions that sign-extend with `CDQ` — **9.01 and Open
    /// Watcom** — and on none of the classic 10.0a-11.0 interior, which inlines the same
    /// `x/const` divide but sign-extends with `MOV EDX,EAX ; SAR EDX,0x1f`.
    ///
    /// ⚠️ This test used to be called `..._fires_on_ow2_not_classic` and its composition assertion
    /// read `vec!["watcom:open"]`. Both were wrong once 9.01 was measured: `9.01.obj` contains
    /// `mov ebx,7 ; cdq ; idiv ebx`, so the anchor is evidence of the lineage's OUTER ENDS, not of
    /// Open Watcom. The 10.0a/10.6/11.0 half of the claim — the half WAR2 actually rests on — is
    /// unchanged and is still asserted below.
    #[test]
    fn inline_const_div_anchor_fires_on_the_cdq_revisions() {
        if crate::lang::load_cached("x86:LE:32:default").is_none() {
            return; // SLEIGH tables unavailable
        }
        let dir = crate::paths::codegen_probes_dir().join("watcom");
        let read = |rev: &str| std::fs::read(dir.join(format!("{rev}.code"))).unwrap();
        assert_eq!(div_anchor_hits(&read("ow2")), 1, "ow2 divc = MOV ECX,7 ; CDQ ; IDIV ECX");
        assert_eq!(div_anchor_hits(&read("9.01")), 1, "9.01 divc = MOV EBX,7 ; CDQ ; IDIV EBX");
        for classic in ["10.0a", "10.6", "11.0"] {
            assert_eq!(
                div_anchor_hits(&read(classic)),
                0,
                "{classic} sign-extends with SAR, not CDQ — anchor must not fire"
            );
        }
        // Composition: a fired anchor is folded into `result_zero_extended`, which excludes the
        // classic interior and leaves the two outer revisions — the honest narrowing.
        let narrowed = Signals { result_zero_extended: Some(true), ..Default::default() };
        assert_eq!(classify(&narrowed), vec!["watcom:9.01", "watcom:open"]);
    }

    /// The division anchor's false-positive guards, on encodings mosura's engine decodes. The
    /// immediate-load requirement is load-bearing: it rejects **variable** division (whose divisor
    /// is a register, not a constant) and the **unsigned** constant form (`XOR EDX,EDX ; DIV`, which
    /// every revision emits identically), and the `cdq` requirement rejects the classic signed form.
    #[test]
    fn inline_const_div_anchor_rejects_lookalikes() {
        if crate::lang::load_cached("x86:LE:32:default").is_none() {
            return; // SLEIGH tables unavailable
        }
        // ow2 VARIABLE signed div: MOV ECX,EDX ; CDQ ; IDIV ECX ; RET — pre-CDQ move is reg→reg,
        // no immediate, so it is not "constant division" and must not fire.
        assert_eq!(div_anchor_hits(&[0x89, 0xd1, 0x99, 0xf7, 0xf9, 0xc3]), 0, "variable division");
        // classic signed CONST div: MOV EDX,EAX ; MOV ECX,7 ; SAR EDX,0x1f ; IDIV ECX ; RET —
        // inlines, but sign-extends with SAR (no CDQ), so it must not fire.
        assert_eq!(
            div_anchor_hits(&[0x89, 0xc2, 0xb9, 0x07, 0, 0, 0, 0xc1, 0xfa, 0x1f, 0xf7, 0xf9, 0xc3]),
            0,
            "classic SAR-form signed constant division"
        );
        // UNSIGNED const div (any revision): MOV ECX,0xa ; XOR EDX,EDX ; DIV ECX ; RET — the divide
        // is DIV (not IDIV) with XOR (not CDQ); emitted identically by every revision, non-diagnostic.
        assert_eq!(
            div_anchor_hits(&[0xb9, 0x0a, 0, 0, 0, 0x31, 0xd2, 0xf7, 0xf1, 0xc3]),
            0,
            "unsigned constant division"
        );
    }

}
