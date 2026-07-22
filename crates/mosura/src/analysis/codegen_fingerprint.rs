//! Watcom codegen **matcher** — identifies the compiler revision from codegen signals extracted
//! from a binary's disassembly (via mosura's own SLEIGH engine — dogfooding). Where the runtime
//! banner gives only an era and no header field carries the release for DOS/4GW LE output, the
//! generated code does: revisions differ in instruction / register choices for the same source.
//!
//! The `version → fingerprint` table below is **measured** (self-compiled binaries are the ground
//! truth — we know which `wcc386` built them; see `docs/watcom-codegen-fingerprint.md`). The
//! matcher scans disassembly for the same signals and reports the consistent revision(s).
//!
//! Signals are `Option` — `None` means "not observed in the scanned code", so an unobserved
//! signal never contradicts a revision. Each construct draws its boundary at a different revision,
//! so together they narrow the answer (no single one separates all four).

use crate::sleigh::Instruction;

/// Codegen signals read from a function/region's disassembly.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct Signals {
    /// A byte/`char` comparison: `Some(true)` = promoted to a 32-bit compare (`CMP EAX,imm`),
    /// `Some(false)` = a byte compare (`CMP AL,imm`). The 10.0a→10.6 boundary.
    pub byte_compare_promoted: Option<bool>,
    /// A `setcc`-into-`int` result is zero-extended (`SETZ AL ; MOVZX EAX,AL`). `Some(true)` is
    /// the Open Watcom form; the classic line omits the `MOVZX`.
    pub result_zero_extended: Option<bool>,
    /// The register a counted loop compares its counter against (the loop bound), e.g. `EBX` /
    /// `ECX`. The 10.6→11.0 boundary (`ebx`→`ecx`).
    pub loop_bound_reg: Option<String>,
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

/// Extract the codegen signals from a disassembled instruction stream.
pub fn extract_signals(instrs: &[Instruction]) -> Signals {
    let mut s = Signals::default();
    for (i, ins) in instrs.iter().enumerate() {
        let (op1, op2) = split2(&ins.body);
        match ins.mnemonic.as_str() {
            "CMP" => {
                // byte-compare-promotion: first CMP of a register against a byte-range immediate.
                if s.byte_compare_promoted.is_none() {
                    if let Some(imm) = parse_imm(op2) {
                        if imm <= 0xff && (is_dword_reg(op1) || is_byte_reg(op1)) {
                            s.byte_compare_promoted = Some(is_dword_reg(op1));
                        }
                    }
                }
                // loop bound: CMP reg,reg immediately before a conditional jump (loop condition).
                if s.loop_bound_reg.is_none()
                    && is_dword_reg(op1)
                    && is_dword_reg(op2)
                    && instrs.get(i + 1).is_some_and(|n| is_cond_jump(&n.mnemonic))
                {
                    s.loop_bound_reg = Some(op2.to_string());
                }
            }
            // zero-extended boolean result: MOVZX EAX,AL right after a SETcc AL.
            "MOVZX" if is_dword_reg(op1) && is_byte_reg(op2) => {
                let prev_setcc = i
                    .checked_sub(1)
                    .and_then(|p| instrs.get(p))
                    .is_some_and(|p| p.mnemonic.starts_with("SET"));
                if prev_setcc {
                    s.result_zero_extended = Some(true);
                }
            }
            _ => {}
        }
    }
    s
}

/// One Watcom revision's measured fingerprint (`None` = the construct was not measured / does not
/// discriminate for that revision).
struct Fp {
    revision: &'static str,
    promoted: Option<bool>,
    zero_extended: Option<bool>,
    loop_bound: Option<&'static str>,
}

/// The measured `version → fingerprint` table (see `docs/watcom-codegen-fingerprint.md`).
const TABLE: &[Fp] = &[
    Fp { revision: "watcom:10.0/10.0a", promoted: Some(true), zero_extended: Some(false), loop_bound: Some("EBX") },
    Fp { revision: "watcom:10.5/10.6", promoted: Some(false), zero_extended: Some(false), loop_bound: Some("EBX") },
    Fp { revision: "watcom:11.0", promoted: Some(false), zero_extended: Some(false), loop_bound: Some("ECX") },
    Fp { revision: "watcom:open", promoted: Some(false), zero_extended: Some(true), loop_bound: Some("ECX") },
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
        })
        .map(|fp| fp.revision)
        .collect()
}

/// Disassemble `code` with mosura's engine and classify the Watcom revision — the end-to-end
/// matcher. `lang_id` is e.g. `x86:LE:32:default`.
pub fn identify_watcom(lang_id: &str, code: &[u8], base: u64) -> Vec<&'static str> {
    let instrs = crate::sleigh::disassemble(lang_id, code, base).unwrap_or_default();
    classify(&extract_signals(&instrs))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four measured fingerprints each classify to their revision (self-compiled ground
    /// truth — see `docs/watcom-codegen-fingerprint.md`).
    #[test]
    fn measured_fingerprints_classify_uniquely() {
        let cases: &[(&str, Signals)] = &[
            ("watcom:10.0/10.0a", Signals { byte_compare_promoted: Some(true), result_zero_extended: Some(false), loop_bound_reg: Some("EBX".into()) }),
            ("watcom:10.5/10.6", Signals { byte_compare_promoted: Some(false), result_zero_extended: Some(false), loop_bound_reg: Some("EBX".into()) }),
            ("watcom:11.0", Signals { byte_compare_promoted: Some(false), result_zero_extended: Some(false), loop_bound_reg: Some("ECX".into()) }),
            ("watcom:open", Signals { byte_compare_promoted: Some(false), result_zero_extended: Some(true), loop_bound_reg: Some("ECX".into()) }),
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
        assert_eq!(classify(&byte_only), vec!["watcom:10.5/10.6", "watcom:11.0", "watcom:open"]);
    }

    /// End-to-end: real encodings disassembled by mosura's engine → signals → classify. 10.0a's
    /// promoting `cmpbyte` (`CMP EAX,5 ; SETZ AL ; RET`) vs Open Watcom's (`CMP AL,5 ; SETZ AL ;
    /// MOVZX EAX,AL ; RET`).
    #[test]
    fn disassembles_and_classifies_real_encodings() {
        if crate::lang::load("x86:LE:32:default").is_none() {
            return; // SLEIGH tables unavailable
        }
        // 10.0a cmpbyte: CMP EAX,0x5 ; SETZ AL ; RET
        let v10a = identify_watcom("x86:LE:32:default", &[0x83, 0xF8, 0x05, 0x0F, 0x94, 0xC0, 0xC3], 0x1000);
        assert!(v10a.contains(&"watcom:10.0/10.0a"), "10.0a cmpbyte → {v10a:?}");
        assert!(!v10a.contains(&"watcom:open"), "must exclude open (promoted) → {v10a:?}");
        // Open Watcom cmpbyte: CMP AL,0x5 ; SETZ AL ; MOVZX EAX,AL ; RET
        let vopen = identify_watcom("x86:LE:32:default", &[0x3C, 0x05, 0x0F, 0x94, 0xC0, 0x0F, 0xB6, 0xC0, 0xC3], 0x1000);
        assert!(vopen.contains(&"watcom:open"), "open cmpbyte → {vopen:?}");
        assert!(!vopen.contains(&"watcom:10.0/10.0a"), "must exclude 10.0a (byte compare) → {vopen:?}");
    }
}
