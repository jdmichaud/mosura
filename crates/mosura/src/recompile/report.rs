//! One measurement run, one fact table — so questions about the population are queries.
//!
//! The census answers "which class dominates each function". That is one level too coarse to
//! act on, and the coarseness has real consequences: a candidate that allocated other registers
//! does not push and pop the same callee-saved ones, so the aligner reports those pushes as
//! [`DivergenceClass::Missing`] — the wrong-code class — when the actual defect is register
//! allocation. A per-function dominant class cannot separate those, so a work-list built from it
//! can point the whole effort at the wrong problem.
//!
//! What separates them is the divergence itself: which instruction, where in the stream, against
//! what. This module emits exactly that, one row per divergence, alongside one row per function.
//! Everything downstream — census, priorities, "did this change help" — is then a query over two
//! tables rather than another bespoke script, which is what the accumulated `census.py`,
//! `classify_diffs.py`, `classify_effects.py`, `audit.py` and `diffruns.py` were each written to
//! be.
//!
//! The schema is deliberately architecture-neutral: mnemonics and rendered operands come from
//! whatever SLEIGH produced, and no column assumes x86.

use super::align::{AlignOp, DivergenceClass, FnDiff};
use super::insn::NormInsn;
use std::fmt::Write as _;

/// Identity of the function a row belongs to.
#[derive(Debug, Clone)]
pub struct FnKey {
    /// Manifest index — the stable per-function id that names its source and object.
    pub idx: String,
    /// Address in the original image.
    pub va: u64,
    pub name: String,
}

/// TSV header for the per-divergence table.
pub const DIVERGENCE_HEADER: &str =
    "idx\tfn_va\tclass\taddr\toi\tci\torig_n\tcand_n\torig_mn\tcand_mn\torig_regs\tcand_regs\torig_text\tcand_text\n";

/// Append one row per divergence in `diff`.
///
/// `oi`/`ci` are the positions in the original and candidate instruction streams (`-1` where the
/// side has no instruction), and `orig_n`/`cand_n` their lengths. Position is what makes the
/// prologue/epilogue question answerable without this module having to guess where a prologue
/// ends — a caller can ask "is this among the first three instructions" itself, and the answer
/// stays true for an architecture whose prologue looks nothing like x86's.
pub fn write_divergence_rows(out: &mut String, key: &FnKey, diff: &FnDiff, orig: &[NormInsn], cand: &[NormInsn]) {
    let (n, m) = (orig.len(), cand.len());
    for op in &diff.ops {
        let (class, oi, ci) = match op {
            AlignOp::Pair { oi, ci, class } => {
                if *class == DivergenceClass::Equal {
                    continue;
                }
                (*class, Some(*oi), Some(*ci))
            }
            AlignOp::OrigOnly { oi } => (DivergenceClass::Missing, Some(*oi), None),
            AlignOp::CandOnly { ci } => (DivergenceClass::Extra, None, Some(*ci)),
        };
        let o = oi.map(|i| &orig[i]);
        let c = ci.map(|i| &cand[i]);
        // The original's address where there is one; otherwise the candidate's, which is in the
        // original's coordinate system too once the object has been relinked.
        let addr = o.map(|x| x.addr).or_else(|| c.map(|x| x.addr)).unwrap_or(0);
        let _ = writeln!(
            out,
            "{}\t{:08x}\t{}\t{:08x}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            key.idx,
            key.va,
            class.as_str(),
            addr,
            oi.map(|i| i as i64).unwrap_or(-1),
            ci.map(|i| i as i64).unwrap_or(-1),
            n,
            m,
            o.map(|x| x.mnemonic.as_str()).unwrap_or(""),
            c.map(|x| x.mnemonic.as_str()).unwrap_or(""),
            o.map(regs_of).unwrap_or_default(),
            c.map(regs_of).unwrap_or_default(),
            o.map(|x| clean(&x.text)).unwrap_or_default(),
            c.map(|x| clean(&x.text)).unwrap_or_default(),
        );
    }
}

/// Register operands as `off:size` pairs, in order of first appearance.
///
/// Offsets rather than names: naming needs the language tables, and the question a query asks of
/// this column — "are the two sides using the same registers" — is answered by the offsets alone.
fn regs_of(i: &NormInsn) -> String {
    i.regs.iter().map(|(o, s)| format!("{o}:{s}")).collect::<Vec<_>>().join(",")
}

/// Strip tabs and newlines so a rendered instruction cannot break the row it sits in.
fn clean(s: &str) -> String {
    s.chars().map(|c| if c == '\t' || c == '\n' || c == '\r' { ' ' } else { c }).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recompile::align::compare;
    use crate::recompile::insn::{normalize, NoReloc};

    fn lift(hex: &str) -> Vec<NormInsn> {
        let bytes: Vec<u8> = (0..hex.len() / 2)
            .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
            .collect();
        normalize("x86:LE:32:default", &bytes, 0x1000, &NoReloc).expect("language tables")
    }

    fn rows(orig_hex: &str, cand_hex: &str) -> Vec<Vec<String>> {
        let (o, c) = (lift(orig_hex), lift(cand_hex));
        let diff = compare(&o, &c);
        let key = FnKey { idx: "t0".into(), va: 0x1000, name: "f".into() };
        let mut s = String::new();
        write_divergence_rows(&mut s, &key, &diff, &o, &c);
        s.lines().map(|l| l.split('\t').map(str::to_string).collect()).collect()
    }

    /// The row set is exactly the non-equal alignment steps: an equal pair contributes nothing,
    /// so the table's length is the defect count and not the instruction count.
    #[test]
    fn equal_pairs_produce_no_rows() {
        // push ebp; mov ebp,esp; pop ebp; ret  — against itself
        assert!(rows("5589e55dc3", "5589e55dc3").is_empty());
    }

    /// The case this table exists for: a candidate that saved no registers reports the original's
    /// `PUSH` as `missing`, and the row carries the mnemonic and the stream position that let a
    /// query recognise it as a save rather than as dropped computation.
    #[test]
    fn a_missing_register_save_is_identifiable_from_its_row() {
        // orig: push esi; push edi; ret     cand: ret
        let r = rows("5657c3", "c3");
        assert_eq!(r.len(), 2, "two missing pushes, got {r:?}");
        for row in &r {
            assert_eq!(row[2], "missing");
            assert_eq!(row[8], "PUSH", "mnemonic column names the instruction");
            assert_eq!(row[9], "", "no candidate instruction for a missing row");
            assert_eq!(row[11], "", "no candidate registers for a missing row");
            // Every register operand is `off:size` — a PUSH names its source *and* the stack
            // pointer it adjusts, so the count is a property of the instruction, not of the row.
            assert!(!row[10].is_empty(), "register operands recorded");
            for r in row[10].split(',') {
                let (off, size) = r.split_once(':').expect("off:size");
                assert!(off.parse::<u64>().is_ok() && size.parse::<u32>().is_ok(), "numeric {r}");
            }
        }
        // Positions: both are at the head of a 3-instruction original stream.
        assert_eq!((r[0][4].as_str(), r[0][6].as_str()), ("0", "3"));
        assert_eq!((r[1][4].as_str(), r[1][6].as_str()), ("1", "3"));
    }

    /// A candidate-only instruction records `ci` and leaves `oi` at -1, so the direction of a gap
    /// survives into the table.
    #[test]
    fn direction_survives_into_the_row() {
        let r = rows("c3", "40c3");
        assert_eq!(r.len(), 1);
        assert_eq!(r[0][2], "extra");
        assert_eq!(r[0][4], "-1", "no original position for an extra row");
        assert_eq!(r[0][5], "0");
    }

    /// Rendered text is data, not structure: an operand containing a tab would otherwise shift
    /// every later column of that row.
    #[test]
    fn rendered_text_cannot_break_the_row() {
        for row in rows("5657c3", "c3") {
            assert_eq!(row.len(), 14, "row must have exactly the header's columns");
        }
        assert_eq!(DIVERGENCE_HEADER.trim_end().split('\t').count(), 14);
    }
}
