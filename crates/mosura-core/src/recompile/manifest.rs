//! The emit manifest — one row per function of a corpus emit, the file every later stage
//! (compile, verify, the text gates, the verdict table) joins on. Moved out of the corpus emit
//! driver (plan WP7 P0 c3, 2026-09-05): the `kind` classification verbatim, the two `#` header
//! lines and the 14-column row as a record with a renderer instead of three `writeln!`s whose
//! formats had to agree by inspection. Text out; the front-end owns the file.

use crate::decompile::emit::EmitChoices;
use crate::switches::Knobs;

/// The column header, in the order every reader (`recompile::gates::load_tree`,
/// `recompile_check`) looks columns up by name.
pub const COLUMNS: &str = "idx\tva\tname\tstatus\torig_len\tcov_lo\tcov_hi\tsmells\torig_hex\tir_calls\tblocks_cfg\tblocks_reached\tkind\tcontract";

/// The names the `# arms:` line stamps as switched off, DERIVED, never assembled by hand: the
/// `--arms-off` names that are emit arms (`Recovered::ARMS`), then `Knobs::stamp_parts` — every
/// knob off its default (a switch, a `--cspec` declaration, a `--disable-analyzers` list — each
/// changes the tree as surely as any arm), so a tree cannot differ from the baseline for a reason
/// the manifest does not carry.
pub fn off_names(arms_off: &[String], knobs: &Knobs) -> Vec<String> {
    let mut off_names: Vec<String> = arms_off
        .iter()
        .filter(|a| crate::decompile::emit::arms::registry::Recovered::ARMS.contains(&a.as_str()))
        .cloned()
        .collect();
    off_names.extend(knobs.stamp_parts());
    off_names
}

/// The `; off: a,b` suffix of the arms line, empty when nothing is off.
pub fn off_stamp(off_names: &[String]) -> String {
    if off_names.is_empty() { String::new() } else { format!("; off: {}", off_names.join(",")) }
}

/// The two `#` header lines: the stamp of the tree that produced the manifest (so a `.tsv` copied
/// away from its directory still says which tree it came from) and the arm set the tree was
/// MEASURED with — the recovered emit's choices, every axis spelled out, plus what is off (code
/// review 2026-08-27: measurement documents carry their arm set). `#` lines are skipped by every
/// reader.
pub fn stamp_lines(stamp: &str, rec_arm: &EmitChoices, off_names: &[String]) -> [String; 2] {
    [format!("# corpus_emit emit @ {stamp}"), format!("# arms: {}", arms_stamp_with(rec_arm, off_names))]
}

/// The arms stamp — the text after `# arms: ` in a manifest: the recovered arm's choice vector,
/// then `; off: a,b` when arms or switches are off. THE identity of an emission's rendering
/// policy; a round records it, the identity gate compares it.
pub fn arms_stamp_with(rec_arm: &EmitChoices, off_names: &[String]) -> String {
    format!("{rec_arm}{}", off_stamp(off_names))
}

/// [`arms_stamp_with`] from the raw ingredients: the recovered arm, the `--arms-off` names (arms
/// and switches in one name space) and the knobs.
pub fn arms_stamp(rec_arm: &EmitChoices, arms_off: &[String], knobs: &Knobs) -> String {
    arms_stamp_with(rec_arm, &off_names(arms_off, knobs))
}

/// Whether a function is the subject's own code or the toolchain's.
///
/// A recompilation denominator must not count library code. `memset`, `printf` and the CRT
/// startup are reproduced by LINKING the Watcom libraries, not by decompiling them, so counting
/// them measures the toolchain rather than the port -- and their verdicts are not the port's to
/// claim either way. Measured on the subject: 5 of 131 library functions are byte-exact (3.8%) against
/// 534 of 2892 of the subject's own (18.5%), so excluding them RAISES the ratio -- they were
/// dragging it down, not flattering it, which is the opposite of what was assumed here first.
///
/// The classification is the program's own: analysis names an unrecognised entry `FUN_<addr>`,
/// and on a stripped image the only thing that replaces that placeholder is FID matching the
/// function against a known library. So "was it identified" IS "is it library code" here, and it
/// is asked through [`Function::name_is_default`] so this file does not carry a second copy of
/// the placeholder format.
pub fn kind_of(name: &str) -> &'static str {
    if crate::analysis::program::function::Function::name_is_default(name) {
        "user"
    } else {
        "library"
    }
}

/// The manifest `kind`, with the not-C classification: a default-named function whose
/// ORIGINAL instructions carry hand-assembly signatures (`buildconfig::looks_hand_written`
/// — calibrated: zero EXACT/SAME_SHAPE functions trip it) is `asm`, and the measurement
/// excludes it exactly as it excludes `library` — un-recompilable from C by construction,
/// so keeping it in the denominator misstates the C-recompilation target.
pub fn kind_of_insns(name: &str, insns: &[crate::recompile::insn::NormInsn]) -> &'static str {
    let k = kind_of(name);
    if k == "user" && crate::recompile::buildconfig::looks_hand_written(insns) {
        return "asm";
    }
    k
}

/// A row's status column.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Ok,
    DecompileFail,
}

/// One manifest row. `render` spells the two shapes the drivers wrote by hand: an `OK` row with
/// the covered extent in hex, and a `DECOMPILE_FAIL` row whose extent is the row's WEIGHT
/// downstream (no candidate to diff against), with `0` for both bounds, no smells, the failure's
/// head in the `orig_hex` column, zero counts and an empty contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManifestRow {
    pub idx: usize,
    pub va: u64,
    pub name: String,
    pub status: Status,
    pub orig_len: u64,
    pub cov_lo: u64,
    pub cov_hi: u64,
    pub smells: Vec<String>,
    /// The original machine code over the extent as hex — or, for a failed row, the failure's head.
    pub orig_hex: String,
    pub ir_calls: usize,
    pub blocks_cfg: usize,
    pub blocks_reached: usize,
    pub kind: &'static str,
    /// `ok`, or `wide:<violation>+<violation>` (`tu::contract_violations`); empty on a failed row.
    pub contract: String,
}

impl ManifestRow {
    /// The `DECOMPILE_FAIL` row: `weight` = the decompiler-independent extent, `head` = the panic
    /// text or "returned None" (tabs and newlines already replaced by the front-end).
    pub fn decompile_fail(idx: usize, va: u64, name: &str, weight: u64, kind: &'static str, head: &str) -> ManifestRow {
        ManifestRow {
            idx,
            va,
            name: name.to_string(),
            status: Status::DecompileFail,
            orig_len: weight,
            cov_lo: 0,
            cov_hi: 0,
            smells: Vec::new(),
            orig_hex: head.to_string(),
            ir_calls: 0,
            blocks_cfg: 0,
            blocks_reached: 0,
            kind,
            contract: String::new(),
        }
    }

    pub fn render(&self) -> String {
        let ManifestRow { idx, va, name, orig_len, cov_lo, cov_hi, orig_hex, ir_calls, blocks_cfg, blocks_reached, kind, contract, .. } = self;
        match self.status {
            Status::Ok => format!(
                "{idx:05}\t{va:08x}\t{name}\tOK\t{orig_len}\t{cov_lo:08x}\t{cov_hi:08x}\t{}\t{orig_hex}\t{ir_calls}\t{blocks_cfg}\t{blocks_reached}\t{kind}\t{contract}",
                self.smells.join(",")
            ),
            Status::DecompileFail => format!("{idx:05}\t{va:08x}\t{name}\tDECOMPILE_FAIL\t{orig_len}\t0\t0\t\t{orig_hex}\t0\t0\t0\t{kind}\t"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Both row shapes, byte for byte as the driver wrote them.
    #[test]
    fn rows_render_as_the_driver_wrote_them() {
        let ok = ManifestRow {
            idx: 7, va: 0x1a2b0, name: "FUN_0001a2b0".into(), status: Status::Ok, orig_len: 12, cov_lo: 0x1a2b0, cov_hi: 0x1a2bb,
            smells: vec!["extraout".into(), "thunk".into()], orig_hex: "5589e5c3".into(), ir_calls: 2, blocks_cfg: 3, blocks_reached: 3,
            kind: "user", contract: "wide:CONCAT44+uint8".into(),
        };
        assert_eq!(ok.render(), "00007\t0001a2b0\tFUN_0001a2b0\tOK\t12\t0001a2b0\t0001a2bb\textraout,thunk\t5589e5c3\t2\t3\t3\tuser\twide:CONCAT44+uint8");
        let fail = ManifestRow::decompile_fail(8, 0x1a2c0, "FUN_0001a2c0", 40, "library", "returned None");
        assert_eq!(fail.render(), "00008\t0001a2c0\tFUN_0001a2c0\tDECOMPILE_FAIL\t40\t0\t0\t\treturned None\t0\t0\t0\tlibrary\t");
        assert_eq!(COLUMNS.split('\t').count(), 14);
        assert_eq!(ok.render().split('\t').count(), 14);
        assert_eq!(fail.render().split('\t').count(), 14);
        for needed in ["idx", "va", "name", "kind"] {
            assert!(COLUMNS.split('\t').any(|c| c == needed), "gates::load_tree looks {needed} up by name");
        }
    }

    /// The header lines: the stamp, and the arms line with a DERIVED off-list — emit arms from
    /// `--arms-off`, switch names ignored there but reported by the knobs.
    #[test]
    fn stamp_lines_derive_the_off_list() {
        let arm = crate::recompile::recovery::canonical_arm();
        let mut knobs = Knobs::default();
        assert_eq!(off_names(&[], &knobs), Vec::<String>::new());
        assert_eq!(off_stamp(&[]), "");
        let [s, a] = stamp_lines("abc1234", &arm, &[]);
        assert_eq!(s, "# corpus_emit emit @ abc1234");
        assert_eq!(a, format!("# arms: {arm}"));
        knobs.turn_off("ret-split").unwrap();
        let off = off_names(&["cmp_sign".to_string(), "not-an-arm".to_string()], &knobs);
        assert_eq!(off, vec!["cmp_sign".to_string(), "ret-split".to_string()], "an emit arm by name, then the knob parts; unknown names are not stamped here");
        assert_eq!(stamp_lines("x", &arm, &off)[1], format!("# arms: {arm}; off: cmp_sign,ret-split"));
    }

    /// `kind`: a default-named function is the subject's own; a named one is the toolchain's; an
    /// own function whose bytes look hand-written is `asm`.
    #[test]
    fn kind_reads_the_name_and_the_bytes() {
        assert_eq!(kind_of("FUN_00012340"), "user");
        assert_eq!(kind_of("memset_"), "library");
        let ret = crate::recompile::insn::normalize("x86:LE:32:default", &[0xc3], 0x1000, &crate::recompile::insn::NoReloc).unwrap();
        assert_eq!(kind_of_insns("FUN_00012340", &ret), "user");
        assert_eq!(kind_of_insns("memset_", &ret), "library");
    }
}
