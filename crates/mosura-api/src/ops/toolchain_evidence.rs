//! `program.toolchain-evidence`: evidence that parts of the current program were NOT built by the
//! toolchain its compiler spec names.
//!
//! Deliberately a separate operation rather than a section of `identify`. `identify` is load-only
//! by contract — it answers "what is this file?" from the container and the bytes, in a moment,
//! before anything is analysed. This needs the function set and their decoded instructions, so it
//! runs on an analysed program and costs what analysis costs. Folding it in would have made the
//! first command anyone runs slow and broken that contract.
//!
//! Counts, and the instructions behind them. Never a verdict: see the core module for why the
//! reasoning only runs one way.

use crate::error::Result;
use crate::ops::program::program_of;
use crate::ops::schemas::TOOLCHAIN_EVIDENCE;
use crate::ops::{Cache, Op, Progress, Tier};
use crate::options::{keys, Options};
use crate::session::Session;
use crate::table::builder::TableBuilder;
use crate::table::Table;
use mosura_core::analysis::toolchain_evidence as te;

pub static EVIDENCE: Op = Op {
    name: "program.toolchain-evidence",
    doc: "evidence that functions were not built by the toolchain the compiler spec names: per verified encoding dichotomy, how many instructions use the toolchain's own encoding and how many use the legal alternative it never emits, which functions carry one, and how those cluster into address bands. Counts only, never a verdict",
    since: "0.1",
    tier: Tier::Product,
    params: &["program", keys::KNOBS_OFF, keys::DECOMPILE_GLOBAL_SCOPE, keys::DECOMPILE_PROTO_SCOPE],
    result: "toolchain_evidence",
    cache: Cache::Transient,
    run: evidence,
};

/// `kind` distinguishes the row shapes: `dichotomy` tallies, `band` clusters, `function` entries,
/// `finding` instructions, and the `note` rows that must travel with the numbers.
fn evidence(s: &mut Session, o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    let (_, prog) = program_of(s, o)?;
    let mut b = TableBuilder::new(&TOOLCHAIN_EVIDENCE);
    let Some(ev) = te::survey(&prog) else {
        b.row().str("note").str("no-table").u64(0).u64(0).str(&format!(
            "no encoding dichotomy has been verified for {} / {} — reporting nothing rather than applying another toolchain's habits",
            prog.language_id, prog.compiler_spec_id
        ));
        return Ok(b.finish(false));
    };
    b.row().str("scanned").str("functions").u64(ev.scanned as u64).u64(0).str("functions with a decodable body");
    for t in &ev.tallies {
        b.row().str("dichotomy").str(t.name).u64(t.native as u64).u64(t.foreign as u64).str(t.doc);
    }
    b.row().str("flagged").str("functions").u64(ev.flagged.len() as u64).u64(ev.findings.len() as u64).str("functions carrying at least one finding, and the instructions behind them");
    for band in &ev.bands {
        b.row().str("band").str(&format!("{:#010x}..{:#010x}", band.lo, band.hi)).u64(band.functions as u64).u64(0).str("contiguous run of flagged functions: linked-in objects sit together, scattered findings do not");
    }
    for va in &ev.flagged {
        let n = ev.findings.iter().filter(|f| f.function == *va).count();
        b.row().str("function").str(&format!("{va:#010x}")).u64(n as u64).u64(0).str("");
    }
    for f in ev.findings.iter().take(200) {
        b.row().str("finding").str(&format!("{:#010x}", f.addr)).u64(f.function).u64(0).str(&format!("{} [{}]", f.text, f.dichotomy));
    }
    // the caveat ships with the output, not in the docs
    b.row().str("note").str("reading").u64(0).u64(0).str(
        "a finding says this toolchain at these settings did not emit that instruction; it does not say a human wrote it, and it is not a verdict. The reasoning runs one way: an encoding the toolchain uses proves it can, an encoding absent from the evidence may merely be unexercised — which is why each dichotomy is admitted only after showing zero occurrences in known-good output of the toolchain (tests/toolchain_evidence_calibration.rs)",
    );
    Ok(b.finish(false))
}
