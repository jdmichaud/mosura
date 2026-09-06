//! The admission bar for an encoding dichotomy, enforced.
//!
//! `analysis::toolchain_evidence` accuses a function of not having been built by a toolchain
//! because it uses an encoding that toolchain never emits. That claim is only worth as much as the
//! evidence that the toolchain really never emits it, so a dichotomy is admitted only after the
//! alternative encoding is shown to appear ZERO times in known-good output — and this test is that
//! showing, run on every build rather than quoted from a commit message.
//!
//! The population here is the committed self-compiled Watcom fixtures: Watcom 10.0a output built
//! from C source that lives in this repository, regenerable with
//! `mosura dev mve.fixtures dev.check=true toolchain.install=<WATCOM>`. Anyone can rebuild it, which
//! is the property a shipped calibration needs and which measurements on a subject binary cannot
//! have.
//!
//! The zero is asserted together with its denominator. A zero over no observations is not evidence
//! of anything, and this test would otherwise pass by finding nothing to look at.
use mosura_core::analysis::toolchain_evidence::{survey_functions, WATCOM_X86_32};
use mosura_core::recompile::insn::{normalize, NoReloc, NormInsn};

const LANG: &str = "x86:LE:32:default";
/// The header `dev.mve.fixtures` writes; only its own products carry it.
const GENERATED_MARKER: &str = "<!-- SELF-COMPILED fixture: wcc386";

/// Every instruction of every self-compiled Watcom fixture, grouped per fixture.
fn self_compiled_watcom() -> Vec<(u64, Vec<NormInsn>)> {
    let dir = mosura_core::paths::oracle_fixtures_dir();
    let Ok(rd) = std::fs::read_dir(&dir) else { return Vec::new() };
    let mut files: Vec<std::path::PathBuf> = rd
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "xml"))
        .collect();
    files.sort();
    let mut out = Vec::new();
    for p in files {
        if !std::fs::read_to_string(&p).map(|s| s.starts_with(GENERATED_MARKER)).unwrap_or(false) {
            continue;
        }
        let Ok(dt) = mosura_core::datatest::parse_file(&p) else { continue };
        for chunk in &dt.chunks {
            let Ok(insns) = normalize(LANG, &chunk.bytes, chunk.offset, &NoReloc) else { continue };
            if !insns.is_empty() {
                out.push((chunk.offset, insns));
            }
        }
    }
    out
}

#[test]
fn every_dichotomy_holds_on_self_compiled_output_of_the_toolchain() {
    let fns = self_compiled_watcom();
    if fns.is_empty() {
        eprintln!("skip: no self-compiled Watcom fixtures present");
        return;
    }
    let ev = survey_functions(&fns, WATCOM_X86_32);
    for t in &ev.tallies {
        // the denominator first: a zero is only readable beside the number of chances it had
        assert!(
            t.native >= 40,
            "{}: only {} observations of the toolchain's own encoding in the self-compiled corpus \
             — too few for the zero below to mean anything; widen the corpus before trusting it",
            t.name,
            t.native
        );
        assert_eq!(
            t.foreign, 0,
            "{}: the toolchain emitted the encoding this dichotomy calls foreign, {} time(s), in \
             its OWN self-compiled output. The dichotomy is refuted and must be removed rather \
             than have its exceptions listed: {:?}",
            t.name,
            t.foreign,
            ev.findings.iter().take(5).map(|f| f.text.as_str()).collect::<Vec<_>>()
        );
    }
    assert!(ev.flagged.is_empty(), "no self-compiled unit may be flagged: {:?}", ev.flagged);
}
