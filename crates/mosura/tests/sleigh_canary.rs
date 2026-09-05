//! The SLEIGH-availability canary — this test **fails loudly** when the language tables or
//! datatests cannot be resolved, where every other SLEIGH-gated test politely *skips*
//! (`lang::load_cached(..) == None` → early return).
//!
//! Why it exists: the skip convention silently hollowed the suite once — with the Ghidra
//! checkout deleted, `cargo test` stayed green while sleigh-dependent coverage skipped and
//! analysis degraded to symbols-only recovery. With the used language files now vendored
//! in-repo (`third_party/ghidra/`, checkout-first resolution in `paths.rs`), resolution can
//! only fail if the repo itself is broken — which must be a red X, never a quiet skip.

use mosura::{lang, paths};

/// Every language id the port loads must resolve and decode. This is the complete set the
/// crate exercises (loaders, coverage suites, decompiler pipeline).
#[test]
fn all_used_languages_load() {
    let ids = [
        "x86:LE:64:default",
        "x86:LE:32:default",
        "x86:LE:16:Real Mode",
        "AARCH64:LE:64:v8A",
        "RISCV:LE:64:default",
        "68000:BE:32:default",
        "z80:LE:16:default",
    ];
    let missing: Vec<&str> = ids.iter().copied().filter(|id| lang::load_cached(id).is_none()).collect();
    assert!(
        missing.is_empty(),
        "SLEIGH tables unresolvable for {missing:?} — processors_dir()={} . \
         Neither the sibling checkout nor the vendored third_party/ghidra copy resolved; \
         the repo is broken (or GHIDRA_SRC points somewhere stale). Other suites are \
         silently SKIPPING right now — do not trust a green run until this passes.",
        paths::processors_dir().display()
    );
}

/// The **Function Start Search** pattern files must resolve too, and this is the test that makes
/// their absence a red X rather than a silent no-op.
///
/// `FunctionStartAnalyzer::for_program` returns `None` when no pattern file matches the program's
/// `(language, compiler)` — correct behaviour for a language Ghidra ships no patterns for, and
/// indistinguishable from "the pattern files went missing". A missing `data/patterns` directory
/// would therefore disable byte-pattern function discovery entirely while every other test stayed
/// green: the exact failure mode this file exists for.
#[test]
fn function_start_pattern_files_resolve() {
    let dir = paths::processors_dir();
    // Every (constraints file, referenced pattern file) the x86 module declares must exist. x86 is
    // the module this port's two live configurations use; the others are checked for presence only.
    for (proc_name, constraints) in [
        ("x86", "patternconstraints.xml"),
        ("x86", "prepatternconstraints.xml"),
        ("AARCH64", "patternconstraints.xml"),
        ("RISCV", "patternconstraints.xml"),
        ("68000", "patternconstraints.xml"),
    ] {
        let pdir = dir.join(proc_name).join("data/patterns");
        let cpath = pdir.join(constraints);
        let text = std::fs::read_to_string(&cpath).unwrap_or_else(|e| {
            panic!(
                "Function Start Search constraints {} unreadable ({e}). processors_dir()={} — \
                 neither the sibling Ghidra checkout nor third_party/ghidra resolved its \
                 data/patterns. Byte-pattern function discovery is SILENTLY OFF right now.",
                cpath.display(),
                dir.display()
            )
        });
        let mut referenced = 0;
        for line in text.lines() {
            let Some(rest) = line.split("<patternfile>").nth(1) else { continue };
            let Some(name) = rest.split("</patternfile>").next() else { continue };
            let f = pdir.join(name.trim());
            assert!(f.is_file(), "{} names a missing pattern file {}", cpath.display(), f.display());
            referenced += 1;
        }
        assert!(referenced > 0, "{} references no pattern file", cpath.display());
    }

    // mosura's own (beyond-Ghidra) Watcom module — the one the subject lands on. See specs/patterns/.
    let mosura = paths::specs_dir().join("patterns");
    for f in ["patternconstraints.xml", "x86watcom_patterns.xml"] {
        assert!(
            mosura.join(f).is_file(),
            "mosura's Watcom pattern module is missing {} — a Watcom binary would silently get \
             NO function-start patterns at all",
            mosura.join(f).display()
        );
    }
}

/// The decompiler conformance fixtures must resolve too (checkout or vendored copy).
#[test]
fn datatests_resolve() {
    let dir = paths::datatests_dir();
    let count = std::fs::read_dir(&dir)
        .map(|d| d.flatten().filter(|e| e.path().extension().is_some_and(|x| x == "xml")).count())
        .unwrap_or(0);
    assert!(
        count >= 70,
        "decompiler datatests missing or truncated at {} ({count} xml files, expected ~79)",
        dir.display()
    );
}
