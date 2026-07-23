//! The SLEIGH-availability canary — this test **fails loudly** when the language tables or
//! datatests cannot be resolved, where every other SLEIGH-gated test politely *skips*
//! (`lang::load(..) == None` → early return).
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
    let missing: Vec<&str> = ids.iter().copied().filter(|id| lang::load(id).is_none()).collect();
    assert!(
        missing.is_empty(),
        "SLEIGH tables unresolvable for {missing:?} — processors_dir()={} . \
         Neither the sibling checkout nor the vendored third_party/ghidra copy resolved; \
         the repo is broken (or GHIDRA_SRC points somewhere stale). Other suites are \
         silently SKIPPING right now — do not trust a green run until this passes.",
        paths::processors_dir().display()
    );
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
