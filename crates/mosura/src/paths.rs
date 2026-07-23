//! Path resolution for the reference corpora and oracle.
//!
//! Honors the `GHIDRA_SRC` environment variable (the same override the setup
//! script uses); otherwise derives every path from the workspace location, so
//! nothing is hard-coded to a home directory.

use std::path::PathBuf;

/// Workspace root — the `mosura/` directory (parent of `crates/`).
pub fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR = <workspace>/crates/mosura
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("crate manifest dir should have >= 2 ancestors")
        .to_path_buf()
}

/// The pinned Ghidra source checkout (`GHIDRA_SRC`, else `<workspace>/../ghidra`).
pub fn ghidra_src() -> PathBuf {
    if let Ok(p) = std::env::var("GHIDRA_SRC") {
        return PathBuf::from(p);
    }
    workspace_root()
        .parent()
        .expect("workspace should have a parent dir")
        .join("ghidra")
}

/// The vendored Ghidra subset committed in-repo (`third_party/ghidra/` — the used languages +
/// datatests at the pin; see its README). The fallback that makes `cargo test` self-contained.
fn vendored_ghidra() -> PathBuf {
    workspace_root().join("third_party/ghidra")
}

/// The `Processors` tree the SLEIGH loader reads (`.ldefs`/`.sla`/`.pspec`/`.cspec`).
/// Resolution: `GHIDRA_SRC` env → the sibling checkout → the vendored in-repo copy, so a
/// developer's checkout wins when present and a bare clone still works.
pub fn processors_dir() -> PathBuf {
    let checkout = ghidra_src().join("Ghidra/Processors");
    if checkout.is_dir() {
        return checkout;
    }
    vendored_ghidra().join("Processors")
}

/// One processor's `data/languages` dir (specs + compiled `.sla`), through the same
/// resolution as [`processors_dir`] — e.g. `language_dir("x86")`.
pub fn language_dir(processor: &str) -> PathBuf {
    processors_dir().join(processor).join("data/languages")
}

/// Directory holding the decompiler datatests (the 79 `.xml` fixtures). Same resolution as
/// [`processors_dir`]: checkout first, vendored fallback.
pub fn datatests_dir() -> PathBuf {
    let checkout = ghidra_src().join("Ghidra/Features/Decompiler/src/decompile/datatests");
    if checkout.is_dir() {
        return checkout;
    }
    vendored_ghidra().join("datatests")
}

/// Directory of captured disasm / p-code goldens (committed to the repo).
pub fn goldens_dir() -> PathBuf {
    workspace_root().join("goldens")
}

/// Mosura-authored (beyond-Ghidra) compiler specs — e.g. the Watcom `watcall` cspec that no
/// Ghidra processor ships. Resolved by [`crate::lang::resolve_cspec`] ahead of the Ghidra tree.
pub fn specs_dir() -> PathBuf {
    workspace_root().join("specs")
}

/// Captured disasm + raw-p-code goldens (`*.golden`).
pub fn disasm_goldens_dir() -> PathBuf {
    goldens_dir().join("disasm")
}

/// Captured auto-analysis Program-state snapshots (`*.snapshot`) — the A0 oracle.
pub fn analysis_goldens_dir() -> PathBuf {
    goldens_dir().join("analysis")
}

/// The real-binary corpus the analysis oracle is captured from (`*.elf` + sources).
pub fn analysis_corpus_dir() -> PathBuf {
    workspace_root().join("oracle/analysis-corpus")
}

/// Committed codegen-fingerprint artefacts — the probe source plus, per compiler revision, the
/// self-compiled machine code (`<rev>.code`) the codegen matcher is gated against (so the test
/// runs without the historical compiler on hand). See `docs/watcom-codegen-fingerprint.md`.
pub fn codegen_probes_dir() -> PathBuf {
    workspace_root().join("oracle/codegen-probes")
}

/// The cross-compiler self-compiled **ground-truth** corpus: stripped binaries + build-derived
/// `.truth` files whose oracle is the source/build we own, not Ghidra (task #3;
/// `docs/ground-truth-corpus.md`, `tests/ground_truth_parity.rs`).
pub fn ground_truth_dir() -> PathBuf {
    workspace_root().join("oracle/ground-truth")
}

/// Hand-authored / extracted fixtures for the offline capture tool (`*.xml`).
pub fn oracle_fixtures_dir() -> PathBuf {
    workspace_root().join("oracle/fixtures")
}

/// Locate a user-provided binary by an env var with a `$HOME`-relative default — the same
/// override convention as [`ghidra_src`]. These are copyrighted third-party files that are
/// **not committed**; the tests that use them skip when absent (`docs/dependencies.md`). No
/// absolute path is baked in — the default is derived from `$HOME`.
fn user_binary(env_var: &str, home_relative_default: &str) -> PathBuf {
    if let Ok(p) = std::env::var(env_var) {
        return PathBuf::from(p);
    }
    let home = std::env::var("HOME").map(PathBuf::from).unwrap_or_default();
    home.join(home_relative_default)
}

/// `WAR2.EXE` — Warcraft II, a DOS/4GW-bound Watcom LE. `MOSURA_WAR2_EXE`, default
/// `$HOME/WAR2.EXE`. Native-LE analysis + Watcom-detection ground truth.
pub fn war2_exe() -> PathBuf {
    user_binary("MOSURA_WAR2_EXE", "WAR2.EXE")
}

/// `cnv.exe` — a Clang-built PE. `MOSURA_CNV_EXE`, default `$HOME/cnv.exe`. PE
/// `CompilerOpinion` ground truth.
pub fn cnv_exe() -> PathBuf {
    user_binary("MOSURA_CNV_EXE", "cnv.exe")
}

/// `comcom32.exe` — a DJGPP MZ. `MOSURA_COMCOM32_EXE`, default
/// `$HOME/.local/share/comcom32/comcom32.exe`. Watcom no-false-positive ground truth.
pub fn comcom32_exe() -> PathBuf {
    user_binary("MOSURA_COMCOM32_EXE", ".local/share/comcom32/comcom32.exe")
}
