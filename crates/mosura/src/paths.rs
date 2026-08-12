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

/// Ghidra's shipped **FID signature databases** — the packed `.fidb` vendored verbatim from
/// `NationalSecurityAgency/ghidra-data` (`third_party/ghidra-data/README.md`). External data
/// read at runtime, not compiled in; `MOSURA_FID_DIR` points elsewhere. With no database
/// present the FID analyzer is simply inert.
pub fn fid_db_dir() -> PathBuf {
    if let Ok(p) = std::env::var("MOSURA_FID_DIR") {
        return PathBuf::from(p);
    }
    workspace_root().join("third_party/ghidra-data/FunctionID")
}

/// Every directory the FID analyzer searches for signature databases.
///
/// Two, because the databases come from two places and **both are shipped data**: Ghidra's
/// vendored `.fidb` (Visual Studio 1998-2019) in `third_party/`, and the databases mosura builds
/// itself in `oracle/fid/db` (Borland, Watcom, sdcc — `docs/fid-building-databases.md`).
///
/// ⚠️ Searching only the first is why FID identified **nothing** in a Watcom binary while the
/// Watcom databases sat in the tree: WAR2.EXE analysed to 3021 functions with 1 name (its entry
/// point) because zero databases matched, and to 121 names the moment this directory was
/// included. A signature database nobody looks in is not a feature.
///
/// `MOSURA_FID_DIR` overrides both — an explicit directory means exactly that directory.
pub fn fid_db_dirs() -> Vec<PathBuf> {
    if let Ok(p) = std::env::var("MOSURA_FID_DIR") {
        return vec![PathBuf::from(p)];
    }
    vec![
        workspace_root().join("third_party/ghidra-data/FunctionID"),
        workspace_root().join("oracle/fid/db"),
    ]
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

/// A 16-bit **Microsoft C** DOS program. `MOSURA_MSC16_EXE`, default `$HOME/msc16.exe`.
/// Ground truth for the 16-bit real-mode path: the `msc-7.0-*` FID columns and the 16-bit
/// Microsoft run-time banner (`docs/flashback-corpus-notes.md`). Generic name on purpose — the
/// compiler and the language are what is under test, not any one product.
pub fn msc16_exe() -> PathBuf {
    user_binary("MOSURA_MSC16_EXE", "msc16.exe")
}

/// An X-32-bound executable (FlashTek X-32 / X-32VM). `MOSURA_X32_EXE`, default
/// `$HOME/x32.exe`. Native-X-32 analysis ground truth for `docs/x32-loader-notes.md`.
/// Deliberately a generic name: the container is what is under test, not any one product.
pub fn x32_exe() -> PathBuf {
    user_binary("MOSURA_X32_EXE", "x32.exe")
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
