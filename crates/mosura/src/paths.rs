//! Path resolution for the reference corpora and oracle — the DEV/TEST tier.
//!
//! Every path derives from the workspace location (the build-time `CARGO_MANIFEST_DIR`) or
//! from `dev-config.toml` ([`crate::devcfg`]); nothing is read from the environment and nothing
//! is hard-coded to a home directory. **The library itself reads none of this**: its spec tables,
//! compiler specs, pattern files and FID databases come through [`crate::resources`] (embedded
//! at build time, an override directory first). What is here serves tests, examples, xtask and
//! the oracle tooling — goldens, fixtures, corpora, the Ghidra checkout, user-provided binaries.

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

/// The pinned Ghidra source checkout: `ghidra_src` in `dev-config.toml`, else
/// `<workspace>/../ghidra` ([`crate::devcfg::ghidra_src`]).
pub fn ghidra_src() -> PathBuf {
    crate::devcfg::ghidra_src()
}

/// The root the oracle capture tools are pointed at: `oracle.ghidra_root` in `dev-config.toml`,
/// else the checkout ([`crate::devcfg::oracle_root`]). A distribution or a `make-oracle-root.sh`
/// root serves here where the source checkout is absent.
pub fn oracle_root() -> PathBuf {
    crate::devcfg::oracle_root()
}

/// The vendored Ghidra subset committed in-repo (`third_party/ghidra/` — the used languages +
/// datatests at the pin; see its README). The fallback that makes `cargo test` self-contained.
fn vendored_ghidra() -> PathBuf {
    workspace_root().join("third_party/ghidra")
}

/// The `Processors` tree on disk (`.ldefs`/`.sla`/`.pspec`/`.cspec`) — for tests and dev tools
/// that want an absolute path; the library resolves languages through [`crate::resources`]
/// (the embedded copy of the vendored tree). Resolution: the configured checkout
/// (`ghidra_src`) when it has a `Ghidra/Processors` → the vendored in-repo copy.
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

/// Mosura-authored (beyond-Ghidra) compiler specs and pattern files — e.g. the Watcom `watcall`
/// cspec that no Ghidra processor ships. The library reads them as the `specs/` resources
/// ([`crate::lang::resolve_cspec`] tries `specs/<file>` ahead of the Ghidra tree); this is the
/// on-disk directory for tests and tooling.
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
/// `NationalSecurityAgency/ghidra-data` (`third_party/ghidra-data/README.md`). For the tests
/// that read them directly. The analyzer sees them through [`crate::resources`] as `fid/<file>`:
/// mounted from the workspace in a developer build, embedded only with the `fid-ghidra` feature
/// (76 MB), or placed in a `--data-dir` override directory.
pub fn fid_db_dir() -> PathBuf {
    workspace_root().join("third_party/ghidra-data/FunctionID")
}

/// Every on-disk directory holding signature databases — for tests and dev tools that load from
/// a directory ([`crate::analysis::fid::query::FidQueryService::load_matching_all`]). The
/// analyzer itself enumerates the provider's `fid/` (`load_matching_resources`), which the
/// workspace mount populates from both of these.
///
/// Two, because the databases come from two places and **both are shipped data**: Ghidra's
/// vendored `.fidb` (Visual Studio 1998-2019) in `third_party/`, and the databases mosura builds
/// itself in `data/fid` (Borland, Watcom, sdcc — `docs/fid-building-databases.md`).
///
/// ⚠️ Searching only the first is why FID identified **nothing** in a Watcom binary while the
/// Watcom databases sat in the tree: the subject binary analysed to 3021 functions with 1 name (its entry
/// point) because zero databases matched, and to 121 names the moment this directory was
/// included. A signature database nobody looks in is not a feature.
///
pub fn fid_db_dirs() -> Vec<PathBuf> {
    vec![
        workspace_root().join("third_party/ghidra-data/FunctionID"),
        workspace_root().join("data/fid"),
    ]
}

// User-provided binaries: located by their `[binaries]` key in `dev-config.toml` with the
// `$HOME`-relative default the dependency manifest promises ([`crate::devcfg::binary`]). These
// are copyrighted third-party files that are **not committed**; the tests that use them skip when
// absent (`docs/dependencies.md`). No absolute path is baked in. The binaries under STUDY are not
// here at all: they are `[[subject]]` entries with a profile ([`crate::devcfg::subjects`]).

/// A 16-bit **Microsoft C** DOS program. `binaries.msc16`, default `$HOME/msc16.exe`.
/// Ground truth for the 16-bit real-mode path: the `msc-7.0-*` FID columns and the 16-bit
/// Microsoft run-time banner (`docs/flashback-corpus-notes.md`). Generic name on purpose — the
/// compiler and the language are what is under test, not any one product.
pub fn msc16_exe() -> PathBuf {
    crate::devcfg::binary("msc16").expect("msc16 has a manifest default")
}

/// An X-32-bound executable (FlashTek X-32 / X-32VM). `binaries.x32`, default
/// `$HOME/x32.exe`. Native-X-32 analysis ground truth for `docs/x32-loader-notes.md`.
/// Deliberately a generic name: the container is what is under test, not any one product.
pub fn x32_exe() -> PathBuf {
    crate::devcfg::binary("x32").expect("x32 has a manifest default")
}

/// `cnv.exe` — a Clang-built PE. `binaries.cnv`, default `$HOME/cnv.exe`. PE
/// `CompilerOpinion` ground truth.
pub fn cnv_exe() -> PathBuf {
    crate::devcfg::binary("cnv").expect("cnv has a manifest default")
}

/// A Watcom C/C++32 installation directory (the one holding `BINW`, `H`, `LIB386`).
/// `watcom.install`, default `$HOME/watcom`. The **recompile oracle**: byte-exactness is a
/// claim about what a particular compiler emits, and only that compiler can settle it. Gates
/// needing it skip when it is absent, like every other user-provided toolchain.
pub fn watcom_dir() -> PathBuf {
    crate::devcfg::watcom_install()
}

/// `comcom32.exe` — a DJGPP MZ. `binaries.comcom32`, default
/// `$HOME/.local/share/comcom32/comcom32.exe`. Watcom no-false-positive ground truth.
pub fn comcom32_exe() -> PathBuf {
    crate::devcfg::binary("comcom32").expect("comcom32 has a manifest default")
}
