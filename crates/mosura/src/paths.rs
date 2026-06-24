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

/// Directory holding the decompiler datatests (the 79 `.xml` fixtures).
pub fn datatests_dir() -> PathBuf {
    ghidra_src().join("Ghidra/Features/Decompiler/src/decompile/datatests")
}

/// Directory of captured disasm / p-code goldens (committed to the repo).
pub fn goldens_dir() -> PathBuf {
    workspace_root().join("goldens")
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

/// Hand-authored / extracted fixtures for the offline capture tool (`*.xml`).
pub fn oracle_fixtures_dir() -> PathBuf {
    workspace_root().join("oracle/fixtures")
}
