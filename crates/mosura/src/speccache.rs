//! Per-process cache of parsed SLEIGH [`Spec`]s. Parsing a `.sla` costs ~0.5–1s in a debug
//! build, and every test that touches a language re-parsed it; test binaries with several
//! such tests paid it several times over. `get` parses each path once per process and hands
//! out a `&'static Spec` (leaked — specs live for the whole run anyway). Purely a loader
//! cache: the parsed `Spec` is bit-identical to a fresh `Spec::from_sla`.
//!
//! (This is also the seat of the architecture's laned-register metadata
//! [`Spec::laned`] — see the reactivation note in [`get`].)

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use crate::sleigh::engine::Spec;

/// The parsed spec for `path`, cached per process. `None` when the file is missing or fails
/// to parse (callers skip, as with a fresh load).
pub fn get(path: &Path) -> Option<&'static Spec> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, Option<&'static Spec>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = cache.lock().unwrap();
    if let Some(&hit) = map.get(path) {
        return hit;
    }
    // The architecture's laned (vector) registers are attached here — the `.sla` alone carries no
    // `vector_lane_sizes` (Ghidra reads them from the `.pspec`), so this loader resolves them
    // (mirrored in `lang::load`). This feeds the lane-division subsystem (TransformManager +
    // LaneDivide + ActionLaneDivide, wired at pipeline.rs post-heritage/pre-pool), a complete
    // faithful port of subflow.cc/coreaction.cc:585.
    //
    // REACTIVATED (task #5 Brick 2) after Brick 1 retired the overlapping XMM0:4 return candidate
    // (recover.rs `recover_return`) whose dead `SUBPIECE XMM0:16 -> :4` mis-sized
    // `collectLaneSizes`' smallest-first lane choice — the cause of the original net regression
    // that had held this populate inert (task #6 S3b). Reactivation measure (base `19f1ebb` +
    // Brick 1): floatprint holds 1.000, stackstring 0.818→0.899 (splits into Ghidra's 8-byte lane
    // shapes), concatsplit 0.881→0.863 — the one regression, a PRE-EXISTING LaneDivide
    // do_trace/placement gap (genuine live 4-byte SUBPIECEs at mosura's pre-pool slot that
    // Ghidra's post-oppool1 stackstall slot never sees; see docs/coverage.md ActionLaneDivide).
    let spec = std::fs::read(path)
        .ok()
        .and_then(|bytes| Spec::from_sla(&bytes).ok())
        .map(|mut s| {
            if let Some(pspec) = crate::lang::default_pspec_for_sla(path) {
                s.laned = crate::lang::pspec_laned_size_masks(&pspec, &s);
            }
            &*Box::leak(Box::new(s))
        });
    map.insert(path.to_path_buf(), spec);
    spec
}
