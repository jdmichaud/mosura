//! Per-process cache of parsed SLEIGH [`Spec`]s. Parsing a `.sla` costs ~0.5–1s in a debug
//! build, and every test that touches a language re-parsed it; test binaries with several
//! such tests paid it several times over. `get` parses each path once per process and hands
//! out a `&'static Spec` (leaked — specs live for the whole run anyway). Purely a loader
//! cache: the parsed `Spec` is bit-identical to a fresh `Spec::from_sla`.
//!
//! (This is also the intended seat of the architecture's laned-register metadata
//! [`Spec::laned`] — see the HELD-INERT note in [`get`].)

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
    // HELD INERT (Task #6 S3b). This is the seat where the architecture's laned (vector) registers
    // would be attached — the `.sla` alone carries no `vector_lane_sizes` (Ghidra reads them from the
    // `.pspec`), so this loader is the natural place to resolve them:
    //
    //     if let Some(pspec) = crate::lang::default_pspec_for_sla(path) {
    //         s.laned = crate::lang::pspec_laned_size_masks(&pspec, &s);
    //     }
    //
    // The lane-division subsystem it feeds (TransformManager + LaneDivide + ActionLaneDivide, wired at
    // pipeline.rs post-heritage/pre-pool) is a COMPLETE, faithful port — but it is NOT populated,
    // because live it net-regresses the corpus (avg 0.8936→0.8935): mosura over-splits XMM into 4-byte
    // lanes where Ghidra uses 8-byte. Re-add the two lines above (and the mirror in `lang::load`) once
    // EITHER upstream cause is fixed:
    //   (i) [PRIMARY] P6 stops the spurious 4-byte XMM output/param trials (`characterizeAsOutput`
    //       over-widen): at lanedivide time mosura carries a dead `SUBPIECE r0x1200:16 -> :4` of XMM0
    //       that Ghidra lacks, so `collectLaneSizes` (smallest-first) picks 4-byte lanes.
    //   (ii) the spacebase/StackPtrFlow model moves stack resolution post-pool, making Ghidra's
    //       stackstall slot usable — measured: moving the action post-pool copy-props the laned
    //       register away entirely (no split), so today only the pre-pool slot has a live reg to divide.
    // At reactivation, `floatcast` already improves (+0.038) — evidence the split itself is right once
    // fed the correct-width reads.
    let spec = std::fs::read(path)
        .ok()
        .and_then(|bytes| Spec::from_sla(&bytes).ok())
        .map(|s| &*Box::leak(Box::new(s)));
    map.insert(path.to_path_buf(), spec);
    spec
}
