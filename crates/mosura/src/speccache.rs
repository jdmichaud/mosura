//! Per-process cache of parsed SLEIGH [`Spec`]s. Parsing a `.sla` costs ~0.5–1s in a debug
//! build, and every test that touches a language re-parsed it; test binaries with several
//! such tests paid it several times over. `get` parses each path once per process and hands
//! out a `&'static Spec` (leaked — specs live for the whole run anyway). Purely a loader
//! cache: the parsed `Spec` is bit-identical to a fresh `Spec::from_sla`.

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
    let spec = std::fs::read(path)
        .ok()
        .and_then(|bytes| Spec::from_sla(&bytes).ok())
        .map(|s| &*Box::leak(Box::new(s)));
    map.insert(path.to_path_buf(), spec);
    spec
}
