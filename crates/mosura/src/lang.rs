//! Language registry: resolve a Ghidra language id (e.g. `x86:LE:64:default`) to
//! its compiled `.sla` tables + default decode context, by reading the processor
//! `.ldefs`/`.pspec` files from the pinned Ghidra tree. This is what lets the
//! top-level [`crate::sleigh::disassemble`] work from a bare language id.

use crate::paths;
use crate::sleigh::engine::Spec;
use std::fs;
use std::path::{Path, PathBuf};

/// Resolve a language id to its `(.sla, .pspec)` paths. Accepts the bare 4-part id
/// (`proc:endian:size:variant`) or one with a trailing `:cspec` (the goldens carry
/// the compiler-spec suffix); only the language part is used.
pub fn resolve(lang_id: &str) -> Option<(PathBuf, PathBuf)> {
    let id4: String = lang_id.split(':').take(4).collect::<Vec<_>>().join(":");
    let procs = paths::ghidra_src().join("Ghidra/Processors");
    for proc in fs::read_dir(&procs).ok()?.flatten() {
        let langs = proc.path().join("data/languages");
        let Ok(rd) = fs::read_dir(&langs) else { continue };
        for entry in rd.flatten() {
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) != Some("ldefs") {
                continue;
            }
            let Ok(text) = fs::read_to_string(&p) else { continue };
            let Ok(doc) = roxmltree::Document::parse(&text) else { continue };
            for l in doc.descendants().filter(|n| n.tag_name().name() == "language") {
                if l.attribute("id") == Some(id4.as_str()) {
                    let sla = l.attribute("slafile")?;
                    let pspec = l.attribute("processorspec")?;
                    return Some((langs.join(sla), langs.join(pspec)));
                }
            }
        }
    }
    None
}

/// The `<context_set>` defaults from a `.pspec` (name → value).
pub fn pspec_context_sets(pspec: &Path) -> Vec<(String, u64)> {
    let Ok(text) = fs::read_to_string(pspec) else { return Vec::new() };
    let Ok(doc) = roxmltree::Document::parse(&text) else { return Vec::new() };
    doc.descendants()
        .filter(|n| n.tag_name().name() == "context_set")
        .flat_map(|cs| cs.children())
        .filter(|n| n.tag_name().name() == "set")
        .filter_map(|n| Some((n.attribute("name")?.to_string(), n.attribute("val")?.parse().ok()?)))
        .collect()
}

/// Load the [`Spec`] + default decode context for a language id. Returns `None`
/// when the tables aren't present (e.g. the Ghidra tree isn't set up).
pub fn load(lang_id: &str) -> Option<(Spec, Vec<u32>)> {
    let (sla, pspec) = resolve(lang_id)?;
    let spec = Spec::from_sla(&fs::read(&sla).ok()?).ok()?;
    let sets = pspec_context_sets(&pspec);
    let refs: Vec<(&str, u64)> = sets.iter().map(|(n, v)| (n.as_str(), *v)).collect();
    let ctx = spec.context_from_sets(&refs);
    Some((spec, ctx))
}
