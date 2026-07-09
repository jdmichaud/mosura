//! Language registry: resolve a Ghidra language id (e.g. `x86:LE:64:default`) to
//! its compiled `.sla` tables + default decode context, by reading the processor
//! `.ldefs`/`.pspec` files from the pinned Ghidra tree. This is what lets the
//! top-level [`crate::sleigh::disassemble`] work from a bare language id.

use crate::decompile::transform::{LanedRegister, LanedRegisterSet};
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

/// Parse the `<register_data>` section of a `.pspec` into the architecture's laned-register set
/// (Ghidra `Architecture::decodeRegisterData`, architecture.cc:929). Each
/// `<register name=… vector_lane_sizes="1,2,4,8"/>` contributes its lane mask to the record for the
/// register's byte size, which is resolved via [`Spec::register_size`] — mirroring Ghidra reading
/// the size from the sleigh register table (`storage.decodeFromAttributes`). For x86-64,
/// x86-64.pspec:79/111/143 give ZMM/YMM/XMM = 64/32/16, all with lane sizes `1,2,4,8`.
pub fn pspec_laned_registers(pspec: &Path, spec: &Spec) -> LanedRegisterSet {
    let Ok(text) = fs::read_to_string(pspec) else { return LanedRegisterSet::default() };
    let Ok(doc) = roxmltree::Document::parse(&text) else { return LanedRegisterSet::default() };
    let mut size_masks: Vec<(i32, u32)> = Vec::new();
    // Only `<register>` elements inside `<register_data>` carry lane sizes (decodeRegisterData).
    for reg in doc
        .descendants()
        .filter(|n| n.tag_name().name() == "register_data")
        .flat_map(|rd| rd.children())
        .filter(|n| n.tag_name().name() == "register")
    {
        let Some(lanes) = reg.attribute("vector_lane_sizes") else { continue };
        let Some(name) = reg.attribute("name") else { continue };
        let Some(size) = spec.register_size(name) else { continue };
        let mut lr = LanedRegister::default();
        lr.parse_sizes(size as i32, lanes);
        size_masks.push((size as i32, lr.size_bit_mask()));
    }
    LanedRegisterSet::from_size_masks(size_masks)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// The x86-64 `.pspec` carries `vector_lane_sizes="1,2,4,8"` on XMM/YMM/ZMM (x86-64.pspec:143/
    /// 111/79). Resolving each name→size via the sleigh register table yields size-keyed records
    /// 16/32/64, each allowing lane sizes {1,2,4,8}, matching Ghidra's `getLanedRegister` semantics.
    /// Gated on the Ghidra tree being present.
    #[test]
    fn x86_64_laned_registers_from_pspec() {
        let Some((sla, pspec)) = resolve("x86:LE:64") else { return }; // tree absent → skip
        let Ok(bytes) = fs::read(&sla) else { return };
        let Ok(spec) = Spec::from_sla(&bytes) else { return };
        let set = pspec_laned_registers(&pspec, &spec);
        assert!(!set.is_empty(), "x86-64 has laned registers");
        assert_eq!(set.minimum_laned_register_size(), 16, "smallest laned reg = XMM (16 bytes)");
        for size in [16, 32, 64] {
            let lr = set.get_laned_register(size).unwrap_or_else(|| panic!("record for size {size}"));
            assert_eq!(lr.lane_sizes().collect::<Vec<_>>(), vec![1, 2, 4, 8], "lanes for size {size}");
            assert!(lr.allowed_lane(8), "8-byte lane allowed for size {size}");
        }
        // A non-laned size (e.g. an 8-byte GP register) has no record.
        assert!(set.get_laned_register(8).is_none());
        // Sanity: the register-name→size resolver agrees with the pspec assumptions.
        assert_eq!(spec.register_size("XMM0"), Some(16));
        assert_eq!(spec.register_size("YMM0"), Some(32));
    }
}
