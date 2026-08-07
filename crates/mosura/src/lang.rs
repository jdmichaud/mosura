//! Language registry: resolve a Ghidra language id (e.g. `x86:LE:64:default`) to
//! its compiled `.sla` tables + default decode context, by reading the processor
//! `.ldefs`/`.pspec` files from the pinned Ghidra tree. This is what lets the
//! top-level [`crate::sleigh::disassemble`] work from a bare language id.

use crate::decompile::transform::{LanedRegister, LanedRegisterSet};
use crate::paths;
use crate::sleigh::engine::Spec;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

/// Resolve a language id to its `(.sla, .pspec)` paths. Accepts the bare 4-part id
/// (`proc:endian:size:variant`) or one with a trailing `:cspec` (the goldens carry
/// the compiler-spec suffix); only the language part is used.
pub fn resolve(lang_id: &str) -> Option<(PathBuf, PathBuf)> {
    let id4: String = lang_id.split(':').take(4).collect::<Vec<_>>().join(":");
    let procs = paths::processors_dir();
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

/// Resolve `(language id, compiler spec id)` to its `.cspec` file path, by reading the
/// processor `.ldefs` `<language>`/`<compiler>` entries (Ghidra `LanguageDescription` +
/// `CompilerSpecDescription`). Used by the analysis cspec loader to load the calling
/// conventions. Returns `None` if no matching `<compiler>` is declared.
pub fn resolve_cspec(lang_id: &str, compiler_spec_id: &str) -> Option<PathBuf> {
    // Mosura-authored (beyond-Ghidra) compiler specs first: the Watcom `watcall` cspec that no
    // Ghidra processor ships (`specs/x86-32-watcom.cspec`). Only x86:LE:32 + "watcom" today.
    if compiler_spec_id == "watcom" && lang_id.starts_with("x86:LE:32") {
        let p = paths::specs_dir().join("x86-32-watcom.cspec");
        if p.exists() {
            return Some(p);
        }
    }

    let id4: String = lang_id.split(':').take(4).collect::<Vec<_>>().join(":");
    let procs = paths::processors_dir();
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
                if l.attribute("id") != Some(id4.as_str()) {
                    continue;
                }
                for c in l.children().filter(|n| n.tag_name().name() == "compiler") {
                    if c.attribute("id") == Some(compiler_spec_id) {
                        return Some(langs.join(c.attribute("spec")?));
                    }
                }
            }
        }
    }
    None
}

/// The `<context_set>` defaults from a `.pspec` (name → value), or `None` when the `.pspec`
/// itself cannot be read or parsed.
///
/// The `None` case matters: Ghidra `SleighLanguage.initialize()` (SleighLanguage.java:116)
/// declares `throws DecoderException, SAXException, IOException` and reads the processor spec
/// through `readInitialDescription`/`read(parser)`, so an I/O or XML error propagates and the
/// `Language` fails to construct — Ghidra never comes up with an *unset* context register
/// because the spec file was unreadable. Returning an empty `Vec` for both "unreadable" and
/// "declares no `<context_set>`" (legitimate on an arch with no context register) made a
/// transient read failure silently decode x86 with `addrsize=0`/`opsize=0`, i.e. in 16-bit real
/// mode (`segment(...)` renders) — see [`load_cached`].
pub fn pspec_context_sets(pspec: &Path) -> Option<Vec<(String, u64)>> {
    let text = fs::read_to_string(pspec).ok()?;
    let doc = roxmltree::Document::parse(&text).ok()?;
    let sets = doc
        .descendants()
        .filter(|n| n.tag_name().name() == "context_set")
        .flat_map(|cs| cs.children())
        .filter(|n| n.tag_name().name() == "set")
        .filter_map(|n| Some((n.attribute("name")?.to_string(), n.attribute("val")?.parse().ok()?)))
        .collect();
    Some(sets)
}

/// Parse the `<register_data>` section of a `.pspec` into `(whole_register_size, lane_size_mask)`
/// pairs, merged by size (Ghidra `Architecture::decodeRegisterData`, architecture.cc:929, which
/// accumulates `maskList[size] |= mask`). Each `<register name=… vector_lane_sizes="1,2,4,8"/>`
/// contributes its lane mask to the record for the register's byte size, resolved via
/// [`Spec::register_size`] — mirroring Ghidra reading the size from the sleigh register table
/// (`storage.decodeFromAttributes`). For x86-64, x86-64.pspec:79/111/143 give ZMM/YMM/XMM = 64/32/16,
/// all with lane sizes `1,2,4,8`. This is the primitive form stored on [`Spec::laned`]; the decompiler
/// wraps it in a [`LanedRegisterSet`] (see [`pspec_laned_registers`]).
///
/// `None` when the `.pspec` cannot be read or parsed, for the same reason as
/// [`pspec_context_sets`]: an unreadable spec must fail the language load, not silently produce
/// a lane-free architecture (which would silently disable lane division for the whole run).
pub fn pspec_laned_size_masks(pspec: &Path, spec: &Spec) -> Option<Vec<(i32, u32)>> {
    let text = fs::read_to_string(pspec).ok()?;
    let doc = roxmltree::Document::parse(&text).ok()?;
    let mut by_size: std::collections::BTreeMap<i32, u32> = std::collections::BTreeMap::new();
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
        *by_size.entry(size as i32).or_insert(0) |= lr.size_bit_mask();
    }
    Some(by_size.into_iter().collect())
}

/// The laned-register set for a processor spec (Ghidra `Architecture::lanerecords`), the
/// [`LanedRegisterSet`] wrapping of [`pspec_laned_size_masks`].
pub fn pspec_laned_registers(pspec: &Path, spec: &Spec) -> Option<LanedRegisterSet> {
    Some(LanedRegisterSet::from_size_masks(pspec_laned_size_masks(pspec, spec)?))
}

/// Resolve the processor spec that carries a `.sla`'s register metadata. A single `.sla` can back
/// several language variants with distinct `.pspec`s (e.g. `x86-64.sla` serves both
/// `x86:LE:64:default` → `x86-64.pspec` and `x86:LE:64:compat32` → `x86-64-compat32.pspec`); the
/// laned (vector) registers are the same physical registers across those variants, so we take the
/// `:default` variant's pspec as canonical (falling back to the first entry that names this `.sla`).
/// This is what lets [`crate::speccache::get`], which is keyed only by the `.sla` path, attach the
/// architecture's laned registers.
pub fn default_pspec_for_sla(sla: &Path) -> Option<PathBuf> {
    let langs = sla.parent()?;
    let sla_name = sla.file_name()?.to_str()?;
    let mut fallback: Option<PathBuf> = None;
    for entry in fs::read_dir(langs).ok()?.flatten() {
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) != Some("ldefs") {
            continue;
        }
        let Ok(text) = fs::read_to_string(&p) else { continue };
        let Ok(doc) = roxmltree::Document::parse(&text) else { continue };
        for l in doc.descendants().filter(|n| n.tag_name().name() == "language") {
            if l.attribute("slafile") != Some(sla_name) {
                continue;
            }
            let Some(pspec) = l.attribute("processorspec") else { continue };
            let path = langs.join(pspec);
            if l.attribute("id").is_some_and(|id| id.ends_with(":default")) {
                return Some(path);
            }
            fallback.get_or_insert(path);
        }
    }
    fallback
}

/// Load the [`Spec`] + default decode context for a language id. Returns `None`
/// when the tables aren't present (e.g. the Ghidra tree isn't set up) or cannot be read.
///
/// Every call re-reads the `.ldefs`, `.sla` and `.pspec` from the Ghidra tree; a caller that
/// decodes more than one function must use [`load_cached`] instead.
/// **Private on purpose — use [`load_cached`].**
///
/// This reads and re-parses the whole `.sla` on every call. Every caller in the tree wants the
/// same tables for the same language, so an uncached call is always either a waste or a
/// correctness hazard, and we have been caught by it repeatedly: analyzer constructors were
/// each paying ~200 ms of table parsing, which made one `analyze()` cost 1.6 s regardless of
/// how small the program was. Keeping this private means the mistake cannot be made from
/// outside this module.
fn load(lang_id: &str) -> Option<(Spec, Vec<u32>)> {
    let (sla, pspec) = resolve(lang_id)?;
    let mut spec = Spec::from_sla(&fs::read(&sla).ok()?).ok()?;
    // The real-disassembly path attaches the laned (vector) registers, mirroring the cache
    // loader — see the reactivation note in `speccache::get`.
    spec.laned = pspec_laned_size_masks(&pspec, &spec)?;
    let sets = pspec_context_sets(&pspec)?;
    let refs: Vec<(&str, u64)> = sets.iter().map(|(n, v)| (n.as_str(), *v)).collect();
    let ctx = spec.context_from_sets(&refs);
    Some((spec, ctx))
}

/// A loaded language: the SLEIGH tables plus the default decode context they are read with
/// (Ghidra `SleighLanguage`, which carries both the decoder and the pspec's context defaults).
pub type Language = (&'static Spec, &'static [u32]);

/// [`load`], resolved once per process — the language tables and their default decode context
/// for a language id, handed out as `&'static` (leaked; they live for the whole run anyway).
///
/// This is Ghidra's structure: `SleighLanguageProvider` keeps a
/// `LinkedHashMap<LanguageID, SleighLanguage>` and `getLanguage()` builds a `SleighLanguage`
/// once, then serves it from that map (SleighLanguageProvider.java:58/128-134). A decompile of
/// N functions reads the `.sla`/`.pspec` once, not N times.
///
/// Mosura's per-function bridge ([`crate::analysis::decompiler::decompile_function`]) used
/// plain [`load`], so a whole-program decompile re-read the tables once per function (1286×
/// for WAR2 — every one of those reads a chance to fail). The failure was silent and
/// *per-function*: an unreadable `.sla` yielded `None` (that function alone did not
/// decompile), and an unreadable `.pspec` yielded an all-zero context register, decoding that
/// one function in 16-bit real mode (`segment(...)`, `xunknown2`) while its neighbours decoded
/// as 32-bit protected mode. With the Ghidra tree on a network mount, a transient read error
/// therefore made the whole-program survey non-deterministic run-to-run. Resolving once makes
/// the tables a per-process constant: every function decodes under the same context, and a
/// tree that cannot be read fails uniformly rather than per function.
pub fn load_cached(lang_id: &str) -> Option<Language> {
    static CACHE: OnceLock<Mutex<HashMap<String, Option<Language>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut map = cache.lock().unwrap();
    if let Some(&hit) = map.get(lang_id) {
        return hit;
    }
    let loaded = load(lang_id).map(|(spec, ctx)| {
        let spec: &'static Spec = Box::leak(Box::new(spec));
        let ctx: &'static [u32] = Box::leak(ctx.into_boxed_slice());
        (spec, ctx)
    });
    map.insert(lang_id.to_string(), loaded);
    loaded
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
        let set = pspec_laned_registers(&pspec, &spec).expect("readable pspec");
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

    /// An unreadable `.pspec` must NOT resolve to a context of zeros. On x86 a zero context
    /// register means `addrsize=0`/`opsize=0` — 16-bit real mode — so the old silent
    /// `Vec::new()` fallback turned a transient read failure into a whole function decoded in
    /// the wrong address-size mode (`segment(...)` renders, `xunknown2` types) instead of a
    /// failed language load. Also pins the x86-32 context to a non-zero word, so the two cases
    /// can never be confused. Gated on the Ghidra tree being present.
    #[test]
    fn unreadable_pspec_fails_the_load_rather_than_zeroing_the_context() {
        assert_eq!(pspec_context_sets(Path::new("/nonexistent/x86.pspec")), None);
        let Some((_, pspec)) = resolve("x86:LE:32:default") else { return }; // tree absent → skip
        let sets = pspec_context_sets(&pspec).expect("x86-32 pspec is readable");
        for want in ["addrsize", "opsize"] {
            assert!(sets.iter().any(|(n, _)| n == want), "x86-32 pspec sets {want}: {sets:?}");
        }
        let Some((spec, ctx)) = load_cached("x86:LE:32:default") else { return };
        assert!(ctx.iter().any(|&w| w != 0), "32-bit protected mode is not the zero context");
        // Cached: the same language id resolves to the very same leaked tables + context.
        let (spec2, ctx2) = load_cached("x86:LE:32:default").expect("cached");
        assert!(std::ptr::eq(spec, spec2) && std::ptr::eq(ctx, ctx2), "one load per process");
        // And the cached context is what the uncached path computes.
        let (_, fresh) = load("x86:LE:32:default").expect("fresh load");
        assert_eq!(ctx, fresh.as_slice());
    }

    /// The reverse `.sla`→default-`.pspec` resolver (the reactivation mechanism for the HELD-INERT
    /// laned-register loading in `speccache::get`): given `x86-64.sla` — shared by `x86:LE:64:default`
    /// and `x86:LE:64:compat32` — it must pick the `:default` variant's `x86-64.pspec`. Gated on the
    /// Ghidra tree being present.
    #[test]
    fn default_pspec_for_sla_prefers_default_variant() {
        let Some((sla, _)) = resolve("x86:LE:64") else { return }; // tree absent → skip
        let pspec = default_pspec_for_sla(&sla).expect("a pspec for x86-64.sla");
        assert_eq!(pspec.file_name().and_then(|s| s.to_str()), Some("x86-64.pspec"));
        // And it resolves to the same laned set the forward path (resolve) produces.
        let Ok(bytes) = fs::read(&sla) else { return };
        let Ok(spec) = Spec::from_sla(&bytes) else { return };
        assert_eq!(
            pspec_laned_size_masks(&pspec, &spec),
            Some(vec![(16, 0x116), (32, 0x116), (64, 0x116)])
        );
    }
}
