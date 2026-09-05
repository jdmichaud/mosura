//! Stage fingerprints and the build id (design §5.4, §5.9). `fp(stage)` = the stage's source
//! fingerprint (from `build.rs`) combined with the DATA digest — everything the resource provider
//! has in effect, embedded or overridden — so an edited `.cspec` invalidates like a code edit. The
//! build id is content-derived (`<version>+<12 hex of the four fingerprints>`), never a git
//! shell-out from a library (decision E8); a front-end adds a git stamp to provenance when it runs
//! in a checkout.

use std::sync::OnceLock;

include!(concat!(env!("OUT_DIR"), "/fingerprints.rs"));

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Stage {
    Analysis,
    Decompile,
    Emit,
    Recompile,
}

impl Stage {
    pub fn name(self) -> &'static str {
        match self {
            Stage::Analysis => "analysis",
            Stage::Decompile => "decompile",
            Stage::Emit => "emit",
            Stage::Recompile => "recompile",
        }
    }
    /// The source half of the fingerprint.
    pub fn source_fp(self) -> [u8; 32] {
        match self {
            Stage::Analysis => FP_ANALYSIS,
            Stage::Decompile => FP_DECOMPILE,
            Stage::Emit => FP_EMIT,
            Stage::Recompile => FP_RECOMPILE,
        }
    }
}

/// blake3 over the names and bytes of every resource in effect (the provider's view: the embedded
/// tables with any override directory applied). Computed once per process — the provider is set
/// by the front-end before the first operation and not changed after (one `Context` per process).
pub fn data_digest() -> [u8; 32] {
    static D: OnceLock<[u8; 32]> = OnceLock::new();
    *D.get_or_init(|| {
        let res = mosura_core::resources::get();
        let mut h = blake3::Hasher::new();
        for (name, _) in res.in_effect() {
            if let Some(bytes) = res.read(&name) {
                h.update(&(name.len() as u32).to_le_bytes());
                h.update(name.as_bytes());
                h.update(&(bytes.len() as u64).to_le_bytes());
                h.update(&bytes);
            }
        }
        *h.finalize().as_bytes()
    })
}

/// The fingerprint a cache key uses for `stage`: blake3(source fingerprint ‖ data digest).
pub fn fp(stage: Stage) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(&stage.source_fp());
    h.update(&data_digest());
    *h.finalize().as_bytes()
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// `<crate version>+<12 hex digits of blake3 over the four source fingerprints>` — stable for a
/// given core source tree, whatever directory or commit it sits in.
pub fn build_id() -> &'static str {
    static ID: OnceLock<String> = OnceLock::new();
    ID.get_or_init(|| {
        let mut h = blake3::Hasher::new();
        for s in [Stage::Analysis, Stage::Decompile, Stage::Emit, Stage::Recompile] {
            h.update(&s.source_fp());
        }
        format!("{}+{}", env!("CARGO_PKG_VERSION"), &hex(h.finalize().as_bytes())[..12])
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The four names carry two source values in P1 (analysis = decompile, by construction); every
    /// fingerprint is non-zero and mixes the data digest; the build id is stable and versioned.
    #[test]
    fn fingerprints_distinct_and_analysis_equals_decompile_in_p1() {
        assert!(CORE_SOURCE_FILES > 100, "the core tree was walked ({CORE_SOURCE_FILES} files)");
        assert_eq!(FP_ANALYSIS, FP_DECOMPILE);
        assert_ne!(FP_EMIT, FP_RECOMPILE);
        assert_ne!(FP_ANALYSIS, FP_EMIT);
        for s in [Stage::Analysis, Stage::Emit, Stage::Recompile] {
            assert_ne!(s.source_fp(), [0u8; 32]);
            assert_ne!(fp(s), s.source_fp(), "the data digest is mixed in");
            assert_eq!(fp(s), fp(s), "stable");
        }
        assert_eq!(fp(Stage::Analysis), fp(Stage::Decompile));
        assert_ne!(data_digest(), [0u8; 32]);
        let id = build_id();
        assert!(id.starts_with(&format!("{}+", env!("CARGO_PKG_VERSION"))) && id.len() == env!("CARGO_PKG_VERSION").len() + 13, "{id}");
        assert_eq!(build_id(), id);
    }
}
