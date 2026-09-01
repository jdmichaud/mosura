//! A content-addressed object cache.
//!
//! A search re-proposes the same source constantly — the same function is recompiled whenever a
//! knob is turned and turned back, and neighbouring candidates in a beam share most of their
//! variants. Caching turns those into disk reads.
//!
//! The lookup is confirmed against the stored source rather than trusted from the digest. A hash
//! collision in a compiler cache does not produce a crash; it produces *the wrong object*,
//! scored as if it came from this source, and there is no downstream check that would notice.
//! Storing the source next to the object and comparing it makes the failure impossible instead
//! of unlikely, and costs one file read.

use super::{CompileOutput, CompileUnit, Toolchain};
use std::path::{Path, PathBuf};

/// Units compiled before results are written to disk. Small enough that an interrupted run loses
/// little, large enough that the underlying driver still batches usefully.
const CACHE_GROUP: usize = 200;

/// Wraps any toolchain with a disk cache.
pub struct Cached<T: Toolchain> {
    inner: T,
    dir: PathBuf,
    hits: std::cell::Cell<usize>,
    misses: std::cell::Cell<usize>,
}

impl<T: Toolchain> Cached<T> {
    pub fn new(inner: T, dir: impl AsRef<Path>) -> std::io::Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)?;
        Ok(Self { inner, dir, hits: 0.into(), misses: 0.into() })
    }

    pub fn stats(&self) -> (usize, usize) {
        (self.hits.get(), self.misses.get())
    }

    fn slot(&self, id: &str, unit: &CompileUnit) -> PathBuf {
        let mut h = Fnv::new();
        h.write(id.as_bytes());
        for f in &unit.flags {
            h.write(f.as_bytes());
            h.write(b"\x1f");
        }
        h.write(b"\x1e");
        h.write(unit.source.as_bytes());
        self.dir.join(format!("{:016x}{:016x}", h.hi, h.lo))
    }

    /// A stored entry, when its recorded source matches this unit exactly.
    fn read(&self, slot: &Path, unit: &CompileUnit) -> Option<CompileOutput> {
        let stored_src = std::fs::read_to_string(slot.with_extension("c")).ok()?;
        if stored_src != unit.source {
            return None;
        }
        let log = std::fs::read_to_string(slot.with_extension("log")).unwrap_or_default();
        let obj = slot.with_extension("obj");
        let object = if obj.exists() { Some(std::fs::read(obj).ok()?) } else { None };
        // anything stored was adjudicated: `compile_batch` below only writes such entries
        Some(CompileOutput { key: unit.key.clone(), object, log, adjudicated: true })
    }

    fn write(&self, slot: &Path, unit: &CompileUnit, out: &CompileOutput) {
        let _ = std::fs::write(slot.with_extension("c"), &unit.source);
        let _ = std::fs::write(slot.with_extension("log"), &out.log);
        match &out.object {
            Some(o) => {
                let _ = std::fs::write(slot.with_extension("obj"), o);
            }
            None => {
                let _ = std::fs::remove_file(slot.with_extension("obj"));
            }
        }
    }
}

impl<T: Toolchain> Toolchain for Cached<T> {
    fn id(&self) -> String {
        self.inner.id()
    }

    fn compile_batch(&self, units: &[CompileUnit]) -> Vec<CompileOutput> {
        let id = self.inner.id();
        let mut out: Vec<Option<CompileOutput>> = vec![None; units.len()];
        let mut todo: Vec<usize> = Vec::new();
        let slots: Vec<PathBuf> = units.iter().map(|u| self.slot(&id, u)).collect();
        for (i, unit) in units.iter().enumerate() {
            match self.read(&slots[i], unit) {
                Some(hit) => {
                    self.hits.set(self.hits.get() + 1);
                    out[i] = Some(hit);
                }
                None => todo.push(i),
            }
        }
        if !todo.is_empty() {
            self.misses.set(self.misses.get() + todo.len());
            // Persist in GROUPS rather than once at the end. A whole-corpus run is thousands of
            // units and many minutes; interrupting it used to discard every object compiled so
            // far, because nothing reached disk until the last one finished. Losing an eight
            // minute compile to a timeout is not a small cost when the loop's whole value is that
            // repeats are free.
            for group in todo.chunks(CACHE_GROUP) {
                let batch: Vec<CompileUnit> = group.iter().map(|&i| units[i].clone()).collect();
                for (slot_i, res) in group.iter().zip(self.inner.compile_batch(&batch)) {
                    // Only a verdict the compiler actually reached is a fact about the source.
                    // A unit nothing adjudicated (unreachable toolchain, aborted session) must
                    // not be stored, or the environment fault becomes permanent: the run that
                    // fixes the environment hits the stored failure and never recompiles. See
                    // `CompileOutput::adjudicated`.
                    if res.adjudicated {
                        self.write(&slots[*slot_i], &units[*slot_i], &res);
                    }
                    out[*slot_i] = Some(res);
                }
            }
        }
        out.into_iter().map(|o| o.expect("every unit answered")).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recompile::toolchain::CompileUnit;
    use std::cell::Cell;

    /// A toolchain that fails on its first batch and succeeds on every later one, counting how
    /// often it was actually asked to compile. Whether that first failure was ADJUDICATED — the
    /// compiler rejecting the source, versus nothing ever running — is the variable under test.
    struct Flaky {
        calls: Cell<usize>,
        first_failure_adjudicated: bool,
    }

    impl Toolchain for Flaky {
        fn id(&self) -> String {
            "flaky".into()
        }
        fn compile_batch(&self, units: &[CompileUnit]) -> Vec<CompileOutput> {
            let first = self.calls.get() == 0;
            self.calls.set(self.calls.get() + 1);
            units
                .iter()
                .map(|u| CompileOutput {
                    key: u.key.clone(),
                    object: (!first).then(|| b"OBJ".to_vec()),
                    log: if first { "compiler aborted".into() } else { String::new() },
                    adjudicated: !first || self.first_failure_adjudicated,
                })
                .collect()
        }
    }

    fn unit() -> CompileUnit {
        CompileUnit { key: "u".into(), source: "int main(void){return 0;}".into(), flags: vec![] }
    }

    fn run(dir: &str, first_failure_adjudicated: bool) -> (bool, usize) {
        let d = std::env::temp_dir().join(format!("mosura-cache-{dir}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let t = Cached::new(Flaky { calls: 0.into(), first_failure_adjudicated }, &d).expect("dir");
        let first = t.compile(&unit());
        assert!(!first.ok(), "the first compile fails by construction");
        let second = t.compile(&unit());
        let calls = t.inner.calls.get();
        let _ = std::fs::remove_dir_all(&d);
        (second.ok(), calls)
    }

    /// The regression this exists for. A failure that never reached the compiler is not a fact
    /// about the source, so it must not be stored under the source's key — otherwise an
    /// environment fault becomes permanent, and the run that FIXES the environment is served the
    /// stored failure and never recompiles. Measured before this guard: a detached run with no
    /// `dosemu` on PATH cached 32 COMPILE_FAILs, and the corrected run reported "32 cached, 0
    /// fresh" in 0.0s. The sibling guard `the_prelude_is_part_of_the_toolchain_identity` cannot
    /// cover this: the toolchain id describes the compiler we meant to run, and here none ran.
    #[test]
    fn an_unadjudicated_failure_is_never_cached() {
        let (ok, calls) = run("unadj", false);
        assert!(ok, "the second attempt must reach the compiler again, not be served the failure");
        assert_eq!(calls, 2, "the unadjudicated failure must not have been stored");
    }

    /// The other half: a verdict the compiler DID reach is a fact about the source, and caching
    /// it is the whole point of this wrapper.
    #[test]
    fn an_adjudicated_failure_is_cached() {
        let (ok, calls) = run("adj", true);
        assert!(!ok, "the stored rejection is served back");
        assert_eq!(calls, 1, "a real rejection is cached, so the compiler is not asked twice");
    }
}

/// 128-bit FNV-1a. Only ever used to pick a filename — correctness rests on the stored-source
/// comparison, not on this.
/// The content digest both the cache slot and a toolchain's [`Toolchain::id`] are built from —
/// one definition, because an `id` that digests differently from the slot key is exactly the
/// inconsistency the cache's confirm-the-source rule exists to prevent.
pub(crate) struct Fnv {
    pub(crate) hi: u64,
    pub(crate) lo: u64,
}

impl Fnv {
    pub(crate) fn new() -> Self {
        Self { hi: 0x6c62272e07bb0142, lo: 0x62b821756295c58d }
    }
    /// The digest so far, as a stable hex string.
    pub(crate) fn hex(&self) -> String {
        format!("{:016x}{:016x}", self.hi, self.lo)
    }
    pub(crate) fn write(&mut self, bytes: &[u8]) {
        for b in bytes {
            self.lo ^= *b as u64;
            // 128-bit multiply by the FNV prime (2^88 + 0x13b), done in two limbs.
            let (lo, carry) = self.lo.overflowing_mul(0x13b);
            let hi = self.hi.wrapping_mul(0x13b).wrapping_add(if carry { 1 } else { 0 });
            let shifted_hi = self.lo << 24;
            self.lo = lo;
            self.hi = hi ^ shifted_hi;
        }
    }
}
