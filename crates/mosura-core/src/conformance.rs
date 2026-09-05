//! Comparison modes for the conformance baseline (design §6).
//!
//! - [`exact`] — byte-exact after normalization (loader / disasm / p-code).
//! - [`stringmatch`] — Ghidra `<stringmatch>` semantics (regex occurrence count
//!   within `[min, max]`), used for the decompiler datatests.
//! - Structural (AST) and behavioral equivalence for decompiled C are a later
//!   milestone (decision #5) and are not implemented here yet.

use regex::Regex;

/// Exact match. Callers are responsible for normalization (addresses, temp
/// varnodes, whitespace) before calling.
pub fn exact(actual: &str, expected: &str) -> bool {
    actual == expected
}

/// Ghidra `<stringmatch>` semantics: the number of non-overlapping occurrences of
/// `pattern` in `haystack` must fall within `[min, max]`.
///
/// Note: Ghidra's reference harness uses C++ `std::regex`; the `regex` crate's
/// flavor differs in some edge cases. That is acceptable for the current baseline
/// (mosura emits no C yet, so every assertion evaluates against empty output and
/// fails by construction); exact regex-flavor parity becomes relevant only when
/// the decompiler stage lands.
pub fn stringmatch(haystack: &str, pattern: &str, min: u32, max: u32) -> Result<bool, regex::Error> {
    let re = Regex::new(pattern)?;
    let n = re.find_iter(haystack).count() as u32;
    Ok(n >= min && n <= max)
}

/// A running pass/total tally for the red-baseline ratchet tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct Tally {
    pub passed: usize,
    pub total: usize,
}

impl Tally {
    pub fn record(&mut self, ok: bool) {
        self.total += 1;
        if ok {
            self.passed += 1;
        }
    }
}

impl std::fmt::Display for Tally {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.passed, self.total)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stringmatch_counts_occurrences() {
        assert!(stringmatch("a b a", "a", 2, 2).unwrap());
        assert!(!stringmatch("a b a", "a", 3, 3).unwrap());
        assert!(stringmatch("", "x", 0, 0).unwrap());
        // a regex with a literal that does not appear → 0 occurrences
        assert!(!stringmatch("hello", r"return x;", 1, 1).unwrap());
    }

    #[test]
    fn tally_displays() {
        let mut t = Tally::default();
        t.record(true);
        t.record(false);
        assert_eq!(t.to_string(), "1/2");
    }
}
