//! `AddressRange` / `AddressSet` — a port of Ghidra's `AddressRange` and
//! `AddressSet`/`AddressSetView` (`program/model/address/`). The set algebra every
//! analyzer leans on: a function body, the locations queued for an analyzer, the
//! bytes disassembled so far, are all `AddressSet`s.
//!
//! Faithful semantics: ranges are **inclusive** `[min, max]` within a single space;
//! a set is the canonical union of non-overlapping, non-**adjacent** ranges (Ghidra
//! coalesces touching ranges, e.g. `[0,5] ∪ [6,10] = [0,10]`), ordered by
//! `(space, min)`. Method names mirror `AddressSetView`: [`AddressSet::contains`],
//! [`union`](AddressSet::union), [`intersect`](AddressSet::intersect),
//! [`subtract`](AddressSet::subtract), [`xor`](AddressSet::xor),
//! [`min_address`](AddressSet::min_address), [`num_addresses`](AddressSet::num_addresses).

use crate::decompile::space::{Address, SpaceId};

/// A contiguous, inclusive `[min, max]` range of addresses within one space
/// (Ghidra's `AddressRange`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct AddressRange {
    pub space: SpaceId,
    pub min: u64,
    pub max: u64,
}

impl AddressRange {
    pub fn new(space: SpaceId, min: u64, max: u64) -> AddressRange {
        debug_assert!(min <= max, "AddressRange min must be <= max");
        AddressRange { space, min, max }
    }
    /// Number of addresses in the range (`max - min + 1`).
    pub fn length(&self) -> u64 {
        self.max - self.min + 1
    }
    pub fn contains_offset(&self, off: u64) -> bool {
        self.min <= off && off <= self.max
    }
}

/// A set of addresses as a canonical, coalesced list of [`AddressRange`]s,
/// ordered by `(space, min)` (Ghidra's `AddressSet`).
#[derive(Clone, Default, PartialEq, Eq, Debug)]
pub struct AddressSet {
    ranges: Vec<AddressRange>,
}

/// `(space, min)` sort key.
fn key(r: &AddressRange) -> (u32, u64) {
    (r.space.0, r.min)
}

impl AddressSet {
    pub fn new() -> AddressSet {
        AddressSet { ranges: Vec::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }

    /// The canonical ranges, ordered by `(space, min)` (Ghidra `getAddressRanges`).
    pub fn ranges(&self) -> impl Iterator<Item = &AddressRange> {
        self.ranges.iter()
    }

    /// Total number of addresses covered (Ghidra `getNumAddresses`).
    pub fn num_addresses(&self) -> u64 {
        self.ranges.iter().map(AddressRange::length).sum()
    }

    /// Lowest address, or `None` if empty (Ghidra `getMinAddress`).
    pub fn min_address(&self) -> Option<Address> {
        self.ranges.first().map(|r| Address::new(r.space, r.min))
    }

    /// Highest address, or `None` if empty (Ghidra `getMaxAddress`).
    pub fn max_address(&self) -> Option<Address> {
        // ordered by (space, min); the max address is the largest `max` in the
        // highest space — i.e. the last range (ranges within a space are disjoint
        // and sorted, and spaces sort by id).
        self.ranges.last().map(|r| Address::new(r.space, r.max))
    }

    pub fn contains(&self, addr: Address) -> bool {
        self.ranges
            .iter()
            .any(|r| r.space == addr.space && r.contains_offset(addr.offset))
    }

    /// Add an inclusive range, coalescing with overlapping/adjacent ranges.
    /// ⚠️ **This used to copy the whole `Vec` and re-`sort` it on EVERY insertion**, which made
    /// every caller that adds ranges in a loop quadratic-with-a-sort:
    /// `union` calls it once per range of the other set, `get_function_body` once per
    /// INSTRUCTION, and `find_locations_remove_function_bodies` unions a growing `in_body` across
    /// all 3023 the subject functions. It showed up in `perf` as `slice::sort::drift::sort` plus the
    /// allocator traffic around it.
    ///
    /// The set is canonical — sorted by `(space, min)`, pairwise non-overlapping and
    /// non-adjacent — so the insertion point is a binary search, and only the run of ranges that
    /// actually touch `new` has to be merged. Same result, no sort, no reallocation.
    pub fn add_range(&mut self, space: SpaceId, min: u64, max: u64) {
        debug_assert!(min <= max);
        let mut new = AddressRange { space, min, max };
        // First range at or after `new` in key order.
        let mut lo = self.ranges.partition_point(|r| key(r) < (space.0, min));
        // At most one earlier range can reach `new` (they are disjoint and non-adjacent).
        if lo > 0 {
            let prev = self.ranges[lo - 1];
            if prev.space == space && touches_or_overlaps(&prev, &new) {
                lo -= 1;
            }
        }
        // Absorb the contiguous run that touches `new`, re-testing against the GROWING `new` so a
        // range only reachable after an earlier merge is still absorbed.
        let mut hi = lo;
        while hi < self.ranges.len() {
            let r = self.ranges[hi];
            if r.space != space || !touches_or_overlaps(&r, &new) {
                break;
            }
            new.min = new.min.min(r.min);
            new.max = new.max.max(r.max);
            hi += 1;
        }
        self.ranges.splice(lo..hi, std::iter::once(new));
    }

    pub fn add(&mut self, addr: Address) {
        self.add_range(addr.space, addr.offset, addr.offset);
    }

    /// Union (Ghidra `union`).
    pub fn union(&self, other: &AddressSet) -> AddressSet {
        let mut out = self.clone();
        for r in &other.ranges {
            out.add_range(r.space, r.min, r.max);
        }
        out
    }

    /// In-place union — `self |= other` (Ghidra `AddressSet.add(AddressSetView)`).
    ///
    /// ⚠️ **`a = a.union(b)` in a loop is quadratic in copying**: `union` starts from
    /// `self.clone()`, so accumulating across N sets clones the growing accumulator N times.
    /// `find_locations_remove_function_bodies` does exactly that over all 3023 the subject functions on
    /// every invocation. This adds into `self` and clones nothing.
    pub fn extend(&mut self, other: &AddressSet) {
        for r in &other.ranges {
            self.add_range(r.space, r.min, r.max);
        }
    }

    /// Intersection (Ghidra `intersect`).
    pub fn intersect(&self, other: &AddressSet) -> AddressSet {
        let mut out = AddressSet::new();
        for a in &self.ranges {
            for b in &other.ranges {
                if a.space != b.space {
                    continue;
                }
                let lo = a.min.max(b.min);
                let hi = a.max.min(b.max);
                if lo <= hi {
                    out.add_range(a.space, lo, hi);
                }
            }
        }
        out
    }

    /// Does `self` share any address with `other`? (Ghidra `AddressSetView.intersects`.)
    ///
    /// ⚠️ **Not `!intersect(other).is_empty()`** — that builds the whole intersection, allocating a
    /// fresh `AddressSet` and every overlapping range, just to answer a yes/no.
    /// `find_locations_remove_function_bodies` asks it once per FUNCTION on every invocation:
    /// 3023 functions x 95 invocations = ~287k allocating intersections per the subject run, which is
    /// most of the allocator traffic `perf` attributes to the analysis lane. This short-circuits
    /// on the first overlap and allocates nothing.
    pub fn intersects(&self, other: &AddressSet) -> bool {
        // Both sides are canonical — sorted by `(space, min)` — so this is a two-pointer merge,
        // O(n + m), not the O(n x m) nested scan. It matters: the caller asks once per FUNCTION
        // per invocation, and on the subject the sets reach 652 ranges against bodies of up to 93.
        let (mut i, mut j) = (0usize, 0usize);
        while i < self.ranges.len() && j < other.ranges.len() {
            let a = self.ranges[i];
            let b = other.ranges[j];
            if (a.space.0, a.max) < (b.space.0, b.min) {
                i += 1;
            } else if (b.space.0, b.max) < (a.space.0, a.min) {
                j += 1;
            } else {
                return true; // same space, overlapping
            }
        }
        false
    }

    /// Difference `self \ other` (Ghidra `subtract`).
    pub fn subtract(&self, other: &AddressSet) -> AddressSet {
        let mut out = AddressSet::new();
        for a in &self.ranges {
            // fragments of `a` not covered by any same-space range of `other`
            let mut cutters: Vec<&AddressRange> = other
                .ranges
                .iter()
                .filter(|b| b.space == a.space && b.max >= a.min && b.min <= a.max)
                .collect();
            cutters.sort_by_key(|b| b.min);
            let mut cur = a.min; // next uncovered offset within `a`
            let mut covered_to_end = false;
            for b in cutters {
                // clamp the cutter to `a` so all arithmetic stays in [a.min, a.max]
                let bmin = b.min.max(a.min);
                let bmax = b.max.min(a.max);
                if bmin > cur {
                    out.add_range(a.space, cur, bmin - 1); // bmin > cur >= 0
                }
                if bmax >= a.max {
                    covered_to_end = true;
                    break;
                }
                cur = cur.max(bmax + 1); // bmax < a.max <= u64::MAX, so no overflow
            }
            if !covered_to_end && cur <= a.max {
                out.add_range(a.space, cur, a.max);
            }
        }
        out
    }

    /// Symmetric difference (Ghidra `xor`).
    pub fn xor(&self, other: &AddressSet) -> AddressSet {
        self.subtract(other).union(&other.subtract(self))
    }

    /// True if both sets cover exactly the same addresses (Ghidra `hasSameAddresses`).
    pub fn has_same_addresses(&self, other: &AddressSet) -> bool {
        self.ranges == other.ranges
    }
}

/// Two same-space ranges overlap or are adjacent (touch), so they coalesce.
fn touches_or_overlaps(a: &AddressRange, b: &AddressRange) -> bool {
    // overlap, or adjacency (a.max + 1 == b.min, either direction), overflow-safe.
    let a_then_b = a.max < b.min && a.max.checked_add(1) == Some(b.min);
    let b_then_a = b.max < a.min && b.max.checked_add(1) == Some(a.min);
    let overlap = a.min <= b.max && b.min <= a.max;
    overlap || a_then_b || b_then_a
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::space::SpaceId;

    const RAM: SpaceId = SpaceId(1);
    const OTHER: SpaceId = SpaceId(2);

    fn set(ranges: &[(u64, u64)]) -> AddressSet {
        let mut s = AddressSet::new();
        for &(lo, hi) in ranges {
            s.add_range(RAM, lo, hi);
        }
        s
    }
    fn as_pairs(s: &AddressSet) -> Vec<(u64, u64)> {
        s.ranges().map(|r| (r.min, r.max)).collect()
    }

    #[test]
    fn coalesces_overlapping_and_adjacent() {
        assert_eq!(as_pairs(&set(&[(0, 5), (3, 8)])), vec![(0, 8)]); // overlap
        assert_eq!(as_pairs(&set(&[(0, 5), (6, 10)])), vec![(0, 10)]); // adjacent
        assert_eq!(as_pairs(&set(&[(0, 5), (7, 10)])), vec![(0, 5), (7, 10)]); // gap kept
        // insertion order independent
        assert_eq!(as_pairs(&set(&[(7, 10), (0, 5), (6, 6)])), vec![(0, 10)]);
    }

    #[test]
    fn contains_and_counts() {
        let s = set(&[(0, 5), (10, 12)]);
        assert!(s.contains(Address::new(RAM, 3)));
        assert!(s.contains(Address::new(RAM, 10)));
        assert!(!s.contains(Address::new(RAM, 6)));
        assert!(!s.contains(Address::new(OTHER, 3))); // wrong space
        assert_eq!(s.num_addresses(), 6 + 3);
        assert_eq!(s.min_address().unwrap().offset, 0);
        assert_eq!(s.max_address().unwrap().offset, 12);
    }

    #[test]
    fn union_intersect_subtract_xor() {
        let a = set(&[(0, 10), (20, 30)]);
        let b = set(&[(5, 25)]);
        assert_eq!(as_pairs(&a.union(&b)), vec![(0, 30)]);
        assert_eq!(as_pairs(&a.intersect(&b)), vec![(5, 10), (20, 25)]);
        assert_eq!(as_pairs(&a.subtract(&b)), vec![(0, 4), (26, 30)]);
        assert_eq!(as_pairs(&a.xor(&b)), vec![(0, 4), (11, 19), (26, 30)]);
    }

    #[test]
    fn subtract_edges() {
        assert_eq!(as_pairs(&set(&[(0, 10)]).subtract(&set(&[(0, 10)]))), vec![]); // whole
        assert_eq!(as_pairs(&set(&[(0, 10)]).subtract(&set(&[(3, 5)]))), vec![(0, 2), (6, 10)]);
        assert_eq!(as_pairs(&set(&[(0, 10)]).subtract(&set(&[(8, 99)]))), vec![(0, 7)]);
    }

    #[test]
    fn spaces_are_independent() {
        let mut a = set(&[(0, 10)]); // RAM
        a.add_range(OTHER, 0, 10);
        let b = set(&[(0, 10)]); // RAM only
        // intersect drops the OTHER-space range
        assert!(a.intersect(&b).ranges().all(|r| r.space == RAM));
        assert_eq!(a.intersect(&b).num_addresses(), 11);
        // subtract leaves the OTHER-space range intact
        let d = a.subtract(&b);
        assert!(d.ranges().any(|r| r.space == OTHER && r.min == 0 && r.max == 10));
    }

    #[test]
    fn max_address_at_u64_boundary_subtract() {
        let mut s = AddressSet::new();
        s.add_range(RAM, u64::MAX - 2, u64::MAX);
        let cut = {
            let mut c = AddressSet::new();
            c.add_range(RAM, u64::MAX, u64::MAX);
            c
        };
        assert_eq!(as_pairs(&s.subtract(&cut)), vec![(u64::MAX - 2, u64::MAX - 1)]);
    }
}
