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
    pub fn add_range(&mut self, space: SpaceId, min: u64, max: u64) {
        debug_assert!(min <= max);
        let mut new = AddressRange { space, min, max };
        let mut out: Vec<AddressRange> = Vec::with_capacity(self.ranges.len() + 1);
        for &r in &self.ranges {
            if r.space != space || !touches_or_overlaps(&r, &new) {
                out.push(r);
            } else {
                // merge r into new
                new.min = new.min.min(r.min);
                new.max = new.max.max(r.max);
            }
        }
        out.push(new);
        out.sort_by_key(|r| key(r));
        self.ranges = out;
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
