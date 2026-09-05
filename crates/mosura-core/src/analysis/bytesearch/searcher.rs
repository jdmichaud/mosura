//! `MemoryBytePatternSearcher` — a port of
//! `Features/Base/.../ghidra/util/bytesearch/MemoryBytePatternSearcher.java`.
//!
//! Drives a compiled [`SequenceSearchState`] across a program's memory blocks and hands each
//! surviving [`Match`] to a callback. Ghidra exposes `preMatchApply`/`postMatchApply` hooks
//! around the per-match action loop; here the callback owns the whole match (it receives the
//! [`Match`], whose `pattern.actions` it iterates), which is the same seam with the analyzer's
//! running state living in the closure rather than in mutable analyzer fields.

use super::pattern::{Match, Pattern};
use super::sequence::SequenceSearchState;
use crate::analysis::program::{AddressSet, Program};
use crate::decompile::space::Address;

/// `RESTRICTED_PATTERN_BYTE_RANGE` (:37) — how far *before* a restricted range the search starts,
/// so a pattern whose pre-part lies just outside the range can still match.
const RESTRICTED_PATTERN_BYTE_RANGE: u64 = 32;

/// One block's whole extent as a set — the "no restrict set" default (:174) and the
/// `searchSet.intersects(block)` test (:123).
fn block_range(start: Address, end: Address) -> AddressSet {
    let mut s = AddressSet::new();
    s.add_range(start.space, start.offset, end.offset);
    s
}

/// `MemoryBytePatternSearcher` (:36).
pub struct MemoryBytePatternSearcher<'a, A> {
    root: &'a SequenceSearchState,
    patterns: &'a [Pattern<A>],
    /// `doExecutableBlocksOnly` (:45).
    do_executable_blocks_only: bool,
    /// `getMaxSequenceSize()` (SequenceSearchState.java:51) — the read slack a match starting at
    /// the last byte of a restricted range needs.
    max_sequence_size: usize,
}

impl<'a, A> MemoryBytePatternSearcher<'a, A> {
    /// `MemoryBytePatternSearcher(searchName, root)` (:65).
    pub fn new(
        root: &'a SequenceSearchState,
        patterns: &'a [Pattern<A>],
    ) -> MemoryBytePatternSearcher<'a, A> {
        let max_sequence_size = patterns.iter().map(|p| p.seq.size()).max().unwrap_or(0);
        MemoryBytePatternSearcher {
            root,
            patterns,
            do_executable_blocks_only: false,
            max_sequence_size,
        }
    }

    /// `setSearchExecutableOnly` (:88).
    pub fn set_search_executable_only(&mut self, only: bool) {
        self.do_executable_blocks_only = only;
    }

    /// `search(program, searchSet, monitor)` (:102) — every initialized (and, when configured,
    /// executable) block that the restrict set touches.
    ///
    /// `apply` is called with the **mark address** of each match that passes its post rules, in
    /// per-range order. Actions run after the whole range has been matched, exactly as in Ghidra
    /// (`searchBlock` collects `mymatches` for a range, then applies them), so an action that
    /// mutates the program cannot change which bytes matched in the same range.
    pub fn search<F>(&self, program: &mut Program, search_set: Option<&AddressSet>, apply: &mut F)
    where
        F: FnMut(&mut Program, Address, &Match<A>),
    {
        // Block descriptors are copied out first: the search reads bytes (immutable) and the
        // actions mutate the program, so the two phases cannot share a borrow.
        let blocks: Vec<(Address, Address, bool, bool)> = program
            .memory
            .blocks()
            .map(|b| (b.start(), b.end(), b.is_initialized(), b.is_execute()))
            .collect();
        for (start, end, initialized, execute) in blocks {
            if !initialized {
                continue;
            }
            if self.do_executable_blocks_only && !execute {
                continue;
            }
            if let Some(s) = search_set {
                if !s.is_empty() && s.intersect(&block_range(start, end)).is_empty() {
                    continue;
                }
            }
            self.search_block(program, start, end, search_set, apply);
        }
    }

    /// `searchBlock(rootState, program, block, restrictSet, monitor)` (:167).
    fn search_block<F>(
        &self,
        program: &mut Program,
        block_start: Address,
        block_end: Address,
        restrict_set: Option<&AddressSet>,
        apply: &mut F,
    ) where
        F: FnMut(&mut Program, Address, &Match<A>),
    {
        // "if no restricted set, make restrict set the full block" (:172-178).
        let done_set = match restrict_set {
            Some(s) if !s.is_empty() => s.intersect(&block_range(block_start, block_end)),
            _ => block_range(block_start, block_end),
        };

        let space = block_start.space;
        let ranges: Vec<(u64, u64)> = done_set.ranges().map(|r| (r.min, r.max)).collect();
        for (rmin, rmax) in ranges {
            // "Give block a starting/ending point before this address to search — patterns might
            // start before, since they have a pre-pattern" (:200-210).
            let block_offset =
                (rmin - block_start.offset).saturating_sub(RESTRICTED_PATTERN_BYTE_RANGE);
            let max_block_search_length = rmax - block_start.offset - block_offset + 1;

            // Read only the range plus the slack a pattern starting at its last byte needs
            // (`maxBytes += getMaxSequenceSize() + 1`, SequenceSearchState.java:274-276). Reading
            // to the end of the block instead makes a search whose restrict set has many ranges
            // quadratic in the block size — which the "After Code" pass, re-triggered by every
            // disassembly round, hits immediately.
            let want = max_block_search_length + self.max_sequence_size as u64 + 1;
            let avail = block_end.offset - block_start.offset - block_offset + 1;
            let data = program.memory.read_window(
                Address::new(space, block_start.offset + block_offset),
                want.min(avail) as usize,
            );
            let mut seq_matches = Vec::new();
            self.root.apply(&data, max_block_search_length as usize, &mut seq_matches);

            // `streamoffset` is the block's own address (:198); post rules see the match's
            // absolute address (:233).
            let streamoffset = block_start.offset;
            for sm in seq_matches {
                let m = Match {
                    pattern: &self.patterns[sm.seq_index],
                    sequence_index: sm.seq_index,
                    offset: sm.offset,
                };
                if !m.check_post_rules(streamoffset + block_offset) {
                    continue;
                }
                let addr = Address::new(space, block_start.offset + m.mark_offset() + block_offset);
                apply(program, addr, &m);
            }
        }
    }
}
