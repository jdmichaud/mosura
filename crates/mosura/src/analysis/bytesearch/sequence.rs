//! `SequenceSearchState` — a port of
//! `Features/Base/.../ghidra/util/bytesearch/SequenceSearchState.java`.
//!
//! The DFA that matches every [`DittedBitSequence`] in a set against a byte stream in one pass.
//! It is built level by level (`buildTransitionLevel`, :408): level *n* holds one state per
//! distinct set of patterns still viable after *n* bytes, with a 256-way transition table.
//! Identical states within a level are merged (:144), which is what keeps the machine small.
//!
//! Java threads the states as an object graph; here they live in an arena (`nodes`) and
//! transitions are indices, with [`NONE`] standing in for Java's `null`. The algorithm is
//! otherwise a literal translation, including the lexicographic state comparison on pattern
//! indices that drives the dedup.

use super::ditted::DittedBitSequence;

/// Arena stand-in for Java's `null` state pointer.
const NONE: u32 = u32::MAX;

struct Node {
    /// `parent` (:31) — used only by [`merge`](SequenceSearchState::merge) to rewire transitions.
    parent: u32,
    /// `possible` (:32) — patterns that could still match in this state, by pattern index.
    possible: Vec<usize>,
    /// `success` (:33) — patterns that have matched if we reached this state.
    success: Option<Vec<usize>>,
    /// `trans` (:34) — state transition per next byte; empty until the level is built.
    trans: Vec<u32>,
}

/// One reported hit: which pattern matched, and the stream offset it started at
/// (`Match`, Match.java:23 — the `getMarkOffset` adjustment lives on
/// [`Pattern`](super::pattern::Pattern), which owns the mark).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SeqMatch {
    /// Index into the pattern list the machine was built from.
    pub seq_index: usize,
    /// Offset within the searched buffer where the match started.
    pub offset: u64,
}

/// The compiled multi-pattern matcher (`SequenceSearchState`, :28).
pub struct SequenceSearchState {
    nodes: Vec<Node>,
}

impl SequenceSearchState {
    /// `buildStateMachine(patterns)` (:447). The sequences are indexed by position in the list;
    /// that index is what a [`SeqMatch`] reports and what orders the DFA's dedup.
    pub fn build_state_machine(patterns: &mut [DittedBitSequence]) -> SequenceSearchState {
        for (i, pat) in patterns.iter_mut().enumerate() {
            pat.set_index(i);
        }
        let mut st = SequenceSearchState { nodes: Vec::new() };
        // `root.addSequence(pat, 0)` for every pattern, then sort by index (:450-455).
        let root = st.new_node(NONE);
        for (i, pat) in patterns.iter().enumerate() {
            st.add_sequence(root, i, pat.size(), 0);
        }
        st.sort_sequences(root);

        let mut statelevel = vec![root];
        let mut level = 0usize;
        while !statelevel.is_empty() {
            statelevel = st.build_transition_level(&statelevel, patterns, level);
            level += 1;
        }
        st
    }

    fn new_node(&mut self, parent: u32) -> u32 {
        self.nodes.push(Node { parent, possible: Vec::new(), success: None, trans: Vec::new() });
        (self.nodes.len() - 1) as u32
    }

    /// `addSequence(pat, pos)` (:68) — the last pattern added is a successful match when `pos`
    /// has reached the pattern's length.
    fn add_sequence(&mut self, node: u32, pat_index: usize, pat_size: usize, pos: usize) {
        let n = &mut self.nodes[node as usize];
        n.possible.push(pat_index);
        if pos == pat_size {
            n.success.get_or_insert_with(Vec::new).push(pat_index);
        }
    }

    /// `sortSequences()` (:81).
    fn sort_sequences(&mut self, node: u32) {
        let n = &mut self.nodes[node as usize];
        n.possible.sort_unstable();
        if let Some(s) = n.success.as_mut() {
            s.sort_unstable();
        }
    }

    /// `compareTo(o)` (:95) — lexicographic comparison of the `possible` index sequences.
    fn compare(&self, a: u32, b: u32) -> std::cmp::Ordering {
        self.nodes[a as usize].possible.cmp(&self.nodes[b as usize].possible)
    }

    /// `buildSingleTransition(all, pos, val)` (:116).
    fn build_single_transition(
        &mut self,
        state: u32,
        patterns: &[DittedBitSequence],
        res: &mut Vec<u32>,
        pos: usize,
        val: u8,
    ) {
        let mut newstate = NONE;
        // Cloned so the arena can be mutated while iterating this state's pattern list.
        let possible = self.nodes[state as usize].possible.clone();
        for curpat in possible {
            if patterns[curpat].is_match(pos, val) {
                if newstate == NONE {
                    newstate = self.new_node(state);
                }
                self.add_sequence(newstate, curpat, patterns[curpat].size(), pos + 1);
            }
        }
        self.nodes[state as usize].trans[val as usize] = newstate;
        if newstate != NONE {
            self.sort_sequences(newstate);
            res.push(newstate);
        }
    }

    /// `buildTransitionLevel(prev, pos)` (:408) — one level of the machine, deduped.
    fn build_transition_level(
        &mut self,
        prev: &[u32],
        patterns: &[DittedBitSequence],
        pos: usize,
    ) -> Vec<u32> {
        let mut res: Vec<u32> = Vec::new();
        for &next in prev {
            self.nodes[next as usize].trans = vec![NONE; 256];
            for i in 0..256u32 {
                self.build_single_transition(next, patterns, &mut res, pos, i as u8);
            }
        }
        if res.is_empty() {
            return res;
        }
        // Dedup the states (:422-438): sort, then merge each run of identical ones.
        res.sort_by(|a, b| self.compare(*a, *b));
        let mut finalres: Vec<u32> = Vec::new();
        let mut curpat = res[0];
        finalres.push(curpat);
        for &nextpat in &res[1..] {
            if self.compare(curpat, nextpat) == std::cmp::Ordering::Equal {
                self.merge(curpat, nextpat);
            } else {
                curpat = nextpat;
                finalres.push(curpat);
            }
        }
        finalres
    }

    /// `merge(op)` (:144) — fold `op` into `keep`: rewire `op`'s parent transitions and take the
    /// sorted union of the two success lists.
    fn merge(&mut self, keep: u32, op: u32) {
        let parent = self.nodes[op as usize].parent;
        if parent != NONE {
            for i in 0..256 {
                if self.nodes[parent as usize].trans[i] == op {
                    self.nodes[parent as usize].trans[i] = keep;
                }
            }
        }
        let op_success = self.nodes[op as usize].success.take();
        if let Some(op_success) = op_success {
            match self.nodes[keep as usize].success.take() {
                None => self.nodes[keep as usize].success = Some(op_success),
                Some(mine) => {
                    // Both lists are index-sorted; the Java merge is a sorted union that drops
                    // duplicates (:156-192).
                    let mut tmp: Vec<usize> = Vec::with_capacity(mine.len() + op_success.len());
                    let (mut i, mut j) = (0usize, 0usize);
                    while i < mine.len() || j < op_success.len() {
                        let take_mine = match (mine.get(i), op_success.get(j)) {
                            (Some(a), Some(b)) => a <= b,
                            (Some(_), None) => true,
                            _ => false,
                        };
                        let v = if take_mine {
                            i += 1;
                            mine[i - 1]
                        } else {
                            j += 1;
                            op_success[j - 1]
                        };
                        if tmp.last() != Some(&v) {
                            tmp.push(v);
                        }
                    }
                    self.nodes[keep as usize].success = Some(tmp);
                }
            }
        }
    }

    /// `apply(buffer, match)` (:226) — every (pattern, offset) hit in `buffer`.
    ///
    /// `max_start` bounds the *starting* offsets tried, mirroring the `maxBytes` argument of the
    /// streaming overload (:266): a pattern that starts inside the searched range is allowed to
    /// run past its end, which is why the two are separate (:274-276).
    pub fn apply(&self, buffer: &[u8], max_start: usize, out: &mut Vec<SeqMatch>) {
        let limit = max_start.min(buffer.len());
        for offset in 0..limit {
            let mut curstate = 0u32; // root
            let mut subindex = offset;
            loop {
                if let Some(success) = &self.nodes[curstate as usize].success {
                    for &s in success {
                        out.push(SeqMatch { seq_index: s, offset: offset as u64 });
                    }
                }
                if subindex >= buffer.len() {
                    break; // out of bytes, restart at the next offset
                }
                let t = &self.nodes[curstate as usize].trans;
                if t.is_empty() {
                    break; // leaf level: no transitions were ever built
                }
                curstate = t[buffer[subindex] as usize];
                subindex += 1;
                if curstate == NONE {
                    break;
                }
            }
        }
    }

    /// `getMaxSequenceSize()` (:51) — the longest pattern the machine can match.
    pub fn max_sequence_size(&self, patterns: &[DittedBitSequence]) -> usize {
        self.nodes
            .first()
            .map(|root| root.possible.iter().map(|&i| patterns[i].size()).max().unwrap_or(0))
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn seqs(specs: &[&str]) -> Vec<DittedBitSequence> {
        specs.iter().map(|s| DittedBitSequence::parse(s).unwrap().0).collect()
    }

    #[test]
    fn finds_every_pattern_at_every_offset() {
        let mut pats = seqs(&["0x5589e5", "0x89e5", "01010..."]);
        let machine = SequenceSearchState::build_state_machine(&mut pats);
        // push ebx; push ebp; mov ebp,esp
        let buf = [0x53u8, 0x55, 0x89, 0xe5, 0x83];
        let mut out = Vec::new();
        machine.apply(&buf, buf.len(), &mut out);
        out.sort_by_key(|m| (m.offset, m.seq_index));
        assert_eq!(
            out,
            vec![
                SeqMatch { seq_index: 2, offset: 0 }, // push ebx
                SeqMatch { seq_index: 0, offset: 1 }, // 55 89 e5
                SeqMatch { seq_index: 2, offset: 1 }, // push ebp
                SeqMatch { seq_index: 1, offset: 2 }, // 89 e5
            ]
        );
    }

    #[test]
    fn max_start_bounds_starts_but_not_match_length() {
        let mut pats = seqs(&["0x5589e5"]);
        let machine = SequenceSearchState::build_state_machine(&mut pats);
        let buf = [0x90u8, 0x55, 0x89, 0xe5];
        // Only offset 0 may START a match, but the pattern beginning at 1 must not be reported.
        let mut out = Vec::new();
        machine.apply(&buf, 1, &mut out);
        assert!(out.is_empty());
        // With starts allowed through offset 1 the match is found, and it reads past `max_start`
        // into bytes 2..4 — the property the streaming overload's `maxBytes` slack exists for.
        let mut out = Vec::new();
        machine.apply(&buf, 2, &mut out);
        assert_eq!(out, vec![SeqMatch { seq_index: 0, offset: 1 }]);
    }

    #[test]
    fn identical_states_are_merged_not_duplicated() {
        // Two patterns whose first byte differs but whose tails are identical: the level-1 states
        // are distinct, the level-2 states are identical and must merge into one.
        let mut pats = seqs(&["0x55aa", "0x56aa"]);
        let machine = SequenceSearchState::build_state_machine(&mut pats);
        let mut out = Vec::new();
        machine.apply(&[0x55, 0xaa, 0x56, 0xaa], 4, &mut out);
        out.sort_by_key(|m| (m.offset, m.seq_index));
        assert_eq!(
            out,
            vec![SeqMatch { seq_index: 0, offset: 0 }, SeqMatch { seq_index: 1, offset: 2 }]
        );
    }
}
