//! Control-flow structuring — Ghidra's `CollapseStructure` (`blockaction.cc`) over a
//! `BlockGraph` (`block.cc`). Repeatedly collapses CFG patterns into structured blocks
//! (list/if/if-else/while/do-while) until one block remains, recovering `if`/`while`/`for`
//! from the goto-level CFG.
//!
//! The graph is a vector of [`FlowBlock`]s; each structured block lists its sub-blocks and
//! presents the same successor interface, so the rules compose. Out-edges are the source of
//! truth; in-edges are recomputed each pass. CBRANCH order is `[false, true]` (as built by
//! `cfg`). This increment ports the reducible patterns; gotos for irreducible regions,
//! switches, and short-circuit conditions are later additions.

use std::collections::{HashMap, HashSet};

use super::block::BlockId;
use super::funcdata::Funcdata;
use super::opcode::OpCode;

/// Boolean properties on a structuring edge — Ghidra's `FlowBlock::edge_flags` (block.hh:108).
/// The label is owned by the source block's out-edge (mosura mirrors Ghidra's `BlockEdge::label`);
/// the reverse in-edge view is derived from the recomputed predecessor lists. These labels are
/// written by the structuring passes that land in later bricks (structureLoops sets
/// `TREE`/`FORWARD`/`CROSS`/`BACK`/`LOOP`/`IRREDUCIBLE`; LoopBody sets `LOOP_EXIT`; selectGoto sets
/// `GOTO`). The current collapse rules do not read them, so a default-clean (`0`) label is
/// byte-identical.
#[allow(dead_code)]
pub mod edge_flags {
    pub const GOTO_EDGE: u32 = 1; // f_goto_edge — edge is unstructured
    pub const LOOP_EDGE: u32 = 2; // f_loop_edge — removing these edges yields a DAG
    pub const DEFAULTSWITCH_EDGE: u32 = 4; // f_defaultswitch_edge — default edge from a switch
    pub const IRREDUCIBLE: u32 = 8; // f_irreducible — must be removed to make the graph reducible
    pub const TREE_EDGE: u32 = 0x10; // f_tree_edge — an edge in the spanning tree
    pub const FORWARD_EDGE: u32 = 0x20; // f_forward_edge — jumps forward in the spanning tree
    pub const CROSS_EDGE: u32 = 0x40; // f_cross_edge — crosses subtrees in the spanning tree
    pub const BACK_EDGE: u32 = 0x80; // f_back_edge — a back edge defining a loop
    pub const LOOP_EXIT_EDGE: u32 = 0x100; // f_loop_exit_edge — edge exits a loop body
}

/// Boolean properties on a structuring block — Ghidra's `FlowBlock::block_flags` (block.hh:88).
/// Written by later bricks (`MARK`/`MARK2` are the generic graph-walk marks used by structureLoops
/// and LoopBody; `SWITCH_OUT` marks a switch head; `INTERIOR_GOTOIN`/`OUT` and `UNSTRUCTURED_TARG`
/// track unstructured jumps into/out of a block's interior). Unread by the current rules → the
/// default `0` is byte-identical.
#[allow(dead_code)]
pub mod block_flags {
    pub const SWITCH_OUT: u32 = 0x10; // f_switch_out — output is decided by a switch
    pub const UNSTRUCTURED_TARG: u32 = 0x20; // f_unstructured_targ — destination of an unstructured goto
    pub const MARK: u32 = 0x80; // f_mark — generic block mark
    pub const MARK2: u32 = 0x100; // f_mark2 — secondary block mark
    pub const INTERIOR_GOTOOUT: u32 = 0x400; // f_interior_gotoout — unstructured jump out of interior
    pub const INTERIOR_GOTOIN: u32 = 0x800; // f_interior_gotoin — target of unstructured jump to interior
}

/// Whether the negation of block `bid`'s terminating CBRANCH condition folds cleanly into a single
/// complementary comparison via [`RuleBoolNegate`](super::rules::RuleBoolNegate) — i.e. the condition
/// varnode is written and its defining op is one of the comparisons `RuleBoolNegate` complements
/// (`==`/`!=`/`<`/`<=` and their signed/float forms). Only such conditions are materialized by the
/// branch-orientation stage; compound (`BOOL_AND`/`BOOL_OR`) or other booleans are left to the
/// deferred normal-form flip (Ghidra's `opFlipInPlaceExecute`).
fn condition_folds_cleanly(f: &Funcdata, bid: BlockId) -> bool {
    let Some(&last) = f.block(bid).ops.last() else {
        return false;
    };
    if f.op(last).code() != OpCode::Cbranch {
        return false;
    }
    let Some(cond) = f.op(last).input(1) else {
        return false;
    };
    let v = f.vn(cond);
    if !v.is_written() {
        return false;
    }
    matches!(
        f.op(v.def.unwrap()).code(),
        OpCode::IntEqual
            | OpCode::IntNotequal
            | OpCode::IntLess
            | OpCode::IntLessequal
            | OpCode::IntSless
            | OpCode::IntSlessequal
            | OpCode::FloatEqual
            | OpCode::FloatNotequal
            | OpCode::FloatLess
            | OpCode::FloatLessequal
    )
}

/// A node in the structuring graph: a leaf basic block or a structured composite.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FlowKind {
    Basic(BlockId),
    /// Sequence; components run in order.
    List,
    /// `if (cond) then` — components `[cond, then]`.
    If,
    /// `if (cond) tc else fc` — components `[cond, tc, fc]`.
    IfElse,
    /// `while (cond) body` — components `[cond, body]`.
    WhileDo,
    /// `do body while (cond)` — components `[body]`.
    DoWhile,
    /// Short-circuit `a && b` — components `[a, b]`; still a two-out condition block.
    CondAnd,
    /// Short-circuit `a || b` — components `[a, b]`; still a two-out condition block.
    CondOr,
    /// `switch` — components `[head, case0, case1, …]`; head ends in BRANCHIND.
    Switch,
}

#[derive(Clone, Debug)]
pub struct FlowBlock {
    pub kind: FlowKind,
    pub components: Vec<usize>,
    pub out_edges: Vec<usize>,
    /// Per-out-edge boolean labels — Ghidra's `BlockEdge::label` ([`edge_flags`], block.hh:108),
    /// parallel to `out_edges`. Written by the structuring passes landing in Bricks 1-4; the current
    /// collapse rules do not read it, so it stays clean (`0`) and the output is byte-identical.
    pub out_labels: Vec<u32>,
    /// Block-level boolean flags — Ghidra's `FlowBlock::flags` ([`block_flags`], block.hh:88).
    pub flags: u32,
    pub active: bool,
    /// For `If`/`IfElse`/`WhileDo`/`DoWhile`: the body/then is reached on the condition's
    /// *false* edge, so the printed condition must be negated.
    pub negated: bool,
}

#[allow(dead_code)]
impl FlowBlock {
    /// Label the `i`-th out-edge with `flag` — Ghidra's `FlowBlock::setOutEdgeFlag` (block.hh:307).
    fn set_out_edge_flag(&mut self, i: usize, flag: u32) {
        self.out_labels[i] |= flag;
    }
    /// Clear `flag` from the `i`-th out-edge — Ghidra's `FlowBlock::clearOutEdgeFlag` (block.hh:308).
    fn clear_out_edge_flag(&mut self, i: usize, flag: u32) {
        self.out_labels[i] &= !flag;
    }
    /// Set a block-level flag — Ghidra's `FlowBlock::setFlag` (block.hh:280).
    fn set_flag(&mut self, flag: u32) {
        self.flags |= flag;
    }
    /// Clear a block-level flag — Ghidra's `FlowBlock::clearFlag` (block.hh:281).
    fn clear_flag(&mut self, flag: u32) {
        self.flags &= !flag;
    }

    /// The `i`-th out-edge is a "decision" (not irreducible/back/goto) — Ghidra's
    /// `FlowBlock::isDecisionOut` (block.hh:336).
    fn is_decision_out(&self, i: usize) -> bool {
        use edge_flags::*;
        self.out_labels[i] & (IRREDUCIBLE | BACK_EDGE | GOTO_EDGE) == 0
    }
    /// The `i`-th out-edge stays within the reducible loop DAG (not irreducible/back/loop-exit/goto)
    /// — Ghidra's `FlowBlock::isLoopDAGOut` (block.hh:342).
    fn is_loop_dag_out(&self, i: usize) -> bool {
        use edge_flags::*;
        self.out_labels[i] & (IRREDUCIBLE | BACK_EDGE | LOOP_EXIT_EDGE | GOTO_EDGE) == 0
    }
    /// The `i`-th out-edge is unstructured (goto or irreducible) — Ghidra's `FlowBlock::isGotoOut`
    /// (block.hh:347).
    fn is_goto_out(&self, i: usize) -> bool {
        use edge_flags::*;
        self.out_labels[i] & (IRREDUCIBLE | GOTO_EDGE) != 0
    }
    /// The `i`-th out-edge is a loop back-edge — Ghidra's `FlowBlock::isBackEdgeOut` (block.hh:331).
    fn is_back_edge_out(&self, i: usize) -> bool {
        self.out_labels[i] & edge_flags::BACK_EDGE != 0
    }
    /// This block's output is decided by a switch — Ghidra's `FlowBlock::isSwitchOut` (block.hh:326).
    fn is_switch_out(&self) -> bool {
        self.flags & block_flags::SWITCH_OUT != 0
    }
    /// There is an unstructured jump into this block's interior — Ghidra's
    /// `FlowBlock::isInteriorGotoTarget` (block.hh:323).
    fn is_interior_goto_target(&self) -> bool {
        self.flags & block_flags::INTERIOR_GOTOIN != 0
    }
}

/// The structured-block forest; `root` is the single block the CFG collapsed to (or the
/// entry, if the CFG was irreducible and could not fully collapse).
pub struct Structured {
    pub blocks: Vec<FlowBlock>,
    pub root: usize,
    /// Edges cut to gotos for an irreducible region: source exit basic block → (target
    /// entry basic block, negated condition). An unconditional source has no CBRANCH.
    pub gotos: HashMap<BlockId, (BlockId, bool)>,
    /// Basic blocks that are goto targets (get a label).
    pub labels: HashSet<BlockId>,
    /// Per basic block: whether its terminating CBRANCH was branch-oriented (Ghidra's `fallthru_true`
    /// flag). An oriented block's body-on-false negation is already materialized positive in the IR,
    /// so the collapse rules XOR this in to flip its `negated` off. Precomputed from `Funcdata`.
    oriented: Vec<bool>,
    /// Reverse-post-order number per leaf block — Ghidra's `FlowBlock::index` set by
    /// [`structure_loops`] (`findSpanningTree`). Loop ordering (`compare_ends`/`compare_head`) keys on
    /// it. Indexed by leaf block id.
    rpo: Vec<i32>,
    /// The loop records built by [`order_loop_bodies`] (Ghidra's `CollapseStructure::loopbody`) — head,
    /// tails, exit block, and exit edges per loop, in nesting order. Brick 2 computes them inert (the
    /// selectGoto driver that consumes them lands in Brick 4), so this stays unread.
    #[allow(dead_code)]
    loopbody: Vec<LoopBody>,
}

/// An edge tracked across graph collapse by its endpoints — Ghidra's `FloatingEdge`
/// (blockaction.hh). Stored as leaf block indices; the current-form lookup (`getCurrentEdge`, which
/// walks the collapse hierarchy) lands with the selectGoto driver in Brick 4 that reads these fields.
#[derive(Clone, Debug)]
#[allow(dead_code)]
struct FloatingEdge {
    top: usize,
    bottom: usize,
}

/// One natural loop — Ghidra's `LoopBody` (blockaction.hh). `head` is the loop head (`None` once a
/// same-head body has been merged away by `mergeIdenticalHeads`); `tails` are the back-edge sources;
/// `exitblock`/`exitedges` are the single structured exit and the edges leaving the body; `depth`
/// and `immed_container` record the nesting. Block fields are leaf indices.
#[derive(Clone, Debug)]
struct LoopBody {
    head: Option<usize>,
    tails: Vec<usize>,
    depth: i32,
    uniquecount: usize,
    exitblock: Option<usize>,
    exitedges: Vec<FloatingEdge>,
    immed_container: Option<usize>,
}

impl Structured {
    /// The entry basic block of a structured block (where a goto label would go).
    fn entry_basic(&self, idx: usize) -> Option<BlockId> {
        match &self.blocks[idx].kind {
            FlowKind::Basic(b) => Some(*b),
            _ => self.entry_basic(*self.blocks[idx].components.first()?),
        }
    }
    /// The exit basic block of a structured block (where its terminating branch lives).
    fn exit_basic(&self, idx: usize) -> Option<BlockId> {
        match &self.blocks[idx].kind {
            FlowKind::Basic(b) => Some(*b),
            _ => self.exit_basic(*self.blocks[idx].components.last()?),
        }
    }

    /// The CBRANCH basic blocks whose branch sense the structurer negated because the body is on
    /// the *false* edge — the blocks Ghidra's `CollapseStructure` runs `negateCondition` on. Only
    /// the branch-direction kinds (`If`/`WhileDo`/`DoWhile`) qualify; an `IfElse`'s `negated` is the
    /// normal-form flip (Ghidra's `ActionNormalizeBranches` / `opFlipInPlaceExecute`, mechanism A),
    /// which is still applied at print time. The condition CBRANCH of a composite is the exit of its
    /// first component (the `render_condition` path reads `exit_basic(components[0])`). Consumed by
    /// [`ActionOrientBranches`] to materialize the negation in the IR.
    pub fn branch_negations(&self, f: &Funcdata) -> Vec<BlockId> {
        let mut out = Vec::new();
        self.collect_negations(self.root, f, &mut out);
        out
    }

    /// Walk the *final* structured tree from `idx` (as [`emit_structured`](super::printc) does),
    /// collecting each rendered negated `if`/`while`/`do-while`'s condition CBRANCH block. Walking
    /// from the root — rather than scanning every `FlowBlock` — skips stale intermediate composites
    /// that were superseded during collapse (e.g. a guard temporarily structured as a negated `if`
    /// then folded into a `switch`): those are never rendered, so orienting them would corrupt the
    /// switch. See [`branch_negations`](Self::branch_negations).
    fn collect_negations(&self, idx: usize, f: &Funcdata, out: &mut Vec<BlockId>) {
        let fb = &self.blocks[idx];
        if fb.negated && matches!(fb.kind, FlowKind::If | FlowKind::WhileDo | FlowKind::DoWhile) {
            if let Some(&cond) = fb.components.first() {
                if matches!(self.blocks[cond].kind, FlowKind::CondAnd | FlowKind::CondOr) {
                    // Compound `&&`/`||` (short-circuit) condition: Ghidra's
                    // `BlockCondition::negateCondition` (block.cc:3023) distributes the NOT to each
                    // short-circuit leaf. Orient every leaf CBRANCH so RuleCondNegate materializes it
                    // (RuleBoolNegate + RuleIntLessEqual then normalize) — all-or-nothing, matching
                    // Ghidra's recursion over both sides; the connective is re-derived by De Morgan.
                    if let Some(mut leaves) = self.compound_leaves(cond, f) {
                        out.append(&mut leaves);
                    }
                } else if let Some(bid) = self.exit_basic(cond) {
                    // Simple condition: orient it when its materialized negation folds cleanly via
                    // RuleBoolNegate (its def is a comparison) and it is not a switch guard.
                    if condition_folds_cleanly(f, bid) {
                        out.push(bid);
                    }
                }
            }
        }
        for &c in &self.blocks[idx].components {
            self.collect_negations(c, f, out);
        }
    }

    /// The leaf CBRANCH blocks of a (possibly nested) short-circuit compound, for branch orientation —
    /// mirroring Ghidra's `BlockCondition::negateCondition` (block.cc:3023) distributing the NOT to
    /// each side (it recurses over both operands). Returns `None` (orient nothing) unless EVERY leaf is
    /// a cleanly-foldable comparison ([`condition_folds_cleanly`]) that is not a switch guard —
    /// all-or-nothing, matching Ghidra's recursion that negates every side, and leaving a compound with
    /// a non-foldable leaf (e.g. a nested `NAN`/`BOOL_OR` test) on the deferred print-time De Morgan.
    fn compound_leaves(&self, cond: usize, f: &Funcdata) -> Option<Vec<BlockId>> {
        match self.blocks[cond].kind {
            FlowKind::CondAnd | FlowKind::CondOr => {
                let c0 = self.blocks[cond].components[0];
                let c1 = self.blocks[cond].components[1];
                let mut a = self.compound_leaves(c0, f)?;
                let mut b = self.compound_leaves(c1, f)?;
                a.append(&mut b);
                Some(a)
            }
            _ => {
                let bid = self.exit_basic(cond)?;
                (condition_folds_cleanly(f, bid)).then_some(vec![bid])
            }
        }
    }

    /// Predecessor lists for the currently-active blocks, from their out-edges.
    fn in_edges(&self) -> Vec<Vec<usize>> {
        let mut ins = vec![Vec::new(); self.blocks.len()];
        for b in 0..self.blocks.len() {
            if self.blocks[b].active {
                for &o in &self.blocks[b].out_edges {
                    ins[o].push(b);
                }
            }
        }
        ins
    }

    /// Replace `components` (entry = `components[0]`) with one structured block of `kind`
    /// and the given external `out_edges`. Predecessors of the entry are redirected to the
    /// new block; components are deactivated.
    fn install(&mut self, components: Vec<usize>, kind: FlowKind, out_edges: Vec<usize>, ins: &[Vec<usize>]) -> usize {
        let entry = components[0];
        let compset: HashSet<usize> = components.iter().copied().collect();
        let n = self.blocks.len();
        let preds: Vec<usize> = ins[entry].iter().copied().filter(|p| !compset.contains(p)).collect();
        // New composite edges start unlabeled (Brick 0: default-clean, byte-identical); the faithful
        // edge-label propagation from the collapsed sub-blocks lands with the flag-consuming rules.
        let out_labels = vec![0u32; out_edges.len()];
        self.blocks.push(FlowBlock { kind, components, out_edges, out_labels, flags: 0, active: true, negated: false });
        for p in preds {
            for e in self.blocks[p].out_edges.iter_mut() {
                if compset.contains(e) {
                    *e = n;
                }
            }
        }
        for &c in &self.blocks[n].components.clone() {
            self.blocks[c].active = false;
        }
        n
    }

    /// `ruleBlockSwitch`: a block with ≥3 out-edges is a switch head (a BRANCHIND). Collapse
    /// it with its single-entry case successors into a `Switch`; the remaining edges (shared
    /// / default cases, or break targets) are the switch's exits.
    fn rule_switch(&mut self, b: usize, ins: &[Vec<usize>]) -> bool {
        if self.out(b).len() < 3 {
            return false;
        }
        // Defer until each single-entry case has fully collapsed: a case with internal control
        // flow (an `if` in its body, >1 exit) must structure first, and a case whose single
        // exit is its own continuation block (a single-entry "break" tail) must `cat` that tail
        // in first — otherwise those tails leak as extra switch exits and the dispatch nests
        // into gotos (the switch-in-loop case).
        for c in self.blocks[b].out_edges.clone() {
            if c == b || ins[c].len() != 1 {
                continue;
            }
            let outc: Vec<usize> = self.out(c).to_vec();
            if outc.len() > 1 || (outc.len() == 1 && outc[0] != b && ins[outc[0]].len() == 1) {
                return false;
            }
        }
        let mut comps = vec![b];
        let mut exits: Vec<usize> = Vec::new();
        for c in self.blocks[b].out_edges.clone() {
            if c == b {
                return false;
            }
            if ins[c].len() == 1 && self.out(c).len() <= 1 {
                comps.push(c);
                exits.extend(self.out(c).iter().copied());
            } else {
                exits.push(c);
            }
        }
        if comps.len() < 2 {
            return false;
        }
        exits.retain(|e| !comps.contains(e));
        exits.sort_unstable();
        exits.dedup();
        self.install(comps, FlowKind::Switch, exits, ins);
        true
    }

    /// Try every rule on `b`; return whether one fired (and changed the graph).
    fn try_rules(&mut self, b: usize, ins: &[Vec<usize>]) -> bool {
        self.rule_switch(b, ins)
            || self.rule_cat(b, ins)
            || self.rule_short_circuit(b, ins)
            || self.rule_proper_if(b, ins)
            || self.rule_if_else(b, ins)
            || self.rule_while_do(b, ins)
            || self.rule_do_while(b, ins)
            // after the loop rules: a loop exit is terminal too, so loops must match first
            || self.rule_if_no_exit(b, ins)
    }

    /// `ruleBlockIfNoExit`: `if (cond) clause` where the clause is a single-entry block with
    /// no exit (it returns/halts), so control continues to the other arm afterwards.
    fn rule_if_no_exit(&mut self, b: usize, ins: &[Vec<usize>]) -> bool {
        if self.out(b).len() != 2 || self.out(b)[0] == b || self.out(b)[1] == b {
            return false;
        }
        for i in 0..2 {
            let (clause, other) = (self.out(b)[i], self.out(b)[1 - i]);
            if clause != other && ins[clause].len() == 1 && self.out(clause).is_empty() {
                // don't dissolve a loop header: if the other arm flows back to `b`, this is the
                // exit test of a loop — leave it for the loop rules (after the body collapses).
                if self.reaches(other, b) {
                    continue;
                }
                let n = self.install(vec![b, clause], FlowKind::If, vec![other], ins);
                self.blocks[n].negated = (i == 0) ^ self.is_oriented(b);
                return true;
            }
        }
        false
    }

    /// Whether `from` can reach `target` over the current (active) structure graph.
    fn reaches(&self, from: usize, target: usize) -> bool {
        let mut seen = vec![false; self.blocks.len()];
        let mut stack = vec![from];
        while let Some(x) = stack.pop() {
            if x == target {
                return true;
            }
            if std::mem::replace(&mut seen[x], true) {
                continue;
            }
            stack.extend_from_slice(self.out(x));
        }
        false
    }

    /// `ruleBlockCondition`: two chained condition blocks collapse to a short-circuit
    /// condition. For `a && b`, `a`'s *true* edge enters `b` and both *false* edges share an
    /// exit; for `a || b`, `a`'s *false* edge enters `b` and both *true* edges share. The
    /// result is itself a two-out condition block (structured later by the `if` rules).
    fn rule_short_circuit(&mut self, b: usize, ins: &[Vec<usize>]) -> bool {
        if self.out(b).len() != 2 {
            return false;
        }
        for and in [true, false] {
            let (cont, shared) = if and { (1, 0) } else { (0, 1) };
            let bb = self.out(b)[cont]; // the second condition
            if bb == b || ins[bb].len() != 1 || self.out(bb).len() != 2 {
                continue;
            }
            if self.out(b)[shared] == bb || self.out(b)[shared] != self.out(bb)[shared] {
                continue;
            }
            let out = self.blocks[bb].out_edges.clone();
            let kind = if and { FlowKind::CondAnd } else { FlowKind::CondOr };
            self.install(vec![b, bb], kind, out, ins);
            return true;
        }
        false
    }

    fn out(&self, b: usize) -> &[usize] {
        &self.blocks[b].out_edges
    }

    /// `ruleBlockGoto`: last resort for an irreducible region — when no structural rule
    /// fires, cut one in-edge of a merge block to a goto so structuring can proceed. The cut
    /// edge `b → t` is recorded (`b`'s exit emits `goto L_t`, `t`'s entry gets a label) and
    /// removed; `b` (now with one fewer out-edge) and `t` (one fewer in-edge) become
    /// reducible. Repeated until the graph collapses.
    fn rule_goto(&mut self) -> bool {
        let ins = self.in_edges();
        let active: Vec<usize> = (0..self.blocks.len()).filter(|&b| self.blocks[b].active).collect();
        for &t in &active {
            if ins[t].len() < 2 {
                continue;
            }
            for &b in &ins[t] {
                if b == t {
                    continue; // a self-loop is a do-while, not a goto
                }
                let Some(idx) = self.blocks[b].out_edges.iter().position(|&o| o == t) else {
                    continue;
                };
                let (Some(eb), Some(et)) = (self.exit_basic(b), self.entry_basic(t)) else {
                    continue;
                };
                self.gotos.insert(eb, (et, idx == 0)); // out[0] is the false edge
                self.labels.insert(et);
                self.blocks[b].out_edges.remove(idx);
                self.blocks[b].out_labels.remove(idx); // keep the parallel edge-label vec aligned
                return true;
            }
        }
        false
    }

    /// `ruleBlockCat`: a chain of single-out → single-in blocks becomes a list.
    fn rule_cat(&mut self, b: usize, ins: &[Vec<usize>]) -> bool {
        if self.out(b).len() != 1 {
            return false;
        }
        // if b's only predecessor has a single out, let that predecessor start the list
        if ins[b].len() == 1 && self.out(ins[b][0]).len() == 1 {
            return false;
        }
        let mut nodes = vec![b];
        let mut cur = b;
        loop {
            let nxt = self.out(cur)[0];
            if nxt == b || ins[nxt].len() != 1 {
                break;
            }
            nodes.push(nxt);
            cur = nxt;
            if self.out(cur).len() != 1 {
                break;
            }
        }
        if nodes.len() < 2 {
            return false;
        }
        let out = self.blocks[*nodes.last().unwrap()].out_edges.clone();
        self.install(nodes, FlowKind::List, out, ins);
        true
    }

    /// `ruleBlockProperIf`: `if (cond) clause` where `clause` reconverges to the other arm.
    fn rule_proper_if(&mut self, b: usize, ins: &[Vec<usize>]) -> bool {
        if self.out(b).len() != 2 || self.out(b)[0] == b || self.out(b)[1] == b {
            return false;
        }
        for i in 0..2 {
            let clause = self.out(b)[i];
            if ins[clause].len() == 1 && self.out(clause).len() == 1 && self.out(clause)[0] == self.out(b)[1 - i] {
                let merge = self.out(b)[1 - i];
                let n = self.install(vec![b, clause], FlowKind::If, vec![merge], ins);
                self.blocks[n].negated = (i == 0) ^ self.is_oriented(b);
                return true;
            }
        }
        false
    }

    /// Whether the condition CBRANCH of block `b` was branch-oriented (Ghidra's `fallthru_true`
    /// flag is set) — either by [`ActionOrientBranches`] (body-on-false negation, mechanism B) or by
    /// [`ActionPreferComplement`] (`if`/`else` normal-form flip, mechanism A). When so, the collapse
    /// rules flip `negated` off / swap the `if`/`else` arms: the flip is already materialized
    /// positive in the IR, so the condition prints directly. The mosura analogue of Ghidra's edge
    /// reversal (`BlockBasic::negateCondition` / `flipInPlaceExecute`), recorded in the flag instead
    /// so the re-deriving structurer collapses the original topology.
    fn is_oriented(&self, b: usize) -> bool {
        // A compound (`&&`/`||`) condition reports NOT oriented at the top level: its leaves are
        // oriented individually (Ghidra's `BlockCondition::negateCondition` distributes the NOT), so
        // the enclosing `if`/`while`'s `negated` (the De Morgan direction) must not read the last
        // leaf's flag — the per-leaf orientation is applied at print (printc `operand_oriented`).
        if matches!(self.blocks[b].kind, FlowKind::CondAnd | FlowKind::CondOr) {
            return false;
        }
        self.exit_basic(b).is_some_and(|bid| self.oriented.get(bid.0 as usize).copied().unwrap_or(false))
    }

    /// The condition CBRANCH basic blocks of `if`/`else` composites, in final-tree order — the split
    /// points Ghidra's `ActionPreferComplement` (blockaction.cc:2140) tests via
    /// `BlockIf::preferComplement` (block.cc:3093, only `getSize()==3`). Walks the final tree from
    /// the root (like [`collect_negations`](Self::collect_negations)) so superseded intermediate
    /// composites are skipped. Consumed by [`ActionPreferComplement`] to materialize the normal-form
    /// flip in the IR.
    pub fn if_else_splits(&self) -> Vec<BlockId> {
        let mut out = Vec::new();
        self.collect_if_else_splits(self.root, &mut out);
        out
    }

    fn collect_if_else_splits(&self, idx: usize, out: &mut Vec<BlockId>) {
        if matches!(self.blocks[idx].kind, FlowKind::IfElse) {
            if let Some(&cond) = self.blocks[idx].components.first() {
                if let Some(bid) = self.exit_basic(cond) {
                    out.push(bid);
                }
            }
        }
        for &c in &self.blocks[idx].components {
            self.collect_if_else_splits(c, out);
        }
    }

    /// `ruleBlockIfElse`: both arms reconverge to one block.
    fn rule_if_else(&mut self, b: usize, ins: &[Vec<usize>]) -> bool {
        if self.out(b).len() != 2 {
            return false;
        }
        let (fc, tc) = (self.out(b)[0], self.out(b)[1]);
        if ins[tc].len() != 1 || ins[fc].len() != 1 || self.out(tc).len() != 1 || self.out(fc).len() != 1 {
            return false;
        }
        let merge = self.out(tc)[0];
        if merge == b || merge != self.out(fc)[0] {
            return false;
        }
        // Ghidra `BlockIf::preferComplement` (block.cc:3093) materializes the if/else normal-form
        // flip in the IR (via [`ActionPreferComplement`]) and `swapBlocks(1,2)`. mosura reads the
        // resulting `fallthru_true` flag (`is_oriented`) to swap the then/else arms; the condition is
        // already positive in the IR, so it prints directly (`negated = false`). When the block was
        // not flipped, `is_oriented` is false and the taken edge `tc` is the then.
        let (then_c, else_c) = if self.is_oriented(b) { (fc, tc) } else { (tc, fc) };
        let n = self.install(vec![b, then_c, else_c], FlowKind::IfElse, vec![merge], ins);
        self.blocks[n].negated = false;
        true
    }

    /// `ruleBlockWhileDo`: one arm is a single-in/single-out block that loops back to `b`.
    fn rule_while_do(&mut self, b: usize, ins: &[Vec<usize>]) -> bool {
        if self.out(b).len() != 2 || self.out(b)[0] == b || self.out(b)[1] == b {
            return false;
        }
        for i in 0..2 {
            let body = self.out(b)[i];
            if ins[body].len() == 1 && self.out(body).len() == 1 && self.out(body)[0] == b {
                let exit = self.out(b)[1 - i];
                let n = self.install(vec![b, body], FlowKind::WhileDo, vec![exit], ins);
                self.blocks[n].negated = (i == 0) ^ self.is_oriented(b);
                return true;
            }
        }
        false
    }

    /// `ruleBlockDoWhile`: a block with a self-edge.
    fn rule_do_while(&mut self, b: usize, ins: &[Vec<usize>]) -> bool {
        if self.out(b).len() != 2 {
            return false;
        }
        for i in 0..2 {
            if self.out(b)[i] == b {
                let exit = self.out(b)[1 - i];
                let n = self.install(vec![b], FlowKind::DoWhile, vec![exit], ins);
                self.blocks[n].negated = (i == 0) ^ self.is_oriented(b);
                return true;
            }
        }
        false
    }
}

/// Ghidra's `BlockGraph::structureLoops` (block.cc:2194) run over the initial leaf graph: label the
/// CFG's loop back-edges and irreducible edges. It is `findSpanningTree` (block.cc:1009 — a DFS that
/// classifies every edge as tree/forward/cross/back) + `findIrreducible` (block.cc:1147, Tarjan's
/// algorithm marking the edges that must be removed to make the graph reducible) + `calcLoop`
/// (block.cc:2104, a safety net that marks any residual directed cycle as a loop edge). Sets the
/// `BACK`/`LOOP`/`IRREDUCIBLE` (and the transient `TREE`/`FORWARD`/`CROSS`) labels on `out_labels`.
///
/// Ghidra runs this once on the permanent CFG (`funcdata_block.cc:711`) and `buildCopy` carries the
/// labels into the structure graph; mosura re-derives the structure graph from the CFG each call, so
/// running the identical pass on the leaf blocks (0..`n`, before any collapse) yields the identical
/// labels. Operating on `list_order`/`preorder`/`index`/`visitcount`/`numdesc`/`copymap` scratch
/// (Ghidra's per-`FlowBlock` fields) leaves mosura's `blocks` order untouched — the labels depend
/// only on out-edge order, which is preserved. Brick 1: nothing reads these labels yet, so the corpus
/// stays byte-identical.
fn structure_loops(s: &mut Structured, n: usize) {
    use edge_flags::*;
    // Default the reverse-post-order index to leaf-id order; the successful spanning tree overwrites
    // it. Keeps `s.rpo` length-`n` even if the pass bails, so loop ordering never indexes out of range.
    s.rpo = (0..n as i32).collect();
    if n == 0 {
        return;
    }
    // In-adjacency with reverse index: `in_adj[t] = [(source, source-out-index), …]` in the order
    // mosura builds `in_edges` (source-block order, then out-edge order), so `getIn`/`getInRevIndex`/
    // `isBackEdgeIn` read the same edge Ghidra does. Static during this pass (no collapse yet); the
    // edge labels are read live off the source's `out_labels`.
    let mut in_adj: Vec<Vec<(usize, usize)>> = vec![Vec::new(); n];
    for src in 0..n {
        for (oi, &t) in s.blocks[src].out_edges.iter().enumerate() {
            in_adj[t].push((src, oi));
        }
    }

    let mut index = vec![-1i32; n]; // reverse-post-order number (FlowBlock::index)
    let mut visitcount = vec![-1i32; n]; // pre-order position (FlowBlock::visitcount)
    let mut numdesc = vec![0i32; n]; // spanning-tree descendant count (FlowBlock::numdesc)
    let mut copymap: Vec<usize> = (0..n).collect(); // union-find (FlowBlock::copymap)
    let mut list_order: Vec<usize> = (0..n).collect(); // Ghidra's `list`, reordered to r-post-order
    let mut preorder: Vec<usize> = Vec::with_capacity(n);
    let mut irreducible_count = 0i32;

    loop {
        // ---- findSpanningTree (block.cc:1009) ----
        preorder.clear();
        for b in 0..n {
            index[b] = -1;
            visitcount[b] = -1;
            copymap[b] = b;
        }
        let mut rootlist: Vec<usize> = list_order.iter().copied().filter(|&b| in_adj[b].is_empty()).collect();
        if rootlist.len() > 1 {
            let last = rootlist.len() - 1;
            rootlist.swap(0, last); // orighead visited last (first in reverse post order)
        } else if rootlist.is_empty() {
            rootlist.push(list_order[0]); // no obvious entry: assume first block
        }
        let origrootpos = rootlist.len() - 1;
        let mut rpostorder = vec![0usize; n];

        let mut spanning_failed = false;
        let mut repeat = 0;
        loop {
            let mut extraroots = false;
            let mut rpostcount = n as i32;
            let mut rootindex = 0usize;
            for b in 0..n {
                for l in s.blocks[b].out_labels.iter_mut() {
                    *l = 0; // clearEdgeFlags(~0)
                }
            }
            preorder.clear();
            for b in 0..n {
                index[b] = -1;
                visitcount[b] = -1;
                copymap[b] = b;
            }
            while preorder.len() < n {
                let mut startbl: Option<usize> = None;
                while rootindex < rootlist.len() {
                    let cand = rootlist[rootindex];
                    rootindex += 1;
                    if visitcount[cand] == -1 {
                        startbl = Some(cand);
                        break;
                    }
                    rootlist.remove(rootindex - 1); // stale root from a previous pass
                    rootindex -= 1;
                }
                let startbl = match startbl {
                    Some(b) => b,
                    None => {
                        extraroots = true;
                        let mut sb = list_order[0];
                        for &b in &list_order {
                            if visitcount[b] == -1 {
                                sb = b;
                                break;
                            }
                        }
                        rootlist.push(sb);
                        rootindex += 1;
                        sb
                    }
                };
                let mut state: Vec<usize> = vec![startbl];
                let mut istate: Vec<usize> = vec![0];
                visitcount[startbl] = preorder.len() as i32;
                preorder.push(startbl);
                numdesc[startbl] = 1;
                while let Some(&curbl) = state.last() {
                    let ist = *istate.last().unwrap();
                    if s.blocks[curbl].out_edges.len() <= ist {
                        state.pop();
                        istate.pop();
                        rpostcount -= 1;
                        index[curbl] = rpostcount;
                        rpostorder[rpostcount as usize] = curbl;
                        if let Some(&parent) = state.last() {
                            numdesc[parent] += numdesc[curbl];
                        }
                    } else {
                        let edgenum = ist;
                        *istate.last_mut().unwrap() += 1;
                        if s.blocks[curbl].out_labels[edgenum] & IRREDUCIBLE != 0 {
                            continue; // pretend irreducible edges don't exist
                        }
                        let childbl = s.blocks[curbl].out_edges[edgenum];
                        if visitcount[childbl] == -1 {
                            s.blocks[curbl].set_out_edge_flag(edgenum, TREE_EDGE);
                            state.push(childbl);
                            istate.push(0);
                            visitcount[childbl] = preorder.len() as i32;
                            preorder.push(childbl);
                            numdesc[childbl] = 1;
                        } else if index[childbl] == -1 {
                            s.blocks[curbl].set_out_edge_flag(edgenum, BACK_EDGE | LOOP_EDGE);
                        } else if visitcount[curbl] < visitcount[childbl] {
                            s.blocks[curbl].set_out_edge_flag(edgenum, FORWARD_EDGE);
                        } else {
                            s.blocks[curbl].set_out_edge_flag(edgenum, CROSS_EDGE);
                        }
                    }
                }
            }
            if !extraroots {
                break;
            }
            if repeat == 1 {
                spanning_failed = true; // Ghidra throws "Could not generate spanning tree"
                break;
            }
            // regenerate so the entry block comes first
            let last = rootlist.len() - 1;
            rootlist.swap(last, origrootpos);
            repeat += 1;
        }
        if spanning_failed {
            return; // irreducible beyond what the DFS can order — leave labels as-is
        }
        list_order = rpostorder;

        // ---- findIrreducible (block.cc:1147) ----
        let mut needrebuild = false;
        let mut mark = vec![false; n];
        let mut reachunder: Vec<usize> = Vec::new();
        let mut xi = preorder.len() as i32 - 1;
        while xi >= 0 {
            let x = preorder[xi as usize];
            xi -= 1;
            for &(y, revidx) in &in_adj[x] {
                if s.blocks[y].out_labels[revidx] & BACK_EDGE == 0 {
                    continue; // only back-edges into x
                }
                if y == x {
                    continue; // reachunder does not include the loop head
                }
                let fy = copymap[y];
                reachunder.push(fy); // Ghidra adds FIND(y) unconditionally (block.cc:1161)
                mark[fy] = true;
            }
            let mut q = 0;
            while q < reachunder.len() {
                let t = reachunder[q];
                q += 1;
                for &(y, revidx) in &in_adj[t] {
                    if s.blocks[y].out_labels[revidx] & IRREDUCIBLE != 0 {
                        continue; // pretend irreducible edges don't exist
                    }
                    let yprime = copymap[y];
                    if visitcount[x] > visitcount[yprime] || visitcount[x] + numdesc[x] <= visitcount[yprime] {
                        irreducible_count += 1;
                        let is_tree = s.blocks[y].out_labels[revidx] & TREE_EDGE != 0;
                        s.blocks[y].set_out_edge_flag(revidx, IRREDUCIBLE);
                        if is_tree {
                            needrebuild = true; // an irreducible tree edge forces a rebuild
                        } else {
                            s.blocks[y].clear_out_edge_flag(revidx, CROSS_EDGE | FORWARD_EDGE);
                        }
                    } else if !mark[yprime] && yprime != x {
                        reachunder.push(yprime);
                        mark[yprime] = true;
                    }
                }
            }
            for &blk in &reachunder {
                mark[blk] = false;
                copymap[blk] = x; // collapse reachunder into x
            }
            reachunder.clear();
        }

        if needrebuild {
            for b in 0..n {
                for l in s.blocks[b].out_labels.iter_mut() {
                    *l &= !(TREE_EDGE | FORWARD_EDGE | CROSS_EDGE | BACK_EDGE | LOOP_EDGE);
                }
            }
            continue; // rebuild the spanning tree
        }
        break;
    }
    s.rpo = index; // final reverse-post-order numbers (FlowBlock::index), for loop ordering

    // ---- calcLoop (block.cc:2104) — only if some edge was irreducible ----
    if irreducible_count > 0 {
        let mut m = vec![false; n]; // f_mark (visited)
        let mut m2 = vec![false; n]; // f_mark2 (on current path)
        let start = list_order[0];
        let mut path: Vec<usize> = vec![start];
        let mut state: Vec<usize> = vec![0];
        m[start] = true;
        m2[start] = true;
        while let Some(&bl) = path.last() {
            let i = *state.last().unwrap();
            if i >= s.blocks[bl].out_edges.len() {
                m2[bl] = false;
                path.pop();
                state.pop();
            } else {
                *state.last_mut().unwrap() += 1;
                if s.blocks[bl].out_labels[i] & LOOP_EDGE != 0 {
                    continue; // previously marked loop edge
                }
                let nextbl = s.blocks[bl].out_edges[i];
                if m2[nextbl] {
                    s.blocks[bl].set_out_edge_flag(i, LOOP_EDGE); // addLoopEdge: found a cycle
                } else if !m[nextbl] {
                    m[nextbl] = true;
                    m2[nextbl] = true;
                    path.push(nextbl);
                    state.push(0);
                }
            }
        }
    }
}

/// In-adjacency of the leaf graph with reverse index: `in_adj[t] = [(source, source-out-index), …]`,
/// mirroring Ghidra's `FlowBlock::intothis`. The edge label is read live off `blocks[source]`.
fn in_adjacency(s: &Structured, n: usize) -> Vec<Vec<(usize, usize)>> {
    let mut in_adj: Vec<Vec<(usize, usize)>> = vec![Vec::new(); n];
    for src in 0..n {
        for (oi, &t) in s.blocks[src].out_edges.iter().enumerate() {
            in_adj[t].push((src, oi));
        }
    }
    in_adj
}

/// Whether the `k`-th in-edge of block `t` is unstructured — Ghidra's `FlowBlock::isGotoIn`
/// (block.hh:346): the source's out-edge label carries `IRREDUCIBLE|GOTO`.
fn is_goto_in(s: &Structured, in_adj: &[Vec<(usize, usize)>], t: usize, k: usize) -> bool {
    let (src, oi) = in_adj[t][k];
    s.blocks[src].out_labels[oi] & (edge_flags::IRREDUCIBLE | edge_flags::GOTO_EDGE) != 0
}

/// Ghidra's `LoopBody::findBase` (blockaction.cc:119): mark the head/tail nodes and every node that
/// reaches a tail without going through the head. Returns the body (marked) and `uniquecount` (the
/// number of distinct head+tail nodes at the front of the list).
fn find_base(s: &mut Structured, in_adj: &[Vec<(usize, usize)>], head: usize, tails: &[usize], body: &mut Vec<usize>) -> usize {
    s.blocks[head].set_flag(block_flags::MARK);
    body.push(head);
    for &tail in tails {
        if s.blocks[tail].flags & block_flags::MARK == 0 {
            s.blocks[tail].set_flag(block_flags::MARK);
            body.push(tail);
        }
    }
    let uniquecount = body.len();
    let mut i = 1;
    while i < body.len() {
        let curblock = body[i];
        i += 1;
        for k in 0..in_adj[curblock].len() {
            if is_goto_in(s, in_adj, curblock, k) {
                continue; // don't trace back through irreducible edges
            }
            let bl = in_adj[curblock][k].0;
            if s.blocks[bl].flags & block_flags::MARK != 0 {
                continue;
            }
            s.blocks[bl].set_flag(block_flags::MARK);
            body.push(bl);
        }
    }
    uniquecount
}

/// Ghidra's `LoopBody::extend` (blockaction.cc:150): extend the body to every block reachable only
/// from within the body (all in-edges accounted for) without passing through the exit block.
fn extend(s: &mut Structured, in_adj: &[Vec<(usize, usize)>], exitblock: Option<usize>, body: &mut Vec<usize>, visitcount: &mut [i32]) {
    let mut trial: Vec<usize> = Vec::new();
    let mut i = 0;
    while i < body.len() {
        let bl = body[i];
        i += 1;
        for j in 0..s.blocks[bl].out_edges.len() {
            if s.blocks[bl].is_goto_out(j) {
                continue; // don't extend through a goto edge
            }
            let curbl = s.blocks[bl].out_edges[j];
            if s.blocks[curbl].flags & block_flags::MARK != 0 {
                continue;
            }
            if Some(curbl) == exitblock {
                continue;
            }
            let count = visitcount[curbl] + 1;
            if count == 1 {
                trial.push(curbl); // new possible extension
            }
            visitcount[curbl] = count;
            if count == in_adj[curbl].len() as i32 {
                s.blocks[curbl].set_flag(block_flags::MARK);
                body.push(curbl);
            }
        }
    }
    for &t in &trial {
        visitcount[t] = 0; // clear the transient counts
    }
}

/// Ghidra's `LoopBody::extendToContainer` (blockaction.cc:46): mark the blocks the immediately
/// containing loop adds to `this` loop's body. `this` loop's body is assumed already marked.
fn extend_to_container(
    s: &mut Structured,
    in_adj: &[Vec<(usize, usize)>],
    container_head: Option<usize>,
    container_tails: &[usize],
    this_head: Option<usize>,
    body: &mut Vec<usize>,
) {
    let mut i = 0;
    if let Some(ch) = container_head {
        if s.blocks[ch].flags & block_flags::MARK == 0 {
            s.blocks[ch].set_flag(block_flags::MARK);
            body.push(ch);
            i = 1; // don't traverse back from the container head
        }
    }
    for &tail in container_tails {
        if s.blocks[tail].flags & block_flags::MARK == 0 {
            s.blocks[tail].set_flag(block_flags::MARK);
            body.push(tail); // do traverse back from container tails
        }
    }
    if this_head != container_head {
        if let Some(th) = this_head {
            for k in 0..in_adj[th].len() {
                if is_goto_in(s, in_adj, th, k) {
                    continue;
                }
                let bl = in_adj[th][k].0;
                if s.blocks[bl].flags & block_flags::MARK != 0 {
                    continue;
                }
                s.blocks[bl].set_flag(block_flags::MARK);
                body.push(bl);
            }
        }
    }
    while i < body.len() {
        let curblock = body[i];
        i += 1;
        for k in 0..in_adj[curblock].len() {
            if is_goto_in(s, in_adj, curblock, k) {
                continue;
            }
            let bl = in_adj[curblock][k].0;
            if s.blocks[bl].flags & block_flags::MARK != 0 {
                continue;
            }
            s.blocks[bl].set_flag(block_flags::MARK);
            body.push(bl);
        }
    }
}

/// Ghidra's `LoopBody::findExit` (blockaction.cc:182): choose the single structured exit block,
/// preferring an exit from a tail, then the head, then the middle; if there is a containing loop the
/// exit must lie within it.
fn find_exit(s: &mut Structured, in_adj: &[Vec<(usize, usize)>], loopbody: &mut [LoopBody], cur: usize, body: &[usize]) {
    let tails = loopbody[cur].tails.clone();
    let uniquecount = loopbody[cur].uniquecount;
    let has_container = loopbody[cur].immed_container.is_some();
    let mut trialexit: Vec<usize> = Vec::new();

    for &tail in &tails {
        for i in 0..s.blocks[tail].out_edges.len() {
            if s.blocks[tail].is_goto_out(i) {
                continue;
            }
            let curbl = s.blocks[tail].out_edges[i];
            if s.blocks[curbl].flags & block_flags::MARK == 0 {
                if !has_container {
                    loopbody[cur].exitblock = Some(curbl);
                    return;
                }
                trialexit.push(curbl);
            }
        }
    }
    for (i, &bl) in body.iter().enumerate() {
        if i > 0 && i < uniquecount {
            continue; // filter out tails (processed above)
        }
        for j in 0..s.blocks[bl].out_edges.len() {
            if s.blocks[bl].is_goto_out(j) {
                continue;
            }
            let curbl = s.blocks[bl].out_edges[j];
            if s.blocks[curbl].flags & block_flags::MARK == 0 {
                if !has_container {
                    loopbody[cur].exitblock = Some(curbl);
                    return;
                }
                trialexit.push(curbl);
            }
        }
    }

    loopbody[cur].exitblock = None;
    if trialexit.is_empty() {
        return;
    }
    // Force the exit to lie within the containing loop.
    let ic = loopbody[cur].immed_container.unwrap();
    let container_head = loopbody[ic].head;
    let container_tails = loopbody[ic].tails.clone();
    let this_head = loopbody[cur].head;
    let mut extension: Vec<usize> = Vec::new();
    extend_to_container(s, in_adj, container_head, &container_tails, this_head, &mut extension);
    for &bl in &trialexit {
        if s.blocks[bl].flags & block_flags::MARK != 0 {
            loopbody[cur].exitblock = Some(bl);
            break;
        }
    }
    clear_marks(s, &extension);
}

/// Ghidra's `LoopBody::orderTails` (blockaction.cc:245): move the tail that has an edge straight to
/// the exit block into the first position.
fn order_tails(s: &Structured, loopbody: &mut [LoopBody], cur: usize) {
    let ntails = loopbody[cur].tails.len();
    if ntails <= 1 {
        return;
    }
    let exitblock = match loopbody[cur].exitblock {
        Some(e) => e,
        None => return,
    };
    let mut prefindex = ntails;
    for pi in 0..ntails {
        let trial = loopbody[cur].tails[pi];
        if s.blocks[trial].out_edges.contains(&exitblock) {
            prefindex = pi;
            break;
        }
    }
    if prefindex >= ntails || prefindex == 0 {
        return;
    }
    loopbody[cur].tails.swap(0, prefindex);
}

/// Ghidra's `LoopBody::labelExitEdges` (blockaction.cc:270): collect the edges leaving the body into
/// `exitedges`, in removal priority order — middle exits first, then the head exit, then tail exits
/// (less-preferred tails first), then the exits to the formal exit block.
fn label_exit_edges(s: &Structured, loopbody: &mut [LoopBody], cur: usize, body: &[usize]) {
    let uniquecount = loopbody[cur].uniquecount;
    let head = loopbody[cur].head;
    let tails = loopbody[cur].tails.clone();
    let exitblock = loopbody[cur].exitblock;
    let mut toexitblock: Vec<usize> = Vec::new();
    let mut exitedges: Vec<FloatingEdge> = Vec::new();

    let collect = |curblock: usize, exitedges: &mut Vec<FloatingEdge>, toexitblock: &mut Vec<usize>| {
        for k in 0..s.blocks[curblock].out_edges.len() {
            if s.blocks[curblock].is_goto_out(k) {
                continue; // don't exit through goto edges
            }
            let bl = s.blocks[curblock].out_edges[k];
            if Some(bl) == exitblock {
                toexitblock.push(curblock); // postpone exit to the exit block
                continue;
            }
            if s.blocks[bl].flags & block_flags::MARK == 0 {
                exitedges.push(FloatingEdge { top: curblock, bottom: bl });
            }
        }
    };

    for &curblock in &body[uniquecount..] {
        collect(curblock, &mut exitedges, &mut toexitblock); // non-head/tail nodes
    }
    if let Some(h) = head {
        collect(h, &mut exitedges, &mut toexitblock);
    }
    for ti in (0..tails.len()).rev() {
        let curblock = tails[ti];
        if Some(curblock) == head {
            continue;
        }
        collect(curblock, &mut exitedges, &mut toexitblock);
    }
    if let Some(e) = exitblock {
        for &bl in &toexitblock {
            exitedges.push(FloatingEdge { top: bl, bottom: e });
        }
    }
    loopbody[cur].exitedges = exitedges;
}

/// Ghidra's `LoopBody::labelContainments` (blockaction.cc:327): record any loops contained in
/// `body`, bumping their depth and updating their immediate container.
fn label_containments(loopbody: &mut [LoopBody], cur: usize, body: &[usize], looporder: &[usize], rpo: &[i32]) {
    let head = loopbody[cur].head;
    let mut containlist: Vec<usize> = Vec::new();
    for &curblock in body {
        if Some(curblock) == head {
            continue;
        }
        if let Some(si) = loop_find(loopbody, looporder, rpo, curblock) {
            containlist.push(si);
            loopbody[si].depth += 1;
        }
    }
    let this_depth = loopbody[cur].depth;
    for &si in &containlist {
        let replace = match loopbody[si].immed_container {
            None => true,
            Some(ic) => loopbody[ic].depth < this_depth,
        };
        if replace {
            loopbody[si].immed_container = Some(cur);
        }
    }
}

/// Ghidra's `LoopBody::mergeIdenticalHeads` (blockaction.cc:446): merge loop bodies sharing a head
/// (their tails fold into the first; the subsumed bodies get their head cleared) and compact
/// `looporder` to the surviving unique-head bodies.
fn merge_identical_heads(loopbody: &mut [LoopBody], looporder: &mut Vec<usize>) {
    let mut i = 0;
    let mut j = 1;
    let mut curidx = looporder[0];
    while j < looporder.len() {
        let nextidx = looporder[j];
        j += 1;
        if loopbody[nextidx].head == loopbody[curidx].head {
            let tail0 = loopbody[nextidx].tails[0];
            loopbody[curidx].tails.push(tail0);
            loopbody[nextidx].head = None; // subsumed
        } else {
            i += 1;
            looporder[i] = nextidx;
            curidx = nextidx;
        }
    }
    i += 1;
    looporder.truncate(i);
}

/// Ghidra's `LoopBody::find` (blockaction.cc:1021): binary-search the head-sorted `looporder` for the
/// loop whose head is `looptop`. Keys on the reverse-post-order index (`compare_head`).
fn loop_find(loopbody: &[LoopBody], looporder: &[usize], rpo: &[i32], looptop: usize) -> Option<usize> {
    if looporder.is_empty() {
        return None;
    }
    let target = rpo[looptop];
    let mut min = 0i64;
    let mut max = looporder.len() as i64 - 1;
    while min <= max {
        let mid = ((min + max) / 2) as usize;
        let h = loopbody[looporder[mid]].head.expect("looporder holds only unique-head bodies");
        match rpo[h].cmp(&target) {
            std::cmp::Ordering::Equal => return Some(looporder[mid]),
            std::cmp::Ordering::Less => min = mid as i64 + 1,
            std::cmp::Ordering::Greater => max = mid as i64 - 1,
        }
    }
    None
}

/// Ghidra's `LoopBody::clearMarks` (blockaction.cc:1039).
fn clear_marks(s: &mut Structured, body: &[usize]) {
    for &b in body {
        s.blocks[b].clear_flag(block_flags::MARK);
    }
}

/// Ghidra's `CollapseStructure::labelLoops` (blockaction.cc:1126): create a `LoopBody` for every loop
/// (identified by a back-edge into its head) and sort them by head then tail (`compare_ends`).
fn label_loops(s: &Structured, in_adj: &[Vec<(usize, usize)>], rpo: &[i32]) -> (Vec<LoopBody>, Vec<usize>) {
    let mut loopbody: Vec<LoopBody> = Vec::new();
    let mut looporder: Vec<usize> = Vec::new();
    for (bl, ins) in in_adj.iter().enumerate() {
        for &(loopbottom, oi) in ins {
            if s.blocks[loopbottom].out_labels[oi] & edge_flags::BACK_EDGE != 0 {
                let idx = loopbody.len();
                loopbody.push(LoopBody {
                    head: Some(bl),
                    tails: vec![loopbottom],
                    depth: 0,
                    uniquecount: 0,
                    exitblock: None,
                    exitedges: Vec::new(),
                    immed_container: None,
                });
                looporder.push(idx);
            }
        }
    }
    looporder.sort_by(|&a, &b| {
        let (ha, hb) = (rpo[loopbody[a].head.unwrap()], rpo[loopbody[b].head.unwrap()]);
        ha.cmp(&hb).then_with(|| rpo[loopbody[a].tails[0]].cmp(&rpo[loopbody[b].tails[0]]))
    });
    (loopbody, looporder)
}

/// Ghidra's `CollapseStructure::orderLoopBodies` (blockaction.cc:1148): identify the loops, label
/// their exit edges, and produce a nesting-depth partial order (deepest first). Runs on the leaf
/// graph. Ghidra erases the subsumed (merged-away) loop bodies; mosura keeps them with `head = None`
/// and skips them, which is equivalent since they are inert.
fn order_loop_bodies(s: &mut Structured, n: usize) -> Vec<LoopBody> {
    let in_adj = in_adjacency(s, n);
    let rpo = s.rpo.clone();
    let (mut loopbody, mut looporder) = label_loops(s, &in_adj, &rpo);
    if loopbody.is_empty() {
        return loopbody;
    }
    merge_identical_heads(&mut loopbody, &mut looporder);

    // First pass: containment (depth + immediate container).
    for cur in 0..loopbody.len() {
        let head = match loopbody[cur].head {
            Some(h) => h,
            None => continue,
        };
        let tails = loopbody[cur].tails.clone();
        let mut body = Vec::new();
        loopbody[cur].uniquecount = find_base(s, &in_adj, head, &tails, &mut body);
        label_containments(&mut loopbody, cur, &body, &looporder, &rpo);
        clear_marks(s, &body);
    }

    // Process deepest loops first (stable → creation order breaks ties, matching Ghidra's list::sort).
    let mut process_order: Vec<usize> = (0..loopbody.len()).filter(|&i| loopbody[i].head.is_some()).collect();
    process_order.sort_by(|&a, &b| loopbody[b].depth.cmp(&loopbody[a].depth));

    // Second pass: choose the exit and label the exit edges.
    let mut visitcount = vec![0i32; n];
    for &cur in &process_order {
        let head = loopbody[cur].head.unwrap();
        let tails = loopbody[cur].tails.clone();
        let mut body = Vec::new();
        loopbody[cur].uniquecount = find_base(s, &in_adj, head, &tails, &mut body);
        find_exit(s, &in_adj, &mut loopbody, cur, &body);
        order_tails(s, &mut loopbody, cur);
        let exitblock = loopbody[cur].exitblock;
        extend(s, &in_adj, exitblock, &mut body, &mut visitcount);
        label_exit_edges(s, &mut loopbody, cur, &body);
        clear_marks(s, &body);
    }
    loopbody
}

/// Structure the CFG of `f`.
pub fn structure(f: &Funcdata) -> Structured {
    let blocks: Vec<FlowBlock> = (0..f.num_blocks())
        .map(|b| {
            let out_edges: Vec<usize> = f.blocks()[b].out_edges.iter().map(|e| e.0 as usize).collect();
            let out_labels = vec![0u32; out_edges.len()];
            FlowBlock {
                kind: FlowKind::Basic(BlockId(b as u32)),
                components: Vec::new(),
                out_edges,
                out_labels,
                flags: 0,
                active: true,
                negated: false,
            }
        })
        .collect();
    // Per basic block: whether its terminating CBRANCH has been branch-oriented by
    // `ActionOrientBranches` (Ghidra's `fallthru_true` flag, which its printc also reads,
    // printc.cc:542). An oriented block's negation is already materialized positive in the IR, so
    // its structuring `negated` is flipped off — the condition prints directly. Recording the flip
    // in this flag (instead of reversing the CFG out-edges as Ghidra's structure-once graph does)
    // keeps the persistent CFG intact so the re-deriving structurer collapses the original topology.
    let oriented: Vec<bool> = (0..f.num_blocks())
        .map(|b| {
            f.block(BlockId(b as u32))
                .ops
                .last()
                .copied()
                .is_some_and(|op| f.op(op).is_fallthru_true())
        })
        .collect();
    let mut s = Structured {
        blocks,
        root: 0,
        gotos: HashMap::new(),
        labels: HashSet::new(),
        oriented,
        rpo: Vec::new(),
        loopbody: Vec::new(),
    };

    // Label loop back-edges and irreducible edges on the leaf graph before collapsing (Ghidra's
    // structureLoops, run on the CFG before ActionBlockStructure's buildCopy). Brick 1: the labels
    // are written but not yet consumed by the collapse rules, so this is byte-identical.
    structure_loops(&mut s, f.num_blocks());

    // Build the loop records (Ghidra's orderLoopBodies): label each loop's exit edges and order the
    // loops by nesting depth. Brick 2: computed inert (the selectGoto driver consuming them lands in
    // Brick 4), so this is byte-identical.
    s.loopbody = order_loop_bodies(&mut s, f.num_blocks());

    loop {
        let active: Vec<usize> = (0..s.blocks.len()).filter(|&b| s.blocks[b].active).collect();
        if active.len() <= 1 {
            break;
        }
        let ins = s.in_edges();
        let mut fired = false;
        for &b in &active {
            if s.try_rules(b, &ins) {
                fired = true;
                break;
            }
        }
        if !fired && !s.rule_goto() {
            break; // truly stuck (no structural rule and no goto edge to cut)
        }
    }
    s.root = (0..s.blocks.len()).find(|&b| s.blocks[b].active).unwrap_or(0);
    s
}

/// Materialize the structurer's branch-direction negations in the IR (the mosura analogue of the
/// `negateCondition` calls Ghidra's `CollapseStructure` makes during `ActionBlockStructure`). Runs
/// the structuring collapse to find every `if`/`while`/`do-while` whose body sits on the false edge,
/// then applies [`Funcdata::block_negate_condition`] to each condition CBRANCH — flipping
/// `boolean_flip`/`fallthru_true` and the out-edge order. The paired post-orientation rule pool
/// ([`RuleCondNegate`] → [`RuleBoolNegate`] → [`RuleIntLessEqual`]) then materializes `!cond` and
/// normalizes it, so the printed condition is read directly off the positive IR instead of negated
/// at print time. Placed after type recovery, mirroring Ghidra's final structuring placement (a
/// once-pass approximation of Ghidra's repeating mainloop, consistent with mosura's hand-unrolled
/// pipeline). The `if`/`else` normal-form flip (mechanism A) follows in [`ActionPreferComplement`].
///
/// [`RuleCondNegate`]: super::rules::RuleCondNegate
/// [`RuleBoolNegate`]: super::rules::RuleBoolNegate
/// [`RuleIntLessEqual`]: super::rules::RuleIntLessEqual
pub struct ActionOrientBranches;

impl super::action::Action for ActionOrientBranches {
    fn name(&self) -> &str {
        "orientbranches"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        // Skip during the jump-table recovery probe: orientation is a render-time transform and
        // materializing a switch guard there under-recovers the table (see `table_recovery_probe`).
        if data.table_recovery_probe {
            return 0;
        }
        let negations = structure(data).branch_negations(data);
        let mut changed = 0;
        for bid in negations {
            data.block_negate_condition(bid);
            changed = 1;
        }
        changed
    }
}

/// Materialize the `if`/`else` normal-form flip in the IR — the mosura analogue of Ghidra's
/// `ActionPreferComplement` (blockaction.cc:2140), which walks the structured block tree calling
/// `BlockIf::preferComplement` (block.cc:3093) on each `if`/`else`. Runs the structuring collapse to
/// find every `if`/`else` split CBRANCH ([`if_else_splits`](Structured::if_else_splits)); for each
/// whose condition [`Funcdata::op_flip_in_place_test`] reports *normalizes* (returns 0), it applies
/// [`Funcdata::op_flip_in_place_execute`] to rewrite the comparison into normal form in place (e.g.
/// `9 < param_1` ⇒ `param_1 <= 9` ⇒ `param_1 < 10` via `replace_lessequal`) and
/// [`Funcdata::flip_in_place_execute`] to flip the CBRANCH's `fallthru_true` (Ghidra's
/// `swapBlocks(1,2)` analogue, recorded in the flag per the no-edge-reversal discipline). The printed
/// condition is then read directly off the positive IR, so [`rule_if_else`](Structured::rule_if_else)
/// swaps the arms from the flag and prints `negated = false` — retiring the print-time normal-form
/// flip. Scoped to `if`/`else` (Ghidra's `getSize()!=3` guard); the global per-basic-block
/// `ActionNormalizeBranches` (blockaction.cc:2117) is deferred (near-inert on the corpus). Placed
/// after [`ActionOrientBranches`] + the condnegate pool, mirroring Ghidra's late `preferComplement`.
pub struct ActionPreferComplement;

impl super::action::Action for ActionPreferComplement {
    fn name(&self) -> &str {
        "prefercomplement"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        if data.table_recovery_probe {
            return 0;
        }
        let splits = structure(data).if_else_splits();
        let mut changed = 0;
        for bid in splits {
            let Some(&cbr) = data.block(bid).ops.last() else {
                continue;
            };
            let (result, fliplist) = data.op_flip_in_place_test(cbr);
            if result != 0 {
                continue;
            }
            data.op_flip_in_place_execute(&fliplist);
            data.flip_in_place_execute(bid);
            changed = 1;
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::block::{BlockBasic, BlockId};
    use crate::decompile::space::{Address, SpaceManager};
    use crate::decompile::Funcdata;

    fn cfg(nb: usize, edges: &[(usize, usize)]) -> Funcdata {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let mut blocks: Vec<BlockBasic> = vec![BlockBasic::default(); nb];
        for &(a, b) in edges {
            blocks[a].out_edges.push(BlockId(b as u32));
            blocks[b].in_edges.push(BlockId(a as u32));
        }
        f.set_blocks(blocks);
        f
    }

    fn active(s: &Structured) -> usize {
        (0..s.blocks.len()).filter(|&b| s.blocks[b].active).count()
    }
    fn kinds(s: &Structured) -> Vec<FlowKind> {
        let mut k = Vec::new();
        fn walk(s: &Structured, b: usize, k: &mut Vec<FlowKind>) {
            k.push(s.blocks[b].kind.clone());
            for &c in &s.blocks[b].components {
                walk(s, c, k);
            }
        }
        walk(s, s.root, &mut k);
        k
    }

    #[test]
    fn condition_folds_cleanly_gates_compound_leaf_orientation() {
        // The all-or-nothing gate (`compound_leaves`) orients a negated compound only when EVERY leaf
        // folds cleanly. `condition_folds_cleanly` is that per-leaf decision: a comparison folds
        // (→ orient), a BOOL_OR (e.g. nan's nested `NAN(x) || NAN(x)` leaf) does not (→ skip the whole
        // compound, keeping it on print-time De Morgan — why nan stays byte-identical).
        use crate::decompile::op::SeqNum;
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        // block 0: CBRANCH on INT_SLESS(v, 5) — a foldable comparison.
        let v = f.new_input(4, Address::new(reg, 0x10));
        let c5 = f.new_const(4, 5);
        let cmp = f.new_op(OpCode::IntSless, seq, vec![v, c5]);
        let cond = f.new_output(cmp, 1, Address::new(reg, 0x20));
        let tgt = f.new_const(8, 0x1000);
        let cbr0 = f.new_op(OpCode::Cbranch, seq, vec![tgt, cond]);
        // block 1: CBRANCH on BOOL_OR(a, b) — not a foldable comparison.
        let a = f.new_input(1, Address::new(reg, 0x30));
        let b = f.new_input(1, Address::new(reg, 0x31));
        let orop = f.new_op(OpCode::BoolOr, seq, vec![a, b]);
        let orcond = f.new_output(orop, 1, Address::new(reg, 0x40));
        let cbr1 = f.new_op(OpCode::Cbranch, seq, vec![tgt, orcond]);
        f.set_blocks(vec![
            BlockBasic { ops: vec![cmp, cbr0], ..Default::default() },
            BlockBasic { ops: vec![orop, cbr1], ..Default::default() },
        ]);
        assert!(condition_folds_cleanly(&f, BlockId(0)), "comparison leaf orients");
        assert!(!condition_folds_cleanly(&f, BlockId(1)), "BOOL_OR leaf is skipped (the nan gate)");
    }

    #[test]
    fn sequence_becomes_a_list() {
        let s = structure(&cfg(3, &[(0, 1), (1, 2)]));
        assert_eq!(active(&s), 1);
        assert_eq!(s.blocks[s.root].kind, FlowKind::List);
    }

    #[test]
    fn diamond_becomes_if_else() {
        // 0 -> {1(false), 2(true)} -> 3
        let s = structure(&cfg(4, &[(0, 1), (0, 2), (1, 3), (2, 3)]));
        assert_eq!(active(&s), 1);
        assert!(kinds(&s).contains(&FlowKind::IfElse));
    }

    #[test]
    fn triangle_becomes_proper_if() {
        // 0 -> {1, 2}; 1 -> 2  (then=1, merge=2)
        let s = structure(&cfg(3, &[(0, 1), (0, 2), (1, 2)]));
        assert_eq!(active(&s), 1);
        assert!(kinds(&s).contains(&FlowKind::If));
    }

    #[test]
    fn loop_becomes_while_do() {
        // 0 -> 1; 1 -> {2(body), 3(exit)}; 2 -> 1
        let s = structure(&cfg(4, &[(0, 1), (1, 2), (1, 3), (2, 1)]));
        assert_eq!(active(&s), 1);
        assert!(kinds(&s).contains(&FlowKind::WhileDo));
    }

    #[test]
    fn short_circuit_and_merges() {
        // A=0 out [merge=3(false), B=1(true)]; B=1 out [merge=3(false), then=2(true)]; 2 -> 3
        //   i.e. if (a && b) then(2); merge=3
        let s = structure(&cfg(4, &[(0, 3), (0, 1), (1, 3), (1, 2), (2, 3)]));
        assert_eq!(active(&s), 1);
        assert!(kinds(&s).contains(&FlowKind::CondAnd), "kinds: {:?}", kinds(&s));
    }

    #[test]
    fn short_circuit_or_merges() {
        // A=0 out [B=1(false), then=2(true)]; B=1 out [merge=3(false), then=2(true)]; 2 -> 3
        //   i.e. if (a || b) then(2); merge=3
        let s = structure(&cfg(4, &[(0, 1), (0, 2), (1, 3), (1, 2), (2, 3)]));
        assert_eq!(active(&s), 1);
        assert!(kinds(&s).contains(&FlowKind::CondOr), "kinds: {:?}", kinds(&s));
    }

    #[test]
    fn irreducible_collapses_with_goto() {
        // 0 -> {1, 2}; 1 -> 2; 2 -> 1  (1 and 2 form an irreducible two-cycle)
        let s = structure(&cfg(3, &[(0, 1), (0, 2), (1, 2), (2, 1)]));
        assert_eq!(active(&s), 1, "collapses fully via gotos");
        assert!(!s.gotos.is_empty(), "recorded a goto edge");
    }

    #[test]
    fn self_loop_becomes_do_while() {
        // 0 -> 1; 1 -> {1(self), 2(exit)}
        let s = structure(&cfg(3, &[(0, 1), (1, 1), (1, 2)]));
        assert_eq!(active(&s), 1);
        assert!(kinds(&s).contains(&FlowKind::DoWhile));
    }
}
