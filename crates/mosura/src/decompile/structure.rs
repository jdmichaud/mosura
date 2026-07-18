//! Control-flow structuring — Ghidra's `CollapseStructure` (`blockaction.cc`) over a
//! `BlockGraph` (`block.cc`). Repeatedly collapses CFG patterns into structured blocks
//! (list/if/if-else/while/do-while) until one block remains, recovering `if`/`while`/`for`
//! from the goto-level CFG.
//!
//! The graph is a vector of [`FlowBlock`]s; each structured block lists its sub-blocks and
//! presents the same successor interface, so the rules compose. Out-edges are the source of
//! truth; in-edges are recomputed each pass. CBRANCH order is `[false, true]` (as built by
//! `cfg`).
//!
//! The collapse driver is Ghidra's `CollapseStructure::collapseAll` (blockaction.cc:1877):
//! `orderLoopBodies` → `collapseConditions` → `collapseInternal` → `{selectGoto →
//! collapseInternal}` until everything is isolated. Gotos are never invented by a fallback
//! rule: `selectGoto` (blockaction.cc:1260) marks a *likely* unstructured edge — a loop exit
//! or last-resort back-edge from `LoopBody::emitLikelyEdges` — and `ruleBlockGoto`
//! (blockaction.cc:1450) consumes marked (`GOTO`/`IRREDUCIBLE`) edges. Ghidra's `TraceDAG`
//! (blockaction.cc:499-1014) scores the additional non-DAG gotos by tracing the reducible DAG
//! (or a loop interior between looptop/loopbottom): it pushes `BlockTrace`s out of each
//! `BranchPoint` and, when it can no longer push, `selectBadEdge` scores the stuck edges and
//! records the worst one as a likely goto. On clean reducible interiors it fully retires and
//! contributes nothing.

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
    /// `do body while(true)` — components `[body]`; a loop with no exits (Ghidra's
    /// `BlockInfLoop`, built by `ruleBlockInfLoop` blockaction.cc:1579).
    InfLoop,
}

/// One unstructured branch recorded by [`rule_block_goto`](Structured::rule_block_goto) —
/// the mosura carrier for Ghidra's `BlockGoto`/`BlockIf::gototarget`/`BlockMultiGoto` print
/// state. Keyed (in [`Structured::gotos`]) by the basic block whose exit emits the goto;
/// rendered by printc after that block's statements, in insertion order (Ghidra emits the
/// conditional if-goto wrapper before an unconditional goto wrapper the same way).
#[derive(Clone, Copy, Debug)]
pub struct GotoRecord {
    /// The target entry basic block (gets a label).
    pub target: BlockId,
    /// For a conditional goto: print `if (!cond) goto` (the goto sits on the false edge,
    /// accounting for a materialized branch orientation).
    pub negated: bool,
    /// Whether the goto is conditional (`BlockIfGoto`: cut from a two-out CBRANCH block) or
    /// unconditional (`BlockGoto`/`BlockMultiGoto`).
    pub conditional: bool,
    /// Whether [`scope_break`](Structured::scope_break) reclassified this edge as a `break;` —
    /// Ghidra's `f_break_goto` (block.hh:90), set when the goto targets the enclosing loop's exit.
    /// (The C++ decompiler never produces `f_continue_goto`, so break is the only reclassification.)
    pub is_break: bool,
}

#[derive(Clone, Debug)]
pub struct FlowBlock {
    pub kind: FlowKind,
    pub components: Vec<usize>,
    pub out_edges: Vec<usize>,
    /// Per-out-edge boolean labels — Ghidra's `BlockEdge::label` ([`edge_flags`], block.hh:108),
    /// parallel to `out_edges`. `structure_loops` writes `BACK`/`LOOP`/`IRREDUCIBLE` on the leaf
    /// graph; `install` propagates the labels of collapsed sub-blocks onto composite edges
    /// (Ghidra's `selfIdentify` edge inheritance); `select_goto` marks `GOTO`.
    pub out_labels: Vec<u32>,
    /// Block-level boolean flags — Ghidra's `FlowBlock::flags` ([`block_flags`], block.hh:88).
    pub flags: u32,
    pub active: bool,
    /// For `If`/`IfElse`/`WhileDo`/`DoWhile`: the body/then is reached on the condition's
    /// *false* edge, so the printed condition must be negated.
    pub negated: bool,
    /// The composite this block collapsed into — Ghidra's `FlowBlock::parent` (block.hh:161).
    /// `None` while the block is still in the top-level graph. `LoopBody::update` and
    /// `FloatingEdge::getCurrentEdge` walk this to find a block's current collapsed form.
    pub parent: Option<usize>,
    /// For a `CondAnd`/`CondOr`: whether `ruleBlockOr` had to negate each side to reach the
    /// canonical orientation (Ghidra's `negateCondition` on `bl`/`orblock`, blockaction.cc:1359-1364).
    /// mosura does not swap CFG edges (see [`Funcdata::block_negate_condition`]), so the swapped-sense
    /// fold records the per-side flip here; [`render_cond_expr`](super::printc) XORs it into each
    /// operand's print negation. `(false, false)` for the canonical fold and every non-condition block.
    pub cond_flip: (bool, bool),
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
    /// The `i`-th out-edge is the switch's default edge — Ghidra's `FlowBlock::isDefaultBranch`
    /// (block.hh:320).
    fn is_default_branch(&self, i: usize) -> bool {
        self.out_labels[i] & edge_flags::DEFAULTSWITCH_EDGE != 0
    }
}

/// The structured-block forest; `root` is the single block the CFG collapsed to (or the
/// entry, if the CFG was irreducible and could not fully collapse).
pub struct Structured {
    pub blocks: Vec<FlowBlock>,
    pub root: usize,
    /// The unstructured branches, keyed by the basic block whose exit emits them — filled by
    /// [`rule_block_goto`](Self::rule_block_goto) consuming `GOTO`/`IRREDUCIBLE`-marked edges
    /// (Ghidra's `BlockGoto`/`BlockIfGoto`/`BlockMultiGoto` wrappers, blockaction.cc:1450).
    pub gotos: HashMap<BlockId, Vec<GotoRecord>>,
    /// Basic blocks that are goto targets (get a label).
    pub labels: HashSet<BlockId>,
    /// Per basic block: whether its terminating CBRANCH was branch-oriented (Ghidra's `fallthru_true`
    /// flag). An oriented block's body-on-false negation is already materialized positive in the IR,
    /// so the collapse rules XOR this in to flip its `negated` off. Precomputed from `Funcdata`.
    oriented: Vec<bool>,
    /// Per basic block: whether it is too complicated to print inside a condition — Ghidra's
    /// `BlockBasic::isComplex` (block.cc:2388), precomputed from `Funcdata` at build. Read by
    /// [`is_complex`](Self::is_complex) (the `ruleBlockOr` orblock guard, blockaction.cc:1342).
    complex: Vec<bool>,
    /// Reverse-post-order number per leaf block — Ghidra's `FlowBlock::index` set by
    /// [`structure_loops`] (`findSpanningTree`). Loop ordering (`compare_ends`/`compare_head`) keys on
    /// it. Indexed by leaf block id.
    rpo: Vec<i32>,
    /// The loop records built by [`order_loop_bodies`] (Ghidra's `CollapseStructure::loopbody`) — head,
    /// tails, exit block, and exit edges per loop. Consumed (and updated to current collapsed forms)
    /// by the `selectGoto` driver.
    loopbody: Vec<LoopBody>,
    /// Indices into `loopbody` in processing order — deepest nesting first (Ghidra's sorted
    /// `loopbody` list, `LoopBody::operator<` blockaction.hh:70), subsumed (headless) bodies
    /// excluded.
    loop_order: Vec<usize>,
    /// The live top-level graph in Ghidra's `BlockGraph::list` order: surviving blocks in creation
    /// order, composites appended as they form. Drives the rule-scan iteration order.
    order: Vec<usize>,
    /// `CollapseStructure::loopbodyiter` — position in `loop_order` of the current innermost loop.
    loopiter: usize,
    /// `CollapseStructure::likelygoto` — the current likely-goto edge list.
    likelygoto: Vec<FloatingEdge>,
    /// `CollapseStructure::likelyiter` — next unconsumed entry of `likelygoto`.
    likelyiter: usize,
    /// `CollapseStructure::likelylistfull` — whether `likelygoto` was generated for the current loop.
    likelylistfull: bool,
    /// `CollapseStructure::finaltrace` — the final DAG search for unstructured edges already ran.
    finaltrace: bool,
    /// Switch heads whose `DEFAULTSWITCH` edge was cut to a goto — Ghidra's
    /// `BlockMultiGoto::hasDefaultGoto`, read by `checkSwitchSkips`.
    default_goto: HashSet<usize>,
}

/// An edge tracked across graph collapse by its endpoints — Ghidra's `FloatingEdge`
/// (blockaction.hh:80). `getCurrentEdge` walks the endpoints up the collapse hierarchy (updating
/// them in place, as Ghidra does) to find the edge's current form.
#[derive(Clone, Copy, Debug)]
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
                    // A leaf reached through an odd number of `ruleBlockOr` fold-flips (`cond_flip`)
                    // was already negated by the fold, so the while's NOT cancels on it (net raw) —
                    // it is left un-oriented and its print sense is fixed by `render_cond_expr`.
                    if let Some(mut leaves) = self.compound_leaves(cond, f, false) {
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
    ///
    /// `acc_flip` accumulates the `ruleBlockOr` fold-flips ([`FlowBlock::cond_flip`]) along the path
    /// to each leaf: a leaf at odd accumulated flip was already negated by the fold, so the while's
    /// distributed NOT cancels on it (Ghidra flips it twice → net raw) and it is left un-oriented
    /// (contributes no CBRANCH to materialize); [`render_cond_expr`](super::printc) then prints it
    /// directly via the same `cond_flip` XOR. Its cleanliness does not gate the all-or-nothing decision.
    fn compound_leaves(&self, cond: usize, f: &Funcdata, acc_flip: bool) -> Option<Vec<BlockId>> {
        match self.blocks[cond].kind {
            FlowKind::CondAnd | FlowKind::CondOr => {
                let (fl0, fl1) = self.blocks[cond].cond_flip;
                let c0 = self.blocks[cond].components[0];
                let c1 = self.blocks[cond].components[1];
                let mut a = self.compound_leaves(c0, f, acc_flip ^ fl0)?;
                let mut b = self.compound_leaves(c1, f, acc_flip ^ fl1)?;
                a.append(&mut b);
                Some(a)
            }
            _ => {
                let bid = self.exit_basic(cond)?;
                if acc_flip {
                    Some(Vec::new()) // odd-flip leaf: net raw, not oriented
                } else {
                    (condition_folds_cleanly(f, bid)).then_some(vec![bid])
                }
            }
        }
    }

    /// Predecessor lists for the currently-active blocks, from their out-edges:
    /// `ins[t] = [(pred, pred-out-index), …]` (the in-edge view of `out_labels` reads the label off
    /// the pred's slot, mirroring Ghidra's paired `intothis`/`outofthis` labels).
    fn in_edges(&self) -> Vec<Vec<(usize, usize)>> {
        let mut ins = vec![Vec::new(); self.blocks.len()];
        for b in 0..self.blocks.len() {
            if self.blocks[b].active {
                for (oi, &o) in self.blocks[b].out_edges.iter().enumerate() {
                    ins[o].push((b, oi));
                }
            }
        }
        ins
    }

    /// Replace `components` (entry = `components[0]`) with one structured block of `kind`
    /// and the given external `out_edges`. Predecessors of the entry are redirected to the
    /// new block; components are deactivated and get their `parent` set.
    ///
    /// The composite inherits its edges' labels and its component flags the way Ghidra's
    /// `identifyInternal`/`selfIdentify` (block.cc:940/895) do: an external predecessor's
    /// redirected edge keeps its label (`replaceOutEdge` carries `label`, block.cc:178); each
    /// composite out-edge takes the OR of the component edges it stands for (`replaceInEdge`
    /// carries the label, and `dedup`'s `eliminateOutDups` ORs duplicates, block.cc:488); the
    /// `INTERIOR_GOTOIN`/`INTERIOR_GOTOOUT` flags are inherited from every component
    /// (identifyInternal block.cc:951) and `SWITCH_OUT` from any component that still has an
    /// external out-edge (selfIdentify block.cc:925).
    fn install(&mut self, components: Vec<usize>, kind: FlowKind, out_edges: Vec<usize>, ins: &[Vec<(usize, usize)>]) -> usize {
        let entry = components[0];
        let compset: HashSet<usize> = components.iter().copied().collect();
        let n = self.blocks.len();
        let preds: Vec<usize> = ins[entry].iter().map(|&(p, _)| p).filter(|p| !compset.contains(p)).collect();
        // An out-target inside the component set is an internal edge Ghidra's `selfIdentify` drops
        // and `forceOutputNum` (block.cc:888) recreates as a LOOP|BACK-labeled self-edge on the
        // composite (e.g. a cat chain ending in the loop bottom whose back-edge re-enters the
        // chain head: the BlockList gets a self-edge and collapses as a do-while).
        let mut out_edges = out_edges;
        let out_labels: Vec<u32> = out_edges
            .iter_mut()
            .map(|t| {
                if compset.contains(t) {
                    *t = n;
                    return edge_flags::LOOP_EDGE | edge_flags::BACK_EDGE;
                }
                let mut lab = 0u32;
                for &c in &components {
                    for (oi, &tt) in self.blocks[c].out_edges.iter().enumerate() {
                        if tt == *t {
                            lab |= self.blocks[c].out_labels[oi];
                        }
                    }
                }
                lab
            })
            .collect();
        let mut flags = 0u32;
        for &c in &components {
            flags |= self.blocks[c].flags & (block_flags::INTERIOR_GOTOOUT | block_flags::INTERIOR_GOTOIN);
            if self.blocks[c].flags & block_flags::SWITCH_OUT != 0
                && self.blocks[c].out_edges.iter().any(|o| !compset.contains(o))
            {
                flags |= block_flags::SWITCH_OUT;
            }
        }
        self.blocks.push(FlowBlock { kind, components, out_edges, out_labels, flags, active: true, negated: false, parent: None, cond_flip: (false, false) });
        for p in preds {
            for e in self.blocks[p].out_edges.iter_mut() {
                if compset.contains(e) {
                    *e = n;
                }
            }
        }
        for &c in &self.blocks[n].components.clone() {
            self.blocks[c].active = false;
            self.blocks[c].parent = Some(n);
        }
        // Maintain the live graph list: components out, composite appended (Ghidra's
        // identifyInternal removes the nodes from `list`, addBlock appends the composite).
        self.order.retain(|x| !compset.contains(x));
        self.order.push(n);
        n
    }

    /// Ghidra's `CollapseStructure::checkSwitchSkips` (blockaction.cc:1607): a switch edge that
    /// goes straight to the exit block must be the \e default edge; if a default exists elsewhere,
    /// the skip edges are converted to gotos (returning `false` so `rule_switch` reports a change
    /// without collapsing).
    fn check_switch_skips(&mut self, switchbl: usize, exitblock: Option<usize>) -> bool {
        let Some(exitblock) = exitblock else {
            return true;
        };
        let sizeout = self.out(switchbl).len();
        let mut defaultnottoexit = false;
        let mut anyskiptoexit = false;
        for e in 0..sizeout {
            if self.out(switchbl)[e] == exitblock {
                if !self.blocks[switchbl].is_default_branch(e) {
                    anyskiptoexit = true;
                }
            } else if self.blocks[switchbl].is_default_branch(e) {
                defaultnottoexit = true;
            }
        }
        if !anyskiptoexit {
            return true;
        }
        // Ghidra checks the BlockMultiGoto wrapper for an already-cut default goto edge; mosura's
        // uncut head is the same block, with the cut recorded in `default_goto`.
        if !defaultnottoexit && self.default_goto.contains(&switchbl) {
            defaultnottoexit = true;
        }
        if !defaultnottoexit {
            return true;
        }
        for e in 0..sizeout {
            if self.out(switchbl)[e] == exitblock && !self.blocks[switchbl].is_default_branch(e) {
                self.set_goto_branch(switchbl, e);
            }
        }
        false
    }

    /// `ruleBlockSwitch` (blockaction.cc:1649): collapse a switch head (`SWITCH_OUT`) with its
    /// case blocks into a `Switch`, all cases exiting to a single exit block.
    fn rule_switch(&mut self, b: usize, ins: &[Vec<(usize, usize)>]) -> bool {
        if !self.blocks[b].is_switch_out() {
            return false;
        }
        let sizeout = self.out(b).len();
        // Find the "obvious" exit block: a self-edge (exit back to the top of a switch loop), or a
        // successor with more than one in- or out-edge.
        let mut exitblock: Option<usize> = None;
        for i in 0..sizeout {
            let curbl = self.out(b)[i];
            if curbl == b || self.out(curbl).len() > 1 || ins[curbl].len() > 1 {
                exitblock = Some(curbl);
                break;
            }
        }
        match exitblock {
            None => {
                // Every immediate successor has sizeIn==1 and sizeOut<=1: the first successor
                // with an output determines the exit, and all others must agree.
                for i in 0..sizeout {
                    let curbl = self.out(b)[i];
                    if is_goto_in(self, ins, curbl, 0) {
                        return false; // in cannot be a goto
                    }
                    if self.blocks[curbl].is_switch_out() {
                        return false; // must resolve nested switch first
                    }
                    if self.out(curbl).len() == 1 {
                        if self.blocks[curbl].is_goto_out(0) {
                            return false; // out cannot be goto
                        }
                        match exitblock {
                            Some(e) if e != self.out(curbl)[0] => return false,
                            Some(_) => {}
                            None => exitblock = Some(self.out(curbl)[0]),
                        }
                    }
                }
            }
            Some(e) => {
                for k in 0..ins[e].len() {
                    if is_goto_in(self, ins, e, k) {
                        return false; // no in gotos to exitblock
                    }
                }
                for k in 0..self.out(e).len() {
                    if self.blocks[e].is_goto_out(k) {
                        return false; // no out gotos from exitblock
                    }
                }
                for i in 0..sizeout {
                    let curbl = self.out(b)[i];
                    if curbl == e {
                        continue; // the switch can go straight to the exit block
                    }
                    if ins[curbl].len() > 1 {
                        return false; // a case can only have the switch fall into it
                    }
                    if is_goto_in(self, ins, curbl, 0) {
                        return false;
                    }
                    if self.out(curbl).len() > 1 {
                        return false; // at most 1 exit from a case
                    }
                    if self.out(curbl).len() == 1 {
                        if self.blocks[curbl].is_goto_out(0) {
                            return false;
                        }
                        if self.out(curbl)[0] != e {
                            return false; // which must be to the exitblock
                        }
                    }
                    if self.blocks[curbl].is_switch_out() {
                        return false; // nested switch must be resolved first
                    }
                }
            }
        }

        if !self.check_switch_skips(b, exitblock) {
            return true; // matched, but the special condition adds gotos instead
        }

        let mut cases = vec![b];
        for i in 0..sizeout {
            let curbl = self.out(b)[i];
            if Some(curbl) == exitblock {
                continue; // don't include the exit as a case
            }
            cases.push(curbl);
        }
        // A self-edge exit ("exit back to top of switch") becomes a self-edge on the composite
        // (Ghidra: the internal edge is collapsed and forceOutputNum recreates it as a
        // LOOP|BACK-labeled self loop, block.cc:888).
        let selfexit = exitblock == Some(b);
        let out_edges = match exitblock {
            Some(e) if !selfexit => vec![e],
            _ => vec![],
        };
        let n = self.install(cases, FlowKind::Switch, out_edges, ins);
        if selfexit {
            self.blocks[n].out_edges.push(n);
            self.blocks[n].out_labels.push(edge_flags::LOOP_EDGE | edge_flags::BACK_EDGE);
        }
        self.blocks[n].clear_flag(block_flags::SWITCH_OUT); // newBlockSwitch, block.cc:1917
        true
    }

    /// `ruleCaseFallthru` (blockaction.cc:1729): a switch case that falls through into another
    /// case gets its fall-through edge marked as a goto (so the switch can collapse; the goto
    /// prints as the fall-through jump).
    fn rule_case_fallthru(&mut self, b: usize, ins: &[Vec<(usize, usize)>]) -> bool {
        if !self.blocks[b].is_switch_out() {
            return false;
        }
        let sizeout = self.out(b).len();
        let mut nonfallthru = 0; // count of exits that are not fallthru
        let mut fallthru: Vec<usize> = Vec::new();
        for i in 0..sizeout {
            let curbl = self.out(b)[i];
            if curbl == b {
                return false; // cannot exit to itself
            }
            if ins[curbl].len() > 2 || self.out(curbl).len() > 1 {
                nonfallthru += 1;
            } else if self.out(curbl).len() == 1 {
                let target = self.out(curbl)[0];
                if ins[target].len() == 2 && self.out(target).len() <= 1 {
                    let inslot = ins[target].iter().position(|&(p, _)| p == curbl).unwrap();
                    if ins[target][1 - inslot].0 == b {
                        fallthru.push(curbl);
                    }
                }
            }
            if nonfallthru > 1 {
                return false; // can have at most 1 other exit block
            }
        }
        if fallthru.is_empty() {
            return false;
        }
        for &curbl in &fallthru {
            self.set_goto_branch(curbl, 0);
        }
        true
    }

    /// `ruleBlockIfNoExit` (blockaction.cc:1481): `if (cond) clause` where the clause is a
    /// single-entry block with no exit (it returns/halts), so control continues to the other arm
    /// afterwards. Only tried when no other rule applies (the `fullchange` slot of
    /// `collapseInternal`).
    fn rule_if_no_exit(&mut self, b: usize, ins: &[Vec<(usize, usize)>]) -> bool {
        if self.out(b).len() != 2 || self.blocks[b].is_switch_out() {
            return false;
        }
        if self.out(b)[0] == b || self.out(b)[1] == b {
            return false;
        }
        if self.blocks[b].is_goto_out(0) || self.blocks[b].is_goto_out(1) {
            return false;
        }
        for i in 0..2 {
            let clause = self.out(b)[i];
            if ins[clause].len() != 1 {
                continue; // nothing else must hit the clause
            }
            if !self.out(clause).is_empty() {
                continue; // must be no way out of the clause
            }
            if self.blocks[clause].is_switch_out() {
                continue;
            }
            if !self.blocks[b].is_decision_out(i) {
                continue;
            }
            let other = self.out(b)[1 - i];
            let n = self.install(vec![b, clause], FlowKind::If, vec![other], ins);
            self.blocks[n].negated = (i == 0) ^ self.is_oriented(b);
            return true;
        }
        false
    }

    /// `ruleBlockOr` (blockaction.cc:1321): two chained condition blocks collapse to a
    /// short-circuit condition. `bl`'s edge `i` enters the second condition `orblock`; the
    /// other edge (`1-i`) and one of `orblock`'s edges (`j`) share the exit `clauseblock`. Ghidra
    /// tries all four orientations `(i,j)`, calling `negateCondition` on `bl` (when `i==1`) and/or
    /// `orblock` (when `j==0`) to reach canonical form; the result is a two-out condition block
    /// (structured later by the `if` rules). Only run by `collapse_conditions` up front (Ghidra
    /// keeps `ruleBlockOr` out of `collapseInternal`).
    ///
    /// mosura never swaps CFG edges (see [`Funcdata::block_negate_condition`]), so instead of the
    /// two `negateCondition` edge reversals it (a) orders the composite's out-edges the way Ghidra's
    /// `newBlockCondition` forces them — false edge = `orblock`'s non-clause continuation, true edge
    /// = the shared clause — and (b) records the per-side flip in [`FlowBlock::cond_flip`], which
    /// [`render_cond_expr`](super::printc) XORs into each operand's print negation. The two canonical
    /// orientations `(i=0,j=1)`/`(i=1,j=0)` carry no flip and reproduce the previous 2-case fold
    /// byte-for-byte; the swapped `(i=0,j=0)`/`(i=1,j=1)` orientations are the newly-recovered folds.
    fn rule_short_circuit(&mut self, b: usize, ins: &[Vec<(usize, usize)>]) -> bool {
        if self.out(b).len() != 2 {
            return false;
        }
        if self.blocks[b].is_goto_out(0) || self.blocks[b].is_goto_out(1) {
            return false;
        }
        if self.blocks[b].is_switch_out() {
            return false;
        }
        for i in 0..2 {
            let orblock = self.out(b)[i]; // the second condition (Ghidra's orblock)
            if orblock == b || ins[orblock].len() != 1 || self.out(orblock).len() != 2 {
                continue;
            }
            if self.blocks[orblock].is_interior_goto_target() {
                continue; // no unstructured jumps into the second condition
            }
            if self.blocks[orblock].is_switch_out() {
                continue;
            }
            if self.blocks[b].is_back_edge_out(i) {
                continue; // don't use a loop branch to reach the second condition
            }
            if self.is_complex(orblock) {
                continue; // second condition block must print as a pure expression
            }
            let clauseblock = self.out(b)[1 - i];
            if clauseblock == b {
                continue; // Ghidra: clauseblock == bl — no looping
            }
            if clauseblock == orblock {
                continue;
            }
            // clauseblock must be one of orblock's two out-edges (index j)
            let Some(j) = (0..2).find(|&j| clauseblock == self.out(orblock)[j]) else {
                continue;
            };
            if self.out(orblock)[1 - j] == b {
                continue; // Ghidra: orblock->getOut(1-j) == bl — no looping
            }
            let continuation = self.out(orblock)[1 - j];
            let out = vec![continuation, clauseblock];
            // opcode: (bl->getFalseOut()==orblock) after the negates → i==0 gives OR, i==1 AND.
            let kind = if i == 0 { FlowKind::CondOr } else { FlowKind::CondAnd };
            let n = self.install(vec![b, orblock], kind, out, ins);
            // The deferred per-side negations: bl flipped when i==1, orblock flipped when j==0.
            self.blocks[n].cond_flip = (i == 1, j == 0);
            return true;
        }
        false
    }

    fn out(&self, b: usize) -> &[usize] {
        &self.blocks[b].out_edges
    }

    /// Whether the block is too complicated to print inside a condition — Ghidra's virtual
    /// `FlowBlock::isComplex` (block.hh:250, default \b true): a basic block (via BlockCopy)
    /// computes it (block.cc:2388, precomputed in [`complex`](Self::complex)); a short-circuit
    /// condition delegates to its first side (`BlockCondition::isComplex`, block.hh:635); every
    /// other composite is complex.
    fn is_complex(&self, idx: usize) -> bool {
        match self.blocks[idx].kind {
            FlowKind::Basic(b) => self.complex.get(b.0 as usize).copied().unwrap_or(true),
            FlowKind::CondAnd | FlowKind::CondOr => self.is_complex(self.blocks[idx].components[0]),
            _ => true,
        }
    }

    /// `ruleBlockGoto` (blockaction.cc:1450): consume an out-edge marked \e unstructured
    /// (`GOTO` by `select_goto`/`check_switch_skips`/`rule_case_fallthru`, or `IRREDUCIBLE` by
    /// `structure_loops`). The edge is recorded — the source's exit basic block emits the goto,
    /// the target's entry gets a label — and removed, exactly the graph shape Ghidra's
    /// `BlockGoto`/`BlockIfGoto`/`BlockMultiGoto` wrappers leave behind (the wrapper itself is
    /// only Ghidra's print carrier; mosura's carrier is the [`GotoRecord`]).
    fn rule_block_goto(&mut self, b: usize, _ins: &[Vec<(usize, usize)>]) -> bool {
        let sizeout = self.out(b).len();
        for i in 0..sizeout {
            if self.blocks[b].is_goto_out(i) {
                if self.blocks[b].is_switch_out() {
                    // BlockMultiGoto (block.cc:1720): pull the goto edge off the switch head.
                    if self.blocks[b].is_default_branch(i) {
                        self.default_goto.insert(b); // BlockMultiGoto::hasDefaultGoto
                    }
                    self.record_goto(b, i, false);
                    self.remove_out_edge(b, i);
                    return true;
                }
                if sizeout == 2 {
                    // BlockIfGoto (block.cc:1799): `if (cond) goto LAB;`, the other edge falls
                    // through (kept as the block's single remaining out-edge).
                    self.record_goto(b, i, true);
                    self.remove_out_edge(b, i);
                    return true;
                }
                if sizeout == 1 {
                    // BlockGoto (block.cc:1702): unconditional goto; the block becomes terminal.
                    self.record_goto(b, i, false);
                    self.remove_out_edge(b, i);
                    return true;
                }
            }
        }
        false
    }

    /// Record the goto for edge `i` of block `b` in [`gotos`](Self::gotos)/[`labels`](Self::labels).
    /// A conditional goto on out-edge 0 sits on the CBRANCH's false edge → print negated; a
    /// materialized branch orientation ([`is_oriented`](Self::is_oriented)) has already negated the
    /// IR condition, so it flips the sense back (the mosura analogue of Ghidra's `negateCondition`
    /// call in `ruleBlockGoto` operating on the already-flipped edge order).
    fn record_goto(&mut self, b: usize, i: usize, conditional: bool) {
        let target = self.blocks[b].out_edges[i];
        let (Some(eb), Some(et)) = (self.exit_basic(b), self.entry_basic(target)) else {
            return;
        };
        let negated = conditional && ((i == 0) ^ self.is_oriented(b));
        self.gotos.entry(eb).or_default().push(GotoRecord { target: et, negated, conditional, is_break: false });
        self.labels.insert(et);
    }

    /// Remove out-edge `i` of block `b`, keeping the parallel label vector aligned.
    fn remove_out_edge(&mut self, b: usize, i: usize) {
        self.blocks[b].out_edges.remove(i);
        self.blocks[b].out_labels.remove(i);
    }

    /// `ruleBlockCat` (blockaction.cc:1284): a chain of single-out → single-in blocks becomes a
    /// list. Internal edges must be plain decision edges (no goto/back); the chain stops at a
    /// switch head or loop bottom.
    fn rule_cat(&mut self, b: usize, ins: &[Vec<(usize, usize)>]) -> bool {
        if self.out(b).len() != 1 {
            return false;
        }
        if self.blocks[b].is_switch_out() {
            return false;
        }
        // if b's only predecessor has a single out, let that predecessor start the list
        if ins[b].len() == 1 && self.out(ins[b][0].0).len() == 1 {
            return false;
        }
        let outblock = self.out(b)[0];
        if outblock == b {
            return false; // no looping
        }
        if ins[outblock].len() != 1 {
            return false; // nothing else can hit outblock
        }
        if !self.blocks[b].is_decision_out(0) {
            return false; // not a goto or a loop bottom
        }
        if self.blocks[outblock].is_switch_out() {
            return false; // switch must be resolved first
        }
        let mut nodes = vec![b, outblock];
        let mut cur = outblock;
        while self.out(cur).len() == 1 {
            let outbl2 = self.out(cur)[0];
            if outbl2 == b {
                break; // no looping
            }
            if ins[outbl2].len() != 1 {
                break;
            }
            if !self.blocks[cur].is_decision_out(0) {
                break; // don't use loop bottom
            }
            if self.blocks[outbl2].is_switch_out() {
                break;
            }
            cur = outbl2;
            nodes.push(cur);
        }
        let out = self.blocks[*nodes.last().unwrap()].out_edges.clone();
        self.install(nodes, FlowKind::List, out, ins);
        true
    }

    /// `ruleBlockProperIf` (blockaction.cc:1378): `if (cond) clause` where `clause` reconverges
    /// to the other arm.
    fn rule_proper_if(&mut self, b: usize, ins: &[Vec<(usize, usize)>]) -> bool {
        if self.out(b).len() != 2 || self.blocks[b].is_switch_out() {
            return false;
        }
        if self.out(b)[0] == b || self.out(b)[1] == b {
            return false;
        }
        if self.blocks[b].is_goto_out(0) || self.blocks[b].is_goto_out(1) {
            return false;
        }
        for i in 0..2 {
            let clause = self.out(b)[i];
            if ins[clause].len() != 1 || self.out(clause).len() != 1 {
                continue;
            }
            if self.blocks[clause].is_switch_out() {
                continue; // don't use switch (possibly with goto edges)
            }
            if !self.blocks[b].is_decision_out(i) {
                continue; // don't use loop bottom or exit
            }
            if self.blocks[clause].is_goto_out(0) {
                continue; // no unstructured jumps out of the clause
            }
            if self.out(clause)[0] != self.out(b)[1 - i] {
                continue; // path after the clause must be the same
            }
            let merge = self.out(b)[1 - i];
            let n = self.install(vec![b, clause], FlowKind::If, vec![merge], ins);
            self.blocks[n].negated = (i == 0) ^ self.is_oriented(b);
            return true;
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

    /// `ruleBlockIfElse` (blockaction.cc:1416): both arms reconverge to one block.
    fn rule_if_else(&mut self, b: usize, ins: &[Vec<(usize, usize)>]) -> bool {
        if self.out(b).len() != 2 || self.blocks[b].is_switch_out() {
            return false;
        }
        if !self.blocks[b].is_decision_out(0) || !self.blocks[b].is_decision_out(1) {
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
        if self.blocks[tc].is_switch_out() || self.blocks[fc].is_switch_out() {
            return false;
        }
        if self.blocks[tc].is_goto_out(0) || self.blocks[fc].is_goto_out(0) {
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

    /// `ruleBlockWhileDo` (blockaction.cc:1518): one arm is a single-in/single-out block that
    /// loops back to `b`. Any break or continue must already have collapsed as a goto.
    /// (Ghidra's `isComplex` overflow-syntax variant is a deferred print-side refinement.)
    fn rule_while_do(&mut self, b: usize, ins: &[Vec<(usize, usize)>]) -> bool {
        if self.out(b).len() != 2 || self.blocks[b].is_switch_out() {
            return false;
        }
        if self.out(b)[0] == b || self.out(b)[1] == b {
            return false; // no loops at this point
        }
        if self.blocks[b].is_interior_goto_target() {
            return false;
        }
        if self.blocks[b].is_goto_out(0) || self.blocks[b].is_goto_out(1) {
            return false;
        }
        for i in 0..2 {
            let body = self.out(b)[i];
            if ins[body].len() != 1 || self.out(body).len() != 1 {
                continue;
            }
            if self.blocks[body].is_switch_out() {
                continue;
            }
            if self.out(body)[0] != b {
                continue; // clause must loop back to b
            }
            let exit = self.out(b)[1 - i];
            let n = self.install(vec![b, body], FlowKind::WhileDo, vec![exit], ins);
            self.blocks[n].negated = (i == 0) ^ self.is_oriented(b);
            return true;
        }
        false
    }

    /// `ruleBlockDoWhile` (blockaction.cc:1555): a two-out block with a self-edge.
    fn rule_do_while(&mut self, b: usize, ins: &[Vec<(usize, usize)>]) -> bool {
        if self.out(b).len() != 2 || self.blocks[b].is_switch_out() {
            return false;
        }
        if self.blocks[b].is_goto_out(0) || self.blocks[b].is_goto_out(1) {
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

    /// `ruleBlockInfLoop` (blockaction.cc:1579): a single-out block falling into itself is a
    /// loop with no exit. Deliberately no switch check (a BRANCHIND self-loop must still
    /// collapse — Ghidra's comment at blockaction.cc:1584).
    fn rule_inf_loop(&mut self, b: usize, ins: &[Vec<(usize, usize)>]) -> bool {
        if self.out(b).len() != 1 {
            return false;
        }
        if self.blocks[b].is_goto_out(0) {
            return false;
        }
        if self.out(b)[0] != b {
            return false; // must fall into itself
        }
        self.install(vec![b], FlowKind::InfLoop, vec![], ins);
        true
    }

    // ---- the collapse driver: Ghidra's CollapseStructure (blockaction.cc:1877) ----

    /// A block's current form in the top-level graph — Ghidra's `getParent()` walk
    /// (`LoopBody::update` blockaction.cc:97, `FloatingEdge::getCurrentEdge` blockaction.cc:30).
    fn current_form(&self, mut b: usize) -> usize {
        while let Some(p) = self.blocks[b].parent {
            b = p;
        }
        b
    }

    /// `FloatingEdge::getCurrentEdge` (blockaction.cc:27): update the edge's endpoints to their
    /// current collapsed forms and return `(top, out-index)` if the edge still exists.
    fn get_current_edge(&self, e: &mut FloatingEdge) -> Option<(usize, usize)> {
        e.top = self.current_form(e.top);
        e.bottom = self.current_form(e.bottom);
        let outedge = self.blocks[e.top].out_edges.iter().position(|&o| o == e.bottom)?;
        Some((e.top, outedge))
    }

    /// `FlowBlock::setGotoBranch` (block.cc:305): mark out-edge `i` of `b` unstructured and set
    /// the interior-goto flags on source and target.
    fn set_goto_branch(&mut self, b: usize, i: usize) {
        self.blocks[b].set_out_edge_flag(i, edge_flags::GOTO_EDGE);
        self.blocks[b].set_flag(block_flags::INTERIOR_GOTOOUT);
        let t = self.blocks[b].out_edges[i];
        self.blocks[t].set_flag(block_flags::INTERIOR_GOTOIN);
    }

    /// `LoopBody::update` (blockaction.cc:94): update the loop's head and tails to their current
    /// collapsed forms; return the first live tail (or the head, for a head looping with itself),
    /// or `None` if the loop has completely collapsed.
    fn loop_body_update(&mut self, li: usize) -> Option<usize> {
        let head = self.current_form(self.loopbody[li].head.expect("loop_order holds only live bodies"));
        self.loopbody[li].head = Some(head);
        for i in 0..self.loopbody[li].tails.len() {
            let bottom = self.current_form(self.loopbody[li].tails[i]);
            self.loopbody[li].tails[i] = bottom;
            if bottom != head {
                return Some(bottom); // the loop hasn't fully collapsed yet
            }
        }
        if self.blocks[head].out_edges.contains(&head) {
            return Some(head); // head looping with itself
        }
        None
    }

    /// `LoopBody::emitLikelyEdges` (blockaction.cc:364): append this loop's exit edges to the
    /// likely-goto list in priority order — the exit edges as labeled (middle, head, then tails),
    /// with the official exit edge held until right before the back-edges, and finally the
    /// back-edges themselves (less-preferred tails first) as the last resort.
    fn emit_likely_edges(&mut self, li: usize) {
        let head = self.current_form(self.loopbody[li].head.expect("live loop"));
        self.loopbody[li].head = Some(head);
        let mut exitblock = self.loopbody[li].exitblock.map(|e| self.current_form(e));
        for i in 0..self.loopbody[li].tails.len() {
            let tail = self.current_form(self.loopbody[li].tails[i]);
            self.loopbody[li].tails[i] = tail;
            if Some(tail) == exitblock {
                exitblock = None; // exitblock collapsed into a tail: no real exit any longer
            }
        }
        self.loopbody[li].exitblock = exitblock;

        let n_exit = self.loopbody[li].exitedges.len();
        let mut hold: Option<(usize, usize)> = None; // (inbl, outbl) of the delayed official exit
        for idx in 0..n_exit {
            let mut e = self.loopbody[li].exitedges[idx];
            let cur = self.get_current_edge(&mut e);
            self.loopbody[li].exitedges[idx] = e;
            let Some((inbl, outedge)) = cur else {
                continue; // edge does not exist (any longer)
            };
            let outbl = self.blocks[inbl].out_edges[outedge];
            if idx + 1 == n_exit && Some(outbl) == exitblock {
                hold = Some((inbl, outbl)); // official exit edge: hold off putting it in the list
                break;
            }
            self.likelygoto.push(FloatingEdge { top: inbl, bottom: outbl });
        }
        let tails = self.loopbody[li].tails.clone();
        for i in (0..tails.len()).rev() {
            // put out less-preferred back-edges first; the delayed exit right before the final one
            if i == 0 {
                if let Some((hin, hout)) = hold {
                    self.likelygoto.push(FloatingEdge { top: hin, bottom: hout });
                }
            }
            let tail = tails[i];
            for j in 0..self.blocks[tail].out_edges.len() {
                if self.blocks[tail].out_edges[j] == head {
                    self.likelygoto.push(FloatingEdge { top: tail, bottom: head });
                }
            }
        }
    }

    /// `LoopBody::setExitMarks` (blockaction.cc:416): label every current exit edge of the loop with
    /// `LOOP_EXIT_EDGE`, so the `TraceDAG` trace (which reads `isLoopDAGOut`) does not push out of the
    /// loop. Bracketed by [`clear_exit_marks`](Self::clear_exit_marks); the marks live only for the
    /// duration of one interior trace and never reach a collapse rule.
    fn set_exit_marks(&mut self, li: usize) {
        let n = self.loopbody[li].exitedges.len();
        for idx in 0..n {
            let mut e = self.loopbody[li].exitedges[idx];
            let cur = self.get_current_edge(&mut e);
            self.loopbody[li].exitedges[idx] = e;
            if let Some((inbl, outedge)) = cur {
                self.blocks[inbl].set_out_edge_flag(outedge, edge_flags::LOOP_EXIT_EDGE);
            }
        }
    }

    /// `LoopBody::clearExitMarks` (blockaction.cc:430): clear the `LOOP_EXIT_EDGE` marks set by
    /// [`set_exit_marks`](Self::set_exit_marks) once the interior trace (and `emit_likely_edges`) is
    /// done.
    fn clear_exit_marks(&mut self, li: usize) {
        let n = self.loopbody[li].exitedges.len();
        for idx in 0..n {
            let mut e = self.loopbody[li].exitedges[idx];
            let cur = self.get_current_edge(&mut e);
            self.loopbody[li].exitedges[idx] = e;
            if let Some((inbl, outedge)) = cur {
                self.blocks[inbl].clear_out_edge_flag(outedge, edge_flags::LOOP_EXIT_EDGE);
            }
        }
    }

    /// Run Ghidra's `TraceDAG` (blockaction.cc:499-1014) over the current collapsed graph, returning
    /// the edges it scores as likely `goto`s. For a loop the trace runs from `looptop` to the
    /// `finishblock` (loopbottom) between the (marked) exit edges; for the final DAG the roots are all
    /// entry blocks. On a clean reducible interior/DAG the trace fully retires and returns nothing.
    fn run_trace_dag(&self, roots: &[usize], finishblock: Option<usize>) -> Vec<FloatingEdge> {
        let in_adj = self.in_edges();
        let n = self.blocks.len();
        let tracer = TraceDag {
            blocks: &self.blocks,
            rpo: &self.rpo,
            in_adj,
            bps: Vec::new(),
            trs: Vec::new(),
            ahead: None,
            atail: None,
            activecount: 0,
            visitcount: vec![0i32; n],
            finishblock,
            rootlist: roots.to_vec(),
            likelygoto: Vec::new(),
        };
        tracer.run()
    }

    /// `CollapseStructure::updateLoopBody` (blockaction.cc:1193): advance to the current
    /// innermost live loop and make sure its likely-goto list is generated. Returns `true` while
    /// there are likely unstructured edges left to provide.
    ///
    /// For a live loop the list is the `TraceDAG` interior gotos (scored between the loop's marked
    /// exit edges from `looptop` to `loopbottom`) followed by `emit_likely_edges`' exit/back edges;
    /// for the final DAG the tracer over all entry roots is the only source — if it finds nothing the
    /// search ends (`finaltrace`).
    fn update_loop_body(&mut self) -> bool {
        if self.finaltrace {
            return false;
        }
        // The current live loop being processed, carried with its live loop bottom (Ghidra's
        // `loopbottom`, which distinguishes a loop trace from the final-DAG trace).
        let mut current: Option<(usize, usize)> = None;
        while self.loopiter < self.loop_order.len() {
            let li = self.loop_order[self.loopiter];
            if let Some(loopbottom) = self.loop_body_update(li) {
                let looptop = self.loopbody[li].head.expect("live loop");
                if loopbottom == looptop {
                    // A single node looping back to itself: with 1 or 2 out-edges the loop would
                    // have collapsed, so the node is likely a switch — mark the loop edge itself.
                    self.likelygoto.clear();
                    self.likelygoto.push(FloatingEdge { top: looptop, bottom: looptop });
                    self.likelyiter = 0;
                    self.likelylistfull = true;
                    return true;
                }
                if !self.likelylistfull || self.likelyiter != self.likelygoto.len() {
                    current = Some((li, loopbottom)); // loop still exists
                    break;
                }
            }
            self.loopiter += 1;
            self.likelylistfull = false; // need to generate the list for the next loop (or DAG)
        }
        if self.likelylistfull && self.likelyiter != self.likelygoto.len() {
            return true;
        }
        // Generate likely gotos for a new inner loop or the final DAG.
        self.likelygoto.clear();
        self.likelylistfull = true;
        match current {
            Some((li, loopbottom)) => {
                // Trace the loop interior (looptop..loopbottom) between the marked exit edges,
                // then append the loop's own exit/back edges — Ghidra's updateLoopBody loop branch.
                let looptop = self.loopbody[li].head.expect("live loop");
                self.set_exit_marks(li);
                let gotos = self.run_trace_dag(&[looptop], Some(loopbottom));
                self.likelygoto.extend(gotos);
                self.emit_likely_edges(li);
                self.clear_exit_marks(li);
            }
            None => {
                // Final DAG: trace from every entry (in-degree-0) root. If nothing is scored, the
                // graph is fully structurable and the search is done.
                let ins = self.in_edges();
                let roots: Vec<usize> = self.order.iter().copied().filter(|&b| ins[b].is_empty()).collect();
                let gotos = self.run_trace_dag(&roots, None);
                self.likelygoto.extend(gotos);
                if self.likelygoto.is_empty() {
                    self.finaltrace = true; // no loops left and the DAG trace found no gotos
                    return false;
                }
            }
        }
        self.likelyiter = 0;
        true
    }

    /// `CollapseStructure::selectGoto` (blockaction.cc:1260): pick the next likely unstructured
    /// edge whose endpoints haven't collapsed together and mark it as a goto.
    fn select_goto(&mut self) -> SelectGoto {
        while self.update_loop_body() {
            while self.likelyiter < self.likelygoto.len() {
                let mut e = self.likelygoto[self.likelyiter];
                let cur = self.get_current_edge(&mut e);
                self.likelygoto[self.likelyiter] = e;
                self.likelyiter += 1;
                if let Some((startbl, outedge)) = cur {
                    self.set_goto_branch(startbl, outedge);
                    return SelectGoto::Target(startbl);
                }
            }
        }
        if self.clip_extra_roots() {
            SelectGoto::Rescan
        } else {
            // Ghidra's `selectGoto` throws `LowlevelError("Could not finish collapsing block
            // structure")` here: the `TraceDAG` trace (run inside `update_loop_body`) has already
            // scored every non-DAG goto, so a well-formed graph never reaches this point with
            // uncollapsed blocks. mosura reports it to the driver, which stops rather than throwing.
            SelectGoto::Stuck
        }
    }

    /// `CollapseStructure::onlyReachableFromRoot` (blockaction.cc:1052): mark and collect the
    /// blocks only reachable from `root`.
    fn only_reachable_from_root(&mut self, root: usize, ins: &[Vec<(usize, usize)>]) -> Vec<usize> {
        let mut visit = vec![0i32; self.blocks.len()];
        let mut body = vec![root];
        self.blocks[root].set_flag(block_flags::MARK);
        let mut i = 0;
        while i < body.len() {
            let bl = body[i];
            i += 1;
            for j in 0..self.blocks[bl].out_edges.len() {
                let curbl = self.blocks[bl].out_edges[j];
                if self.blocks[curbl].flags & block_flags::MARK != 0 {
                    continue;
                }
                visit[curbl] += 1;
                if visit[curbl] == ins[curbl].len() as i32 {
                    self.blocks[curbl].set_flag(block_flags::MARK);
                    body.push(curbl);
                }
            }
        }
        body
    }

    /// `CollapseStructure::markExitsAsGotos` (blockaction.cc:1083): mark every edge leaving the
    /// (marked) body as unstructured; return how many were marked.
    fn mark_exits_as_gotos(&mut self, body: &[usize]) -> usize {
        let mut changecount = 0;
        for &bl in body {
            for j in 0..self.blocks[bl].out_edges.len() {
                let curbl = self.blocks[bl].out_edges[j];
                if self.blocks[curbl].flags & block_flags::MARK == 0 {
                    self.set_goto_branch(bl, j);
                    changecount += 1;
                }
            }
        }
        changecount
    }

    /// `CollapseStructure::clipExtraRoots` (blockaction.cc:1108): find a disjoint subset hanging
    /// off an extra root (no in-edges, other than the canonical root) with cross-over edges into
    /// the rest of the graph; mark those exits as gotos.
    fn clip_extra_roots(&mut self) -> bool {
        let ins = self.in_edges();
        for oi in 1..self.order.len() {
            // skip the canonical root
            let bl = self.order[oi];
            if !ins[bl].is_empty() {
                continue;
            }
            let body = self.only_reachable_from_root(bl, &ins);
            let count = self.mark_exits_as_gotos(&body);
            for &b in &body {
                self.blocks[b].clear_flag(block_flags::MARK);
            }
            if count != 0 {
                return true;
            }
        }
        false
    }

    /// `CollapseStructure::collapseConditions` (blockaction.cc:1854): simplify just the
    /// short-circuit AND/OR constructions, to a fixed point. Run once, up front (Ghidra keeps
    /// `ruleBlockOr` out of the main rule scan).
    fn collapse_conditions(&mut self) {
        loop {
            let mut change = false;
            let mut index = 0;
            while index < self.order.len() {
                let bl = self.order[index];
                index += 1;
                let ins = self.in_edges();
                if self.rule_short_circuit(bl, &ins) {
                    change = true;
                }
            }
            if !change {
                break;
            }
        }
    }

    /// `CollapseStructure::collapseInternal` (blockaction.cc:1768): apply the structuring rules
    /// to a fixed point, starting from `targetbl` if given (the block `select_goto` just marked).
    /// `ruleBlockIfNoExit`/`ruleCaseFallthru` run only when nothing else applies. Returns the
    /// count of isolated blocks (no in- or out-edges).
    fn collapse_internal(&mut self, mut targetbl: Option<usize>) -> usize {
        let mut isolated_count;
        loop {
            loop {
                let mut change = false;
                let mut index = 0;
                isolated_count = 0;
                while index < self.order.len() {
                    let bl = match targetbl.take() {
                        Some(t) => {
                            change = true; // force a rescan so we still go through all blocks
                            index = self.order.len(); // only target the block once
                            t
                        }
                        None => {
                            let b = self.order[index];
                            index += 1;
                            b
                        }
                    };
                    let ins = self.in_edges();
                    if self.blocks[bl].out_edges.is_empty() && ins[bl].is_empty() {
                        isolated_count += 1; // a completely collapsed block; not a change
                        continue;
                    }
                    if self.rule_block_goto(bl, &ins) {
                        change = true;
                        continue;
                    }
                    if self.rule_cat(bl, &ins) {
                        change = true;
                        continue;
                    }
                    if self.rule_proper_if(bl, &ins) {
                        change = true;
                        continue;
                    }
                    if self.rule_if_else(bl, &ins) {
                        change = true;
                        continue;
                    }
                    if self.rule_while_do(bl, &ins) {
                        change = true;
                        continue;
                    }
                    if self.rule_do_while(bl, &ins) {
                        change = true;
                        continue;
                    }
                    if self.rule_inf_loop(bl, &ins) {
                        change = true;
                        continue;
                    }
                    if self.rule_switch(bl, &ins) {
                        change = true;
                        continue;
                    }
                }
                if !change {
                    break;
                }
            }
            // Applying IfNoExit too early can cause other (preferable) rules to miss; only when
            // nothing else applies.
            let mut fullchange = false;
            let mut index = 0;
            while index < self.order.len() {
                let bl = self.order[index];
                index += 1;
                let ins = self.in_edges();
                if self.rule_if_no_exit(bl, &ins) {
                    fullchange = true;
                    break;
                }
                if self.rule_case_fallthru(bl, &ins) {
                    fullchange = true;
                    break;
                }
            }
            if !fullchange {
                break;
            }
        }
        isolated_count
    }

    /// `CollapseStructure::collapseAll` (blockaction.cc:1877): collapse everything to isolated
    /// blocks — conditions first, then the structural rules, marking one likely goto at a time
    /// when stuck. Every `select_goto` marks at least one new goto edge (consumed and removed by
    /// `rule_block_goto`), so the isolated count grows and the loop terminates; the counter is a
    /// safety net for that invariant.
    fn collapse_all(&mut self) {
        self.finaltrace = false;
        self.collapse_conditions();
        let mut isolated_count = self.collapse_internal(None);
        // Every spin cuts >=1 edge; the leaf graph's edge count (plus slack) bounds the spins.
        let cap = 16 + self.blocks.iter().map(|b| b.out_edges.len() + 1).sum::<usize>();
        let mut spins = 0usize;
        while isolated_count < self.order.len() {
            spins += 1;
            if spins > cap {
                debug_assert!(false, "structure collapse did not converge in {cap} goto selections");
                break;
            }
            match self.select_goto() {
                SelectGoto::Target(t) => isolated_count = self.collapse_internal(Some(t)),
                SelectGoto::Rescan => isolated_count = self.collapse_internal(None),
                // Ghidra throws here (the TraceDAG has already scored every non-DAG goto); a
                // well-formed graph never reaches this, so stop instead of looping forever.
                SelectGoto::Stuck => {
                    debug_assert!(false, "structure collapse stuck: TraceDAG scored no goto and no extra roots");
                    break;
                }
            }
        }
    }

    /// Ghidra's `BlockGraph::scopeBreak` (block.cc:1270) plus the per-block overrides, run by
    /// `ActionFinalStructure` (blockaction.cc:2193) after `collapseAll`: walk the structured tree
    /// and flip every loop-exit goto to a `break`. Only `f_break_goto` (block.hh:90) is produced —
    /// the C++ decompiler never assigns `f_continue_goto`, because a back-edge to the loop head is
    /// the loop's own structure, so no explicit `continue` arises. `curexit`/`curloopexit` are the
    /// entry basic blocks of the emission-successor and of the innermost enclosing loop's exit; a
    /// goto whose target equals `curloopexit` is a break (`BlockGoto`/`BlockIf::scopeBreak`, both
    /// test `gototarget->getIndex() == curloopexit`). After the walk, targets referenced only by
    /// breaks no longer need a label — Ghidra's `markUnstructured` marks `f_unstructured_targ` only
    /// for surviving `f_goto_goto` edges — so the label set is rebuilt from the non-break gotos.
    fn scope_break(&mut self) {
        let mut loopexit: HashMap<BlockId, Option<BlockId>> = HashMap::new();
        self.scope_break_walk(self.root, None, None, &mut loopexit);
        for (src, records) in self.gotos.iter_mut() {
            if let Some(&cle) = loopexit.get(src) {
                for r in records.iter_mut() {
                    if Some(r.target) == cle {
                        r.is_break = true;
                    }
                }
            }
        }
        self.labels.clear();
        for records in self.gotos.values() {
            for r in records {
                if !r.is_break {
                    self.labels.insert(r.target);
                }
            }
        }
    }

    /// Recurse `scopeBreak` over the structured tree (the block-type overrides in block.cc),
    /// recording the `curloopexit` in effect at each leaf basic block into `loopexit` so
    /// [`scope_break`](Self::scope_break) can flip that leaf's gotos. `curexit` is the block emitted
    /// immediately after this subtree; `curloopexit` is the innermost enclosing loop's exit.
    fn scope_break_walk(&self, idx: usize, curexit: Option<BlockId>, curloopexit: Option<BlockId>, loopexit: &mut HashMap<BlockId, Option<BlockId>>) {
        let kind = self.blocks[idx].kind.clone();
        let comps = self.blocks[idx].components.clone();
        match kind {
            // A leaf (BlockCopy, or a BlockGoto/BlockIfGoto carrier): a goto here is a break iff it
            // targets the current loop exit (BlockGoto/BlockIf::scopeBreak, block.cc:2866/3075).
            FlowKind::Basic(bid) => {
                loopexit.insert(bid, curloopexit);
            }
            // BlockGraph::scopeBreak (block.cc:1270): each subblock exits into the next sibling.
            FlowKind::List => {
                for i in 0..comps.len() {
                    let sub_exit = if i + 1 < comps.len() { self.entry_basic(comps[i + 1]) } else { curexit };
                    self.scope_break_walk(comps[i], sub_exit, curloopexit, loopexit);
                }
            }
            // BlockIf::scopeBreak (block.cc:3075): condition has multiple exits (curexit=-1); the
            // arms share this block's curexit.
            FlowKind::If => {
                self.scope_break_walk(comps[0], None, curloopexit, loopexit);
                self.scope_break_walk(comps[1], curexit, curloopexit, loopexit);
            }
            FlowKind::IfElse => {
                self.scope_break_walk(comps[0], None, curloopexit, loopexit);
                self.scope_break_walk(comps[1], curexit, curloopexit, loopexit);
                self.scope_break_walk(comps[2], curexit, curloopexit, loopexit);
            }
            // BlockWhileDo::scopeBreak (block.cc:3324): a new loop scope — curloopexit becomes this
            // loop's curexit; the body exits back into the condition (the loop top).
            FlowKind::WhileDo => {
                self.scope_break_walk(comps[0], None, curexit, loopexit);
                let top = self.entry_basic(comps[0]);
                self.scope_break_walk(comps[1], top, curexit, loopexit);
            }
            // BlockDoWhile::scopeBreak (block.cc:3434): new loop scope, curloopexit becomes curexit.
            FlowKind::DoWhile => {
                self.scope_break_walk(comps[0], None, curexit, loopexit);
            }
            // BlockInfLoop::scopeBreak (block.cc:3462): exits into itself, curloopexit becomes curexit.
            FlowKind::InfLoop => {
                let top = self.entry_basic(comps[0]);
                self.scope_break_walk(comps[0], top, curexit, loopexit);
            }
            // BlockCondition::scopeBreak (block.cc:3034): both sides, no fixed exit.
            FlowKind::CondAnd | FlowKind::CondOr => {
                self.scope_break_walk(comps[0], None, curloopexit, loopexit);
                self.scope_break_walk(comps[1], None, curloopexit, loopexit);
            }
            // BlockSwitch::scopeBreak (block.cc:3613): new scope; cases share the switch exit.
            FlowKind::Switch => {
                self.scope_break_walk(comps[0], None, curexit, loopexit);
                for &case in &comps[1..] {
                    self.scope_break_walk(case, curexit, curexit, loopexit);
                }
            }
        }
    }
}

/// The outcome of [`Structured::select_goto`]: a block whose out-edge was just marked (Ghidra
/// returns the FlowBlock), a rescan request after `clipExtraRoots` marked cross-over edges
/// (Ghidra returns null), or a genuinely stuck graph (Ghidra throws `LowlevelError`).
enum SelectGoto {
    Target(usize),
    Rescan,
    Stuck,
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
/// and excludes them from the returned processing order, which is equivalent since they are inert.
/// Returns the bodies and the deepest-first order the collapse driver iterates.
fn order_loop_bodies(s: &mut Structured, n: usize) -> (Vec<LoopBody>, Vec<usize>) {
    let in_adj = in_adjacency(s, n);
    let rpo = s.rpo.clone();
    let (mut loopbody, mut looporder) = label_loops(s, &in_adj, &rpo);
    if loopbody.is_empty() {
        return (loopbody, Vec::new());
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
    (loopbody, process_order)
}

// ---- Ghidra's TraceDAG (blockaction.cc:499-1014): score the non-DAG unstructured edges ----

/// `TraceDAG::BlockTrace::f_active` (blockaction.hh:125): this `BlockTrace` is on the active list.
const TR_ACTIVE: u32 = 1;
/// `TraceDAG::BlockTrace::f_terminal` (blockaction.hh:126): all paths from this trace exit without
/// merging back to the parent.
const TR_TERMINAL: u32 = 2;

/// `TraceDAG::BranchPoint` (blockaction.hh:102): a node with multiple outgoing DAG edges, along which
/// the trace splits. `top` is the branch FlowBlock (`None` for the virtual root); `paths` are the
/// `BlockTrace` indices out of it. Parent pointers + `depth` give the ancestor distance metric.
struct BpNode {
    parent: Option<usize>,
    pathout: i32,
    top: Option<usize>,
    paths: Vec<usize>,
    depth: i32,
    ismark: bool,
}

/// `TraceDAG::BlockTrace` (blockaction.hh:123): a single traced path out of a `BranchPoint`. `bottom`
/// is the current node reached along the path, `destnode` the next node it will try to push into, and
/// `edgelump` the number of real edges a retired sub-branch collapsed into. `anext`/`aprev` implement
/// the intrusive active list (Ghidra's `std::list<BlockTrace*>` + per-trace `activeiter`).
struct TrNode {
    flags: u32,
    top: usize,
    pathout: i32,
    bottom: Option<usize>,
    destnode: Option<usize>,
    edgelump: i32,
    derivedbp: Option<usize>,
    anext: Option<usize>,
    aprev: Option<usize>,
}

/// `TraceDAG::BadEdgeScore` (blockaction.hh:146): metrics for ranking a stuck `BlockTrace` as the
/// unstructured edge.
struct BadEdgeScore {
    exitproto: usize,
    trace: usize,
    distance: i32,
    terminal: i32,
    siblingedge: i32,
}

/// Ghidra's `TraceDAG` (blockaction.cc:499-1014), ported over mosura's index-based collapse graph.
/// `BranchPoint`/`BlockTrace` pointers become indices into `bps`/`trs`; the `std::list` active set is
/// an intrusive doubly linked list threaded through `TrNode::anext`/`aprev`. The graph is read-only
/// during a trace (no collapse happens), so `in_adj` is snapshotted once; `visitcount` is the tracer's
/// own copy of Ghidra's per-`FlowBlock` field (only touched by `removeTrace`, discarded at the end).
struct TraceDag<'a> {
    blocks: &'a [FlowBlock],
    rpo: &'a [i32],
    in_adj: Vec<Vec<(usize, usize)>>,
    bps: Vec<BpNode>,
    trs: Vec<TrNode>,
    ahead: Option<usize>,
    atail: Option<usize>,
    activecount: i32,
    visitcount: Vec<i32>,
    finishblock: Option<usize>,
    rootlist: Vec<usize>,
    likelygoto: Vec<FloatingEdge>,
}

impl<'a> TraceDag<'a> {
    /// `FlowBlock::getIndex` (block.hh:160): the reverse-post-order number; a composite `BlockGraph`
    /// takes the minimum index over its components (`BlockGraph::addBlock`, block.cc:862).
    fn block_index(&self, b: usize) -> i32 {
        match self.blocks[b].kind {
            FlowKind::Basic(bid) => self.rpo[bid.0 as usize],
            _ => self.blocks[b].components.iter().map(|&c| self.block_index(c)).min().unwrap_or(0),
        }
    }

    /// `FlowBlock::isLoopDAGIn` (block.hh:345): the `k`-th in-edge of `bl` stays within the reducible
    /// loop DAG (label read off the source's out-edge, as elsewhere).
    fn is_loop_dag_in(&self, bl: usize, k: usize) -> bool {
        use edge_flags::*;
        let (src, oi) = self.in_adj[bl][k];
        self.blocks[src].out_labels[oi] & (IRREDUCIBLE | BACK_EDGE | LOOP_EXIT_EDGE | GOTO_EDGE) == 0
    }

    /// `TraceDAG::insertActive` (blockaction.cc:786): append `tr` to the active list.
    fn insert_active(&mut self, tr: usize) {
        self.trs[tr].aprev = self.atail;
        self.trs[tr].anext = None;
        match self.atail {
            Some(x) => self.trs[x].anext = Some(tr),
            None => self.ahead = Some(tr),
        }
        self.atail = Some(tr);
        self.trs[tr].flags |= TR_ACTIVE;
        self.activecount += 1;
    }

    /// `TraceDAG::removeActive` (blockaction.cc:798): unlink `tr` from the active list.
    fn remove_active(&mut self, tr: usize) {
        let p = self.trs[tr].aprev;
        let nx = self.trs[tr].anext;
        match p {
            Some(x) => self.trs[x].anext = nx,
            None => self.ahead = nx,
        }
        match nx {
            Some(x) => self.trs[x].aprev = p,
            None => self.atail = p,
        }
        self.trs[tr].flags &= !TR_ACTIVE;
        self.activecount -= 1;
    }

    /// `TraceDAG::BlockTrace::BlockTrace(BranchPoint*,int4,int4)` (blockaction.cc:586): a path out of
    /// `bp` along its out-edge `eo` (the `po`-th loop-DAG path).
    fn new_trace_from_bp(&mut self, bp: usize, po: i32, eo: usize) -> usize {
        let bottom = self.bps[bp].top;
        let destnode = Some(self.blocks[bottom.expect("branch point has a FlowBlock")].out_edges[eo]);
        self.trs.push(TrNode {
            flags: 0,
            top: bp,
            pathout: po,
            bottom,
            destnode,
            edgelump: 1,
            derivedbp: None,
            anext: None,
            aprev: None,
        });
        self.trs.len() - 1
    }

    /// `TraceDAG::BlockTrace::BlockTrace(BranchPoint*,int4,FlowBlock*)` (blockaction.cc:603): a root
    /// path off the virtual BranchPoint to entry block `bl` (the edge is not a real edge).
    fn new_root_trace(&mut self, bp: usize, po: i32, bl: usize) -> usize {
        self.trs.push(TrNode {
            flags: 0,
            top: bp,
            pathout: po,
            bottom: None,
            destnode: Some(bl),
            edgelump: 1,
            derivedbp: None,
            anext: None,
            aprev: None,
        });
        self.trs.len() - 1
    }

    /// `TraceDAG::BranchPoint::createTraces` (blockaction.cc:499): one `BlockTrace` per loop-DAG
    /// out-edge of the branch FlowBlock.
    fn create_traces(&mut self, bp: usize) {
        let fb = self.bps[bp].top.expect("branch point has a FlowBlock");
        let sizeout = self.blocks[fb].out_edges.len();
        for i in 0..sizeout {
            if !self.blocks[fb].is_loop_dag_out(i) {
                continue;
            }
            let po = self.bps[bp].paths.len() as i32;
            let tr = self.new_trace_from_bp(bp, po, i);
            self.bps[bp].paths.push(tr);
        }
    }

    /// `TraceDAG::BranchPoint::BranchPoint(BlockTrace*)` (blockaction.cc:565): open a new BranchPoint
    /// at the destination of `parent_tr`.
    fn make_bp_from_trace(&mut self, parent_tr: usize) -> usize {
        let parent = self.trs[parent_tr].top;
        let depth = self.bps[parent].depth + 1;
        let pathout = self.trs[parent_tr].pathout;
        let top = self.trs[parent_tr].destnode;
        self.bps.push(BpNode { parent: Some(parent), pathout, top, paths: Vec::new(), depth, ismark: false });
        let bp = self.bps.len() - 1;
        self.create_traces(bp);
        bp
    }

    /// `TraceDAG::BranchPoint::markPath` (blockaction.cc:509): toggle the mark from `bp` up to the root.
    fn mark_path(&mut self, bp: usize) {
        let mut cur = Some(bp);
        while let Some(c) = cur {
            self.bps[c].ismark = !self.bps[c].ismark;
            cur = self.bps[c].parent;
        }
    }

    /// `TraceDAG::BranchPoint::distance` (blockaction.cc:524): edges from `a` up to the common ancestor
    /// of `a` and `b` plus edges down to `b` (`a`'s path to the root is assumed marked).
    fn distance(&self, a: usize, b: usize) -> i32 {
        let mut cur = Some(b);
        while let Some(c) = cur {
            if self.bps[c].ismark {
                return (self.bps[a].depth - self.bps[c].depth) + (self.bps[b].depth - self.bps[c].depth);
            }
            cur = self.bps[c].parent;
        }
        self.bps[a].depth + self.bps[b].depth + 1
    }

    /// `TraceDAG::removeTrace` (blockaction.cc:656): record `tr`'s edge as a likely goto and detach it
    /// (terminal if it has advanced past the branch root, else spliced out of the BranchPoint's paths).
    fn remove_trace(&mut self, tr: usize) {
        let bottom = self.trs[tr].bottom;
        let dn = self.trs[tr].destnode;
        self.likelygoto.push(FloatingEdge { top: bottom.expect("non-terminal trace"), bottom: dn.expect("non-terminal trace") });
        self.visitcount[dn.unwrap()] += self.trs[tr].edgelump;
        let parentbp = self.trs[tr].top;
        if self.trs[tr].bottom != self.bps[parentbp].top {
            // Trace moved past the root branch: treat it as terminal, keep it on the active list.
            self.trs[tr].flags |= TR_TERMINAL;
            self.trs[tr].bottom = None;
            self.trs[tr].destnode = None;
            self.trs[tr].edgelump = 0;
            return;
        }
        // Otherwise remove the path from the BranchPoint (its root branch becomes a goto).
        self.remove_active(tr);
        let size = self.bps[parentbp].paths.len();
        let po = self.trs[tr].pathout as usize;
        for i in (po + 1)..size {
            let moved = self.bps[parentbp].paths[i];
            self.trs[moved].pathout -= 1;
            if let Some(dbp) = self.trs[moved].derivedbp {
                self.bps[dbp].pathout -= 1;
            }
            self.bps[parentbp].paths[i - 1] = moved;
        }
        self.bps[parentbp].paths.pop();
    }

    /// `TraceDAG::processExitConflict` (blockaction.cc:694): for a run of BlockTraces sharing an exit
    /// block, compute the minimum inter-branchpoint distance and count sibling edges.
    fn process_exit_conflict(&mut self, scores: &mut [BadEdgeScore], start: usize, end: usize) {
        let mut s = start;
        while s < end {
            let startbp = self.trs[scores[s].trace].top;
            if s + 1 < end {
                self.mark_path(startbp);
                for it in (s + 1)..end {
                    if startbp == self.trs[scores[it].trace].top {
                        scores[s].siblingedge += 1;
                        scores[it].siblingedge += 1;
                    }
                    let dist = self.distance(startbp, self.trs[scores[it].trace].top);
                    if scores[s].distance == -1 || scores[s].distance > dist {
                        scores[s].distance = dist;
                    }
                    if scores[it].distance == -1 || scores[it].distance > dist {
                        scores[it].distance = dist;
                    }
                }
                self.mark_path(startbp);
            }
            s += 1;
        }
    }

    /// `TraceDAG::BadEdgeScore::operator<` (blockaction.cc:635): group traces by exit block, then by
    /// branch-point FlowBlock, then by the branch taken (`pathout`).
    fn bad_edge_cmp(&self, a: &BadEdgeScore, b: &BadEdgeScore) -> std::cmp::Ordering {
        let ai = self.block_index(a.exitproto);
        let bi = self.block_index(b.exitproto);
        if ai != bi {
            return ai.cmp(&bi);
        }
        let atmp = self.bps[self.trs[a.trace].top].top.map(|x| self.block_index(x)).unwrap_or(-1);
        let btmp = self.bps[self.trs[b.trace].top].top.map(|x| self.block_index(x)).unwrap_or(-1);
        if atmp != btmp {
            return atmp.cmp(&btmp);
        }
        self.trs[a.trace].pathout.cmp(&self.trs[b.trace].pathout)
    }

    /// `TraceDAG::BadEdgeScore::compareFinal` (blockaction.cc:617): `true` if `a` is LESS likely to be
    /// the bad edge than `b` (bigger sibling edge / non-terminal / smaller distance / shallower).
    fn compare_final(&self, a: &BadEdgeScore, b: &BadEdgeScore) -> bool {
        if a.siblingedge != b.siblingedge {
            return b.siblingedge < a.siblingedge;
        }
        if a.terminal != b.terminal {
            return a.terminal < b.terminal;
        }
        if a.distance != b.distance {
            return a.distance < b.distance;
        }
        self.bps[self.trs[a.trace].top].depth < self.bps[self.trs[b.trace].top].depth
    }

    /// `TraceDAG::selectBadEdge` (blockaction.cc:730): annotate the active BlockTraces and return the
    /// one most likely to be an unstructured edge.
    fn select_bad_edge(&mut self) -> usize {
        let mut list: Vec<BadEdgeScore> = Vec::new();
        let mut cur = self.ahead;
        while let Some(tr) = cur {
            cur = self.trs[tr].anext;
            if self.trs[tr].flags & TR_TERMINAL != 0 {
                continue;
            }
            // Never remove virtual edges (the root paths off the artificial BranchPoint).
            if self.bps[self.trs[tr].top].top.is_none() && self.trs[tr].bottom.is_none() {
                continue;
            }
            let exitproto = self.trs[tr].destnode.expect("non-terminal trace has a destnode");
            let terminal = if self.blocks[exitproto].out_edges.is_empty() { 1 } else { 0 };
            list.push(BadEdgeScore { exitproto, trace: tr, distance: -1, terminal, siblingedge: 0 });
        }
        list.sort_by(|a, b| self.bad_edge_cmp(a, b));

        // Process each maximal run of traces sharing an exit block.
        let mut i = 0;
        while i < list.len() {
            let curbl = list[i].exitproto;
            let mut j = i + 1;
            while j < list.len() && list[j].exitproto == curbl {
                j += 1;
            }
            if j - i > 1 {
                self.process_exit_conflict(&mut list, i, j);
            }
            i = j;
        }

        let mut maxi = 0;
        for k in 1..list.len() {
            if self.compare_final(&list[maxi], &list[k]) {
                maxi = k;
            }
        }
        list[maxi].trace
    }

    /// `TraceDAG::checkOpen` (blockaction.cc:810): a node can be opened only once all its loop-DAG
    /// in-edges have been traced (accounting for edges already treated as goto via `visitcount`).
    fn check_open(&self, tr: usize) -> bool {
        if self.trs[tr].flags & TR_TERMINAL != 0 {
            return false;
        }
        let mut isroot = false;
        if self.bps[self.trs[tr].top].depth == 0 {
            if self.trs[tr].bottom.is_none() {
                return true; // artificial root can always open its first level
            }
            isroot = true;
        }
        let bl = self.trs[tr].destnode.expect("active non-terminal trace has a destnode");
        if Some(bl) == self.finishblock && !isroot {
            return false; // only the root may open the designated exit
        }
        let ignore = self.trs[tr].edgelump + self.visitcount[bl];
        let mut count = 0;
        for k in 0..self.in_adj[bl].len() {
            if self.is_loop_dag_in(bl, k) {
                count += 1;
                if count > ignore {
                    return false;
                }
            }
        }
        true
    }

    /// `TraceDAG::openBranch` (blockaction.cc:839): split `parent` into a new BranchPoint at its
    /// destination; returns the active cursor to resume from.
    fn open_branch(&mut self, parent: usize) -> Option<usize> {
        let newbp = self.make_bp_from_trace(parent);
        self.trs[parent].derivedbp = Some(newbp);
        if self.bps[newbp].paths.is_empty() {
            // No new traces: the destination has no loop-DAG out-edges, so `parent` is terminal.
            self.trs[parent].derivedbp = None;
            self.trs[parent].flags |= TR_TERMINAL;
            self.trs[parent].bottom = None;
            self.trs[parent].destnode = None;
            self.trs[parent].edgelump = 0;
            return Some(parent); // parent stays active
        }
        self.remove_active(parent);
        let paths = self.bps[newbp].paths.clone();
        for &p in &paths {
            self.insert_active(p);
        }
        Some(self.bps[newbp].paths[0])
    }

    /// `TraceDAG::checkRetirement` (blockaction.cc:866): a BranchPoint can retire once all sibling
    /// paths (checked from the first sibling) either terminate or flow to the same node. Returns
    /// `Some(exitblock)` (`exitblock` may be `None` when all paths terminated) or `None` if not ready.
    fn check_retirement(&self, tr: usize) -> Option<Option<usize>> {
        if self.trs[tr].pathout != 0 {
            return None; // only check on the first sibling
        }
        let bp = self.trs[tr].top;
        if self.bps[bp].depth == 0 {
            for &p in &self.bps[bp].paths {
                if self.trs[p].flags & TR_ACTIVE == 0 {
                    return None;
                }
                if self.trs[p].flags & TR_TERMINAL == 0 {
                    return None; // all root paths must be terminal
                }
            }
            return Some(None);
        }
        let mut outblock: Option<usize> = None;
        for idx in 0..self.bps[bp].paths.len() {
            let p = self.bps[bp].paths[idx];
            if self.trs[p].flags & TR_ACTIVE == 0 {
                return None;
            }
            if self.trs[p].flags & TR_TERMINAL != 0 {
                continue;
            }
            if outblock == self.trs[p].destnode {
                continue;
            }
            if outblock.is_some() {
                return None;
            }
            outblock = self.trs[p].destnode;
        }
        Some(outblock)
    }

    /// `TraceDAG::retireBranch` (blockaction.cc:900): remove all of `bp`'s child traces from the active
    /// list and re-activate its parent trace as having reached `exitblock`.
    fn retire_branch(&mut self, bp: usize, exitblock: Option<usize>) -> Option<usize> {
        let mut edgeout_bl: Option<usize> = None;
        let mut edgelump_sum = 0;
        let paths = self.bps[bp].paths.clone();
        for &p in &paths {
            if self.trs[p].flags & TR_TERMINAL == 0 {
                edgelump_sum += self.trs[p].edgelump;
                if edgeout_bl.is_none() {
                    edgeout_bl = self.trs[p].bottom;
                }
            }
            self.remove_active(p);
        }
        if self.bps[bp].depth == 0 {
            return self.ahead; // root block: nothing more to do
        }
        if let Some(parent) = self.bps[bp].parent {
            let po = self.bps[bp].pathout as usize;
            let parenttrace = self.bps[parent].paths[po];
            self.trs[parenttrace].derivedbp = None;
            if edgeout_bl.is_none() {
                self.trs[parenttrace].flags |= TR_TERMINAL;
                self.trs[parenttrace].bottom = None;
                self.trs[parenttrace].destnode = None;
                self.trs[parenttrace].edgelump = 0;
            } else {
                self.trs[parenttrace].bottom = edgeout_bl;
                self.trs[parenttrace].destnode = exitblock;
                self.trs[parenttrace].edgelump = edgelump_sum;
            }
            self.insert_active(parenttrace);
            return Some(parenttrace);
        }
        self.ahead
    }

    /// `TraceDAG::initialize` (blockaction.cc:967): create the virtual root BranchPoint and a root
    /// BlockTrace for each entry FlowBlock.
    fn initialize(&mut self) {
        self.bps.push(BpNode { parent: None, pathout: -1, top: None, paths: Vec::new(), depth: 0, ismark: false });
        let rb = self.bps.len() - 1;
        for i in 0..self.rootlist.len() {
            let bl = self.rootlist[i];
            let po = self.bps[rb].paths.len() as i32;
            let tr = self.new_root_trace(rb, po, bl);
            self.bps[rb].paths.push(tr);
            self.insert_active(tr);
        }
    }

    /// `TraceDAG::pushBranches` (blockaction.cc:983): push the traces as far as possible, retiring or
    /// removing edges, until nothing is active.
    fn push_branches(&mut self) {
        let mut cursor = self.ahead;
        let mut missed = 0i32;
        // Ghidra relies on the algorithm's own progress guarantee; a generous cap guards a port bug.
        let cap = 16 + 8 * self.blocks.iter().map(|b| b.out_edges.len() + 1).sum::<usize>();
        let mut steps = 0usize;
        while self.activecount > 0 {
            steps += 1;
            if steps > cap {
                debug_assert!(false, "TraceDAG pushBranches did not converge");
                break;
            }
            if cursor.is_none() {
                cursor = self.ahead;
            }
            let curtrace = cursor.expect("active list non-empty while activecount > 0");
            if missed >= self.activecount {
                let badtrace = self.select_bad_edge();
                self.remove_trace(badtrace);
                cursor = self.ahead;
                missed = 0;
            } else if let Some(exitblock) = self.check_retirement(curtrace) {
                let bp = self.trs[curtrace].top;
                cursor = self.retire_branch(bp, exitblock);
                missed = 0;
            } else if self.check_open(curtrace) {
                cursor = self.open_branch(curtrace);
                missed = 0;
            } else {
                missed += 1;
                cursor = self.trs[curtrace].anext;
            }
        }
    }

    /// Run the trace and return the likely unstructured edges it scored.
    fn run(mut self) -> Vec<FloatingEdge> {
        self.initialize();
        self.push_branches();
        self.likelygoto
    }
}

/// Ghidra's `Funcdata::installSwitchDefaults` (funcdata_block.cc:687), run at the head of
/// `ActionBlockStructure` (blockaction.cc:2176) — after `structureLoops` has (re)cleared the edge
/// labels: mark each jump table's \e default out-edge on its BRANCHIND block with
/// `DEFAULTSWITCH_EDGE` (`FlowBlock::setDefaultSwitch`, block.cc:318). mosura's default-case record
/// is `Funcdata::switch_defaults` (BRANCHIND pc → default target address).
fn install_switch_defaults(s: &mut Structured, f: &Funcdata) {
    if f.switch_defaults.is_empty() {
        return;
    }
    for b in 0..f.num_blocks() {
        let bid = BlockId(b as u32);
        let Some(&last) = f.block(bid).ops.last() else {
            continue;
        };
        if f.op(last).code() != OpCode::Branchind {
            continue;
        }
        let Some(&defaddr) = f.switch_defaults.get(&f.op(last).seqnum.pc.offset) else {
            continue;
        };
        for oi in 0..s.blocks[b].out_edges.len() {
            let t = s.blocks[b].out_edges[oi];
            let FlowKind::Basic(tb) = s.blocks[t].kind else {
                continue;
            };
            if f.block_range(tb).map(|(a, _)| a) == Some(defaddr) {
                s.blocks[b].set_out_edge_flag(oi, edge_flags::DEFAULTSWITCH_EDGE);
                break;
            }
        }
    }
}

/// Structure the CFG of `f`.
pub fn structure(f: &Funcdata) -> Structured {
    let blocks: Vec<FlowBlock> = (0..f.num_blocks())
        .map(|b| {
            let out_edges: Vec<usize> = f.blocks()[b].out_edges.iter().map(|e| e.0 as usize).collect();
            let out_labels = vec![0u32; out_edges.len()];
            // SWITCH_OUT: a block ending in BRANCHIND (BlockBasic::insertOp, block.cc:2287) or
            // with more than two out-edges (newBlockCopy, block.cc:1693).
            let mut flags = 0u32;
            let branchind = f.blocks()[b].ops.last().is_some_and(|&op| f.op(op).code() == OpCode::Branchind);
            if branchind || out_edges.len() > 2 {
                flags |= block_flags::SWITCH_OUT;
            }
            FlowBlock {
                kind: FlowKind::Basic(BlockId(b as u32)),
                components: Vec::new(),
                out_edges,
                out_labels,
                flags,
                active: true,
                negated: false,
                parent: None,
                cond_flip: (false, false),
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
    // Per-block print complexity — Ghidra's `BlockBasic::isComplex` (block.cc:2388): count the
    // ops that print as statements (a conservative `calc_explicit`); more than two (the branch
    // counts as one) makes the block too complex to fold into a condition.
    let complex: Vec<bool> = (0..f.num_blocks())
        .map(|b| {
            let bid = BlockId(b as u32);
            let mut statement = if f.block(bid).out_edges.len() >= 2 { 1 } else { 0 };
            for &op in &f.block(bid).ops {
                let o = f.op(op);
                if o.is_marker() {
                    continue;
                }
                let yes = if matches!(o.code(), OpCode::Call | OpCode::Callind | OpCode::Callother) {
                    true
                } else if let Some(vn) = o.output {
                    let v = f.vn(vn);
                    v.descend.is_empty()
                        || v.is_addrtied()
                        || v.descend.len() > 2 // max_implied_ref (architecture.cc:1420)
                        || v.descend.iter().any(|&r| f.op(r).is_marker() || f.op(r).parent != Some(bid))
                } else {
                    // a no-output op that isn't a flow break is a statement (e.g. STORE)
                    !matches!(o.code(), OpCode::Branch | OpCode::Cbranch | OpCode::Branchind | OpCode::Return)
                };
                if yes {
                    statement += 1;
                }
                if statement > 2 {
                    return true;
                }
            }
            false
        })
        .collect();
    let n = f.num_blocks();
    let mut s = Structured {
        blocks,
        root: 0,
        gotos: HashMap::new(),
        labels: HashSet::new(),
        oriented,
        complex,
        rpo: Vec::new(),
        loopbody: Vec::new(),
        loop_order: Vec::new(),
        order: (0..n).collect(),
        loopiter: 0,
        likelygoto: Vec::new(),
        likelyiter: 0,
        likelylistfull: false,
        finaltrace: false,
        default_goto: HashSet::new(),
    };

    // Label loop back-edges and irreducible edges on the leaf graph before collapsing (Ghidra's
    // structureLoops, run on the CFG at structureReset before ActionBlockStructure's buildCopy).
    structure_loops(&mut s, n);

    // Mark the jump tables' default out-edges (Ghidra's installSwitchDefaults at the head of
    // ActionBlockStructure — after structureLoops cleared the edge labels).
    install_switch_defaults(&mut s, f);

    // Build the loop records (Ghidra's orderLoopBodies): label each loop's exit edges and order
    // the loops by nesting depth, deepest first.
    let (loopbody, loop_order) = order_loop_bodies(&mut s, n);
    s.loopbody = loopbody;
    s.loop_order = loop_order;

    // Collapse everything (Ghidra's CollapseStructure::collapseAll).
    s.collapse_all();

    // The root is the entry block's collapsed form (the single isolated block, when the graph
    // fully collapsed).
    s.root = if n == 0 { 0 } else { s.current_form(0) };

    // Reclassify loop-exit gotos as breaks (Ghidra's ActionFinalStructure → BlockGraph::scopeBreak,
    // blockaction.cc:2193), run over the fully-collapsed tree.
    if n != 0 {
        s.scope_break();
    }
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
    fn short_circuit_swapped_sense_records_fold_flip() {
        // The mirrored `ruleBlockOr` orientation (i=0, j=0): bl(0) out [orblock=1(false), clause=3];
        // orblock(1) out [clause=3(false), cont=2(true)] — the shared clause sits on orblock's
        // *false* edge, so Ghidra negates orblock. mosura never swaps CFG edges, so it folds anyway
        // (a `CondOr`, i==0) and records the orblock-side flip in `cond_flip.1` for the printer.
        let s = structure(&cfg(4, &[(0, 1), (0, 3), (1, 3), (1, 2), (2, 3)]));
        assert_eq!(active(&s), 1);
        let cond = s.blocks.iter().position(|b| matches!(b.kind, FlowKind::CondOr)).expect("CondOr formed");
        assert_eq!(s.blocks[cond].components, vec![0, 1]);
        assert_eq!(s.blocks[cond].cond_flip, (false, true), "orblock (j=0) side flip recorded");
        // Composite out-edges are Ghidra's forced order: false = orblock's continuation, true = clause.
        assert_eq!(s.blocks[cond].out_edges, vec![2, 3]);
    }

    #[test]
    fn irreducible_collapses_with_goto() {
        // 0 -> {1, 2}; 1 -> 2; 2 -> 1  (1 and 2 form an irreducible two-cycle)
        let s = structure(&cfg(3, &[(0, 1), (0, 2), (1, 2), (2, 1)]));
        assert_eq!(active(&s), 1, "collapses fully via gotos");
        assert!(!s.gotos.is_empty(), "recorded a goto edge");
        // The irreducible edge is not a loop-exit break — scopeBreak leaves it a labeled goto.
        assert!(s.gotos.values().all(|v| v.iter().all(|r| !r.is_break)), "irreducible goto stays a goto");
        assert!(!s.labels.is_empty(), "the surviving goto keeps its target label");
    }

    #[test]
    fn loop_break_edge_becomes_conditional_break() {
        // while (c1) { s; if (c2) break; s2 }:
        // 0 -> 1(head c1); 1 -> {2(s), 5(exit)}; 2 -> 3(c2); 3 -> {4(s2), 5(break)}; 4 -> 1(back)
        // The break edge keeps the body multi-block, so the flat rules are stuck; selectGoto
        // picks the loop-exit edge 3->5 (the middle exit — first in the emitLikelyEdges
        // priority) and NEVER the back-edge, so the while loop is recovered with one
        // conditional goto owned by the [2,3] cat composite (Ghidra's BlockIfGoto). scopeBreak
        // (B4b) then reclassifies it as a break because the goto targets the loop exit (5).
        let s = structure(&cfg(6, &[(0, 1), (1, 2), (1, 5), (2, 3), (3, 4), (3, 5), (4, 1)]));
        assert_eq!(active(&s), 1);
        let k = kinds(&s);
        assert!(k.contains(&FlowKind::WhileDo), "loop recovered, not goto-cut: {k:?}");
        let recs = s.gotos.get(&BlockId(3)).expect("break edge cut at the composite's exit basic 3");
        assert_eq!(recs.len(), 1, "records: {recs:?}");
        assert!(recs[0].conditional, "break is an if-goto");
        assert_eq!(recs[0].target, BlockId(5));
        assert!(recs[0].is_break, "loop-exit goto reclassified as break by scopeBreak");
        // a break references no label — block 5 is not a goto target
        assert!(!s.labels.contains(&BlockId(5)), "break needs no label");
        // exactly one goto total — the back-edge survived
        assert_eq!(s.gotos.values().map(|v| v.len()).sum::<usize>(), 1, "gotos: {:?}", s.gotos);
    }

    #[test]
    fn while_condition_break_folds_to_or() {
        // while (c1) { if (c2) break; body }, with the break test heading the body: the exact
        // ruleBlockOr topology (both exits shared), so collapseConditions folds c1/c2 into one
        // compound condition and the loop collapses with NO goto (Ghidra's collapseAll does the
        // same — the guard blocks only a *complex* second condition).
        let s = structure(&cfg(5, &[(0, 1), (1, 2), (1, 4), (2, 3), (2, 4), (3, 1)]));
        assert_eq!(active(&s), 1);
        let k = kinds(&s);
        assert!(k.contains(&FlowKind::WhileDo), "kinds: {k:?}");
        assert!(k.contains(&FlowKind::CondOr) || k.contains(&FlowKind::CondAnd), "kinds: {k:?}");
        assert!(s.gotos.is_empty(), "no goto needed: {:?}", s.gotos);
    }

    #[test]
    fn complex_second_condition_blocks_or_merge() {
        // The or-topology (0 -> {1(false), 2(true)}; 1 -> {3(false), 2(true)}) whose second
        // condition block carries three STOREs: `BlockBasic::isComplex` reports it too complex
        // to print inside a condition, so ruleBlockOr must NOT fold it (blockaction.cc:1342).
        use crate::decompile::op::SeqNum;
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let spc = f.new_const(8, 0);
        let addr = f.new_input(8, Address::new(reg, 0x10));
        let val = f.new_input(4, Address::new(reg, 0x20));
        let stores: Vec<_> =
            (0..3).map(|_| f.new_op(OpCode::Store, seq, vec![spc, addr, val])).collect();
        let mut blocks: Vec<BlockBasic> = vec![BlockBasic::default(); 4];
        blocks[1].ops = stores;
        for &(a, b) in &[(0usize, 1usize), (0, 2), (1, 3), (1, 2), (2, 3)] {
            blocks[a].out_edges.push(BlockId(b as u32));
            blocks[b].in_edges.push(BlockId(a as u32));
        }
        f.set_blocks(blocks);
        let s = structure(&f);
        // No short-circuit composite may exist anywhere in the collapse history: the or-fold was
        // refused, so this non-structurable DAG resolved through a goto scored by the final-DAG
        // TraceDAG trace, instead of swallowing the statements into a condition.
        assert!(
            !s.blocks.iter().any(|b| matches!(b.kind, FlowKind::CondOr | FlowKind::CondAnd)),
            "complex condition must not fold"
        );
        assert_eq!(active(&s), 1, "still collapses fully (via gotos)");
        assert!(!s.gotos.is_empty());
    }

    #[test]
    fn no_exit_self_loop_becomes_inf_loop() {
        // 0 -> 1; 1 -> 1 (single-out self edge: a loop with no exit)
        let s = structure(&cfg(2, &[(0, 1), (1, 1)]));
        assert_eq!(active(&s), 1);
        assert!(kinds(&s).contains(&FlowKind::InfLoop), "kinds: {:?}", kinds(&s));
        assert!(s.gotos.is_empty());
    }

    #[test]
    fn case_fallthru_marks_goto_and_switch_collapses() {
        // switch head 0 (3 outs -> SWITCH_OUT) with case 1 falling through into case 2;
        // cases 2 and 3 exit to 4. ruleCaseFallthru marks 1->2 as a goto so the switch
        // can collapse with 4 as its exit.
        let s = structure(&cfg(5, &[(0, 1), (0, 2), (0, 3), (1, 2), (2, 4), (3, 4)]));
        assert_eq!(active(&s), 1);
        assert!(kinds(&s).contains(&FlowKind::Switch), "kinds: {:?}", kinds(&s));
        let recs = s.gotos.get(&BlockId(1)).expect("fallthru edge cut at case 1");
        assert!(!recs[0].conditional, "fallthru goto is unconditional");
        assert_eq!(recs[0].target, BlockId(2));
        assert!(s.labels.contains(&BlockId(2)));
    }

    #[test]
    fn tangled_graph_converges() {
        // an irreducible two-cycle with separate exits — multiple selectGoto rounds needed
        let s = structure(&cfg(4, &[(0, 1), (0, 2), (1, 2), (2, 1), (1, 3), (2, 3)]));
        assert_eq!(active(&s), 1, "collapse terminates and fully collapses");
        assert!(!s.gotos.is_empty());
    }

    #[test]
    fn self_loop_becomes_do_while() {
        // 0 -> 1; 1 -> {1(self), 2(exit)}
        let s = structure(&cfg(3, &[(0, 1), (1, 1), (1, 2)]));
        assert_eq!(active(&s), 1);
        assert!(kinds(&s).contains(&FlowKind::DoWhile));
    }

    /// A bare leaf-only `Structured` (all edges unlabeled = loop-DAG) with identity reverse-post-order,
    /// for testing the `TraceDAG` port directly.
    fn bare(nb: usize, edges: &[(usize, usize)]) -> Structured {
        let mut blocks: Vec<FlowBlock> = (0..nb)
            .map(|b| FlowBlock {
                kind: FlowKind::Basic(BlockId(b as u32)),
                components: Vec::new(),
                out_edges: Vec::new(),
                out_labels: Vec::new(),
                flags: 0,
                active: true,
                negated: false,
                parent: None,
                cond_flip: (false, false),
            })
            .collect();
        for &(a, b) in edges {
            blocks[a].out_edges.push(b);
            blocks[a].out_labels.push(0);
        }
        Structured {
            blocks,
            root: 0,
            gotos: HashMap::new(),
            labels: HashSet::new(),
            oriented: vec![false; nb],
            complex: vec![false; nb],
            rpo: (0..nb as i32).collect(),
            loopbody: Vec::new(),
            loop_order: Vec::new(),
            order: (0..nb).collect(),
            loopiter: 0,
            likelygoto: Vec::new(),
            likelyiter: 0,
            likelylistfull: false,
            finaltrace: false,
            default_goto: HashSet::new(),
        }
    }

    #[test]
    fn trace_dag_clean_diamond_needs_no_goto() {
        // 0 -> {1, 2} -> 3: a clean reducible DAG. Both branch paths merge at 3, the BranchPoint
        // retires, and the trace finishes with no unstructured edge.
        let s = bare(4, &[(0, 1), (0, 2), (1, 3), (2, 3)]);
        let gotos = s.run_trace_dag(&[0], None);
        assert!(gotos.is_empty(), "clean DAG scores no goto: {gotos:?}");
    }

    #[test]
    fn trace_dag_forward_jump_needs_one_goto() {
        // 0 -> {1, 2}; 1 -> {3, 2}; 2 -> 3. Node 2 has two loop-DAG in-edges (from 0 and from 1)
        // at different branch depths, so the trace cannot open it from either path alone and gets
        // stuck; selectBadEdge scores exactly one edge as the unstructured goto.
        let s = bare(4, &[(0, 1), (0, 2), (1, 3), (1, 2), (2, 3)]);
        let gotos = s.run_trace_dag(&[0], None);
        assert_eq!(gotos.len(), 1, "one non-DAG edge scored: {gotos:?}");
        // The scored edge is a real out-edge of its source in the graph.
        let e = gotos[0];
        assert!(s.blocks[e.top].out_edges.contains(&e.bottom), "scored edge exists: {e:?}");
    }

    #[test]
    fn trace_dag_loop_interior_clean_scores_no_goto() {
        // A while-loop interior with a nested if: head 0 -> {1, exit 4}; body 1 -> {2, 3}; 2 -> 3;
        // 3 -> 0 (back). Tracing from the head to the loop bottom (3), with the exit edge 0->4
        // marked, the interior is a clean DAG so no interior goto is scored — the loop is fully
        // reducible (mirrors the corpus loops, which stay byte-identical).
        let mut s = bare(5, &[(0, 1), (0, 4), (1, 2), (1, 3), (2, 3), (3, 0)]);
        // Mark the exit edge (0 -> 4) LOOP_EXIT and the back-edge (3 -> 0) BACK, as structureLoops +
        // setExitMarks would, so isLoopDAGOut excludes them.
        s.blocks[0].out_labels[1] = edge_flags::LOOP_EXIT_EDGE; // 0 -> 4
        s.blocks[3].out_labels[0] = edge_flags::BACK_EDGE | edge_flags::LOOP_EDGE; // 3 -> 0
        let gotos = s.run_trace_dag(&[0], Some(3));
        assert!(gotos.is_empty(), "clean loop interior scores no goto: {gotos:?}");
    }
}
