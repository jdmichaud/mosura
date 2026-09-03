//! `sparse-switch` — Watcom's balanced compare tree (JB/JBE pivots, JE leaves, range-pruned
//! singletons) prints as the `switch` it was compiled from, with the byte WITNESS the IR cannot
//! carry: the CMP immediates and jump kinds at every flag-consuming site (docs/sparse-switch-arm.md,
//! W5; the witness is `recovered.sparse_cmp_sites`, from `buildconfig::sparse_cmps_from_evidence`).
//! A target-informed emit choice, NOT Ghidra: the reference decompiler prints the if-chain, and
//! Ghidra canonicalizes `x < 4` on the fall-through edge to `3 < x`, so the IR's constants cannot
//! tell a pivot's JB side from a run's JBE bound — the bytes can.
//!
//! Moved verbatim out of printc.rs (review R2, commit 3): the range algebra (`Ranges`), the walk's
//! keys and leaves (`SparseKey`, `SparseLeaf`, `SparseBody`), the entry (`try_emit_sparse_switch`)
//! and the `sparse_*` walk. The textual changes are the free-function form only (`self.` → `p.`,
//! sibling calls `f(pr, ..)`, `&Self` → `&PrintC<'_>`); the receiver is `pr` because the walk
//! has locals named `p` (pivots).
//!
//! The arm answers ONE seam, `Site::IfEntry` — the head of an if that is not an `else if` — under
//! the `sparse-switch` choice gate, which lives here. What it consumes it records in the port's
//! `sparse_consumed` set of structured nodes: a PRINTER SERVICE for the arms (like `suppressed`
//! for ops), which the port's root loop and component walk consult — a root or component the
//! switch already printed emits nothing. That is a service, not a site: the `Node` kind belongs to
//! string-ops' suppression and one arm declares each kind.
use std::fmt::Write as _;

use crate::decompile::block::BlockId;
use crate::decompile::emit::arms::{Answer, Arm, Site, SiteKind};
use crate::decompile::op::OpId;
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::{collect_basics, entry_basic, exit_basic, operand_oriented, render_const_typed, strip_copies, PrintC};
use crate::decompile::structure::{FlowKind, Structured};
use crate::decompile::varnode::VarnodeId;

/// The arm, as the [`super::ARMS`] table holds it.
pub const ARM: Arm = Arm {
    name: "sparse-switch: Watcom's compare tree as the switch it came from (docs/sparse-switch-arm.md)",
    kinds: &[SiteKind::IfEntry],
    try_emit,
};

fn try_emit(pr: &mut PrintC<'_>, site: Site<'_>, out: &mut String) -> Option<Answer> {
    let Site::IfEntry { s, idx, indent } = site else { return None };
    (pr.arms.sparse_switch.switch && (try_emit_sparse_switch(pr, s, idx, indent, out) || try_emit_narrow_switch(pr, s, idx, indent, out)))
        .then_some(Answer::Emitted)
}

/// A set of closed integer ranges — the values a path through the compare tree admits.
#[derive(Clone, Debug, PartialEq)]
struct Ranges(Vec<(i64, i64)>);

impl Ranges {
    fn intersect(&self, o: &Ranges) -> Ranges {
        let mut v = Vec::new();
        for &(a, b) in &self.0 {
            for &(c, d) in &o.0 {
                let (lo, hi) = (a.max(c), b.min(d));
                if lo <= hi {
                    v.push((lo, hi));
                }
            }
        }
        Ranges(v)
    }
    fn complement(&self, lo: i64, hi: i64) -> Ranges {
        let mut sorted = self.0.clone();
        sorted.sort();
        let mut v = Vec::new();
        let mut cur = lo;
        for &(a, b) in &sorted {
            if a > cur {
                v.push((cur, a - 1));
            }
            cur = cur.max(b + 1);
        }
        if cur <= hi {
            v.push((cur, hi));
        }
        Ranges(v)
    }
    fn union(&self, o: &Ranges) -> Ranges {
        let mut v = self.0.clone();
        v.extend(o.0.iter().copied());
        Ranges(v)
    }
    fn count(&self) -> i64 {
        self.0.iter().map(|&(a, b)| b - a + 1).sum()
    }
    fn is_empty(&self) -> bool {
        self.0.iter().all(|&(a, b)| a > b)
    }
    fn values(&self) -> Vec<i64> {
        let mut v: Vec<i64> = self.0.iter().flat_map(|&(a, b)| a..=b).collect();
        v.sort();
        v.dedup();
        v
    }
}

/// How the tree's compares name their scrutinee: one HighVariable, or — when Watcom re-loads it
/// before every compare — the load of `base + off` (base by HighVariable), or a PIECE of two.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SparseKey {
    High(u32),
    Load(u32, i64, u32),
    Piece(u32, u32),
}

/// One leaf of the compare tree: the structured node its path lands on and the values reaching it.
struct SparseLeaf {
    node: usize,
    vals: Ranges,
    /// the shared continuation (list components after the IfElse this leaf sits under), if any
    join: Option<Vec<usize>>,
    /// an unstructured jump to this block: a tree edge the collapse cut to a `goto`
    goto: Option<BlockId>,
    /// the unconditional `goto` an enclosing if/list takes after this leaf's body (Ghidra's
    /// BlockGoto follows the wrapped node's ENTIRE body, so a leaf cut out of it still ends there)
    exit_goto: Option<BlockId>,
}

/// The kind of a recorded tree compare, in the orientation `x OP k`: Watcom's `JB k` (a pivot's
/// left side or a run's lower guard), `JBE k` / `JA k` (a run's upper bound), `JE k`.
const CMP_LT: u8 = 0;
const CMP_LE: u8 = 1;
const CMP_EQ: u8 = 2;

/// What a case prints: nothing (`break;`), a structured node, or a `goto` out of the tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum SparseBody {
    Empty,
    Node(usize),
    Goto(BlockId),
}

/// `sparse-switch=switch` (docs/wc2src-reconciliation-4.md W5): the structured if/else tree rooted
/// at `idx` whose every condition compares ONE scrutinee against constants is Watcom's compare
/// tree for a sparse `switch`; print the `switch`. Bails (returns false) on any other shape.
fn try_emit_sparse_switch(pr: &mut PrintC<'_>, s: &Structured, idx: usize, indent: usize, out: &mut String) -> bool {
    // the root's condition: a plain compare block, or a List-condition whose last component is
    // the compare — its leading components are tree nodes (0x14ac8's `if (u < 2) {..}` folded
    // ahead of the `u <= 2` test) or pure statements the printer hoists above the switch
    let cond_node = s.blocks[idx].components[0];
    let root_cond = match s.blocks[cond_node].kind {
        FlowKind::List => s.blocks[cond_node].components.last().and_then(|&c| sparse_cbranch_cond(pr, s, c)),
        _ => pr.plain_if_condition_vn(s, idx),
    };
    let Some(root_cond) = root_cond else { return false };
    let Some((scrut, _, _, _)) = sparse_compare(pr, root_cond) else { return false };
    let scrut_high = sparse_key(pr, scrut);
    debug!(crate::debug::Topic::SparseSwitch, "{:#x} enter root node {idx} key {scrut_high:?} negated {} kind {:?} parent {:?}", pr.f.addr.offset, s.blocks[idx].negated, s.blocks[idx].kind, s.blocks[idx].parent.map(|p| (p, format!("{:?}", s.blocks[p].kind), s.blocks[p].components.clone())));
    pr.arms.sparse_switch.hoist_pending.borrow_mut().clear();
    pr.arms.sparse_switch.exit_goto.borrow_mut().clear();
    pr.arms.sparse_switch.head_stmts.borrow_mut().clear();
    pr.arms.sparse_switch.root.set(idx);
    // root only: a parent that is itself a compare on the same scrutinee owns the tree
    if let Some(parent) = s.blocks[idx].parent {
        let mut anc = Some(parent);
        while let Some(a) = anc {
            if matches!(s.blocks[a].kind, FlowKind::If | FlowKind::IfElse) {
                if let Some(pc) = pr.plain_if_condition_vn(s, a) {
                    if sparse_compare(pr, pc).is_some_and(|(x, _, _, _)| sparse_key(pr, x) == scrut_high) {
                        return false;
                    }
                }
                break;
            }
            if !matches!(s.blocks[a].kind, FlowKind::List) {
                break;
            }
            anc = s.blocks[a].parent;
        }
    }
    // siblings in the enclosing List: an earlier one that compares the scrutinee owns the tree
    // (this node is its continuation: `if (u < 3) break;` above 0x1201c's `== 4`); a later one
    // continues THIS tree (0x14ac8: `if (u < 2) {..}` then `if (u <= 2) .. else ..`) — walk the
    // list from here, up to (not including) a closing bare `return`
    let mut list_from: Option<(Option<usize>, usize, usize)> = None;
    let siblings = |parent: Option<usize>| -> Vec<usize> { parent.map(|p| s.blocks[p].components.clone()).unwrap_or_else(|| s.roots.clone()) };
    {
        let parent = s.blocks[idx].parent;
        // a node in the CONDITION list of an enclosing if is that if's tree, never a root
        if let Some(p) = parent {
            if s.blocks[p].parent.is_some_and(|pp| matches!(s.blocks[pp].kind, FlowKind::If | FlowKind::IfElse) && s.blocks[pp].components.first() == Some(&p)) {
                debug!(crate::debug::Topic::SparseSwitch, "  not a root: inside the condition list of node {:?}", s.blocks[p].parent);
                return false;
            }
        }
        if parent.is_none_or(|p| matches!(s.blocks[p].kind, FlowKind::List)) {
            let comps = siblings(parent);
            let pos = comps.iter().position(|&c| c == idx).unwrap_or(0);
            let compares_scrut = |me: &PrintC<'_>, c: usize| -> bool {
                let cond = match s.blocks[c].kind {
                    FlowKind::If | FlowKind::IfElse => me.plain_if_condition_vn(s, c),
                    FlowKind::Basic(_) => sparse_cond_goto(me, s, c, true).and_then(|_| sparse_cbranch_cond(me, s, c)),
                    _ => None,
                };
                cond.and_then(|v| sparse_compare(me, v)).is_some_and(|(x, _, _, _)| sparse_key(me, x) == scrut_high)
            };
            debug!(crate::debug::Topic::SparseSwitch, "  siblings of node {idx} (parent {parent:?}, pos {pos}): {:?}", comps.iter().map(|&c| (c, format!("{:?}", s.blocks[c].kind), compares_scrut(pr, c))).collect::<Vec<_>>());
            if comps[..pos].iter().any(|&c| compares_scrut(pr, c)) {
                debug!(crate::debug::Topic::SparseSwitch, "  not a root: an earlier sibling compares the scrutinee");
                return false;
            }
            if matches!(s.blocks[idx].kind, FlowKind::If) && comps.get(pos + 1).is_some_and(|&c| compares_scrut(pr, c)) {
                let mut end = comps.len();
                if end > pos + 2 && sparse_is_bare_return(pr, s, comps[end - 1]) {
                    end -= 1;
                }
                list_from = Some((parent, pos, end));
            }
        }
    }
    let size = pr.f.vn(scrut).size as i64;
    let signed = sparse_signed(pr, root_cond);
    let (lo, hi) = if size >= 8 {
        (i64::MIN / 2, i64::MAX / 2)
    } else if signed {
        (-(1i64 << (8 * size - 1)), (1i64 << (8 * size - 1)) - 1)
    } else {
        (0, (1i64 << (8 * size)) - 1)
    };
    // the post-switch flow: a leaf that IS that block (or only jumps to it) is the switch's tail
    let tail = match list_from {
        Some((parent, _, end)) => {
            let comps = siblings(parent);
            if end < comps.len() { entry_basic(s, comps[end]) } else { pr.next_flow_after(s, comps[end - 1]) }
        }
        None => pr.next_flow_after(s, idx),
    };
    pr.arms.sparse_switch.cond_override_pending.borrow_mut().clear();
    pr.arms.sparse_switch.tail.set(tail);
    let mut leaves: Vec<SparseLeaf> = Vec::new();
    let mut compares: Vec<OpId> = Vec::new();
    let mut consts: Vec<(u64, i64, u8)> = Vec::new();
    let mut depth = 0usize;
    // the enclosing loop's condition narrows the body's reach: 0x1201c's `while (!(u < 3))`
    // holds the tree's `JB 3` guard, so the body only ever sees u >= 3
    let mut reach = Ranges(vec![(lo, hi)]);
    if let Some(p) = s.blocks[idx].parent {
        if matches!(s.blocks[p].kind, FlowKind::WhileDo) && s.blocks[p].components.get(1) == Some(&idx) {
            let cn = s.blocks[p].components[0];
            let cond_vn = match s.blocks[cn].kind {
                FlowKind::List => s.blocks[cn].components.last().and_then(|&c| sparse_cbranch_cond(pr, s, c)),
                FlowKind::Basic(_) => sparse_cbranch_cond(pr, s, cn),
                _ => None,
            };
            if let Some(cv) = cond_vn {
                let mut scratch: Vec<OpId> = Vec::new();
                if let Some(t) = sparse_true_ranges(pr, cv, scrut_high, lo, hi, &mut scratch, &mut consts) {
                    // `while (C)` runs the body while the rendered condition holds; the
                    // overflow form `if (C) break;` while it does not
                    let rendered = if s.blocks[p].negated { t.complement(lo, hi) } else { t };
                    reach = if s.blocks[p].has_overflow_syntax() { rendered.complement(lo, hi) } else { rendered };
                    debug!(crate::debug::Topic::SparseSwitch, "  loop condition narrows the root's reach to {:?}", reach.0);
                    // the loop owns part of the tree (its exit is one of the cases): the switch
                    // the body alone can print recompiles worse than the if-chain (0x1201c,
                    // -0.146 on the w5a round) — decline
                    return false;
                }
            }
        }
    }
    let walked = match list_from {
        Some((parent, pos, end)) => {
            let comps: Vec<usize> = siblings(parent)[pos..end].to_vec();
            sparse_walk_list(pr, s, &comps, None, scrut_high, signed, reach.clone(), lo, hi, &mut leaves, &mut compares, &mut consts, 0, &mut depth, None)
        }
        None => sparse_walk(pr, s, idx, scrut_high, signed, reach.clone(), lo, hi, &mut leaves, &mut compares, &mut consts, 0, &mut depth, None),
    };
    if !walked {
        return false;
    }
    let dbg = crate::debug::on(crate::debug::Topic::SparseSwitch);
    // a compared value is a case when compared for equality, or as a pivot (two compares of
    // the same constant at one pc: `CMP p; JB; JBE`)
    // (Ghidra attributes the JB's and the JBE's compares to their own jump pcs, so the pivot
    // signature is the constant compared twice, not twice at one pc.)
    // an equality the IR folded away but the bytes still hold: Ghidra rewrites `!(x <= 0xfe)`
    // on a byte to `x == 0xff` and drops the now-redundant `CMP AL,0xff; JE` (0x2d7fc), so
    // that case survives only as a witness entry right after a tree compare (within one
    // jump + one CMP of it) at a pc no tree compare claims
    let folded_eq = |v: i64| -> bool {
        pr.recovered.sparse_cmp_sites.iter().any(|(&pc, &(imm, kind, reg))| {
            kind == CMP_EQ
                && (imm as i64) == v
                && !consts.iter().any(|&(cp, _, _)| cp == pc)
                && consts.iter().any(|&(cp, _, _)| pc > cp && pc - cp <= 12 && pr.recovered.sparse_cmp_sites.get(&cp).is_some_and(|w| w.2 == reg))
        })
    };
    let cased_const = |v: i64| -> bool {
        consts.iter().any(|&(_, k, kind)| k == v && kind == CMP_EQ) || consts.iter().filter(|&&(_, k, _)| k == v).count() >= 2 || folded_eq(v)
    };
    // a run [a, b] is delimited by its own compares: `JB a` below (or the domain's floor),
    // `JBE b` / `JA b` above (or the ceiling) — a pivot's `JB p` side ([.., p-1]) is not a run,
    // and neither is an interval a `JB k` cuts inside (0x2d7fc's `CMP AL,1; JB exit; JBE exit`:
    // 0 is below the range, 1 the pivot's empty case)
    let run_bounded = |r: &Ranges| -> bool {
        r.0.iter().all(|&(a, b)| {
            (a == lo || consts.iter().any(|&(_, k, kind)| k == a && kind == CMP_LT))
                && (b == hi || consts.iter().any(|&(_, k, kind)| k == b && kind == CMP_LE))
                && !consts.iter().any(|&(_, k, kind)| kind == CMP_LT && k > a && k <= b)
        })
    };
    if dbg {
        debug!(crate::debug::Topic::SparseSwitch, "{:#x} root node {idx}: scrut key {scrut_high:?} depth {depth} consts {consts:?} tail {tail:?}", pr.f.addr.offset);
        for l in &leaves {
            debug!(crate::debug::Topic::SparseSwitch, "  leaf node {} kind {:?} vals {:?}", l.node, s.blocks[l.node].kind, l.vals.0);
        }
    }
    if depth < 2 || leaves.len() < 3 {
        debug!(crate::debug::Topic::SparseSwitch, "  bail: depth {depth} leaves {}", leaves.len());
        return false;
    }
    // classify the leaves: a leaf whose values are few is a case (an empty one when it lands on
    // the tail); one with many values must be the default and land on the tail (or return)
    let is_tail = |me: &PrintC<'_>, node: usize| -> bool {
        match s.blocks[node].kind {
            FlowKind::Basic(b) => Some(b) == tail || sparse_goto_only(me, s, node).is_some_and(|t| Some(t) == tail),
            _ => false,
        }
    };
    // the tail itself may be the function's final `return;`: a bare-return leaf is then the
    // same exit, not a second default body
    let tail_is_return = tail
        .and_then(|tb| s.blocks.iter().position(|fb| fb.kind == FlowKind::Basic(tb)))
        .is_some_and(|tn| sparse_is_bare_return(pr, s, tn));
    let mut cases: Vec<(Vec<i64>, SparseBody, Option<Vec<usize>>, Option<BlockId>)> = Vec::new(); // (labels, body, join, exit goto)
    let mut default_body: Option<SparseBody> = None;
    let mut body_of: std::collections::HashMap<SparseBody, usize> = std::collections::HashMap::new(); // body → cases index
    // what a leaf prints: nothing when it lands on the tail; the leaf that OWNS a jumped-to
    // block when there is one (the target is inside the tree); else the `goto` itself
    let leaf_body = |me: &PrintC<'_>, leaf: &SparseLeaf, goto_target: Option<BlockId>| -> SparseBody {
        if is_tail(me, leaf.node) || goto_target.is_some_and(|t| Some(t) == tail) || (tail_is_return && sparse_is_bare_return(me, s, leaf.node)) {
            SparseBody::Empty
        } else if let Some(t) = goto_target {
            match leaves.iter().find(|l| l.goto.is_none() && sparse_goto_only(me, s, l.node).is_none() && (matches!(s.blocks[l.node].kind, FlowKind::Basic(b) if b == t) || entry_basic(s, l.node) == Some(t))) {
                Some(owner) => SparseBody::Node(owner.node),
                None => SparseBody::Goto(t),
            }
        } else {
            SparseBody::Node(leaf.node)
        }
    };
    for leaf in &leaves {
        if leaf.vals.is_empty() {
            continue;
        }
        let goto_target = leaf.goto.or_else(|| sparse_goto_only(pr, s, leaf.node));
        let tail_like = is_tail(pr, leaf.node) || sparse_is_bare_return(pr, s, leaf.node) || goto_target.is_some_and(|t| Some(t) == tail);
        let single = leaf.vals.count() == 1;
        // Watcom's tree ends every case value at its own body; a leaf with several values is
        // the remainder — the default — and must be the tail or a bare return. A singleton that
        // lands on the tail is an explicit EMPTY case only when its value was compared (0xd:
        // `JBE` past the switch after `CMP AL,0xd`); a never-compared singleton (0xe between the
        // 0xd and 0xf compares) is default territory.
        // a tail-like leaf with several values: its COMPARED values are explicit empty cases
        // (0xd), the never-compared remainder (0xe) is the default
        if tail_like && !single {
            // a small run delimited by its own compares that lands on the tail is a run of
            // EMPTY cases (`CMP AX,1; JBE exit` under a pivot = `case 0: case 1: break;`)
            if run_bounded(&leaf.vals) && leaf.vals.count() <= 16 {
                cases.push((leaf.vals.values(), SparseBody::Empty, None, None));
                continue;
            }
            // never enumerate a wide leaf (a 4-byte scrutinee's default spans billions): the
            // compared values inside it are the candidates, the rest is the default
            let contains = |v: i64| leaf.vals.0.iter().any(|&(a, b)| a <= v && v <= b);
            let mut cased: Vec<i64> = consts.iter().map(|&(_, k, _)| k).filter(|&k| contains(k) && cased_const(k)).collect();
            cased.sort();
            cased.dedup();
            let rest_nonempty = leaf.vals.count() > cased.len() as i64;
            if !cased.is_empty() {
                cases.push((cased, SparseBody::Empty, None, None));
            }
            if rest_nonempty {
                let body = leaf_body(pr, leaf, goto_target);
                match default_body {
                    None => default_body = Some(body),
                    Some(existing) if existing == body => {}
                    Some(existing) => { debug!(crate::debug::Topic::SparseSwitch, "  bail: two defaults: {existing:?} vs {body:?} (leaf node {})", leaf.node); return false; }
                }
            }
            continue;
        }
        // a multi-valued leaf WITH a body: Watcom merges consecutive cases that share a body into
        // range leaves (`CMP AL,1; JB default; CMP AL,6; JBE body` = `case 1: … case 6:`), so a
        // small one is a run of labels; a wide one is the default with a real body
        if !single && !tail_like {
            // a merged range leaf is delimited by its own compares (`CMP AL,1; JB; CMP AL,6; JBE`;
            // `CMP AX,1; JBE` alone at the domain's floor) — a pivot's `JB` side (`< 4` = [0,3])
            // is not a run, its values are the subtree's or the default's
            if leaf.vals.count() <= 16 && run_bounded(&leaf.vals) {
                let vals = leaf.vals.values();
                let key = leaf_body(pr, leaf, goto_target);
                if let Some(&ci) = body_of.get(&key) {
                    cases[ci].0.extend(vals);
                } else {
                    body_of.insert(key, cases.len());
                    cases.push((vals, key, leaf.join.clone(), leaf.exit_goto));
                }
                continue;
            }
            let body = leaf_body(pr, leaf, goto_target);
            match default_body {
                None => default_body = Some(body),
                Some(existing) if existing == body => {}
                Some(existing) => { debug!(crate::debug::Topic::SparseSwitch, "  bail: two defaults: {existing:?} vs {body:?} (wide body leaf node {})", leaf.node); return false; }
            }
            continue;
        }
        if !single || (tail_like && !cased_const(leaf.vals.values()[0])) {
            if !tail_like {
                if dbg {
                    let ops: Vec<String> = match s.blocks[leaf.node].kind { FlowKind::Basic(b) => pr.f.block(b).ops.iter().filter(|&&op| !pr.f.op(op).is_dead()).map(|&op| format!("{:?}{}", pr.f.op(op).code(), if pr.f.op(op).is_marker() { "*" } else { "" })).collect(), _ => vec![] };
                    debug!(crate::debug::Topic::SparseSwitch, "  bail: multi-valued non-tail leaf node {} vals {:?} ops {:?} gotos {:?}", leaf.node, leaf.vals.0, ops, s.node_gotos.get(&leaf.node).map(|r| r.len()));
                }
                return false;
            }
            let body = leaf_body(pr, leaf, goto_target);
            match default_body {
                None => default_body = Some(body),
                Some(existing) if existing == body => {}
                Some(existing) => { debug!(crate::debug::Topic::SparseSwitch, "  bail: two defaults: {existing:?} vs {body:?} (leaf node {})", leaf.node); return false; }
            }
            continue;
        }
        let vals = leaf.vals.values();
        if tail_like {
            cases.push((vals, SparseBody::Empty, None, None));
            continue;
        }
        let key = leaf_body(pr, leaf, goto_target);
        if let Some(&ci) = body_of.get(&key) {
            cases[ci].0.extend(vals);
        } else {
            body_of.insert(key, cases.len());
            cases.push((vals, key, leaf.join.clone(), leaf.exit_goto));
        }
    }
    // a leaf that jumps where the default jumps (`CMP 1; JNE default` leaving 0 on the default's
    // edge) is the default unless its value was compared by itself
    let mut with_default: Vec<i64> = Vec::new();
    let mut default_join: Option<Vec<usize>> = None;
    if let Some(db) = default_body {
        if db != SparseBody::Empty {
            // every leaf that lands on the default's own body folds into it — its structural
            // continuation (what follows the shared body: 0x4fbcc's `LAB_0004fc8a: uVar1 =
            // uVar1 + 1`) prints after the body; an explicitly compared value among them keeps
            // its label in the default's group (`case 0: default:`), never a second copy
            for c in cases.iter().filter(|c| c.1 == db) {
                if default_join.is_none() {
                    default_join = c.2.clone();
                }
                if c.0.iter().any(|&v| cased_const(v)) {
                    with_default.extend(c.0.iter().copied());
                }
            }
            cases.retain(|c| c.1 != db);
        }
    }
    let total: usize = cases.iter().map(|c| c.0.len()).sum::<usize>() + with_default.len();
    debug!(crate::debug::Topic::SparseSwitch, "  cases {:?} default {:?}", cases.iter().map(|c| (c.0.clone(), c.1, c.2.clone())).collect::<Vec<_>>(), default_body);
    // a pivot (one constant compared twice, at least once by range) is Watcom's tree signature:
    // with it two cases are a switch (0x122b0's `CMP AX,8; JB; JBE; CMP AX,9`); without it a
    // plain equality chain is not
    // Watcom's tree signature is a pivot (one constant compared by range and by equality/range
    // at one CMP: `CMP p; JB; JBE`), which it emits even for two or three cases (0x122b0's outer
    // {8, 9}, its inner {0, 1, 2}); a chain of plain equalities is the if-chain the source
    // wrote (0x12360, EXACT as `if (p == 3) .. else if (p == 0) .. else if (p == 2)`)
    let has_pivot = consts.iter().any(|&(_, k, kind)| kind != CMP_EQ && consts.iter().filter(|&&(_, k2, _)| k2 == k).count() >= 2);
    if total < 2 || !has_pivot {
        debug!(crate::debug::Topic::SparseSwitch, "  bail: total cases {total} (pivot {has_pivot})");
        return false;
    }
    for (n, c) in pr.arms.sparse_switch.cond_override_pending.borrow_mut().drain(..) {
        pr.sparse_cond_override.insert(n, c);
    }
    if let Some((parent, pos, end)) = list_from {
        pr.sparse_consumed.extend(siblings(parent)[pos + 1..end].iter().copied());
    }
    // bodies in address order (Watcom lays bodies out in source order); empty cases first
    let mut order: Vec<usize> = (0..cases.len()).collect();
    let pc_of = |me: &PrintC<'_>, ci: usize| -> u64 { match cases[ci].1 { SparseBody::Node(n) => me.first_pc(s, n).unwrap_or(0), _ => 0 } };
    order.sort_by_key(|&ci| (matches!(cases[ci].1, SparseBody::Node(_)), pc_of(pr, ci)));
    // join groups: the address-last member carries the shared continuation, the others jump to it
    let join_last: std::collections::HashMap<usize, bool> = {
        let mut m = std::collections::HashMap::new();
        for &ci in &order {
            if let Some(j) = &cases[ci].2 {
                let last = order.iter().copied().filter(|&o| cases[o].2.as_ref() == Some(j)).max_by_key(|&o| pc_of(pr, o)).unwrap();
                m.insert(ci, last == ci);
            }
        }
        m
    };
    // the scrutinee: inline its defining load when the compares are its only uses
    let scrut_def = pr.f.vn(scrut).def;
    let (inline, suppress) = match scrut_high {
        SparseKey::High(h) => {
            let members: Vec<VarnodeId> = pr.high_members.get(&h).cloned().unwrap_or_else(|| vec![scrut]);
            let ok = scrut_def.is_some_and(|d| {
                matches!(pr.f.op(d).code(), OpCode::Load | OpCode::Copy | OpCode::IntZext)
                    && members.iter().all(|&m| pr.f.vn(m).descend.iter().all(|u| compares.contains(u) || pr.f.op(*u).is_dead()))
            });
            (ok, ok)
        }
        // re-loaded / pieced before every compare: the switch operand is the expression itself
        _ => (true, false),
    };
    if suppress {
        if let Some(d) = scrut_def {
            pr.suppressed.insert(d);
        }
    }
    // a COPY of the (re-loaded) scrutinee into a variable read only by the tree's compares is
    // dead once the switch operand is the expression (0x122b0: `uVar1 = param_2[1];`)
    let mut copy_srcs: Vec<VarnodeId> = vec![scrut];
    for &op in &compares {
        for i in 0..2 {
            if let Some(v) = pr.f.op(op).input(i) {
                if let Some(d) = pr.f.vn(v).def {
                    if pr.f.op(d).code() == OpCode::Copy {
                        if let Some(src) = pr.f.op(d).input(0) {
                            if !copy_srcs.contains(&src) {
                                copy_srcs.push(src);
                            }
                        }
                    }
                }
            }
        }
    }
    let copy_uses: Vec<OpId> = copy_srcs.iter().flat_map(|&src| pr.f.vn(src).descend.clone()).collect();
    for u in copy_uses {
        let uo = pr.f.op(u);
        if uo.code() == OpCode::Copy && !uo.is_dead() {
            if let Some(out) = uo.output {
                let members: Vec<VarnodeId> = pr.high_members.get(&pr.high_of[out.0 as usize]).cloned().unwrap_or_else(|| vec![out]);
                let tree_only = pr.f.vn(out).descend.iter().all(|r| compares.contains(r) || pr.f.op(*r).is_dead())
                    && members.iter().all(|&m| m == out || pr.f.vn(m).descend.iter().all(|r| compares.contains(r) || pr.f.op(*r).is_dead()) || !pr.f.vn(m).is_written());
                if tree_only {
                    pr.suppressed.insert(u);
                }
            }
        }
    }
    // the root's condition block may carry statements before the compare (the scrutinee load);
    // a List-condition head prints its statement components (its ifs are the tree's nodes)
    let head = s.blocks[idx].components[0];
    match s.blocks[head].kind {
        FlowKind::List => {
            let head_stmts: Vec<usize> = pr.arms.sparse_switch.head_stmts.borrow().clone();
            for c in s.blocks[head].components.clone() {
                if head_stmts.contains(&c) || !matches!(s.blocks[c].kind, FlowKind::If | FlowKind::IfElse | FlowKind::CondAnd | FlowKind::CondOr | FlowKind::List) {
                    pr.emit_structured(s, c, indent, out);
                }
            }
        }
        _ => pr.emit_structured(s, head, indent, out),
    }
    let hoisted: Vec<usize> = pr.arms.sparse_switch.hoist_pending.borrow_mut().drain(..).collect();
    for c in hoisted {
        pr.emit_structured(s, c, indent, out);
    }
    let pad = "  ".repeat(indent);
    let (sv, _) = if inline { pr.render_op(scrut_def.unwrap()) } else { pr.render_var(scrut) };
    let _ = writeln!(out, "{pad}switch ({sv}) {{");
    let last = order.len() - 1;
    for (pos, &ci) in order.iter().enumerate() {
        let (labels, body, join, exit_goto) = (&cases[ci].0, cases[ci].1, cases[ci].2.clone(), cases[ci].3);
        let mut labels = labels.clone();
        labels.sort();
        labels.dedup();
        for v in &labels {
            let _ = writeln!(out, "{pad}case {}:", render_const_typed((*v as u64) & if size >= 8 { u64::MAX } else { (1u64 << (8 * size)) - 1 }, size as u32, signed));
        }
        match body {
            SparseBody::Empty => {
                let _ = writeln!(out, "{pad}  break;");
            }
            SparseBody::Goto(t) => {
                pr.labels.insert(t);
                let _ = writeln!(out, "{pad}  goto {};", pr.lab_name(t));
            }
            SparseBody::Node(n) => {
                pr.emit_structured(s, n, indent + 1, out);
                if let Some(j) = join {
                    // the continuation's first block carries the label when the group shares it
                    let jb = entry_basic(s, j[0]);
                    let shared = order.iter().filter(|&&o| cases[o].2.as_ref() == Some(&j)).count() > 1;
                    if let (Some(b), true) = (jb, shared) {
                        pr.labels.insert(b);
                    }
                    if join_last.get(&ci).copied().unwrap_or(true) {
                        for &c in &j {
                            pr.emit_structured(s, c, indent + 1, out);
                        }
                        let tail_node = *j.last().unwrap();
                        if s.blocks[tail_node].out_edges.len() == 1 && (pos != last || default_body.is_some()) {
                            let _ = writeln!(out, "{pad}  break;");
                        }
                    } else if let Some(b) = jb {
                        let _ = writeln!(out, "{pad}  goto {};", pr.lab_name(b));
                    }
                    continue;
                }
                // the enclosing node's goto follows the body: `break` when it is the switch's
                // exit, the `goto` itself otherwise
                if let Some(t) = exit_goto {
                    if Some(t) == tail {
                        let _ = writeln!(out, "{pad}  break;");
                    } else {
                        pr.labels.insert(t);
                        let _ = writeln!(out, "{pad}  goto {};", pr.lab_name(t));
                    }
                    continue;
                }
                // Ghidra's rule: an exiting case (one out-edge) breaks unless it is the last
                if s.blocks[n].out_edges.len() == 1 && (pos != last || default_body.is_some()) {
                    let _ = writeln!(out, "{pad}  break;");
                }
            }
        }
    }
    if let Some(db) = default_body {
        with_default.sort();
        with_default.dedup();
        for v in &with_default {
            let _ = writeln!(out, "{pad}case {}:", render_const_typed((*v as u64) & if size >= 8 { u64::MAX } else { (1u64 << (8 * size)) - 1 }, size as u32, signed));
        }
        let _ = writeln!(out, "{pad}default:");
        match db {
            SparseBody::Empty => {
                let _ = writeln!(out, "{pad}  break;");
            }
            SparseBody::Goto(t) => {
                pr.labels.insert(t);
                let _ = writeln!(out, "{pad}  goto {};", pr.lab_name(t));
            }
            SparseBody::Node(n) => {
                pr.emit_structured(s, n, indent + 1, out);
                if let Some(j) = &default_join {
                    for &c in j {
                        pr.emit_structured(s, c, indent + 1, out);
                    }
                }
            }
        }
    }
    let _ = writeln!(out, "{pad}}}");
    true
}


/// `sparse-switch=switch`, the ONE-CASE tree: `if (x == k)` — or a conjunction of such tests —
/// where every scrutinee is a 16-bit value whose ORIGINAL compare is a 16-bit REGISTER compare
/// (`MOV AX,[..] ; CMP AX,k` / `TEST AX,AX`: the `sparse_cmp_sites` witness at the branch with a
/// 2-byte register and the case's constant) prints as nested one-case switches. The bytes say the
/// source wrote a switch: this compiler compares a 16-bit `if` operand at int width (`MOVSX` /
/// `XOR ; MOV` then `CMP EAX,k`, or `CMP word ptr [mem],k` in place — measured on WAR2
/// FUN_0004921c under every `if` spelling), and only a `switch` selector is loaded into a 16-bit
/// register and compared there; `switch (*param_2) { case 9: .. }` is EXACT, and 89 message
/// dispatchers share the shape (`if ((*p == 9) && (p[1] == 0))` = two nested one-case switches).
/// A plain `if` with no else only, every clause a witnessed equality, and a body that does not
/// `break` out of an enclosing loop — the switch would capture the break.
fn try_emit_narrow_switch(pr: &mut PrintC<'_>, s: &Structured, idx: usize, indent: usize, out: &mut String) -> bool {
    if !matches!(s.blocks[idx].kind, FlowKind::If) || s.blocks[idx].components.len() != 2 {
        return false;
    }
    let (cond_node, body) = (s.blocks[idx].components[0], s.blocks[idx].components[1]);
    let mut clauses: Vec<(usize, bool)> = Vec::new();
    pr.collect_conj_clauses(s, cond_node, s.blocks[idx].negated, &mut clauses);
    if clauses.is_empty() {
        return false;
    }
    let mut cases: Vec<(VarnodeId, Vec<i64>)> = Vec::new();
    // the leading clauses that are witnessed 16-bit equalities become the switch nest; a TAIL of
    // other clauses (a byte global's test after the two message compares, WAR2 FUN_0003ec58)
    // prints as an inner `if` in the innermost case — the switch owns exactly the compares the
    // original made at 16 bits. One tail clause, and only one that reads MEMORY: a tail testing
    // a register local measured 10 downs in the long dispatcher chains (round e30), the switch
    // nest re-laying their blocks
    let mut tail: Vec<(usize, bool)> = Vec::new();
    for &(node, neg) in &clauses {
        // a clause with a cut edge of its own is not a plain test
        let FlowKind::Basic(bid) = s.blocks[node].kind else { return false };
        if s.gotos.contains_key(&bid) || s.node_gotos.contains_key(&node) {
            return false;
        }
        if !tail.is_empty() {
            tail.push((node, neg));
            continue;
        }
        let Some(cb) = pr.f.block(bid).ops.iter().rev().copied().find(|&op| !pr.f.op(op).is_dead() && pr.f.op(op).code() == OpCode::Cbranch) else { return false };
        let narrow = (|| {
            let cond = pr.f.op(cb).input(1)?;
            let (x, code, k, cneg) = sparse_compare(pr, cond)?;
            if pr.f.vn(x).size != 2 {
                return None;
            }
            let pc = pr.f.op(cb).seqnum.pc.offset;
            let &(imm, kind, (_, rsize)) = pr.recovered.sparse_cmp_sites.get(&pc)?;
            if rsize != 2 {
                return None;
            }
            let imm = (imm & 0xffff) as i64;
            match code {
                // the clause holds iff `x == k`: an equality printed straight, or an inequality
                // negated
                OpCode::IntEqual | OpCode::IntNotequal => {
                    let is_eq = code == OpCode::IntEqual;
                    if is_eq == (neg ^ cneg) || kind != CMP_EQ || imm != k & 0xffff {
                        return None;
                    }
                    Some((x, vec![k]))
                }
                // an UNSIGNED 16-bit range `x <= k` / `x < k` for a small k, witnessed by the
                // original's `CMP r16,k ; JBE/JA` (or `JB/JAE`): the case list `0 .. k` — the
                // switch compares at 16 bits where the `if` promotes and compares signed
                // (`XOR EBX,EBX ; .. CMP EBX,1 ; JLE` for `CMP BX,1 ; JBE`, WAR2 FUN_0002bb98,
                // probed EXACT as `case 0: case 1:`)
                OpCode::IntLessequal | OpCode::IntLess => {
                    // `sparse_compare` folds a mirrored compare into `cneg`: the clause holds
                    // iff `x code k` XOR (neg ^ cneg) -- a PREFIX range `0 .. top` when not
                    // negated (`x < k` = `0 .. k-1`, `x <= k` = `0 .. k`), a suffix otherwise.
                    // The witness is the switch's own range check, `CMP r16,top ; JA` (an
                    // LE-kind jump whose immediate IS the top): Ghidra's normalization moves
                    // the IR constant (`x <= 1` lifts as `x < 2`), so the RANGE has to agree,
                    // not the immediate
                    if neg ^ cneg || !scrutinee_is_memory(pr, x) {
                        return None;
                    }
                    let top = if code == OpCode::IntLessequal { k } else { k - 1 };
                    if kind != CMP_LE || imm != top || !(0..=3).contains(&top) {
                        return None;
                    }
                    Some((x, (0..=top).collect()))
                }
                _ => None,
            }
        })();
        match narrow {
            // (a scrutinee compared elsewhere too — a tree the full recognizer declined, or a
            // chain — still prints: declining measured net negative, -0.70 sim over 47 TUs in
            // round e3, the one-case switch fragment recompiling closer than the `if` more often
            // than not)
            Some(case) => cases.push(case),
            None => tail.push((node, neg)),
        }
    }
    if cases.is_empty() || tail.len() > 1 || tail.iter().any(|&(node, _)| !clause_reads_memory(pr, s, node)) {
        return false;
    }
    // a `break;` inside the body would bind to the switch instead of the loop it exits
    let mut stack = vec![body];
    while let Some(n) = stack.pop() {
        if s.node_gotos.get(&n).is_some_and(|rs| rs.iter().any(|r| r.is_break)) {
            return false;
        }
        if let FlowKind::Basic(b) = s.blocks[n].kind {
            if s.gotos.get(&b).is_some_and(|rs| rs.iter().any(|r| r.is_break)) {
                return false;
            }
        }
        stack.extend(s.blocks[n].components.iter().copied());
    }
    debug!(crate::debug::Topic::SparseSwitch, "{:#x} narrow switch at node {idx}: {} case(s)", pr.f.addr.offset, cases.len());
    // the condition block's own statements first, as the if emitter prints them
    pr.emit_structured(s, cond_node, indent, out);
    let n = cases.len();
    for (i, (x, ks)) in cases.iter().enumerate() {
        let pad = "  ".repeat(indent + i);
        let sv = pr.operand(*x, 0, false);
        let _ = writeln!(out, "{pad}switch ({sv}) {{");
        for &k in ks {
            let _ = writeln!(out, "{pad}case {}:", render_const_typed((k as u64) & 0xffff, 2, false));
        }
    }
    if tail.is_empty() {
        pr.emit_structured(s, body, indent + n, out);
    } else {
        let conds: Vec<String> = tail.iter().map(|&(node, neg)| pr.render_condition(s, node, neg)).collect();
        let pad = "  ".repeat(indent + n);
        let _ = writeln!(out, "{pad}if ({}) {{", conds.join(" && "));
        pr.emit_structured(s, body, indent + n + 1, out);
        let _ = writeln!(out, "{pad}}}");
    }
    for i in (0..n).rev() {
        let pad = "  ".repeat(indent + i);
        let _ = writeln!(out, "{pad}  break;");
        let _ = writeln!(out, "{pad}}}");
    }
    true
}

/// The identity of a compare operand across the tree (see [`SparseKey`]).
fn sparse_key(pr: &PrintC<'_>, x: VarnodeId) -> SparseKey {
    let x = strip_copies(pr.f, x);
    if let Some(d) = pr.f.vn(x).def {
        let o = pr.f.op(d);
        match o.code() {
            OpCode::Load => {
                if let Some(a) = o.input(1) {
                    let a = strip_copies(pr.f, a);
                    if let Some(ad) = pr.f.vn(a).def {
                        let ao = pr.f.op(ad);
                        if matches!(ao.code(), OpCode::Ptradd | OpCode::Ptrsub | OpCode::IntAdd) {
                            if let (Some(b), Some(k)) = (ao.input(0), ao.input(1)) {
                                if pr.f.vn(k).is_constant() {
                                    let mut off = pr.f.vn(k).constant_value() as i64;
                                    if ao.code() == OpCode::Ptradd {
                                        off *= o.input(2).map(|e| pr.f.vn(e).constant_value() as i64).unwrap_or(1);
                                    }
                                    return SparseKey::Load(pr.high_of[strip_copies(pr.f, b).0 as usize], off, pr.f.vn(x).size);
                                }
                            }
                        }
                    }
                    return SparseKey::Load(pr.high_of[a.0 as usize], 0, pr.f.vn(x).size);
                }
            }
            OpCode::Piece => {
                if let (Some(hi), Some(lo)) = (o.input(0), o.input(1)) {
                    return SparseKey::Piece(pr.high_of[strip_copies(pr.f, hi).0 as usize], pr.high_of[strip_copies(pr.f, lo).0 as usize]);
                }
            }
            _ => {}
        }
    }
    SparseKey::High(pr.high_of[x.0 as usize])
}

/// The compare a condition varnode expresses on a scrutinee: `(scrutinee, opcode, constant,
/// negated)` — through one BOOL_NEGATE, with the constant on either side (mirrored).
/// A clause whose compare reads MEMORY — a global or a load, never a register-held local — on
/// at least one side, with no explicit local on either: the tail form of the narrow switch is
/// admitted for these only (see `try_emit_narrow_switch`).
/// Whether the range form's scrutinee is a memory read — a global, or a load inlined at the
/// compare: the switch SELECTOR's shape (`MOV AX,[..] ; CMP AX,k`). A named 16-bit local
/// compares at 16 bits under an `if` as well, so the range on one is no witness: the two
/// locals the form reached in round e32 measured 0 and −0.066 (FUN_0005dd14).
fn scrutinee_is_memory(pr: &PrintC<'_>, x: VarnodeId) -> bool {
    let vn = pr.f.vn(x);
    let ram = pr.f.spaces.by_name("ram");
    Some(vn.loc.space) == ram || (!pr.is_explicit(x) && vn.def.is_some_and(|d| pr.f.op(d).code() == OpCode::Load))
}

fn clause_reads_memory(pr: &PrintC<'_>, s: &Structured, node: usize) -> bool {
    let FlowKind::Basic(bid) = s.blocks[node].kind else { return false };
    let Some(cb) = pr.f.block(bid).ops.iter().rev().copied().find(|&op| !pr.f.op(op).is_dead() && pr.f.op(op).code() == OpCode::Cbranch) else { return false };
    let Some(mut cond) = pr.f.op(cb).input(1) else { return false };
    for _ in 0..3 {
        let Some(d) = pr.f.vn(cond).def else { return false };
        let o = pr.f.op(d);
        match o.code() {
            OpCode::BoolNegate | OpCode::Copy => {
                let Some(x) = o.input(0) else { return false };
                cond = x;
            }
            _ => break,
        }
    }
    let Some(d) = pr.f.vn(cond).def else { return false };
    let o = pr.f.op(d);
    if !o.is_bool_output() {
        return false;
    }
    let ram = pr.f.spaces.by_name("ram");
    let mut memory = false;
    for i in 0..o.num_inputs() {
        let Some(v) = o.input(i) else { return false };
        let vn = pr.f.vn(v);
        if vn.is_constant() {
            continue;
        }
        // a global, or a load INLINED at the compare; a named local — even one holding a load
        // (FUN_00047594's `iVar2 != 10`, a down of round e30) — is a register-held value
        let global = Some(vn.loc.space) == ram;
        let inline_load = !pr.is_explicit(v) && vn.def.is_some_and(|dd| pr.f.op(dd).code() == OpCode::Load);
        if global || inline_load {
            memory = true;
        } else if pr.is_explicit(v) {
            return false;
        }
    }
    memory
}

fn sparse_compare(pr: &PrintC<'_>, cond: VarnodeId) -> Option<(VarnodeId, OpCode, i64, bool)> {
    let mut v = cond;
    let mut neg = false;
    let d = pr.f.vn(v).def?;
    if pr.f.op(d).code() == OpCode::BoolNegate {
        neg = true;
        v = pr.f.op(d).input(0)?;
    } else if pr.f.op(d).code() == OpCode::Copy {
        // Since RuleBoolNegate was ported faithfully (Order Z(5)) a negated comparison arrives as
        // a COPY of an ALREADY-FLIPPED comparison, not as a BOOL_NEGATE of the original: Ghidra
        // flips the producer in place and turns every negate reading it into a COPY. So look
        // through the copy, and leave `neg` FALSE -- the flip has already happened upstream and
        // negating again would undo it.
        v = pr.f.op(d).input(0)?;
    }
    let d = pr.f.vn(v).def?;
    let o = pr.f.op(d);
    let code = o.code();
    if !matches!(code, OpCode::IntLess | OpCode::IntLessequal | OpCode::IntSless | OpCode::IntSlessequal | OpCode::IntEqual | OpCode::IntNotequal) {
        return None;
    }
    let (a, b) = (o.input(0)?, o.input(1)?);
    let (x, k, mirrored) = if pr.f.vn(b).is_constant() {
        (a, pr.f.vn(b).constant_value(), false)
    } else if pr.f.vn(a).is_constant() {
        (b, pr.f.vn(a).constant_value(), true)
    } else {
        return None;
    };
    let size = pr.f.vn(x).size;
    let signed = matches!(code, OpCode::IntSless | OpCode::IntSlessequal);
    let mask = if size >= 8 { u64::MAX } else { (1u64 << (8 * size)) - 1 };
    let kv = if signed && size < 8 && (k & mask) & (1u64 << (8 * size - 1)) != 0 { ((k & mask) | !mask) as i64 } else { (k & mask) as i64 };
    // `k < x` mirrors to `x > k` = !(x <= k); `k <= x` to `x >= k` = !(x < k)
    let (code, neg) = if mirrored {
        match code {
            OpCode::IntLess => (OpCode::IntLessequal, !neg),
            OpCode::IntLessequal => (OpCode::IntLess, !neg),
            OpCode::IntSless => (OpCode::IntSlessequal, !neg),
            OpCode::IntSlessequal => (OpCode::IntSless, !neg),
            other => (other, neg),
        }
    } else {
        (code, neg)
    };
    Some((strip_copies(pr.f, x), code, kv, neg))
}

/// Whether the compare under `cond` (past a BOOL_NEGATE) has its constant on the LEFT
/// (`c < x`), the orientation Ghidra's canonical forms use for `x >= c+1` / `x > c`.
fn sparse_compare_mirrored(pr: &PrintC<'_>, cond: VarnodeId) -> bool {
    let mut v = cond;
    if let Some(d) = pr.f.vn(v).def {
        if pr.f.op(d).code() == OpCode::BoolNegate {
            if let Some(i) = pr.f.op(d).input(0) {
                v = i;
            }
        }
    }
    pr.f.vn(v).def.and_then(|d| pr.f.op(d).input(0)).is_some_and(|a| pr.f.vn(a).is_constant())
}

fn sparse_signed(pr: &PrintC<'_>, cond: VarnodeId) -> bool {
    sparse_compare(pr, cond).is_some_and(|(_, c, _, _)| matches!(c, OpCode::IntSless | OpCode::IntSlessequal))
}

/// The value ranges for which `cond` (on the scrutinee, domain `[lo, hi]`) is TRUE.
fn sparse_true_ranges(pr: &PrintC<'_>, cond: VarnodeId, scrut_high: SparseKey, lo: i64, hi: i64, compares: &mut Vec<OpId>, consts: &mut Vec<(u64, i64, u8)>) -> Option<Ranges> {
    let Some((x, code, k, neg)) = sparse_compare(pr, cond) else {
        if crate::debug::on(crate::debug::Topic::SparseSwitch) {
            let d = pr.f.vn(cond).def.map(|d| { let o = pr.f.op(d); (format!("{:x}", o.seqnum.pc.offset), o.code(), (0..o.num_inputs()).map(|i| o.input(i).map(|v| pr.f.vn(v).def.map(|dd| format!("{:?}", pr.f.op(dd).code())).unwrap_or_else(|| if pr.f.vn(v).is_constant() { format!("#{:x}", pr.f.vn(v).constant_value()) } else { "in".into() }))).collect::<Vec<_>>()) });
            debug!(crate::debug::Topic::SparseSwitch, "  unreadable compare: cond {cond:?} def {d:?}");
        }
        return None;
    };
    // Ghidra's melded range test (`RuleRangeMeld`): `(x + c) < k` unsigned is x in the wrapped
    // interval [-c, k-1-c] — the `< 0xfe` / `!= 0xff` nodes of 0x2d7fc's tree print that way
    if sparse_key(pr, x) != scrut_high && !neg || sparse_key(pr, x) != scrut_high && neg {
        if let Some(ad) = pr.f.vn(x).def {
            let ao = pr.f.op(ad);
            if ao.code() == OpCode::IntAdd && matches!(code, OpCode::IntLess | OpCode::IntLessequal) {
                if let (Some(base), Some(cv)) = (ao.input(0), ao.input(1)) {
                    if pr.f.vn(cv).is_constant() && sparse_key(pr, base) == scrut_high {
                        let size = pr.f.vn(base).size as i64;
                        let m = if size >= 8 { u64::MAX } else { (1u64 << (8 * size)) - 1 };
                        let c = (pr.f.vn(cv).constant_value() & m) as i64;
                        let top = if size >= 8 { i64::MAX / 2 } else { (1i64 << (8 * size)) - 1 };
                        let width = if matches!(code, OpCode::IntLess) { k - 1 } else { k };
                        let start = (top + 1 - c) % (top + 1);
                        let end = (start + width) % (top + 1);
                        let t = if width < 0 { Ranges(vec![]) } else if start <= end { Ranges(vec![(start, end)]) } else { Ranges(vec![(start, top), (0, end)]) };
                        let pc = pr.f.vn(cond).def.map(|d| pr.f.op(d).seqnum.pc.offset).unwrap_or(0);
                        debug!(crate::debug::Topic::SparseSwitch, "  meld compare @{pc:#x}: (x + {c}) {:?} {k} -> [{start}, {end}] neg {neg}", code);
                        consts.push((pc, start, CMP_LT));
                        consts.push((pc, end, CMP_LE));
                        if let Some(d) = pr.f.vn(cond).def {
                            compares.push(d);
                            if let Some(i) = pr.f.op(d).input(0) { if let Some(dd) = pr.f.vn(i).def { compares.push(dd); } }
                        }
                        compares.push(ad);
                        let t = t.intersect(&Ranges(vec![(lo, hi)]));
                        return Some(if neg { t.complement(lo, hi) } else { t });
                    }
                }
            }
        }
    }
    if sparse_key(pr, x) != scrut_high {
        debug!(crate::debug::Topic::SparseSwitch, "  key mismatch: compare {:?} k {k} key {:?} vs {scrut_high:?}", code, sparse_key(pr, x));
        return None;
    }
    // the compare's instruction: Watcom's pivot is one CMP with two jumps (JB below, JBE the
    // equal case), which lifts to two compares of the same constant at the same pc; a lone
    // range compare (`CMP 4; JB`, printed `3 < u` once normalized) names no case by itself
    let pc = pr.f.vn(cond).def.map(|d| pr.f.op(d).seqnum.pc.offset).unwrap_or(0);
    // the compare's kind and constant, from the original's bytes when the witness has the
    // site; else from the IR, reading Ghidra's canonical `c < x` (mirrored) as `!(x < c+1)`
    // (`CMP c+1; JB` on its fall-through edge) and `c <= x` as `!(x < c)`
    let mirrored = sparse_compare_mirrored(pr, cond);
    let (kc, kind) = match pr.recovered.sparse_cmp_sites.get(&pc) {
        Some(&(imm, wk, _)) => {
            let size = pr.f.vn(x).size;
            let signed = matches!(code, OpCode::IntSless | OpCode::IntSlessequal);
            let mask = if size >= 8 { u64::MAX } else { (1u64 << (8 * size)) - 1 };
            let kw = if signed && size < 8 && (imm & mask) & (1u64 << (8 * size - 1)) != 0 { ((imm & mask) | !mask) as i64 } else { (imm & mask) as i64 };
            (kw, wk)
        }
        None => match (code, mirrored) {
            (OpCode::IntEqual | OpCode::IntNotequal, _) => (k, CMP_EQ),
            (OpCode::IntLessequal | OpCode::IntSlessequal, false) => (k, CMP_LE),
            (OpCode::IntLessequal | OpCode::IntSlessequal, true) => (k + 1, CMP_LT),
            (_, _) => (k, CMP_LT),
        },
    };
    debug!(crate::debug::Topic::SparseSwitch, "  compare @{pc:#x}: x {:?} {k} neg {neg} mirrored {mirrored} -> ({kc}, kind {kind}) witness {:?}", code, pr.recovered.sparse_cmp_sites.get(&pc));
    consts.push((pc, kc, kind));
    if let Some(d) = pr.f.vn(cond).def {
        compares.push(d);
        if let Some(i) = pr.f.op(d).input(0) {
            if let Some(dd) = pr.f.vn(i).def {
                compares.push(dd);
            }
        }
    }
    let t = match code {
        OpCode::IntLess | OpCode::IntSless => Ranges(vec![(lo, k - 1)]),
        OpCode::IntLessequal | OpCode::IntSlessequal => Ranges(vec![(lo, k)]),
        OpCode::IntEqual => Ranges(vec![(k, k)]),
        OpCode::IntNotequal => Ranges(vec![(lo, k - 1), (k + 1, hi)]),
        _ => return None,
    };
    let t = Ranges(t.0.into_iter().filter(|&(a, b)| a <= b).collect());
    Some(if neg { t.complement(lo, hi) } else { t })
}

/// The true-ranges of a condition NODE (a plain compare block, or a CondAnd/CondOr of them).
fn sparse_cond_ranges(pr: &PrintC<'_>, s: &Structured, node: usize, scrut_high: SparseKey, lo: i64, hi: i64, compares: &mut Vec<OpId>, consts: &mut Vec<(u64, i64, u8)>) -> Option<Ranges> {
    match s.blocks[node].kind {
        FlowKind::Basic(bid) => {
            // the block must hold nothing but the compare and its branch (the root's head is
            // emitted separately by the caller)
            let cb = pr.f.block(bid).ops.iter().rev().copied().find(|&op| !pr.f.op(op).is_dead() && pr.f.op(op).code() == OpCode::Cbranch)?;
            let cond = pr.f.op(cb).input(1)?;
            sparse_true_ranges(pr, cond, scrut_high, lo, hi, compares, consts)
        }
        FlowKind::CondAnd | FlowKind::CondOr => {
            let comps = &s.blocks[node].components;
            if comps.len() != 2 {
                return None;
            }
            let a = sparse_cond_ranges(pr, s, comps[0], scrut_high, lo, hi, compares, consts)?;
            let b = sparse_cond_ranges(pr, s, comps[1], scrut_high, lo, hi, compares, consts)?;
            // the printer's own polarity (`render_cond_expr`): each operand is negated by
            // `operand_oriented ^ flip`; the connective is the node kind (the enclosing if's
            // `negated` complements the whole, applied by the caller)
            let (fa, fb) = s.blocks[node].cond_flip;
            let (oa, ob) = (operand_oriented(pr.f, s, comps[0]), operand_oriented(pr.f, s, comps[1]));
            let a2 = if oa ^ fa { a.complement(lo, hi) } else { a.clone() };
            let b2 = if ob ^ fb { b.complement(lo, hi) } else { b.clone() };
            debug!(crate::debug::Topic::SparseSwitch, "  cond {:?} node {node}: a {:?} b {:?} oriented ({oa},{ob}) flip ({fa},{fb}) -> a {:?} b {:?}", s.blocks[node].kind, a.0, b.0, a2.0, b2.0);
            Some(if matches!(s.blocks[node].kind, FlowKind::CondAnd) { a2.intersect(&b2) } else { a2.union(&b2) })
        }
        _ => None,
    }
}

/// Walk the tree under `node` with the values `reach` admits; collect the leaves.
fn sparse_walk(pr: &PrintC<'_>, s: &Structured, node: usize, scrut_high: SparseKey, signed: bool, reach: Ranges, lo: i64, hi: i64, leaves: &mut Vec<SparseLeaf>, compares: &mut Vec<OpId>, consts: &mut Vec<(u64, i64, u8)>, d: usize, depth: &mut usize, join: Option<Vec<usize>>) -> bool {
    let _ = signed;
    match s.blocks[node].kind {
        FlowKind::If | FlowKind::IfElse => {
            let comps = s.blocks[node].components.clone();
            // a condition that is a List: its leading components are tree compares (`if (u <
            // 0x13) {..return;}` folded ahead of the next if's own compare) or empty blocks —
            // narrow through them; the if's own condition is the last component
            let Some((cond, reach)) = sparse_if_cond(pr, s, node, reach, scrut_high, signed, lo, hi, leaves, compares, consts, d, depth, join.clone()) else { return false };
            let Some(cond) = cond else {
                leaves.push(SparseLeaf { node, vals: reach, join: join.clone(), goto: None, exit_goto: pr.arms.sparse_switch.exit_goto.borrow().last().copied() });
                return true;
            };
            // an inner condition block must be nothing but its compare; the root's head may
            // carry the scrutinee load (emitted before the switch)
            if d > 0 && !sparse_cond_accept(pr, s, cond, d) {
                debug!(crate::debug::Topic::SparseSwitch, "  leaf(impure cond) node {node}: cond node {cond} kind {:?} comps {:?}", s.blocks[cond].kind, s.blocks[cond].components);
                leaves.push(SparseLeaf { node, vals: reach, join: join.clone(), goto: None, exit_goto: pr.arms.sparse_switch.exit_goto.borrow().last().copied() });
                return true;
            }
            let Some(t) = sparse_cond_ranges(pr, s, cond, scrut_high, lo, hi, compares, consts) else {
                if crate::debug::on(crate::debug::Topic::SparseSwitch) {
                    let cv = pr.plain_if_condition_vn(s, node);
                    debug!(crate::debug::Topic::SparseSwitch, "  leaf(no ranges) node {node} cond kind {:?} cond vn {:?} compare {:?}", s.blocks[cond].kind, cv, cv.and_then(|c| sparse_compare(pr, c)).map(|(x, c, k, n)| (pr.high_of[x.0 as usize], c, k, n)));
                }
                if d == 0 {
                    return false;
                }
                leaves.push(SparseLeaf { node, vals: reach, join: join.clone(), goto: None, exit_goto: pr.arms.sparse_switch.exit_goto.borrow().last().copied() });
                return true;
            };
            *depth = (*depth).max(d + 1);
            let neg = s.blocks[node].negated;
            let then_r = if neg { t.complement(lo, hi) } else { t.clone() };
            let else_r = then_r.complement(lo, hi);
            let then_reach = reach.intersect(&then_r);
            let else_reach = reach.intersect(&else_r);
            // the node's own unconditional goto (`if (..) {..} goto LAB;`) follows the bodies
            // of both branches: leaves inside them end there
            let via_goto = s.node_gotos.get(&node).and_then(|rs| rs.iter().find(|g| !g.conditional && !g.is_break).map(|g| g.target));
            if let Some(t) = via_goto {
                pr.arms.sparse_switch.exit_goto.borrow_mut().push(t);
            }
            let mut ok = sparse_walk(pr, s, comps[1], scrut_high, signed, then_reach, lo, hi, leaves, compares, consts, d + 1, depth, join.clone());
            if ok && comps.len() == 3 {
                ok = sparse_walk(pr, s, comps[2], scrut_high, signed, else_reach.clone(), lo, hi, leaves, compares, consts, d + 1, depth, join.clone());
            }
            if via_goto.is_some() {
                pr.arms.sparse_switch.exit_goto.borrow_mut().pop();
            }
            if !ok {
                return false;
            }
            if comps.len() != 3 {
                // no else: the complement falls out through the node's own unconditional goto
                // record when it has one (`if (4 < u) {..} goto LAB;`), else to what follows
                let fallout = via_goto.or_else(|| pr.next_flow_after(s, node));
                if let Some(tb) = fallout {
                    if let Some(tn) = sparse_body_node(pr, s, tb) {
                        leaves.push(SparseLeaf { node: tn, vals: else_reach, join: join.clone(), goto: via_goto, exit_goto: None });
                    }
                }
            }
            true
        }
        FlowKind::List => sparse_walk_list(pr, s, &s.blocks[node].components.clone(), Some(node), scrut_high, signed, reach, lo, hi, leaves, compares, consts, d, depth, join),
        _ => {
            // a basic block that is a compare with a conditional `goto` out of the tree
            // (`if (u != 3) goto LAB;`): the jump is a leaf, the fall-through is what follows
            if let Some((target, when_true)) = sparse_cond_goto(pr, s, node, false) {
                if sparse_pure_cond(pr, s, node) {
                    if let Some(t) = sparse_cond_ranges(pr, s, node, scrut_high, lo, hi, compares, consts) {
                        *depth = (*depth).max(d + 1);
                        let taken = if when_true { t } else { t.complement(lo, hi) };
                        let tn = sparse_body_node(pr, s, target).unwrap_or(node);
                        leaves.push(SparseLeaf { node: tn, vals: reach.intersect(&taken), join: join.clone(), goto: Some(target), exit_goto: None });
                        let rest = reach.intersect(&taken.complement(lo, hi));
                        if let Some(fb) = pr.next_flow_after(s, node) {
                            if let Some(fnode) = sparse_body_node(pr, s, fb) {
                                leaves.push(SparseLeaf { node: fnode, vals: rest, join: join.clone(), goto: None, exit_goto: pr.arms.sparse_switch.exit_goto.borrow().last().copied() });
                                return true;
                            }
                        }
                        debug!(crate::debug::Topic::SparseSwitch, "  bail: cond-goto node {node} has no structural fall-through");
                        return false;
                    }
                }
            }
            if matches!(s.blocks[node].kind, FlowKind::CondAnd | FlowKind::CondOr) {
                debug!(crate::debug::Topic::SparseSwitch, "  leaf(cond group) node {node} kind {:?}: cond-goto {:?} node_gotos {:?} pure {}", s.blocks[node].kind, sparse_cond_goto(pr, s, node, true), s.node_gotos.get(&node).map(|r| r.len()), sparse_pure_cond(pr, s, node));
            }
            leaves.push(SparseLeaf { node, vals: reach, join: join.clone(), goto: None, exit_goto: pr.arms.sparse_switch.exit_goto.borrow().last().copied() });
            true
        }
    }
}

/// Walk the components of a list: a compare `if` without else falls out into the NEXT
/// component, so the reach narrows component by component; a compare cut to a conditional
/// `goto` jumps out with part of it; the first statement component is the leaf (the whole list
/// when nothing before it was walked, else that component with the rest as its continuation);
/// the last component is walked as a tree node.
fn sparse_walk_list(pr: &PrintC<'_>, s: &Structured, comps: &[usize], list_node: Option<usize>, scrut_high: SparseKey, signed: bool, reach: Ranges, lo: i64, hi: i64, leaves: &mut Vec<SparseLeaf>, compares: &mut Vec<OpId>, consts: &mut Vec<(u64, i64, u8)>, d: usize, depth: &mut usize, join: Option<Vec<usize>>) -> bool {
    let list_goto = list_node.and_then(|n| s.node_gotos.get(&n)).and_then(|rs| rs.iter().find(|g| !g.conditional && !g.is_break).map(|g| g.target));
    if let Some(t) = list_goto {
        pr.arms.sparse_switch.exit_goto.borrow_mut().push(t);
    }
    let ok = sparse_walk_list_inner(pr, s, comps, list_node, scrut_high, signed, reach, lo, hi, leaves, compares, consts, d, depth, join);
    if list_goto.is_some() {
        pr.arms.sparse_switch.exit_goto.borrow_mut().pop();
    }
    ok
}

fn sparse_walk_list_inner(pr: &PrintC<'_>, s: &Structured, comps: &[usize], list_node: Option<usize>, scrut_high: SparseKey, signed: bool, reach: Ranges, lo: i64, hi: i64, leaves: &mut Vec<SparseLeaf>, compares: &mut Vec<OpId>, consts: &mut Vec<(u64, i64, u8)>, d: usize, depth: &mut usize, join: Option<Vec<usize>>) -> bool {
    let dbg = crate::debug::on(crate::debug::Topic::SparseSwitch);
    let mut cur = reach;
    for (i, &c) in comps.iter().enumerate() {
        let is_last = i + 1 == comps.len();
        let stmt_leaf = |leaves: &mut Vec<SparseLeaf>, vals: Ranges| match (list_node, i) {
            (Some(n), 0) => leaves.push(SparseLeaf { node: n, vals, join: join.clone(), goto: None, exit_goto: None }),
            // the rest of a flattened list that begins with a whole list node: that node (the
            // same one a jump into it resolves to), the remainder as its continuation
            _ if s.blocks.iter().any(|b| matches!(b.kind, FlowKind::List) && !b.components.is_empty() && comps[i..].starts_with(&b.components)) => {
                let (n, len) = s.blocks.iter().enumerate().filter(|(_, b)| matches!(b.kind, FlowKind::List) && !b.components.is_empty() && comps[i..].starts_with(&b.components)).map(|(k, b)| (k, b.components.len())).max_by_key(|&(_, l)| l).unwrap();
                let mut rest: Vec<usize> = comps[i + len..].to_vec();
                if let Some(j) = &join {
                    rest.extend(j.iter().copied());
                }
                leaves.push(SparseLeaf { node: n, vals, join: (!rest.is_empty()).then_some(rest), goto: None, exit_goto: None });
            }
            _ => {
                let mut rest: Vec<usize> = comps[i + 1..].to_vec();
                if let Some(j) = &join {
                    rest.extend(j.iter().copied());
                }
                leaves.push(SparseLeaf { node: c, vals, join: (!rest.is_empty()).then_some(rest), goto: None, exit_goto: pr.arms.sparse_switch.exit_goto.borrow().last().copied() });
            }
        };
        if !is_last && matches!(s.blocks[c].kind, FlowKind::IfElse) {
            // both branches flow into the components that follow: a JOIN — walk the
            // IfElse as a tree node whose leaves carry the continuation
            let rest: Vec<usize> = comps[i + 1..].to_vec();
            let Some((cond, cur2)) = sparse_if_cond(pr, s, c, cur.clone(), scrut_high, signed, lo, hi, leaves, compares, consts, d, depth, join.clone()) else { return false };
            if let Some(cond) = cond {
                if sparse_cond_accept(pr, s, cond, d + 1) {
                    if sparse_cond_ranges(pr, s, cond, scrut_high, lo, hi, compares, consts).is_some() {
                        if !sparse_walk(pr, s, c, scrut_high, signed, cur2, lo, hi, leaves, compares, consts, d, depth, Some(rest)) {
                            return false;
                        }
                        return true;
                    }
                }
            }
            debug!(crate::debug::Topic::SparseSwitch, "  leaf(list ifelse) list {list_node:?}: comp {i} = node {c}");
            stmt_leaf(leaves, cur);
            return true;
        }
        if !is_last && matches!(s.blocks[c].kind, FlowKind::If) {
            let Some((cond, cur2)) = sparse_if_cond(pr, s, c, cur.clone(), scrut_high, signed, lo, hi, leaves, compares, consts, d, depth, join.clone()) else { return false };
            if let Some(cond) = cond {
                if sparse_cond_accept(pr, s, cond, d + 1) {
                    if let Some(t) = sparse_cond_ranges(pr, s, cond, scrut_high, lo, hi, compares, consts) {
                        *depth = (*depth).max(d + 1);
                        let then_r = if s.blocks[c].negated { t.complement(lo, hi) } else { t };
                        let then_reach = cur2.intersect(&then_r);
                        if !sparse_walk(pr, s, s.blocks[c].components[1], scrut_high, signed, then_reach, lo, hi, leaves, compares, consts, d + 1, depth, join.clone()) {
                            return false;
                        }
                        cur = cur2.intersect(&then_r.complement(lo, hi));
                        continue;
                    }
                }
            }
        }
        if matches!(s.blocks[c].kind, FlowKind::List) {
            // a nested list: its components sit in this list's flow at this position; one
            // that ends the outer list keeps its identity, so a statement leaf at its head is
            // the list node itself (the same node a jump into it resolves to)
            let mut flat: Vec<usize> = s.blocks[c].components.clone();
            flat.extend_from_slice(&comps[i + 1..]);
            let inner = if i == 0 { list_node } else if is_last { Some(c) } else { None };
            return sparse_walk_list(pr, s, &flat, inner, scrut_high, signed, cur, lo, hi, leaves, compares, consts, d, depth, join);
        }
        if !is_last {
            // a compare cut to a conditional goto (`if (u != 1) goto LAB;`): the jump is a
            // leaf out of the tree, the rest of the reach falls into the next component
            if let Some((target, when_true)) = sparse_cond_goto(pr, s, c, false) {
                if sparse_pure_cond(pr, s, c) {
                    if let Some(t) = sparse_cond_ranges(pr, s, c, scrut_high, lo, hi, compares, consts) {
                        *depth = (*depth).max(d + 1);
                        let taken = if when_true { t } else { t.complement(lo, hi) };
                        let tn = sparse_body_node(pr, s, target).unwrap_or(c);
                        debug!(crate::debug::Topic::SparseSwitch, "  cond-goto node {c} -> {target:?} (node {tn}) vals {:?}", cur.intersect(&taken).0);
                        leaves.push(SparseLeaf { node: tn, vals: cur.intersect(&taken), join: join.clone(), goto: Some(target), exit_goto: None });
                        cur = cur.intersect(&taken.complement(lo, hi));
                        continue;
                    }
                }
            }
            // a statement component before the leaf: the list is a body, not a tree
            if dbg {
                if matches!(s.blocks[c].kind, FlowKind::If | FlowKind::IfElse) {
                    let cn = s.blocks[c].components[0];
                    let cv = pr.plain_if_condition_vn(s, c);
                    debug!(crate::debug::Topic::SparseSwitch, "  unwalked if node {c}: cond node {cn} kind {:?} comps {:?} cond vn {:?} compare {:?} pure {}", s.blocks[cn].kind, s.blocks[cn].components.iter().map(|&x| (x, format!("{:?}", s.blocks[x].kind))).collect::<Vec<_>>(), cv, cv.and_then(|v| sparse_compare(pr, v)).map(|(x, code, k, n)| (sparse_key(pr, x), code, k, n)), sparse_pure_cond(pr, s, cn));
                }
                let ops: Vec<String> = match s.blocks[c].kind { FlowKind::Basic(b) => pr.f.block(b).ops.iter().filter(|&&op| !pr.f.op(op).is_dead()).map(|&op| format!("{:?}{}", pr.f.op(op).code(), if pr.f.op(op).is_marker() { "*" } else { "" })).collect(), _ => vec![] };
                debug!(crate::debug::Topic::SparseSwitch, "  leaf(list stmt) list {list_node:?}: comp {i} = node {c} kind {:?} pure {} ops {:?} gotos {:?}", s.blocks[c].kind, matches!(s.blocks[c].kind, FlowKind::If) && sparse_pure_cond(pr, s, s.blocks[c].components[0]), ops, s.node_gotos.get(&c).map(|r| r.len()));
            }
            stmt_leaf(leaves, cur);
            return true;
        }
        if !sparse_walk(pr, s, c, scrut_high, signed, cur.clone(), lo, hi, leaves, compares, consts, d + 1, depth, join.clone()) {
            return false;
        }
    }
    true
}

/// The condition of `if_node` for the tree walk: `Some((Some(cond), reach))` with the if's own
/// condition node and the reach remaining after narrowing through a List-condition's leading
/// tree compares (each walked as a tree node, the if registered for a condition override);
/// `Some((None, reach))` when a leading component is a statement (the if is a leaf body);
/// `None` on a failed sub-walk.
fn sparse_if_cond(pr: &PrintC<'_>, s: &Structured, if_node: usize, mut reach: Ranges, scrut_high: SparseKey, signed: bool, lo: i64, hi: i64, leaves: &mut Vec<SparseLeaf>, compares: &mut Vec<OpId>, consts: &mut Vec<(u64, i64, u8)>, d: usize, depth: &mut usize, join: Option<Vec<usize>>) -> Option<(Option<usize>, Ranges)> {
    let cond = s.blocks[if_node].components[0];
    if !matches!(s.blocks[cond].kind, FlowKind::List) {
        return Some((Some(cond), reach));
    }
    let mut cc = s.blocks[cond].components.clone();
    // a nested list at the end (Ghidra folds lists into lists) flattens into this one
    while let Some(&l) = cc.last() {
        if !matches!(s.blocks[l].kind, FlowKind::List) {
            break;
        }
        cc.pop();
        cc.extend(s.blocks[l].components.iter().copied());
    }
    let last = cc.len() - 1;
    for &c in &cc[..last] {
        let empty_basic = matches!(s.blocks[c].kind, FlowKind::Basic(b) if pr.f.block(b).ops.iter().all(|&op| pr.f.op(op).is_dead() || pr.f.op(op).is_marker()));
        if empty_basic {
            continue;
        }
        if matches!(s.blocks[c].kind, FlowKind::If) {
            let (inner, reach2) = sparse_if_cond(pr, s, c, reach.clone(), scrut_high, signed, lo, hi, leaves, compares, consts, d, depth, join.clone())?;
            if let Some(ic) = inner {
                if sparse_pure_cond(pr, s, ic) {
                    if let Some(t) = sparse_cond_ranges(pr, s, ic, scrut_high, lo, hi, compares, consts) {
                        *depth = (*depth).max(d + 1);
                        let then_r = if s.blocks[c].negated { t.complement(lo, hi) } else { t };
                        if !sparse_walk(pr, s, s.blocks[c].components[1], scrut_high, signed, reach2.intersect(&then_r), lo, hi, leaves, compares, consts, d + 1, depth, join.clone()) {
                            return None;
                        }
                        reach = reach2.intersect(&then_r.complement(lo, hi));
                        continue;
                    }
                }
            }
        }
        // a pure statement (an address the cases share, hoisted by the compiler to the
        // subtree's root: 0x2d7fc's `puVar3 = param_1 + 8`) prints above the switch
        if sparse_pure_stmt(pr, s, c) {
            if d > 0 {
                pr.arms.sparse_switch.hoist_pending.borrow_mut().push(c);
            }
            continue;
        }
        // at the ROOT any leading component that is not a tree compare is the switch's head
        // (0x4ccc4: `if (cVar1 == 0) func();` on another variable, the calls, and the
        // `iVar2 = func_0x00059060();` defining the scrutinee): printed above the switch
        if d == 0 {
            pr.arms.sparse_switch.head_stmts.borrow_mut().push(c);
            continue;
        }
        if crate::debug::on(crate::debug::Topic::SparseSwitch) {
            let ops: Vec<String> = match s.blocks[c].kind { FlowKind::Basic(b) => pr.f.block(b).ops.iter().filter(|&&op| !pr.f.op(op).is_dead()).map(|&op| format!("{:?}", pr.f.op(op).code())).collect(), _ => vec![] };
            debug!(crate::debug::Topic::SparseSwitch, "  leaf(list cond stmt) if {if_node}: comp node {c} kind {:?} pure_stmt {} gotos {:?} ops {:?}", s.blocks[c].kind, sparse_pure_stmt(pr, s, c), matches!(s.blocks[c].kind, FlowKind::Basic(b) if s.gotos.get(&b).is_some()), ops);
        }
        return Some((None, reach));
    }
    pr.arms.sparse_switch.cond_override_pending.borrow_mut().push((if_node, cc[last]));
    Some((Some(cc[last]), reach))
}

/// A basic block of side-effect-free computations (no store, call, return or branch) that
/// can run before the switch instead of inside the tree.
fn sparse_pure_stmt(pr: &PrintC<'_>, s: &Structured, node: usize) -> bool {
    let FlowKind::Basic(bid) = s.blocks[node].kind else { return false };
    s.gotos.get(&bid).is_none_or(|g| g.is_empty())
        && pr.f.block(bid).ops.iter().all(|&op| {
            let o = pr.f.op(op);
            o.is_dead() || o.is_marker() || !matches!(o.code(), OpCode::Store | OpCode::Call | OpCode::Callind | OpCode::Callother | OpCode::Return | OpCode::Cbranch | OpCode::Branchind)
        })
}

/// Accept a tree node's condition: pure, or a basic block whose extra ops are side-effect-free
/// computations the cases share (0x2d7fc's `puVar3 = param_1 + 8` sitting in the `< 0x26`
/// compare block) — those print above the switch.
fn sparse_cond_accept(pr: &PrintC<'_>, s: &Structured, cond: usize, d: usize) -> bool {
    if sparse_pure_cond(pr, s, cond) {
        return true;
    }
    if let FlowKind::Basic(bid) = s.blocks[cond].kind {
        let no_side_effects = s.gotos.get(&bid).is_none_or(|g| g.is_empty())
            && pr.f.block(bid).ops.iter().all(|&op| {
                let o = pr.f.op(op);
                o.is_dead() || o.is_marker() || !matches!(o.code(), OpCode::Store | OpCode::Call | OpCode::Callind | OpCode::Callother | OpCode::Return | OpCode::Branchind)
            });
        if no_side_effects {
            if d > 0 {
                pr.arms.sparse_switch.hoist_pending.borrow_mut().push(cond);
            }
            return true;
        }
    }
    false
}

/// A condition node that holds only its compare chain (no statements of its own).
fn sparse_pure_cond(pr: &PrintC<'_>, s: &Structured, node: usize) -> bool {
    match s.blocks[node].kind {
        FlowKind::Basic(bid) => {
            let ops: Vec<OpId> = pr.f.block(bid).ops.iter().copied().filter(|&op| !pr.f.op(op).is_dead() && !pr.f.op(op).is_marker()).collect();
            // every live op feeds the branch: no side effect, and every output consumed inside
            // the block — the scrutinee's own re-load / address / piece ops qualify, a value a
            // body reads does not
            let pure = ops.iter().all(|&op| {
                let o = pr.f.op(op);
                if matches!(o.code(), OpCode::Store | OpCode::Call | OpCode::Callind | OpCode::Callother | OpCode::Return | OpCode::Branch | OpCode::Branchind) {
                    return false;
                }
                o.output.map_or(true, |out| pr.f.vn(out).descend.iter().all(|u| ops.contains(u) || pr.f.op(*u).is_dead()))
            });
            if !pure {
                debug!(crate::debug::Topic::SparseSwitch, "  impure cond block {bid:?}: {:?}", ops.iter().map(|&op| pr.f.op(op).code()).collect::<Vec<_>>());
            }
            pure
        }
        FlowKind::CondAnd | FlowKind::CondOr => s.blocks[node].components.iter().all(|&c| sparse_pure_cond(pr, s, c)),
        _ => false,
    }
}

/// A basic-block node whose only content is an unconditional goto: its target.
fn sparse_goto_only(pr: &PrintC<'_>, s: &Structured, node: usize) -> Option<BlockId> {
    let FlowKind::Basic(bid) = s.blocks[node].kind else { return None };
    let live = pr.f.block(bid).ops.iter().any(|&op| !pr.f.op(op).is_dead() && !pr.f.op(op).is_marker() && pr.f.op(op).code() != OpCode::Branch);
    if live {
        return None;
    }
    let recs = s.node_gotos.get(&node)?;
    let r = recs.first()?;
    (!r.conditional && !r.is_break).then_some(r.target)
}

/// The structured node a jump into block `b` lands on: the outermost list/if/condition
/// group entered at `b` (0x4fbcc's default body `if ((p < lo) || ..) {..}; ..` is entered at
/// its condition's first block), stopping below the tree's own root.
fn sparse_body_node(pr: &PrintC<'_>, s: &Structured, b: BlockId) -> Option<usize> {
    let root = pr.arms.sparse_switch.root.get();
    let tail = pr.arms.sparse_switch.tail.get();
    let mut n = s.blocks.iter().position(|fb| fb.kind == FlowKind::Basic(b))?;
    // the switch's exit is the exit, never a body (a leaf landing there is an empty case)
    if Some(b) == tail {
        return Some(n);
    }
    let holds_tail = |node: usize| -> bool {
        let mut basics = Vec::new();
        collect_basics(s, node, &mut basics);
        tail.is_some_and(|t| basics.contains(&t))
    };
    while let Some(p) = s.blocks[n].parent {
        if p == root || !matches!(s.blocks[p].kind, FlowKind::List | FlowKind::If | FlowKind::IfElse | FlowKind::CondAnd | FlowKind::CondOr) || entry_basic(s, p) != Some(b) {
            break;
        }
        // a node that runs on past the switch's exit is the code AFTER the switch (0x4822c's
        // `[A-if, LAB]` list, 0x29dcc's shared `LAB_00029ee2:` continuation), not a body
        if holds_tail(p) {
            break;
        }
        let mut anc = s.blocks[root].parent;
        let mut is_anc = false;
        while let Some(a) = anc {
            if a == p { is_anc = true; break; }
            anc = s.blocks[a].parent;
        }
        if is_anc {
            break;
        }
        n = p;
    }
    Some(n)
}

/// The CBRANCH condition of a basic-block node.
fn sparse_cbranch_cond(pr: &PrintC<'_>, s: &Structured, node: usize) -> Option<VarnodeId> {
    let FlowKind::Basic(bid) = s.blocks[node].kind else { return None };
    let cb = pr.f.block(bid).ops.iter().rev().copied().find(|&op| !pr.f.op(op).is_dead() && pr.f.op(op).code() == OpCode::Cbranch)?;
    pr.f.op(cb).input(1)
}

/// A node whose CBRANCH edge the collapse cut to a conditional `goto` (`if (u != 1) goto LAB;`):
/// the target and whether the jump is taken when the node's condition is true (a record's
/// `negated` prints `if (!cond) goto`: the jump sits on the false edge). `allow_break` admits
/// the `break;` reclassification of a loop-exit edge.
fn sparse_cond_goto(_pr: &PrintC<'_>, s: &Structured, node: usize, allow_break: bool) -> Option<(BlockId, bool)> {
    let recs = match s.blocks[node].kind {
        FlowKind::Basic(bid) => s.gotos.get(&bid).or_else(|| s.node_gotos.get(&node))?,
        FlowKind::CondAnd | FlowKind::CondOr => exit_basic(s, node).and_then(|eb| s.gotos.get(&eb)).or_else(|| s.node_gotos.get(&node))?,
        _ => return None,
    };
    let r = recs.iter().find(|r| r.conditional && (allow_break || !r.is_break))?;
    Some((r.target, !r.negated))
}

fn sparse_is_bare_return(pr: &PrintC<'_>, s: &Structured, node: usize) -> bool {
    let FlowKind::Basic(bid) = s.blocks[node].kind else { return false };
    // the epilogue's register restores are COPYs that never print; the statement is `return;`
    let live: Vec<OpId> = pr.f.block(bid).ops.iter().copied().filter(|&op| !pr.f.op(op).is_dead() && !pr.f.op(op).is_marker() && pr.f.op(op).code() != OpCode::Copy).collect();
    live.len() == 1 && pr.f.op(live[0]).code() == OpCode::Return
}

/// The arm's state: its configuration and the walk's working state, one place (review R2,
/// commit 7). The walk keeps interior-mutable cells because it runs through `&PrintC` readers.
#[derive(Debug)]
pub(crate) struct State {
    /// `sparse-switch=switch` is on for this function.
    pub(crate) switch: bool,
    /// The node the switch being printed hangs from (`usize::MAX` = none).
    pub(crate) root: std::cell::Cell<usize>,
    /// The switch's tail block, when its body flows into one.
    pub(crate) tail: std::cell::Cell<Option<BlockId>>,
    /// The walk's stack of enclosing unconditional gotos (see `SparseLeaf::exit_goto`).
    pub(crate) exit_goto: std::cell::RefCell<Vec<BlockId>>,
    /// Statements hoisted ahead of the switch head.
    pub(crate) head_stmts: std::cell::RefCell<Vec<usize>>,
    /// Nodes whose hoist is pending.
    pub(crate) hoist_pending: std::cell::RefCell<Vec<usize>>,
    /// Overrides recorded during a `&PrintC` walk, applied at the next `&mut` point.
    pub(crate) cond_override_pending: std::cell::RefCell<Vec<(usize, usize)>>,
}

impl State {
    pub(crate) fn new(choices: &crate::decompile::emit::EmitChoices) -> Self {
        State {
            switch: choices.sparse_switch == crate::decompile::emit::SparseSwitch::Switch,
            root: std::cell::Cell::new(usize::MAX),
            tail: std::cell::Cell::new(None),
            exit_goto: std::cell::RefCell::new(Vec::new()),
            head_stmts: std::cell::RefCell::new(Vec::new()),
            hoist_pending: std::cell::RefCell::new(Vec::new()),
            cond_override_pending: std::cell::RefCell::new(Vec::new()),
        }
    }
}
