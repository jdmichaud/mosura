//! Variable merging — Ghidra's `Merge`/`HighVariable` (`merge.cc`, `variable.cc`). Groups
//! the SSA Varnodes that represent one C variable into a [`HighVariable`], so the printer
//! emits one named variable instead of many SSA versions.
//!
//! P5 increment 1: the [`HighVariables`] union-find and the *required* marker merges
//! (`mergeMarker`) — a MULTIEQUAL/INDIRECT output is the same variable as its inputs, which
//! threads a value's SSA versions across control flow into one variable (loop counters,
//! merged conditionals). Cover-based merging of non-interfering same-storage varnodes, and
//! naming, are the next increments.

use std::cmp::Ordering;
use std::collections::HashMap;

use super::block::BlockId;
use super::cover::{all_covers, extended_cover, op_positions, Cover, OpPositions};
use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;
use super::space::{Address, SpaceId};
use super::types::{type_order, Datatype};
use super::varnode::VarnodeId;

/// Ghidra `max_implied_ref` (architecture.cc:1420) — the descendant-count ceiling above which
/// `ActionMarkExplicit::baseExplicit` (coreaction.cc:3078) forces a value explicit. A value with
/// `2..=max_implied_ref` descendants is a `multlist` member whose explicitness the term-duplication
/// machinery decides.
const MAX_IMPLIED_REF: usize = 2;

/// Ghidra `ActionMarkExplicit::baseExplicit`'s reference limit for `v` (coreaction.cc:3047): the
/// architecture's `max_implied_ref`, lifted to 1000000 for a PTRSUB of the spacebase (a constant
/// or input stack pointer) — "Should always be implicit, so remove limit on max references".
fn max_implied_ref(f: &Funcdata, v: VarnodeId) -> usize {
    match f.vn(v).def.filter(|&d| f.op(d).code() == OpCode::Ptrsub) {
        Some(d) => match f.op(d).input(0) {
            Some(b) if f.vn(b).is_spacebase() && (f.vn(b).is_constant() || f.vn(b).is_input()) => 1_000_000,
            _ => MAX_IMPLIED_REF,
        },
        None => MAX_IMPLIED_REF,
    }
}
/// Ghidra `max_term_duplication` (architecture.cc:1421) — a multi-use value whose expression has at
/// most this many explicit terms stays *implied* and is duplicated at each use rather than named
/// (`ActionMarkExplicit::processMultiplier`, coreaction.cc:3166).
const MAX_TERM_DUPLICATION: i32 = 2;

/// A union-find over Varnodes: each class is one HighVariable (one C variable).
#[derive(Clone)]
pub struct HighVariables {
    parent: Vec<u32>,
    /// The member Varnodes of each class, indexed by its ROOT — Ghidra's
    /// `HighVariable::inst` (variable.hh:137), which `HighIntersectTest` reads directly.
    ///
    /// Without it, a class's membership can only be recovered by scanning every Varnode in the
    /// function and testing `high(v) == rep`. The merge tests ask for a handful of classes tens
    /// of thousands of times per function, so that scan was the dominant cost of the whole merge
    /// family. Maintaining it on `union` — the same place Ghidra concatenates `inst` in
    /// `mergeInternal` (variable.cc:626) — makes a lookup cost the class, not the function.
    ///
    /// Non-root entries are left empty; only `members[root]` is meaningful. Path halving in
    /// [`Self::find`] never changes which node is the root, so the index stays valid.
    members: Vec<Vec<VarnodeId>>,
}

impl HighVariables {
    fn new(n: usize) -> HighVariables {
        HighVariables {
            parent: (0..n as u32).collect(),
            members: (0..n as u32).map(|i| vec![VarnodeId(i)]).collect(),
        }
    }

    /// Grow the union-find to cover `n` varnodes: each new varnode starts as its own
    /// HighVariable (Ghidra allocates a fresh HighVariable per new Varnode). Used by the
    /// graph-mutating marker merge, whose trims create new COPY outputs mid-pass.
    pub(crate) fn extend_to(&mut self, n: usize) {
        let old = self.parent.len() as u32;
        self.parent.extend(old..n as u32);
        self.members.extend((old..n as u32).map(|i| vec![VarnodeId(i)]));
    }

    fn find(&mut self, mut x: u32) -> u32 {
        while self.parent[x as usize] != x {
            self.parent[x as usize] = self.parent[self.parent[x as usize] as usize]; // halving
            x = self.parent[x as usize];
        }
        x
    }

    fn union(&mut self, a: u32, b: u32) {
        if let Ok(watch) = std::env::var("MOSURA_MERGE_WATCH") {
            MERGE_PHASE.with(|ph| {
                let _ = ph; // used in the print below
            });
            if let Ok(w) = u32::from_str_radix(watch.trim_start_matches("0x"), 16) {
                if self.find(a) == self.find(w) || self.find(b) == self.find(w) || a == w || b == w {
                    MERGE_PHASE.with(|ph| debug!(crate::debug::Topic::Merge, "union {a} <- {b} (watch {w}) phase {}", ph.get()));
                }
            }
        }
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb {
            self.parent[ra as usize] = rb;
            // Ghidra `HighVariable::mergeInternal` (variable.cc:626) appends the absorbed
            // variable's instances to the survivor's. Same here, so the index tracks `parent`.
            //
            // Kept ASCENDING by VarnodeId: every reader below replaced a `0..num_varnodes` scan,
            // and two of them are order-sensitive (`piece_rep` takes the FIRST match,
            // `high_props`'s `tied` keeps the LAST). Both lists are already sorted, so this is a
            // linear merge, not a sort.
            let a = std::mem::take(&mut self.members[ra as usize]);
            let b = std::mem::take(&mut self.members[rb as usize]);
            let mut m = Vec::with_capacity(a.len() + b.len());
            let (mut i, mut j) = (0, 0);
            while i < a.len() && j < b.len() {
                if a[i].0 <= b[j].0 {
                    m.push(a[i]);
                    i += 1;
                } else {
                    m.push(b[j]);
                    j += 1;
                }
            }
            m.extend_from_slice(&a[i..]);
            m.extend_from_slice(&b[j..]);
            self.members[rb as usize] = m;
        }
    }

    /// The members of the class rooted at `rep`, in the order they were unioned.
    ///
    /// Returned by value: the callers hold several classes at once (the merge testlist) and
    /// cannot keep multiple borrows of `self` alive across `high()`, which needs `&mut` for path
    /// compression. A class is small; the function is not — that is the whole point.
    pub(crate) fn class_of(&mut self, rep: u32) -> Vec<VarnodeId> {
        self.members[rep as usize].clone()
    }

    /// The HighVariable id of a varnode (its union-find representative).
    pub fn high(&mut self, v: VarnodeId) -> u32 {
        self.find(v.0)
    }

    /// Whether two varnodes belong to the same HighVariable.
    pub fn same(&mut self, a: VarnodeId, b: VarnodeId) -> bool {
        self.find(a.0) == self.find(b.0)
    }

    /// The number of distinct HighVariables among the given varnodes.
    pub fn count(&mut self, vns: impl IntoIterator<Item = VarnodeId>) -> usize {
        let mut reps: Vec<u32> = vns.into_iter().map(|v| self.find(v.0)).collect();
        reps.sort_unstable();
        reps.dedup();
        reps.len()
    }
}

/// A varnode that can belong to a HighVariable — not a constant (constants are values, not
/// variables) and not an annotation.
fn mergeable(f: &Funcdata, v: VarnodeId) -> bool {
    let vn = f.vn(v);
    !vn.is_constant() && vn.flags & super::varnode::flags::ANNOTATION == 0
}

/// Build the HighVariables for `f`, in Ghidra's merge-phase order: `ActionMergeRequired`
/// (`coreaction.hh:370`) does `mergeAddrTied(); groupPartials(); mergeMarker();` — address-tied
/// unification (`Merge::mergeAddrTied`) FIRST, then the required marker merges (`Merge::mergeMarker`);
/// then `ActionMergeCopy`'s COPY input/output merges (`Merge::mergeOpcode(COPY)`), then
/// `ActionMergeType`'s speculative cover-based merging of non-interfering same-storage varnodes.
/// (mosura has no `groupPartials` — the VariablePiece debt.) The addrtied-before-marker order matters
/// now that `merge_markers` gates each union on `merge_test_required`: the marker gate must see the
/// address-tied HighVariables already aggregated, exactly as Ghidra does.
pub fn merge(f: &Funcdata) -> (HighVariables, VariablePieces) {
    let mut h = HighVariables::new(f.num_varnodes());
    let covers = all_covers(f);
    let pieces = merge_addrtied(f, &mut h);
    merge_markers(f, &mut h, &pieces);
    // The `ActionMarkExplicit` / `ActionMarkImplied` slot (coreaction.cc:5719-5720, "this must
    // come BEFORE general merging"): classify every varnode explicit-or-implied against the
    // required-merges-only state just built, so the COPY and speculative merges below can apply
    // `mergeTestBasic`'s implied exclusion (merge.cc:255). Without it a trim COPY's single-use
    // input would be fused back into the phi's HighVariable, the COPY would turn internal
    // (unprinted), and the input's def — implied at print time — would silently vanish.
    let explicit = mark_explicit(f, &mut h, &covers);
    // From here the covers are Ghidra's post-classification covers (`Cover::rebuild` through
    // implied consumers): a phi input defined BEFORE a call whose argument is an implied
    // expression of the phi's own value must not merge into the phi (ground truth `fib`:
    // `uVar2 = uVar2 - 2; fib(uVar2 - 1)` read the decremented value — wrong code).
    let covers = super::cover::all_covers_extended(f, &explicit);
    merge_copy(f, &mut h, &pieces, &covers, &explicit);
    merge_adjacent(f, &mut h, &pieces, &covers, &explicit);
    merge_same_storage(f, &mut h, &pieces, &covers, &explicit);
    (h, pieces)
}

/// Ghidra `ActionMarkImplied` (coreaction.cc:3416) as a standalone per-varnode classification:
/// `true` where a value is *implied* (folded inline into its use, no named declaration). This is the
/// `Varnode::isImplied` state Ghidra's `ActionSetCasts::castOutput` reads — Ghidra runs
/// `ActionMarkImplied` (coreaction.cc:5720) immediately before `ActionSetCasts` (5735). It is the
/// complement of the shared [`mark_explicit`] classifier (the merge-time
/// `ActionMarkExplicit`+`ActionMarkImplied`), evaluated on the required-merges-only HighVariable
/// state — exactly the state Ghidra has at that slot (before the COPY/speculative merges). printc's
/// print-time `is_explicit` layers naming-only additions on top; those are a mosura print concern
/// Ghidra's setcasts does not see, so this bare classification is the faithful input to castOutput.
pub fn implied_classification(f: &Funcdata) -> Vec<bool> {
    let mut h = HighVariables::new(f.num_varnodes());
    let covers = all_covers(f);
    let pieces = merge_addrtied(f, &mut h);
    merge_markers(f, &mut h, &pieces);
    mark_explicit(f, &mut h, &covers).into_iter().map(|e| !e).collect()
}

/// Ghidra `ActionMarkExplicit` + `ActionMarkImplied` (coreaction.cc:3237/3416) evaluated at their
/// pipeline slot — between the required merges and the COPY/speculative merges. Returns, per
/// varnode, whether it is *explicit* (a named variable; a merge candidate) as opposed to *implied*
/// (an expression term — excluded from every later merge by `mergeTestBasic`, merge.cc:255).
///
/// The classification is the shared core ([`explicit_leading`]/[`explicit_trailing`]) that printc's
/// print-time `is_explicit` also applies (with its print-only arms layered on top; those arms only
/// ADD explicitness, so merge-explicit ⊆ print-explicit and a value this pass leaves un-merged
/// always materializes in the output).
fn mark_explicit(f: &Funcdata, h: &mut HighVariables, covers: &HashMap<VarnodeId, Cover>) -> Vec<bool> {
    let of: Vec<u32> = (0..f.num_varnodes() as u32).map(|i| h.high(VarnodeId(i))).collect();
    let mut members: HashMap<u32, Vec<VarnodeId>> = HashMap::new();
    for (i, &rep) in of.iter().enumerate() {
        members.entry(rep).or_default().push(VarnodeId(i as u32));
    }
    classify_explicit(f, &of, &of, &members, covers)
}

/// Ghidra `ActionMarkImplied::apply` (coreaction.cc:3416): decide every varnode's
/// explicit/implied state with a depth-first walk that settles DESCENDANTS FIRST ("All
/// descendants are traced first", :3432). The order is load-bearing, not a traversal detail:
/// `check_implied_cover` tests the candidate's cover EXTENDED through consumers already decided
/// implied (`Cover::rebuild`, cover.cc:487 — Ghidra gets the same effect from its lazy
/// cover-dirty rebuild), so whether a LOAD crosses a STORE depends on the decisions made for the
/// expressions consuming it. A flat per-varnode loop got this wrong in whichever direction the
/// arena order happened to run.
fn classify_explicit(
    f: &Funcdata,
    persist_of: &[u32],
    ih_of: &[u32],
    ih_members: &HashMap<u32, Vec<VarnodeId>>,
    covers: &HashMap<VarnodeId, Cover>,
) -> Vec<bool> {
    let ctx = ImpliedCtx::new(f);
    let n = f.num_varnodes();
    let mut decision: Vec<Option<bool>> = vec![None; n];
    let mut in_stack = vec![false; n];
    for i in 0..n as u32 {
        if decision[i as usize].is_some() {
            continue;
        }
        let mut stack: Vec<(VarnodeId, usize)> = vec![(VarnodeId(i), 0)];
        in_stack[i as usize] = true;
        while let Some(&(v, di)) = stack.last() {
            let dlen = f.vn(v).descend.len();
            if di < dlen {
                stack.last_mut().unwrap().1 = di + 1;
                let dop = f.vn(v).descend[di];
                if let Some(out) = f.op(dop).output {
                    let oi = out.0 as usize;
                    // Ghidra pushes only undecided outputs (:3448); `in_stack` guards the phi
                    // back-edges Ghidra's flags make unreachable.
                    if decision[oi].is_none() && !in_stack[oi] {
                        in_stack[oi] = true;
                        stack.push((out, 0));
                    }
                }
            } else {
                if decision[v.0 as usize].is_none() {
                    let e = explicit_leading(f, v).unwrap_or_else(|| {
                        explicit_trailing(f, persist_of, ih_of, ih_members, covers, &ctx, &decision, v)
                    });
                    decision[v.0 as usize] = Some(e);
                }
                in_stack[v.0 as usize] = false;
                stack.pop();
            }
        }
    }
    decision.into_iter().map(|d| d.unwrap_or(true)).collect()
}

/// The leading arms of the explicitness chain (Ghidra `ActionMarkExplicit::baseExplicit`,
/// coreaction.cc:3007): a constant is never explicit; a function input or an address-tied varnode
/// always is — except an addrtied SUBPIECE reading the matching overlap of the same addrtied whole
/// (coreaction.cc:3023-3029), which is an internal copymarker rendered inline. `None` means the
/// decision falls to [`explicit_trailing`].
pub(crate) fn explicit_leading(f: &Funcdata, v: VarnodeId) -> Option<bool> {
    let vn = f.vn(v);
    if vn.is_constant() {
        return Some(false);
    }
    if vn.is_input() {
        return Some(true);
    }
    if vn.is_addrtied() {
        // Address-tied is explicit ("pointers may reference it", coreaction.cc:3022) — EXCEPT two
        // lone-descendant escapes (coreaction.cc:3029-3047) that FALL THROUGH to the ordinary
        // implied heuristics:
        //   - a lone `INT_ZEXT` whose output is itself addrtied and contains this varnode at its
        //     least-significant base (`0 == vnout->contains(*vn)`, :3031-3034);
        //   - a lone `PIECE` where this varnode is NOT the root of its CONCAT tree
        //     (`PieceNode::findRoot`, :3036-3043; the `isPartialRoot` re-assert needs the
        //     protoPartial marking mosura lacks — never set, so the escape stands).
        // Any other use, or several uses, stays explicit. The SUBPIECE `overlapJoin` sub-case
        // (:3023-3028) also answers explicit — same as the default, handled at its print slot by
        // [`copy_marker_nonprinting`].
        //
        // The PIECE escape is load-bearing for byte-granular global updates: a `mov byte [g], 1`
        // into a 4-byte global heritages as `g = PIECE(SUBPIECE(old >> 8), 1)`, and the 3-byte
        // SUBPIECE output lands at the global's address+1 — addrtied. Ghidra marks it IMPLIED
        // (measured on WAR2 FUN_00021b84's site with `CAPTURE_FLAGS_AT`: `ram:0x8196d:3
        // addrtied=1 ... explicit=0 implied=1`) and prints it inline, `CONCAT31((unkint3)uVar4,
        // 1)`. Marking it explicit instead materialized the statement `uRam._1_3_ = …` — the
        // partial-symbol accessor whose 3-byte width no emitter rewrite can legalize (the WAR2
        // E1032 family).
        let use_op = match vn.descend.as_slice() {
            [only] => *only,
            _ => return Some(true),
        };
        match f.op(use_op).code() {
            OpCode::IntZext => {
                let Some(out) = f.op(use_op).output else { return Some(true) };
                let outvn = f.vn(out);
                // `Varnode::contains` == 0: same space, same start offset (the LE least-
                // significant base), and this varnode fits inside the output's storage.
                let contains_at_base = outvn.is_addrtied()
                    && outvn.loc.space == vn.loc.space
                    && outvn.loc.offset == vn.loc.offset
                    && vn.size <= outvn.size;
                if !contains_at_base {
                    return Some(true);
                }
            }
            OpCode::Piece => {
                if piece_find_root(f, v) == v {
                    return Some(true);
                }
            }
            _ => return Some(true),
        }
        return None; // fall through to the trailing/implied heuristics (coreaction.cc:3049…)
    }
    None
}

/// Ghidra `PieceNode::findRoot` (op.cc:824): from an addrtied (or protoPartial) varnode, climb
/// through the `PIECE` op whose output's storage CONTAINS it at the matching position — for little
/// endian, the low piece (slot 1) sits at the output's own address and the high piece (slot 0) at
/// `output + sizeof(low)` (op.cc:836-838) — to the maximal containing varnode of the CONCAT tree.
/// Among several position-matching `PIECE` readers Ghidra attaches to the earliest
/// (`PcodeOp::compareOrder`, :841-846); mosura compares block-schedule position within a shared
/// block and keeps the first candidate across blocks (the cross-block tie needs a dominator walk
/// no merge-phase caller carries; a piece feeding position-matched PIECEs in two different blocks
/// reconverges to the same root either way). mosura has no protoPartial marking, so only the
/// addrtied climb is live, and no join space, so the `renormalize` is a no-op.
fn piece_find_root(f: &Funcdata, v: VarnodeId) -> VarnodeId {
    let mut v = v;
    while f.vn(v).is_addrtied() {
        let vn = f.vn(v);
        let mut piece_op: Option<OpId> = None;
        for &d in &vn.descend {
            let op = f.op(d);
            if op.code() != OpCode::Piece {
                continue;
            }
            let Some(out) = op.output else { continue };
            let slot = if op.input(0) == Some(v) { 0usize } else { 1 };
            let mut addr = f.vn(out).loc;
            if slot == 0 {
                let Some(sib) = op.input(1) else { continue };
                addr.offset = addr.offset.wrapping_add(f.vn(sib).size as u64);
            }
            if addr == vn.loc {
                piece_op = match piece_op {
                    None => Some(d),
                    Some(prev) => {
                        let (pa, pb) = (f.op(d).parent, f.op(prev).parent);
                        if pa == pb && pa.is_some() {
                            let bl = f.block(pa.unwrap());
                            let pos = |o| bl.ops.iter().position(|&x| x == o);
                            if pos(d) < pos(prev) { Some(d) } else { Some(prev) }
                        } else {
                            Some(prev)
                        }
                    }
                };
            }
        }
        match piece_op.and_then(|p| f.op(p).output) {
            Some(out) => v = out,
            None => break,
        }
    }
    v
}

/// The trailing arms of the explicitness chain (`baseExplicit`'s written/marker/use-count terms
/// plus `ActionMarkImplied::checkImpliedCover`, coreaction.cc:3376): marker/call outputs are always
/// named; PTRADD/PTRSUB stay inline; a cross-high COPY of a persistent global materializes; a
/// multi-use value is named; a single-use value stays implied unless inlining it would read a
/// HighVariable instance redefined between def and use (the implied-cover conflict), or it feeds a
/// marker standing for the same variable. `persist_of` is the HighVariable state for the
/// cross-high COPY arm (printc passes its full-merge classes; the merge-time classifier the
/// required-only ones); `ih_of`/`ih_members` are the required-merges-only classes
/// `Merge::inflateTest` walks.
pub(crate) fn explicit_trailing(
    f: &Funcdata,
    persist_of: &[u32],
    ih_of: &[u32],
    ih_members: &HashMap<u32, Vec<VarnodeId>>,
    covers: &HashMap<VarnodeId, Cover>,
    ctx: &ImpliedCtx,
    decision: &[Option<bool>],
    v: VarnodeId,
) -> bool {
    let vn = f.vn(v);
    if !vn.is_written() {
        return true;
    }
    if let Some(def) = vn.def {
        // a phi is a merged variable, an INDIRECT is an opaque `extraout_*`, and a CALL's return
        // value is always named (`baseExplicit`, coreaction.cc:3015 `def->isCall()` — the call
        // FLAG, which `TypeOpCallother` also sets, typeop.cc:814: a userop's result, e.g.
        // `in(0x21)`, is named exactly like a call's).
        if matches!(
            f.op(def).code(),
            OpCode::Multiequal | OpCode::Indirect | OpCode::Call | OpCode::Callind | OpCode::Callother
        ) {
            return true;
        }
        // (A former mosura-only arm declared every PTRADD/PTRSUB implied outright. Ghidra has no
        // such exemption: `baseExplicit` only lifts the reference LIMIT for a PTRSUB of the
        // spacebase (`max_implied_ref`), and `ActionMarkImplied::checkImpliedCover` still decides —
        // ground truth `slen`: the address `param_1 + iVar3` is read at the loop's CBRANCH, after
        // the back-edge COPY redefines `iVar3`, so Ghidra names it `pcVar1 = param_1 + iVar3;`
        // where the shortcut printed `while (param_1[iVar1] != '\0')` on the incremented index.)
        // The snapshot COPY of an address-tied persistent value read before its address is
        // overwritten stays cross-high and must render as an explicit `iVar = <snapshot>`.
        if f.op(def).code() == OpCode::Copy {
            if let Some(inv) = f.op(def).input(0) {
                if f.vn(inv).is_persist()
                    && persist_of[v.0 as usize] != persist_of[inv.0 as usize]
                {
                    return true;
                }
            }
        }
    }
    // Ghidra `ActionMarkExplicit::baseExplicit`'s descendant-count arms (coreaction.cc:3064/3078):
    // a value with no descendants, or more than `max_implied_ref` of them, is named.
    let dn = vn.descend.len();
    if dn == 0 || dn > max_implied_ref(f, v) {
        return true;
    }
    if dn > 1 {
        // A `multlist` member (`ActionMarkExplicit`, coreaction.cc:3256): `2..=max_implied_ref`
        // descendants. A value feeding a MULTIEQUAL/INDIRECT is the merged variable itself
        // (baseExplicit's marker-descendant bail, :3076). Otherwise the `multipleInteraction`
        // flow-into rule (:3091) and the `processMultiplier` term count (:3166) decide, falling
        // through to the same implied-cover test as the single-use case. (A former mosura-only
        // arm forced every multi-use LOAD explicit while checkImpliedCover's LOAD arms were
        // unported; those arms are now real, so the conservative arm is retired and Ghidra's own
        // test decides — Ghidra freely duplicates `iVar7 + -1` from an inline LOAD when no store
        // intervenes.)
        if vn.descend.iter().any(|&u| f.op(u).is_marker()) {
            return true;
        }
        if is_purged_top(f, persist_of, v) {
            return true;
        }
        if process_multiplier(f, persist_of, v, MAX_TERM_DUPLICATION) {
            return true;
        }
        return !check_implied_cover(f, ih_of, ih_members, covers, ctx, decision, v);
    }
    // Single use (`dn == 1`): a MARKER reader makes the value explicit — Ghidra `baseExplicit`'s
    // descendant loop, coreaction.cc:3073 `if (op->isMarker()) return -1`, for ANY marker. (A
    // former mosura arm accepted an INDIRECT reader only when its output had the same storage;
    // the trim COPY `Merge::trimOpInput` puts on a passthrough INDIRECT's input has a unique
    // output, so `iVar1 = param_2;` before the call was never printed and `iVar1` read
    // uninitialized — ground truth `globals`' `event`, the value carried across `note()`.)
    // Otherwise inline unless the implied-cover test fails.
    let user = vn.descend[0];
    if f.op(user).is_marker() {
        return true;
    }
    !check_implied_cover(f, ih_of, ih_members, covers, ctx, decision, v)
}

/// Ghidra `ActionMarkImplied::isPossibleAliasStep` (coreaction.cc:3279): if either pointer is
/// `other + <non-constant>` (through INT_ADD/PTRSUB/PTRADD/INT_XOR), the two provably differ.
fn is_possible_alias_step(f: &Funcdata, vn1: VarnodeId, vn2: VarnodeId) -> bool {
    let var = [vn1, vn2];
    for i in 0..2 {
        let Some(def) = f.vn(var[i]).def else { continue };
        let opc = f.op(def).code();
        if !matches!(opc, OpCode::IntAdd | OpCode::Ptrsub | OpCode::Ptradd | OpCode::IntXor) {
            continue;
        }
        if f.op(def).input(0) != Some(var[1 - i]) {
            continue;
        }
        if f.op(def).input(1).is_some_and(|c| f.vn(c).is_constant()) {
            return false;
        }
    }
    true
}

/// Ghidra `ActionMarkImplied::isPossibleAlias` (coreaction.cc:3303): false ONLY when the two
/// pointer expressions provably hold different values, recursing to `depth` through matching
/// COPY/extension/negation wrappers and INT_ADD/PTRSUB/PTRADD terms.
fn is_possible_alias(f: &Funcdata, vn1: VarnodeId, vn2: VarnodeId, depth: u32) -> bool {
    if vn1 == vn2 {
        return true; // Definite alias
    }
    if !f.vn(vn1).is_written() || !f.vn(vn2).is_written() {
        if f.vn(vn1).is_constant() && f.vn(vn2).is_constant() {
            return f.vn(vn1).loc.offset == f.vn(vn2).loc.offset;
        }
        return is_possible_alias_step(f, vn1, vn2);
    }
    if !is_possible_alias_step(f, vn1, vn2) {
        return false;
    }
    let op1 = f.vn(vn1).def.unwrap();
    let op2 = f.vn(vn2).def.unwrap();
    let (mut opc1, mut mult1) = (f.op(op1).code(), 1i64);
    let (mut opc2, mut mult2) = (f.op(op2).code(), 1i64);
    if opc1 == OpCode::Ptrsub {
        opc1 = OpCode::IntAdd;
    } else if opc1 == OpCode::Ptradd {
        opc1 = OpCode::IntAdd;
        mult1 = f.op(op1).input(2).map_or(1, |c| f.vn(c).loc.offset as i32 as i64);
    }
    if opc2 == OpCode::Ptrsub {
        opc2 = OpCode::IntAdd;
    } else if opc2 == OpCode::Ptradd {
        opc2 = OpCode::IntAdd;
        mult2 = f.op(op2).input(2).map_or(1, |c| f.vn(c).loc.offset as i32 as i64);
    }
    if opc1 != opc2 {
        return true;
    }
    if depth == 0 {
        return true; // Couldn't find absolute difference
    }
    let depth = depth - 1;
    match opc1 {
        OpCode::Copy | OpCode::IntZext | OpCode::IntSext | OpCode::Int2comp | OpCode::IntNegate => {
            is_possible_alias(f, f.op(op1).input(0).unwrap(), f.op(op2).input(0).unwrap(), depth)
        }
        OpCode::IntAdd => {
            let (a0, a1) = (f.op(op1).input(0).unwrap(), f.op(op1).input(1).unwrap());
            let (b0, b1) = (f.op(op2).input(0).unwrap(), f.op(op2).input(1).unwrap());
            if f.vn(a1).is_constant() && f.vn(b1).is_constant() {
                let val1 = (mult1 as u64).wrapping_mul(f.vn(a1).loc.offset);
                let val2 = (mult2 as u64).wrapping_mul(f.vn(b1).loc.offset);
                if val1 == val2 {
                    return is_possible_alias(f, a0, b0, depth);
                }
                return !super::rules::functional_equality(f, a0, b0);
            }
            if mult1 != mult2 {
                return true;
            }
            if super::rules::functional_equality(f, a0, b0) {
                return is_possible_alias(f, a1, b1, depth);
            }
            if super::rules::functional_equality(f, a1, b1) {
                return is_possible_alias(f, a0, b0, depth);
            }
            if super::rules::functional_equality(f, a0, b1) {
                return is_possible_alias(f, a1, b0, depth);
            }
            if super::rules::functional_equality(f, a1, b0) {
                return is_possible_alias(f, a0, b1, depth);
            }
            true
        }
        _ => true,
    }
}

/// `ActionMarkImplied::checkImpliedCover`'s LOAD-vs-STORE and load/call-crossing arms
/// (coreaction.cc:3384-3406), against the candidate's cover EXTENDED through implied consumers
/// (`Cover::rebuild`, cover.cc:487 — Ghidra's lazy dirty-bit rebuild sees the descendants'
/// just-decided implied marks; mosura passes the decision state in). A LOAD whose value would
/// print past a STORE to a possibly-aliasing address must be explicit — inlining it would re-read
/// post-write memory (the wrong-VALUE defect worked in
/// docs/decompiler-bug-guarded-store-hoisted.md's follow-up). Same for a LOAD or call result
/// printing past any call. Returns `true` on violation.
fn implied_load_call_violation(
    f: &Funcdata,
    pos: &OpPositions,
    stores: &[OpId],
    calls: &[OpId],
    cov: &Cover,
    v: VarnodeId,
) -> bool {
    let Some(def) = f.vn(v).def else { return false };
    let dcode = f.op(def).code();
    if dcode == OpCode::Load {
        for &st in stores {
            let Some((b, j)) = pos.get(st) else { continue };
            if !cov.contains_op_interior(b, 2 * j as i32 + 1) {
                continue;
            }
            // The LOAD crosses a STORE. Ghidra is "cavalier and lets it through unless we can
            // verify that the pointers are actually the same": same address space, and the
            // pointers possibly alias at depth 2.
            let (Some(s_spc), Some(l_spc)) = (f.op(st).input(0), f.op(def).input(0)) else {
                continue;
            };
            if f.vn(s_spc).loc.offset != f.vn(l_spc).loc.offset {
                continue;
            }
            let (Some(s_ptr), Some(l_ptr)) = (f.op(st).input(1), f.op(def).input(1)) else {
                continue;
            };
            if is_possible_alias(f, s_ptr, l_ptr, 2) {
                return true;
            }
        }
    }
    if dcode == OpCode::Load || f.op(def).is_call() {
        for &c in calls {
            let Some((b, j)) = pos.get(c) else { continue };
            if cov.contains_op_interior(b, 2 * j as i32 + 1) {
                return true;
            }
        }
    }
    false
}

/// Positioning and op inventory shared across one classification run: op positions plus the live
/// STOREs and calls the LOAD/call-crossing arms scan.
pub(crate) struct ImpliedCtx {
    pos: OpPositions,
    stores: Vec<OpId>,
    calls: Vec<OpId>,
}

impl ImpliedCtx {
    fn new(f: &Funcdata) -> Self {
        let pos = op_positions(f);
        let (mut stores, mut calls) = (Vec::new(), Vec::new());
        for op in f.op_ids() {
            let o = f.op(op);
            if o.is_dead() {
                continue;
            }
            match o.code() {
                OpCode::Store => stores.push(op),
                // Ghidra's crossing test is `op->isCall()` (checkImpliedCover, the call FLAG) —
                // CALLOTHER carries it too (typeop.cc:814): a userop with side effects (port I/O)
                // blocks inlining a load/persist read across it exactly like a CALL.
                OpCode::Call | OpCode::Callind | OpCode::Callother => calls.push(op),
                _ => {}
            }
        }
        ImpliedCtx { pos, stores, calls }
    }
}

/// Ghidra `ActionMarkImplied::checkImpliedCover` (coreaction.cc:3376), all three arms in Ghidra's
/// order: LOAD-vs-STORE, load/call-crossing, then the input inflate arm ([`implied_cover_ok`]).
/// The first two test the candidate's cover EXTENDED through already-decided implied consumers,
/// which is why classification runs descendants-first ([`classify_explicit`]). Returns `true`
/// when the value may stay implied.
fn check_implied_cover(
    f: &Funcdata,
    ih_of: &[u32],
    ih_members: &HashMap<u32, Vec<VarnodeId>>,
    covers: &HashMap<VarnodeId, Cover>,
    ctx: &ImpliedCtx,
    decision: &[Option<bool>],
    v: VarnodeId,
) -> bool {
    let load_or_call =
        f.vn(v).def.is_some_and(|d| f.op(d).code() == OpCode::Load || f.op(d).is_call());
    if load_or_call {
        let ext = extended_cover(f, v, &ctx.pos, &|x| decision[x.0 as usize] == Some(false));
        if implied_load_call_violation(f, &ctx.pos, &ctx.stores, &ctx.calls, &ext, v) {
            return false;
        }
    }
    // Ghidra's `inflateTest(defvn, vn->getHigh())` reads the candidate's cover as `Cover::rebuild`
    // leaves it (cover.cc:477): extended through every consumer already decided IMPLIED, because
    // an implied expression is evaluated where its implied consumer is, not where it was defined.
    // `sum_to` (ground truth): `EDX_next = EDX_phi + 1` feeds an implied compare whose CBRANCH
    // sits at the block end, PAST the back-edge COPY into the phi's own variable; on the plain
    // cover the redefinition was invisible, the add went implied, and the C read
    // `iVar3 = iVar3 + 1; } while (n+1 != iVar3 + 1)` — a double increment, wrong code.
    let ext = extended_cover(f, v, &ctx.pos, &|x| decision[x.0 as usize] == Some(false));
    implied_cover_ok(f, ih_of, ih_members, covers, &ext, v)
}

/// `ActionMarkImplied::checkImpliedCover` (coreaction.cc:3376) input-cover arm, via `Merge::
/// inflateTest`: a value can stay implied only if no def-op input's HighVariable has ANOTHER live
/// instance whose range intersects the value's own cover — otherwise the inlined expression would
/// read a value REDEFINED between its def and its use. Copy shadows / partial-piece copy shadows of
/// the input are exempt. Returns `true` when the value can be implied (no cover violation).
///
/// The LOAD-vs-STORE and load/call-crossing arms (:3384-3406) live in [`check_implied_cover`],
/// which runs them against the implied-extended cover before falling through to this arm.
/// ("Single-use LOADs matched Ghidra without them" was believed and is false — the post-store
/// re-read defect in docs/decompiler-bug-guarded-store-hoisted.md was exactly a single-use LOAD
/// implied across an aliasing STORE.)
fn implied_cover_ok(
    f: &Funcdata,
    ih_of: &[u32],
    ih_members: &HashMap<u32, Vec<VarnodeId>>,
    covers: &HashMap<VarnodeId, Cover>,
    vcov: &Cover,
    v: VarnodeId,
) -> bool {
    let vn = f.vn(v);
    if let Some(def) = vn.def {
        for slot in 0..f.op(def).num_inputs() {
            let Some(defvn) = f.op(def).input(slot) else { continue };
            if f.vn(defvn).is_constant() {
                continue;
            }
            let Some(members) = ih_members.get(&ih_of[defvn.0 as usize]) else {
                continue;
            };
            for &b in members {
                if b == defvn || copy_shadow(f, defvn, b) {
                    continue;
                }
                // Cross-size members of mosura's address-tied class stand in for Ghidra's
                // VariablePiece group; inflateTest's piece branch exempts partial copy shadows
                // (`b->partialCopyShadow(a, off)`, merge.cc) — a SUBPIECE/PIECE of the same value
                // is not a redefinition.
                if f.vn(b).size != f.vn(defvn).size
                    && f.vn(b).loc.space == f.vn(defvn).loc.space
                    && super::mergesnip::partial_copy_shadow(
                        f,
                        defvn,
                        b,
                        (f.vn(defvn).loc.offset as i64 - f.vn(b).loc.offset as i64) as i32,
                    )
                {
                    continue;
                }
                if covers.get(&b).is_some_and(|bc| bc.intersects(vcov)) {
                    if crate::debug::on(crate::debug::Topic::Merge) {
                        let pc = |x: VarnodeId| f.vn(x).def.map_or(0, |d| f.op(d).seqnum.pc.offset);
                        let blk = |x: VarnodeId| f.vn(x).def.and_then(|d| f.op(d).parent).map_or(9999, |b| b.0);
                        let bc = covers.get(&b).unwrap();
                        let shared: Vec<String> = (0..f.num_blocks()).filter_map(|blk_i| {
                            let r1 = vcov.block_range(blk_i)?; let r2 = bc.block_range(blk_i)?;
                            Some(format!("b{blk_i}:v{r1:?}/b{r2:?}"))
                        }).collect();
                        let readers: Vec<String> = f.vn(b).descend.iter().map(|&r| {
                            let rb = f.op(r).parent.map_or(9999, |x| x.0);
                            let ins: Vec<u32> = f.op(r).parent.map_or(vec![], |x| f.blocks()[x.0 as usize].in_edges.iter().map(|e| e.0).collect());
                            let g = if f.op(r).code() == OpCode::Indirect { f.op(r).guarded_op().map(|g| format!("g={:?}@{:#x}/blk{}", f.op(g).code(), f.op(g).seqnum.pc.offset, f.op(g).parent.map_or(9999, |x| x.0))).unwrap_or_default() } else { String::new() };
                            format!("{:?}@{:#x}/blk{}<-{:?} {}", f.op(r).code(), f.op(r).seqnum.pc.offset, rb, ins, g)
                        }).collect();
                        debug!(crate::debug::Topic::Merge,
                            "implied v={:?}@{:#x} blk{} defvn={:?}@{:#x}/{:#x} intersects b={:?}@{:#x}/{:#x} blk{} ({}) readers=[{}] [{}]",
                            f.op(def).code(), f.op(def).seqnum.pc.offset, blk(v), defvn, pc(defvn), f.vn(defvn).loc.offset, b, pc(b), f.vn(b).loc.offset, blk(b),
                            f.vn(b).def.map_or("input".into(), |d| format!("{:?}", f.op(d).code())), readers.join(","), shared.join(" ")
                        );
                    }
                    return false;
                }
            }
        }
    }
    true
}

/// Whether `v` is a `multlist` member — Ghidra `ActionMarkExplicit::baseExplicit` returning a
/// descendant count in `2..=max_implied_ref` (coreaction.cc:3256, the varnodes `setMark`'d). Mirrors
/// the leading arms of [`explicit_leading`]/[`explicit_trailing`]: not a constant/input/addrtied
/// value, written by a non-marker/non-call/non-pointer op, with no marker descendant and
/// `2..=max_implied_ref` descendants (the limit lifted for a spacebase PTRSUB, `max_implied_ref`).
fn is_mark_candidate(f: &Funcdata, persist_of: &[u32], v: VarnodeId) -> bool {
    if explicit_leading(f, v).is_some() {
        return false;
    }
    let vn = f.vn(v);
    let Some(def) = vn.def.filter(|_| vn.is_written()) else { return false };
    match f.op(def).code() {
        OpCode::Multiequal | OpCode::Indirect | OpCode::Call | OpCode::Callind | OpCode::Callother => return false,
        OpCode::Copy => {
            if let Some(inv) = f.op(def).input(0) {
                if f.vn(inv).is_persist() && persist_of[v.0 as usize] != persist_of[inv.0 as usize] {
                    return false;
                }
            }
        }
        _ => {}
    }
    if vn.descend.iter().any(|&u| f.op(u).is_marker()) {
        return false;
    }
    let dn = vn.descend.len();
    dn > 1 && dn <= max_implied_ref(f, v)
}

/// Whether `v` is already \e explicit as `processMultiplier` sees it — Ghidra's `Varnode::isExplicit`
/// at that pipeline point: the values `baseExplicit` set explicit (its leading / marker / pointer /
/// count arms) plus any `multipleInteraction` purged. A not-yet-decided `multlist` member or
/// single-use candidate returns false, so the term walk recurses into its expression.
fn is_core_explicit(f: &Funcdata, persist_of: &[u32], v: VarnodeId) -> bool {
    if let Some(b) = explicit_leading(f, v) {
        return b;
    }
    let vn = f.vn(v);
    let Some(def) = vn.def.filter(|_| vn.is_written()) else { return true };
    match f.op(def).code() {
        OpCode::Multiequal | OpCode::Indirect | OpCode::Call | OpCode::Callind | OpCode::Callother => return true,
        OpCode::Copy => {
            if let Some(inv) = f.op(def).input(0) {
                if f.vn(inv).is_persist() && persist_of[v.0 as usize] != persist_of[inv.0 as usize] {
                    return true;
                }
            }
        }
        _ => {}
    }
    if vn.descend.iter().any(|&u| f.op(u).is_marker()) {
        return true;
    }
    let dn = vn.descend.len();
    if dn == 0 || dn > max_implied_ref(f, v) {
        return true;
    }
    // A single-use / `multlist` candidate is explicit only if `multipleInteraction` purged it.
    is_purged_top(f, persist_of, v)
}

/// Ghidra `ActionMarkExplicit::multipleInteraction` (coreaction.cc:3091) from the purged Varnode's
/// view: `v` is made explicit when it is a `multlist` member that flows (slot 0 or 1) into another
/// member whose defining op is a boolean output, INT_ZEXT, INT_SEXT, or PTRADD (a PTRADD only purges
/// a PTRADD input). A boolean-defined `v` is skipped (Ghidra avoids making boolean outputs explicit).
fn is_purged_top(f: &Funcdata, persist_of: &[u32], v: VarnodeId) -> bool {
    if !is_mark_candidate(f, persist_of, v) {
        return false;
    }
    let vn = f.vn(v);
    let v_bool = vn.def.is_some_and(|d| f.op(d).is_bool_output());
    if v_bool {
        return false; // "Try not to make boolean outputs explicit" (coreaction.cc:3110)
    }
    let topopc = vn.def.map(|d| f.op(d).code()).unwrap_or(OpCode::Copy);
    for &u in &vn.descend {
        let Some(uout) = f.op(u).output else { continue };
        if !is_mark_candidate(f, persist_of, uout) {
            continue; // the descendant op's output must itself be a `multlist` member
        }
        let uc = f.op(u).code();
        if !(f.op(u).is_bool_output()
            || matches!(uc, OpCode::IntZext | OpCode::IntSext | OpCode::Ptradd))
        {
            continue;
        }
        let maxparam = f.op(u).num_inputs().min(2);
        for j in 0..maxparam {
            if f.op(u).input(j) != Some(v) {
                continue;
            }
            if uc == OpCode::Ptradd {
                if topopc == OpCode::Ptradd {
                    return true;
                }
            } else {
                return true;
            }
        }
    }
    false
}

/// Ghidra `ActionMarkExplicit::processMultiplier` (coreaction.cc:3166): depth-first over the
/// expression feeding `vroot`, counting explicit terms (a term is an already-explicit or unwritten
/// Varnode; spacebases are not counted). Returns true — `vroot` should be named — when the count
/// exceeds `max` (duplicating the expression at each use would be too verbose) or the walk reaches
/// another live `multlist` member (an ancestor that will itself be duplicated).
fn process_multiplier(f: &Funcdata, persist_of: &[u32], vroot: VarnodeId, max: i32) -> bool {
    // `(vn, slot, slotback)` — Ghidra's `OpStackElement` (coreaction.cc:3136): the back edges to
    // traverse, skipping a LOAD's space input, a PTRADD's multiplier, a SEGMENTOP's selectors.
    fn frame(f: &Funcdata, v: VarnodeId) -> (VarnodeId, usize, usize) {
        if let Some(def) = f.vn(v).def.filter(|_| f.vn(v).is_written()) {
            return match f.op(def).code() {
                OpCode::Load => (v, 1, 2),
                OpCode::Ptradd => (v, 0, 1),
                OpCode::Segmentop => (v, 2, 3),
                _ => (v, 0, f.op(def).num_inputs()),
            };
        }
        (v, 0, 0)
    }
    let mut stack: Vec<(VarnodeId, usize, usize)> = vec![frame(f, vroot)];
    let mut finalcount = 0i32;
    while let Some(&(vncur, slot, slotback)) = stack.last() {
        let isaterm = is_core_explicit(f, persist_of, vncur) || !f.vn(vncur).is_written();
        if isaterm || slotback <= slot {
            if isaterm && !f.vn(vncur).is_spacebase() {
                finalcount += 1;
            }
            if finalcount > max {
                return true;
            }
            stack.pop();
        } else {
            let op = f.vn(vncur).def.expect("written has a def");
            let newvn = f.op(op).input(slot).expect("slot within numInput");
            stack.last_mut().expect("nonempty").1 = slot + 1;
            // An ancestor that is itself a live (non-purged) `multlist` member forces `vroot`
            // explicit (coreaction.cc:3192).
            if is_mark_candidate(f, persist_of, newvn) && !is_purged_top(f, persist_of, newvn) {
                return true;
            }
            stack.push(frame(f, newvn));
        }
    }
    false
}

/// The HighVariable state at Ghidra's `ActionMarkImplied` slot (coreaction.cc:5720, "this must come
/// BEFORE general merging"): only `ActionMergeRequired`'s merges have run — address-tied unification
/// plus the marker merges — not the COPY / adjacent / speculative type merges. This is the instance
/// set `ActionMarkImplied::checkImpliedCover` → `Merge::inflateTest` walks; using the fully-merged
/// classes instead makes the implied test see speculative same-storage merges Ghidra hasn't done yet
/// and over-materializes temps (divopt's inline loads).
pub fn merge_required_only(f: &Funcdata) -> HighVariables {
    let mut h = HighVariables::new(f.num_varnodes());
    let pieces = merge_addrtied(f, &mut h);
    merge_markers(f, &mut h, &pieces);
    h
}

/// `Merge::mergeMarker` (merge.cc:889) — merge a MULTIEQUAL/INDIRECT output with its inputs. Like
/// every other required merge (`Merge::mergeOp`/`mergeIndirect`/`mergeOpcode`, merge.cc), each union
/// is gated by `mergeTestRequired`: Ghidra force-resolves a forbidden merge by trimming the input (an
/// inserted COPY), which in mosura's union-find model is simply a *non-union* — the input keeps its
/// own HighVariable. This gate is what stops an address-forced INDIRECT that carries a stack slot into
/// a ram global (`r0x140 = INDIRECT s_f0`, once copy-prop has threaded the store's source through the
/// INDIRECT) from fusing the global's HighVariable with the stack slot's — without it the global's
/// store COPY looks like an internal same-high copy and vanishes (stackreturn's shadowed writes). For
/// an address-forced INDIRECT `mergeIndirect` additionally snips on cover interference, but the gate
/// and the resulting non-union are identical whether or not the output is address forced. (An
/// indirect *creation* has a constant `#0` data input, filtered by `mergeable`, so it never merges —
/// matching Ghidra's `isIndirectCreation` skip.)
fn merge_markers(f: &Funcdata, h: &mut HighVariables, pieces: &VariablePieces) {
    set_phase("markers");
    for op in f.op_ids() {
        let o = f.op(op);
        if o.is_dead() || !o.is_marker() {
            continue;
        }
        let Some(out) = o.output else { continue };
        if !mergeable(f, out) {
            continue;
        }
        // INDIRECT merges only its data input (slot 0); MULTIEQUAL merges all inputs.
        let max = if o.code() == OpCode::Indirect { 1 } else { o.num_inputs() };
        for j in 0..max {
            if let Some(inv) = o.input(j) {
                if mergeable(f, inv) {
                    let (rep_out, rep_in) = (h.high(out), h.high(inv));
                    if merge_test_required(f, h, pieces, rep_out, rep_in) {
                        h.union(out.0, inv.0);
                    }
                }
            }
        }
    }
}

/// Do any member of class `a` and member of class `b` have overlapping liveness?
fn classes_interfere(a: &[VarnodeId], b: &[VarnodeId], covers: &HashMap<VarnodeId, Cover>) -> bool {
    a.iter().any(|x| {
        b.iter().any(|y| match (covers.get(x), covers.get(y)) {
            (Some(cx), Some(cy)) => cx.intersects(cy),
            _ => false,
        })
    })
}

/// `Merge::mergeAdjacent` (merge.cc:983, the `ActionMergeAdjacent` slot at coreaction.cc:5726) —
/// speculatively merge an op's input into its output when the op advertises the *same local type* for
/// both, they are the same size, and their Covers don't intersect. This is where Ghidra does most of
/// its non-forced merging: it gates on [`merge_test_adjacent`], which — unlike
/// [`merge_test_speculative`] — permits input / persist / address-tied variables. Without it,
/// applying the speculative refusals at [`merge_same_storage`] would leave mosura merging strictly
/// *less* than Ghidra rather than the same.
///
/// Calls are skipped (merge.cc:995): a call's output is a new value, never a continuation of an input.
fn merge_adjacent(
    f: &Funcdata,
    h: &mut HighVariables,
    pieces: &VariablePieces,
    covers: &HashMap<VarnodeId, Cover>,
    explicit: &[bool],
) {
    set_phase("adjacent");
    for op in f.op_ids().collect::<Vec<_>>() {
        let o = f.op(op);
        if o.is_dead() || o.is_call() {
            continue;
        }
        let Some(vn1) = o.output else { continue };
        if !merge_test_basic(f, covers, explicit, vn1) {
            continue;
        }
        let ct = super::infertypes::output_type_local(f, op);
        for i in 0..f.op(op).num_inputs() {
            if ct != super::infertypes::input_type_local(f, op, i) {
                continue; // Only merge if types should be the same
            }
            let Some(vn2) = f.op(op).input(i) else { continue };
            if !merge_test_basic(f, covers, explicit, vn2) {
                continue;
            }
            if f.vn(vn1).size != f.vn(vn2).size {
                continue;
            }
            // Ghidra merge.cc:1004: a Varnode that is neither written nor an input is \e free and
            // has no place in a variable.
            if f.vn(vn2).def.is_none() && !f.vn(vn2).is_input() {
                continue;
            }
            let (rep_out, rep_in) = (h.high(vn1), h.high(vn2));
            if rep_out == rep_in || !merge_test_adjacent(f, h, pieces, rep_out, rep_in) {
                continue;
            }
            let (cls_out, cls_in) = (h.class_of(rep_out), h.class_of(rep_in));
            let out_members = pieces.extend_members(h, &cls_out);
            let in_members = pieces.extend_members(h, &cls_in);
            if !classes_interfere(&out_members, &in_members, covers) {
                h.union(vn1.0, vn2.0);
            }
        }
    }
}

/// The speculative same-storage merges (Ghidra `Merge::mergeByDatatype` / `ActionMergeType`):
/// greedily merge HighVariables that share storage and never live simultaneously, so reused
/// registers/slots become one variable. Candidates are gated by `mergeTestBasic` (merge.cc:341):
/// an *implied* varnode (an expression term, per [`mark_explicit`]) is never a merge seed, and by
/// [`merge_test_speculative`] (`Merge::mergeTestSpeculative`, merge.cc:220), the gate `mergeLinear`
/// applies at this slot — required + adjacency (including data-type equality) + the speculative
/// refusal of globals, function inputs and address-tied storage.
///
/// Two structural differences from Ghidra remain, both filed rather than fixed here:
/// * Ghidra groups candidates by *exact data-type* over the whole varnode range and merges within
///   each type group; mosura groups by *storage*. With the type gate above, mosura's grouping is a
///   strict subset of Ghidra's (same storage AND same type ⊂ same type), so this under-merges rather
///   than over-merges. Widening it to Ghidra's type grouping is a separate change.
/// * `mergeLinear` (merge.cc:282) orders candidates by `compareHighByBlock` — the index of the
///   earliest block in the variable's range. mosura keeps its own lowest-member-id order so that the
///   effect of the gates is attributable on its own; the ordering is a separate faithfulness item.
fn merge_same_storage(
    f: &Funcdata,
    h: &mut HighVariables,
    pieces: &VariablePieces,
    covers: &HashMap<VarnodeId, Cover>,
    explicit: &[bool],
) {
    // Group by storage *and size* with members in varnode (create_index) order — Ghidra processes
    // varnodes in a deterministic order, so this drives a deterministic merge (a HashMap's
    // iteration order must never reach the output). A Ghidra HighVariable has a single size: a
    // differently-sized varnode sharing an address (e.g. scratch reuse of a parameter register as a
    // 4-byte temporary) is a *distinct* variable, accessed via SUBPIECE — never merged in. Keying
    // on size keeps an 8-byte pointer parameter from being dragged to a 4-byte scratch's `int4`.
    let mut by_storage: HashMap<(SpaceId, u64, u32), Vec<VarnodeId>> = HashMap::new();
    for i in 0..f.num_varnodes() as u32 {
        let v = VarnodeId(i);
        if merge_test_basic(f, covers, explicit, v) {
            let vn = f.vn(v);
            by_storage.entry((vn.loc.space, vn.loc.offset, vn.size)).or_default().push(v);
        }
    }
    // Process the (independent) storage groups in a deterministic order too.
    let mut groups: Vec<Vec<VarnodeId>> = by_storage.into_values().filter(|m| m.len() >= 2).collect();
    groups.sort_by_key(|m| m[0]);

    // The interference test must compare the WHOLE HighVariable each storage member belongs
    // to, not just the same-storage members — Ghidra's `HighVariable::updateInternalCover`
    // (variable.cc) unions the covers of *all* member Varnodes, so merging two same-storage
    // values transitively merges their whole HighVariables and interferes if any pair of
    // members does. (pointercmp: the bound `param_1+0x18` shares RAX with the iterator's
    // init value, whose HighVariable also holds the stack-slot phi that is live across the
    // compare — checking only the RAX members missed that overlap and unified them into the
    // bogus `pStack_10 < pStack_10`.)
    //
    // `full` (rep → all cover-bearing members) is maintained incrementally across unions —
    // only the two unioned classes change, and `classes_interfere` is an order-insensitive
    // any-pair test, so splicing their member lists is decision-identical to the full rescan.
    for members in groups {
        loop {
            // partition this storage group into current HighVariable classes, ordered by their
            // lowest member so the pairwise merge below is deterministic
            let mut classes: HashMap<u32, Vec<VarnodeId>> = HashMap::new();
            for &v in &members {
                classes.entry(h.high(v)).or_default().push(v);
            }
            let mut class_list: Vec<Vec<VarnodeId>> = classes.into_values().collect();
            class_list.sort_by_key(|c| c[0]);
            // A successful union restarts this pass (`break 'pair`), so within one pass the
            // classes — and therefore their extended member lists — never change. Building them
            // once per CLASS instead of once per PAIR turns O(k^2) extensions into O(k); the
            // pair loop only reads them. They come from the union-find's own member index, so
            // the hand-maintained `full` map that used to be threaded alongside `h` is gone: it
            // recorded exactly what `class_of` already knows.
            let reps: Vec<u32> = class_list.iter().map(|c| h.high(c[0])).collect();
            let exts: Vec<Vec<VarnodeId>> = reps
                .iter()
                .map(|&rep| {
                    let cls = h.class_of(rep);
                    pieces.extend_members(h, &cls)
                })
                .collect();
            let mut merged = false;
            'pair: for i in 0..class_list.len() {
                for j in (i + 1)..class_list.len() {
                    let (rep_i, rep_j) = (reps[i], reps[j]);
                    if !merge_test_speculative(f, h, pieces, rep_i, rep_j) {
                        continue;
                    }
                    if !classes_interfere(&exts[i], &exts[j], covers) {
                        h.union(class_list[i][0].0, class_list[j][0].0);
                        merged = true;
                        break 'pair;
                    }
                }
            }
            if !merged {
                break;
            }
        }
    }
}



/// One `VariablePiece` (variable.hh:71): the HighVariable formed by the Varnodes at one exact
/// `(address, size)`, together with where it sits inside its overlap group.
#[derive(Clone)]
struct Piece {
    group: u32,
    /// Byte offset of this piece within its group (`VariablePiece::groupOffset`).
    offset: u32,
    size: u32,
    /// The Varnodes at this exact `(address, size)` — `mergeRangeMust` unions them, so they are one
    /// HighVariable and any of them identifies it.
    members: Vec<VarnodeId>,
}

/// One `VariableGroup` (variable.hh:44): the set of mutually overlapping pieces at a storage
/// location, and the number of contiguous bytes the whole group covers.
#[derive(Clone)]
struct Group {
    size: u32,
    pieces: Vec<u32>,
}

/// Ghidra's `VariableGroup`/`VariablePiece` structure (variable.hh:44/71), as built by
/// `Merge::mergeAddrTied`'s `groupWith` (variable.cc:571).
///
/// **The distinction this exists to draw.** Ghidra separates two things mosura used to conflate:
/// *identity* — which C variable a Varnode belongs to, decided per `(address, size)` — from *the
/// Cover used for interference*, which spans the byte-overlapping pieces. mosura's old size-blind
/// `mergeAddrTied` union was an approximation **of the extended cover**, not of identity: it bought
/// the spanning liveness by fusing a 2-byte and a 4-byte value at one address into a single C
/// variable, which is what let an 8-byte store render as a 4-byte assignment (`partialmerge`).
///
/// Ghidra's caching (`intersectdirty`/`extendcoverdirty`, `markIntersectionDirty`, `combineGroups`,
/// `adjustOffsets`) does not port: mosura's [`all_covers`]/[`classes_interfere`] recompute from
/// scratch on every call, so `updateIntersections`/`updateCover` reduce to the two pure functions
/// [`Self::intersecting`] and [`Self::extend_members`].
#[derive(Clone)]
pub struct VariablePieces {
    /// Varnode → its piece, or `None` when it is in no overlap group.
    piece_of: Vec<Option<u32>>,
    pieces: Vec<Piece>,
    groups: Vec<Group>,
}

impl VariablePieces {
    /// No overlap groups — every HighVariable is a whole variable (Ghidra's `piece == nullptr`).
    pub fn empty(n: usize) -> VariablePieces {
        VariablePieces { piece_of: vec![None; n], pieces: Vec::new(), groups: Vec::new() }
    }

    fn piece(&self, v: VarnodeId) -> Option<&Piece> {
        self.piece_of.get(v.0 as usize).copied().flatten().map(|p| &self.pieces[p as usize])
    }

    /// `VariablePiece::updateIntersections` (variable.cc:140) — exactly the pieces of the group that
    /// byte-overlap the given one. Ghidra's early-out on `intersectdirty` is the cache; the loop is
    /// the definition.
    fn intersecting<'a>(&'a self, p: &'a Piece) -> impl Iterator<Item = &'a Piece> + 'a {
        let end = p.offset + p.size;
        self.groups[p.group as usize].pieces.iter().map(|&i| &self.pieces[i as usize]).filter(
            move |q| {
                !std::ptr::eq(*q, p) && end > q.offset && p.offset < q.offset + q.size
            },
        )
    }

    /// Does this Varnode's piece cover its whole group? Ghidra
    /// `high->piece->getSize() != group->getSize()` (merge.cc:151-152).
    pub fn spans_group(&self, v: VarnodeId) -> bool {
        self.piece(v).is_some_and(|p| p.size == self.groups[p.group as usize].size)
    }

    /// `(group, offset within the group, size)` of this Varnode's piece — Ghidra's
    /// `vn->getHigh()->piece`.
    pub fn at(&self, v: VarnodeId) -> Option<(u32, u32, u32)> {
        self.piece(v).map(|p| (p.group, p.offset, p.size))
    }

    /// The number of contiguous bytes the Varnode's whole group covers (`VariableGroup::getSize`).
    pub fn group_size(&self, v: VarnodeId) -> Option<u32> {
        self.piece(v).map(|p| self.groups[p.group as usize].size)
    }

    /// A Varnode of the piece that spans the whole group — the one whose name the printer uses as
    /// the base of a partial symbol. `None` when no single piece covers the group.
    pub fn group_base(&self, v: VarnodeId) -> Option<VarnodeId> {
        let p = self.piece(v)?;
        let g = &self.groups[p.group as usize];
        g.pieces
            .iter()
            .map(|&i| &self.pieces[i as usize])
            .find(|q| q.offset == 0 && q.size == g.size)
            .and_then(|q| q.members.first().copied())
    }

    fn same_group(&self, a: VarnodeId, b: VarnodeId) -> bool {
        match (self.piece(a), self.piece(b)) {
            (Some(pa), Some(pb)) => pa.group == pb.group,
            _ => false,
        }
    }

    /// `VariablePiece::updateCover` (variable.cc:160) expressed over member lists: the extended
    /// Cover of a HighVariable is its own internal Cover unioned with the internal Covers of the
    /// pieces it intersects, and an internal Cover is the union of its members' Covers — so unioning
    /// the *member lists* and testing pairwise is the same predicate, with no Cover algebra.
    ///
    /// This is what `HighIntersectTest::intersection` (variable.cc:1166) reads via `getCover()`, and
    /// the only place Ghidra consults it: the extended Cover *prevents merges*, it never *forces a
    /// snip*.
    /// `by_rep` is the caller's already-built rep → members map. It is the SAME partition
    /// `members_of` recomputes — `full_members_by_rep` and `members_of` share one predicate
    /// (`covers.contains_key(v) && h.high(v) == rep`) and one ascending-`VarnodeId` order — so
    /// looking a class up is identical to rescanning for it, and rescanning made this the whole
    /// cost of the pass: `members_of` walks EVERY varnode in the function, once per seed, per
    /// rep, per call. Ghidra never pays it — a `HighVariable` owns its members in `inst`
    /// (variable.hh:137) and `HighIntersectTest` reads them directly.
    fn extend_members(&self, h: &mut HighVariables, base: &[VarnodeId]) -> Vec<VarnodeId> {
        // Collect the intersecting pieces first: the rep lookup needs `&mut h`, which cannot be
        // held across the borrow of `self.pieces`.
        let mut seeds: Vec<VarnodeId> = Vec::new();
        for &v in base {
            let Some(p) = self.piece(v) else { continue };
            for q in self.intersecting(p) {
                if let Some(&m) = q.members.first() {
                    seeds.push(m);
                }
            }
        }
        if seeds.is_empty() {
            return base.to_vec();
        }
        let mut out = base.to_vec();
        // Set-based dedup: the old `out.contains(&w)` was linear in the extended class, making
        // the append quadratic. Insertion order into `out` is unchanged.
        let mut seen: std::collections::HashSet<VarnodeId> = out.iter().copied().collect();
        for m in seeds {
            let rep = h.high(m);
            for w in h.class_of(rep) {
                if seen.insert(w) {
                    out.push(w);
                }
            }
        }
        out
    }

}

/// `Merge::mergeAddrTied` (merge.cc:609) — force-merge address-tied Varnodes into HighVariables and
/// build the overlap groups.
///
/// Ghidra walks each space's maximal overlapping range (`VarnodeBank::overlapLoc`, varnode.cc:1785 —
/// "one subrange for each set of Varnodes with the same size and starting address") and does three
/// distinct things with it, which must not be confused:
///
/// * `unifyAddress`/`eliminateIntersect` runs over the **whole overlap range** — the snip that
///   resolves Cover intersections by splitting data-flow. In mosura that is
///   [`super::mergesnip::ActionMergeRequired`], which already ran.
/// * `mergeRangeMust` runs over each **same-`(address, size)` subrange only** — this is the identity
///   merge, and it is why a 2-byte and a 4-byte value at one address are *different C variables*.
/// * `groupWith` (variable.cc:571) links those separate HighVariables into one `VariableGroup`, with
///   each piece's offset relative to the lowest-addressed subrange. The group only exists when the
///   range has more than one subrange (`if (max > 2)`, merge.cc:637); a lone `(address, size)` gets
///   no piece at all.
///
/// The extended Cover the group carries *prevents speculative merges*; it does not *force snips*.
///
/// Faithfully narrowed: Ghidra's range walk covers every non-free Varnode in the space and gates the
/// range on the union of its flags containing `addrtied`, so a non-tied Varnode overlapping a tied
/// one also becomes a piece. mosura gates each Varnode on `addrtied` — the same population this
/// function has always operated on, so the change here is purely partition-vs-union. Widening the
/// population is a separate step; it can only add pieces, which can only *forbid* merges.
thread_local! {
    /// MOSURA_MERGE_WATCH diagnostic: which merge phase is running (set by the drivers).
    static MERGE_PHASE: std::cell::Cell<&'static str> = const { std::cell::Cell::new("?") };
}

fn set_phase(p: &'static str) {
    MERGE_PHASE.with(|ph| ph.set(p));
}

fn merge_addrtied(f: &Funcdata, h: &mut HighVariables) -> VariablePieces {
    set_phase("addrtied");
    // Ghidra `unifyAddress` gates on `!isFree` (heritaged), NOT on having a Cover: an address-forced
    // write held to the end of the function has no explicit reader (so mosura's Cover is empty) but
    // is still an instance of the storage's variable and must be unified, else the `guardReturns`
    // terminal COPY stays cross-high and prints a spurious `g = g`.
    let mut by_storage: HashMap<(SpaceId, u64, u32), Vec<VarnodeId>> = HashMap::new();
    for i in 0..f.num_varnodes() as u32 {
        let v = VarnodeId(i);
        let vn = f.vn(v);
        if vn.is_free() || !vn.is_addrtied() {
            continue;
        }
        if std::env::var_os("MOSURA_MERGE_WATCH").is_some()
            && f.spaces.get(vn.loc.space).kind == crate::decompile::space::SpaceKind::Processor
            && f.spaces.get(vn.loc.space).delay == 0
        {
            debug!(crate::debug::Topic::Merge, "addrtied-reg v{} {}+{:#x}:{} flags {:#x}", v.0, f.spaces.get(vn.loc.space).name, vn.loc.offset, vn.size, vn.flags);
        }
        by_storage.entry((vn.loc.space, vn.loc.offset, vn.size)).or_default().push(v);
    }
    // `mergeRangeMust` over each same-(address, size) subrange. Deterministic order: the union
    // representative is the lowest-index member.
    let mut subranges: Vec<((SpaceId, u64, u32), Vec<VarnodeId>)> = by_storage.into_iter().collect();
    subranges.sort_by_key(|((sp, off, sz), _)| (sp.0, *off, *sz));
    for (_, members) in &subranges {
        for &w in &members[1..] {
            h.union(members[0].0, w.0);
        }
    }

    // `overlapLoc`: walk the subranges in (space, offset, size) order accumulating maximal
    // overlapping ranges, then `groupWith` every range that has more than one subrange.
    let mut pieces = VariablePieces::empty(f.num_varnodes());
    let mut i = 0;
    while i < subranges.len() {
        let (sp, base_off, _) = subranges[i].0;
        // `maxOff = off + (vn->getSize()-1)` (varnode.cc:1797). Ghidra tracks the INCLUSIVE end,
        // and that is not a stylistic choice: it is what keeps a range that ends at the top of
        // the address space representable. A 64-bit spacebase offset like -8 is
        // 0xffff_ffff_ffff_fff8, whose EXCLUSIVE end is 2^64 — unrepresentable, and the reason
        // this line used to panic (`attempt to add with overflow`) on the varargs ground-truth
        // fixture in debug. `uintb` wraps in C++, so the adds wrap here too.
        let mut max_off = base_off.wrapping_add(subranges[i].0 .2 as u64 - 1);
        let mut j = i + 1;
        while j < subranges.len() {
            let (sp2, off2, sz2) = subranges[j].0;
            // `vn->getSpace() != spc || vn->getOffset() > maxOff` (varnode.cc:1804) — strict,
            // because maxOff is the last byte of the range rather than one past it.
            if sp2 != sp || off2 > max_off {
                break;
            }
            // `endOff = off + (size-1); if (endOff > maxOff) maxOff = endOff;` (varnode.cc:1810-1812)
            let end_off = off2.wrapping_add(sz2 as u64 - 1);
            if end_off > max_off {
                max_off = end_off;
            }
            j += 1;
        }
        if j - i > 1 {
            let gid = pieces.groups.len() as u32;
            let mut ids = Vec::new();
            for ((_, off, sz), members) in subranges[i..j].iter() {
                let pid = pieces.pieces.len() as u32;
                ids.push(pid);
                for &v in members {
                    pieces.piece_of[v.0 as usize] = Some(pid);
                }
                pieces.pieces.push(Piece {
                    group: gid,
                    offset: (off - base_off) as u32,
                    size: *sz,
                    members: members.clone(),
                });
            }
            // `VariableGroup::size` is a byte count ("Number of contiguous bytes covered by the
            // whole group", variable.hh:53), so an inclusive end spans one more byte than it
            // measures.
            let span = max_off.wrapping_sub(base_off).wrapping_add(1);
            pieces.groups.push(Group { size: span as u32, pieces: ids });
        }
        i = j;
    }
    pieces
}

/// `Merge::mergeOpcode(CPUI_COPY)` (merge.cc:326) — in linear block order, try to merge each
/// COPY's input HighVariable with its output HighVariable. The merge is skipped if `mergeTestBasic`
/// or `mergeTestRequired` forbids it, or if it would introduce a Cover intersection (Ghidra ignores
/// `merge()`'s return, merge.cc:346). This collapses redundant register/return COPYs into one
/// variable and — crucially — LEAVES a COPY whose input and output Covers interfere (a snapshot of
/// an address-tied value taken before that address is overwritten) as two distinct HighVariables,
/// so the printer renders it as an explicit `iVar = <snapshot>` assignment (see printc's
/// cross-high COPY arm, Ghidra `Merge::markInternalCopies`).
fn merge_copy_phase_marker() { set_phase("copy") }
fn merge_copy(
    f: &Funcdata,
    h: &mut HighVariables,
    pieces: &VariablePieces,
    covers: &HashMap<VarnodeId, Cover>,
    explicit: &[bool],
) {
    set_phase("copy");
    for b in 0..f.num_blocks() as u32 {
        let ops = f.block(BlockId(b)).ops.clone();
        for op in ops {
            let o = f.op(op);
            if o.is_dead() || o.code() != OpCode::Copy {
                continue;
            }
            let Some(out) = o.output else { continue };
            if !merge_test_basic(f, covers, explicit, out) {
                continue;
            }
            for j in 0..o.num_inputs() {
                let Some(inv) = o.input(j) else { continue };
                if !merge_test_basic(f, covers, explicit, inv) {
                    continue;
                }
                let rep_out = h.high(out);
                let rep_in = h.high(inv);
                if rep_out == rep_in {
                    continue;
                }
                if !merge_test_required(f, h, pieces, rep_out, rep_in) {
                    continue;
                }
                let (cls_out, cls_in) = (h.class_of(rep_out), h.class_of(rep_in));
                let mo = pieces.extend_members(h, &cls_out);
                let mi = pieces.extend_members(h, &cls_in);
                if classes_interfere(&mo, &mi, covers) {
                    continue; // would introduce a Cover intersection — skip
                }
                h.union(out.0, inv.0);
            }
        }
    }
}

/// `Merge::mergeTestBasic` (merge.cc:255) — a Varnode may take part in a merge only if it has a
/// Cover and is neither implied nor a spacebase. The implied exclusion reads the [`mark_explicit`]
/// classification (Ghidra's varnode flags set by `ActionMarkImplied` just before the COPY merge).
/// (Ghidra also excludes `isProtoPartial`; mosura has no VariablePiece so that case is
/// inapplicable.)
fn merge_test_basic(
    f: &Funcdata,
    covers: &HashMap<VarnodeId, Cover>,
    explicit: &[bool],
    v: VarnodeId,
) -> bool {
    if !covers.contains_key(&v) {
        return false;
    }
    explicit[v.0 as usize] && !f.vn(v).is_spacebase()
}

/// Ghidra's `high->piece`: the VariablePiece of a HighVariable, identified by any member Varnode
/// that carries one. (`mergeRangeMust` puts a whole `(address, size)` subrange in one class, and
/// [`merge_test_required`] refuses to merge two pieces of a group, so a class holds at most one
/// piece per group.)
fn piece_rep(
    h: &mut HighVariables,
    pieces: &VariablePieces,
    rep: u32,
) -> Option<VarnodeId> {
    h.class_of(rep).into_iter().find(|&v| pieces.piece(v).is_some())
}

/// The aggregate `(address-tied storage address, is-input, is-persist)` over every Varnode merged
/// into HighVariable `rep` — Ghidra's HighVariable flag aggregation across its instances. A `stack`
/// member counts as tied-to-its-address even without the `addrtied` flag: Ghidra maps every stack
/// local (so it is addrtied), while mosura marks only *escaped* slots ([`super::varnodeprops`]), so
/// the merge guard would otherwise let a stack local merge with a differently-addressed global.
fn high_props(f: &Funcdata, h: &mut HighVariables, rep: u32) -> (Option<Address>, bool, bool) {
    let stack = f.spaces.by_name("stack");
    let mut tied: Option<Address> = None;
    let (mut input, mut persist) = (false, false);
    for v in h.class_of(rep) {
        let vn = f.vn(v);
        if vn.is_addrtied() || Some(vn.loc.space) == stack {
            tied = Some(vn.loc);
        }
        input |= vn.is_input();
        persist |= vn.is_persist();
    }
    (tied, input, persist)
}

/// `Merge::mergeTestRequired` (merge.cc:102), the subset mosura models: keep an address-tied output
/// from swallowing an address-tied input of a *different* address, keep the pieces of one
/// VariableGroup from being merged back together, and keep function inputs distinct from persistent
/// / address-tied storage (an input must not be dragged into the internal parts of a stack
/// structure). The typelock / extraout / protopartial / symbol guards are not modeled — mosura has
/// no type-locks or symbol tables at merge time.
fn merge_test_required(
    f: &Funcdata,
    h: &mut HighVariables,
    pieces: &VariablePieces,
    rep_out: u32,
    rep_in: u32,
) -> bool {
    if rep_out == rep_in {
        return true; // already merged
    }
    // merge.cc:147-153, the VariablePiece guard. Two pieces of the SAME group are different parts of
    // one storage location and never merge — without this the same-address arm below would happily
    // re-fuse the 2-byte and 4-byte versions that `mergeRangeMust` just kept apart, undoing the
    // split. Across groups, at least one piece must represent its whole group.
    if let (Some(po), Some(pi)) = (piece_rep(h, pieces, rep_out), piece_rep(h, pieces, rep_in))
    {
        if pieces.same_group(po, pi) {
            return false;
        }
        if !pieces.spans_group(po) && !pieces.spans_group(pi) {
            return false;
        }
    }
    let (out_tied, out_input, out_persist) = high_props(f, h, rep_out);
    let (in_tied, in_input, in_persist) = high_props(f, h, rep_in);
    if let (Some(oa), Some(ia)) = (out_tied, in_tied) {
        if oa != ia {
            return false; // address-tied output vs address-tied input of a different address
        }
    }
    if in_input {
        if out_persist {
            return false; // inputs and persists are inherently different variables
        }
        if out_tied.is_some() && in_tied.is_none() {
            return false; // don't drag an input into address-tied storage
        }
    }
    if out_input {
        if in_persist {
            return false;
        }
        if in_tied.is_some() && out_tied.is_none() {
            return false;
        }
    }
    true
}

/// `HighVariable::getTypeRepresentative` (variable.cc:377) → `HighVariable::getType` (variable.hh:174)
/// — the data-type of a whole *variable*: the member Varnode carrying the strongest data-type, with a
/// type-locked member always outranking an unlocked one regardless of type. This is the type
/// [`merge_test_adjacent`] compares when deciding whether two variables may merge, and the type
/// `HighVariable::updateType` publishes to the printer.
///
/// `members` is the HighVariable's instance list (Ghidra's `HighVariable::inst`); it must be
/// non-empty, which every union-find class is.
///
/// Faithfully deferred: `HighVariable::stripType` (variable.cc:302) normalizes enum / partial-union /
/// partial-struct representatives down to their stripped base. mosura's [`Datatype`] has no enum,
/// union or partial metatype, so no representative can ever be `hasStripped()` and the call is a
/// no-op here.
fn high_type(f: &Funcdata, members: &[VarnodeId]) -> Datatype {
    let mut rep = members[0];
    for &v in &members[1..] {
        let (rep_locked, v_locked) = (f.vn(rep).is_typelock(), f.vn(v).is_typelock());
        if rep_locked != v_locked {
            if v_locked {
                rep = v;
            }
        } else if type_order(&f.vn(v).get_type(), &f.vn(rep).get_type()) == Ordering::Less {
            rep = v;
        }
    }
    f.vn(rep).get_type()
}

/// [`high_type`] over the Varnodes currently merged into HighVariable `rep` — Ghidra's
/// `vn->getHigh()->getType()`.
fn high_type_of(f: &Funcdata, h: &mut HighVariables, rep: u32) -> Datatype {
    let members: Vec<VarnodeId> =
        h.class_of(rep).into_iter().filter(|&v| mergeable(f, v)).collect();
    if members.is_empty() {
        // `rep` names a constant/annotation singleton — its own type is the variable's type.
        return f.vn(VarnodeId(rep)).get_type();
    }
    high_type(f, &members)
}

/// `Merge::mergeTestAdjacent` (merge.cc:175) — the required tests plus the *adjacency* tests, applied
/// to any speculative merge. The arm that matters for mosura is the data-type equality gate
/// (merge.cc:186, "Make sure variables have the same type"): two variables of different data-type are
/// never merged, so an inferred `Pointer` variable can never swallow an inferred `Uint` one and
/// broadcast its type over it.
///
/// Faithfully deferred — Ghidra predicates with no mosura counterpart, each unable to fire here:
/// * `isNameLock` on both (merge.cc:181) — mosura has no name locks; nothing sets the flag.
/// * `isIllegalInput && !isIndirectOnly` on an input member (merge.cc:194-201) — mosura models
///   neither `illegalinput` nor `indirectonly`, so no varnode can satisfy the test.
/// * `Symbol::isIsolated` on either side (merge.cc:202-208) — there is no symbol table at merge time
///   (the same absence already noted on [`merge_test_required`]).
///
/// These are omissions of *restrictions*: each can only ever forbid a merge, so their absence makes
/// mosura merge no less than Ghidra, never more. They are recorded rather than dropped so the debt
/// stays visible when symbols do land.
fn merge_test_adjacent(
    f: &Funcdata,
    h: &mut HighVariables,
    pieces: &VariablePieces,
    rep_out: u32,
    rep_in: u32,
) -> bool {
    if !merge_test_required(f, h, pieces, rep_out, rep_in) {
        return false;
    }
    if rep_out == rep_in {
        return true; // already merged; Ghidra's getType() comparison is trivially equal
    }
    // merge.cc:210-212, "Currently don't allow speculative merging of variables that are in separate
    // overlapping collections" — stricter than the required test, which permits the cross-group
    // whole-group case.
    if piece_rep(h, pieces, rep_out).is_some() && piece_rep(h, pieces, rep_in).is_some() {
        return false;
    }
    high_type_of(f, h, rep_out) == high_type_of(f, h, rep_in)
}

/// `Merge::mergeTestSpeculative` (merge.cc:220) — the adjacency tests plus the tests that apply only
/// to a *speculative* merge (one not forced by the data-flow graph): never speculatively merge
/// anything with a global (`isPersist`), a function input (`isInput`), or address-tied storage
/// (`isAddrTied`). This is the gate `mergeLinear` (merge.cc:286) applies inside `mergeByDatatype`,
/// i.e. at [`merge_same_storage`]'s slot.
fn merge_test_speculative(
    f: &Funcdata,
    h: &mut HighVariables,
    pieces: &VariablePieces,
    rep_out: u32,
    rep_in: u32,
) -> bool {
    if !merge_test_adjacent(f, h, pieces, rep_out, rep_in) {
        return false;
    }
    let (out_tied, out_input, out_persist) = high_props(f, h, rep_out);
    let (in_tied, in_input, in_persist) = high_props(f, h, rep_in);
    if out_persist || in_persist {
        return false; // don't merge anything with a global speculatively
    }
    if out_input || in_input {
        return false; // don't merge anything speculatively with input
    }
    if out_tied.is_some() || in_tied.is_some() {
        return false; // don't merge anything speculatively with addrtied
    }
    true
}

/// `Merge::mergeMarker` (merge.cc:889) — the graph-mutating half of the required marker merge that
/// mosura's read-only [`merge`] cannot do: run through the MULTIEQUAL ops and force-merge each one's
/// output with its inputs via [`merge_op`], doing data-flow modification (trim COPYs) where a merge
/// restriction or Cover intersection stands in the way. State is live across ops as in Ghidra: the
/// address-tied unification runs first (`mergeAddrTied`, the [`super::mergesnip`] snip having
/// already run), then each `merge_op` call trims *and* unions, so later phis see earlier merges.
/// (Ghidra also dispatches INDIRECT markers here — `mergeIndirect`, with its address-forced output
/// protocol; that half is not yet ported, and the read-only [`merge_markers`] gate still models it
/// as a non-union.)
///
/// floatcast: the incoming address-tied global read `fRam80` reaches the phi with a broad Cover that
/// conflicts with the phi output (the value live from the join onward). `merge_markers` gates only on
/// `merge_test_required` — which passes — so it fuses the phi output into the global's HighVariable and
/// names the whole thing `fRam80`. The trim severs that fusion: `fVar1 = fRam80;` at the entry, the
/// phi output a distinct local `fVar1`.
///
/// **Faithful trim-any-conflict** (Ghidra merge.cc:719 tests *any* cover conflict): a conflicting
/// input is trimmed regardless of whether it is address-tied. A conflicting *register* input — one
/// Ghidra would SSA-split into narrow single-use versions that never conflict, but mosura keeps as a
/// single broad version — is trimmed here too. That over-trim is mosura's coarse-register-SSA gap
/// (varcross), a diagnostic naming the upstream fix, not a reason to restrict this pass.
fn merge_marker_trim(f: &mut Funcdata) {
    if f.num_blocks() == 0 {
        return;
    }
    let mut covers = all_covers(f);
    let mut h = HighVariables::new(f.num_varnodes());
    let pieces = merge_addrtied(f, &mut h);
    // `Merge::mergeMarker` (merge.cc:889): run through all MULTIEQUAL and INDIRECT ops, forcing the
    // merge of each input with the output; skip indirect *creations* (Ghidra `op->isIndirectCreation`).
    for op in f.op_ids() {
        let o = f.op(op);
        if o.is_dead() || !o.is_marker() {
            continue;
        }
        let Some(out) = o.output else { continue };
        let is_indirect = o.code() == OpCode::Indirect;
        if is_indirect
            && (f.vn(out).is_indirect_creation()
                || o.input(0).is_some_and(|iv| f.vn(iv).is_constant()))
        {
            continue;
        }
        if !mergeable(f, out) {
            continue;
        }
        if is_indirect {
            merge_indirect(f, &mut h, &pieces, &mut covers, op);
        } else {
            merge_op(f, &mut h, &pieces, &mut covers, op);
        }
    }
}

/// `Merge::mergeIndirect` (merge.cc:846) — force the merge of the input and output of an INDIRECT.
/// A non-address-forced output merges exactly like a MULTIEQUAL ([`merge_op`] with the data input
/// only). An address-forced output must by convention hold the value at its address BEFORE the
/// indirect effect, so its input is never blind-trimmed: try the direct merge; failing that, snip
/// instances of the output HighVariable that feed the affected op ([`snip_output_interference`])
/// and retry; finally snip the INDIRECT's own input into a COPY placed just before it. (Where
/// Ghidra's last-resort merge would throw `LowlevelError`, mosura leaves the pair un-unioned — the
/// read-only merge gate keeps them distinct.)
fn merge_indirect(
    f: &mut Funcdata,
    h: &mut HighVariables,
    pieces: &VariablePieces,
    covers: &mut HashMap<VarnodeId, Cover>,
    indop: super::op::OpId,
) {
    let outvn = f.op(indop).output.expect("INDIRECT has an output");
    if !f.vn(outvn).is_addr_force() {
        merge_op(f, h, pieces, covers, indop);
        return;
    }
    let try_merge = |f: &Funcdata, h: &mut HighVariables, covers: &HashMap<VarnodeId, Cover>| -> bool {
        let outvn = f.op(indop).output.expect("INDIRECT has an output");
        let Some(in0) = f.op(indop).input(0) else { return true };
        if !mergeable(f, in0) {
            return false;
        }
        let (rep_out, rep_in) = (h.high(outvn), h.high(in0));
        if rep_out == rep_in {
            return true;
        }
        if !merge_test_required(f, h, pieces, rep_out, rep_in) {
            return false;
        }
        // Merge::merge fails only on a Cover intersection.
        let (cls_out, cls_in) = (h.class_of(rep_out), h.class_of(rep_in));
        let mo = pieces.extend_members(h, &cls_out);
        let mi = pieces.extend_members(h, &cls_in);
        if class_intersect(f, &mo, &mi, covers) {
            return false;
        }
        h.union(outvn.0, in0.0);
        true
    };
    if try_merge(f, h, covers) {
        return;
    }
    // The only thing that can go wrong with an input trim is the output being involved in the
    // input to the op causing the indirect effect — test for (and snip) that.
    let first_new = f.num_varnodes() as u32;
    if let Some(block) = snip_output_interference(f, h, indop) {
        h.extend_to(f.num_varnodes());
        refresh_covers(f, covers, block, first_new);
        if try_merge(f, h, covers) {
            return;
        }
    }
    // Snip the INDIRECT itself: a COPY of the input placed just before it (allocateCopyTrim).
    let first_new = f.num_varnodes() as u32;
    let in0 = f.op(indop).input(0).expect("INDIRECT has a data input");
    let size = f.vn(in0).size;
    let pc = f.op(indop).seqnum.pc;
    let uniq = f.num_ops() as u32;
    let copyop = f.new_op(OpCode::Copy, super::op::SeqNum { pc, uniq }, vec![in0]);
    let cout = f.new_output_unique(copyop, size);
    f.op_set_input(indop, 0, cout);
    f.op_insert_before(copyop, indop);
    f.copy_trims.push(copyop); // allocateCopyTrim records it (merge.cc:432)
    h.extend_to(f.num_varnodes());
    refresh_covers(f, covers, f.op(indop).parent.expect("INDIRECT has a parent block"), first_new);
    // Try the merge again; where Ghidra would throw ("Unable to merge address forced indirect"),
    // a residual conflict is left un-unioned.
    try_merge(f, h, covers);
}

/// `Merge::snipOutputInterference` (merge.cc:815) + `collectInputs` (merge.cc:780): collect reads,
/// by the op causing the given INDIRECT (and the INDIRECTs stacked directly above it), of Varnodes
/// belonging to the INDIRECT output's HighVariable; snip them by COPYing to a temporary just before
/// the affected op — one COPY per distinct read Varnode HighVariable — and repoint the reads.
/// Returns the block the snip COPYs were inserted into (for [`refresh_covers`]), `None` if
/// nothing was snipped.
fn snip_output_interference(
    f: &mut Funcdata,
    h: &mut HighVariables,
    indop: super::op::OpId,
) -> Option<super::block::BlockId> {
    let affect = f.op(indop).guarded_op()?;
    let out = f.op(indop).output.expect("INDIRECT has an output");
    let rep = h.high(out);
    // collectInputs: the affected op, plus any INDIRECT immediately preceding it in its block.
    let mut oplist: Vec<(super::op::OpId, usize)> = Vec::new();
    let parent = f.op(affect).parent?;
    let ops = f.block(parent).ops.clone();
    let mut idx = ops.iter().position(|&o| o == affect)?;
    loop {
        let op = ops[idx];
        for i in 0..f.op(op).num_inputs() {
            let Some(vn) = f.op(op).input(i) else { continue };
            if !mergeable(f, vn) {
                continue; // annotations/constants
            }
            if h.high(vn) == rep {
                oplist.push((op, i));
            }
        }
        if idx == 0 {
            break;
        }
        idx -= 1;
        if f.op(ops[idx]).code() != OpCode::Indirect {
            break;
        }
    }
    if oplist.is_empty() {
        return None;
    }
    // Group by the read Varnode's HighVariable (compareByHigh): one snip COPY per group, all the
    // group's reads repointed at it.
    oplist.sort_by_key(|&(op, slot)| {
        let vn = f.op(op).input(slot).expect("collected read has an input");
        (h.high(vn), vn.0)
    });
    let mut snip_out: Option<VarnodeId> = None;
    let mut cur_high: Option<u32> = None;
    for (op, slot) in oplist {
        let vn = f.op(op).input(slot).expect("collected read has an input");
        if cur_high != Some(h.high(vn)) {
            let size = f.vn(vn).size;
            let pc = f.op(op).seqnum.pc;
            let uniq = f.num_ops() as u32;
            let snipop = f.new_op(OpCode::Copy, super::op::SeqNum { pc, uniq }, vec![vn]);
            let so = f.new_output_unique(snipop, size);
            f.op_insert_before(snipop, op);
            f.copy_trims.push(snipop);
            cur_high = Some(h.high(vn));
            h.extend_to(f.num_varnodes());
            snip_out = Some(so);
        }
        f.op_set_input(op, slot, snip_out.expect("snip COPY exists"));
    }
    Some(parent)
}

/// `Merge::mergeOp` (merge.cc:719) — force the merge of all input and output Varnodes for the given
/// marker op, snipping data-flow until everything can be merged.
///
/// Three phases, exactly Ghidra's:
/// 1. *Non-cover restrictions*: an input whose HighVariable fails `mergeTestRequired` against the
///    output — or against any earlier input — is trimmed ([`trim_op_input`]).
/// 2. *Cover restrictions*: the output and every input class must be pairwise intersection-free
///    ([`merge_test_class`]). If not, inputs are trimmed **blind-sequentially** — slot 0, retest,
///    slot 1, retest, … — until the whole set tests clean (Ghidra trims in slot order regardless of
///    which pair conflicts; this is what produces the per-case block-stop COPYs on a switch's header
///    phi, and with them Ghidra's `iVar3 = 2; param_1 = param_1 + 2;` per-case statement order). If
///    every input trim is exhausted, the *output* is trimmed ([`trim_op_output`]).
/// 3. *Forced union*: the output is merged with every input for real. (Where Ghidra's `merge` would
///    throw `LowlevelError` on a residual intersection, mosura unions regardless — the phase-2 trims
///    have made the set intersection-free by construction.)
fn merge_op(
    f: &mut Funcdata,
    h: &mut HighVariables,
    pieces: &VariablePieces,
    covers: &mut HashMap<VarnodeId, Cover>,
    op: super::op::OpId,
) {
    // An INDIRECT force-merges only its data input, slot 0 (merge.cc:726).
    let max = if f.op(op).code() == OpCode::Indirect { 1 } else { f.op(op).num_inputs() };
    // Phase 1: non-cover related merge restrictions.
    for i in 0..max {
        let out = f.op(op).output.expect("marker op has an output");
        let Some(inv) = f.op(op).input(i) else { continue };
        let (rep_out, rep_in) = (h.high(out), h.high(inv));
        if !merge_test_required(f, h, pieces, rep_out, rep_in) {
            trim_slot(f, h, covers, op, i);
            continue;
        }
        for j in 0..i {
            let Some(invj) = f.op(op).input(j) else { continue };
            let (rep_j, rep_in) = (h.high(invj), h.high(inv));
            if !merge_test_required(f, h, pieces, rep_j, rep_in) {
                trim_slot(f, h, covers, op, i);
                break;
            }
        }
    }
    // Phase 2: cover restrictions — blind-sequential trims until the whole set tests clean.
    if !merge_test_all(f, h, pieces, covers, op) {
        let mut nexttrim = 0;
        while nexttrim < max {
            trim_slot(f, h, covers, op, nexttrim); // trim one of the branches
            if merge_test_all(f, h, pieces, covers, op) {
                break; // we successfully test merged everything
            }
            nexttrim += 1;
        }
        if nexttrim == max {
            // One last trim we can try.
            let first_new = f.num_varnodes() as u32;
            trim_op_output(f, op);
            h.extend_to(f.num_varnodes());
            let block = f.op(op).parent.expect("marker op has a parent block");
            refresh_covers(f, covers, block, first_new);
        }
    }
    // Phase 3: merge everything for real now.
    let out = f.op(op).output.expect("marker op has an output");
    for i in 0..max {
        let Some(inv) = f.op(op).input(i) else { continue };
        // The phase-2 trims leave every input coverable (a constant/annotation input fails
        // `merge_test_class` and gets trimmed into a COPY); a degenerate leftover is skipped
        // rather than unioned, mirroring the read-only `merge_markers` `mergeable` gate.
        if mergeable(f, inv) {
            h.union(out.0, inv.0);
        }
    }
}

/// The cumulative pairwise cover test of `Merge::mergeOp`'s phase 2 (merge.cc:742-745): seed the
/// testlist with the output's class (its own result discarded, as in Ghidra), then require every
/// input class to pass [`merge_test_class`] against everything before it.
fn merge_test_all(
    f: &Funcdata,
    h: &mut HighVariables,
    pieces: &VariablePieces,
    covers: &HashMap<VarnodeId, Cover>,
    op: super::op::OpId,
) -> bool {
    // Only the output's class and the input classes are ever consulted, so they are materialised
    // on demand from the union-find's member index instead of rebuilding the whole function's
    // rep -> members map for every call. Same classes, same order, same predicate.
    let mut testlist: Vec<(u32, Vec<VarnodeId>)> = Vec::new();
    let out = f.op(op).output.expect("marker op has an output");
    let rep_out = h.high(out);
    merge_test_class(f, h, pieces, covers, out, rep_out, &mut testlist);
    for i in 0..f.op(op).num_inputs() {
        let Some(inv) = f.op(op).input(i) else { continue };
        let rep_in = h.high(inv);
        if !merge_test_class(f, h, pieces, covers, inv, rep_in, &mut testlist) {
            return false;
        }
    }
    true
}

/// `Merge::mergeTest` (merge.cc:1657) — test a HighVariable (here: the class of `v`, rep `rep`)
/// for intersections against a list of other HighVariables; on success append it to the list.
/// A class without a cover (a constant or annotation — Ghidra `HighVariable::hasCover`,
/// variable.hh:217) always fails, which is what routes such an input into the blind trim loop.
fn merge_test_class(
    f: &Funcdata,
    h: &mut HighVariables,
    pieces: &VariablePieces,
    covers: &HashMap<VarnodeId, Cover>,
    v: VarnodeId,
    rep: u32,
    testlist: &mut Vec<(u32, Vec<VarnodeId>)>,
) -> bool {
    let vn = f.vn(v);
    if !mergeable(f, v) || vn.is_free() {
        return false; // no cover: constant / annotation / never-heritaged
    }
    // The extended members of this class, carried in the testlist so each class is built once
    // per test rather than looked up out of a whole-function map.
    let cls = h.class_of(rep);
    let mine = pieces.extend_members(h, &cls);
    for (other, theirs) in testlist.iter() {
        if *other == rep {
            continue; // same HighVariable (Ghidra intersection(a,a) == false)
        }
        if class_intersect(f, &mine, theirs, covers) {
            return false;
        }
    }
    testlist.push((rep, mine));
    true
}

/// `HighIntersectTest::intersection` → `blockIntersection` → `testBlockIntersection`
/// (variable.cc:1166/998/968) reduced to mosura's model: pairwise member-Cover intersection with
/// the copy-shadow exemptions — a member pair carrying the same value (`Varnode::copyShadow`, or
/// the cross-size `partialCopyShadow` standing in for Ghidra's VariablePiece branch) does not
/// forbid a merge. This is what lets a chain of trim COPYs of one value coexist in the test. (No
/// result cache, and no `testUntiedCallIntersection` — the addrtied-with-aliases vs call-crossing
/// branch needs the stack-affecting-ops model, unported.)
fn class_intersect(
    f: &Funcdata,
    a: &[VarnodeId],
    b: &[VarnodeId],
    covers: &HashMap<VarnodeId, Cover>,
) -> bool {
    for &x in a {
        // A member with no cover entry cannot block anything, so absence here is silent permission.
        // Since `cover_of` adds Ghidra's unconditional def point, only free/constant varnodes reach
        // this arm; anything else missing is a bug that would quietly widen merging (it did: the
        // reader-less INDIRECT placeholder, §"Order O"). Assert it rather than let it pass unseen.
        let Some(cx) = covers.get(&x) else {
            debug_assert!(
                !f.vn(x).is_written() && !f.vn(x).is_input(),
                "a def'd/input varnode has no cover: it would silently permit a merge"
            );
            continue;
        };
        for &y in b {
            let Some(cy) = covers.get(&y) else {
                debug_assert!(
                    !f.vn(y).is_written() && !f.vn(y).is_input(),
                    "a def'd/input varnode has no cover: it would silently permit a merge"
                );
                continue;
            };
            if !cx.intersects(cy) {
                continue;
            }
            let (vx, vy) = (f.vn(x), f.vn(y));
            let exempt = if vx.size == vy.size {
                copy_shadow(f, x, y)
            } else {
                vx.loc.space == vy.loc.space
                    && super::mergesnip::partial_copy_shadow(
                        f,
                        x,
                        y,
                        (vx.loc.offset as i64 - vy.loc.offset as i64) as i32,
                    )
            };
            if !exempt {
                return true;
            }
        }
    }
    false
}

/// `Varnode::copyShadow` (varnode.cc:977) — two varnodes carry the same value when one is reachable
/// from the other through a chain of COPY defs: trace each to the root of its copy chain and compare.
pub fn copy_shadow(f: &Funcdata, a: VarnodeId, b: VarnodeId) -> bool {
    if a == b {
        return true;
    }
    let mut vn = a;
    while f.vn(vn).is_written() && f.vn(vn).def.is_some_and(|d| f.op(d).code() == OpCode::Copy) {
        vn = f.op(f.vn(vn).def.unwrap()).input(0).expect("COPY has an input");
        if vn == b {
            return true;
        }
    }
    let mut other = b;
    while f.vn(other).is_written() && f.vn(other).def.is_some_and(|d| f.op(d).code() == OpCode::Copy)
    {
        other = f.op(f.vn(other).def.unwrap()).input(0).expect("COPY has an input");
        if vn == other {
            return true;
        }
    }
    false
}

/// [`trim_op_input`] plus the live-state upkeep the mid-pass mutation needs: grow the union-find for
/// the new COPY output (its own HighVariable until phase 3 unions it) and recompute covers (the
/// inserted op shifts every position in its block; Ghidra tracks this with cover-dirty flags).
fn trim_slot(
    f: &mut Funcdata,
    h: &mut HighVariables,
    covers: &mut HashMap<VarnodeId, Cover>,
    op: super::op::OpId,
    slot: usize,
) {
    let first_new = f.num_varnodes() as u32;
    let block = trim_op_input(f, op, slot);
    h.extend_to(f.num_varnodes());
    refresh_covers(f, covers, block, first_new);
}

/// Refresh `covers` after a trim/snip mutation confined to one `block` (a COPY insertion there,
/// plus read rewiring at ops whose cover position sits in that block): recomputing only the covers
/// that touch `block`, plus the varnodes created by the mutation (`first_new..`), reproduces
/// `all_covers(f)` exactly. Positions in every other block are untouched, a varnode read or
/// defined in `block` necessarily covers it (a phi read covers the predecessor whose exit it is
/// live at — where the trim COPY lands), and the rewiring gives reads only to the new varnodes,
/// so no absent-from-map cover can become non-empty. The former full `all_covers` rebuild per trim
/// was the dominant WAR2 decompile cost.
fn refresh_covers(
    f: &Funcdata,
    covers: &mut HashMap<VarnodeId, Cover>,
    block: super::block::BlockId,
    first_new: u32,
) {
    let pos = super::cover::op_positions(f);
    let mut redo: Vec<VarnodeId> = covers
        .iter()
        .filter(|(_, c)| c.block_range(block.0 as usize).is_some())
        .map(|(&v, _)| v)
        .collect();
    redo.extend((first_new..f.num_varnodes() as u32).map(VarnodeId));
    for v in redo {
        let c = super::cover::cover_of(f, v, &pos);
        if c.is_empty() {
            covers.remove(&v);
        } else {
            covers.insert(v, c);
        }
    }
}

/// `Merge::trimOpInput` (merge.cc:692) — snip input `slot` into a fresh `unique` via a COPY, then
/// rewire the op to read the COPY. The COPY's cover is tiny, so it no longer conflicts. Ghidra
/// branches on the op: a MULTIEQUAL places the COPY at the predecessor block's end (`opInsertEnd`,
/// at the block's stop address, `getIn(slot)`); any other marker op (an INDIRECT, whose slot-0 data
/// input is not a phi edge) places it right before the op in the op's own block (`opInsertBefore`,
/// at `op->getAddr()`). Returns the block the COPY was inserted into (for [`refresh_covers`]).
fn trim_op_input(f: &mut Funcdata, op: super::op::OpId, slot: usize) -> super::block::BlockId {
    if f.op(op).code() == OpCode::Multiequal {
        // MULTIEQUAL input `slot` corresponds to `in_edges[slot]` (heritage wires `op_set_input(phi,
        // j, ...)` with `j = in_edges.position(pred)`).
        let parent = f.op(op).parent.expect("MULTIEQUAL has a parent block");
        let pred = f.block(parent).in_edges[slot];
        // Ghidra places the COPY at the predecessor block's stop address (`bb->getStop()`).
        let pc = f.block(pred).ops.last().map(|&o| f.op(o).seqnum.pc).unwrap_or(f.addr);
        let vn = f.op(op).input(slot).expect("trimmed slot has an input");
        let size = f.vn(vn).size;
        let uniq = f.num_ops() as u32;
        let copyop = f.new_op(OpCode::Copy, super::op::SeqNum { pc, uniq }, vec![vn]);
        let cout = f.new_output_unique(copyop, size);
        f.op_set_input(op, slot, cout);
        f.op_insert_end(copyop, pred);
        // `allocateCopyTrim` records every trim COPY (merge.cc:432) for ActionDominantCopy.
        f.copy_trims.push(copyop);
        pred
    } else {
        // Ghidra's else branch (merge.cc:701/709): `pc = op->getAddr()`, `opInsertBefore(copyop,
        // op)` — the COPY sits in the op's own block just before it. An INDIRECT reaches here (its
        // slot-0 data input is trimmed by `merge_op` with `max == 1`); its parent may be the entry
        // block, which has no in-edges, so the MULTIEQUAL predecessor lookup does not apply.
        let pc = f.op(op).seqnum.pc;
        let vn = f.op(op).input(slot).expect("trimmed slot has an input");
        let size = f.vn(vn).size;
        let uniq = f.num_ops() as u32;
        let copyop = f.new_op(OpCode::Copy, super::op::SeqNum { pc, uniq }, vec![vn]);
        let cout = f.new_output_unique(copyop, size);
        f.op_set_input(op, slot, cout);
        f.op_insert_before(copyop, op);
        f.copy_trims.push(copyop);
        f.op(op).parent.expect("marker op has a parent block")
    }
}

/// `Merge::trimOpOutput` (merge.cc:658) — trim the *output* HighVariable of a forced-merge op so
/// its Cover is tiny: the original output Varnode is *moved* onto a new COPY inserted right after
/// the op, and the op is given a fresh stubby `unique` output that the COPY reads. (For an INDIRECT
/// Ghidra inserts after the op causing the indirect effect — the mergeIndirect scope; a MULTIEQUAL
/// inserts after itself.)
fn trim_op_output(f: &mut Funcdata, op: super::op::OpId) {
    let vn = f.op(op).output.expect("trimmed op has an output");
    let size = f.vn(vn).size;
    let pc = f.op(op).seqnum.pc;
    let uniq = f.num_ops() as u32;
    // merge.cc:663-666: for an INDIRECT the COPY goes AFTER THE SOURCE OF THE INDIRECT (the
    // call/store it is guarded by), not after the INDIRECT — which sits BEFORE that op. Placed
    // after the INDIRECT, a global's post-store version was written before the STORE that must
    // read the old one: WAR2 FUN_0002cca0 (a list push) printed `iRam = iVar1; *(param_1 + 8) =
    // iRam;` where Ghidra prints `*(param_1 + 8) = iRam; iRam = iVar1;`.
    let afterop = if f.op(op).code() == OpCode::Indirect {
        f.op(op).guarded_op().filter(|&g| !f.op(g).is_dead()).unwrap_or(op)
    } else {
        op
    };
    let tiny = f.new_output_unique(op, size); // output of op is now the stubby uniq…
    let copyop = f.new_op(OpCode::Copy, super::op::SeqNum { pc, uniq }, vec![tiny]);
    f.op_set_output(copyop, vn); // …and the original output is bumped forward slightly
    f.op_insert_after(copyop, afterop);
}

/// `Merge::processCopyTrims` (merge.cc:1415), the body of `ActionDominantCopy`
/// (coreaction.cc:5723): the merge trimming process can insert multiple COPYs from the same source
/// Varnode into one HighVariable; collect the recorded trim COPYs ([`Funcdata::copy_trims`]), and
/// for each HighVariable with at least two of them try to replace same-source groups with a single
/// *dominant* COPY ([`build_dominant_copy`]). The high state is Ghidra's at that action: required
/// merges + the explicit/implied classification + the COPY merges (`ActionMergeCopy` runs at
/// coreaction.cc:5722, just before), re-derived here read-only. Groups are re-derived from scratch
/// after each replacement (Ghidra's live HighVariable state equivalent).
fn process_copy_trims(f: &mut Funcdata) {
    let trims: Vec<super::op::OpId> = std::mem::take(&mut f.copy_trims);
    if f.num_blocks() == 0 {
        return;
    }
    let mut done: std::collections::HashSet<super::op::OpId> = std::collections::HashSet::new();
    'outer: loop {
        // Ghidra's state at the ActionDominantCopy slot.
        let covers = all_covers(f);
        let mut h = HighVariables::new(f.num_varnodes());
        let pieces = merge_addrtied(f, &mut h);
        merge_markers(f, &mut h, &pieces);
        let explicit = mark_explicit(f, &mut h, &covers);
        let covers = super::cover::all_covers_extended(f, &explicit);
        merge_copy(f, &mut h, &pieces, &covers, &explicit);
        let of: Vec<u32> = (0..f.num_varnodes() as u32).map(|i| h.high(VarnodeId(i))).collect();

        // Walk the trigger highs in trim order; process the first unprocessed same-source group of
        // size >= 2 (keyed by its leading COPY op, stable across re-derivations), then re-derive.
        let mut tried: std::collections::HashSet<u32> = std::collections::HashSet::new();
        for &t in &trims {
            if f.op(t).is_dead() {
                continue;
            }
            let Some(out) = f.op(t).output else { continue };
            let rep = of[out.0 as usize];
            if !tried.insert(rep) {
                continue;
            }
            let copy_ins = find_all_into_copies(f, &of, rep, true);
            let mut pos = 0;
            while pos < copy_ins.len() {
                let in_vn = f.op(copy_ins[pos]).input(0);
                let mut sz = 1;
                while pos + sz < copy_ins.len() && f.op(copy_ins[pos + sz]).input(0) == in_vn {
                    sz += 1;
                }
                if sz > 1 && done.insert(copy_ins[pos]) {
                    build_dominant_copy(f, &mut h, &covers, rep, &copy_ins[pos..pos + sz]);
                    continue 'outer; // graph changed (or group resolved) — re-derive state
                }
                pos += sz;
            }
        }
        break;
    }
}

/// `Merge::findAllIntoCopies` (merge.cc:1290): collect the COPYs whose output belongs to
/// HighVariable `rep` but whose input comes from a different HighVariable, sorted first by the
/// input Varnode (creation order) then by block order (`compareCopyByInVarnode`, merge.cc:1045).
/// With `filter_temps` only COPYs with a `unique`-space output are returned (the trim temps).
/// `of` is the frozen HighVariable representative per varnode.
fn find_all_into_copies(
    f: &Funcdata,
    of: &[u32],
    rep: u32,
    filter_temps: bool,
) -> Vec<super::op::OpId> {
    let uniq_space = f.spaces.by_name("unique");
    let mut copy_ins: Vec<super::op::OpId> = Vec::new();
    for i in 0..f.num_varnodes() as u32 {
        let v = VarnodeId(i);
        if of[v.0 as usize] != rep {
            continue;
        }
        let vn = f.vn(v);
        if !vn.is_written() {
            continue;
        }
        let def = vn.def.expect("written varnode has a def");
        if f.op(def).code() != OpCode::Copy || f.op(def).is_dead() {
            continue;
        }
        let Some(inv) = f.op(def).input(0) else { continue };
        if of[inv.0 as usize] == rep {
            continue; // internal copy, not a copy INTO the variable
        }
        if filter_temps && Some(vn.loc.space) != uniq_space {
            continue;
        }
        copy_ins.push(def);
    }
    let block_pos = |op: super::op::OpId| -> (u32, usize) {
        let b = f.op(op).parent.expect("live COPY has a parent block");
        let idx = f.block(b).ops.iter().position(|&o| o == op).unwrap_or(usize::MAX);
        (b.0, idx)
    };
    copy_ins.sort_by_key(|&op| {
        let inv = f.op(op).input(0).expect("COPY has an input");
        let (b, idx) = block_pos(op);
        (f.vn(inv).create_index, b, idx)
    });
    copy_ins
}

/// `Merge::buildDominantCopy` (merge.cc:1151): try to replace a group of COPYs from the same
/// source Varnode (all outputs instances of one HighVariable) with a single COPY that dominates
/// them — either an existing group member whose block is the common dominator, or a new COPY built
/// at that block's stop. Each replaced COPY's reads are repointed at the dominant output, unless
/// doing so would intersect the HighVariable's remaining Cover; if fewer than two COPYs are
/// replaceable the whole attempt is abandoned.
fn build_dominant_copy(
    f: &mut Funcdata,
    h: &mut HighVariables,
    covers: &HashMap<VarnodeId, Cover>,
    rep: u32,
    group: &[super::op::OpId],
) {
    let doms = super::dominator::compute(f);
    let blocks: Vec<usize> = group
        .iter()
        .map(|&op| f.op(op).parent.expect("live COPY has a parent block").0 as usize)
        .collect();
    let dom_bl = common_dominator(&doms, &blocks);
    let mut dom_copy = group[0];
    let root_vn = f.op(dom_copy).input(0).expect("COPY has an input");
    let mut dom_vn = f.op(dom_copy).output.expect("COPY has an output");
    let dom_copy_is_new = dom_bl != blocks[0];
    if dom_copy_is_new {
        // Build the new dominating COPY at the common dominator's stop.
        let bid = super::block::BlockId(dom_bl as u32);
        let pc = f.block(bid).ops.last().map(|&o| f.op(o).seqnum.pc).unwrap_or(f.addr);
        let uniq = f.num_ops() as u32;
        let size = f.vn(root_vn).size;
        dom_copy = f.new_op(OpCode::Copy, super::op::SeqNum { pc, uniq }, vec![root_vn]);
        dom_vn = f.new_output_unique(dom_copy, size);
        f.op_insert_end(dom_copy, bid);
        h.extend_to(f.num_varnodes());
    }
    // The Cover the HighVariable would keep after removing all the COPYs from rootVn
    // (merge.cc:1185-1196): every instance except the rootVn copy-shadows.
    let fresh; // recompute if the inserted COPY shifted positions
    let covers = if dom_copy_is_new {
        fresh = all_covers(f);
        &fresh
    } else {
        covers
    };
    let mut b_cover = Cover::default();
    for v in h.class_of(rep) {
        let vn = f.vn(v);
        if vn.is_written() {
            let d = vn.def.expect("written varnode has a def");
            if f.op(d).code() == OpCode::Copy
                && f.op(d).input(0).is_some_and(|iv| copy_shadow(f, iv, root_vn))
            {
                continue;
            }
        }
        if let Some(c) = covers.get(&v) {
            b_cover.merge_from(c);
        }
    }
    // Test which COPYs can be replaced by a read of the dominant Varnode.
    let pos = super::cover::op_positions(f);
    let mut marked = vec![false; group.len()];
    let mut count = group.len();
    for (i, &op) in group.iter().enumerate() {
        if op == dom_copy {
            continue; // no intersections from domVn already proven
        }
        let out_vn = f.op(op).output.expect("COPY has an output");
        let a_cover = super::cover::cover_replacing(f, dom_vn, out_vn, &pos);
        if b_cover.intersects(&a_cover) {
            count -= 1;
            marked[i] = true;
        }
    }
    if count <= 1 {
        // Don't bother if we only replace one COPY with another.
        marked.iter_mut().for_each(|m| *m = true);
        if dom_copy_is_new {
            destroy_op(f, dom_copy);
        }
    }
    // Replace all non-intersecting COPYs with a read of the dominating Varnode.
    for (i, &op) in group.iter().enumerate() {
        if marked[i] {
            continue;
        }
        let out_vn = f.op(op).output.expect("COPY has an output");
        if out_vn != dom_vn {
            f.total_replace(out_vn, dom_vn);
            destroy_op(f, op);
        }
    }
}

/// `Merge::markInternalCopies` (merge.cc:1444), the body of `ActionCopyMarker`
/// (coreaction.cc:5729): the ops that copy data *within* one variable, or repeat an earlier copy,
/// are not printed. Ghidra switches on three opcodes and mosura now models all three —
///
/// * **COPY** — the *shadow assignment* skip (a never-read output whose HighVariable has another
///   instance live at the same point carries no new value, merge.cc:1470-1474) and the *redundant
///   copy* marking (`processHighRedundantCopy`/`markRedundantCopies`/`checkCopyPair`,
///   merge.cc:1345/1252/1112). The same-HighVariable internal-copy arm (merge.cc:1461) is printc's
///   existing `hidden` test.
/// * **PIECE / SUBPIECE** (merge.cc:1487/1516) — an op that assembles a variable out of its own
///   pieces, or extracts one, is internal to a `VariableGroup` and prints as a piece accessor at the
///   use site instead of as a statement. Both arms also force the *source* explicit
///   (`clearImplied`/`setExplicit`), which is what gives the accessor a name to hang off.
///
/// `of` is the frozen full-merge representative per varnode and `members` its class lists —
/// Ghidra's state at ActionCopyMarker (after all merging). Returns the non-printing ops and the
/// Varnodes the piece arms force explicit.
pub(crate) fn copy_marker_nonprinting(
    f: &Funcdata,
    of: &[u32],
    members: &HashMap<u32, Vec<VarnodeId>>,
    covers: &HashMap<VarnodeId, Cover>,
    pieces: &VariablePieces,
) -> (std::collections::HashSet<super::op::OpId>, Vec<VarnodeId>) {
    let mut nonprint: std::collections::HashSet<super::op::OpId> = std::collections::HashSet::new();
    let mut force_explicit: Vec<VarnodeId> = Vec::new();
    if f.num_blocks() == 0 {
        return (nonprint, force_explicit);
    }
    // The PIECE and SUBPIECE arms (merge.cc:1487/1516). Both require every operand to be a piece of
    // the SAME group, and the offsets to line up exactly, so the op only re-expresses bytes the
    // variable already holds. Little-endian only: mosura's corpus targets are little-endian, and the
    // big-endian offset arithmetic is written out in the source for when a big-endian target lands.
    for op in f.op_ids() {
        let o = f.op(op);
        if o.is_dead() {
            continue;
        }
        let internal = match o.code() {
            OpCode::Piece => (|| {
                let (v1, v2, v3) = (o.output?, o.input(0)?, o.input(1)?);
                let (g1, off1, _) = pieces.at(v1)?;
                let (g2, off2, _) = pieces.at(v2)?;
                let (g3, off3, _) = pieces.at(v3)?;
                if g1 != g2 || g1 != g3 {
                    return None;
                }
                // in(0) is the most significant half, in(1) the least — little-endian puts the
                // least-significant piece at the output's own offset.
                (off3 == off1 && off2 == off1 + f.vn(v3).size).then_some(vec![v2, v3])
            })(),
            OpCode::Subpiece => (|| {
                let (v1, v2, cst) = (o.output?, o.input(0)?, o.input(1)?);
                if !f.vn(cst).is_constant() {
                    return None;
                }
                let (g1, off1, _) = pieces.at(v1)?;
                let (g2, off2, _) = pieces.at(v2)?;
                if g1 != g2 {
                    return None;
                }
                (off2 + f.vn(cst).loc.offset as u32 == off1).then_some(vec![v2])
            })(),
            _ => None,
        };
        if let Some(sources) = internal {
            nonprint.insert(op);
            force_explicit.extend(sources);
        }
    }
    let pos = super::cover::op_positions(f);
    // First pass: count cross-high COPYs into each high (Ghidra's copyIn1/copyIn2 marks) and mark
    // shadow assignments.
    let mut copies_in: HashMap<u32, u32> = HashMap::new();
    let mut multi_copy: Vec<u32> = Vec::new();
    for op in f.op_ids() {
        let o = f.op(op);
        if o.is_dead() || o.code() != OpCode::Copy {
            continue;
        }
        let Some(out) = o.output else { continue };
        let Some(inv) = o.input(0) else { continue };
        let rep = of[out.0 as usize];
        if rep == of[inv.0 as usize] {
            continue; // internal copy — printc's same-high arm already hides it
        }
        let n = copies_in.entry(rep).or_insert(0);
        *n += 1;
        if *n == 2 {
            multi_copy.push(rep);
        }
        // Don't print shadow assignments: a never-read output whose value another live instance of
        // the variable already carries.
        if f.vn(out).descend.is_empty() && shadowed_varnode(f, of, members, covers, &pos, out) {
            nonprint.insert(op);
        }
    }
    // Second pass: redundant-copy marking per multi-copy high.
    let doms = super::dominator::compute(f);
    let empty: Vec<VarnodeId> = Vec::new();
    for rep in multi_copy {
        let copy_ins = find_all_into_copies(f, of, rep, false);
        if copy_ins.len() < 2 {
            continue;
        }
        let mems = members.get(&rep).unwrap_or(&empty);
        let mut posn = 0;
        while posn < copy_ins.len() {
            let in_vn = f.op(copy_ins[posn]).input(0);
            let mut sz = 1;
            while posn + sz < copy_ins.len() && f.op(copy_ins[posn + sz]).input(0) == in_vn {
                sz += 1;
            }
            if sz > 1 {
                // markRedundantCopies (merge.cc:1252): from the back, find a dominating earlier
                // COPY that makes each later one redundant.
                for i in (1..sz).rev() {
                    let sub_op = copy_ins[posn + i];
                    for j in (0..i).rev() {
                        let dom_op = copy_ins[posn + j];
                        if check_copy_pair(f, mems, covers, &doms, &pos, dom_op, sub_op) {
                            nonprint.insert(sub_op);
                            break;
                        }
                    }
                }
            }
            posn += sz;
        }
    }
    (nonprint, force_explicit)
}

/// `Merge::shadowedVarnode` (merge.cc:1272): is the given Varnode shadowed by another Varnode in
/// the same HighVariable — another instance whose live range really intersects it (which, both
/// being one variable, means it carries the same value there)? The never-read `vn` contributes its
/// def point ([`super::cover::def_point_cover`]) where mosura's read-derived cover is empty.
fn shadowed_varnode(
    f: &Funcdata,
    of: &[u32],
    members: &HashMap<u32, Vec<VarnodeId>>,
    covers: &HashMap<VarnodeId, Cover>,
    pos: &super::cover::OpPositions,
    v: VarnodeId,
) -> bool {
    let empty: Vec<VarnodeId> = Vec::new();
    let mems = members.get(&of[v.0 as usize]).unwrap_or(&empty);
    let own;
    let vcov = match covers.get(&v) {
        Some(c) => c,
        None => {
            own = super::cover::def_point_cover(f, v, pos);
            &own
        }
    };
    for &o in mems {
        if o == v {
            continue;
        }
        if covers.get(&o).is_some_and(|oc| oc.intersects(vcov)) {
            return true;
        }
    }
    false
}

/// `Merge::checkCopyPair` (merge.cc:1112): the second COPY is redundant if the first dominates it
/// and no other write to the HighVariable (from a different source Varnode) lands between the
/// first COPY's def and the second COPY's read.
fn check_copy_pair(
    f: &Funcdata,
    members: &[VarnodeId],
    _covers: &HashMap<VarnodeId, Cover>,
    doms: &super::dominator::Dominators,
    pos: &super::cover::OpPositions,
    dom_op: super::op::OpId,
    sub_op: super::op::OpId,
) -> bool {
    let (Some(db), Some(sb)) = (f.op(dom_op).parent, f.op(sub_op).parent) else { return false };
    if !doms.dominates(db.0 as usize, sb.0 as usize) {
        return false;
    }
    let Some(dom_out) = f.op(dom_op).output else { return false };
    // range = [def(domOp's output) .. the read at subOp] (Cover::addDefPoint + addRefPoint).
    let range = super::cover::cover_to_read(f, dom_out, sub_op, pos);
    let in_vn = f.op(dom_op).input(0);
    for &v in members {
        let vn = f.vn(v);
        if !vn.is_written() {
            continue;
        }
        let d = vn.def.expect("written varnode has a def");
        if f.op(d).code() == OpCode::Copy && f.op(d).input(0) == in_vn {
            continue; // a COPY from the same source as domOp/subOp is not intervening
        }
        if let Some((b, i)) = super::cover::op_index(f, d, pos) {
            if range.contains_point(b, 2 * i as i32 + 2) {
                return false; // an intervening write — subOp is not redundant
            }
        }
    }
    true
}

/// `FlowBlock::findCommonBlock` over a set (block.cc:796) — the nearest common dominator of the
/// given blocks, via the immediate-dominator chains.
fn common_dominator(doms: &super::dominator::Dominators, blocks: &[usize]) -> usize {
    let mut res = blocks[0];
    for &b in &blocks[1..] {
        let mut anc = std::collections::HashSet::new();
        let mut n = res;
        loop {
            anc.insert(n);
            if doms.idom[n] == n {
                break;
            }
            n = doms.idom[n];
        }
        let mut m = b;
        while !anc.contains(&m) {
            m = doms.idom[m];
        }
        res = m;
    }
    res
}

/// `Funcdata::opDestroy` plus the block unlink (Ghidra's op lists are intrusive; mosura removes
/// from the owning block's op vector separately, as the dead-code sweep does).
fn destroy_op(f: &mut Funcdata, op: super::op::OpId) {
    let parent = f.op(op).parent;
    f.op_destroy(op);
    if let Some(b) = parent {
        let kept: Vec<super::op::OpId> =
            f.block(b).ops.iter().copied().filter(|&o| o != op).collect();
        f.set_block_ops(b, kept);
    }
}

/// Pipeline action wrapping [`process_copy_trims`] — Ghidra's `ActionDominantCopy`
/// (coreaction.cc:5723, `rule_onceperfunc`), run after the marker trims so the multiple COPYs the
/// trimming inserted from one source collapse to a single dominant COPY (switchloop case 4's
/// duplicate `param_1 = uVar2`).
pub struct ActionDominantCopy;

impl super::action::Action for ActionDominantCopy {
    fn name(&self) -> &str {
        "dominantcopy"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        process_copy_trims(data);
        0
    }
}

/// Graph-mutating pipeline action wrapping [`merge_marker_trim`] — the mosura analogue of Ghidra's
/// `Merge::mergeMarker` (`mergeOp`/`trimOpInput`/`trimOpOutput`, merge.cc:889/719/692/658), run
/// inside `ActionMergeRequired` (`coreaction.cc:5718`) after `mergeAddrTied`
/// ([`super::mergesnip::ActionMergeRequired`]).
pub struct ActionMergeMarkerTrim;

impl super::action::Action for ActionMergeMarkerTrim {
    fn name(&self) -> &str {
        "mergemarkertrim"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        let before = data.num_ops();
        merge_marker_trim(data);
        (data.num_ops() - before) as u32
    }
}

/// Ghidra `ActionMarkExplicit` + `ActionMarkImplied` (coreaction.cc:3237/3416) as a real
/// in-pipeline pass that SETS the EXPLICIT/IMPLIED flag on every varnode, on the FINAL pre-cast
/// graph. This freezes the leading/trailing classification core (the same one printc's `is_explicit`
/// computes) BEFORE `ActionSetCasts`, matching Ghidra's ordering (markImplied 5720 < setCasts 5735):
/// the CAST ops setcasts inserts then can't perturb the use-count/cover classification (a cast
/// interposed between a def and its uses would otherwise flip a value from explicit to implied — the
/// switchloop/stackstring regressions). It replicates printc's `is_explicit` core exactly — the
/// full-merge `high_of` for the persistent-COPY arm, the required-merges-only classes for the
/// implied-cover walk — so on fixtures where casts don't perturb, the frozen flag equals the old
/// print-time recompute (no churn); the print-only additions (`slot_write`, `high_ram_off`) stay in
/// printc as cast-invariant OR-terms.
pub fn mark_explicit_flags(f: &mut Funcdata) {
    let (mut h, _pieces) = merge(f);
    let high_of: Vec<u32> = (0..f.num_varnodes() as u32).map(|i| h.high(VarnodeId(i))).collect();
    let covers = all_covers(f);
    let mut ih = merge_required_only(f);
    let ih_of: Vec<u32> = (0..f.num_varnodes() as u32).map(|i| ih.high(VarnodeId(i))).collect();
    let mut ih_members: HashMap<u32, Vec<VarnodeId>> = HashMap::new();
    for (i, &rep) in ih_of.iter().enumerate() {
        ih_members.entry(rep).or_default().push(VarnodeId(i as u32));
    }
    // (Constants come back `false` from `explicit_leading`, so the old constant special-case is
    // subsumed by the shared traversal.)
    let explicit = classify_explicit(f, &high_of, &ih_of, &ih_members, &covers);
    for i in 0..f.num_varnodes() as u32 {
        let v = VarnodeId(i);
        if explicit[i as usize] && !f.vn(v).is_constant() {
            f.vn_mut(v).set_explicit();
        } else {
            f.vn_mut(v).set_implied();
        }
    }
}

/// The HighVariables frozen at Ghidra's merge slot, with the lookup tables the type channel needs:
/// the union-find itself (for printc), each Varnode's representative, and each variable's member
/// list. Ghidra keeps the equivalent as `Varnode::high` plus `HighVariable::inst`.
#[derive(Clone)]
pub struct FrozenHighs {
    uf: HighVariables,
    of: Vec<u32>,
    members: HashMap<u32, Vec<VarnodeId>>,
    /// The overlap groups `mergeAddrTied` built (Ghidra's `VariableGroup`/`VariablePiece`), so the
    /// printer can render a piece that does not span its group as a partial symbol.
    pieces: VariablePieces,
}

impl FrozenHighs {
    fn new(f: &Funcdata) -> Self {
        let (mut uf, pieces) = merge(f);
        let of: Vec<u32> = (0..f.num_varnodes() as u32).map(|i| uf.high(VarnodeId(i))).collect();
        let mut members: HashMap<u32, Vec<VarnodeId>> = HashMap::new();
        for (i, &rep) in of.iter().enumerate() {
            let v = VarnodeId(i as u32);
            if mergeable(f, v) {
                members.entry(rep).or_default().push(v);
            }
        }
        FrozenHighs { uf, of, members, pieces }
    }

    /// The union-find, for callers that need to compare two Varnodes' variables.
    pub fn union_find(&self) -> &HighVariables {
        &self.uf
    }

    /// The overlap groups (Ghidra's `VariableGroup`/`VariablePiece`), for the printer's partial
    /// symbol rendering.
    pub fn pieces(&self) -> &VariablePieces {
        &self.pieces
    }

    /// Ghidra `Varnode::getHighTypeReadFacing`/`getHighTypeDefFacing` (varnode.cc:651/665) →
    /// `vn->getHigh()->getType()`: the data-type of the *variable* a Varnode belongs to, as opposed
    /// to [`super::varnode::Varnode::get_type`], the type propagation committed onto that one
    /// Varnode. (The union-resolution half of the read/def-facing pair is deferred with the union
    /// lattice, so the two coincide here.)
    ///
    /// Recomputed on each call from the members' current types rather than cached. Ghidra caches it
    /// on `HighVariable::type` but invalidates on every `Varnode::updateType` via `typeDirty`
    /// (varnode.cc:456, variable.cc:400), and `ActionSetCasts::castOutput` *relies* on that: it
    /// calls `updateType` and then immediately re-reads `getHighTypeDefFacing` to see the recomputed
    /// value (coreaction.cc:2570/2579). A cache without the dirty flag would hand back a stale type
    /// there. The value is a pure function of the member types, so computing it fresh is
    /// observationally identical to Ghidra's invalidate-and-recompute, and needs no flag.
    ///
    /// A Varnode created *after* the freeze — the CAST varnodes `ActionSetCasts` inserts — has no
    /// entry, and its own type is the answer: Ghidra gives every new Varnode a fresh HighVariable,
    /// so such a value is a singleton variable.
    pub fn type_of(&self, f: &Funcdata, v: VarnodeId) -> Datatype {
        match self.of.get(v.0 as usize).and_then(|rep| self.members.get(rep)) {
            Some(m) => high_type(f, m),
            None => f.vn(v).get_type(),
        }
    }
}

/// [`FrozenHighs::type_of`] on the function's frozen HighVariables — Ghidra's
/// `vn->getHighTypeReadFacing(op)`. Panics if the merge slot was never reached, rather than falling
/// back to the per-Varnode type: the two are different channels and silently substituting one for
/// the other is the bug this split exists to remove.
pub fn high_type_read_facing(f: &Funcdata, v: VarnodeId) -> Datatype {
    f.highs
        .as_ref()
        .expect("high-facing type read before ActionMergeType froze the HighVariables")
        .type_of(f, v)
}

/// Ghidra's merge slot, `ActionMergeType` (coreaction.cc:5727) — the last of the merge actions
/// (`ActionMergeRequired` 5718 … `ActionMergeCopy` 5722, `ActionDominantCopy` 5723,
/// `ActionMergeAdjacent` 5726, `ActionMergeType` 5727), all of which run *before*
/// `ActionSetCasts` (:5735). [`merge`] computes that whole sequence in one pass, so running it
/// here and storing the result on the `Funcdata` puts mosura's HighVariables at Ghidra's slot.
///
/// Why it has to be frozen here: Ghidra's merging is finished before a single CAST op exists, and
/// every CAST varnode `ActionSetCasts` inserts afterwards gets its own fresh HighVariable.
/// Recomputing the merge at print time — over a graph that now contains those casts — partitions a
/// *different* varnode set and can therefore reach a different answer. That is the same defect
/// class as the explicit/implied classification being recomputed after the casts, fixed one slot
/// over by [`ActionMarkImplied`].
pub struct ActionMergeType;

impl super::action::Action for ActionMergeType {
    fn name(&self) -> &str {
        "mergetype"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        // Skip during the jump-table recovery probe, as [`ActionMarkImplied`] does: the frozen
        // HighVariables are read only by printc, which the probe never runs.
        if data.table_recovery_probe {
            return 0;
        }
        data.highs = Some(FrozenHighs::new(data));
        0
    }
}

/// Ghidra's `ActionCopyMarker` (coreaction.cc:5729) — `Merge::markInternalCopies` (merge.cc:1444)
/// run as a real pipeline action, after the merges finish (`ActionMergeType`, :5727) and *before*
/// `ActionSetCasts` (:5735), which is where Ghidra runs it.
///
/// Why the slot matters: `markInternalCopies` switches on COPY, PIECE and SUBPIECE, and every arm
/// reasons about the relationship between the output Varnode's HighVariable (and Cover) and its
/// inputs'. `ActionSetCasts::castOutput` (coreaction.cc:2532) *rewires* an op whose output needs a
/// cast — the op is given a fresh unique to write and the new CAST produces the original Varnode —
/// so post-cast those ops have a different output Varnode, in a fresh singleton HighVariable, with a
/// different live range. Deciding the marks at print time therefore answers the question over a
/// graph Ghidra never analyzed. The Covers this consumes are the same story one level down: `Cover`
/// belongs to `HighVariable` and is built with the merges at 5717-5727, before any CAST exists.
///
/// [`copy_marker_nonprinting`] takes the frozen full-merge classes, so this reads
/// [`Funcdata::highs`] rather than re-running [`merge`] — the same tables printc used to build, now
/// built one slot earlier.
pub struct ActionCopyMarker;

impl super::action::Action for ActionCopyMarker {
    fn name(&self) -> &str {
        "copymarker"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        // Skip during the jump-table recovery probe, as [`ActionMergeType`] does — the marks are
        // read only by printc, which the probe never runs (and `highs` is `None` there).
        if data.table_recovery_probe {
            return 0;
        }
        let mut h = data
            .highs
            .as_ref()
            .expect("ActionCopyMarker requires the HighVariables frozen by ActionMergeType")
            .union_find()
            .clone();
        h.extend_to(data.num_varnodes());
        let of: Vec<u32> =
            (0..data.num_varnodes() as u32).map(|i| h.high(VarnodeId(i))).collect();
        let mut members: HashMap<u32, Vec<VarnodeId>> = HashMap::new();
        for (i, &rep) in of.iter().enumerate() {
            members.entry(rep).or_default().push(VarnodeId(i as u32));
        }
        let covers = all_covers(data);
        let pieces = data.highs.as_ref().expect("frozen above").pieces().clone();
        let (nonprint, force_explicit) =
            copy_marker_nonprinting(data, &of, &members, &covers, &pieces);
        // merge.cc:1500/1523 — the piece arms force their source explicit, so the accessor the use
        // site now renders has a named variable to hang off.
        for v in force_explicit {
            data.vn_mut(v).set_explicit();
        }
        data.nonprinting = Some(nonprint);
        0
    }
}

/// Pipeline action wrapping [`mark_explicit_flags`] — Ghidra's `ActionMarkExplicit`/`ActionMarkImplied`
/// (coreaction.cc:5719-5720), run just before `ActionSetCasts` so the explicit/implied classification
/// is frozen against the casts setcasts inserts.
pub struct ActionMarkImplied;

impl super::action::Action for ActionMarkImplied {
    fn name(&self) -> &str {
        "markimplied"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        // Skip during the jump-table recovery probe: the flags are read only by printc (not run in
        // the probe) and ActionSetCasts (gated off in the probe), so they are inert there.
        if data.table_recovery_probe {
            return 0;
        }
        mark_explicit_flags(data);
        // Record how far the classification reached. Ghidra classifies once, here (5719-5720), over
        // the Varnodes that exist at this point; `ActionSetCasts` (5735) creates more and sets their
        // flag itself, with no later pass to re-derive it.
        data.classified_upto = Some(data.num_varnodes());
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::space::{Address, SpaceManager};
    use crate::decompile::{BlockBasic, BlockId, Funcdata, OpCode, SeqNum};

    /// Regression for the WAR2 `FUN_00011954` panic (`merge.rs:1205` index-out-of-bounds): a
    /// non-MULTIEQUAL marker op (an INDIRECT, whose slot-0 data input `merge_op` may force-trim)
    /// must trim in its OWN block at `op->getAddr()` (`opInsertBefore`), not via the MULTIEQUAL
    /// predecessor lookup `in_edges[slot]`. `Merge::trimOpInput` (merge.cc:692) branches on the op
    /// for exactly this reason; porting only the MULTIEQUAL branch panicked when the INDIRECT sat in
    /// the entry block, which has no in-edges.
    #[test]
    fn trim_op_input_on_indirect_trims_in_own_block() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0x10), uniq: 0 };
        // A source value (slot 0, trimmed) and a cause annotation (slot 1). The INDIRECT sits in
        // block 0 — the entry block, in_edges == [] — which is what triggered the OOB.
        let src = f.new_const(8, 7);
        let cause = f.new_const(8, 0);
        let ind = f.new_op(OpCode::Indirect, seq, vec![src, cause]);
        let _out = f.new_output(ind, 8, Address::new(reg, 0));
        f.set_blocks(vec![BlockBasic { ops: vec![], in_edges: vec![], out_edges: vec![] }]);
        f.op_insert_end(ind, BlockId(0));

        let before = f.num_ops();
        // Must not panic (the regression) and must add exactly one COPY.
        trim_op_input(&mut f, ind, 0);
        assert_eq!(f.num_ops(), before + 1, "trim inserts one COPY");

        // slot 0 now reads the trim COPY, defined in block 0, placed BEFORE the INDIRECT.
        let copy_out = f.op(ind).input(0).expect("trimmed slot rewired");
        let copydef = f.vn(copy_out).def.expect("trim COPY has a def");
        assert_eq!(f.op(copydef).code(), OpCode::Copy);
        assert_eq!(f.op(copydef).parent, Some(BlockId(0)), "COPY lands in the op's own block");
        let ops = &f.block(BlockId(0)).ops;
        let pi = ops.iter().position(|&o| o == ind).unwrap();
        let pc = ops.iter().position(|&o| o == copydef).unwrap();
        assert!(pc < pi, "trim COPY is inserted before the INDIRECT (opInsertBefore)");
    }

    #[test]
    fn multiequal_merges_its_versions() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        // x1, x2 are two SSA versions; phi = MULTIEQUAL(x1, x2, #0)
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let one = f.new_const(8, 1);
        let c1 = f.new_op(OpCode::Copy, seq, vec![one]);
        let x1 = f.new_output(c1, 8, Address::new(reg, 0));
        let two = f.new_const(8, 2);
        let c2 = f.new_op(OpCode::Copy, seq, vec![two]);
        let x2 = f.new_output(c2, 8, Address::new(reg, 0));
        let zero = f.new_const(8, 0);
        let phi = f.new_op(OpCode::Multiequal, seq, vec![x1, x2, zero]);
        let xp = f.new_output(phi, 8, Address::new(reg, 0));
        f.set_blocks(vec![BlockBasic { ops: vec![c1, c2, phi], ..Default::default() }]);

        let (mut h, _) = merge(&f);
        // the phi output and both written versions are one HighVariable…
        assert!(h.same(xp, x1) && h.same(xp, x2));
        // …but the constant is its own thing.
        assert!(!h.same(xp, zero));
        assert_eq!(h.count([xp, x1, x2]), 1);
    }

    /// Regression for the cover/interference bug (pointercmp): a register value (the loop bound)
    /// that shares storage with the iterator's *init* value must not be merged into the iterator
    /// when the iterator's whole HighVariable — which includes the loop-carried phi that is live
    /// across the compare — interferes with the bound, even though the bound and the init value
    /// alone never overlap. Same-storage interference must be tested over the full HighVariable.
    #[test]
    fn same_storage_merge_respects_full_highvariable_cover() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let uniq = spaces.by_name("unique").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let s = |u: u32| SeqNum { pc: Address::new(ram, u as u64), uniq: u };
        let param = f.new_input(8, Address::new(reg, 0x38));

        // block 0 (entry): vinit = param + 8  -> RAX(reg 0); then branch to the loop header.
        let c8 = f.new_const(8, 8);
        let o_init = f.new_op(OpCode::IntAdd, s(0), vec![param, c8]);
        let vinit = f.new_output(o_init, 8, Address::new(reg, 0));
        let br0 = f.new_op(OpCode::Branch, s(1), vec![]);

        // The loop-carried phi lives at a *stack-like* slot (distinct storage from RAX).
        let phi = f.new_op(OpCode::Multiequal, SeqNum { pc: Address::new(ram, 2), uniq: u32::MAX }, vec![vinit, vinit]);
        let vphi = f.new_output(phi, 8, Address::new(reg, 0x100));

        // block 1 (loop body): vinc = PTRADD(vphi, 1, 1) -> unique; back-edge to the header.
        let c1a = f.new_const(8, 1);
        let c1b = f.new_const(8, 1);
        let o_inc = f.new_op(OpCode::Ptradd, s(3), vec![vphi, c1a, c1b]);
        let vinc = f.new_output(o_inc, 8, Address::new(uniq, 0x500));
        f.op_set_input(phi, 1, vinc); // phi = MULTIEQUAL(vinit, vinc)

        // block 2 (header): vbound = param + 0x18 -> RAX(reg 0); cmp = vphi < vbound; cbranch.
        let c18 = f.new_const(8, 0x18);
        let o_bound = f.new_op(OpCode::IntAdd, s(4), vec![param, c18]);
        let vbound = f.new_output(o_bound, 8, Address::new(reg, 0));
        let cmp = f.new_op(OpCode::IntLess, s(5), vec![vphi, vbound]);
        let _b = f.new_output(cmp, 1, Address::new(reg, 0x200));
        let cbr = f.new_op(OpCode::Cbranch, s(6), vec![]);

        // block 3 (exit): return, carrying vbound (so it stays live past the compare).
        let ret = f.new_op(OpCode::Return, s(7), vec![vbound]);

        f.set_blocks(vec![
            BlockBasic { ops: vec![o_init, br0], in_edges: vec![], out_edges: vec![BlockId(2)] },
            BlockBasic { ops: vec![o_inc], in_edges: vec![BlockId(2)], out_edges: vec![BlockId(2)] },
            BlockBasic {
                ops: vec![phi, o_bound, cmp, cbr],
                in_edges: vec![BlockId(0), BlockId(1)],
                out_edges: vec![BlockId(1), BlockId(3)],
            },
            BlockBasic { ops: vec![ret], in_edges: vec![BlockId(2)], out_edges: vec![] },
        ]);

        let (mut h, _) = merge(&f);
        // the iterator's versions are one HighVariable (the phi merge)…
        assert!(h.same(vphi, vinit) && h.same(vphi, vinc));
        // …and the bound, though it reuses RAX like vinit, is a DISTINCT variable: vphi is live at
        // the compare where vbound is also live, so the whole HighVariables interfere.
        assert!(!h.same(vinit, vbound), "bound must not merge into the iterator (full-cover interference)");
        assert!(!h.same(vphi, vbound));
    }

    /// `merge_addrtied` is `mergeRangeMust` + `groupWith` (merge.cc:625/638): it unifies the
    /// address-tied versions of one exact `(address, size)` — so a 4-byte and an 8-byte write to the
    /// same global are DIFFERENT C variables — and links the overlapping ones into a VariableGroup
    /// whose extended Cover (`VariablePiece::updateCover`, variable.cc:160) is what carries the
    /// spanning liveness that the old size-blind union bought by fusing the two.
    ///
    /// This test used to assert the opposite (the size-blind approximation); it now asserts the
    /// faithful contract: separate identity, joint interference.
    #[test]
    fn merge_addrtied_separates_sizes_but_groups_them() {
        use crate::decompile::varnode::flags as vflags;
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let (c1, c2, c3) = (f.new_const(8, 1), f.new_const(4, 2), f.new_const(8, 3));
        let o1 = f.new_op(OpCode::Copy, seq, vec![c1]);
        let g8 = f.new_output(o1, 8, Address::new(ram, 0x1000));
        let o2 = f.new_op(OpCode::Copy, seq, vec![c2]);
        let g4 = f.new_output(o2, 4, Address::new(ram, 0x1000)); // same address, smaller size
        let o3 = f.new_op(OpCode::Copy, seq, vec![c3]);
        let other = f.new_output(o3, 8, Address::new(ram, 0x2000)); // different address
        for v in [g8, g4, other] {
            f.vn_mut(v).flags |= vflags::ADDRTIED | vflags::PERSIST;
        }
        // Give both overlapping versions a read, so each has a Cover to contribute (a Varnode with
        // no reader has an empty internal Cover and adds nothing to the extended one).
        let r8 = f.new_op(OpCode::Copy, seq, vec![g8]);
        let _ = f.new_output_unique(r8, 8);
        let r4 = f.new_op(OpCode::Copy, seq, vec![g4]);
        let _ = f.new_output_unique(r4, 4);
        f.set_blocks(vec![BlockBasic { ops: vec![o1, o2, o3, r8, r4], ..Default::default() }]);

        let mut h = HighVariables::new(f.num_varnodes());
        let pieces = merge_addrtied(&f, &mut h);
        // Identity: per (address, size).
        assert!(!h.same(g8, g4), "different sizes at one address are different variables");
        assert!(!h.same(g8, other), "a different address stays a distinct variable");
        // Grouping: the two overlapping subranges are pieces of one group, the 8-byte one spanning
        // it; the varnode at an unrelated address is in no group at all.
        assert!(pieces.same_group(g8, g4), "the overlapping versions form one VariableGroup");
        assert_eq!(pieces.at(g8).map(|(_, off, sz)| (off, sz)), Some((0, 8)));
        assert_eq!(pieces.at(g4).map(|(_, off, sz)| (off, sz)), Some((0, 4)));
        assert_eq!(pieces.group_size(g4), Some(8));
        assert!(pieces.spans_group(g8) && !pieces.spans_group(g4));
        assert_eq!(pieces.group_base(g4), Some(g8), "the spanning piece names the group");
        assert!(pieces.at(other).is_none(), "a lone (address, size) gets no piece");
        // Interference: the extended Cover of the narrow piece includes the whole's members, so a
        // merge test sees them as jointly live even though they are separate variables.
        let ext = pieces.extend_members(&mut h, &[g4]);
        assert!(ext.contains(&g8), "the extended Cover spans the byte-overlapping piece");
    }

    /// `merge_copy` (mergeOpcode COPY) merges a COPY's input and output when their Covers don't
    /// interfere, but LEAVES them distinct when they do — a snapshot read that stays live across a
    /// later write to the same variable must remain its own explicit temporary. All four values are
    /// multi-use (explicit): `mergeTestBasic`'s implied exclusion (an expression term never merges)
    /// is exercised separately below.
    #[test]
    fn merge_copy_merges_noninterfering_but_not_interfering() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let s = |u: u32| SeqNum { pc: Address::new(ram, u as u64), uniq: u };
        let c = f.new_const(8, 5);

        // Non-interfering chain: a = (c + c) + c; a2 = a + c; b = COPY(a); rb = b + c; rb2 = b + c.
        // `a` has three explicit terms (> max_term_duplication), so `ActionMarkExplicit`'s
        // `processMultiplier` keeps it explicit rather than an inlined term; it (2 uses, dead after
        // the COPY) and `b` (2 uses) are both explicit and don't overlap.
        let ot = f.new_op(OpCode::IntAdd, s(0), vec![c, c]);
        let t = f.new_output(ot, 8, Address::new(reg, 0x48));
        let o1 = f.new_op(OpCode::IntAdd, s(1), vec![t, c]);
        let a = f.new_output(o1, 8, Address::new(reg, 0));
        let o1b = f.new_op(OpCode::IntAdd, s(2), vec![a, c]);
        let _a2 = f.new_output(o1b, 8, Address::new(reg, 0x30));
        let o2 = f.new_op(OpCode::Copy, s(3), vec![a]);
        let b = f.new_output(o2, 8, Address::new(reg, 0x8));
        let o3 = f.new_op(OpCode::IntAdd, s(4), vec![b, c]);
        let _rb = f.new_output(o3, 8, Address::new(reg, 0x10));
        let o3b = f.new_op(OpCode::IntAdd, s(5), vec![b, c]);
        let _rb2 = f.new_output(o3b, 8, Address::new(reg, 0x38));

        // Interfering chain: e = (c + c) + c; d = COPY(e); rd = e + d; rd2 = d + c. `e` is read again
        // alongside `d`, so `e` and `d` are both live at `rd` and must NOT merge. `e` also has three
        // explicit terms so it stays explicit (a merge candidate at all).
        let ote = f.new_op(OpCode::IntAdd, s(6), vec![c, c]);
        let te = f.new_output(ote, 8, Address::new(reg, 0x50));
        let o4 = f.new_op(OpCode::IntAdd, s(7), vec![te, c]);
        let e = f.new_output(o4, 8, Address::new(reg, 0x18));
        let o5 = f.new_op(OpCode::Copy, s(8), vec![e]);
        let d = f.new_output(o5, 8, Address::new(reg, 0x20));
        let o6 = f.new_op(OpCode::IntAdd, s(9), vec![e, d]);
        let _rd = f.new_output(o6, 8, Address::new(reg, 0x28));
        let o7 = f.new_op(OpCode::IntAdd, s(10), vec![d, c]);
        let _rd2 = f.new_output(o7, 8, Address::new(reg, 0x40));
        f.set_blocks(vec![BlockBasic {
            ops: vec![ot, o1, o1b, o2, o3, o3b, ote, o4, o5, o6, o7],
            ..Default::default()
        }]);

        let (mut h, _) = merge(&f);
        assert!(h.same(a, b), "a non-interfering COPY merges its input and output");
        assert!(!h.same(e, d), "an interfering COPY (input still live) is left as a distinct variable");
    }

    /// `mergeTestBasic`'s implied exclusion (merge.cc:255, via the [`mark_explicit`] classification
    /// at the `ActionMarkImplied` slot): a single-use value feeding a COPY is an *expression term*
    /// — it must NOT be merged into the COPY's HighVariable, so the COPY stays cross-high and the
    /// term renders inline at the COPY's site. (This is what keeps a `mergeOp` blind-trim COPY
    /// printing `param_1 = param_1 + 2;` at the block stop instead of silently vanishing.)
    #[test]
    fn merge_copy_never_merges_an_implied_term() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let s = |u: u32| SeqNum { pc: Address::new(ram, u as u64), uniq: u };
        let c = f.new_const(8, 5);

        // a = c + c (single use: the COPY — implied); b = COPY(a); rb = b + c; rb2 = b + c.
        let o1 = f.new_op(OpCode::IntAdd, s(0), vec![c, c]);
        let a = f.new_output(o1, 8, Address::new(reg, 0));
        let o2 = f.new_op(OpCode::Copy, s(1), vec![a]);
        let b = f.new_output(o2, 8, Address::new(reg, 0x8));
        let o3 = f.new_op(OpCode::IntAdd, s(2), vec![b, c]);
        let _rb = f.new_output(o3, 8, Address::new(reg, 0x10));
        let o3b = f.new_op(OpCode::IntAdd, s(3), vec![b, c]);
        let _rb2 = f.new_output(o3b, 8, Address::new(reg, 0x18));
        f.set_blocks(vec![BlockBasic { ops: vec![o1, o2, o3, o3b], ..Default::default() }]);

        let (mut h, _) = merge(&f);
        assert!(!h.same(a, b), "an implied term must stay outside the COPY's HighVariable");
    }

    /// `merge_marker_trim` (`Merge::mergeMarker`→`mergeOp`→`trimOpInput`): a MULTIEQUAL input whose
    /// address-tied HighVariable Cover conflicts with the (register) phi output — which `merge_markers`
    /// would fuse (`merge_test_required` passes) — is trimmed: a COPY of the input is inserted at the
    /// predecessor block's end and the phi rewired to read it, so the phi output stays a distinct
    /// variable. This is floatcast's `fVar1 = fRam80;` init in miniature.
    #[test]
    fn marker_trim_snips_a_cover_conflicting_addrtied_phi_input() {
        use crate::decompile::varnode::flags as vflags;
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let s = |u: u32| SeqNum { pc: Address::new(ram, u as u64), uniq: u };

        // g0: the incoming global (ram:0x2000), an address-tied input.
        let g0 = f.new_input(8, Address::new(ram, 0x2000));
        f.vn_mut(g0).flags |= vflags::ADDRTIED | vflags::PERSIST;

        // block 0 (entry): conditional branch to the if-body (block 1) or straight to the join (block 2).
        let cbr = f.new_op(OpCode::Cbranch, s(0), vec![]);

        // block 1 (if-body): v1 = COPY(param) into a plain register (the written value flows through a
        // register, NOT address-tied — as in floatcast, where the phi's second input is a unique).
        let param = f.new_input(8, Address::new(reg, 0x38));
        let wr = f.new_op(OpCode::Copy, s(1), vec![param]);
        let v1 = f.new_output(wr, 8, Address::new(reg, 0x8));
        let br1 = f.new_op(OpCode::Branch, s(2), vec![]);

        // block 2 (join): phi = MULTIEQUAL(g0 from block 0, v1 from block 1) -> a register (NOT tied).
        let phi = f.new_op(OpCode::Multiequal, SeqNum { pc: Address::new(ram, 3), uniq: u32::MAX }, vec![g0, v1]);
        let phi_out = f.new_output(phi, 8, Address::new(reg, 0));
        // A use that reads BOTH the phi output and g0, keeping g0 live across the phi (the conflict).
        let add = f.new_op(OpCode::IntAdd, s(4), vec![phi_out, g0]);
        let _r = f.new_output(add, 8, Address::new(reg, 0x10));
        let ret = f.new_op(OpCode::Return, s(5), vec![]);

        let blocks = vec![
            BlockBasic { ops: vec![cbr], in_edges: vec![], out_edges: vec![BlockId(1), BlockId(2)] },
            BlockBasic { ops: vec![wr, br1], in_edges: vec![BlockId(0)], out_edges: vec![BlockId(2)] },
            BlockBasic {
                ops: vec![phi, add, ret],
                in_edges: vec![BlockId(0), BlockId(1)],
                out_edges: vec![],
            },
        ];
        // Assign each op its parent block, as `build_cfg` does before `set_blocks` (cfg.rs:292).
        for (bi, blk) in blocks.iter().enumerate() {
            for &opid in &blk.ops {
                f.op_mut(opid).parent = Some(BlockId(bi as u32));
            }
        }
        f.set_blocks(blocks);

        merge_marker_trim(&mut f);

        // The phi's slot-0 input is no longer g0 directly: it now reads a fresh unique COPY of g0…
        let new_in0 = f.op(phi).input(0).unwrap();
        assert_ne!(new_in0, g0, "the cover-conflicting addrtied input was not trimmed");
        let def = f.vn(new_in0).def.expect("trimmed input must be COPY-defined");
        assert_eq!(f.op(def).code(), OpCode::Copy);
        assert_eq!(f.op(def).input(0), Some(g0), "the COPY must snapshot g0");
        // …and that COPY sits at the end of the slot-0 predecessor (block 0), before its branch.
        assert_eq!(f.op(def).parent, Some(BlockId(0)));
        let blk0 = &f.block(BlockId(0)).ops;
        assert_eq!(blk0.last(), Some(&cbr), "COPY must be inserted before the terminating branch");
        assert!(blk0.contains(&def));

        // With the conflict severed, the read-only merge keeps the phi output its own HighVariable
        // (a distinct local) rather than fusing it into the global.
        let (mut h, _) = merge(&f);
        assert!(!h.same(phi_out, g0), "phi output must not be fused into the addrtied global");
        // The slot-1 (register) input has no cover conflict, so it is untouched.
        assert_eq!(f.op(phi).input(1), Some(v1), "the non-conflicting input is left in place");
    }

    /// `merge_op`'s phase-2 blind-sequential trim (merge.cc:748-758): when the conflicting input
    /// sits at a LATE slot, Ghidra still trims slots 0, 1, … in order until the whole set tests
    /// clean — every leading slot gets a block-stop COPY even though it never conflicted itself.
    /// (This is what produces the per-case `iVar3 = N; param_1 = …;` statement order on a switch
    /// header phi.)
    #[test]
    fn merge_op_blind_sequential_trim_trims_leading_slots() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let s = |u: u32| SeqNum { pc: Address::new(ram, u as u64), uniq: u };

        // block 0: three-way dispatch (BRANCHIND) to blocks 1/2/3.
        let bind = f.new_op(OpCode::Branchind, s(0), vec![]);
        // blocks 1..3: each writes its own version of reg:0 and branches to the join.
        let c = f.new_const(8, 7);
        let w1 = f.new_op(OpCode::IntAdd, s(1), vec![c, c]);
        let v1 = f.new_output(w1, 8, Address::new(reg, 0));
        let b1 = f.new_op(OpCode::Branch, s(2), vec![]);
        let w2 = f.new_op(OpCode::IntAdd, s(3), vec![c, c]);
        let v2 = f.new_output(w2, 8, Address::new(reg, 0));
        let b2 = f.new_op(OpCode::Branch, s(4), vec![]);
        let w3 = f.new_op(OpCode::IntAdd, s(5), vec![c, c]);
        let v3 = f.new_output(w3, 8, Address::new(reg, 0));
        let b3 = f.new_op(OpCode::Branch, s(6), vec![]);
        // block 4 (join): phi = MULTIEQUAL(v1, v2, v3); r = phi + v3 — the extra v3 read keeps v3
        // live across the join, conflicting with the phi output (slot-2 conflict only).
        let phi = f.new_op(OpCode::Multiequal, SeqNum { pc: Address::new(ram, 7), uniq: u32::MAX }, vec![v1, v2, v3]);
        let phi_out = f.new_output(phi, 8, Address::new(reg, 0));
        let add = f.new_op(OpCode::IntAdd, s(8), vec![phi_out, v3]);
        let _r = f.new_output(add, 8, Address::new(reg, 0x10));
        let ret = f.new_op(OpCode::Return, s(9), vec![]);

        let blocks = vec![
            BlockBasic { ops: vec![bind], in_edges: vec![], out_edges: vec![BlockId(1), BlockId(2), BlockId(3)] },
            BlockBasic { ops: vec![w1, b1], in_edges: vec![BlockId(0)], out_edges: vec![BlockId(4)] },
            BlockBasic { ops: vec![w2, b2], in_edges: vec![BlockId(0)], out_edges: vec![BlockId(4)] },
            BlockBasic { ops: vec![w3, b3], in_edges: vec![BlockId(0)], out_edges: vec![BlockId(4)] },
            BlockBasic {
                ops: vec![phi, add, ret],
                in_edges: vec![BlockId(1), BlockId(2), BlockId(3)],
                out_edges: vec![],
            },
        ];
        for (bi, blk) in blocks.iter().enumerate() {
            for &opid in &blk.ops {
                f.op_mut(opid).parent = Some(BlockId(bi as u32));
            }
        }
        f.set_blocks(blocks);

        merge_marker_trim(&mut f);

        // ALL three slots were trimmed (blind-sequential), not just the conflicting slot 2.
        for (slot, orig) in [(0, v1), (1, v2), (2, v3)] {
            let inv = f.op(phi).input(slot).unwrap();
            assert_ne!(inv, orig, "slot {slot} must read a trim COPY");
            let def = f.vn(inv).def.expect("trim output is written");
            assert_eq!(f.op(def).code(), OpCode::Copy);
            assert_eq!(f.op(def).input(0), Some(orig));
            assert_eq!(f.op(def).parent, Some(BlockId(slot as u32 + 1)), "COPY sits in the matching predecessor");
        }
        // The output was NOT trimmed: after the slot-2 trim the set tests clean.
        assert_eq!(f.op(phi).output, Some(phi_out));
        // The conflicting value stays a distinct variable from the phi's.
        let (mut h, _) = merge(&f);
        assert!(!h.same(phi_out, v3), "v3 keeps its own HighVariable");
    }

    /// `merge_op`'s phase-1 trim (merge.cc:731-741): an input whose HighVariable fails
    /// `mergeTestRequired` against the output (here a function input flowing into a persistent
    /// global phi) is trimmed even with no Cover conflict — where the read-only `merge_markers`
    /// would merely decline the union, the graph pass materializes the required merge through a COPY.
    #[test]
    fn merge_op_required_failure_trims_input() {
        use crate::decompile::varnode::flags as vflags;
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let s = |u: u32| SeqNum { pc: Address::new(ram, u as u64), uniq: u };

        let param = f.new_input(8, Address::new(reg, 0x38));
        // block 0: conditional branch to block 1 (write path) or block 2 (join).
        let cbr = f.new_op(OpCode::Cbranch, s(0), vec![]);
        // block 1: w = param + 1 into a register.
        let c1 = f.new_const(8, 1);
        let wr = f.new_op(OpCode::IntAdd, s(1), vec![param, c1]);
        let w = f.new_output(wr, 8, Address::new(reg, 0x8));
        let br = f.new_op(OpCode::Branch, s(2), vec![]);
        // block 2 (join): phi = MULTIEQUAL(param, w) -> a PERSISTENT global (ram), then return.
        let phi = f.new_op(OpCode::Multiequal, SeqNum { pc: Address::new(ram, 3), uniq: u32::MAX }, vec![param, w]);
        let phi_out = f.new_output(phi, 8, Address::new(ram, 0x2000));
        f.vn_mut(phi_out).flags |= vflags::ADDRTIED | vflags::PERSIST;
        let ret = f.new_op(OpCode::Return, s(4), vec![phi_out]);

        let blocks = vec![
            BlockBasic { ops: vec![cbr], in_edges: vec![], out_edges: vec![BlockId(1), BlockId(2)] },
            BlockBasic { ops: vec![wr, br], in_edges: vec![BlockId(0)], out_edges: vec![BlockId(2)] },
            BlockBasic { ops: vec![phi, ret], in_edges: vec![BlockId(0), BlockId(1)], out_edges: vec![] },
        ];
        for (bi, blk) in blocks.iter().enumerate() {
            for &opid in &blk.ops {
                f.op_mut(opid).parent = Some(BlockId(bi as u32));
            }
        }
        f.set_blocks(blocks);

        merge_marker_trim(&mut f);

        // Slot 0 (the function input) was trimmed by the required-merge failure…
        let in0 = f.op(phi).input(0).unwrap();
        assert_ne!(in0, param, "the input↛persist required failure must trim slot 0");
        let def = f.vn(in0).def.expect("trim output is written");
        assert_eq!(f.op(def).code(), OpCode::Copy);
        assert_eq!(f.op(def).input(0), Some(param));
        assert_eq!(f.op(def).parent, Some(BlockId(0)));
        // …and the read-only merge now unions the COPY into the phi while the input stays its own.
        let (mut h, _) = merge(&f);
        assert!(h.same(phi_out, in0), "the trim COPY joins the phi's HighVariable");
        assert!(!h.same(phi_out, param), "the function input stays distinct");
    }

    /// `merge_op`'s output trim (`trimOpOutput`, merge.cc:658): when every input trim still leaves
    /// the output class conflicting (an address-tied member of the output's own HighVariable is
    /// live across every predecessor stop), the phi's output is moved onto a COPY after the op and
    /// the op gets a stubby unique output.
    #[test]
    fn merge_op_exhausted_trims_trim_the_output() {
        use crate::decompile::varnode::flags as vflags;
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let s = |u: u32| SeqNum { pc: Address::new(ram, u as u64), uniq: u };

        // g: another version of the SAME global address as the phi output — merge_addrtied unions
        // them, and g's late read keeps the output class live across both predecessor stops.
        let cz = f.new_const(8, 0);
        let g_wr = f.new_op(OpCode::Copy, s(0), vec![cz]);
        let g = f.new_output(g_wr, 8, Address::new(ram, 0x3000));
        f.vn_mut(g).flags |= vflags::ADDRTIED;
        // block 0: g written, then a conditional branch to block 1 / block 2.
        let cbr = f.new_op(OpCode::Cbranch, s(1), vec![]);
        // blocks 1 and 2: each writes a register version feeding the phi.
        let c7 = f.new_const(8, 7);
        let w1 = f.new_op(OpCode::IntAdd, s(2), vec![c7, c7]);
        let v1 = f.new_output(w1, 8, Address::new(reg, 0));
        let b1 = f.new_op(OpCode::Branch, s(3), vec![]);
        let w2 = f.new_op(OpCode::IntAdd, s(4), vec![c7, c7]);
        let v2 = f.new_output(w2, 8, Address::new(reg, 0));
        let b2 = f.new_op(OpCode::Branch, s(5), vec![]);
        // block 3 (join): phi -> the SAME addrtied global address as g; then a read of g (keeping
        // the merged output class live everywhere) and of the phi result.
        let phi = f.new_op(OpCode::Multiequal, SeqNum { pc: Address::new(ram, 6), uniq: u32::MAX }, vec![v1, v2]);
        let phi_out = f.new_output(phi, 8, Address::new(ram, 0x3000));
        f.vn_mut(phi_out).flags |= vflags::ADDRTIED;
        let use1 = f.new_op(OpCode::IntAdd, s(7), vec![phi_out, g]);
        let _u = f.new_output(use1, 8, Address::new(reg, 0x10));
        let ret = f.new_op(OpCode::Return, s(8), vec![]);

        let blocks = vec![
            BlockBasic { ops: vec![g_wr, cbr], in_edges: vec![], out_edges: vec![BlockId(1), BlockId(2)] },
            BlockBasic { ops: vec![w1, b1], in_edges: vec![BlockId(0)], out_edges: vec![BlockId(3)] },
            BlockBasic { ops: vec![w2, b2], in_edges: vec![BlockId(0)], out_edges: vec![BlockId(3)] },
            BlockBasic {
                ops: vec![phi, use1, ret],
                in_edges: vec![BlockId(1), BlockId(2)],
                out_edges: vec![],
            },
        ];
        for (bi, blk) in blocks.iter().enumerate() {
            for &opid in &blk.ops {
                f.op_mut(opid).parent = Some(BlockId(bi as u32));
            }
        }
        f.set_blocks(blocks);

        merge_marker_trim(&mut f);

        // The phi's output is now a fresh unique, and the original global varnode is written by a
        // COPY of it placed right after the phi.
        let new_out = f.op(phi).output.unwrap();
        assert_ne!(new_out, phi_out, "the exhausted blind loop must trim the output");
        let def = f.vn(phi_out).def.expect("original output now COPY-written");
        assert_eq!(f.op(def).code(), OpCode::Copy);
        assert_eq!(f.op(def).input(0), Some(new_out));
        assert_eq!(f.op(def).parent, Some(BlockId(3)));
        let blk3 = &f.block(BlockId(3)).ops;
        assert_eq!(blk3.iter().position(|&o| o == def), Some(1), "COPY sits immediately after the phi");
        // Both inputs were blind-trimmed along the way.
        assert_ne!(f.op(phi).input(0), Some(v1));
        assert_ne!(f.op(phi).input(1), Some(v2));
    }

    /// `processCopyTrims`/`buildDominantCopy` (merge.cc:1415/1151): two trim COPYs of the same
    /// source at two predecessor stops collapse into ONE dominant COPY at their common dominator's
    /// stop, with the phi rewired to read it from both slots — the dedup of the per-predecessor
    /// `x = <same source>;` statements (switchloop case 4, loopcomment's repeated init sets).
    #[test]
    fn dominant_copy_collapses_same_source_trims() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let s_n = |u: u32| SeqNum { pc: Address::new(ram, u as u64), uniq: u };

        // block 0: s = c + c; cbranch -> blocks 1 / 2; both branch to the join (block 3).
        let c = f.new_const(8, 7);
        let sdef = f.new_op(OpCode::IntAdd, s_n(0), vec![c, c]);
        let s = f.new_output(sdef, 8, Address::new(reg, 0));
        let cbr = f.new_op(OpCode::Cbranch, s_n(1), vec![]);
        let b1 = f.new_op(OpCode::Branch, s_n(2), vec![]);
        let b2 = f.new_op(OpCode::Branch, s_n(3), vec![]);
        // block 3: phi = MULTIEQUAL(s, s); r = phi + s (keeps s live across the join, forcing the
        // blind loop to trim BOTH slots).
        let phi = f.new_op(OpCode::Multiequal, SeqNum { pc: Address::new(ram, 4), uniq: u32::MAX }, vec![s, s]);
        let phi_out = f.new_output(phi, 8, Address::new(reg, 0x8));
        let add = f.new_op(OpCode::IntAdd, s_n(5), vec![phi_out, s]);
        let _r = f.new_output(add, 8, Address::new(reg, 0x10));
        let ret = f.new_op(OpCode::Return, s_n(6), vec![]);

        let blocks = vec![
            BlockBasic { ops: vec![sdef, cbr], in_edges: vec![], out_edges: vec![BlockId(1), BlockId(2)] },
            BlockBasic { ops: vec![b1], in_edges: vec![BlockId(0)], out_edges: vec![BlockId(3)] },
            BlockBasic { ops: vec![b2], in_edges: vec![BlockId(0)], out_edges: vec![BlockId(3)] },
            BlockBasic {
                ops: vec![phi, add, ret],
                in_edges: vec![BlockId(1), BlockId(2)],
                out_edges: vec![],
            },
        ];
        for (bi, blk) in blocks.iter().enumerate() {
            for &opid in &blk.ops {
                f.op_mut(opid).parent = Some(BlockId(bi as u32));
            }
        }
        f.set_blocks(blocks);

        merge_marker_trim(&mut f);
        assert_eq!(f.copy_trims.len(), 2, "the blind loop trims both same-source slots");

        process_copy_trims(&mut f);

        // Both phi slots now read ONE dominant COPY of s, sitting at the common dominator's stop
        // (block 0, before its branch), and the per-predecessor trim COPYs are destroyed.
        let in0 = f.op(phi).input(0).unwrap();
        let in1 = f.op(phi).input(1).unwrap();
        assert_eq!(in0, in1, "both slots read the single dominant COPY");
        let dom_def = f.vn(in0).def.expect("dominant COPY output is written");
        assert_eq!(f.op(dom_def).code(), OpCode::Copy);
        assert_eq!(f.op(dom_def).input(0), Some(s));
        assert_eq!(f.op(dom_def).parent, Some(BlockId(0)), "COPY sits in the common dominator");
        let live_copies: Vec<_> = f
            .op_ids()
            .filter(|&op| !f.op(op).is_dead() && f.op(op).code() == OpCode::Copy)
            .collect();
        assert_eq!(live_copies, vec![dom_def], "the two trim COPYs are gone");
        assert!(f.copy_trims.is_empty(), "processCopyTrims drains the record");
    }

    /// `merge_test_required` (the modeled subset of `mergeTestRequired`): an address-tied output
    /// never swallows a differently-addressed address-tied input — including a `stack` local, which
    /// mosura does not flag `addrtied` but Ghidra maps — nor a function input into persistent
    /// storage; a plain register temporary CAN become a global's value.
    #[test]
    fn merge_test_required_guards() {
        use crate::decompile::varnode::flags as vflags;
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let stack = spaces.by_name("stack").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let glob = f.new_varnode(8, Address::new(ram, 0x1000));
        let glob2 = f.new_varnode(8, Address::new(ram, 0x2000));
        for v in [glob, glob2] {
            f.vn_mut(v).flags |= vflags::ADDRTIED | vflags::PERSIST | vflags::INSERT;
        }
        let slot = f.new_varnode(4, Address::new(stack, 0xffff_ffff_ffff_fff0));
        f.vn_mut(slot).flags |= vflags::INSERT; // stack local, NOT addrtied in mosura
        let inp = f.new_input(8, Address::new(reg, 0x38));
        let tmp = f.new_varnode(8, Address::new(reg, 0));
        f.vn_mut(tmp).flags |= vflags::INSERT;

        // No unions performed, so each Varnode is its own HighVariable (rep == id).
        let mut h = HighVariables::new(f.num_varnodes());
        let np = VariablePieces::empty(f.num_varnodes());
        assert!(!merge_test_required(&f, &mut h, &np, glob.0, glob2.0), "two globals at different addresses");
        assert!(!merge_test_required(&f, &mut h, &np, glob.0, slot.0), "a global and a stack local");
        assert!(!merge_test_required(&f, &mut h, &np, glob.0, inp.0), "a persistent global and a function input");
        assert!(merge_test_required(&f, &mut h, &np, glob.0, tmp.0), "a register temp CAN become the global's value");
    }
}
