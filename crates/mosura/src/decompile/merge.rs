//! Variable merging — Ghidra's `Merge`/`HighVariable` (`merge.cc`, `variable.cc`). Groups
//! the SSA Varnodes that represent one C variable into a [`HighVariable`], so the printer
//! emits one named variable instead of many SSA versions.
//!
//! P5 increment 1: the [`HighVariables`] union-find and the *required* marker merges
//! (`mergeMarker`) — a MULTIEQUAL/INDIRECT output is the same variable as its inputs, which
//! threads a value's SSA versions across control flow into one variable (loop counters,
//! merged conditionals). Cover-based merging of non-interfering same-storage varnodes, and
//! naming, are the next increments.

use std::collections::HashMap;

use super::block::BlockId;
use super::cover::{all_covers, Cover};
use super::funcdata::Funcdata;
use super::opcode::OpCode;
use super::space::{Address, SpaceId};
use super::varnode::VarnodeId;

/// Ghidra `max_implied_ref` (architecture.cc:1420) — the descendant-count ceiling above which
/// `ActionMarkExplicit::baseExplicit` (coreaction.cc:3078) forces a value explicit. A value with
/// `2..=max_implied_ref` descendants is a `multlist` member whose explicitness the term-duplication
/// machinery decides.
const MAX_IMPLIED_REF: usize = 2;
/// Ghidra `max_term_duplication` (architecture.cc:1421) — a multi-use value whose expression has at
/// most this many explicit terms stays *implied* and is duplicated at each use rather than named
/// (`ActionMarkExplicit::processMultiplier`, coreaction.cc:3166).
const MAX_TERM_DUPLICATION: i32 = 2;

/// A union-find over Varnodes: each class is one HighVariable (one C variable).
pub struct HighVariables {
    parent: Vec<u32>,
}

impl HighVariables {
    fn new(n: usize) -> HighVariables {
        HighVariables { parent: (0..n as u32).collect() }
    }

    /// Grow the union-find to cover `n` varnodes: each new varnode starts as its own
    /// HighVariable (Ghidra allocates a fresh HighVariable per new Varnode). Used by the
    /// graph-mutating marker merge, whose trims create new COPY outputs mid-pass.
    fn extend_to(&mut self, n: usize) {
        let old = self.parent.len() as u32;
        self.parent.extend(old..n as u32);
    }

    fn find(&mut self, mut x: u32) -> u32 {
        while self.parent[x as usize] != x {
            self.parent[x as usize] = self.parent[self.parent[x as usize] as usize]; // halving
            x = self.parent[x as usize];
        }
        x
    }

    fn union(&mut self, a: u32, b: u32) {
        let (ra, rb) = (self.find(a), self.find(b));
        if ra != rb {
            self.parent[ra as usize] = rb;
        }
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
pub fn merge(f: &Funcdata) -> HighVariables {
    let mut h = HighVariables::new(f.num_varnodes());
    let covers = all_covers(f);
    merge_addrtied(f, &mut h, &covers);
    merge_markers(f, &mut h);
    // The `ActionMarkExplicit` / `ActionMarkImplied` slot (coreaction.cc:5719-5720, "this must
    // come BEFORE general merging"): classify every varnode explicit-or-implied against the
    // required-merges-only state just built, so the COPY and speculative merges below can apply
    // `mergeTestBasic`'s implied exclusion (merge.cc:255). Without it a trim COPY's single-use
    // input would be fused back into the phi's HighVariable, the COPY would turn internal
    // (unprinted), and the input's def — implied at print time — would silently vanish.
    let explicit = mark_explicit(f, &mut h, &covers);
    merge_copy(f, &mut h, &covers, &explicit);
    merge_same_storage(f, &mut h, &covers, &explicit);
    h
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
    (0..f.num_varnodes() as u32)
        .map(VarnodeId)
        .map(|v| {
            explicit_leading(f, v)
                .unwrap_or_else(|| explicit_trailing(f, &of, &of, &members, covers, v))
        })
        .collect()
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
        // baseExplicit's addrtied SUBPIECE-of-addrtied sub-case: a narrow addrtied piece read from
        // the SAME addrtied whole at the matching overlap is an internal copymarker, NOT a store —
        // printed inline as a piece read (`(int2)glob`), not a spurious `glob = (int2)glob;`.
        if let Some(def) = vn.def {
            if f.op(def).code() == OpCode::Subpiece {
                if let (Some(inv), Some(cst)) = (f.op(def).input(0), f.op(def).input(1)) {
                    let ivn = f.vn(inv);
                    let coff = f.vn(cst);
                    if coff.is_constant()
                        && ivn.is_addrtied()
                        && ivn.loc.space == vn.loc.space
                        && vn.loc.offset == ivn.loc.offset + coff.loc.offset
                        && vn.loc.offset + vn.size as u64 <= ivn.loc.offset + ivn.size as u64
                    {
                        return Some(false);
                    }
                }
            }
        }
        return Some(true);
    }
    None
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
    v: VarnodeId,
) -> bool {
    let vn = f.vn(v);
    if !vn.is_written() {
        return true;
    }
    if let Some(def) = vn.def {
        // a phi is a merged variable, an INDIRECT is an opaque `extraout_*`, and a CALL's return
        // value is always named (`baseExplicit`, coreaction.cc:3015 `def->isCall()`).
        if matches!(
            f.op(def).code(),
            OpCode::Multiequal | OpCode::Indirect | OpCode::Call | OpCode::Callind
        ) {
            return true;
        }
        // PTRADD/PTRSUB are address sub-expressions recomputed inline at every use — implied even
        // with multiple uses, unless one of those uses is a phi.
        if matches!(f.op(def).code(), OpCode::Ptradd | OpCode::Ptrsub) {
            return vn.descend.iter().any(|&u| f.op(u).code() == OpCode::Multiequal);
        }
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
    if dn == 0 || dn > MAX_IMPLIED_REF {
        return true;
    }
    if dn > 1 {
        // A `multlist` member (`ActionMarkExplicit`, coreaction.cc:3256): `2..=max_implied_ref`
        // descendants. A value feeding a MULTIEQUAL/INDIRECT is the merged variable itself
        // (baseExplicit's marker-descendant bail, :3076). A multi-use LOAD stays named — its
        // implied-cover analysis (checkImpliedCover's LOAD-vs-STORE/CALL arms, :3384-3406) is not
        // ported, so we conservatively never inline it (an under-approximation of Ghidra that can
        // only leave it explicit, never emit wrong code). Otherwise the `multipleInteraction`
        // flow-into rule (:3091) and the `processMultiplier` term count (:3166) decide, falling
        // through to the same implied-cover test as the single-use case.
        if vn.descend.iter().any(|&u| f.op(u).is_marker()) {
            return true;
        }
        if vn.def.is_some_and(|d| f.op(d).code() == OpCode::Load) {
            return true;
        }
        if is_purged_top(f, persist_of, v) {
            return true;
        }
        if process_multiplier(f, persist_of, v, MAX_TERM_DUPLICATION) {
            return true;
        }
        return !implied_cover_ok(f, ih_of, ih_members, covers, v);
    }
    // Single use (`dn == 1`): inline unless the implied-cover test fails, or it feeds a marker
    // standing for the same variable, in which case it materializes as an assignment.
    if !implied_cover_ok(f, ih_of, ih_members, covers, v) {
        return true;
    }
    let user = vn.descend[0];
    match f.op(user).code() {
        OpCode::Multiequal => true,
        OpCode::Indirect => f
            .op(user)
            .output
            .is_some_and(|uout| f.vn(uout).loc == vn.loc && f.vn(uout).size == vn.size),
        _ => false,
    }
}

/// `ActionMarkImplied::checkImpliedCover` (coreaction.cc:3376) input-cover arm, via `Merge::
/// inflateTest`: a value can stay implied only if no def-op input's HighVariable has ANOTHER live
/// instance whose range intersects the value's own cover — otherwise the inlined expression would
/// read a value REDEFINED between its def and its use. Copy shadows / partial-piece copy shadows of
/// the input are exempt. Returns `true` when the value can be implied (no cover violation).
///
/// The LOAD-vs-STORE and load/call-crossing arms (:3384-3406) are not ported: multi-use LOADs are
/// kept explicit by the caller, and single-use LOADs matched Ghidra without them.
fn implied_cover_ok(
    f: &Funcdata,
    ih_of: &[u32],
    ih_members: &HashMap<u32, Vec<VarnodeId>>,
    covers: &HashMap<VarnodeId, Cover>,
    v: VarnodeId,
) -> bool {
    let vn = f.vn(v);
    if let (Some(def), Some(vcov)) = (vn.def, covers.get(&v)) {
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
/// `2..=max_implied_ref` descendants. (mosura folds Ghidra's spacebase-PTRSUB-always-implied special
/// case, :3066-3072, into the pointer arm, so PTRADD/PTRSUB are never members here.)
fn is_mark_candidate(f: &Funcdata, persist_of: &[u32], v: VarnodeId) -> bool {
    if explicit_leading(f, v).is_some() {
        return false;
    }
    let vn = f.vn(v);
    let Some(def) = vn.def.filter(|_| vn.is_written()) else { return false };
    match f.op(def).code() {
        OpCode::Multiequal | OpCode::Indirect | OpCode::Call | OpCode::Callind => return false,
        OpCode::Ptradd | OpCode::Ptrsub => return false,
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
    dn > 1 && dn <= MAX_IMPLIED_REF
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
        OpCode::Multiequal | OpCode::Indirect | OpCode::Call | OpCode::Callind => return true,
        OpCode::Ptradd | OpCode::Ptrsub => {
            return vn.descend.iter().any(|&u| f.op(u).code() == OpCode::Multiequal)
        }
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
    if dn == 0 || dn > MAX_IMPLIED_REF {
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
    let covers = all_covers(f);
    merge_addrtied(f, &mut h, &covers);
    merge_markers(f, &mut h);
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
fn merge_markers(f: &Funcdata, h: &mut HighVariables) {
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
                    if merge_test_required(f, h, rep_out, rep_in) {
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

/// The speculative same-storage merges (Ghidra `Merge::mergeByDatatype` / `ActionMergeType`):
/// greedily merge HighVariables that share storage and never live simultaneously, so reused
/// registers/slots become one variable. Candidates are gated by `mergeTestBasic` (merge.cc:341):
/// an *implied* varnode (an expression term, per [`mark_explicit`]) is never a merge seed.
fn merge_same_storage(
    f: &Funcdata,
    h: &mut HighVariables,
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
    let mut full = full_members_by_rep(f, h, covers);
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
            let empty: Vec<VarnodeId> = Vec::new();
            let mut merged = false;
            'pair: for i in 0..class_list.len() {
                for j in (i + 1)..class_list.len() {
                    let rep_i = h.high(class_list[i][0]);
                    let rep_j = h.high(class_list[j][0]);
                    let fi = full.get(&rep_i).unwrap_or(&empty);
                    let fj = full.get(&rep_j).unwrap_or(&empty);
                    if !classes_interfere(fi, fj, covers) {
                        h.union(class_list[i][0].0, class_list[j][0].0);
                        let mut m = full.remove(&rep_i).unwrap_or_default();
                        m.extend(full.remove(&rep_j).unwrap_or_default());
                        full.insert(h.high(class_list[i][0]), m);
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

/// Map each current HighVariable representative to *all* its member Varnodes that have a cover —
/// the membership over which interference is tested (Ghidra's `HighVariable::inst`).
fn full_members_by_rep(
    f: &Funcdata,
    h: &mut HighVariables,
    covers: &HashMap<VarnodeId, Cover>,
) -> HashMap<u32, Vec<VarnodeId>> {
    let mut full: HashMap<u32, Vec<VarnodeId>> = HashMap::new();
    for i in 0..f.num_varnodes() as u32 {
        let v = VarnodeId(i);
        if covers.contains_key(&v) {
            let rep = h.high(v);
            full.entry(rep).or_default().push(v);
        }
    }
    full
}

/// All cover-bearing Varnodes currently merged into the HighVariable `rep` — the membership over
/// which Cover interference is tested (Ghidra's `HighVariable::inst`).
fn members_of(
    f: &Funcdata,
    h: &mut HighVariables,
    covers: &HashMap<VarnodeId, Cover>,
    rep: u32,
) -> Vec<VarnodeId> {
    (0..f.num_varnodes() as u32)
        .map(VarnodeId)
        .filter(|&v| covers.contains_key(&v) && h.high(v) == rep)
        .collect()
}

/// `Merge::mergeAddrTied` (merge.cc:609) — force-merge address-tied Varnodes sharing a storage
/// address into one HighVariable. Ghidra force-merges the same-size versions (`mergeRangeMust`,
/// the [`super::mergesnip`] snip having already resolved any Cover intersection) and links
/// different-size versions into a VariableGroup (`groupWith`/VariablePiece). mosura has no
/// VariablePiece (the P4/P8 debt), so it approximates the group by unioning *every* address-tied
/// cover-bearing version at an address, any size — giving the storage one HighVariable whose Cover
/// spans all its versions. That spanning Cover is what lets [`merge_copy`] tell a pre-store
/// snapshot (which stays live across the overwriting store) apart from the stored value.
fn merge_addrtied(f: &Funcdata, h: &mut HighVariables, _covers: &HashMap<VarnodeId, Cover>) {
    let mut by_addr: HashMap<(SpaceId, u64), Vec<VarnodeId>> = HashMap::new();
    for i in 0..f.num_varnodes() as u32 {
        let v = VarnodeId(i);
        let vn = f.vn(v);
        // Ghidra `unifyAddress` gates on `!isFree` (heritaged), NOT on having a Cover: an
        // address-forced write held to the end of the function has no explicit reader (so mosura's
        // Cover is empty) but is still an instance of the storage's variable and must be unified,
        // else the `guardReturns` terminal COPY stays cross-high and prints a spurious `g = g`.
        if vn.is_free() || !vn.is_addrtied() {
            continue;
        }
        by_addr.entry((vn.loc.space, vn.loc.offset)).or_default().push(v);
    }
    // Deterministic order (the union representative is the lowest-index member of each group).
    let mut groups: Vec<Vec<VarnodeId>> = by_addr.into_values().filter(|g| g.len() >= 2).collect();
    groups.sort_by_key(|g| g[0]);
    for g in groups {
        for &w in &g[1..] {
            h.union(g[0].0, w.0);
        }
    }
}

/// `Merge::mergeOpcode(CPUI_COPY)` (merge.cc:326) — in linear block order, try to merge each
/// COPY's input HighVariable with its output HighVariable. The merge is skipped if `mergeTestBasic`
/// or `mergeTestRequired` forbids it, or if it would introduce a Cover intersection (Ghidra ignores
/// `merge()`'s return, merge.cc:346). This collapses redundant register/return COPYs into one
/// variable and — crucially — LEAVES a COPY whose input and output Covers interfere (a snapshot of
/// an address-tied value taken before that address is overwritten) as two distinct HighVariables,
/// so the printer renders it as an explicit `iVar = <snapshot>` assignment (see printc's
/// cross-high COPY arm, Ghidra `Merge::markInternalCopies`).
fn merge_copy(
    f: &Funcdata,
    h: &mut HighVariables,
    covers: &HashMap<VarnodeId, Cover>,
    explicit: &[bool],
) {
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
                if !merge_test_required(f, h, rep_out, rep_in) {
                    continue;
                }
                let mo = members_of(f, h, covers, rep_out);
                let mi = members_of(f, h, covers, rep_in);
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

/// The aggregate `(address-tied storage address, is-input, is-persist)` over every Varnode merged
/// into HighVariable `rep` — Ghidra's HighVariable flag aggregation across its instances. A `stack`
/// member counts as tied-to-its-address even without the `addrtied` flag: Ghidra maps every stack
/// local (so it is addrtied), while mosura marks only *escaped* slots ([`super::varnodeprops`]), so
/// the merge guard would otherwise let a stack local merge with a differently-addressed global.
fn high_props(f: &Funcdata, h: &mut HighVariables, rep: u32) -> (Option<Address>, bool, bool) {
    let stack = f.spaces.by_name("stack");
    let mut tied: Option<Address> = None;
    let (mut input, mut persist) = (false, false);
    for i in 0..f.num_varnodes() as u32 {
        let v = VarnodeId(i);
        if h.high(v) != rep {
            continue;
        }
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
/// from swallowing an address-tied input of a *different* address, and keep function inputs
/// distinct from persistent / address-tied storage (an input must not be dragged into the internal
/// parts of a stack structure). The typelock / extraout / protopartial / VariablePiece / symbol
/// guards are not modeled — mosura has no type-locks, VariablePieces or symbol tables at merge time.
fn merge_test_required(f: &Funcdata, h: &mut HighVariables, rep_out: u32, rep_in: u32) -> bool {
    if rep_out == rep_in {
        return true; // already merged
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
    merge_addrtied(f, &mut h, &covers);
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
            merge_indirect(f, &mut h, &mut covers, op);
        } else {
            merge_op(f, &mut h, &mut covers, op);
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
    covers: &mut HashMap<VarnodeId, Cover>,
    indop: super::op::OpId,
) {
    let outvn = f.op(indop).output.expect("INDIRECT has an output");
    if !f.vn(outvn).is_addr_force() {
        merge_op(f, h, covers, indop);
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
        if !merge_test_required(f, h, rep_out, rep_in) {
            return false;
        }
        // Merge::merge fails only on a Cover intersection.
        let members = full_members_by_rep(f, h, covers);
        let empty: Vec<VarnodeId> = Vec::new();
        let mo = members.get(&rep_out).unwrap_or(&empty);
        let mi = members.get(&rep_in).unwrap_or(&empty);
        if class_intersect(f, mo, mi, covers) {
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
    if snip_output_interference(f, h, indop) {
        h.extend_to(f.num_varnodes());
        *covers = all_covers(f);
        if try_merge(f, h, covers) {
            return;
        }
    }
    // Snip the INDIRECT itself: a COPY of the input placed just before it (allocateCopyTrim).
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
    *covers = all_covers(f);
    // Try the merge again; where Ghidra would throw ("Unable to merge address forced indirect"),
    // a residual conflict is left un-unioned.
    try_merge(f, h, covers);
}

/// `Merge::snipOutputInterference` (merge.cc:815) + `collectInputs` (merge.cc:780): collect reads,
/// by the op causing the given INDIRECT (and the INDIRECTs stacked directly above it), of Varnodes
/// belonging to the INDIRECT output's HighVariable; snip them by COPYing to a temporary just before
/// the affected op — one COPY per distinct read Varnode HighVariable — and repoint the reads.
/// Returns `true` if anything was snipped.
fn snip_output_interference(f: &mut Funcdata, h: &mut HighVariables, indop: super::op::OpId) -> bool {
    let Some(affect) = f.op(indop).guarded_op() else { return false };
    let out = f.op(indop).output.expect("INDIRECT has an output");
    let rep = h.high(out);
    // collectInputs: the affected op, plus any INDIRECT immediately preceding it in its block.
    let mut oplist: Vec<(super::op::OpId, usize)> = Vec::new();
    let parent = match f.op(affect).parent {
        Some(p) => p,
        None => return false,
    };
    let ops = f.block(parent).ops.clone();
    let Some(mut idx) = ops.iter().position(|&o| o == affect) else { return false };
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
        return false;
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
    true
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
        if !merge_test_required(f, h, rep_out, rep_in) {
            trim_slot(f, h, covers, op, i);
            continue;
        }
        for j in 0..i {
            let Some(invj) = f.op(op).input(j) else { continue };
            let (rep_j, rep_in) = (h.high(invj), h.high(inv));
            if !merge_test_required(f, h, rep_j, rep_in) {
                trim_slot(f, h, covers, op, i);
                break;
            }
        }
    }
    // Phase 2: cover restrictions — blind-sequential trims until the whole set tests clean.
    if !merge_test_all(f, h, covers, op) {
        let mut nexttrim = 0;
        while nexttrim < max {
            trim_slot(f, h, covers, op, nexttrim); // trim one of the branches
            if merge_test_all(f, h, covers, op) {
                break; // we successfully test merged everything
            }
            nexttrim += 1;
        }
        if nexttrim == max {
            // One last trim we can try.
            trim_op_output(f, op);
            h.extend_to(f.num_varnodes());
            *covers = all_covers(f);
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
    covers: &HashMap<VarnodeId, Cover>,
    op: super::op::OpId,
) -> bool {
    let members = full_members_by_rep(f, h, covers);
    let mut testlist: Vec<u32> = Vec::new();
    let out = f.op(op).output.expect("marker op has an output");
    let rep_out = h.high(out);
    merge_test_class(f, covers, &members, out, rep_out, &mut testlist);
    for i in 0..f.op(op).num_inputs() {
        let Some(inv) = f.op(op).input(i) else { continue };
        let rep_in = h.high(inv);
        if !merge_test_class(f, covers, &members, inv, rep_in, &mut testlist) {
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
    covers: &HashMap<VarnodeId, Cover>,
    members: &HashMap<u32, Vec<VarnodeId>>,
    v: VarnodeId,
    rep: u32,
    testlist: &mut Vec<u32>,
) -> bool {
    let vn = f.vn(v);
    if !mergeable(f, v) || vn.is_free() {
        return false; // no cover: constant / annotation / never-heritaged
    }
    let empty: Vec<VarnodeId> = Vec::new();
    let mine = members.get(&rep).unwrap_or(&empty);
    for &other in testlist.iter() {
        if other == rep {
            continue; // same HighVariable (Ghidra intersection(a,a) == false)
        }
        let theirs = members.get(&other).unwrap_or(&empty);
        if class_intersect(f, mine, theirs, covers) {
            return false;
        }
    }
    testlist.push(rep);
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
        let Some(cx) = covers.get(&x) else { continue };
        for &y in b {
            let Some(cy) = covers.get(&y) else { continue };
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
    trim_op_input(f, op, slot);
    h.extend_to(f.num_varnodes());
    *covers = all_covers(f);
}

/// `Merge::trimOpInput` (merge.cc:692) — snip phi input `slot` into a fresh `unique` via a COPY placed
/// at the predecessor block's end (`opInsertEnd`, at the block's stop address), then rewire the phi to
/// read the COPY. The COPY's cover is tiny (just the block-end read), so it no longer conflicts.
fn trim_op_input(f: &mut Funcdata, op: super::op::OpId, slot: usize) {
    // MULTIEQUAL input `slot` corresponds to `in_edges[slot]` (heritage wires `op_set_input(phi, j,
    // ...)` with `j = in_edges.position(pred)`).
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
    let tiny = f.new_output_unique(op, size); // output of op is now the stubby uniq…
    let copyop = f.new_op(OpCode::Copy, super::op::SeqNum { pc, uniq }, vec![tiny]);
    f.op_set_output(copyop, vn); // …and the original output is bumped forward slightly
    f.op_insert_after(copyop, op);
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
        merge_addrtied(f, &mut h, &covers);
        merge_markers(f, &mut h);
        let explicit = mark_explicit(f, &mut h, &covers);
        merge_copy(f, &mut h, &covers, &explicit);
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
    for i in 0..f.num_varnodes() as u32 {
        let v = VarnodeId(i);
        if h.high(v) != rep {
            continue;
        }
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
/// (coreaction.cc:5729) reduced to its non-printing marks that printc does not already model: the
/// *shadow assignment* skip (a never-read COPY output whose HighVariable has another instance live
/// at the same point carries no new value, merge.cc:1470-1474) and the *redundant copy* marking
/// (`processHighRedundantCopy`/`markRedundantCopies`/`checkCopyPair`, merge.cc:1345/1252/1112 —
/// a COPY dominated by an earlier COPY from the same source with no intervening write to the
/// HighVariable is not printed). The same-HighVariable internal-copy arm (merge.cc:1461) is
/// printc's existing `hidden` test; the PIECE/SUBPIECE arms need VariablePiece (the P4/P8 debt).
///
/// `of` is the frozen full-merge representative per varnode and `members` its class lists —
/// Ghidra's state at ActionCopyMarker (after all merging). Returns the set of non-printing ops.
pub(crate) fn copy_marker_nonprinting(
    f: &Funcdata,
    of: &[u32],
    members: &HashMap<u32, Vec<VarnodeId>>,
    covers: &HashMap<VarnodeId, Cover>,
) -> std::collections::HashSet<super::op::OpId> {
    let mut nonprint: std::collections::HashSet<super::op::OpId> = std::collections::HashSet::new();
    if f.num_blocks() == 0 {
        return nonprint;
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
    nonprint
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
    pos: &HashMap<super::op::OpId, (usize, usize)>,
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
    pos: &HashMap<super::op::OpId, (usize, usize)>,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::space::{Address, SpaceManager};
    use crate::decompile::{BlockBasic, BlockId, Funcdata, OpCode, SeqNum};

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

        let mut h = merge(&f);
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

        let mut h = merge(&f);
        // the iterator's versions are one HighVariable (the phi merge)…
        assert!(h.same(vphi, vinit) && h.same(vphi, vinc));
        // …and the bound, though it reuses RAX like vinit, is a DISTINCT variable: vphi is live at
        // the compare where vbound is also live, so the whole HighVariables interfere.
        assert!(!h.same(vinit, vbound), "bound must not merge into the iterator (full-cover interference)");
        assert!(!h.same(vphi, vbound));
    }

    /// `merge_addrtied` unifies every address-tied version at one storage address, ANY size (the
    /// VariablePiece approximation) — a 4-byte and an 8-byte write to the same global become one
    /// HighVariable, while a write to a different address stays distinct.
    #[test]
    fn merge_addrtied_unifies_all_sizes_at_one_address() {
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
        f.set_blocks(vec![BlockBasic { ops: vec![o1, o2, o3], ..Default::default() }]);

        let covers = all_covers(&f);
        let mut h = HighVariables::new(f.num_varnodes());
        merge_addrtied(&f, &mut h, &covers);
        assert!(h.same(g8, g4), "same-address addrtied versions unify regardless of size");
        assert!(!h.same(g8, other), "a different address stays a distinct variable");
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

        let mut h = merge(&f);
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

        let mut h = merge(&f);
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
        let mut h = merge(&f);
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
        let mut h = merge(&f);
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
        let mut h = merge(&f);
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
        assert!(!merge_test_required(&f, &mut h, glob.0, glob2.0), "two globals at different addresses");
        assert!(!merge_test_required(&f, &mut h, glob.0, slot.0), "a global and a stack local");
        assert!(!merge_test_required(&f, &mut h, glob.0, inp.0), "a persistent global and a function input");
        assert!(merge_test_required(&f, &mut h, glob.0, tmp.0), "a register temp CAN become the global's value");
    }
}
