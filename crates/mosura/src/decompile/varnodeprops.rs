//! Address-tied varnode property sync — a port of the `addrtied`/`addrforce` update half of
//! Ghidra's `Funcdata::syncVarnodesWithSymbols` (`funcdata_varnode.cc:939`, per-varnode update
//! `syncVarnodesWithSymbol`, `:1046`) together with the `nolocalalias` classification of
//! `ScopeLocal::restructureVarnode`/`markUnaliased` (`varmap.cc:1256`/`:1332`,
//! `isUnmappedUnaliased` `varmap.cc:494`), which `ActionRestructureVarnode`
//! (`coreaction.cc:2274`) drives every mainloop iteration.
//!
//! The *set* side lives at varnode CREATION (`Funcdata::alloc_varnode`; Ghidra `newVarnode`/
//! `newVarnodeOut`, `funcdata_varnode.cc:162`/`:115`, → `Scope::queryProperties`,
//! `database.cc:1263`): every stack/ram varnode is born `mapped | addrtied` (+ `persist` for a
//! ram global). This pass is the *reconcile* side: Ghidra "can CLEAR but not SET the addrtied
//! flag" here (`funcdata_varnode.cc:1057-1062` — and "if addrtied is cleared, so should
//! addrforce"), clearing it on the stack locals whose address never escapes (`nolocalalias`).
//! mosura has no populated `ScopeLocal` in the decompile corpus (the fixture `map addr` script is
//! skipped), so the classification is the alias analysis directly ([`super::alias`], the same
//! `AliasChecker` boundary heritage's `guard_calls` uses):
//!
//! * a *ram* (global) varnode ⇒ keep/set `mapped | addrtied | persist` (a global is never
//!   `nolocalalias`);
//! * a *stack* varnode ⇒ `mapped | addrtied` iff its slot is aliased; a non-aliased local (a
//!   spilled loop/temp variable) gets `addrtied`/`addrforce` CLEARED — the `nolocalalias` net
//!   effect. "Aliased" is Ghidra's `ScopeLocal::markUnaliased` walk (varmap.cc:1332), not a bare
//!   boundary compare: the scope's OWNERSHIP is `localrange ∪ paramrange`
//!   (`resetLocalWindow`, varmap.cc:441) MINUS every `markNotMapped` carve-out (varmap.cc:510 —
//!   mosura's `Funcdata::not_mapped`, fed by `ActionRestrictLocal`'s callee-save slots), and an
//!   alias does NOT propagate across an unowned hole ("Aliases shouldn't go thru unmapped
//!   regions of the local variables"): a symbol is aliased iff the LAST alias offset at/below its
//!   end lies in the SAME contiguous owned run (and within 0xffff bytes). This is what kills a
//!   Watcom callee-save area: `ActionRestrictLocal` carves the saved-EBP slot, the carve
//!   disconnects the save slots above it from every `&local` escape below, they classify
//!   `nolocalalias`, `RuleIndirectCollapse` folds their call INDIRECTs, and the dead saves —
//!   and the phantom register parameters read from them — vanish (WAR2 0x2a1b4: `maphdr_TYPE`
//!   is 1 parameter, not 2). A varnode in an unowned range is Ghidra's no-symbol/not-inScope
//!   branch (funcdata_varnode.cc:970): `isUnmappedUnaliased` (varmap.cc:494) — with no
//!   parameter-area carve tracked (`maxParamOffset < minParamOffset`) it is unaliased outright.
//!   A varnode in `paramrange` keeps `mapped | addrtied`: Ghidra's parameter symbols carry their
//!   symbol flags through the sync. Until the alias analysis has run at `aliasyes` strength
//!   (`Funcdata::alias_offsets` is `None`), the pre-existing boundary approximation
//!   (`offset >= alias_boundary`, Ghidra `AliasChecker::hasLocalAlias`, `varmap.cc:711`) stands;
//! * register/unique/constant ⇒ untouched (never scope-mapped);
//! * free varnodes ⇒ skipped (`syncVarnodesWithSymbol`: `if (vn->isFree()) continue`) — they
//!   keep their creation flags until heritage links them.

use super::funcdata::Funcdata;
use super::varnode::{flags, VarnodeId};

/// Reconcile `addrtied`/`addrforce`/`persist`/`mapped` on the memory varnodes with the current
/// alias classification (Ghidra `syncVarnodesWithSymbols` + `markUnaliased`). See the module docs.
/// `unmapped_alias_check` is Ghidra's `syncVarnodesWithSymbols(..., unmappedAliasCheck)` argument —
/// `aliasyes`, true only from the second `ActionRestructureVarnode` pass on (coreaction.cc:2279),
/// once the `AliasChecker` has actually run over the graph. Before that, Ghidra sets NO
/// `nolocalalias` (`fl = 0` for an unmapped varnode), so a call-guarded INDIRECT on a stack slot
/// survives into the pass where the alias analysis can see the slot's address escaping; marking
/// the flag unconditionally let `RuleIndirectCollapse` fold the guard in pass 0, before the
/// `MOV EAX,ESP`-to-call escape was ever examined (WAR2's FUN_00066da8 collapse).
pub fn mark_addrtied(f: &mut Funcdata, unmapped_alias_check: bool) {
    let ram = f.spaces.by_name("ram");
    let stack = f.spaces.by_name("stack");
    let boundary = f.alias_boundary;
    let ctx = match (&f.alias_offsets, stack) {
        (Some(alias), Some(stack)) => Some(StackAliasCtx::build(f, stack, alias.clone())),
        _ => None,
    };
    if std::env::var_os("MOSURA_ALIAS_DEBUG").is_some() {
        let nstack = (0..f.num_varnodes() as u32)
            .filter(|&i| Some(f.vn(VarnodeId(i)).loc.space) == stack && !f.vn(VarnodeId(i)).is_free())
            .count();
        eprintln!("[alias] boundary={boundary:?} stack_vns={nstack}");
    }
    for i in 0..f.num_varnodes() as u32 {
        let id = VarnodeId(i);
        let vn = f.vn(id);
        if vn.is_free() {
            continue; // syncVarnodesWithSymbol: free varnodes are not updated
        }
        let space = vn.loc.space;
        if Some(space) == ram {
            // Unmapped ram is a global: mapped|addrtied|persist (queryProperties, isGlobal branch).
            f.vn_mut(id).flags |= flags::MAPPED | flags::ADDRTIED | flags::PERSIST;
        } else if Some(space) == stack {
            let aliased = match &ctx {
                // The `markUnaliased` walk (see the module docs and [`classify_stack`]).
                Some(c) => classify_stack(c, vn.loc.offset, vn.size),
                // Boundary approximation until the alias analysis has run at `aliasyes` strength.
                None => {
                    if boundary.is_some_and(|b| (vn.loc.offset as i64) >= b) {
                        StackClass::Aliased
                    } else {
                        StackClass::Unaliased
                    }
                }
            };
            match aliased {
                StackClass::Aliased => {
                    // An aliased stack slot stays addrtied. Ghidra can set nolocalalias but never
                    // clears it (funcdata_varnode.cc:1063) — the boundary only ever moves down as
                    // escapes are discovered, so an aliased slot was never marked.
                    f.vn_mut(id).flags |= flags::MAPPED | flags::ADDRTIED;
                }
                StackClass::Unaliased if !unmapped_alias_check => {
                    // Pass 0: no alias analysis has run, so Ghidra's `fl = 0` — addrtied is cleared
                    // ("we can CLEAR but not SET"), but nolocalalias is NOT set.
                    f.vn_mut(id).flags &= !(flags::ADDRTIED | flags::ADDRFORCE);
                }
                StackClass::Unaliased => {
                    // A non-aliased local: nolocalalias ⇒ clear addrtied, and addrforce with it
                    // ("if addrtied is cleared, so should addrforce", funcdata_varnode.cc:1060-1062)
                    // — and STORE the attribute itself (Ghidra varmap.cc:1375
                    // `setAttribute(symbol, Varnode::nolocalalias)`, reaching varnodes via
                    // `syncVarnodesWithSymbols`). This is the producer `RuleIndirectCollapse`'s
                    // live-call arm was waiting for (rules.rs documented it INERT): a call-guarded
                    // INDIRECT on a local no pointer can reach collapses, exactly Ghidra's 24
                    // firings on the war2split fixture that mosura fired zero of.
                    f.vn_mut(id).flags &= !(flags::ADDRTIED | flags::ADDRFORCE);
                    f.vn_mut(id).flags |= flags::NOLOCALALIAS;
                }
            }
        }
    }
}

/// The stack classification a varnode nets out to under the `markUnaliased` walk.
#[derive(Clone, Copy, Debug, PartialEq)]
enum StackClass {
    /// Keep `mapped | addrtied` (aliased, or a parameter-area symbol).
    Aliased,
    /// Clear `addrtied`/`addrforce`; at an `aliasyes` pass also record `nolocalalias`.
    Unaliased,
}

/// The precomputed side of Ghidra `ScopeLocal::markUnaliased` (varmap.cc:1332): the scope's
/// ownership tree and the sorted alias-offset list. Built once per [`mark_addrtied`] call.
struct StackAliasCtx {
    /// `(localrange ∪ paramrange) − not_mapped` — `resetLocalWindow` (varmap.cc:441) minus every
    /// `markNotMapped` carve (varmap.cc:546 `removeRange`) — as disjoint inclusive intervals,
    /// ascending. The walk's `getRangeTree()`.
    owned: Vec<(u64, u64)>,
    /// The `paramrange` intervals: Ghidra's parameter symbols keep their symbol flags
    /// (`mapped | addrtied`) through `syncVarnodesWithSymbols`, so the walk never strips them.
    params: Vec<(u64, u64)>,
    /// `AliasChecker`'s escaped offsets, canonical and ascending (`sortAlias`).
    alias: Vec<u64>,
}

impl StackAliasCtx {
    fn build(f: &Funcdata, stack: super::space::SpaceId, alias: Vec<u64>) -> StackAliasCtx {
        let collect = |rl: &super::space::RangeList| -> Vec<(u64, u64)> {
            rl.iter().filter(|r| r.spc == stack).map(|r| (r.first, r.last)).collect()
        };
        let mut base = collect(&f.proto_model.localrange);
        base.extend(collect(&f.proto_model.paramrange));
        base.sort_unstable();
        // Merge overlapping/adjacent, exactly RangeList's disjoint-cover invariant.
        let mut merged: Vec<(u64, u64)> = Vec::new();
        for (first, last) in base {
            match merged.last_mut() {
                Some((_, plast)) if first <= plast.saturating_add(1) => *plast = (*plast).max(last),
                _ => merged.push((first, last)),
            }
        }
        // Subtract the carve-outs (`ScopeLocal::markNotMapped` → `removeRange`).
        let carves = collect(&f.not_mapped);
        let mut owned = merged;
        for (cfirst, clast) in carves {
            let mut next: Vec<(u64, u64)> = Vec::with_capacity(owned.len() + 1);
            for (first, last) in owned {
                if clast < first || last < cfirst {
                    next.push((first, last)); // disjoint
                    continue;
                }
                if first < cfirst {
                    next.push((first, cfirst - 1));
                }
                if clast < last {
                    next.push((clast + 1, last));
                }
            }
            owned = next;
        }
        let mut params = collect(&f.proto_model.paramrange);
        params.sort_unstable();
        StackAliasCtx { owned, params, alias }
    }
}

/// Pointwise Ghidra `ScopeLocal::markUnaliased` (varmap.cc:1332) + the no-symbol branches of
/// `Funcdata::syncVarnodesWithSymbols` (funcdata_varnode.cc:960-976), for the varnode occupying
/// `[off, off+size-1]` of the stack space:
///
/// * outside the ownership tree (a `markNotMapped` carve, or past the local/param windows) —
///   Ghidra's not-inScope branch → `isUnmappedUnaliased` (varmap.cc:494): with no
///   parameter-area carve tracked (`maxParamOffset < minParamOffset`) that is *unaliased*;
/// * inside `paramrange` — a parameter symbol; symbol flags (`mapped | addrtied`) survive the
///   sync, so *aliased* here (the walk may add `nolocalalias` to the symbol, but the flags a
///   varnode inherits keep `addrtied`, and mosura's net classification folds the two);
/// * otherwise the walk itself: aliased iff the last alias offset at/below the varnode's end
///   (`while (alias[i] <= curoff) curalias = alias[i++]`) lies in the SAME contiguous owned run
///   (`rng.getFirst() > curalias → aliason = false` — "Aliases shouldn't go thru unmapped
///   regions") and within `0xffff` bytes ("enough distance ... to warrant ignoring the alias").
fn classify_stack(ctx: &StackAliasCtx, off: u64, size: u32) -> StackClass {
    let end = off.wrapping_add(size.max(1) as u64 - 1);
    if end < off {
        return StackClass::Unaliased; // wraps the top of the space: never a mappable local
    }
    let Some(&(run_first, _)) = ctx.owned.iter().find(|&&(a, b)| a <= off && end <= b) else {
        return StackClass::Unaliased; // not inScope → isUnmappedUnaliased → no alias
    };
    if ctx.params.iter().any(|&(a, b)| a <= off && end <= b) {
        return StackClass::Aliased; // parameter symbols keep mapped|addrtied
    }
    let idx = ctx.alias.partition_point(|&a| a <= end);
    if idx > 0 {
        let curalias = ctx.alias[idx - 1];
        if run_first <= curalias && end - curalias <= 0xffff {
            return StackClass::Aliased;
        }
    }
    StackClass::Unaliased
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::space::{Address, SpaceManager};

    #[test]
    fn marks_by_space_and_alias() {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let stack = spaces.by_name("stack").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);

        // a global (ram), an aliased stack slot, a non-aliased stack slot, and a register
        let g = f.new_input(4, Address::new(ram, 0x100670));
        let stk_aliased = f.new_input(8, Address::new(stack, (-8i64) as u64));
        let stk_local = f.new_input(8, Address::new(stack, (-32i64) as u64));
        let rax = f.new_input(8, Address::new(reg, 0));

        // a pointer to offset -16 escaped, so everything at/above -16 is aliased
        f.alias_boundary = Some(-16);
        mark_addrtied(&mut f, true);

        // ram global: mapped | addrtied | persist
        assert!(f.vn(g).is_addrtied() && f.vn(g).is_persist());
        assert_ne!(f.vn(g).flags & flags::MAPPED, 0);
        // aliased stack slot: addrtied | mapped, but NOT persist (not global)
        assert!(f.vn(stk_aliased).is_addrtied() && !f.vn(stk_aliased).is_persist());
        // non-aliased local (offset -32 < boundary -16): never addrtied (nolocalalias clear)
        assert!(!f.vn(stk_local).is_addrtied());
        // register: untouched
        assert!(!f.vn(rax).is_addrtied() && !f.vn(rax).is_persist());
    }

    #[test]
    fn no_boundary_leaves_stack_untied() {
        // With no escaped pointer, no stack slot is aliased ⇒ none is addrtied.
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let stack = spaces.by_name("stack").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let stk = f.new_input(8, Address::new(stack, (-8i64) as u64));
        assert_eq!(f.alias_boundary, None);
        mark_addrtied(&mut f, true);
        assert!(!f.vn(stk).is_addrtied());
    }
}
