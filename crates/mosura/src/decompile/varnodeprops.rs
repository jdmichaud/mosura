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
//! * a *stack* varnode ⇒ `mapped | addrtied` iff its slot is aliased — its address escapes
//!   (`offset >= alias_boundary`, Ghidra `AliasChecker::hasLocalAlias`, `varmap.cc:711`); a
//!   non-aliased local (a spilled loop/temp variable) gets `addrtied`/`addrforce` CLEARED — the
//!   `nolocalalias` net effect;
//! * register/unique/constant ⇒ untouched (never scope-mapped);
//! * free varnodes ⇒ skipped (`syncVarnodesWithSymbol`: `if (vn->isFree()) continue`) — they
//!   keep their creation flags until heritage links them.

use super::funcdata::Funcdata;
use super::varnode::{flags, VarnodeId};

/// Reconcile `addrtied`/`addrforce`/`persist`/`mapped` on the memory varnodes with the current
/// alias classification (Ghidra `syncVarnodesWithSymbols` + `markUnaliased`). See the module docs.
pub fn mark_addrtied(f: &mut Funcdata) {
    let ram = f.spaces.by_name("ram");
    let stack = f.spaces.by_name("stack");
    let boundary = f.alias_boundary;
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
            if boundary.is_some_and(|b| (vn.loc.offset as i64) >= b) {
                // An aliased stack slot stays addrtied.
                f.vn_mut(id).flags |= flags::MAPPED | flags::ADDRTIED;
            } else {
                // A non-aliased local: nolocalalias ⇒ clear addrtied, and addrforce with it
                // ("if addrtied is cleared, so should addrforce", funcdata_varnode.cc:1060-1062).
                f.vn_mut(id).flags &= !(flags::ADDRTIED | flags::ADDRFORCE);
            }
        }
    }
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
        mark_addrtied(&mut f);

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
        mark_addrtied(&mut f);
        assert!(!f.vn(stk).is_addrtied());
    }
}
