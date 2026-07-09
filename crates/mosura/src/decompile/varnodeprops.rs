//! Address-tied varnode properties — a port of the `addrtied`/`persist` half of Ghidra's
//! `Funcdata::setVarnodeProperties` (`funcdata_varnode.cc:25`, via `Scope::queryProperties`,
//! `database.cc:1263`) together with the `nolocalalias` clear performed by
//! `ActionRestructureVarnode`/`Funcdata::syncVarnodesWithSymbols` (`funcdata_varnode.cc:938`,
//! `ScopeLocal::isUnmappedUnaliased`, `varmap.cc:494`).
//!
//! Ghidra sets these flags at varnode-creation time: `queryProperties` returns `mapped | addrtied`
//! for any *unmapped memory* location (`+persist` for a global), so every processor/spacebase
//! varnode is born address-tied. `ActionRestructureVarnode` then *clears* `addrtied` on the stack
//! locals whose address does not escape (the `nolocalalias` case). mosura has no populated
//! `ScopeLocal` in the decompile corpus (the fixture `map addr` script is skipped), so this pass
//! computes the *net* result directly by space, refined for the stack by the alias analysis
//! ([`super::alias`], the same `AliasChecker` boundary heritage's `guard_calls` uses):
//!
//! * a *ram* (global) varnode ⇒ `mapped | addrtied | persist` (unmapped ram is always addrtied);
//! * a *stack* varnode ⇒ `mapped | addrtied` iff its slot is aliased — its address escapes to a
//!   call (`offset >= alias_boundary`, Ghidra `AliasChecker::hasLocalAlias`); a non-aliased local
//!   (a spilled loop/temp variable) stays *not* addrtied, matching the `nolocalalias` clear;
//! * register/unique/constant ⇒ untouched (never addrtied).
//!
//! Ghidra applies `queryProperties` at creation, before its mainloop; mosura runs this once after
//! heritage/alias info is available and before the first simplification pool, so the downstream
//! rules that guard on `addrtied`/`persist` (RuleSubRight, ActionConditionalConst's phi guards,
//! SubVariableFlow) see the flag for the whole pool run — mirroring Ghidra's addrtied-before-mainloop.

use super::funcdata::Funcdata;
use super::varnode::{flags, VarnodeId};

/// Set `addrtied`/`persist`/`mapped` on the memory varnodes that Ghidra's `queryProperties`
/// (+ the `nolocalalias` clear) would leave address-tied. See the module docs.
pub fn mark_addrtied(f: &mut Funcdata) {
    let ram = f.spaces.by_name("ram");
    let stack = f.spaces.by_name("stack");
    let boundary = f.alias_boundary;
    for i in 0..f.num_varnodes() as u32 {
        let id = VarnodeId(i);
        let vn = f.vn(id);
        let space = vn.loc.space;
        let fl = if Some(space) == ram {
            // Unmapped ram is a global: mapped|addrtied|persist (queryProperties, isGlobal branch).
            flags::MAPPED | flags::ADDRTIED | flags::PERSIST
        } else if Some(space) == stack && boundary.is_some_and(|b| (vn.loc.offset as i64) >= b) {
            // An aliased stack slot stays addrtied; a non-aliased local is cleared (nolocalalias).
            flags::MAPPED | flags::ADDRTIED
        } else {
            continue;
        };
        f.vn_mut(id).flags |= fl;
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
