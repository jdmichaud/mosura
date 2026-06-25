//! Stack-aliasing analysis — a port of Ghidra's `AliasChecker` (`varmap.cc`).
//!
//! Decides which stack slots are *aliased* — a pointer to them escapes — so that heritage's
//! conservative call-guards ([`super::recover::recover_call_effects`]) are applied only to those.
//! A non-aliased local (a spilled loop variable touched only by direct constant-offset load/store)
//! is left untouched, so its loop SSA is undisturbed; an aliased local (one whose address is taken
//! and passed to a call, so the callee can modify it through the pointer) is guarded.
//!
//! `AliasChecker::gatherAdditiveBase` (varmap.cc:741): forward-walk the entry stack-pointer value
//! through *additive* ops only (`COPY`/`INT_ADD`/`INT_SUB`, the constant-offset address arithmetic);
//! an SP-derived value used by any *non-additive* op (a CALL argument, a STORE value, a compare, a
//! MULTIEQUAL, …) is a root, and its stack offset has escaped. Dead ops are skipped — Ghidra walks
//! the live graph. A slot reached only via direct constant-offset load/store never becomes a root
//! (those are already stack-space varnodes), so it is not aliased — the exact discriminator between
//! a spilled loop variable and a call-modified local, with no calling-convention register scan.

use std::collections::HashSet;

use super::funcdata::Funcdata;
use super::opcode::OpCode;
use super::varnode::VarnodeId;

const RSP: u64 = 0x20; // x86-64 register RSP, the entry stack pointer

/// Ghidra `AliasChecker::gatherAdditiveBase`/`gatherOffset`: the entry-stack-relative offsets whose
/// address escapes as a value (a pointer can reach them).
pub fn aliased_stack_offsets(f: &Funcdata) -> HashSet<i64> {
    let mut aliased = HashSet::new();
    let Some(reg) = f.spaces.by_name("register") else { return aliased };
    // The entry stack-pointer input varnode (Ghidra `findSpacebaseInput`).
    let Some(sp) = (0..f.num_varnodes() as u32).map(VarnodeId).find(|&v| {
        let vn = f.vn(v);
        vn.is_input() && vn.loc.space == reg && vn.loc.offset == RSP
    }) else {
        return aliased;
    };

    let mut seen: HashSet<VarnodeId> = HashSet::new();
    let mut queue = vec![(sp, 0i64)]; // (varnode holding entry_sp + off, off)
    while let Some((vn, off)) = queue.pop() {
        if !seen.insert(vn) {
            continue;
        }
        for op in f.vn(vn).descend.clone() {
            if f.op(op).is_dead() {
                continue; // a dead op is not a real use — walk the live graph
            }
            let o = f.op(op);
            match o.code() {
                // additive value movement — propagate the offset to the result
                OpCode::Copy => {
                    if let Some(out) = o.output {
                        queue.push((out, off));
                    }
                }
                OpCode::IntAdd => {
                    let other = if o.input(0) == Some(vn) { o.input(1) } else { o.input(0) };
                    match other.filter(|&x| f.vn(x).is_constant()) {
                        Some(c) => {
                            if let Some(out) = o.output {
                                queue.push((out, off + f.vn(c).loc.offset as i64));
                            }
                        }
                        None => {
                            aliased.insert(off); // a non-constant index ⇒ an indexed (aliased) access
                        }
                    }
                }
                OpCode::IntSub if o.input(0) == Some(vn) => match o.input(1).filter(|&x| f.vn(x).is_constant()) {
                    Some(c) => {
                        if let Some(out) = o.output {
                            queue.push((out, off - f.vn(c).loc.offset as i64));
                        }
                    }
                    None => {
                        aliased.insert(off);
                    }
                },
                // any other use ⇒ the SP-derived address escapes here, so the slot is aliased
                _ => {
                    aliased.insert(off);
                }
            }
        }
    }
    aliased
}

/// Ghidra `AliasChecker::aliasBoundary`/`hasLocalAlias`: once a pointer to some stack offset
/// escapes, the callee can reach every slot at or above it (a negative-growth frame), so the whole
/// region from the shallowest escaped offset upward is aliased. Returns that boundary, or `None`
/// when nothing escapes.
pub fn alias_boundary(f: &Funcdata) -> Option<i64> {
    aliased_stack_offsets(f).into_iter().min()
}
