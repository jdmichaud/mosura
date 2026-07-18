//! `directwrite` propagation — a faithful port of Ghidra's `ActionDirectWrite`
//! (`coreaction.cc:1350`, header doc `coreaction.hh:234`).
//!
//! A varnode is a *direct write* if its value could be directly affected by a legitimate function
//! input (a parameter register/stack slot, a spacebase, a persistent global, or a real constant),
//! propagated forward through the assignment ops. The attribute is *initially* set on those roots
//! and then tainted downstream.
//!
//! The single consumer in mosura is [`super::deadcode`]: `ActionDeadCode` (`coreaction.cc:3944`)
//! clears `addrforce` on any varnode that is *not* a direct write, so a value forced into its
//! storage only stays exempt from dead-code removal if a real input feeds it. This is exactly what
//! removes a callee-saved-register save slot: `s-0x8 = COPY RBP(input)` where `RBP` is *not* a
//! parameter (not `possibleInputParam`), not persist, not spacebase — so the COPY, the loop-header
//! MULTIEQUAL, and the call INDIRECTs that carry it are never direct writes, `guardCalls`' addrforce
//! is stripped, and the write-only chain dies in the following deadcode (noforloop_alias's spurious
//! `xStack_8 = xVar1`). An aliased *parameter* spill survives instead: its param-register input is a
//! direct write that taints the COPY into the slot.
//!
//! Ghidra runs two instances back-to-back before each deadcode — `protorecovery_a`
//! (`propagateIndirect = true`) then `protorecovery_b` (`propagateIndirect = false`); the second
//! re-clears and recomputes, so the state the deadcode sees is the `propagateIndirect = false` one
//! (directwrite does *not* flow through a call INDIRECT). Both are ported for faithfulness.
//!
//! Not yet modeled (documented gaps, inert here exactly as the flags are unset):
//! * `Varnode::isStackStore` — set by `RuleStoreVarnode` when a real `CPUI_STORE` resolves to a
//!   stack COPY; the COPY-of-INDIRECT-source branch (`coreaction.cc:1381-1393`) that keeps a
//!   call-modified value spilled to the stack a direct write. mosura omits `setStackStore`
//!   (see `RuleStoreVarnode`), so that branch cannot fire and is left out.
//! * `PcodeOp::isIndirectStore` — an INDIRECT that models a `CPUI_STORE` (vs. a call clobber);
//!   would let directwrite propagate through it even at `propagateIndirect = false`. mosura's
//!   call-clobber INDIRECTs are never indirect-stores, so treating it as false is correct for them.

use super::action::Action;
use super::fspec::sysv_input;
use super::funcdata::Funcdata;
use super::opcode::OpCode;
use super::varnode::VarnodeId;

/// Ghidra `ActionDirectWrite` (coreaction.cc:1350).
pub struct ActionDirectWrite {
    /// Ghidra `ActionDirectWrite::propagateIndirect` (coreaction.hh:243): whether directwrite taints
    /// forward through call-based INDIRECT ops.
    pub propagate_indirect: bool,
}

impl ActionDirectWrite {
    pub fn new(propagate_indirect: bool) -> ActionDirectWrite {
        ActionDirectWrite { propagate_indirect }
    }
}

impl Action for ActionDirectWrite {
    fn name(&self) -> &str {
        "directwrite"
    }

    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        let input_list = sysv_input(&data.spaces);
        let n = data.num_varnodes() as u32;
        let mut worklist: Vec<VarnodeId> = Vec::new();

        // Collect legal inputs and other auto direct writes (coreaction.cc:1359-1416).
        for i in 0..n {
            let id = VarnodeId(i);
            data.vn_mut(id).clear_direct_write();
            let vn = data.vn(id);
            if vn.is_input() {
                if vn.is_persist() || vn.is_spacebase() {
                    data.vn_mut(id).set_direct_write();
                    worklist.push(id);
                } else if input_list.as_ref().is_some_and(|pl| pl.possible_param(vn.loc, vn.size)) {
                    // Ghidra `FuncProto::possibleInputParam` (fspec.cc): storage that could hold a
                    // parameter under the calling convention.
                    data.vn_mut(id).set_direct_write();
                    worklist.push(id);
                }
            } else if vn.is_written() {
                let def = vn.def.unwrap();
                let opc = data.op(def).code();
                let is_marker = data.op(def).is_marker();
                if !is_marker {
                    if vn.is_persist() {
                        // A real write to a global variable is a direct write.
                        data.vn_mut(id).set_direct_write();
                        worklist.push(id);
                    } else if opc == OpCode::Copy {
                        // For most COPYs, not a direct write. (The `isStackStore` branch — a COPY
                        // that was really a STORE whose source traces to an INDIRECT — is a
                        // documented gap; see the module docs.)
                    } else if opc != OpCode::Piece && opc != OpCode::Subpiece {
                        // Anything writing a variable in a way that isn't some form of COPY.
                        data.vn_mut(id).set_direct_write();
                        worklist.push(id);
                    }
                } else if !self.propagate_indirect && opc == OpCode::Indirect {
                    // A call-based INDIRECT: mark the output a direct write only when it acts as an
                    // active COPY (storage address changes) or the value must be present at a global
                    // (persist). It is NOT added to the worklist — INDIRECT does not propagate here.
                    let out_addr = vn.loc;
                    let in0_addr = data.op(def).input(0).map(|v| data.vn(v).loc);
                    // Ghidra's two conditions (coreaction.cc:1403-1406), same action: the storage
                    // address changes input→output (an active COPY), OR the value must be present at
                    // global storage when the call is made (output persist).
                    if in0_addr != Some(out_addr) || vn.is_persist() {
                        data.vn_mut(id).set_direct_write();
                    }
                }
            } else if vn.is_constant() && !is_indirect_zero(data, id) {
                data.vn_mut(id).set_direct_write();
                worklist.push(id);
            }
        }

        // Let legalness taint forward through assignment ops (coreaction.cc:1417-1432).
        while let Some(vn) = worklist.pop() {
            for op in data.vn(vn).descend.clone() {
                // Ghidra `PcodeOp::isAssignment` — the op writes an output value.
                let out = match data.op(op).output {
                    Some(o) => o,
                    None => continue,
                };
                if !data.vn(out).is_direct_write() {
                    data.vn_mut(out).set_direct_write();
                    // For call-based INDIRECTs the output is marked but does not propagate unless
                    // this is the propagating pass or a genuine indirect-store (unmodeled → false).
                    if self.propagate_indirect || data.op(op).code() != OpCode::Indirect {
                        worklist.push(out);
                    }
                }
            }
        }

        // Signal the next deadcode to run the `addrforce`-clear-for-`!directwrite` step
        // (Ghidra `ActionDeadCode`, coreaction.cc:3944); see `Funcdata::directwrite_pending_clear`.
        data.directwrite_pending_clear = true;
        // Flag-only pass: it makes no data-flow change the restart loop should count.
        0
    }
}

/// Ghidra `Varnode::isIndirectZero` (varnode.hh): the constant-0 IOP-zero input of an INDIRECT.
/// mosura's 1-input INDIRECT carries no iop-zero annotation, so no constant is ever an indirect-zero
/// (matching [`super::rules`]' local check); the guard is kept faithful to Ghidra's condition.
fn is_indirect_zero(_data: &Funcdata, _vn: VarnodeId) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::op::SeqNum;
    use crate::decompile::space::{Address, SpaceManager};

    // x86-64 register offsets (mosura's model, see fspec.rs).
    const RDI: u64 = 0x38; // first integer parameter
    const RBP: u64 = 0x28; // callee-saved frame pointer — NOT a parameter
    const RSP: u64 = 0x20; // stack pointer (spacebase)

    fn seq() -> SeqNum {
        SeqNum { pc: Address::new(SpaceManager::standard().by_name("ram").unwrap(), 0), uniq: 0 }
    }

    /// A parameter-register input is a direct write; a callee-saved register input (RBP) is not.
    #[test]
    fn param_input_is_direct_write_rbp_is_not() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(spaces.by_name("ram").unwrap(), 0), spaces);
        let rdi = f.new_input(8, Address::new(reg, RDI));
        let rbp = f.new_input(8, Address::new(reg, RBP));

        ActionDirectWrite::new(false).apply(&mut f);

        assert!(f.vn(rdi).is_direct_write(), "parameter register is a direct write");
        assert!(!f.vn(rbp).is_direct_write(), "callee-saved RBP is not a direct write");
        assert!(f.directwrite_pending_clear, "pass signals the deadcode addrforce-clear");
    }

    /// directwrite taints forward through a COPY: a param spilled to the stack stays direct,
    /// a saved RBP does not — the exact discriminator that lets deadcode drop the RBP-save slot.
    #[test]
    fn taint_propagates_from_param_not_from_saved_rbp() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let stack = spaces.by_name("stack").unwrap();
        let mut f = Funcdata::new("t", Address::new(spaces.by_name("ram").unwrap(), 0), spaces);
        let rdi = f.new_input(8, Address::new(reg, RDI));
        let rbp = f.new_input(8, Address::new(reg, RBP));
        // s-0x10 = COPY RDI (a parameter spill); s-0x8 = COPY RBP (the callee-saved save slot).
        let cp_param = f.new_op(OpCode::Copy, seq(), vec![rdi]);
        let slot_param = f.new_output(cp_param, 8, Address::new(stack, (-16i64) as u64));
        let cp_rbp = f.new_op(OpCode::Copy, seq(), vec![rbp]);
        let slot_rbp = f.new_output(cp_rbp, 8, Address::new(stack, (-8i64) as u64));

        ActionDirectWrite::new(false).apply(&mut f);

        assert!(f.vn(slot_param).is_direct_write(), "param spill inherits directwrite via the COPY");
        assert!(!f.vn(slot_rbp).is_direct_write(), "RBP-save slot never becomes a direct write");
    }

    /// A spacebase input is always a direct write (Ghidra seeds `isSpacebase`).
    #[test]
    fn spacebase_input_is_direct_write() {
        let spaces = SpaceManager::standard();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(spaces.by_name("ram").unwrap(), 0), spaces);
        let rsp = f.new_input(8, Address::new(reg, RSP));
        f.vn_mut(rsp).set_spacebase();
        ActionDirectWrite::new(false).apply(&mut f);
        assert!(f.vn(rsp).is_direct_write());
    }

    /// The deadcode addrforce-clear only fires when a directwrite pass has flagged it, and it strips
    /// addrforce from a non-direct-write varnode while leaving a direct-write one alone.
    #[test]
    fn deadcode_clears_addrforce_only_on_nondirectwrite() {
        use crate::decompile::deadcode::dead_code;
        let spaces = SpaceManager::standard();
        let stack = spaces.by_name("stack").unwrap();
        let mut f = Funcdata::new("t", Address::new(spaces.by_name("ram").unwrap(), 0), spaces);
        // Two written stack slots forced into storage; one directwrite, one not.
        let op_a = f.new_op(OpCode::Copy, seq(), vec![]);
        let a = f.new_output(op_a, 8, Address::new(stack, (-8i64) as u64));
        let op_b = f.new_op(OpCode::Copy, seq(), vec![]);
        let b = f.new_output(op_b, 8, Address::new(stack, (-16i64) as u64));
        f.vn_mut(a).set_addr_force();
        f.vn_mut(b).set_addr_force();
        f.vn_mut(b).set_direct_write();

        // Without the flag set, deadcode must not touch addrforce.
        f.directwrite_pending_clear = false;
        dead_code(&mut f);
        assert!(f.vn(a).is_addr_force(), "no clear when the flag is unset");

        // With the flag, the non-direct-write slot loses addrforce; the direct-write one keeps it.
        f.directwrite_pending_clear = true;
        dead_code(&mut f);
        assert!(!f.vn(a).is_addr_force(), "non-direct-write addrforce is cleared");
        assert!(f.vn(b).is_addr_force(), "direct-write addrforce is preserved");
        assert!(!f.directwrite_pending_clear, "the flag is consumed");
    }
}
