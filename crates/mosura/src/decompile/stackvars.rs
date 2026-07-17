//! Call-mechanism stack modelling — the return-address-push half of what Ghidra's
//! `ActionStackPtrFlow` handles. A forward symbolic pass tracks each location's value as an
//! offset from the entry stack pointer so each x86 `call`'s return-address push can be
//! neutralized (RSP net-unchanged across the call, the callee's `ret` popping the slot) and
//! its constant return-address store landed at the real pushed `stack` slot.
//!
//! The *general* stack LOAD/STORE resolution is NOT done here: it is Ghidra's in-pool
//! mechanism — `RuleLoadVarnode`/`RuleStoreVarnode`'s spacebase-register branch
//! (`checkSpacebase`/`correctSpacebase`, ruleaction.cc:4173-4334, actprop2) converts a
//! `RSP_input [+ const]` LOAD/STORE into a direct addrtied `stack`-space COPY inside the
//! iterating mainloop, and the next iteration's `ActionHeritage` gives the slot SSA form.
//! (This module's pre-heritage symbolic tracker used to convert them all — a loose superset
//! of `correctSpacebase` that also resolved COPY/MULTIEQUAL-of-RSP, over-resolving the
//! indexed/derived accesses Ghidra deliberately keeps indirect; task #22-B cancelled it.)
//!
//! Tracking from the entry RSP unifies frame-pointer (RBP) and frameless (RSP) frames —
//! `mov rbp, rsp` simply copies the current offset into RBP. It runs pre-heritage (reads
//! aren't yet linked to defs), which is why the value is tracked by location rather than
//! followed through the def graph.

use std::collections::HashMap;

use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;
use super::space::{Address, SpaceId};
use super::varnode::VarnodeId;

const RSP: u64 = 0x20; // x86-64 register RSP, the entry stack pointer

type Loc = (SpaceId, u64);

fn loc_of(f: &Funcdata, v: VarnodeId) -> Loc {
    let vn = f.vn(v);
    (vn.loc.space, vn.loc.offset)
}

/// The stack offset this op's output holds, if it computes `entry_rsp + constant`.
fn symbolic_value(f: &Funcdata, o: &super::op::PcodeOp, sval: &HashMap<Loc, i64>) -> Option<i64> {
    let tracked = |v: VarnodeId| sval.get(&loc_of(f, v)).copied();
    let cval = |v: VarnodeId| f.vn(v).is_constant().then(|| f.vn(v).constant_value() as i64);
    match o.code() {
        OpCode::Copy => tracked(o.input(0)?),
        OpCode::IntAdd => {
            let (a, b) = (o.input(0)?, o.input(1)?);
            if let (Some(av), Some(bc)) = (tracked(a), cval(b)) {
                return Some(av + bc);
            }
            if let (Some(bv), Some(ac)) = (tracked(b), cval(a)) {
                return Some(bv + ac);
            }
            None
        }
        OpCode::IntSub => {
            let (a, b) = (o.input(0)?, o.input(1)?);
            Some(tracked(a)? + cval(b).map(|c| -c)?)
        }
        _ => None,
    }
}

/// Detect each CALL's return-address push — the x86 `call` SLEIGH emits
/// `RSP = RSP - N; STORE RSP, <next-insn>; CALL`. Returns, for every call that has both the push
/// (`RSP = RSP - N`) and the constant return-address store, the push op and the push amount `N`.
///
/// [`recover_stack`] uses this to model the call mechanism faithfully (the spirit of Ghidra's
/// `ActionStackPtrFlow`, `coreaction.cc`): it keeps the return-address store — Ghidra keeps it, and
/// it survives as `xStack_NN = <retaddr>` when the pushed slot is an aliased mapped local
/// (`wayoffarray`), or is removed by dead-code otherwise — but neutralizes the push to an identity
/// COPY *after* converting the store, so the store lands at the real pushed slot while RSP is
/// net-unchanged across the call (the callee's `ret` pops those `N` bytes; the default prototype
/// marks the stack pointer `unaffected`).
fn call_push_restores(f: &Funcdata) -> HashMap<OpId, (OpId, OpId, i64)> {
    let mut out = HashMap::new();
    let Some(reg) = f.spaces.by_name("register") else { return out };
    let is_rsp = |v: VarnodeId, f: &Funcdata| {
        let vn = f.vn(v);
        vn.loc.space == reg && vn.loc.offset == RSP
    };
    let calls: Vec<_> = f
        .op_ids()
        .filter(|&op| matches!(f.op(op).code(), OpCode::Call | OpCode::Callind))
        .collect();
    for call in calls {
        let pc = f.op(call).seqnum.pc;
        // Scan backward over the ops emitted by the same `call` instruction for its push/store.
        let mut store: Option<OpId> = None;
        let mut push: Option<(OpId, i64)> = None;
        let mut i = call.0 as usize;
        while i > 0 {
            i -= 1;
            let op = OpId(i as u32);
            if f.op(op).seqnum.pc != pc {
                break; // left this instruction's micro-ops
            }
            match f.op(op).code() {
                // the return-address store: STORE [RSP], <constant return address>
                OpCode::Store
                    if store.is_none()
                        && f.op(op).input(1).is_some_and(|a| is_rsp(a, f))
                        && f.op(op).input(2).is_some_and(|v| f.vn(v).is_constant()) =>
                {
                    store = Some(op);
                }
                // the push: RSP = RSP - <const>
                OpCode::IntSub
                    if push.is_none()
                        && f.op(op).output.is_some_and(|o| is_rsp(o, f))
                        && f.op(op).input(0).is_some_and(|a| is_rsp(a, f))
                        && f.op(op).input(1).is_some_and(|c| f.vn(c).is_constant()) =>
                {
                    let amt = f.vn(f.op(op).input(1).unwrap()).constant_value() as i64;
                    push = Some((op, amt));
                }
                _ => {}
            }
        }
        if let (Some(s), Some((p, amt))) = (store, push) {
            out.insert(call, (s, p, amt));
        }
    }
    out
}

/// Model the call mechanism's return-address push (per [`call_push_restores`]), propagating the
/// stack pointer over the CFG: each block's entry stack state is a processed predecessor's exit
/// state (the pre-heritage analog of the SSA MULTIEQUAL phi-join Ghidra's `StackSolver` relies
/// on), so the stack pointer no longer drifts across independent blocks the flat op order
/// interleaves. Only each call's return-address STORE is converted to its `stack` slot; every
/// other stack LOAD/STORE is left for the in-pool `RuleLoadVarnode`/`RuleStoreVarnode`
/// spacebase-register branch (see the module docs).
pub fn recover_stack(f: &mut Funcdata) {
    let (Some(reg), Some(stack)) = (f.spaces.by_name("register"), f.spaces.by_name("stack")) else {
        return;
    };
    let nblk = f.num_blocks();
    if nblk == 0 {
        return;
    }
    let call_restores = call_push_restores(f);
    let retaddr_stores: std::collections::HashSet<OpId> =
        call_restores.values().map(|&(store, _, _)| store).collect();
    let entry_sval = HashMap::from([((reg, RSP), 0i64)]);
    let mut sval_out: Vec<Option<HashMap<Loc, i64>>> = vec![None; nblk];

    // Process blocks in reverse postorder so each block's forward-edge predecessors are processed
    // before it (the loop back-edge predecessor is processed after the header, which already has the
    // loop-invariant stack pointer from the pre-header). Any block unreachable from the entry is
    // visited last with the entry seed.
    let mut order: Vec<usize> = super::dominator::postorder(f);
    order.reverse();
    let mut in_order = vec![false; nblk];
    for &b in &order {
        in_order[b] = true;
    }
    order.extend((0..nblk).filter(|&b| !in_order[b]));

    for b in order {
        let bid = super::block::BlockId(b as u32);
        // Entry state: a processed predecessor's exit state; the entry block (no preds) seeds RSP=0.
        let mut sval: HashMap<Loc, i64> = {
            let preds: Vec<usize> = f.block(bid).in_edges.iter().map(|e| e.0 as usize).collect();
            preds.iter().find_map(|&p| sval_out[p].clone()).unwrap_or_else(|| entry_sval.clone())
        };
        let ops = f.block(bid).ops.clone();
        for op in ops {
            if f.op(op).is_dead() {
                continue;
            }
            let o = f.op(op).clone();
            match o.code() {
                // ONLY each call's return-address store is converted here (the call-mechanism
                // model); a general stack STORE stays a STORE for the in-pool RuleStoreVarnode.
                OpCode::Store if retaddr_stores.contains(&op) => {
                    if let (Some(addr), Some(val)) = (o.input(1), o.input(2)) {
                        if let Some(&c) = sval.get(&loc_of(f, addr)) {
                            let size = f.vn(val).size;
                            f.op_set_all_input(op, &[val]);
                            f.op_set_opcode(op, OpCode::Copy);
                            f.new_output(op, size, Address::new(stack, c as u64));
                            continue;
                        }
                    }
                }
                OpCode::Call | OpCode::Callind => {
                    // The return-address store (one of the ops above, already converted to its
                    // `stack`-space slot) is kept; now neutralize the push to an identity COPY so RSP
                    // is net-unchanged across the call, and add the push amount back to the tracked
                    // RSP (modelling the callee's `ret` pop). Done here, after the store conversion,
                    // so the store lands at the real pushed slot rather than the pre-push one.
                    if let Some(&(_, push, amt)) = call_restores.get(&op) {
                        let base = f.op(push).input(0).unwrap();
                        f.op_set_opcode(push, OpCode::Copy);
                        f.op_set_all_input(push, &[base]);
                        if let Some(v) = sval.get_mut(&(reg, RSP)) {
                            *v += amt;
                        }
                    }
                }
                _ => {}
            }
            // propagate the stack-offset value through the op's output
            if let Some(out) = o.output {
                let outloc = loc_of(f, out);
                match symbolic_value(f, &o, &sval) {
                    Some(v) => {
                        sval.insert(outloc, v);
                    }
                    None => {
                        sval.remove(&outloc);
                    }
                }
            }
        }
        sval_out[b] = Some(sval);
    }
}
