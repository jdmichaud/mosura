//! Stack-variable recovery — the spacebase part of Ghidra's `ActionStackPtrFlow` /
//! `Funcdata::spacebase`. A forward symbolic pass tracks each location's value as an offset
//! from the entry stack pointer; a `LOAD`/`STORE` through such a value becomes an access to
//! the `stack` space at that offset. Heritage (P1) then gives those slots SSA form: a
//! spilled value's `STORE` then `LOAD` link directly, the frame ops fall to dead-code, and
//! locals become variables instead of raw pointer arithmetic.
//!
//! Tracking from the entry RSP unifies frame-pointer (RBP) and frameless (RSP) frames —
//! `mov rbp, rsp` simply copies the current offset into RBP. It runs pre-heritage (reads
//! aren't yet linked to defs), which is why the value is tracked by location rather than
//! followed through the def graph.

use std::collections::HashMap;

use super::funcdata::Funcdata;
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

/// Remove the call-mechanism return-address push — the faithful effect of Ghidra's
/// `ActionStackPtrFlow` (`coreaction.cc`) for a CALL site. The x86 `call` SLEIGH emits
/// `RSP = RSP - 8; STORE RSP, <next-insn>; CALL`, and the callee's `ret` pops those 8 bytes, so
/// RSP is net-unchanged across the call (the default prototype marks the stack pointer
/// `unaffected`). mosura does not trace into the callee, so without this the push survives as a
/// bogus return-address stack slot that (a) shifts every later frame offset by 8 and (b) drags the
/// alias boundary down onto itself, spuriously guarding the slot. Drop the push and the
/// return-address store so RSP is restored across the call.
///
/// Runs pre-heritage on the flat op list: the matched ops are marked dead (recover_stack and the
/// CFG builder skip dead ops), so the stack-offset tracking never sees the -8 and later RSP reads
/// resolve to the pre-call value.
pub fn normalize_call_stack(f: &mut Funcdata) {
    let Some(reg) = f.spaces.by_name("register") else { return };
    let is_rsp = |v: &VarnodeId, f: &Funcdata| {
        let vn = f.vn(*v);
        vn.loc.space == reg && vn.loc.offset == RSP
    };
    let calls: Vec<_> = f
        .op_ids()
        .filter(|&op| matches!(f.op(op).code(), OpCode::Call | OpCode::Callind))
        .collect();
    for call in calls {
        let pc = f.op(call).seqnum.pc;
        let idx = call.0 as usize;
        // Scan backward over the ops emitted by the same `call` instruction for its push/store.
        let mut store = None;
        let mut push = None;
        let mut i = idx;
        while i > 0 {
            i -= 1;
            let op = super::op::OpId(i as u32);
            if f.op(op).seqnum.pc != pc {
                break; // left this instruction's micro-ops
            }
            match f.op(op).code() {
                // the return-address store: STORE [RSP], <constant return address>
                OpCode::Store
                    if store.is_none()
                        && f.op(op).input(1).is_some_and(|a| is_rsp(&a, f))
                        && f.op(op).input(2).is_some_and(|v| f.vn(v).is_constant()) =>
                {
                    store = Some(op);
                }
                // the push: RSP = RSP - <const>
                OpCode::IntSub
                    if push.is_none()
                        && f.op(op).output.is_some_and(|o| is_rsp(&o, f))
                        && f.op(op).input(0).is_some_and(|a| is_rsp(&a, f))
                        && f.op(op).input(1).is_some_and(|c| f.vn(c).is_constant()) =>
                {
                    push = Some(op);
                }
                _ => {}
            }
        }
        if let (Some(store), Some(push)) = (store, push) {
            // Neutralize the push to an identity COPY (RSP unchanged across the call) and drop the
            // return-address store. Later reads of RSP propagate through the COPY to the pre-call
            // value; the store has no output, so destroying it orphans nothing.
            let base = f.op(push).input(0).unwrap();
            f.op_set_opcode(push, OpCode::Copy);
            f.op_set_all_input(push, &[base]);
            f.op_destroy(store);
        }
    }
}

/// Rewrite stack-pointer-relative LOAD/STORE into `stack`-space accesses.
pub fn recover_stack(f: &mut Funcdata) {
    let (Some(reg), Some(stack)) = (f.spaces.by_name("register"), f.spaces.by_name("stack")) else {
        return;
    };
    let mut sval: HashMap<Loc, i64> = HashMap::new();
    sval.insert((reg, RSP), 0); // entry stack pointer is offset 0

    for op in f.op_ids().collect::<Vec<_>>() {
        if f.op(op).is_dead() {
            continue; // skip ops removed by normalize_call_stack
        }
        let o = f.op(op).clone();
        match o.code() {
            OpCode::Store => {
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
            OpCode::Load => {
                if let (Some(addr), Some(out)) = (o.input(1), o.output) {
                    if let Some(&c) = sval.get(&loc_of(f, addr)) {
                        let size = f.vn(out).size;
                        let sv = f.new_varnode(size, Address::new(stack, c as u64));
                        f.op_set_all_input(op, &[sv]);
                        f.op_set_opcode(op, OpCode::Copy);
                        // the loaded value is data, not a stack address
                        sval.remove(&loc_of(f, out));
                        continue;
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
}
