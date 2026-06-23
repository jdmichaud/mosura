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

/// Rewrite stack-pointer-relative LOAD/STORE into `stack`-space accesses.
pub fn recover_stack(f: &mut Funcdata) {
    let (Some(reg), Some(stack)) = (f.spaces.by_name("register"), f.spaces.by_name("stack")) else {
        return;
    };
    let mut sval: HashMap<Loc, i64> = HashMap::new();
    sval.insert((reg, RSP), 0); // entry stack pointer is offset 0

    for op in f.op_ids().collect::<Vec<_>>() {
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
