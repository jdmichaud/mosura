//! Return-value recovery — a port of Ghidra's `ActionReturnRecovery` (`coreaction.cc`) +
//! the core of `AncestorRealistic` (`funcdata_varnode.cc`).
//!
//! Every RETURN is given the candidate return-convention registers as inputs (RAX for
//! integers/pointers, XMM0 for floats). After heritage links each to the value reaching
//! that RETURN, [`is_realistic`] decides which candidate actually holds a returned value —
//! i.e. its value traces back to a *real write the function made*, not to the unwritten
//! passthrough register. The non-realistic candidates are removed, so dead-code keeps
//! exactly the return value and the scratch register writes die.
//!
//! `is_realistic` ports `AncestorRealistic`'s essence for the return-register case (where
//! the candidates are never directwrite parameters, so an unwritten input is not realistic);
//! the full action's directwrite/unaffected/kill machinery is for input-parameter trials.

use std::collections::HashSet;

use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;
use super::space::Address;
use super::varnode::VarnodeId;

const RAX: u64 = 0x0;
const XMM0: u64 = 0x1200;

/// SysV integer argument registers, in order: RDI, RSI, RDX, RCX, R8, R9.
const ARG_REGS: [u64; 6] = [0x38, 0x30, 0x10, 0x8, 0x80, 0x88];

/// Does `vn`'s value trace back to a real write the function made (a "solid" definition),
/// rather than to the unwritten passthrough register? Traverses transparent ops (COPY,
/// SUBPIECE, extensions) and MULTIEQUALs; any solid producer (arithmetic, LOAD, …) or a
/// constant is realistic.
fn is_realistic(f: &Funcdata, vn: VarnodeId, seen: &mut HashSet<VarnodeId>) -> bool {
    let v = f.vn(vn);
    if v.is_constant() {
        return true;
    }
    if !v.is_written() {
        return false; // an unwritten input — the function never set this register
    }
    if !seen.insert(vn) {
        return false; // a cycle contributes no fresh realism
    }
    let def = v.def.unwrap();
    match f.op(def).code() {
        // transparent value movement — keep tracing the source
        OpCode::Copy | OpCode::Subpiece | OpCode::IntZext | OpCode::IntSext => {
            f.op(def).input(0).is_some_and(|i| is_realistic(f, i, seen))
        }
        // a join is realistic if any incoming value is
        OpCode::Multiequal => f.op(def).inrefs.clone().iter().any(|&i| is_realistic(f, i, seen)),
        // INDIRECT through a call creates a value out of nothing — not a real return
        OpCode::Indirect => false,
        // arithmetic / LOAD / PIECE / etc. — a real computed value
        _ => true,
    }
}

/// Append the candidate return-convention registers (RAX, XMM0) to every RETURN op, so
/// heritage links them to the value reaching each RETURN. Runs pre-heritage.
pub fn recover_return(f: &mut Funcdata) {
    let Some(reg) = f.spaces.by_name("register") else { return };
    let rets: Vec<OpId> = f.op_ids().filter(|&op| f.op(op).code() == OpCode::Return).collect();
    for ret in rets {
        // RAX/XMM0 at 8 bytes, plus XMM0 at 4 bytes for a `float` return (the low lane of a
        // zeroed XMM0). resolve keeps the first realistic, so the wider candidates win first.
        for (off, size) in [(RAX, 8), (XMM0, 8), (XMM0, 4)] {
            let v = f.new_varnode(size, Address::new(reg, off));
            f.op_append_input(ret, v);
        }
    }
}

/// Keep only the realistic return-value candidate on each RETURN (preferring RAX over XMM0
/// when both are realistic, as a function returns one value). Runs post-heritage.
pub fn resolve_return(f: &mut Funcdata) {
    let rets: Vec<OpId> = f.op_ids().filter(|&op| f.op(op).code() == OpCode::Return).collect();
    for ret in rets {
        let n = f.op(ret).num_inputs();
        // slot 0 is the return address; slots 1.. are the candidate return registers
        let keep = (1..n).find(|&slot| {
            let v = f.op(ret).input(slot).unwrap();
            is_realistic(f, v, &mut HashSet::new())
        });
        for slot in (1..n).rev() {
            if Some(slot) != keep {
                f.op_remove_input(ret, slot);
            }
        }
    }
}

/// Append the candidate integer argument registers (RDI…R9) to every CALL op, so heritage
/// links them to the value each holds at the call site. Runs pre-heritage. (Mirrors
/// `recover_return` on the input side — Ghidra's `ActionFuncLink`/`ParamActive` setup.)
pub fn recover_call_args(f: &mut Funcdata) {
    let Some(reg) = f.spaces.by_name("register") else { return };
    let calls: Vec<OpId> =
        f.op_ids().filter(|&op| matches!(f.op(op).code(), OpCode::Call | OpCode::Callind)).collect();
    for call in calls {
        for off in ARG_REGS {
            let v = f.new_varnode(8, Address::new(reg, off));
            f.op_append_input(call, v);
        }
    }
}

/// Keep the call's real arguments: the contiguous prefix of candidate registers (from RDI)
/// whose value is realistic (set by the caller). The first candidate that is merely an
/// unwritten/scratch register ends the argument list. Runs post-heritage.
pub fn resolve_call_args(f: &mut Funcdata) {
    let calls: Vec<OpId> =
        f.op_ids().filter(|&op| matches!(f.op(op).code(), OpCode::Call | OpCode::Callind)).collect();
    for call in calls {
        let n = f.op(call).num_inputs();
        let mut keep = 0; // slots 1..=keep are arguments (contiguous from RDI)
        for slot in 1..n {
            let v = f.op(call).input(slot).unwrap();
            if is_realistic(f, v, &mut HashSet::new()) {
                keep = slot;
            } else {
                break;
            }
        }
        for slot in (keep + 1..n).rev() {
            f.op_remove_input(call, slot);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::space::{Address, SpaceManager};
    use crate::decompile::{BlockBasic, Funcdata, OpCode, SeqNum};

    /// A RETURN with candidate inputs `[retaddr, RAX, XMM0]` where each named register is
    /// either a real write (an INT_ADD output) or the unwritten function input.
    fn ret_with(rax_written: bool, xmm0_written: bool) -> (Funcdata, OpId) {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let mk = |f: &mut Funcdata, off: u64, written: bool| -> VarnodeId {
            if written {
                let a = f.new_input(8, Address::new(reg, 0x38));
                let c = f.new_const(8, 1);
                let op = f.new_op(OpCode::IntAdd, seq, vec![a, c]);
                f.new_output(op, 8, Address::new(reg, off))
            } else {
                f.new_input(8, Address::new(reg, off))
            }
        };
        let rax = mk(&mut f, RAX, rax_written);
        let xmm0 = mk(&mut f, XMM0, xmm0_written);
        let retaddr = f.new_input(8, Address::new(reg, 0x20));
        let ret = f.new_op(OpCode::Return, seq, vec![retaddr, rax, xmm0]);
        f.set_blocks(vec![BlockBasic { ops: vec![ret], ..Default::default() }]);
        (f, ret)
    }

    fn kept_offset(f: &Funcdata, ret: OpId, reg_off: u64) -> bool {
        f.op(ret).num_inputs() == 2 && {
            let v = f.op(ret).input(1).unwrap();
            f.vn(v).loc.offset == reg_off
        }
    }

    #[test]
    fn integer_return_keeps_rax() {
        let (mut f, ret) = ret_with(true, false);
        resolve_return(&mut f);
        assert!(kept_offset(&f, ret, RAX), "RAX (written) is the return value");
    }

    #[test]
    fn float_return_keeps_xmm0() {
        let (mut f, ret) = ret_with(false, true);
        resolve_return(&mut f);
        assert!(kept_offset(&f, ret, XMM0), "XMM0 (written) is the return value, not the unwritten RAX");
    }

    #[test]
    fn void_return_keeps_nothing() {
        let (mut f, ret) = ret_with(false, false);
        resolve_return(&mut f);
        assert_eq!(f.op(ret).num_inputs(), 1, "neither register written ⇒ void");
    }

    #[test]
    fn both_written_prefers_rax() {
        let (mut f, ret) = ret_with(true, true);
        resolve_return(&mut f);
        assert!(kept_offset(&f, ret, RAX), "a function returns one value; prefer RAX");
    }

    /// A CALL with candidate inputs `[target, RDI, RSI, RDX, RCX, R8, R9]` where the first
    /// `written` (in SysV order) are real computed writes and the rest are scratch registers.
    fn call_with(written: usize) -> (Funcdata, OpId) {
        let spaces = SpaceManager::standard();
        let ram = spaces.by_name("ram").unwrap();
        let reg = spaces.by_name("register").unwrap();
        let mut f = Funcdata::new("t", Address::new(ram, 0), spaces);
        let seq = SeqNum { pc: Address::new(ram, 0), uniq: 0 };
        let target = f.new_const(8, 0x400430);
        let mut inputs = vec![target];
        for (i, &off) in ARG_REGS.iter().enumerate() {
            let v = if i < written {
                let c = f.new_const(8, 0x10 + i as u64);
                let op = f.new_op(OpCode::Copy, seq, vec![c]);
                f.new_output(op, 8, Address::new(reg, off))
            } else {
                f.new_input(8, Address::new(reg, off))
            };
            inputs.push(v);
        }
        let call = f.new_op(OpCode::Call, seq, inputs);
        f.set_blocks(vec![BlockBasic { ops: vec![call], ..Default::default() }]);
        (f, call)
    }

    #[test]
    fn call_keeps_contiguous_written_args() {
        let (mut f, call) = call_with(2); // RDI, RSI written; RDX.. scratch
        resolve_call_args(&mut f);
        assert_eq!(f.op(call).num_inputs(), 3, "[target, RDI, RSI] — two arguments");
    }

    #[test]
    fn call_with_no_set_registers_has_no_args() {
        let (mut f, call) = call_with(0);
        resolve_call_args(&mut f);
        assert_eq!(f.op(call).num_inputs(), 1, "only the call target remains");
    }
}
