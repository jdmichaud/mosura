//! Ghidra `ActionDeindirect`'s constant-target path (coreaction.cc:1219).
//!
//! A constant is a direct target only when the global function database contains
//! that address. COPY chains, addressable-unit conversion and function-pointer
//! encoding bits follow Ghidra's lookup. Mutable memory is not a constant.
//!
//! `FuncCallSpecs::deindirect` (fspec.cc:5443) records an indirect override and
//! restarts when `lateRestriction` cannot transfer the newly known prototype.
//! Our call summaries do not retain Ghidra's locked input/output transfer state,
//! so conversion uses that restart path: the bridge reapplies the ordinary
//! direct-call contract before heritage runs on the original instructions.
//! External-reference and typed-function-pointer paths remain unported; the
//! current `Datatype::Code` has no attached `FuncProto`.

use super::{Action, Address, Funcdata, OpCode, OpId};

fn make_direct(data: &mut Funcdata, call: OpId, target: Address) {
    let reference = data.new_code_ref(target);
    data.op_set_input(call, 0, reference);
    data.op_set_opcode(call, OpCode::Call);
}

/// Apply `Override::indirectover` to fresh p-code, before callee contracts/SSA.
pub fn apply_overrides(data: &mut Funcdata) {
    let calls: Vec<_> = data
        .op_ids()
        .filter(|&id| data.op(id).code() == OpCode::Callind)
        .filter_map(|id| {
            data.indirect_overrides
                .get(&data.op(id).seqnum.pc)
                .copied()
                .map(|target| (id, target))
        })
        .collect();
    for (call, target) in calls {
        make_direct(data, call, target);
    }
}

pub struct ActionDeindirect;

impl Action for ActionDeindirect {
    fn name(&self) -> &str {
        "deindirect"
    }

    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        if data.known_functions.is_empty() {
            return 0;
        }
        let calls: Vec<_> = data
            .op_ids()
            .filter(|&id| !data.op(id).is_dead() && data.op(id).code() == OpCode::Callind)
            .collect();
        let mut count = 0;
        for call in calls {
            let Some(mut vn) = data.op(call).input(0) else {
                continue;
            };
            let mut seen = std::collections::HashSet::new();
            while seen.insert(vn) {
                let Some(def) = data.vn(vn).def else { break };
                if data.op(def).code() != OpCode::Copy {
                    break;
                }
                let Some(input) = data.op(def).input(0) else {
                    break;
                };
                vn = input;
            }
            if !data.vn(vn).is_constant() {
                continue;
            }
            let space = data.addr.space;
            let mut offset = data
                .vn(vn)
                .constant_value()
                .wrapping_mul(data.spaces.get(space).wordsize as u64);
            if data.funcptr_align > 0 {
                offset = offset
                    .checked_shr(data.funcptr_align as u32)
                    .and_then(|v| v.checked_shl(data.funcptr_align as u32))
                    .unwrap_or(0);
            }
            let target = Address::new(space, offset);
            if !data.known_functions.contains(&target) {
                continue;
            }
            data.indirect_overrides
                .insert(data.op(call).seqnum.pc, target);
            make_direct(data, call, target);
            data.restart_pending = true;
            count += 1;
        }
        count
    }
}
