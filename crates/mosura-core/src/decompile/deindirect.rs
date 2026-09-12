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

use super::fspec::ProtoSlot;
use super::{Action, Address, Funcdata, OpCode, OpId};

/// Parse explicit pointer-slot input declarations: `hex=REG,REG;hex=REG`.
/// Empty right-hand sides declare no inputs. Duplicate slots/registers are errors.
pub fn parse_indirect_inputs(
    text: &str,
) -> Result<std::collections::BTreeMap<u64, Vec<String>>, String> {
    let mut result = std::collections::BTreeMap::new();
    if text.trim().is_empty() {
        return Ok(result);
    }
    for item in text.split(';') {
        let (address, registers) = item.split_once('=').ok_or("expected hex=REG,REG")?;
        let address = address.trim();
        let slot = u64::from_str_radix(
            address
                .strip_prefix("0x")
                .or_else(|| address.strip_prefix("0X"))
                .unwrap_or(address),
            16,
        )
        .map_err(|_| format!("invalid pointer slot address `{address}`"))?;
        let regs: Vec<String> = if registers.trim().is_empty() {
            vec![]
        } else {
            registers.split(',').map(|r| r.trim().to_string()).collect()
        };
        let mut seen = std::collections::HashSet::new();
        for r in &regs {
            if r.is_empty()
                || !r.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                || !seen.insert(r.to_ascii_lowercase())
            {
                return Err(format!("invalid or duplicate register `{r}`"));
            }
        }
        if result.insert(slot, regs).is_some() {
            return Err(format!("duplicate pointer slot {slot:#x}"));
        }
    }
    Ok(result)
}

/// Resolve declared names against the selected language and reject overlapping
/// storage (e.g. EAX and AX cannot be two independent argument slots).
pub fn validate_indirect_inputs(
    knobs: &crate::switches::Knobs,
    spec: &crate::sleigh::engine::Spec,
) -> Result<(), String> {
    let registers = spec.register_table();
    for (slot, names) in &knobs.indirect_inputs {
        let mut used: Vec<(u64, u32)> = Vec::new();
        for name in names {
            let &(storage, _) = registers
                .iter()
                .find(|(_, n)| n.eq_ignore_ascii_case(name))
                .ok_or_else(|| format!("indirect input at {slot:#x}: unknown register `{name}`"))?;
            if used.iter().any(|&(off, size)| {
                storage.0 < off + size as u64 && off < storage.0 + storage.1 as u64
            }) {
                return Err(format!(
                    "indirect input at {slot:#x}: overlapping register `{name}`"
                ));
            }
            used.push(storage);
        }
    }
    Ok(())
}

fn slot_inputs(data: &Funcdata, vn: super::VarnodeId) -> Option<Vec<ProtoSlot>> {
    let v = data.vn(vn);
    if v.loc.space != data.addr.space {
        return None;
    }
    let names = data.knobs.indirect_inputs.get(&v.loc.offset)?;
    let register = data.spaces.by_name("register")?;
    names
        .iter()
        .map(|name| {
            data.reg_names
                .iter()
                .find(|(_, n)| n.eq_ignore_ascii_case(name))
                .map(|(&(offset, size), _)| ProtoSlot {
                    addr: Address::new(register, offset),
                    size,
                })
        })
        .collect()
}

/// Install a declared input model before `ActionFuncLink` creates its inputs.
/// Like a function-pointer prototype, it changes neither the pointer nor the return contract.
pub fn apply_input_overrides(data: &mut Funcdata) {
    let calls: Vec<_> = data
        .op_ids()
        .filter(|&id| matches!(data.op(id).code(), OpCode::Call | OpCode::Callind))
        .collect();
    for call in calls {
        let pc = data.op(call).seqnum.pc;
        let inputs = data.call_input_overrides.get(&pc).cloned().or_else(|| {
            (data.op(call).code() == OpCode::Callind)
                .then(|| data.op(call).input(0).and_then(|vn| slot_inputs(data, vn)))
                .flatten()
        });
        let Some(inputs) = inputs else { continue };
        data.call_input_overrides.insert(pc, inputs.clone());
        let cs = data.call_specs.entry(call).or_default();
        cs.param_widths = Some(inputs.iter().map(|p| p.size).collect());
        cs.locked_inputs = Some(inputs);
    }
}

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
        if data.known_functions.is_empty() && data.knobs.indirect_inputs.is_empty() {
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
            // The pointer's declared input contract applies to every value of that
            // storage. Carry it to the fresh graph without replacing the live target.
            let pc = data.op(call).seqnum.pc;
            if !data.call_input_overrides.contains_key(&pc) {
                if let Some(inputs) = slot_inputs(data, vn) {
                    data.call_input_overrides.insert(pc, inputs);
                    data.restart_pending = true;
                    count += 1;
                }
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
