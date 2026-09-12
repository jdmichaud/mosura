//! Explicit register prototypes shared by definitions and direct calls.
//!
//! Ports the locked branches of Ghidra `ActionPrototypeTypes`, `ActionInputPrototype`
//! and `ActionFuncLink` (coreaction.cc). Declarations retain their storage, order and
//! types independently of the prototype model's recovery candidates.

use std::collections::BTreeMap;

use super::fspec::{ProtoParameter, RegisterOutput, RegisterParameter};
use super::types::Datatype;
use super::{Address, Funcdata, OpCode};

/// Parse `hex=REGISTER:type;hex=void`. Type widths are in bytes, as in Ghidra's
/// core types. The selected language validates register existence and width.
pub fn parse_function_outputs(text: &str) -> Result<BTreeMap<u64, RegisterOutput>, String> {
    let mut result = BTreeMap::new();
    if text.trim().is_empty() {
        return Ok(result);
    }
    for item in text.split(';') {
        let (entry, value) = item
            .split_once('=')
            .ok_or("expected hex=REGISTER:type or hex=void")?;
        let entry = entry.trim();
        let address = u64::from_str_radix(
            entry
                .strip_prefix("0x")
                .or_else(|| entry.strip_prefix("0X"))
                .unwrap_or(entry),
            16,
        )
        .map_err(|_| format!("invalid function address `{entry}`"))?;
        let value = value.trim();
        let output = if value == "void" {
            RegisterOutput {
                register: String::new(),
                datatype: Datatype::Void,
            }
        } else {
            parse_register_parameter(value, "output")?
        };
        if result.insert(address, output).is_some() {
            return Err(format!("duplicate output declaration at {address:#x}"));
        }
    }
    Ok(result)
}

/// Parse `hex=REGISTER:type,REGISTER:type;hex=void`. An empty option leaves
/// recovery enabled everywhere; `void` declares an explicit empty input list.
pub fn parse_function_inputs(text: &str) -> Result<BTreeMap<u64, Vec<RegisterParameter>>, String> {
    let mut result = BTreeMap::new();
    if text.trim().is_empty() { return Ok(result); }
    for item in text.split(';') {
        let (entry, value) = item.split_once('=')
            .ok_or("expected hex=REGISTER:type,... or hex=void")?;
        let entry = entry.trim();
        let address = u64::from_str_radix(
            entry.strip_prefix("0x").or_else(|| entry.strip_prefix("0X")).unwrap_or(entry), 16,
        ).map_err(|_| format!("invalid function address `{entry}`"))?;
        let params = if value.trim() == "void" { Vec::new() } else {
            value.split(',').map(|p| parse_register_parameter(p.trim(), "input"))
                .collect::<Result<Vec<_>, _>>()?
        };
        if result.insert(address, params).is_some() {
            return Err(format!("duplicate input declaration at {address:#x}"));
        }
    }
    Ok(result)
}

fn parse_register_parameter(text: &str, kind: &str) -> Result<RegisterParameter, String> {
    let (register, ty) = text.split_once(':').ok_or("expected REGISTER:type")?;
    let register = register.trim();
    if register.is_empty() || !register.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err(format!("invalid {kind} register `{register}`"));
    }
    let ty = ty.trim();
    let datatype = match ty {
        "bool" => Datatype::Bool,
        "char" => Datatype::Char,
        _ => {
            let (prefix, size) = ["uint", "int", "float", "unknown"].into_iter()
                .find_map(|p| ty.strip_prefix(p).and_then(|s| s.parse::<u32>().ok()).map(|s| (p, s)))
                .ok_or_else(|| format!("unknown {kind} type `{ty}`"))?;
            if !matches!(size, 1 | 2 | 4 | 8 | 16) && !(prefix == "float" && size == 10) {
                return Err(format!("unsupported {kind} type width in `{ty}`"));
            }
            match prefix {
                "uint" => Datatype::Uint(size),
                "int" => Datatype::Int(size),
                "float" => Datatype::Float(size),
                _ => Datatype::Unknown(size),
            }
        }
    };
    Ok(RegisterParameter { register: register.into(), datatype })
}

pub fn validate_function_outputs(
    knobs: &crate::switches::Knobs,
    spec: &crate::sleigh::engine::Spec,
) -> Result<(), String> {
    let registers = spec.register_table();
    for (entry, result) in &knobs.function_outputs {
        if result.datatype == Datatype::Void {
            if !result.register.is_empty() {
                return Err("void output must not name a register".into());
            }
            continue;
        }
        let &((_, size), _) = registers
            .iter()
            .find(|(_, n)| n.eq_ignore_ascii_case(&result.register))
            .ok_or_else(|| {
                format!(
                    "output at {entry:#x}: unknown register `{}`",
                    result.register
                )
            })?;
        if size != result.datatype.size() {
            return Err(format!(
                "output at {entry:#x}: register `{}` has {size} bytes, type has {}",
                result.register,
                result.datatype.size()
            ));
        }
    }
    Ok(())
}

/// Check explicit input storage against the selected language, including overlap.
/// A named register establishes the storage width independently of its declared type.
pub fn validate_function_inputs(
    knobs: &crate::switches::Knobs,
    spec: &crate::sleigh::engine::Spec,
) -> Result<(), String> {
    let registers = spec.register_table();
    for (entry, params) in &knobs.function_inputs {
        let mut used: Vec<(u64, u32)> = Vec::new();
        for param in params {
            let &((offset, size), _) = registers.iter()
                .find(|(_, name)| name.eq_ignore_ascii_case(&param.register))
                .ok_or_else(|| format!("input at {entry:#x}: unknown register `{}`", param.register))?;
            if param.datatype == Datatype::Void || param.datatype.size() != size {
                return Err(format!("input at {entry:#x}: register `{}` has {size} bytes, type has {}",
                    param.register, param.datatype.size()));
            }
            if used.iter().any(|&(a, n)| offset < a + u64::from(n) && a < offset + u64::from(size)) {
                return Err(format!("input at {entry:#x}: overlapping register `{}`", param.register));
            }
            used.push((offset, size));
        }
    }
    Ok(())
}

/// Supply the same explicit prototype to a function and its direct calls. This runs
/// before call-site overrides, which retain their more specific declaration, and on restart.
pub fn bind_input_declarations(f: &mut Funcdata) {
    if f.knobs.function_inputs.is_empty() { return; }
    let Some(register) = f.spaces.by_name("register") else { return };
    let resolve = |entry: u64| -> Option<Vec<ProtoParameter>> {
        f.knobs.function_inputs.get(&entry)?.iter().map(|param| {
            let (&(offset, _), _) = f.reg_names.iter()
                .find(|(_, name)| name.eq_ignore_ascii_case(&param.register))?;
            Some(ProtoParameter { addr: Address::new(register, offset), datatype: param.datatype.clone() })
        }).collect()
    };
    let own = resolve(f.addr.offset);
    let calls: Vec<_> = f.op_ids().filter(|&id| !f.op(id).is_dead() && f.op(id).code() == OpCode::Call)
        .filter_map(|id| {
            let target = f.vn(f.op(id).input(0)?);
            (target.loc.space == f.addr.space).then(|| resolve(target.loc.offset)).flatten().map(|p| (id, p))
        }).collect();
    f.locked_inputs = own;
    for (id, params) in calls {
        let cs = f.call_specs.entry(id).or_default();
        cs.param_widths = Some(params.iter().map(|p| p.datatype.size()).collect());
        cs.locked_inputs = Some(params);
    }
}

/// `ActionPrototypeTypes` (:4676): force each locked input to exist before heritage,
/// even if unused. Input extension follows the compiler specification's ParamEntry.
pub fn lock_function_inputs(f: &mut Funcdata) {
    let Some(params) = f.locked_inputs.clone() else { return };
    let top = (!f.blocks().is_empty()).then_some(super::block::BlockId(0));
    for param in params {
        let vn = f.new_varnode(param.datatype.size(), param.addr);
        let vn = f.set_input_varnode(vn);
        f.vn_mut(vn).set_locked_input();
        // Ghidra obtains this symbol type/lock when creating the mapped input Varnode.
        f.vn_mut(vn).update_type(param.datatype.clone());
        f.vn_mut(vn).set_typelock();
        if let Some(top) = top {
            let extension = f.proto_model.input.as_ref().and_then(|list| list.entry.iter()
                .filter(|e| e.minsize <= param.datatype.size())
                .find_map(|e| e.assumed_extension(&f.spaces, param.addr, param.datatype.size())));
            if let Some((mut opcode, container)) = extension {
                if opcode == OpCode::Piece {
                    opcode = if matches!(param.datatype, Datatype::Int(_) | Datatype::Char) {
                        OpCode::IntSext
                    } else { OpCode::IntZext };
                }
                let op = f.new_op(opcode, super::op::SeqNum { pc: f.addr, uniq: 0 }, vec![vn]);
                f.new_output(op, container.size, container.addr);
                f.op_insert_begin(op, top);
            }
        }
    }
}

/// Bind explicit facts before heritage and again after an analysis restart.
pub fn bind_output_declarations(f: &mut Funcdata) {
    if f.knobs.function_outputs.is_empty() {
        return;
    }
    let Some(register) = f.spaces.by_name("register") else {
        return;
    };
    let resolve = |entry: u64| -> Option<ProtoParameter> {
        let result = f.knobs.function_outputs.get(&entry)?;
        let offset = if result.datatype == Datatype::Void {
            0
        } else {
            let (&(offset, _), _) = f
                .reg_names
                .iter()
                .find(|(_, n)| n.eq_ignore_ascii_case(&result.register))?;
            offset
        };
        Some(ProtoParameter {
            addr: Address::new(register, offset),
            datatype: result.datatype.clone(),
        })
    };
    let own = resolve(f.addr.offset);
    let calls: Vec<_> = f
        .op_ids()
        .filter(|&id| !f.op(id).is_dead() && f.op(id).code() == OpCode::Call)
        .filter_map(|id| {
            let target = f.vn(f.op(id).input(0)?);
            (target.loc.space == f.addr.space)
                .then(|| resolve(target.loc.offset))
                .flatten()
                .map(|p| (id, p))
        })
        .collect();
    f.locked_output = own;
    for (id, param) in calls {
        f.call_specs.entry(id).or_default().locked_output = Some(param);
    }
}

/// `ActionPrototypeTypes`: force the declared non-void result onto every normal
/// RETURN and lock its type. A locked void prototype opens no output trials.
pub fn lock_return_output(f: &mut Funcdata) -> bool {
    let Some(param) = f.locked_output.clone() else {
        return false;
    };
    if param.datatype != Datatype::Void {
        let returns: Vec<_> = f
            .op_ids()
            .filter(|&id| !f.op(id).is_dead() && f.op(id).code() == OpCode::Return)
            .collect();
        for ret in returns {
            let vn = f.new_varnode(param.datatype.size(), param.addr);
            f.vn_mut(vn).update_type(param.datatype.clone());
            f.vn_mut(vn).set_typelock();
            let mut inputs = f.op(ret).inrefs.clone();
            inputs.push(vn);
            f.op_set_all_input(ret, &inputs);
        }
        f.output_storage_size = Some(param.datatype.size());
    }
    true
}

/// `ActionFuncLink::funcLinkOutput`: create the locked register output before
/// heritage, then materialize the extension promised by the callee model.
/// Stack results require the separate delayed stack-output-lock mechanism.
pub fn link_call_outputs(f: &mut Funcdata) {
    let mut calls: Vec<_> = f
        .call_specs
        .iter()
        .filter_map(|(&id, cs)| cs.locked_output.clone().map(|p| (id, p)))
        .collect();
    calls.sort_by_key(|(call, _)| call.0);
    for (call, param) in calls {
        if f.op(call).is_dead() {
            continue;
        }
        assert!(
            f.op(call).output.is_none(),
            "raw CALL unexpectedly has an output"
        );
        if param.datatype == Datatype::Void {
            continue;
        }
        if param.datatype == Datatype::Bool {
            f.op_mut(call).flags |= super::op::flags::CALCULATED_BOOL;
        }
        f.new_output(call, param.datatype.size(), param.addr);
        f.call_specs.get_mut(&call).unwrap().output_storage =
            Some((param.addr, param.datatype.size()));
        let model = f
            .call_specs
            .get(&call)
            .and_then(|cs| cs.model.as_ref())
            .unwrap_or_else(|| f.called_model());
        let extension = model.output.as_ref().and_then(|list| {
            list.entry
                .iter()
                .filter(|e| e.minsize <= param.datatype.size())
                .find_map(|e| e.assumed_extension(&f.spaces, param.addr, param.datatype.size()))
        });
        if let Some((mut opcode, container)) = extension {
            if opcode == OpCode::Piece {
                opcode = if matches!(param.datatype, Datatype::Int(_) | Datatype::Char) {
                    OpCode::IntSext
                } else {
                    OpCode::IntZext
                };
            }
            let input = f.new_varnode(param.datatype.size(), param.addr);
            let op = f.new_op(opcode, f.op(call).seqnum, vec![input]);
            f.new_output(op, container.size, container.addr);
            f.op_insert_after(op, call);
        }
    }
}
