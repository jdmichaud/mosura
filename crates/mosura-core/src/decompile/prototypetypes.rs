//! The register/void locked-output branches of Ghidra `ActionPrototypeTypes`
//! and `ActionFuncLink::funcLinkOutput` (coreaction.cc:4637,1540).
//!
//! An output declaration is shared by the function and its direct call sites.
//! This does not infer output storage or replace the convention's output list.

use std::collections::BTreeMap;

use super::fspec::{ProtoParameter, RegisterOutput};
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
            let (register, ty) = value.split_once(':').ok_or("expected REGISTER:type")?;
            let register = register.trim();
            if register.is_empty()
                || !register
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_')
            {
                return Err(format!("invalid output register `{register}`"));
            }
            let ty = ty.trim();
            let datatype = match ty {
                "bool" => Datatype::Bool,
                "char" => Datatype::Char,
                _ => {
                    let (prefix, size) = ["uint", "int", "float", "unknown"]
                        .into_iter()
                        .find_map(|p| {
                            ty.strip_prefix(p)
                                .and_then(|s| s.parse::<u32>().ok())
                                .map(|s| (p, s))
                        })
                        .ok_or_else(|| format!("unknown output type `{ty}`"))?;
                    if !matches!(size, 1 | 2 | 4 | 8 | 16) && !(prefix == "float" && size == 10) {
                        return Err(format!("unsupported output type width in `{ty}`"));
                    }
                    match prefix {
                        "uint" => Datatype::Uint(size),
                        "int" => Datatype::Int(size),
                        "float" => Datatype::Float(size),
                        _ => Datatype::Unknown(size),
                    }
                }
            };
            RegisterOutput {
                register: register.into(),
                datatype,
            }
        };
        if result.insert(address, output).is_some() {
            return Err(format!("duplicate output declaration at {address:#x}"));
        }
    }
    Ok(result)
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
