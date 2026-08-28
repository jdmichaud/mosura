//! Variadic-function recovery — BEYOND GHIDRA, owed to the recompilation goal.
//!
//! A variadic callee takes the ADDRESS of the first anonymous argument: the caller-frame stack
//! slot just past its named parameters (`va_start`). Ghidra renders that address as a bare
//! caller-frame symbol (`&stack0x0000000c`), or — when its own `RulePushMulti` has factored a
//! constant out of a loop phi and left the raw stack-pointer register as a phi input — as the
//! register itself (`register0x00000020`). Neither is C that compiles, and both lose the one fact
//! a recompile needs: the function is variadic and that address is `va_start`'s value.
//!
//! Two pieces:
//!
//! 1. [`ActionVarargsRecovery`] (pipeline, after the cleanup pools): the inverse of
//!    `RulePushMulti`'s substitute for the spacebase case. Ghidra's rule refuses to push through
//!    a MULTIEQUAL whose input IS the spacebase register (ruleaction.cc:1084-1085), but the
//!    substitute phi it manufactures for `phi(SP + c, x + c)` is `phi(SP, x)` — the very input
//!    the guard forbids, one level down. The action restores `phi(PTRSUB(SP, c), x + c)`, so the
//!    stack-slot address exists again as a `PTRSUB` (ground truth `vsum`: the overflow-area
//!    walk `phi(RSP, p) + 8` becomes `p = &stack0x8; … p = p + 8`).
//!
//! 2. [`recognize`] (print time, after the prototype is known): a live `PTRSUB(SP_in, #off)`
//!    whose value is USED (not merely dereferenced) at a caller-frame offset at or past the
//!    parameter base, with no recovered stack parameter at or beyond it, marks the function
//!    variadic. Stack slots between the parameter base and `off` that the prototype did not
//!    claim become unnamed parameters (they are the named arguments the body never reads —
//!    `printf_`'s format string), so that `va_start(ap, <last named>)` computes exactly `off`.
//!    The printer then declares `va_list ap;`, renders the PTRSUB's definition as
//!    `va_start(ap, param_N);` and every use as `ap`. The per-target prelude defines `va_list`
//!    as a raw `char *` and `va_start` as the target's first-anonymous-argument address
//!    (Watcom: `(char *)&last + sizeof(last)` rounded; gcc: `__builtin_next_arg(last)`), so the
//!    C compiles to the original's `lea`.

use super::funcdata::Funcdata;
use super::op::OpId;
use super::opcode::OpCode;
use super::printc::RenderedParam;
use super::space::Address;
use super::varnode::VarnodeId;

/// The inverse of `RulePushMulti`'s spacebase substitute — see the module doc.
pub struct ActionVarargsRecovery;

impl super::action::Action for ActionVarargsRecovery {
    fn name(&self) -> &str {
        "varargsrecovery"
    }
    fn apply(&mut self, data: &mut Funcdata) -> u32 {
        let n = unpush_spacebase_phis(data);
        debug!(crate::debug::Topic::Varargs, "unpushed {n}");
        n
    }
}

/// The spacebase INPUT varnode of `v`'s function — the incoming stack pointer (`is_spacebase`,
/// set by `ActionSpacebase`, and a function input).
fn is_spacebase_input(f: &Funcdata, v: VarnodeId) -> bool {
    let vn = f.vn(v);
    vn.is_spacebase() && vn.is_input()
}

/// For every MULTIEQUAL with a spacebase-input operand whose only reader is `INT_ADD(phi, #c)`,
/// move the `+ c` back into the phi's inputs: the spacebase input becomes `PTRSUB(SP, c)`, a
/// back-edge through the add becomes `INT_ADD(phi, c)`, any other input `INT_ADD(in, c)` — each
/// placed at the end of the corresponding predecessor block. The add's readers read the phi.
fn unpush_spacebase_phis(f: &mut Funcdata) -> u32 {
    let phis: Vec<OpId> = f
        .op_ids()
        .filter(|&op| !f.op(op).is_dead() && f.op(op).code() == OpCode::Multiequal)
        .collect();
    let mut count = 0;
    for phi in phis {
        let Some(out) = f.op(phi).output else { continue };
        let inputs: Vec<VarnodeId> = (0..f.op(phi).num_inputs()).filter_map(|i| f.op(phi).input(i)).collect();
        if !inputs.iter().any(|&v| is_spacebase_input(f, v)) {
            continue;
        }
        let desc = f.vn(out).descend.clone();
        if crate::debug::on(crate::debug::Topic::Varargs) {
            let d: Vec<String> = desc.iter().map(|&o| format!("{:?}@{:#x}", f.op(o).code(), f.op(o).seqnum.pc.offset)).collect();
            debug!(crate::debug::Topic::Varargs, "phi@{:#x} spacebase input; readers [{}]", f.op(phi).seqnum.pc.offset, d.join(" "));
        }
        if desc.len() != 1 {
            continue;
        }
        let add = desc[0];
        if f.op(add).is_dead() || f.op(add).input(0) != Some(out) {
            continue;
        }
        // `INT_ADD(phi, #c)`, or the typed form `PTRADD(phi, #i, #e)` (c = i * e) RulePtrArith
        // leaves once the phi carries a pointer type.
        let c = match f.op(add).code() {
            OpCode::IntAdd => {
                let Some(cvn) = f.op(add).input(1) else { continue };
                if !f.vn(cvn).is_constant() {
                    continue;
                }
                f.vn(cvn).constant_value()
            }
            OpCode::Ptradd => {
                let (Some(i), Some(e)) = (f.op(add).input(1), f.op(add).input(2)) else { continue };
                if !f.vn(i).is_constant() || !f.vn(e).is_constant() {
                    continue;
                }
                f.vn(i).constant_value().wrapping_mul(f.vn(e).constant_value())
            }
            _ => continue,
        };
        let Some(add_out) = f.op(add).output else { continue };
        let Some(block) = f.op(phi).parent else { continue };
        let preds = f.blocks()[block.0 as usize].in_edges.clone();
        if preds.len() != inputs.len() {
            continue;
        }
        let size = f.vn(out).size;
        let seq = f.op(phi).seqnum;
        for (k, &inp) in inputs.iter().enumerate() {
            let pred = preds[k];
            let new_in = if is_spacebase_input(f, inp) {
                let cst = f.new_const(size, c);
                let op = f.new_op(OpCode::Ptrsub, seq, vec![inp, cst]);
                let o = f.new_output_unique(op, size);
                f.op_insert_end(op, pred);
                o
            } else {
                // A back-edge carrying the add's own value reads the phi (the add is retired).
                let base = if inp == add_out { out } else { inp };
                let cst = f.new_const(size, c);
                let op = f.new_op(OpCode::IntAdd, seq, vec![base, cst]);
                let o = f.new_output_unique(op, size);
                f.op_insert_end(op, pred);
                o
            };
            f.op_set_input(phi, k, new_in);
        }
        f.total_replace(add_out, out);
        f.op_destroy(add);
        count += 1;
    }
    count
}

/// What [`recognize`] found: the function is variadic.
#[derive(Clone, Debug)]
pub struct VarargsInfo {
    /// Stack offset of the first anonymous argument.
    pub start_offset: u64,
    /// The `PTRSUB(SP_in, #start_offset)` ops whose outputs are `va_start`'s value.
    pub va_start_ops: Vec<OpId>,
    /// Caller-frame slots between the parameter base and `start_offset` that the prototype did
    /// not claim — rendered as unnamed parameters, in offset order.
    pub extra_params: Vec<(Address, u32)>,
    /// `param_N` of the last named parameter (the `va_start` anchor), 1-based.
    pub last_named: u32,
}

/// Recognize the `va_start` address in a function whose prototype (`rendered`, in convention
/// order) is known. See the module doc for the rule.
pub fn recognize(f: &Funcdata, rendered: &[RenderedParam]) -> Option<VarargsInfo> {
    let stack = f.spaces.by_name("stack")?;
    let reg = f.spaces.by_name("register")?;
    // The parameter base: the start of the convention's stack-parameter window.
    let base = f.proto_model.input.as_ref()?.entry.iter().find(|e| e.space == stack)?.addressbase;
    let ptr_size = f.spaces.get(stack).addr_size;
    // Candidate PTRSUBs: SP_in + #off used as a VALUE (not only as a LOAD/STORE pointer).
    let mut by_off: std::collections::BTreeMap<u64, Vec<OpId>> = std::collections::BTreeMap::new();
    for op in f.op_ids() {
        let o = f.op(op);
        if o.is_dead() || o.code() != OpCode::Ptrsub {
            continue;
        }
        let (Some(b), Some(c), Some(out)) = (o.input(0), o.input(1), o.output) else { continue };
        if !is_spacebase_input(f, b) || f.vn(b).loc.space != reg || !f.vn(c).is_constant() {
            continue;
        }
        let off = f.spaces.get(stack).wrap_offset(f.vn(c).constant_value());
        // The caller's frame only: at or past the parameter base, inside the convention's
        // parameter window (a negative offset is a local whose address escapes, not `va_start`).
        if off < base || !f.proto_model.paramrange.in_range(Address::new(stack, off), 1) {
            continue;
        }
        let desc = &f.vn(out).descend;
        if desc.is_empty() {
            continue;
        }
        let only_deref = desc.iter().all(|&d| {
            matches!(f.op(d).code(), OpCode::Load | OpCode::Store) && f.op(d).input(1) == Some(out)
        });
        if only_deref {
            continue;
        }
        by_off.entry(off).or_default().push(op);
    }
    if crate::debug::on(crate::debug::Topic::Varargs) {
        let pr: Vec<String> = f.proto_model.paramrange.iter().map(|r| format!("{:?}:{:#x}-{:#x}", r.spc, r.first, r.last)).collect();
        debug!(crate::debug::Topic::Varargs, "base={base:#x} ptr_size={ptr_size} candidates={:?} paramrange=[{}]", by_off.keys().collect::<Vec<_>>(), pr.join(","));
    }
    let (&off, ops) = by_off.iter().next()?;
    // No recovered stack parameter may sit at or beyond the anonymous area.
    let stack_params: Vec<&RenderedParam> = rendered.iter().filter(|p| p.addr.space == stack).collect();
    if stack_params.iter().any(|p| p.addr.offset.wrapping_add(p.size as u64) > off) {
        return None;
    }
    // Tile the window [base, off) with the recovered stack parameters plus unnamed fillers.
    let mut extra: Vec<(Address, u32)> = Vec::new();
    let mut cursor = base;
    if off.wrapping_sub(base) > 64 * ptr_size as u64 {
        return None; // not a parameter window any compiler would declare
    }
    while cursor < off {
        if let Some(p) = stack_params.iter().find(|p| p.addr.offset == cursor) {
            cursor = cursor.wrapping_add(p.size.max(ptr_size) as u64);
            // a recovered parameter narrower than a slot still occupies the whole slot
            cursor = cursor.wrapping_add(ptr_size as u64 - 1) & !(ptr_size as u64 - 1);
        } else {
            extra.push((Address::new(stack, cursor), ptr_size));
            cursor = cursor.wrapping_add(ptr_size as u64);
        }
    }
    if cursor != off {
        return None; // the parameters do not tile up to the anonymous area
    }
    // The last named parameter: the highest stack slot below `off` (recovered or filler), else
    // the last register parameter. Watcom's `va_start` needs a stack anchor; gcc's
    // `__builtin_next_arg` accepts any — the prelude decides, the anchor is the same.
    let last_named = if !extra.is_empty() || !stack_params.is_empty() {
        // count = all rendered params + fillers; the last in offset order is the anchor
        (rendered.len() + extra.len()) as u32
    } else {
        rendered.len() as u32
    };
    if last_named == 0 {
        return None;
    }
    Some(VarargsInfo { start_offset: off, va_start_ops: ops.clone(), extra_params: extra, last_named })
}
