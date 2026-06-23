//! Type inference — a first port of Ghidra's `ActionInferTypes` (`coreaction.cc`). Each
//! varnode gets a *local* type from the ops that produce and consume it (a float op ⇒
//! float, a comparison ⇒ bool, a memory address ⇒ pointer, integer arithmetic ⇒ int); the
//! local types of one variable (a [`merge`] HighVariable) are met into the variable's type.
//!
//! This is the structural core; the full action also follows pointer pointees, resolves
//! signedness from sign-sensitive ops more carefully, and types globals.

use std::collections::HashMap;

use super::funcdata::Funcdata;
use super::merge::merge;
use super::opcode::OpCode;
use super::types::{meet, Datatype};
use super::varnode::VarnodeId;

/// Ops whose output is a float.
fn produces_float(c: OpCode) -> bool {
    use OpCode::*;
    matches!(
        c,
        FloatAdd | FloatSub | FloatMult | FloatDiv | FloatNeg | FloatAbs | FloatSqrt
            | FloatCeil | FloatFloor | FloatRound | FloatInt2float | FloatFloat2float
    )
}

/// Ops whose data inputs are floats.
fn consumes_float(c: OpCode) -> bool {
    use OpCode::*;
    produces_float(c)
        || matches!(c, FloatEqual | FloatNotequal | FloatLess | FloatLessequal | FloatNan | FloatTrunc)
}

/// Ops that produce a boolean.
fn produces_bool(c: OpCode) -> bool {
    use OpCode::*;
    matches!(
        c,
        IntEqual | IntNotequal | IntLess | IntLessequal | IntSless | IntSlessequal
            | FloatEqual | FloatNotequal | FloatLess | FloatLessequal | FloatNan
            | BoolNegate | BoolAnd | BoolOr | BoolXor
    )
}

/// The type implied for `v` by its defining op and its uses.
fn local_type(f: &Funcdata, v: VarnodeId) -> Datatype {
    let vn = f.vn(v);
    let size = vn.size;
    let mut t = Datatype::Unknown(size);
    let mut signal = |s: Datatype| t = meet(&t, &s);

    if let Some(def) = vn.def {
        let c = f.op(def).code();
        if produces_float(c) {
            signal(Datatype::Float(size));
        } else if produces_bool(c) {
            signal(Datatype::Bool);
        }
    }
    for &u in &vn.descend {
        let o = f.op(u);
        for (slot, &iv) in o.inrefs.iter().enumerate() {
            if iv != v {
                continue;
            }
            use OpCode::*;
            match o.code() {
                Load | Store if slot == 1 => {
                    signal(Datatype::Pointer(size, Box::new(Datatype::Unknown(1))))
                }
                c if consumes_float(c) => signal(Datatype::Float(size)),
                IntSless | IntSlessequal | IntSright | IntSdiv | IntSrem => signal(Datatype::Int(size)),
                IntLess | IntLessequal | IntRight | IntDiv | IntRem => signal(Datatype::Uint(size)),
                IntAdd | IntSub | IntMult | IntAnd | IntOr | IntXor | IntLeft => {
                    signal(Datatype::Int(size))
                }
                _ => {}
            }
        }
    }
    t
}

/// Infer a type for every non-constant varnode (its variable's met type).
pub fn infer(f: &Funcdata) -> HashMap<VarnodeId, Datatype> {
    let mut h = merge(f);
    let locals: Vec<(VarnodeId, Datatype)> = (0..f.num_varnodes() as u32)
        .map(VarnodeId)
        .filter(|&v| !f.vn(v).is_constant())
        .map(|v| (v, local_type(f, v)))
        .collect();

    let mut hv: HashMap<u32, Datatype> = HashMap::new();
    for (v, lt) in &locals {
        let id = h.high(*v);
        hv.entry(id).and_modify(|t| *t = meet(t, lt)).or_insert_with(|| lt.clone());
    }

    locals
        .into_iter()
        .map(|(v, lt)| {
            let t = hv.get(&h.high(v)).cloned().unwrap_or(lt);
            (v, t)
        })
        .collect()
}
