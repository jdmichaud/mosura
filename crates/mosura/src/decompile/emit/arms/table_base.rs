//! `table-base` — a sum of a value and a constant DATA ADDRESS (`uRam * 0x24 + 0x8f070`, the
//! address of a table element computed as a value: a call argument, a stored pointer) prints
//! through an extern array symbol, `(int4)(aRam0008f070 + uRam * 0x24)`, where the ORIGINAL
//! materializes the base as an immediate (`MOV EDX,0x8f070 ; .. ; ADD EDX,EAX`, or `ADD
//! EAX,0x8f070 ; LEA EDX,[EAX + 0x8]` for a field of the element). This compiler folds a
//! literal address into one `LEA r,[idx + 0x8f070]` and keeps a relocatable symbol as its own
//! operand — the original's tables were symbols. WAR2 FUN_00013bfc and FUN_00013a9c go EXACT
//! with the symbol; 126 non-exact functions carry a base-address immediate the recompile lacks
//! (round f0). Value-identical: the symbol resolves to the base (the survey declares
//! `extern char aRam<base>[]` and the relink binds it there), so the sum names the same address;
//! the constant's excess over the base prints as a trailing field offset. The witness
//! (`recovered.table_base.sites`, from `buildconfig::table_bases_from_evidence` over this arm's
//! candidates): a `MOV r32,imm` / `ADD r32,imm` in the original whose immediate is the constant
//! or lies within an element below it — the base. A target-informed emit choice, NOT Ghidra.
//!
//! The arm answers at `ValueSite::Sum` after `sum-order`; `None` = the port's own rendering.
use crate::decompile::op::OpId;
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::PrintC;

/// The arm's answer at `ValueSite::Sum`: `op` the INT_ADD.
pub(crate) fn render(pr: &mut PrintC<'_>, op: OpId) -> Option<(String, u8)> {
    let o = pr.f.op(op);
    if o.code() != OpCode::IntAdd || o.num_inputs() != 2 {
        return None;
    }
    let (a, b) = (o.input(0)?, o.input(1)?);
    let (x, k) = match (pr.f.vn(a).is_constant(), pr.f.vn(b).is_constant()) {
        (false, true) => (a, b),
        (true, false) => (b, a),
        _ => return None,
    };
    let kn = pr.f.vn(k);
    if kn.size != pr.f.size_of_int() || kn.constant_value() < 0x10000 {
        return None;
    }
    // an INLINE sum only (an argument, a deref's address): a sum assigned to a declared local
    // takes the local's register and the symbol form costs a `MOV r,offset` the original's
    // in-place `ADD r,offset` does not have (WAR2 FUN_00016764, SAME_SHAPE → MISMATCH, round f4)
    if o.output.is_some_and(|out| pr.is_explicit(out)) {
        return None;
    }
    let kv = kn.constant_value();
    let pc = o.seqnum.pc.offset;
    pr.report.table_base.candidates.push((pc, kv));
    let &base = pr.recovered.table_base.sites.get(&pc)?;
    if base > kv {
        return None;
    }
    let off = kv - base;
    let xs = pr.operand(x, 12, true);
    let ty = o.output.map(|out| pr.type_of(out).name()).unwrap_or_else(|| "int4".to_string());
    let sum = if off == 0 { format!("aRam{base:08x} + {xs}") } else { format!("aRam{base:08x} + {xs} + 0x{off:x}") };
    Some((format!("({ty})({sum})"), 14))
}

/// The table-base's candidates the report pass collects (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Report {
    /// Every sum of a value and an address-range constant (`table-base`), as `(sum address,
    /// constant)`: the original folds the constant into an addressing mode or materializes a
    /// base immediate.
    pub candidates: Vec<(u64, u64)>,
}

/// The table-base's witnessed decisions the recovered pass renders (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Sites {
    /// Sum addresses whose constant prints through the symbol of the witnessed base
    /// (`table-base`, `table_base` candidates evidence, `buildconfig::table_bases_from_evidence`):
    /// sum address → base address.
    pub sites: std::collections::HashMap<u64, u64>,
}
