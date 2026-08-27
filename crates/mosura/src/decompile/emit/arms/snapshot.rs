//! Entry snapshots — an input-flagged narrow RAM value consumed as a call argument renders as a
//! declared temp initialized from the global at body top, every use reading the temp; the
//! original either snapshots the global into a register at entry (one narrow load) or re-reads it
//! at each use, and the witness (`recovered.snapshot_sites`, from
//! `buildconfig::entry_snapshots_from_evidence` over this arm's `snapshot_candidates` report)
//! settles it per value, with the temp's width. Value-identical by SSA construction: the uses
//! read the INPUT version of the value. A target-informed emit choice, NOT Ghidra: the reference
//! decompiler reads the global at each use.
//!
//! Moved verbatim out of printc.rs (review R2b, commit 8): the census that sat in
//! `print_c_inner`'s evidence section (`recognize`: records the candidates, declares the witnessed
//! temps), the temp-name substitution that sat at the head of `render_var` (`render`) and the
//! initialized declarations printed after the plain locals (`init_decls`, the port's loop reads
//! the arm's list through the seam); the only textual changes are `p.`/`self.` → `pr.`, the
//! temps' path (the arm's own State — `snapshot_names`/`snapshot_decls` were PrintC fields only
//! this rule read) and the answer form (`return (..)` → `return Some((..))`). Reclassified from
//! mark to rule in the R2b split: it synthesizes a declaration AND an assignment.
//!
//! The arm answers two seams: `ValueSite::VarEntry` (a value about to render — the temp's name)
//! and `arms::init_decls` (the declarations with initializers).
use crate::decompile::emit::EmitChoices;
use crate::decompile::funcdata::Funcdata;
use crate::decompile::opcode::OpCode;
use crate::decompile::printc::PrintC;
use crate::decompile::types::Datatype;
use crate::decompile::varnode::VarnodeId;
use std::collections::HashMap;

/// The arm's state: value → temp name (uses render the name), plus the declaration list
/// `(name, type, initializer)` printed with the locals.
#[derive(Debug, Default)]
pub(crate) struct State {
    pub(crate) names: HashMap<VarnodeId, String>,
    pub(crate) decls: Vec<(String, Datatype, String)>,
}

impl State {
    pub(crate) fn new(_choices: &EmitChoices) -> Self {
        State::default()
    }
}

/// The census (survey evidence + the witnessed temps), called from `print_c_inner`'s evidence
/// section where it sat. The global expression is rendered BEFORE the substitution registers, so
/// the initializer names the global itself.
pub(crate) fn recognize(pr: &mut PrintC<'_>, f: &Funcdata) {
        let ram = f.spaces.by_name("ram");
        for i in 0..f.num_varnodes() as u32 {
            let v = VarnodeId(i);
            let vn = f.vn(v);
            if !vn.is_input()
                || Some(vn.loc.space) != ram
                || vn.size == 0
                || vn.size >= f.size_of_int()
            {
                continue;
            }
            // the probe family's shape: EVERY use is a call argument. A value also stored or
            // computed with (measured: FUN_00011a50's store use) perturbs allocation when
            // materialized — outside the validated shape, so not a candidate.
            let live: Vec<_> = vn
                .descend
                .iter()
                .copied()
                .filter(|&u| !f.op(u).is_dead() && !f.op(u).is_marker())
                .collect();
            let all_call_args = !live.is_empty()
                && live.iter().all(|&u| {
                    matches!(f.op(u).code(), OpCode::Call | OpCode::Callind)
                        && f.op(u).inrefs.iter().skip(1).any(|&a| a == v)
                });
            if !all_call_args {
                continue;
            }
            pr.report.snapshot_candidates.push((v, vn.loc.offset, vn.size));
            if let Some(&w) = pr.recovered.snapshot_sites.get(&v) {
                let gexpr = pr.render_var(v).0;
                pr.var_counter += 1;
                let n = format!("uVar{}", pr.var_counter);
                pr.arms.snapshot.decls.push((n.clone(), Datatype::Uint(w.max(vn.size)), gexpr));
                pr.arms.snapshot.names.insert(v, n);
            }
        }
}

/// The arm's answer at `ValueSite::VarEntry`: the temp's name for a snapshotted value.
pub(crate) fn render(pr: &mut PrintC<'_>, v: VarnodeId) -> Option<(String, u8)> {
    if let Some(n) = pr.arms.snapshot.names.get(&v) {
        return Some((n.clone(), 16));
    }
    None
}

/// The declarations with initializers the port prints after the plain locals.
pub(crate) fn init_decls<'p>(pr: &'p PrintC<'_>) -> &'p [(String, Datatype, String)] {
    &pr.arms.snapshot.decls
}
