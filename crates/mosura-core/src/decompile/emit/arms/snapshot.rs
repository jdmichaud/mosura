//! Entry snapshots — an input-flagged narrow RAM value consumed as a call argument renders as a
//! declared temp initialized from the global at body top, every use reading the temp; the
//! original either snapshots the global into a register at entry (one narrow load) or re-reads it
//! at each use, and the witness (`recovered.snapshot.sites`, from
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
        let stack = f.spaces.by_name("stack");
        // globals this function WRITES directly (a live COPY into the ram location): a value read,
        // masked and written back is not a snapshot — the original re-reads it at the write
        // (measured: FUN_0002b184 lost EXACT to a snapshot of its `|= 2` flag byte, round e3)
        // the global's address for a written varnode: the ram location itself, or — when the
        // pipeline restructured the store into an explicit unique the naming machinery renders
        // AS the global — the `high_ram_off` mapping (rounds e4/e5: the `|= 2` write-back of
        // FUN_0002b184 and the `g1 = g2` copy of FUN_00014214 both live in such uniques)
        let written: std::collections::HashSet<u64> = (0..f.num_varnodes() as u32)
            .map(VarnodeId)
            .filter(|&w| {
                let wn = f.vn(w);
                wn.def.is_some_and(|d| {
                    // a REAL write: not heritage's return-guard COPY of a persistent global
                    // (`markReturnCopy`, every global at every RETURN) — round e4 counted
                    // those and un-snapshotted the whole 0x39554 family
                    f.op(d).code() == OpCode::Copy && !f.op(d).is_dead() && !f.op(d).is_return_copy()
                })
            })
            .filter_map(|w| {
                let wn = f.vn(w);
                if Some(wn.loc.space) == ram {
                    Some(wn.loc.offset)
                } else {
                    pr.high_ram_off.get(&pr.high_of[w.0 as usize]).copied()
                }
            })
            .collect();
        for i in 0..f.num_varnodes() as u32 {
            let v = VarnodeId(i);
            let vn = f.vn(v);
            if !vn.is_input()
                || Some(vn.loc.space) != ram
                || vn.size == 0
                || vn.size >= f.size_of_int()
                || written.contains(&vn.loc.offset)
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
            // the probe family's shape: every use is a call argument — or, since round e3, any
            // READ of the value (an index, an arithmetic operand: the subject's 0x39554 family indexes a
            // table by the byte global and then passes it to a call, and the original snapshots it
            // once into AL for both). A STORE of the value stays outside the shape (measured:
            // FUN_00011a50's store use perturbs allocation when materialized).
            let all_reads = !live.is_empty()
                && live.iter().all(|&u| {
                    let o = f.op(u);
                    match o.code() {
                        OpCode::Call | OpCode::Callind => o.inrefs.iter().skip(1).any(|&a| a == v),
                        OpCode::Store => false,
                        // a COPY into another global or a frame slot is a store too (measured:
                        // FUN_00014214's `xRam00080004 = xRam0008f046`, round e3) — by its ram
                        // or stack location, or by the unique's name mapping
                        _ => !o.output.is_some_and(|out| {
                            let os = f.vn(out).loc.space;
                            Some(os) == ram
                                || Some(os) == stack
                                || pr.high_ram_off.contains_key(&pr.high_of[out.0 as usize])
                                || pr.high_stack_off.contains_key(&pr.high_of[out.0 as usize])
                        }),
                    }
                });
            if !all_reads {
                continue;
            }
            pr.report.snapshot.candidates.push((v, vn.loc.offset, vn.size));
            if let Some(&w) = pr.recovered.snapshot.sites.get(&v) {
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

/// The snapshot's candidates the report pass collects (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Report {
    /// Every input-flagged narrow RAM value consumed as a call argument, as
    /// `(value, global address, size)` — the entry-snapshot candidates. The original either
    /// snapshots the global into a register at entry (ONE narrow load from that absolute
    /// address — `MOV AL,[0x8032c]` before the branch, probe-validated EXACT as
    /// `uint1 uVarN = xRamX;` at body top) or references memory at each use. Rendering the
    /// snapshot is value-identical by SSA construction: the uses read the INPUT version of
    /// the global, which is definitionally its entry value.
    pub candidates: Vec<(VarnodeId, u64, u32)>,
}

/// The snapshot's witnessed decisions the recovered pass renders (review F1: the arm owns its evidence vocabulary; the printer holds the registry opaquely).
#[derive(Debug, Default, Clone)]
pub struct Sites {
    /// Input-flagged narrow RAM values rendered as an entry snapshot — a declared temp
    /// initialized from the global at body top, uses reading the temp. The value is the
    /// DECLARED width: the value's own size (bare narrow load in the original) or int width
    /// (the original pre-zeroes the container — the widening idiom on a global).
    pub sites: std::collections::HashMap<VarnodeId, u32>,
}
