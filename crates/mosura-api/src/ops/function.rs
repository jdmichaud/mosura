//! The function operations: `function.decompile` — one function of a program, decompiled through
//! the core's bridge (`analysis::decompiler::decompile_function`, the multi-function context the
//! survey and the analyzers use) into a pure set of the decompile stage: `c` and `raw` text, the
//! recovered `prototype`, the `jumptables` and the `calls`. `format` picks what the call answers.

use crate::error::{Error, Result};
use crate::fingerprint::Stage;
use crate::key::{key, no_annotations, Key};
use crate::options::{keys, parse_hex, Options};
use crate::ops::program::program_of;
use crate::ops::schemas::{CALLS, JUMPTABLES, PROTOTYPE};
use crate::ops::{Cache, Op, Progress, Tier};
use crate::render::text_table;
use crate::session::{Provenance, Session, SetKind};
use crate::set::TableSet;
use crate::table::builder::TableBuilder;
use crate::table::Table;
use mosura_core::analysis::program::Program;
use mosura_core::decompile::funcdata::Funcdata;
use mosura_core::decompile::opcode::OpCode;
use mosura_core::decompile::printc::print_c_with;
use mosura_core::decompile::space::Address;

/// The marker in an op's `params` that admits every `emit.<axis>` key (generated at run time from
/// the core's axes, so they cannot be listed statically).
pub const EMIT_KEYS: &str = "emit.*";

pub static DECOMPILE: Op = Op {
    name: "function.decompile",
    doc: "decompile one function (entry) of a program: format=c (default) | raw | table:<prototype|jumptables|calls>",
    since: "0.1",
    tier: Tier::Product,
    params: &["program", "entry", "format", keys::KNOBS_OFF, keys::DECOMPILE_GLOBAL_SCOPE, keys::DECOMPILE_PROTO_SCOPE, EMIT_KEYS],
    result: "text",
    cache: Cache::Pure { stage: Stage::Decompile, set: SetKind::Function },
    run: decompile,
};

/// The key of a function set: the program key ‖ the entry (little-endian), under the Result tag.
pub fn function_key(op: &str, program: &Key, entry: u64, o: &Options) -> Key {
    key(Stage::Decompile, op, &[&program.0, &entry.to_le_bytes()], &o.tag(), &no_annotations())
}

/// The function's entry from `entry` — an address (the registry types the key Hex; a front-end
/// resolves names through the functions table before calling).
pub fn entry_of(p: &Program, o: &Options) -> Result<u64> {
    let v = o.get("entry")?;
    if v.is_empty() {
        return Err(Error::InvalidArg("`entry` is required (an address)".into()));
    }
    let entry = parse_hex(v).ok_or_else(|| Error::InvalidArg(format!("`entry` is not an address: {v}")))?;
    if p.function_manager.function_at(Address::new(p.default_space, entry)).is_none() {
        return Err(Error::NotFound(format!("no function at {entry:#x}")));
    }
    Ok(entry)
}

/// The three fact tables of a decompiled function.
pub fn fact_tables(f: &Funcdata, set: &mut TableSet) {
    let proto = mosura_core::analysis::interface::prototype_of(f);
    let model = proto.model.as_ref().map(|m| m.name.as_str()).unwrap_or("");
    let mut b = TableBuilder::new(&PROTOTYPE);
    for (i, s) in proto.params.iter().enumerate() {
        b.row().u32(i as u32).str("param").u32(s.addr.space.0).u64(s.addr.offset).u32(s.size).str(model);
    }
    if let Some(out) = &proto.output {
        b.row().u32(0).str("output").u32(out.addr.space.0).u64(out.addr.offset).u32(out.size).str(model);
    }
    set.insert("prototype", b.finish(false));
    let mut b = TableBuilder::new(&JUMPTABLES);
    for jt in &f.jumptables {
        for (i, t) in jt.targets.iter().enumerate() {
            b.row().u64(jt.op_addr).u32(i as u32).u64(*t).i64(jt.labels.get(i).copied().unwrap_or(0)).bool(jt.default == Some(*t));
        }
        if let Some(d) = jt.default {
            if !jt.targets.contains(&d) {
                b.row().u64(jt.op_addr).u32(jt.targets.len() as u32).u64(d).i64(0).bool(true);
            }
        }
    }
    set.insert("jumptables", b.finish(false));
    let mut calls: Vec<(u64, u64, bool)> = Vec::new();
    for id in f.op_ids() {
        let op = f.op(id);
        if op.is_dead() || !matches!(op.code(), OpCode::Call | OpCode::Callind) {
            continue;
        }
        let pc = op.seqnum.pc.offset;
        let target = op.input(0).map(|v| f.vn(v)).filter(|vn| !vn.is_constant() && f.spaces.get(vn.loc.space).name == "ram").map(|vn| vn.loc.offset);
        calls.push((pc, target.unwrap_or(0), op.code() == OpCode::Call && target.is_some()));
    }
    calls.sort_unstable();
    let mut b = TableBuilder::new(&CALLS);
    for (pc, target, has) in calls {
        b.row().u64(pc).u64(target).bool(has);
    }
    set.insert("calls", b.finish(true));
}

/// Decompile `entry` of `p` into a fresh set: `c`, `raw` and the fact tables.
pub fn decompile_set(p: &Program, entry: u64, o: &Options) -> Result<TableSet> {
    let f = mosura_core::analysis::decompiler::decompile_function(p, Address::new(p.default_space, entry)).ok_or_else(|| Error::Internal(format!("decompile of {entry:#x} produced no result (the pipeline declined or panicked)")))?;
    let choices = o.emit_choices()?;
    let mut set = TableSet::default();
    set.insert("c", text_table(&print_c_with(&f, &choices)));
    set.insert("raw", text_table(&f.print_raw()));
    fact_tables(&f, &mut set);
    Ok(set)
}

/// What `format` asks for, out of a set.
pub fn pick(set: &TableSet, format: &str) -> Result<Table> {
    match format {
        "" | "c" => set.table("c").cloned(),
        "raw" => set.table("raw").cloned(),
        t if t.starts_with("table:") => set.table(&t["table:".len()..]).cloned(),
        other => Err(Error::InvalidArg(format!("`format` is c, raw or table:<name>, not `{other}`"))),
    }
}

fn decompile(s: &mut Session, o: &Options, prog: &mut dyn Progress) -> Result<Table> {
    let (pk, p) = program_of(s, o)?;
    let entry = entry_of(&p, o)?;
    let format = o.get("format")?.to_string();
    let k = function_key(DECOMPILE.name, &pk, entry, o);
    if s.has_set(SetKind::Function, &k) {
        return pick(&s.read_set(SetKind::Function, &k)?, &format);
    }
    if !prog.report(DECOMPILE.name, 0, 1) {
        return Err(Error::Cancelled);
    }
    let set = decompile_set(&p, entry, o)?;
    let mut inputs = Vec::with_capacity(2);
    inputs.push(pk.0);
    let mut e = [0u8; 32];
    e[..8].copy_from_slice(&entry.to_le_bytes());
    inputs.push(e);
    s.write_set(SetKind::Function, &k, &set, &Provenance { stage: Stage::Decompile, op: DECOMPILE.name, inputs: &inputs, tag: &o.tag(), label: &format!("{entry:#x}") })?;
    pick(&set, &format)
}

