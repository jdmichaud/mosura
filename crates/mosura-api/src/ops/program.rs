//! The program operations: `program.load` / `program.analyze` (pure sets of the analysis stage),
//! `program.tables` (served from the set; the virtual `snapshot`), `program.read` and
//! `program.disassemble` (transient views of a thawed program). The helpers here resolve WHAT an
//! op runs on (`input`, `program`) and hold the one thawed program the session caches.

use std::sync::Arc;

use crate::error::{Error, Result};
use crate::fingerprint::Stage;
use crate::key::{key, no_annotations, Key};
use crate::options::{keys, parse_hex, Options};
use crate::ops::schemas::{BYTES, INSTRUCTIONS, PROGRAM_SUMMARY, TABLES as TABLES_SCHEMA};
use crate::ops::{Cache, Op, Progress, Tier};
use crate::program::{freeze, snapshot_table, thaw};
use crate::session::{Provenance, Session, SetKind};
use crate::set::TableSet;
use crate::table::builder::TableBuilder;
use crate::table::Table;
use mosura_core::analysis::program::{CodeUnit, Program};
use mosura_core::analysis::{self, Loader};
use mosura_core::decompile::space::Address;

const LOAD_PARAMS: &[&str] = &["input", keys::LOAD_LOADER, keys::LOAD_LANGUAGE, keys::LOAD_BASE, keys::LOAD_CSPEC_X86_32, keys::ANALYSIS_DISABLE, keys::ANALYSIS_SWITCH_TABLE_REFS, keys::KNOBS_OFF];

pub static LOAD: Op = Op { name: "program.load", doc: "load the input (no analysis) into a program set", since: "0.1", tier: Tier::Product, params: LOAD_PARAMS, result: "program_summary", cache: Cache::Pure { stage: Stage::Analysis, set: SetKind::Program }, run: |s, o, p| load_or_analyze(s, o, p, false) };
pub static ANALYZE: Op = Op { name: "program.analyze", doc: "load and auto-analyze the input into a program set", since: "0.1", tier: Tier::Product, params: LOAD_PARAMS, result: "program_summary", cache: Cache::Pure { stage: Stage::Analysis, set: SetKind::Program }, run: |s, o, p| load_or_analyze(s, o, p, true) };
pub static TABLES: Op = Op { name: "program.tables", doc: "a table of the program set by name (`snapshot` = the analysis snapshot text); the list of tables when no name is given", since: "0.1", tier: Tier::Product, params: &["program", "table"], result: "tables", cache: Cache::Transient, run: tables };
pub static READ: Op = Op { name: "program.read", doc: "the loaded bytes at addr (len bytes)", since: "0.1", tier: Tier::Product, params: &["program", "addr", "len", keys::KNOBS_OFF, keys::DECOMPILE_GLOBAL_SCOPE, keys::DECOMPILE_PROTO_SCOPE], result: "bytes", cache: Cache::Transient, run: read };
pub static DISASSEMBLE: Op = Op { name: "program.disassemble", doc: "the listing's code units over addr+len or a function's body (entry), with their text", since: "0.1", tier: Tier::Product, params: &["program", "addr", "len", "entry", keys::KNOBS_OFF, keys::DECOMPILE_GLOBAL_SCOPE, keys::DECOMPILE_PROTO_SCOPE], result: "instructions", cache: Cache::Transient, run: disassemble };

// ── what an op runs on ──

/// The input named by `input`, else the session's only one.
pub fn input_of(s: &Session, o: &Options) -> Result<[u8; 32]> {
    let name = o.get("input")?;
    if name.is_empty() { s.only_input() } else { s.resolve_input(name) }
}

/// The loader `load.loader` names (with `load.language`/`load.base` for `raw`).
pub fn loader_of<'a>(o: &Options, language: &'a str, base: &str) -> Result<Loader<'a>> {
    Ok(match o.get(keys::LOAD_LOADER)? {
        "default" => Loader::Default,
        "native" => Loader::Native,
        "le" => Loader::Le,
        "x32" => Loader::X32,
        "com" => Loader::Com,
        "xml" => Loader::Xml,
        "raw" => {
            if language.is_empty() {
                return Err(Error::InvalidArg("load.loader=raw needs load.language".into()));
            }
            let base = if base.is_empty() { 0 } else { parse_hex(base).ok_or_else(|| Error::InvalidArg(format!("load.base `{base}` is not an address")))? };
            Loader::Raw { language, base }
        }
        other => return Err(Error::InvalidArg(format!("unknown loader `{other}`"))),
    })
}

fn load_error(e: mosura_core::analysis::loader::LoadError) -> Error {
    Error::Format(format!("load: {e}"))
}

/// The key of the program set an op names: `program` (a hex key), else the session's last program,
/// else the only program set in the session.
pub fn program_key(s: &Session, o: &Options) -> Result<Key> {
    let name = o.get("program")?;
    if !name.is_empty() {
        return Key::from_hex(name).ok_or_else(|| Error::InvalidArg(format!("`program` is not a 64-hex key: {name}")));
    }
    if let Some((k, _)) = &s.last_program {
        return Ok(*k);
    }
    let keys = s.set_keys(SetKind::Program)?;
    match keys.len() {
        1 => Ok(keys[0]),
        0 => Err(Error::NotFound("the session has no program; run program.analyze (or program.load) first".into())),
        n => Err(Error::InvalidArg(format!("the session has {n} programs; name one with `program`"))),
    }
}

/// The program an op runs on, thawed once per session and reused. The knobs and the decompile
/// settings come from the options (they are part of every function key, not of the tables).
pub fn program_of(s: &mut Session, o: &Options) -> Result<(Key, Arc<Program>)> {
    let k = program_key(s, o)?;
    if let Some((lk, p)) = &s.last_program {
        if *lk == k {
            return Ok((k, Arc::clone(p)));
        }
    }
    let set = s.read_set(SetKind::Program, &k)?;
    let p = Arc::new(thaw(&set, o.knobs()?, &o.decompile_settings()?)?);
    s.last_program = Some((k, Arc::clone(&p)));
    Ok((k, p))
}

// ── program.load / program.analyze ──

pub fn summary_of_set(k: &Key, set: &TableSet) -> Result<Table> {
    let pt = set.table("program")?;
    let listing = set.table("listing")?;
    let mut insns = 0u64;
    for r in 0..listing.rows() {
        if listing.u64(r, 3)? == 0 {
            insns += 1;
        }
    }
    let mut b = TableBuilder::new(&PROGRAM_SUMMARY);
    b.row().str(&k.hex()).str(pt.str(0, 0)?).str(pt.str(0, 1)?).str(pt.str(0, 2)?).str(pt.str(0, 3)?).u64(pt.u64(0, 8)?).u32(pt.u64(0, 10)? as u32).u64(set.table("blocks")?.rows()).u64(set.table("functions")?.rows()).u64(set.table("symbols")?.rows()).u64(set.table("references")?.rows()).u64(insns);
    Ok(b.finish(false))
}

fn load_or_analyze(s: &mut Session, o: &Options, p: &mut dyn Progress, analyze: bool) -> Result<Table> {
    let op = if analyze { &ANALYZE } else { &LOAD };
    let digest = input_of(s, o)?;
    let k = key(Stage::Analysis, op.name, &[&digest], &o.tag(), &no_annotations());
    if s.has_set(SetKind::Program, &k) {
        let set = s.read_set(SetKind::Program, &k)?;
        if s.last_program.as_ref().is_none_or(|(lk, _)| *lk != k) {
            // leave the cached program alone: the next op on this key thaws it on demand
            s.last_program = None;
        }
        return summary_of_set(&k, &set);
    }
    if !p.report(op.name, 0, 2) {
        return Err(Error::Cancelled);
    }
    let data = s.input_bytes(&digest)?;
    let filename = s.input_filename(&digest).map(str::to_string);
    let knobs = o.knobs()?;
    let (language, base) = (o.get(keys::LOAD_LANGUAGE)?.to_string(), o.get(keys::LOAD_BASE)?.to_string());
    let which = loader_of(o, &language, &base)?;
    let mut program = analysis::load_bytes_with(&data, filename.as_deref(), which, &knobs).map_err(load_error)?;
    if analyze {
        if !p.report("analyze", 1, 2) {
            return Err(Error::Cancelled);
        }
        analysis::analyze(&mut program);
    }
    // the decompile-time settings (global scope, proto scope) are OPTIONS applied at thaw, not
    // program state: the set carries none
    let set = freeze(&program, &o.tag());
    s.write_set(SetKind::Program, &k, &set, &Provenance { stage: Stage::Analysis, op: op.name, inputs: &[digest], tag: &o.tag(), label: filename.as_deref().unwrap_or("") })?;
    s.last_program = Some((k, Arc::new(program)));
    summary_of_set(&k, &set)
}

// ── program.tables ──

fn tables(s: &mut Session, o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    let k = program_key(s, o)?;
    let set = s.read_set(SetKind::Program, &k)?;
    let name = o.get("table")?;
    if name.is_empty() {
        let mut b = TableBuilder::new(&TABLES_SCHEMA);
        for (n, t) in &set.tables {
            b.row().str(n).u64(t.rows()).str(&crate::fingerprint::hex(&t.digest()));
        }
        b.row().str("snapshot").u64(1).str("(virtual: the analysis snapshot text)");
        return Ok(b.finish(false));
    }
    if name == "snapshot" {
        return snapshot_table(&set);
    }
    set.table(name).cloned()
}

// ── program.read / program.disassemble ──

fn required_hex(o: &Options, k: &str) -> Result<u64> {
    let v = o.get(k)?;
    if v.is_empty() {
        return Err(Error::InvalidArg(format!("`{k}` is required")));
    }
    parse_hex(v).ok_or_else(|| Error::InvalidArg(format!("`{k}` is not a number: {v}")))
}

/// `len` is a U64 option: decimal, as the registry validates it.
fn required_len(o: &Options) -> Result<u64> {
    let v = o.get("len")?;
    if v.is_empty() {
        return Err(Error::InvalidArg("`len` is required".into()));
    }
    v.trim().parse::<u64>().map_err(|_| Error::InvalidArg(format!("`len` is not a decimal count: {v}")))
}

fn read(s: &mut Session, o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    let (_, p) = program_of(s, o)?;
    let addr = required_hex(o, "addr")?;
    let len = required_len(o)? as usize;
    let a = Address::new(p.default_space, addr);
    if !p.memory.contains(a) {
        return Err(Error::NotFound(format!("address {addr:#x} is not loaded")));
    }
    let bytes = p.memory.read_window(a, len);
    let mut b = TableBuilder::new(&BYTES);
    b.row().u64(addr).bytes(&bytes);
    Ok(b.finish(false))
}

fn flow_text(k: mosura_core::analysis::flowtype::FlowKind) -> String {
    use mosura_core::analysis::flowtype::FlowKind as F;
    match k {
        F::FallThrough => "FALL_THROUGH".into(),
        F::Invalid => "INVALID".into(),
        F::Terminator => "TERMINATOR".into(),
        F::ConditionalTerminator => "CONDITIONAL_TERMINATOR".into(),
        F::JumpTerminator => "JUMP_TERMINATOR".into(),
        F::Ref(r) => r.name().to_string(),
    }
}

fn disassemble(s: &mut Session, o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    let (_, p) = program_of(s, o)?;
    // the range: a function's body ranges, or addr+len
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    if !o.get("entry")?.is_empty() {
        let entry = required_hex(o, "entry")?;
        let f = p.function_manager.function_at(Address::new(p.default_space, entry)).ok_or_else(|| Error::NotFound(format!("no function at {entry:#x}")))?;
        for r in f.body().ranges() {
            ranges.push((r.min, r.max));
        }
        if ranges.is_empty() {
            ranges.push((entry, entry));
        }
    } else {
        let addr = required_hex(o, "addr")?;
        let len = required_len(o)?;
        ranges.push((addr, addr.saturating_add(len.saturating_sub(1))));
    }
    let mut units: Vec<(u64, &CodeUnit)> = p.listing.code_units().filter(|(a, _)| a.space == p.default_space && ranges.iter().any(|(lo, hi)| a.offset >= *lo && a.offset <= *hi)).map(|(a, u)| (a.offset, u)).collect();
    units.sort_by_key(|(a, _)| *a);
    let mut b = TableBuilder::new(&INSTRUCTIONS);
    for (addr, u) in units {
        let len = u.length();
        let bytes = p.memory.read_window(Address::new(p.default_space, addr), len as usize);
        match u {
            CodeUnit::Instruction { flow, .. } => {
                let (mn, body) = match mosura_core::sleigh::disassemble(&p.language_id, &bytes, addr) {
                    Ok(v) if !v.is_empty() => (v[0].mnemonic.clone(), v[0].body.clone()),
                    _ => ("??".to_string(), String::new()),
                };
                b.row().u64(addr).u32(len).bytes(&bytes).str(&mn).str(&body).str(&flow_text(flow.kind)).bool(flow.ends_flow).bool(flow.call_target.is_some()).u64(flow.call_target.unwrap_or(0)).list_u64(&flow.flows);
            }
            CodeUnit::Data { type_name, .. } => {
                b.row().u64(addr).u32(len).bytes(&bytes).str(type_name).str("").str("DATA").bool(false).bool(false).u64(0).list_u64(&[]);
            }
        }
    }
    Ok(b.finish(true))
}
