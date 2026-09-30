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

const LOAD_PARAMS: &[&str] = &["input", keys::LOAD_LOADER, keys::LOAD_LANGUAGE, keys::LOAD_BASE, keys::LOAD_ENTRIES, keys::LOAD_FLOWS, keys::LOAD_DATA, keys::LOAD_CSPEC_X86_32, keys::ANALYSIS_DISABLE, keys::ANALYSIS_SWITCH_TABLE_REFS, keys::ANALYSIS_DATA_POINTER_FUNCTIONS, keys::KNOBS_OFF];

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
/// The entry points `load.entries` declares for a raw image (hex, comma-separated; none when unset).
pub fn raw_entries(o: &Options) -> Result<Vec<u64>> {
    o.get(keys::LOAD_ENTRIES)?
        .split(',')
        .map(str::trim)
        .filter(|e| !e.is_empty())
        .map(|e| parse_hex(e).ok_or_else(|| Error::InvalidArg(format!("`{}`: `{e}` is not an address", keys::LOAD_ENTRIES))))
        .collect()
}

/// The computed flows `load.flows` declares: `jump:FROM=TO,…` and `call:FROM=TO,…`, `;`-separated,
/// hex. Every address must lie in the program's memory: a flow into nothing declares nothing.
pub fn declared_flows(o: &Options, program: &mosura_core::analysis::Program) -> Result<Vec<mosura_core::analysis::program::DeclaredFlow>> {
    let bad = |what: String| Error::InvalidArg(format!("`{}`: {what}", keys::LOAD_FLOWS));
    let at = |a: &str| -> Result<Address> {
        let off = parse_hex(a.trim()).ok_or_else(|| bad(format!("`{a}` is not an address")))?;
        let addr = Address::new(program.default_space, off);
        if program.memory.block_at(addr).is_none() {
            return Err(bad(format!("{off:#x} is outside the program's memory")));
        }
        Ok(addr)
    };
    let mut flows = Vec::new();
    for decl in o.get(keys::LOAD_FLOWS)?.split(';').map(str::trim).filter(|d| !d.is_empty()) {
        let (kind, rest) = decl.split_once(':').ok_or_else(|| bad(format!("`{decl}` is not KIND:FROM=TO,…")))?;
        let call = match kind.trim() {
            "jump" => false,
            "call" => true,
            k => return Err(bad(format!("`{k}` is not jump or call"))),
        };
        let (from, to) = rest.split_once('=').ok_or_else(|| bad(format!("`{decl}` names no targets")))?;
        let targets = to.split(',').filter(|t| !t.trim().is_empty()).map(|t| at(t)).collect::<Result<Vec<_>>>()?;
        if targets.is_empty() {
            return Err(bad(format!("`{decl}` names no targets")));
        }
        flows.push(mosura_core::analysis::program::DeclaredFlow { from: at(from)?, call, targets });
    }
    Ok(flows)
}

/// The data units `load.data` declares: `KIND:ADDR[*COUNT][@BASE]`, `;`-separated; ADDR and BASE
/// hex, COUNT decimal (or 0x…). Each
/// element is read from the program's image in its byte order; a pointer (`ptr16`, `ptr32`: the
/// value, plus BASE if given) or an offset (`off16`, `off32`: BASE plus the value, signed) that is
/// not 0 gets a target. Every element must lie in initialized memory and overlap no other unit.
pub fn declared_data(o: &Options, program: &Program) -> Result<Vec<mosura_core::analysis::program::DeclaredUnit>> {
    let bad = |what: String| Error::InvalidArg(format!("`{}`: {what}", keys::LOAD_DATA));
    let hex = |a: &str| parse_hex(a.trim()).ok_or_else(|| bad(format!("`{a}` is not a number")));
    let ram = program.default_space;
    let mut units: Vec<mosura_core::analysis::program::DeclaredUnit> = Vec::new();
    for decl in o.get(keys::LOAD_DATA)?.split(';').map(str::trim).filter(|d| !d.is_empty()) {
        let (kind, rest) = decl.split_once(':').ok_or_else(|| bad(format!("`{decl}` is not KIND:ADDR[*COUNT][@BASE]")))?;
        let (rest, base) = match rest.split_once('@') {
            Some((r, b)) => (r, Some(hex(b)?)),
            None => (rest, None),
        };
        // A count is a number of elements: decimal, unless written 0x….
        let count_of = |n: &str| -> Result<u64> {
            let n = n.trim();
            match n.strip_prefix("0x").or_else(|| n.strip_prefix("0X")) {
                Some(h) => u64::from_str_radix(h, 16).ok(),
                None => n.parse().ok(),
            }
            .ok_or_else(|| bad(format!("`{n}` is not a count")))
        };
        let (addr, count) = match rest.split_once('*') {
            Some((a, n)) => (hex(a)?, count_of(n)?),
            None => (hex(rest)?, 1),
        };
        // (size, type name, how an element's value becomes a target)
        let (size, type_name, offset): (u32, &str, Option<bool>) = match kind.trim() {
            "u8" => (1, "byte", None),
            "u16" => (2, "word", None),
            "u32" => (4, "dword", None),
            "ptr16" => (2, "pointer16", Some(false)),
            "ptr32" => (4, "pointer32", Some(false)),
            "off16" => (2, "word", Some(true)),
            "off32" => (4, "dword", Some(true)),
            k => return Err(bad(format!("`{k}` is not u8, u16, u32, ptr16, ptr32, off16 or off32"))),
        };
        if offset == Some(true) && base.is_none() {
            return Err(bad(format!("`{decl}`: an offset table needs its @BASE")));
        }
        if count == 0 {
            return Err(bad(format!("`{decl}` declares no element")));
        }
        for i in 0..count {
            let at = Address::new(ram, addr + i * u64::from(size));
            let bytes = program.memory.read_window(at, size as usize);
            if bytes.len() < size as usize || (0..u64::from(size)).any(|k| program.memory.block_at(Address::new(ram, at.offset + k)).is_none_or(|b| !b.is_initialized())) {
                return Err(bad(format!("{:#x} is outside the program's initialized memory", at.offset)));
            }
            let mut value = 0u64;
            for k in 0..size as usize {
                let byte = if program.big_endian { bytes[k] } else { bytes[size as usize - 1 - k] };
                value = (value << 8) | u64::from(byte);
            }
            let target = match offset {
                None => None,
                Some(_) if value == 0 => None,
                Some(false) => Some(value.wrapping_add(base.unwrap_or(0))),
                Some(true) => {
                    let shift = 64 - 8 * size;
                    Some(base.unwrap_or(0).wrapping_add((((value << shift) as i64) >> shift) as u64))
                }
            };
            let end = at.offset + u64::from(size);
            let clash = units.iter().any(|u| at.offset < u.at.offset + u64::from(u.length) && u.at.offset < end)
                || (at.offset..end).any(|k| program.listing.code_unit_containing(Address::new(ram, k), 16).is_some());
            if clash {
                return Err(bad(format!("{:#x} overlaps another unit", at.offset)));
            }
            units.push(mosura_core::analysis::program::DeclaredUnit { at, length: size, type_name: type_name.to_string(), target: target.map(|t| Address::new(ram, t)) });
        }
    }
    Ok(units)
}

pub fn loader_of<'a>(o: &Options, language: &'a str, base: &str, entries: &'a [u64]) -> Result<Loader<'a>> {
    if !entries.is_empty() && o.get(keys::LOAD_LOADER)? != "raw" {
        return Err(Error::InvalidArg(format!("`{}` declares a raw image's entry points: it needs load.loader=raw", keys::LOAD_ENTRIES)));
    }
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
            Loader::Raw { language, base, entries }
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
    let knobs = o.knobs()?;
    let settings = o.decompile_settings()?;
    if let Some((lk, p)) = &s.last_program {
        if *lk == k {
            validate_contracts(&knobs, &p.language_id)?;
            if p.knobs == knobs && p.global_scope_all_loaded == settings.global_scope_all_loaded
                && p.proto_scope == settings.proto_scope {
                return Ok((k, Arc::clone(p)));
            }
            let mut configured = (**p).clone();
            configured.knobs = knobs;
            configured.global_scope_all_loaded = settings.global_scope_all_loaded;
            configured.proto_scope = settings.proto_scope;
            return Ok((k, Arc::new(configured)));
        }
    }
    let set = s.read_set(SetKind::Program, &k)?;
    let p = Arc::new(thaw(&set, knobs, &settings)?);
    validate_contracts(&p.knobs, &p.language_id)?;
    s.last_program = Some((k, Arc::clone(&p)));
    Ok((k, p))
}

fn validate_contracts(knobs: &mosura_core::switches::Knobs, language: &str) -> Result<()> {
    if knobs.indirect_inputs.is_empty() && knobs.function_outputs.is_empty() && knobs.function_inputs.is_empty() { return Ok(()); }
    let (spec, _) = mosura_core::lang::load_cached(language)
        .ok_or_else(|| Error::InvalidArg(format!("cannot load register names for {language}")))?;
    mosura_core::decompile::deindirect::validate_indirect_inputs(knobs, spec).map_err(Error::InvalidArg)?;
    mosura_core::decompile::prototypetypes::validate_function_inputs(knobs, spec).map_err(Error::InvalidArg)?;
    mosura_core::decompile::prototypetypes::validate_function_outputs(knobs, spec).map_err(Error::InvalidArg)
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
    let entries = raw_entries(o)?;
    let which = loader_of(o, &language, &base, &entries)?;
    let mut program = analysis::load_bytes_with(&data, filename.as_deref(), which, &knobs).map_err(load_error)?;
    program.declared_flows = declared_flows(o, &program)?;
    let data = declared_data(o, &program)?;
    program.declare_data(&data);
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
                // The flow type analysis left (Ghidra `getFlowType()`: the prototype's, modified by
                // any flow override), not the bytes' alone.
                let kind = mosura_core::analysis::flowtype::overridden_flow_kind(flow.kind, p.flow_override_at(Address::new(p.default_space, addr)));
                let (mn, body) = match mosura_core::sleigh::disassemble(&p.language_id, &bytes, addr) {
                    Ok(v) if !v.is_empty() => (v[0].mnemonic.clone(), v[0].body.clone()),
                    _ => ("??".to_string(), String::new()),
                };
                b.row().u64(addr).u32(len).bytes(&bytes).str(&mn).str(&body).str(&flow_text(kind)).bool(!mosura_core::analysis::flowtype::overridden_props_of(flow.kind, p.flow_override_at(Address::new(p.default_space, addr))).fallthrough).bool(flow.call_target.is_some()).u64(flow.call_target.unwrap_or(0)).list_u64(&flow.flows);
            }
            CodeUnit::Data { type_name, .. } => {
                b.row().u64(addr).u32(len).bytes(&bytes).str(type_name).str("").str("DATA").bool(false).bool(false).u64(0).list_u64(&[]);
            }
        }
    }
    Ok(b.finish(true))
}
