//! The `Program` in tables (design §5.6): `freeze` writes every collection of a loaded and analyzed
//! program as one table per collection (the image bytes as a sibling blob), `thaw` rebuilds the
//! program through the core's own constructors — nothing in `mosura-core` changes shape for the
//! store. Row ORDER is semantic in three collections (`symbols`: `primary_at` falls back to the
//! first; `references`: `first_flow_reference_from`; `functions`: the decompile order of the
//! prototype pass): those tables keep insertion order. Addresses are `(space, offset)` pairs;
//! `space` indexes `spaces`. Enums are `u8` codes with exhaustive encoders below.
//!
//! Not frozen: `contract_cache` (a memo, order-dependent), `proto_scope` and
//! `global_scope_all_loaded` (decompile-time OPTIONS, not program state), `knobs` (recorded as the
//! options tag and set from the options at thaw, which are in the key).

pub mod schemas;

use std::collections::{BTreeMap, HashMap, HashSet};

use crate::error::{Error, Result};
use crate::options::DecompileSettings;
use crate::set::TableSet;
use crate::table::builder::TableBuilder;
use crate::table::Table;
use mosura_core::analysis::flowtype::{FlowKind, FlowOverride};
use mosura_core::analysis::program::{CodeUnit, CommentKind, InstructionFlow, Program, RefType, Symbol, SymbolType};
use mosura_core::analysis::sret::{CallEvidence, SretFact, SretShape};
use mosura_core::decompile::fspec::{EffectRecord, FuncProto, ParamEntry, ParamList, ProtoModel, ProtoSlot};
use mosura_core::decompile::space::{Address, RangeList, Space, SpaceId, SpaceKind, SpaceManager};
use mosura_core::decompile::types::Datatype;
use mosura_core::switches::Knobs;

use schemas::*;

// ── enum codes (exhaustive both ways; a test decodes every code) ──

pub fn ref_type_code(r: RefType) -> u8 {
    match r {
        RefType::Data => 0,
        RefType::Read => 1,
        RefType::Write => 2,
        RefType::UnconditionalJump => 3,
        RefType::ConditionalJump => 4,
        RefType::ComputedJump => 5,
        RefType::ConditionalComputedJump => 6,
        RefType::UnconditionalCall => 7,
        RefType::ConditionalCall => 8,
        RefType::ComputedCall => 9,
        RefType::ConditionalComputedCall => 10,
        RefType::CallTerminator => 11,
        RefType::ComputedCallTerminator => 12,
        RefType::Indirection => 13,
        RefType::Param => 14,
    }
}
pub fn ref_type(code: u8) -> Result<RefType> {
    Ok(match code {
        0 => RefType::Data,
        1 => RefType::Read,
        2 => RefType::Write,
        3 => RefType::UnconditionalJump,
        4 => RefType::ConditionalJump,
        5 => RefType::ComputedJump,
        6 => RefType::ConditionalComputedJump,
        7 => RefType::UnconditionalCall,
        8 => RefType::ConditionalCall,
        9 => RefType::ComputedCall,
        10 => RefType::ConditionalComputedCall,
        11 => RefType::CallTerminator,
        12 => RefType::ComputedCallTerminator,
        13 => RefType::Indirection,
        14 => RefType::Param,
        _ => return Err(Error::Format(format!("unknown reference type code {code}"))),
    })
}
pub const REF_TYPE_CODES: u8 = 15;

/// `FlowKind` as `(kind code, ref code)`: the `Ref` variant carries its reference type.
pub fn flow_kind_code(k: FlowKind) -> (u8, u8) {
    match k {
        FlowKind::FallThrough => (0, 0),
        FlowKind::Invalid => (1, 0),
        FlowKind::Terminator => (2, 0),
        FlowKind::ConditionalTerminator => (3, 0),
        FlowKind::JumpTerminator => (4, 0),
        FlowKind::Ref(r) => (5, ref_type_code(r)),
    }
}
pub fn flow_kind(kind: u8, r: u8) -> Result<FlowKind> {
    Ok(match kind {
        0 => FlowKind::FallThrough,
        1 => FlowKind::Invalid,
        2 => FlowKind::Terminator,
        3 => FlowKind::ConditionalTerminator,
        4 => FlowKind::JumpTerminator,
        5 => FlowKind::Ref(ref_type(r)?),
        _ => return Err(Error::Format(format!("unknown flow kind code {kind}"))),
    })
}
pub fn flow_override_code(f: FlowOverride) -> u8 {
    match f {
        FlowOverride::None => 0,
        FlowOverride::CallReturn => 1,
    }
}
pub fn flow_override(code: u8) -> Result<FlowOverride> {
    Ok(match code {
        0 => FlowOverride::None,
        1 => FlowOverride::CallReturn,
        _ => return Err(Error::Format(format!("unknown flow override code {code}"))),
    })
}
pub fn symbol_type_code(s: SymbolType) -> u8 {
    match s {
        SymbolType::Label => 0,
        SymbolType::Function => 1,
        SymbolType::Data => 2,
    }
}
pub fn symbol_type(code: u8) -> Result<SymbolType> {
    Ok(match code {
        0 => SymbolType::Label,
        1 => SymbolType::Function,
        2 => SymbolType::Data,
        _ => return Err(Error::Format(format!("unknown symbol type code {code}"))),
    })
}
pub fn comment_kind_code(c: CommentKind) -> u8 {
    match c {
        CommentKind::Eol => 0,
        CommentKind::Pre => 1,
        CommentKind::Post => 2,
        CommentKind::Plate => 3,
        CommentKind::Repeatable => 4,
    }
}
pub fn comment_kind(code: u8) -> Result<CommentKind> {
    Ok(match code {
        0 => CommentKind::Eol,
        1 => CommentKind::Pre,
        2 => CommentKind::Post,
        3 => CommentKind::Plate,
        4 => CommentKind::Repeatable,
        _ => return Err(Error::Format(format!("unknown comment kind code {code}"))),
    })
}
pub fn space_kind_code(k: SpaceKind) -> u8 {
    match k {
        SpaceKind::Constant => 0,
        SpaceKind::Processor => 1,
        SpaceKind::Internal => 2,
        SpaceKind::Spacebase => 3,
        SpaceKind::Special => 4,
    }
}
pub fn space_kind(code: u8) -> Result<SpaceKind> {
    Ok(match code {
        0 => SpaceKind::Constant,
        1 => SpaceKind::Processor,
        2 => SpaceKind::Internal,
        3 => SpaceKind::Spacebase,
        4 => SpaceKind::Special,
        _ => return Err(Error::Format(format!("unknown space kind code {code}"))),
    })
}

// ── the Datatype intern table ──

/// Builds the `types` table: structural dedup, children before parents, `Spacebase(id)` stored
/// as the id (same spec ⇒ same ids).
#[derive(Default)]
pub struct TypeIntern {
    rows: Vec<(u8, u32, i64, u64, Vec<u64>)>, // kind, size, sub, count, fields (offset, type interleaved)
    index: HashMap<(u8, u32, i64, u64, Vec<u64>), u32>,
}

impl TypeIntern {
    pub fn intern(&mut self, t: &Datatype) -> u32 {
        let row = match t {
            Datatype::Void => (0, 0, -1, 0, vec![]),
            Datatype::Spacebase(s) => (1, s.0, -1, 0, vec![]),
            Datatype::Unknown(n) => (2, *n, -1, 0, vec![]),
            Datatype::Char => (3, 1, -1, 0, vec![]),
            Datatype::Int(n) => (4, *n, -1, 0, vec![]),
            Datatype::Uint(n) => (5, *n, -1, 0, vec![]),
            Datatype::Bool => (6, 1, -1, 0, vec![]),
            Datatype::Float(n) => (7, *n, -1, 0, vec![]),
            Datatype::Code => (8, 0, -1, 0, vec![]),
            Datatype::Pointer(n, sub) => {
                let s = self.intern(sub) as i64;
                (9, *n, s, 0, vec![])
            }
            Datatype::Array(sub, count) => {
                let s = self.intern(sub) as i64;
                (10, 0, s, *count, vec![])
            }
            Datatype::Struct(size, fields) => {
                let mut fl = Vec::with_capacity(fields.len() * 2);
                for (off, ty) in fields {
                    let id = self.intern(ty);
                    fl.push(*off);
                    fl.push(id as u64);
                }
                (11, *size, -1, 0, fl)
            }
        };
        if let Some(&id) = self.index.get(&row) {
            return id;
        }
        let id = self.rows.len() as u32;
        self.index.insert(row.clone(), id);
        self.rows.push(row);
        id
    }

    pub fn table(&self) -> Table {
        let mut b = TableBuilder::new(&TYPES);
        for (i, (kind, size, sub, count, fields)) in self.rows.iter().enumerate() {
            b.row().u32(i as u32).u8(*kind).u32(*size).i64(*sub).u64(*count).list_u64(fields);
        }
        b.finish(true)
    }
}

/// Reads a type back from the `types` table.
pub fn datatype_at(types: &Table, id: u32) -> Result<Datatype> {
    let r = id as u64;
    let kind = types.u64(r, 1)? as u8;
    let size = types.u64(r, 2)? as u32;
    let sub = types.i64(r, 3)?;
    let count = types.u64(r, 4)?;
    Ok(match kind {
        0 => Datatype::Void,
        1 => Datatype::Spacebase(SpaceId(size)),
        2 => Datatype::Unknown(size),
        3 => Datatype::Char,
        4 => Datatype::Int(size),
        5 => Datatype::Uint(size),
        6 => Datatype::Bool,
        7 => Datatype::Float(size),
        8 => Datatype::Code,
        9 => Datatype::Pointer(size, Box::new(datatype_at(types, sub as u32)?)),
        10 => Datatype::Array(Box::new(datatype_at(types, sub as u32)?), count),
        11 => {
            let f: Vec<u64> = types.list_u64(r, 5)?.collect();
            let mut fields = Vec::with_capacity(f.len() / 2);
            for pair in f.chunks_exact(2) {
                fields.push((pair[0], datatype_at(types, pair[1] as u32)?));
            }
            Datatype::Struct(size, fields)
        }
        _ => return Err(Error::Format(format!("unknown datatype kind code {kind}"))),
    })
}

// ── the prototype models ──

struct ModelWriter {
    models: TableBuilder,
    param_lists: TableBuilder,
    param_entries: TableBuilder,
    effects: TableBuilder,
    ranges: TableBuilder,
    trash: TableBuilder,
    next: u32,
}

impl ModelWriter {
    fn new() -> ModelWriter {
        ModelWriter {
            models: TableBuilder::new(&PROTO_MODELS),
            param_lists: TableBuilder::new(&PARAM_LISTS),
            param_entries: TableBuilder::new(&PARAM_ENTRIES),
            effects: TableBuilder::new(&EFFECTS),
            ranges: TableBuilder::new(&MODEL_RANGES),
            trash: TableBuilder::new(&LIKELYTRASH),
            next: 0,
        }
    }
    fn write(&mut self, m: &ProtoModel, parent: i64) -> u32 {
        let id = self.next;
        self.next += 1;
        self.models.row().u32(id).i64(parent).str(&m.name).bool(m.print_in_decl).i64(m.extrapop as i64).bool(m.custom_conventions).bool(m.input.is_some()).bool(m.output.is_some());
        for (which, list) in [(0u8, &m.input), (1u8, &m.output)] {
            if let Some(l) = list {
                self.param_lists.row().u32(id).u8(which).bool(l.is_output).list_u32(&l.resource_start);
                for (i, e) in l.entry.iter().enumerate() {
                    self.param_entries.row().u32(id).u8(which).u32(i as u32).u32(e.group).u8(e.type_class).u32(e.space.0).u64(e.addressbase).u32(e.size).u32(e.minsize).u32(e.alignment);
                }
            }
        }
        for (i, e) in m.effectlist.iter().enumerate() {
            self.effects.row().u32(id).u32(i as u32).u32(e.space.0).u64(e.offset).u32(e.size).u8(e.effect);
        }
        for (which, rl) in [(0u8, &m.localrange), (1u8, &m.paramrange)] {
            for r in rl.iter() {
                self.ranges.row().u32(id).u8(which).u32(r.spc.0).u64(r.first).u64(r.last);
            }
        }
        for (i, (a, sz)) in m.likelytrash.iter().enumerate() {
            self.trash.row().u32(id).u32(i as u32).u32(a.space.0).u64(a.offset).u32(*sz);
        }
        for child in &m.merged {
            self.write(child, id as i64);
        }
        id
    }
}

/// Freeze a list of prototype models alone (the six model tables) — the unit under test for the
/// structural round-trip; `freeze` uses the same writer inside the program set.
pub fn freeze_proto_models(models: &[ProtoModel]) -> TableSet {
    let mut mw = ModelWriter::new();
    for m in models {
        mw.write(m, -1);
    }
    let mut set = TableSet::default();
    set.insert("proto_models", mw.models.finish(true));
    set.insert("param_lists", mw.param_lists.finish(false));
    set.insert("param_entries", mw.param_entries.finish(false));
    set.insert("effects", mw.effects.finish(false));
    set.insert("model_ranges", mw.ranges.finish(false));
    set.insert("likelytrash", mw.trash.finish(false));
    set
}

/// Read the prototype model with `id` back from the model tables (children included).
pub fn proto_model_at(set: &TableSet, id: u32) -> Result<ProtoModel> {
    read_model(set, id)
}

fn read_model(set: &TableSet, id: u32) -> Result<ProtoModel> {
    let models = set.table("proto_models")?;
    let row = models.find(0, id as u64).ok_or_else(|| Error::Format(format!("proto model {id} missing")))?;
    let mut m = ProtoModel::empty();
    m.name = models.str(row, 2)?.to_string();
    m.print_in_decl = models.bool(row, 3)?;
    m.extrapop = models.i64(row, 4)? as i32;
    m.custom_conventions = models.bool(row, 5)?;
    let has_input = models.bool(row, 6)?;
    let has_output = models.bool(row, 7)?;
    let lists = set.table("param_lists")?;
    let entries = set.table("param_entries")?;
    for (which, has) in [(0u8, has_input), (1u8, has_output)] {
        if !has {
            continue;
        }
        let mut list: Option<ParamList> = None;
        for r in 0..lists.rows() {
            if lists.u64(r, 0)? as u32 == id && lists.u64(r, 1)? as u8 == which {
                list = Some(ParamList { entry: Vec::new(), resource_start: lists.list_u32(r, 3)?.collect(), is_output: lists.bool(r, 2)? });
            }
        }
        let mut list = list.ok_or_else(|| Error::Format(format!("param list {which} of model {id} missing")))?;
        let mut ents: Vec<(u32, ParamEntry)> = Vec::new();
        for r in 0..entries.rows() {
            if entries.u64(r, 0)? as u32 == id && entries.u64(r, 1)? as u8 == which {
                ents.push((
                    entries.u64(r, 2)? as u32,
                    ParamEntry {
                        group: entries.u64(r, 3)? as u32,
                        type_class: entries.u64(r, 4)? as u8,
                        space: SpaceId(entries.u64(r, 5)? as u32),
                        addressbase: entries.u64(r, 6)?,
                        size: entries.u64(r, 7)? as u32,
                        minsize: entries.u64(r, 8)? as u32,
                        alignment: entries.u64(r, 9)? as u32,
                    },
                ));
            }
        }
        ents.sort_by_key(|e| e.0);
        list.entry = ents.into_iter().map(|e| e.1).collect();
        if which == 0 {
            m.input = Some(list);
        } else {
            m.output = Some(list);
        }
    }
    let effects = set.table("effects")?;
    let mut eff: Vec<(u32, EffectRecord)> = Vec::new();
    for r in 0..effects.rows() {
        if effects.u64(r, 0)? as u32 == id {
            eff.push((effects.u64(r, 1)? as u32, EffectRecord { space: SpaceId(effects.u64(r, 2)? as u32), offset: effects.u64(r, 3)?, size: effects.u64(r, 4)? as u32, effect: effects.u64(r, 5)? as u8 }));
        }
    }
    eff.sort_by_key(|e| e.0);
    m.effectlist = eff.into_iter().map(|e| e.1).collect();
    let ranges = set.table("model_ranges")?;
    let (mut local, mut param) = (RangeList::new(), RangeList::new());
    for r in 0..ranges.rows() {
        if ranges.u64(r, 0)? as u32 == id {
            let spc = SpaceId(ranges.u64(r, 2)? as u32);
            let (first, last) = (ranges.u64(r, 3)?, ranges.u64(r, 4)?);
            if ranges.u64(r, 1)? as u8 == 0 { local.insert_range(spc, first, last) } else { param.insert_range(spc, first, last) }
        }
    }
    m.localrange = local;
    m.paramrange = param;
    let trash = set.table("likelytrash")?;
    let mut tr: Vec<(u32, (Address, u32))> = Vec::new();
    for r in 0..trash.rows() {
        if trash.u64(r, 0)? as u32 == id {
            tr.push((trash.u64(r, 1)? as u32, (Address::new(SpaceId(trash.u64(r, 2)? as u32), trash.u64(r, 3)?), trash.u64(r, 4)? as u32)));
        }
    }
    tr.sort_by_key(|e| e.0);
    m.likelytrash = tr.into_iter().map(|e| e.1).collect();
    // children: rows whose parent is this id, in row order
    let mut merged = Vec::new();
    for r in 0..models.rows() {
        if models.i64(r, 1)? == id as i64 {
            merged.push(read_model(set, models.u64(r, 0)? as u32)?);
        }
    }
    m.merged = merged;
    Ok(m)
}

// ── freeze ──

/// Freeze a program into its table set. `opts_tag` is the options tag recorded in the `program`
/// row (the knobs are set from the options at thaw).
pub fn freeze(p: &Program, opts_tag: &str) -> TableSet {
    let mut set = TableSet::default();
    let ds = p.default_space;

    // program (1 row)
    let mut b = TableBuilder::new(&PROGRAM);
    b.row()
        .str(&p.language_id)
        .str(&p.compiler_spec_id)
        .str(&p.compiler)
        .str(p.compiler_version.as_deref().unwrap_or(""))
        .bool(p.compiler_version.is_some())
        .str(p.compiler_signature.as_deref().unwrap_or(""))
        .bool(p.compiler_signature.is_some())
        .u32(p.image_base.space.0)
        .u64(p.image_base.offset)
        .bool(p.big_endian)
        .u32(p.addr_size_bits)
        .u32(ds.0)
        .bool(p.relocation_table.is_relocatable())
        .str(opts_tag);
    set.insert("program", b.finish(false));

    // spaces
    let mut b = TableBuilder::new(&SPACES);
    for i in 0..p.spaces.num_spaces() {
        let s = p.spaces.get(SpaceId(i as u32));
        let mut sb: Vec<u64> = Vec::new();
        for (a, sz) in &s.spacebase {
            sb.extend([a.space.0 as u64, a.offset, *sz as u64]);
        }
        b.row().u32(s.id.0).str(&s.name).u8(space_kind_code(s.kind)).u32(s.addr_size).bool(s.big_endian).u32(s.wordsize).i64(s.delay as i64).i64(s.deadcodedelay as i64).bool(s.contain.is_some()).u32(s.contain.map(|c| c.0).unwrap_or(0)).list_u64(&sb);
    }
    set.insert("spaces", b.finish(true));

    // blocks + the image blob
    let mut blob: Vec<u8> = Vec::new();
    let mut b = TableBuilder::new(&BLOCKS);
    for blk in p.memory.blocks() {
        let (off, len) = match &blk.bytes {
            Some(bytes) => {
                let off = blob.len() as u64;
                blob.extend_from_slice(bytes);
                (off, bytes.len() as u64)
            }
            None => (0, 0),
        };
        b.row().u32(blk.start.space.0).u64(blk.start.offset).u64(blk.end.offset).str(&blk.name).bool(blk.read).bool(blk.write).bool(blk.execute).bool(blk.bytes.is_some()).u64(off).u64(len);
    }
    set.insert("blocks", b.finish(false));
    set.blobs.insert("bytes".to_string(), blob);

    // functions + bodies (insertion order)
    let mut fb = TableBuilder::new(&FUNCTIONS);
    let mut bb = TableBuilder::new(&BODIES);
    for f in p.function_manager.functions() {
        fb.row().u32(f.entry.space.0).u64(f.entry.offset).str(&f.name);
        for r in f.body.ranges() {
            bb.row().u32(f.entry.space.0).u64(f.entry.offset).u32(r.space.0).u64(r.min).u64(r.max);
        }
    }
    set.insert("functions", fb.finish(false));
    set.insert("bodies", bb.finish(false));

    // symbols (insertion order)
    let mut b = TableBuilder::new(&SYMBOLS);
    for s in p.symbol_table.symbols() {
        b.row().u32(s.address.space.0).u64(s.address.offset).str(&s.name).u8(symbol_type_code(s.symbol_type)).bool(s.primary).bool(s.external);
    }
    set.insert("symbols", b.finish(false));

    // references (insertion order)
    let mut b = TableBuilder::new(&REFERENCES);
    for r in p.reference_manager.references() {
        b.row().u32(r.from.space.0).u64(r.from.offset).u32(r.to.space.0).u64(r.to.offset).u8(ref_type_code(r.ref_type)).i64(r.op_index as i64);
    }
    set.insert("references", b.finish(false));

    // listing (sorted by (space, addr))
    let mut units: Vec<(Address, &CodeUnit)> = p.listing.code_units().collect();
    units.sort_by_key(|(a, _)| (a.space.0, a.offset));
    let mut b = TableBuilder::new(&LISTING);
    for (a, u) in units {
        match u {
            CodeUnit::Instruction { length, flow } => {
                let (k, r) = flow_kind_code(flow.kind);
                b.row().u32(a.space.0).u64(a.offset).u32(*length).u8(0).u8(k).u8(r).bool(flow.ends_flow).bool(flow.call_target.is_some()).u64(flow.call_target.unwrap_or(0)).list_u64(&flow.flows).str("");
            }
            CodeUnit::Data { length, type_name } => {
                b.row().u32(a.space.0).u64(a.offset).u32(*length).u8(1).u8(0).u8(0).bool(false).bool(false).u64(0).list_u64(&[]).str(type_name);
            }
        }
    }
    set.insert("listing", b.finish(false));

    // relocations, entry points (insertion order)
    let mut b = TableBuilder::new(&RELOCATIONS);
    for r in p.relocation_table.relocations() {
        b.row().u32(r.address.space.0).u64(r.address.offset).u64(r.value);
    }
    set.insert("relocations", b.finish(false));
    let mut b = TableBuilder::new(&ENTRY_POINTS);
    for a in &p.entry_points {
        b.row().u32(a.space.0).u64(a.offset);
    }
    set.insert("entry_points", b.finish(false));

    // comments (BTreeMap order), indirect branches, noreturn, defined data, flow overrides (sorted)
    let mut b = TableBuilder::new(&COMMENTS);
    for ((addr, kind), text) in &p.comments {
        b.row().u64(*addr).u8(comment_kind_code(*kind)).str(text);
    }
    set.insert("comments", b.finish(false));
    let mut ib: Vec<u64> = p.indirect_branches.iter().copied().collect();
    ib.sort_unstable();
    let mut b = TableBuilder::new(&INDIRECT_BRANCHES);
    for a in ib {
        b.row().u64(a);
    }
    set.insert("indirect_branches", b.finish(true));
    let mut nr: Vec<(u32, u64)> = p.noreturn_functions.iter().copied().collect();
    nr.sort_unstable();
    let mut b = TableBuilder::new(&NORETURN);
    for (s, a) in nr {
        b.row().u32(s).u64(a);
    }
    set.insert("noreturn", b.finish(false));
    let mut b = TableBuilder::new(&DEFINED_DATA);
    for (a, ty, len) in &p.defined_data {
        b.row().u32(a.space.0).u64(a.offset).str(ty).u32(*len);
    }
    set.insert("defined_data", b.finish(false));
    let mut fo: Vec<((u32, u64), FlowOverride)> = p.flow_overrides.iter().map(|(k, v)| (*k, *v)).collect();
    fo.sort_by_key(|(k, _)| *k);
    let mut b = TableBuilder::new(&FLOW_OVERRIDES);
    for ((s, a), f) in fo {
        b.row().u32(s).u64(a).u8(flow_override_code(f));
    }
    set.insert("flow_overrides", b.finish(false));

    // facts: tail-return writes (kind 0), sorted
    let mut tr: Vec<u64> = p.tail_return_writes.iter().copied().collect();
    tr.sort_unstable();
    let mut b = TableBuilder::new(&FACTS);
    for a in tr {
        b.row().u64(a).u8(0).str("");
    }
    set.insert("facts", b.finish(true));

    // protos + slots + models (functions in address order for determinism)
    let mut types = TypeIntern::default();
    let mut mw = ModelWriter::new();
    let mut pb = TableBuilder::new(&PROTOS);
    let mut sb = TableBuilder::new(&PROTO_SLOTS);
    let mut fns: Vec<(&u64, &FuncProto)> = p.recovered_protos.iter().collect();
    fns.sort_by_key(|(k, _)| **k);
    for (fnva, proto) in fns {
        let model = proto.model.as_ref().map(|m| mw.write(m, -1));
        let out = proto.output.as_ref();
        pb.row().u64(*fnva).bool(out.is_some()).u32(out.map(|o| o.addr.space.0).unwrap_or(0)).u64(out.map(|o| o.addr.offset).unwrap_or(0)).u32(out.map(|o| o.size).unwrap_or(0)).bool(model.is_some()).u32(model.unwrap_or(0));
        for (i, s) in proto.params.iter().enumerate() {
            sb.row().u64(*fnva).u32(i as u32).u32(s.addr.space.0).u64(s.addr.offset).u32(s.size);
        }
    }
    set.insert("protos", pb.finish(true));
    set.insert("proto_slots", sb.finish(false));

    // sret facts, fields, callers
    let mut sf = TableBuilder::new(&SRET_FACTS);
    let mut sfl = TableBuilder::new(&SRET_FIELDS);
    let mut srets: Vec<(&u64, &SretFact)> = p.recovered_sret.iter().collect();
    srets.sort_by_key(|(k, _)| **k);
    for (fnva, fact) in srets {
        let sh = fact.shape.as_ref();
        sf.row().u64(*fnva).bool(sh.is_some()).u32(sh.map(|s| s.slot.space.0).unwrap_or(0)).u64(sh.map(|s| s.slot.offset).unwrap_or(0)).u32(sh.map(|s| s.size).unwrap_or(0)).bool(fact.ret_pop.is_some()).u32(fact.ret_pop.unwrap_or(0));
        if let Some(s) = sh {
            for (i, (off, size, ty)) in s.fields.iter().enumerate() {
                let tid = types.intern(ty);
                sfl.row().u64(*fnva).u32(i as u32).u32(*off).u32(*size).u32(tid);
            }
        }
    }
    set.insert("sret_facts", sf.finish(true));
    set.insert("sret_fields", sfl.finish(false));
    let mut callers: Vec<(&u64, &Vec<CallEvidence>)> = p.sret_callers.iter().collect();
    callers.sort_by_key(|(k, _)| **k);
    let mut b = TableBuilder::new(&SRET_CALLERS);
    for (callee, evs) in callers {
        for (i, e) in evs.iter().enumerate() {
            b.row().u64(*callee).u32(i as u32).bool(e.output_dead).bool(e.arg0_local_addr);
        }
    }
    set.insert("sret_callers", b.finish(false));

    set.insert("types", types.table());
    set.insert("proto_models", mw.models.finish(true));
    set.insert("param_lists", mw.param_lists.finish(false));
    set.insert("param_entries", mw.param_entries.finish(false));
    set.insert("effects", mw.effects.finish(false));
    set.insert("model_ranges", mw.ranges.finish(false));
    set.insert("likelytrash", mw.trash.finish(false));
    set
}

// ── thaw ──

fn addr(t: &Table, r: u64, space_col: u32, off_col: u32) -> Result<Address> {
    Ok(Address::new(SpaceId(t.u64(r, space_col)? as u32), t.u64(r, off_col)?))
}

/// Rebuild a program from its table set. `knobs` and `settings` come from the OPTIONS (they are
/// in the key, not in the tables).
pub fn thaw(set: &TableSet, knobs: Knobs, settings: &DecompileSettings) -> Result<Program> {
    let pt = set.table("program")?;
    if pt.rows() != 1 {
        return Err(Error::Format("the program table has one row".into()));
    }
    // spaces
    let st = set.table("spaces")?;
    let mut spaces: Vec<Space> = Vec::with_capacity(st.rows() as usize);
    for r in 0..st.rows() {
        let sbl: Vec<u64> = st.list_u64(r, 10)?.collect();
        let spacebase = sbl.chunks_exact(3).map(|c| (Address::new(SpaceId(c[0] as u32), c[1]), c[2] as u32)).collect();
        spaces.push(Space {
            id: SpaceId(st.u64(r, 0)? as u32),
            name: st.str(r, 1)?.to_string(),
            kind: space_kind(st.u64(r, 2)? as u8)?,
            addr_size: st.u64(r, 3)? as u32,
            big_endian: st.bool(r, 4)?,
            wordsize: st.u64(r, 5)? as u32,
            delay: st.i64(r, 6)? as i32,
            deadcodedelay: st.i64(r, 7)? as i32,
            spacebase,
            contain: st.bool(r, 8)?.then(|| SpaceId(st.u64(r, 9).unwrap_or(0) as u32)),
        });
    }
    let sm = SpaceManager::from_spaces(spaces);
    let default_space = SpaceId(pt.u64(0, 11)? as u32);
    let mut p = Program::new(sm, default_space, pt.str(0, 0)?, pt.str(0, 1)?, addr(pt, 0, 7, 8)?, pt.bool(0, 9)?, pt.u64(0, 10)? as u32);
    p.compiler = pt.str(0, 2)?.to_string();
    p.compiler_version = pt.bool(0, 4)?.then(|| pt.str(0, 3).unwrap_or("").to_string());
    p.compiler_signature = pt.bool(0, 6)?.then(|| pt.str(0, 5).unwrap_or("").to_string());
    p.relocation_table.set_relocatable(pt.bool(0, 12)?);

    // blocks
    let bt = set.table("blocks")?;
    let blob = set.blob("bytes")?;
    for r in 0..bt.rows() {
        let start = addr(bt, r, 0, 1)?;
        let end = bt.u64(r, 2)?;
        let len = end - start.offset + 1;
        let bytes = if bt.bool(r, 7)? {
            let (off, blen) = (bt.u64(r, 8)? as usize, bt.u64(r, 9)? as usize);
            Some(blob.get(off..off + blen).ok_or_else(|| Error::Format("block bytes outside the blob".into()))?.to_vec())
        } else {
            None
        };
        p.memory.add_block(bt.str(r, 3)?, start, len, bt.bool(r, 4)?, bt.bool(r, 5)?, bt.bool(r, 6)?, bytes);
    }
    // functions + bodies
    let ft = set.table("functions")?;
    let bo = set.table("bodies")?;
    let mut bodies: HashMap<(u32, u64), mosura_core::analysis::program::AddressSet> = HashMap::new();
    for r in 0..bo.rows() {
        let key = (bo.u64(r, 0)? as u32, bo.u64(r, 1)?);
        bodies.entry(key).or_default().add_range(SpaceId(bo.u64(r, 2)? as u32), bo.u64(r, 3)?, bo.u64(r, 4)?);
    }
    for r in 0..ft.rows() {
        let entry = addr(ft, r, 0, 1)?;
        let body = bodies.remove(&(entry.space.0, entry.offset)).unwrap_or_default();
        p.function_manager.create_function(entry, ft.str(r, 2)?, body);
    }
    // symbols
    let syt = set.table("symbols")?;
    for r in 0..syt.rows() {
        p.symbol_table.add(Symbol { address: addr(syt, r, 0, 1)?, name: syt.str(r, 2)?.to_string(), symbol_type: symbol_type(syt.u64(r, 3)? as u8)?, primary: syt.bool(r, 4)?, external: syt.bool(r, 5)? });
    }
    // references
    let rt = set.table("references")?;
    for r in 0..rt.rows() {
        p.reference_manager.add(addr(rt, r, 0, 1)?, addr(rt, r, 2, 3)?, ref_type(rt.u64(r, 4)? as u8)?, rt.i64(r, 5)? as i32);
    }
    // listing
    let lt = set.table("listing")?;
    for r in 0..lt.rows() {
        let a = addr(lt, r, 0, 1)?;
        let length = lt.u64(r, 2)? as u32;
        let unit = if lt.u64(r, 3)? == 0 {
            CodeUnit::Instruction {
                length,
                flow: InstructionFlow { kind: flow_kind(lt.u64(r, 4)? as u8, lt.u64(r, 5)? as u8)?, flows: lt.list_u64(r, 9)?.collect(), ends_flow: lt.bool(r, 6)?, call_target: lt.bool(r, 7)?.then(|| lt.u64(r, 8).unwrap_or(0)) },
            }
        } else {
            CodeUnit::Data { length, type_name: lt.str(r, 10)?.to_string() }
        };
        p.listing.define(a, unit);
    }
    // relocations, entry points, comments, indirect branches, noreturn, defined data, overrides
    let rl = set.table("relocations")?;
    for r in 0..rl.rows() {
        p.relocation_table.add(addr(rl, r, 0, 1)?, rl.u64(r, 2)?);
    }
    let ep = set.table("entry_points")?;
    for r in 0..ep.rows() {
        p.entry_points.push(addr(ep, r, 0, 1)?);
    }
    let ct = set.table("comments")?;
    for r in 0..ct.rows() {
        p.comments.insert((ct.u64(r, 0)?, comment_kind(ct.u64(r, 1)? as u8)?), ct.str(r, 2)?.to_string());
    }
    let ib = set.table("indirect_branches")?;
    for r in 0..ib.rows() {
        p.indirect_branches.insert(ib.u64(r, 0)?);
    }
    let nr = set.table("noreturn")?;
    for r in 0..nr.rows() {
        p.noreturn_functions.insert((nr.u64(r, 0)? as u32, nr.u64(r, 1)?));
    }
    let dd = set.table("defined_data")?;
    for r in 0..dd.rows() {
        p.defined_data.push((addr(dd, r, 0, 1)?, dd.str(r, 2)?.to_string(), dd.u64(r, 3)? as u32));
    }
    let fo = set.table("flow_overrides")?;
    for r in 0..fo.rows() {
        p.flow_overrides.insert((fo.u64(r, 0)? as u32, fo.u64(r, 1)?), flow_override(fo.u64(r, 2)? as u8)?);
    }
    let fa = set.table("facts")?;
    for r in 0..fa.rows() {
        if fa.u64(r, 1)? == 0 {
            p.tail_return_writes.insert(fa.u64(r, 0)?);
        }
    }
    // protos
    let pr = set.table("protos")?;
    let ps = set.table("proto_slots")?;
    let mut slots: HashMap<u64, Vec<(u32, ProtoSlot)>> = HashMap::new();
    for r in 0..ps.rows() {
        slots.entry(ps.u64(r, 0)?).or_default().push((ps.u64(r, 1)? as u32, ProtoSlot { addr: addr(ps, r, 2, 3)?, size: ps.u64(r, 4)? as u32 }));
    }
    for r in 0..pr.rows() {
        let fnva = pr.u64(r, 0)?;
        let mut params = slots.remove(&fnva).unwrap_or_default();
        params.sort_by_key(|s| s.0);
        let output = pr.bool(r, 1)?.then(|| ProtoSlot { addr: Address::new(SpaceId(pr.u64(r, 2).unwrap_or(0) as u32), pr.u64(r, 3).unwrap_or(0)), size: pr.u64(r, 4).unwrap_or(0) as u32 });
        let model = if pr.bool(r, 5)? { Some(read_model(set, pr.u64(r, 6)? as u32)?) } else { None };
        p.recovered_protos.insert(fnva, FuncProto { params: params.into_iter().map(|s| s.1).collect(), output, model });
    }
    // sret
    let types = set.table("types")?;
    let sf = set.table("sret_facts")?;
    let sfl = set.table("sret_fields")?;
    let mut fields: HashMap<u64, Vec<(u32, (u32, u32, Datatype))>> = HashMap::new();
    for r in 0..sfl.rows() {
        fields.entry(sfl.u64(r, 0)?).or_default().push((sfl.u64(r, 1)? as u32, (sfl.u64(r, 2)? as u32, sfl.u64(r, 3)? as u32, datatype_at(types, sfl.u64(r, 4)? as u32)?)));
    }
    for r in 0..sf.rows() {
        let fnva = sf.u64(r, 0)?;
        let shape = if sf.bool(r, 1)? {
            let mut f = fields.remove(&fnva).unwrap_or_default();
            f.sort_by_key(|x| x.0);
            Some(SretShape { slot: addr(sf, r, 2, 3)?, size: sf.u64(r, 4)? as u32, fields: f.into_iter().map(|x| x.1).collect() })
        } else {
            None
        };
        p.recovered_sret.insert(fnva, SretFact { shape, ret_pop: sf.bool(r, 5)?.then(|| sf.u64(r, 6).unwrap_or(0) as u32) });
    }
    let sc = set.table("sret_callers")?;
    let mut callers: BTreeMap<u64, Vec<(u32, CallEvidence)>> = BTreeMap::new();
    for r in 0..sc.rows() {
        callers.entry(sc.u64(r, 0)?).or_default().push((sc.u64(r, 1)? as u32, CallEvidence { output_dead: sc.bool(r, 2)?, arg0_local_addr: sc.bool(r, 3)? }));
    }
    for (callee, mut evs) in callers {
        evs.sort_by_key(|e| e.0);
        p.sret_callers.insert(callee, evs.into_iter().map(|e| e.1).collect());
    }
    // the options' share
    p.knobs = knobs;
    p.global_scope_all_loaded = settings.global_scope_all_loaded;
    p.proto_scope = settings.proto_scope.clone().map(|s| s.into_iter().collect::<HashSet<u64>>());
    Ok(p)
}

/// The Snapshot v1 text of a frozen program — the analysis golden format, rendered by the core
/// from a thawed program (one implementation of the format; parity is structural).
pub fn snapshot_text(set: &TableSet) -> Result<String> {
    let p = thaw(set, Knobs::default(), &DecompileSettings { global_scope_all_loaded: true, proto_scope: None })?;
    Ok(p.snapshot().render())
}

/// The snapshot as a `text` table — `program.tables` serves it under the virtual name
/// `snapshot`, and `render(TEXT)` prints the golden format bare.
pub fn snapshot_table(set: &TableSet) -> Result<Table> {
    Ok(crate::render::text_table(&snapshot_text(set)?))
}
