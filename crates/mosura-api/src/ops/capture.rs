//! `function.capture`: many input vectors through one function of a session program, over one
//! decoded image whose bytes are the machine's memory (`docs/emulation.md`, "Capturing vectors").
//! A specification — JSON text in `capture.spec` — names the inputs and outputs as pieces of
//! registers and memory, the seeds every vector shares, and the generators that produce the rows;
//! the answer is one `capture` row per vector, with its outputs when it returned and the reason its
//! run stopped. The generators are the reference executor's, draw for draw (splitmix64, Lemire's
//! multiply-shift, the log2-uniform bit length), so a specification converted from its format
//! produces the same vectors.

use std::collections::HashSet;

use serde_json::{Map, Value};

use crate::error::{Error, Result};
use crate::options::{keys, Options};
use crate::ops::emulate::{prepare, program_blocks, stored_state, with_stack, RegisterNames, Seeds};
use crate::ops::function::entry_of;
use crate::ops::program::program_of;
use crate::ops::schemas::CAPTURE;
use crate::ops::sleigh::parse_bytes;
use crate::ops::{Cache, Op, Progress, Tier};
use crate::session::Session;
use crate::table::builder::TableBuilder;
use crate::table::Table;
use mosura_core::sleigh::emu::{Image, RunOptions, Stop};
use mosura_core::sleigh::engine::Spec;

pub static FUNCTION_CAPTURE: Op = Op { name: "function.capture", doc: "run many input vectors through one function (entry) of a program over one decoded image, the program's loaded image as memory: capture.spec (JSON) names the inputs and outputs as register and memory pieces, the seeds every vector shares and the generators (explicit, range, sample, chain); emulate.state is every vector's starting state. One row per vector: case, generator, inputs, outputs (when it returned), stop, address, steps, unmodeled, uninitialized (registers read before anything wrote them), unanswered (ports read that the specification's ports did not answer)", since: "0.1", tier: Tier::Product, params: &["program", "entry", keys::CAPTURE_SPEC, keys::EMULATE_STATE], result: "capture", cache: Cache::Transient, run: capture };

/// `size` bytes at `offset` in `space`, holding the value's bits from `shift` up.
struct Piece {
    space: String,
    offset: u64,
    size: u32,
    shift: u32,
}

/// A logical input or output: a `bits`-wide unsigned value assembled from pieces.
struct Slot {
    name: String,
    bits: u32,
    pieces: Vec<Piece>,
}

enum Gen {
    /// Fixed rows, one value per input.
    Explicit { rows: Vec<Vec<u64>> },
    /// Every value of one input in `[from, to]`, the others fixed.
    Range { input: usize, from: u64, to: u64, fixed: Vec<u64> },
    /// `count` seeded rows, each input drawn in its range and mapped through `offset + scale * draw`.
    Sample { count: u64, seed: u64, log2: bool, ranges: Vec<(u64, u64)>, maps: Vec<(i64, u64)> },
    /// `count` rows, each next row's inputs fed from the previous row's outputs.
    Chain { count: u64, start: Vec<u64>, feed: Vec<(usize, usize)> },
}

impl Gen {
    /// How many rows the generator can produce (before duplicates and chain ends).
    fn rows(&self) -> u64 {
        match self {
            Gen::Explicit { rows } => rows.len() as u64,
            Gen::Range { from, to, .. } => (to - from).saturating_add(1),
            Gen::Sample { count, .. } | Gen::Chain { count, .. } => *count,
        }
    }
}

struct CaptureSpec {
    fixed: Seeds,
    follow_calls: bool,
    stubs: std::collections::BTreeSet<u64>,
    max_steps: usize,
    inputs: Vec<Slot>,
    outputs: Vec<Slot>,
    cases: Vec<Gen>,
}

fn mask(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

fn bad(what: &str, why: impl std::fmt::Display) -> Error {
    Error::InvalidArg(format!("{}: {what}: {why}", keys::CAPTURE_SPEC))
}

/// A number: a JSON non-negative integer, or a string in decimal or `0x` hex.
fn num(v: Option<&Value>, what: &str) -> Result<u64> {
    match v {
        Some(Value::Number(n)) => n.as_u64().ok_or_else(|| bad(what, "not a non-negative integer")),
        Some(Value::String(s)) => {
            let t = s.trim();
            let parsed = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                Some(h) => u64::from_str_radix(h, 16).ok(),
                None => t.parse::<u64>().ok(),
            };
            parsed.ok_or_else(|| bad(what, format!("`{s}` is not a number")))
        }
        Some(_) => Err(bad(what, "not a number")),
        None => Err(bad(what, "missing")),
    }
}

/// A signed number (a JSON integer, or a decimal string with an optional `-`), `default` when absent.
fn snum(v: Option<&Value>, what: &str, default: i64) -> Result<i64> {
    match v {
        None => Ok(default),
        Some(Value::Number(n)) => n.as_i64().ok_or_else(|| bad(what, "not an integer")),
        Some(Value::String(s)) => s.trim().parse::<i64>().map_err(|_| bad(what, format!("`{s}` is not an integer"))),
        Some(_) => Err(bad(what, "not an integer")),
    }
}

fn object<'a>(v: &'a Value, what: &str) -> Result<&'a Map<String, Value>> {
    v.as_object().ok_or_else(|| bad(what, "not an object"))
}

fn array<'a>(v: Option<&'a Value>, what: &str) -> Result<&'a Vec<Value>> {
    v.ok_or_else(|| bad(what, "missing"))?.as_array().ok_or_else(|| bad(what, "not an array"))
}

fn string<'a>(v: Option<&'a Value>, what: &str) -> Result<&'a str> {
    v.ok_or_else(|| bad(what, "missing"))?.as_str().ok_or_else(|| bad(what, "not a string"))
}

/// Refuse any key but `allowed` and `note` (a comment, allowed on every object with fixed keys).
fn only(m: &Map<String, Value>, allowed: &[&str], what: &str) -> Result<()> {
    match m.keys().find(|k| k.as_str() != "note" && !allowed.contains(&k.as_str())) {
        Some(k) => Err(bad(what, format!("unknown key `{k}` (expected {})", allowed.join(", ")))),
        None => Ok(()),
    }
}

fn parse_piece(v: &Value, spec: &Spec, lang: &str, what: &str) -> Result<Piece> {
    let m = object(v, what)?;
    let shift = match m.get("shift") {
        None => 0,
        s => num(s, &format!("{what}.shift"))?,
    };
    if shift >= 64 {
        return Err(bad(what, "shift must be below 64"));
    }
    if let Some(r) = m.get("register") {
        only(m, &["register", "shift"], what)?;
        let name = r.as_str().ok_or_else(|| bad(what, "register must be a name"))?;
        let (Some(offset), Some(size)) = (spec.register_offset(name), spec.register_size(name)) else {
            return Err(bad(what, format!("`{name}` is not a register of {lang}")));
        };
        if size > 8 {
            return Err(bad(what, format!("`{name}` is wider than eight bytes")));
        }
        return Ok(Piece { space: "register".into(), offset, size, shift: shift as u32 });
    }
    only(m, &["space", "offset", "size", "shift"], what)?;
    let space = string(m.get("space"), &format!("{what}.space"))?;
    if matches!(space, "const" | "unique") || !spec.spaces.iter().any(|s| s.name == space) {
        return Err(bad(what, format!("`{space}` is not a register or memory space of {lang}")));
    }
    let size = num(m.get("size"), &format!("{what}.size"))?;
    if !(1..=8).contains(&size) {
        return Err(bad(what, "size must be 1 to 8 bytes"));
    }
    Ok(Piece { space: space.to_string(), offset: num(m.get("offset"), &format!("{what}.offset"))?, size: size as u32, shift: shift as u32 })
}

fn parse_slots(v: Option<&Value>, spec: &Spec, lang: &str, what: &str) -> Result<Vec<Slot>> {
    let mut slots: Vec<Slot> = Vec::new();
    for (i, s) in array(v, what)?.iter().enumerate() {
        let sw = format!("{what}[{i}]");
        let m = object(s, &sw)?;
        only(m, &["name", "bits", "pieces"], &sw)?;
        let name = string(m.get("name"), &format!("{sw}.name"))?.to_string();
        if slots.iter().any(|x| x.name == name) {
            return Err(bad(&sw, format!("`{name}` is named twice")));
        }
        let bits = num(m.get("bits"), &format!("{sw}.bits"))?;
        if !(1..=64).contains(&bits) {
            return Err(bad(&sw, "bits must be 1 to 64"));
        }
        let pieces = array(m.get("pieces"), &format!("{sw}.pieces"))?
            .iter()
            .enumerate()
            .map(|(j, p)| parse_piece(p, spec, lang, &format!("{sw}.pieces[{j}]")))
            .collect::<Result<Vec<_>>>()?;
        if pieces.is_empty() {
            return Err(bad(&sw, "no pieces"));
        }
        slots.push(Slot { name, bits: bits as u32, pieces });
    }
    Ok(slots)
}

fn slot_index(slots: &[Slot], name: &str, what: &str) -> Result<usize> {
    slots.iter().position(|s| s.name == name).ok_or_else(|| bad(what, format!("no slot named `{name}`")))
}

/// A row from an object of `input name -> value`; every input present unless `defaults` has it.
fn parse_row(v: &Value, inputs: &[Slot], defaults: Option<&[u64]>, what: &str) -> Result<Vec<u64>> {
    let m = object(v, what)?;
    if let Some(k) = m.keys().find(|k| !inputs.iter().any(|s| &s.name == *k)) {
        return Err(bad(what, format!("unknown input `{k}`")));
    }
    let mut row = Vec::with_capacity(inputs.len());
    for (i, slot) in inputs.iter().enumerate() {
        let value = match (m.get(&slot.name), defaults) {
            (Some(x), _) => num(Some(x), &format!("{what}.{}", slot.name))?,
            (None, Some(d)) => d[i],
            (None, None) => return Err(bad(what, format!("missing input `{}`", slot.name))),
        };
        if value & !mask(slot.bits) != 0 {
            return Err(bad(what, format!("`{}` = {value:#x} is wider than {} bits", slot.name, slot.bits)));
        }
        row.push(value);
    }
    Ok(row)
}

fn parse_spec(text: &str, spec: &Spec, lang: &str) -> Result<CaptureSpec> {
    let v: Value = serde_json::from_str(text).map_err(|e| bad("not JSON", e))?;
    let top = "the specification";
    let m = object(&v, top)?;
    only(m, &["registers", "memory", "ports", "stubs", "follow_calls", "max_steps", "inputs", "outputs", "cases"], top)?;
    let mut fixed = Seeds { registers: Vec::new(), memory: Vec::new(), ports: Vec::new() };
    if let Some(r) = m.get("registers") {
        for (name, value) in object(r, "registers")? {
            let (Some(offset), Some(size)) = (spec.register_offset(name), spec.register_size(name)) else {
                return Err(bad("registers", format!("`{name}` is not a register of {lang}")));
            };
            let value = num(Some(value), &format!("registers.{name}"))?;
            if size < 8 && value >> (8 * size) != 0 {
                return Err(bad("registers", format!("{name} = {value:#x} is wider than {size} bytes")));
            }
            fixed.registers.push((offset, size, value));
        }
    }
    if let Some(list) = m.get("memory") {
        for (i, e) in array(Some(list), "memory")?.iter().enumerate() {
            let mw = format!("memory[{i}]");
            let em = object(e, &mw)?;
            only(em, &["address", "bytes"], &mw)?;
            let address = num(em.get("address"), &format!("{mw}.address"))?;
            let bytes = parse_bytes(string(em.get("bytes"), &format!("{mw}.bytes"))?).map_err(|e| bad(&mw, e))?;
            fixed.memory.push((address, bytes));
        }
    }
    if let Some(p) = m.get("ports") {
        for (port, values) in object(p, "ports")? {
            let pw = format!("ports.{port}");
            let number = num(Some(&Value::String(port.clone())), &pw)?;
            let values = match values {
                Value::Array(list) => list.iter().enumerate().map(|(i, v)| num(Some(v), &format!("{pw}[{i}]"))).collect::<Result<Vec<u64>>>()?,
                v => vec![num(Some(v), &pw)?],
            };
            if values.is_empty() {
                return Err(bad(&pw, "no values"));
            }
            fixed.ports.push((number, values));
        }
    }
    let follow_calls = match m.get("follow_calls") {
        None => false,
        Some(b) => b.as_bool().ok_or_else(|| bad("follow_calls", "not a boolean"))?,
    };
    let stubs = match m.get("stubs") {
        None => Default::default(),
        s => array(s, "stubs")?.iter().enumerate().map(|(i, a)| num(Some(a), &format!("stubs[{i}]"))).collect::<Result<_>>()?,
    };
    let max_steps = match m.get("max_steps") {
        None => RunOptions::default().max_steps,
        s => num(s, "max_steps")? as usize,
    };
    if max_steps == 0 {
        return Err(bad("max_steps", "must be positive"));
    }
    let inputs = parse_slots(m.get("inputs"), spec, lang, "inputs")?;
    let outputs = parse_slots(m.get("outputs"), spec, lang, "outputs")?;
    if outputs.is_empty() {
        return Err(bad("outputs", "a capture needs at least one output"));
    }
    let mut cases = Vec::new();
    for (i, c) in array(m.get("cases"), "cases")?.iter().enumerate() {
        let cw = format!("cases[{i}]");
        let cm = object(c, &cw)?;
        let kind = string(cm.get("kind"), &format!("{cw}.kind"))?;
        cases.push(match kind {
            "explicit" => {
                only(cm, &["kind", "rows"], &cw)?;
                let rows = array(cm.get("rows"), &format!("{cw}.rows"))?
                    .iter()
                    .enumerate()
                    .map(|(j, r)| parse_row(r, &inputs, None, &format!("{cw}.rows[{j}]")))
                    .collect::<Result<_>>()?;
                Gen::Explicit { rows }
            }
            "range" => {
                only(cm, &["kind", "input", "from", "to", "fixed"], &cw)?;
                let input = slot_index(&inputs, string(cm.get("input"), &format!("{cw}.input"))?, &cw)?;
                let from = num(cm.get("from"), &format!("{cw}.from"))?;
                let to = num(cm.get("to"), &format!("{cw}.to"))?;
                if from > to || to & !mask(inputs[input].bits) != 0 {
                    return Err(bad(&cw, format!("{from:#x}..={to:#x} is not a range of `{}`", inputs[input].name)));
                }
                let zero = vec![0u64; inputs.len()];
                let fixed = match cm.get("fixed") {
                    Some(f) => parse_row(f, &inputs, Some(&zero), &format!("{cw}.fixed"))?,
                    None => zero,
                };
                Gen::Range { input, from, to, fixed }
            }
            "sample" => {
                only(cm, &["kind", "count", "seed", "distribution", "inputs"], &cw)?;
                let count = num(cm.get("count"), &format!("{cw}.count"))?;
                let seed = num(cm.get("seed"), &format!("{cw}.seed"))?;
                let log2 = match cm.get("distribution").map(|d| d.as_str()) {
                    None | Some(Some("uniform")) => false,
                    Some(Some("log2-uniform")) => true,
                    Some(d) => return Err(bad(&cw, format!("unknown distribution {d:?} (uniform or log2-uniform)"))),
                };
                let per_input = match cm.get("inputs") {
                    Some(x) => Some(object(x, &format!("{cw}.inputs"))?),
                    None => None,
                };
                if let Some(k) = per_input.and_then(|p| p.keys().find(|k| !inputs.iter().any(|s| &s.name == *k))) {
                    return Err(bad(&cw, format!("unknown input `{k}`")));
                }
                let mut ranges = Vec::new();
                let mut maps = Vec::new();
                for slot in &inputs {
                    let sw = format!("{cw}.inputs.{}", slot.name);
                    let r = match per_input.and_then(|p| p.get(&slot.name)) {
                        Some(r) => {
                            let rm = object(r, &sw)?;
                            only(rm, &["min", "max", "scale", "offset"], &sw)?;
                            Some(rm)
                        }
                        None => None,
                    };
                    let min = match r.and_then(|r| r.get("min")) {
                        Some(x) => num(Some(x), &format!("{sw}.min"))?,
                        None => 0,
                    };
                    let max = match r.and_then(|r| r.get("max")) {
                        Some(x) => num(Some(x), &format!("{sw}.max"))?,
                        None => mask(slot.bits),
                    };
                    if min > max || max & !mask(slot.bits) != 0 {
                        return Err(bad(&sw, format!("{min:#x}..={max:#x} is not a range of {} bits", slot.bits)));
                    }
                    let scale = snum(r.and_then(|r| r.get("scale")), &format!("{sw}.scale"), 1)?;
                    if scale == 0 {
                        return Err(bad(&sw, "scale must not be 0"));
                    }
                    let offset = match r.and_then(|r| r.get("offset")) {
                        Some(x) => num(Some(x), &format!("{sw}.offset"))?,
                        None => 0,
                    };
                    ranges.push((min, max));
                    maps.push((scale, offset));
                }
                Gen::Sample { count, seed, log2, ranges, maps }
            }
            "chain" => {
                only(cm, &["kind", "count", "start", "feed"], &cw)?;
                let count = num(cm.get("count"), &format!("{cw}.count"))?;
                let start = parse_row(cm.get("start").ok_or_else(|| bad(&cw, "missing start"))?, &inputs, None, &format!("{cw}.start"))?;
                let mut feed = Vec::new();
                for (j, f) in array(cm.get("feed"), &format!("{cw}.feed"))?.iter().enumerate() {
                    let fw = format!("{cw}.feed[{j}]");
                    let fm = object(f, &fw)?;
                    only(fm, &["output", "input"], &fw)?;
                    let out = slot_index(&outputs, string(fm.get("output"), &format!("{fw}.output"))?, &fw)?;
                    let inp = slot_index(&inputs, string(fm.get("input"), &format!("{fw}.input"))?, &fw)?;
                    feed.push((out, inp));
                }
                if feed.is_empty() {
                    return Err(bad(&cw, "feed is empty"));
                }
                Gen::Chain { count, start, feed }
            }
            k => return Err(bad(&cw, format!("unknown kind `{k}` (explicit, range, sample, chain)"))),
        });
    }
    Ok(CaptureSpec { fixed, follow_calls, stubs, max_steps, inputs, outputs, cases })
}

/// The reference executor's seeded generator: splitmix64 (Vigna), one 64-bit draw per call.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    /// A value in `[0, n)` by Lemire's multiply-shift; `n == 0` means the whole 64-bit range.
    fn below(&mut self, n: u64) -> u64 {
        let r = self.next();
        if n == 0 {
            r
        } else {
            ((r as u128 * n as u128) >> 64) as u64
        }
    }
    fn in_range(&mut self, min: u64, max: u64) -> u64 {
        let span = max.wrapping_sub(min).wrapping_add(1);
        min.wrapping_add(self.below(span))
    }
    /// A bit length uniform over those of `[min, max]`, then a value uniform within it; a value
    /// outside the range is drawn again, up to 64 times, then a uniform draw is used.
    fn log2_in_range(&mut self, min: u64, max: u64) -> u64 {
        let bitlen = |x: u64| 64 - x.leading_zeros();
        let (lo, hi) = (bitlen(min), bitlen(max));
        for _ in 0..64 {
            let b = lo + self.below((hi - lo + 1) as u64) as u32;
            let v = if b == 0 {
                0
            } else {
                let half = 1u64 << (b - 1);
                half | (self.next() & (half - 1))
            };
            if v >= min && v <= max {
                return v;
            }
        }
        self.in_range(min, max)
    }
}

/// Runs vectors over one image and writes their rows.
struct Runner<'a> {
    image: Image<'a>,
    spec: &'a Spec,
    names: RegisterNames,
    cs: &'a CaptureSpec,
    state: Vec<(String, u64, Vec<u8>)>,
    opts: RunOptions,
    seen: HashSet<Vec<u64>>,
    b: TableBuilder,
    case: u64,
    total: u64,
}

impl Runner<'_> {
    /// Run one vector (skipped when an earlier generator produced the same row) and write its row;
    /// the outputs, when the run returned with nothing unmodeled — what a chain may feed on.
    fn take(&mut self, generator: u32, row: Vec<u64>, prog: &mut dyn Progress) -> Result<Option<Vec<u64>>> {
        if !self.seen.insert(row.clone()) {
            return Ok(None);
        }
        self.case += 1;
        if self.case.is_multiple_of(256) && !prog.report("capture", self.case, self.total) {
            return Err(Error::Cancelled);
        }
        let mut m = prepare(&self.image, self.spec, &self.state, &self.cs.fixed);
        for (slot, value) in self.cs.inputs.iter().zip(&row) {
            for p in &slot.pieces {
                m.write(&p.space, p.offset, p.size, value >> p.shift);
            }
        }
        let run = self.image.resume(m, &self.opts);
        let (stop, address) = match run.stop {
            Stop::Returned => ("returned", 0),
            Stop::Fault => ("fault", 0),
            Stop::NoInstruction(a) => ("no-instruction", a),
            Stop::StepCap => ("step-cap", 0),
        };
        let outputs: Vec<u64> = if run.stop == Stop::Returned {
            self.cs
                .outputs
                .iter()
                .map(|slot| {
                    let v = slot.pieces.iter().fold(0u64, |v, p| v | ((run.machine.read(&p.space, p.offset, p.size) & mask(p.size * 8)) << p.shift));
                    v & mask(slot.bits)
                })
                .collect()
        } else {
            Vec::new()
        };
        let unmodeled: Vec<&str> = run.machine.unmodeled_ops.iter().map(String::as_str).collect();
        let uninitialized: Vec<String> = run.machine.uninitialized_registers().into_iter().map(|(off, size, _)| self.names.name(off, size)).collect();
        let unanswered: Vec<u64> = run.machine.unanswered_ports().into_iter().map(|(port, _)| port).collect();
        self.b.row().u64(self.case).u32(generator).list_u64(&row).list_u64(&outputs).str(stop).u64(address).u64(run.steps as u64).u64(run.machine.unmodeled as u64).str(&unmodeled.join(",")).str(&uninitialized.join(",")).list_u64(&unanswered);
        Ok((run.stop == Stop::Returned && run.machine.unmodeled == 0).then_some(outputs))
    }
}

fn capture(s: &mut Session, o: &Options, prog: &mut dyn Progress) -> Result<Table> {
    let (_, p) = program_of(s, o)?;
    let entry = entry_of(&p, o)?;
    let (spec, ctx) = mosura_core::lang::load_cached(&p.language_id).ok_or_else(|| Error::NotFound(format!("language `{}` (tables unavailable)", p.language_id)))?;
    let text = o.get(keys::CAPTURE_SPEC)?;
    if text.trim().is_empty() {
        return Err(Error::InvalidArg(format!("`{}` is required (a capture specification, JSON; docs/emulation.md)", keys::CAPTURE_SPEC)));
    }
    let cs = parse_spec(text, spec, &p.language_id)?;
    let state = stored_state(s, o)?;
    let blocks = program_blocks(&p);
    let mut runner = Runner {
        image: with_stack(Image::from_blocks(spec, &blocks, ctx).with_image_memory(), spec, &p.language_id, &p.compiler_spec_id),
        spec,
        names: RegisterNames::of(spec),
        cs: &cs,
        state,
        opts: RunOptions { entry: Some(entry), follow_calls: cs.follow_calls, max_steps: cs.max_steps, stubs: cs.stubs.clone(), ..RunOptions::default() },
        seen: HashSet::new(),
        b: TableBuilder::new(&CAPTURE),
        case: 0,
        total: cs.cases.iter().fold(0u64, |n, g| n.saturating_add(g.rows())),
    };
    for (g, gen) in cs.cases.iter().enumerate() {
        let g = g as u32;
        match gen {
            Gen::Explicit { rows } => {
                for r in rows {
                    runner.take(g, r.clone(), prog)?;
                }
            }
            Gen::Range { input, from, to, fixed } => {
                let mut v = *from;
                loop {
                    let mut row = fixed.clone();
                    row[*input] = v;
                    runner.take(g, row, prog)?;
                    if v == *to {
                        break;
                    }
                    v += 1;
                }
            }
            Gen::Sample { count, seed, log2, ranges, maps } => {
                let mut rng = SplitMix64(*seed);
                for _ in 0..*count {
                    let row: Vec<u64> = ranges
                        .iter()
                        .zip(maps)
                        .zip(&cs.inputs)
                        .map(|((&(min, max), &(scale, offset)), slot)| {
                            let draw = if *log2 { rng.log2_in_range(min, max) } else { rng.in_range(min, max) };
                            offset.wrapping_add((draw as i64).wrapping_mul(scale) as u64) & mask(slot.bits)
                        })
                        .collect();
                    runner.take(g, row, prog)?;
                }
            }
            Gen::Chain { count, start, feed } => {
                let mut row = start.clone();
                for _ in 0..*count {
                    let Some(outs) = runner.take(g, row.clone(), prog)? else { break };
                    for &(out, inp) in feed {
                        row[inp] = outs[out] & mask(cs.inputs[inp].bits);
                    }
                }
            }
        }
    }
    prog.report("capture", runner.case, runner.case);
    Ok(runner.b.finish(true))
}
