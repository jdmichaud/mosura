//! The operations that execute original code through the p-code interpreter (`sleigh::emu`;
//! `docs/emulation.md`): `sleigh.emulate` over raw bytes and `function.emulate` over a function of
//! a session program. In both the image is the machine's memory as well as its code — the bytes
//! given, or the program's loaded blocks — as it is for a loaded program.

use crate::error::{Error, Result};
use crate::options::{keys, parse_bool, parse_hex, Options};
use crate::ops::function::entry_of;
use crate::ops::program::program_of;
use crate::ops::schemas::EMULATION;
use crate::ops::sleigh::{inputs, parse_bytes};
use crate::ops::{Cache, Op, Progress, Tier};
use crate::session::schemas::MACHINE_STATE;
use crate::session::Session;
use crate::table::builder::TableBuilder;
use crate::table::Table;
use mosura_core::analysis::program::Program;
use mosura_core::sleigh::emu::{Effect, Image, Machine, Run, RunOptions, Stop};
use mosura_core::sleigh::engine::Spec;

pub static SLEIGH_EMULATE: Op = Op { name: "sleigh.emulate", doc: "execute the p-code of raw bytes from base (or emulate.entry) over an initial state (emulate.registers, emulate.memory; the bytes themselves are memory too) until the routine returns, faults, reaches an address with no instruction, or spends emulate.max-steps; a call is an event unless emulate.follow-calls. Rows: outcome (stop = returned | fault | no-instruction | step-cap, address, steps, unmodeled, unmodeled-op), register (every register the final state holds, widest first), memory (every run of bytes it holds, as hex), and with emulate.effects every effect of the run in order; emulate.state starts from a stored machine state, emulate.save-state stores the one the run stopped in", since: "0.1", tier: Tier::Product, params: &["lang", "bytes", "base", "ctx", keys::EMULATE_ENTRY, keys::EMULATE_REGISTERS, keys::EMULATE_MEMORY, keys::EMULATE_FOLLOW_CALLS, keys::EMULATE_MAX_STEPS, keys::EMULATE_EFFECTS, keys::EMULATE_STATE, keys::EMULATE_SAVE_STATE], result: "emulation", cache: Cache::Transient, run: sleigh_emulate };
pub static FUNCTION_EMULATE: Op = Op { name: "function.emulate", doc: "execute one function (entry) of a program through the p-code interpreter, with the program's loaded image as memory, over an initial state (emulate.registers, emulate.memory) until it returns, faults, reaches an address with no instruction, or spends emulate.max-steps; a call is an event unless emulate.follow-calls. Rows as sleigh.emulate", since: "0.1", tier: Tier::Product, params: &["program", "entry", keys::EMULATE_REGISTERS, keys::EMULATE_MEMORY, keys::EMULATE_FOLLOW_CALLS, keys::EMULATE_MAX_STEPS, keys::EMULATE_EFFECTS, keys::EMULATE_STATE, keys::EMULATE_SAVE_STATE], result: "emulation", cache: Cache::Transient, run: function_emulate };

/// The run settings every emulate operation reads.
struct Settings {
    follow_calls: bool,
    max_steps: usize,
    effects: bool,
}

impl Settings {
    fn run_options(&self, entry: Option<u64>) -> RunOptions {
        RunOptions { entry, follow_calls: self.follow_calls, max_steps: self.max_steps, trace: self.effects }
    }
}

fn flag(o: &Options, key: &str) -> Result<bool> {
    match o.get(key)? {
        "" => Ok(false),
        v => parse_bool(v).ok_or_else(|| Error::InvalidArg(format!("`{key}` is not a boolean: {v}"))),
    }
}

fn settings(o: &Options) -> Result<Settings> {
    let follow_calls = flag(o, keys::EMULATE_FOLLOW_CALLS)?;
    let max_steps = match o.get(keys::EMULATE_MAX_STEPS)? {
        "" => RunOptions::default().max_steps,
        v => v.trim().parse::<usize>().map_err(|_| Error::InvalidArg(format!("`{}` is not a count: {v}", keys::EMULATE_MAX_STEPS)))?,
    };
    Ok(Settings { follow_calls, max_steps, effects: flag(o, keys::EMULATE_EFFECTS)? })
}

/// The initial state an operation names: registers by the language's names, memory as bytes.
pub(crate) struct Seeds {
    /// `(offset, size, value)` in the register space.
    pub(crate) registers: Vec<(u64, u32, u64)>,
    /// `(address, bytes)` in the language's default space.
    pub(crate) memory: Vec<(u64, Vec<u8>)>,
}

fn seeds(o: &Options, spec: &Spec, lang: &str) -> Result<Seeds> {
    let mut registers = Vec::new();
    for part in o.get(keys::EMULATE_REGISTERS)?.split([',', ';']).map(str::trim).filter(|p| !p.is_empty()) {
        let (name, value) = part.split_once('=').ok_or_else(|| Error::InvalidArg(format!("`{}` entry `{part}` is not NAME=hex", keys::EMULATE_REGISTERS)))?;
        let (name, value) = (name.trim(), value.trim());
        let (Some(off), Some(size)) = (spec.register_offset(name), spec.register_size(name)) else {
            return Err(Error::InvalidArg(format!("`{}`: `{name}` is not a register of {lang}", keys::EMULATE_REGISTERS)));
        };
        let v = parse_hex(value).ok_or_else(|| Error::InvalidArg(format!("`{}`: `{value}` is not a hex value", keys::EMULATE_REGISTERS)))?;
        registers.push((off, size, v));
    }
    let mut memory = Vec::new();
    for part in o.get(keys::EMULATE_MEMORY)?.split(';').map(str::trim).filter(|p| !p.is_empty()) {
        let (addr, hex) = part.split_once('=').ok_or_else(|| Error::InvalidArg(format!("`{}` entry `{part}` is not hexaddr=hexbytes", keys::EMULATE_MEMORY)))?;
        let addr = parse_hex(addr).ok_or_else(|| Error::InvalidArg(format!("`{}`: `{addr}` is not an address", keys::EMULATE_MEMORY)))?;
        memory.push((addr, parse_bytes(hex)?));
    }
    Ok(Seeds { registers, memory })
}

/// The language's default space: where the image lives and where memory seeds go.
pub(crate) fn memory_space(spec: &Spec) -> &str {
    &spec.spaces[spec.default_space].name
}

/// The machine state `emulate.state` names, as `(space, address, bytes)` runs (none without it).
pub(crate) fn stored_state(s: &Session, o: &Options) -> Result<Vec<(String, u64, Vec<u8>)>> {
    match o.get(keys::EMULATE_STATE)? {
        "" => Ok(Vec::new()),
        name => {
            let t = s.read_state(name)?;
            (0..t.rows()).map(|r| Ok((t.str(r, 0)?.to_string(), t.u64(r, 1)?, t.bytes(r, 2)?.to_vec()))).collect()
        }
    }
}

/// A machine for `image`: the stored state, then `seeds` over it.
pub(crate) fn prepare(image: &Image<'_>, spec: &Spec, state: &[(String, u64, Vec<u8>)], seeds: &Seeds) -> Machine {
    let mut m = image.machine();
    for (space, addr, bytes) in state {
        m.write_bytes(space, *addr, bytes);
    }
    for &(off, size, value) in &seeds.registers {
        m.write("register", off, size, value);
    }
    for (addr, bytes) in &seeds.memory {
        m.write_bytes(memory_space(spec), *addr, bytes);
    }
    m
}

/// The state a machine holds, as `machine_state` rows: every run of bytes in every space but
/// `unique`, whose temporaries are dead between instructions.
fn state_table(m: &Machine) -> Table {
    let mut b = TableBuilder::new(&MACHINE_STATE);
    for space in m.spaces().into_iter().filter(|s| *s != "unique") {
        for (addr, bytes) in m.written(space) {
            b.row().str(space).u64(addr).bytes(&bytes);
        }
    }
    b.finish(false)
}

/// `emulate.save-state`: store the state the run stopped in, whatever its stop.
fn save_state(s: &mut Session, o: &Options, run: &Run) -> Result<()> {
    match o.get(keys::EMULATE_SAVE_STATE)? {
        "" => Ok(()),
        name => s.write_state(name, &state_table(&run.machine)),
    }
}

/// A program's loaded memory as image blocks: every initialized block of its default space.
pub(crate) fn program_blocks(p: &Program) -> Vec<(u64, &[u8])> {
    p.memory
        .blocks()
        .filter(|b| b.start.space == p.default_space)
        .filter_map(|b| b.bytes.as_deref().map(|bytes| (b.start.offset, bytes)))
        .collect()
}

/// One effect as its row text: a verb and its operands, space-separated, numbers in hex (a size in
/// decimal) — `store <space> <address> <size> <value>`, `call <target>`, `in|out <port> <size>
/// <value>`, `swi <number>`, `fault`; any argument values follow, in order.
fn effect_text(e: &Effect) -> String {
    let args = |vals: &[u64]| vals.iter().map(|v| format!(" {v:#x}")).collect::<String>();
    match e {
        Effect::Store(space, at, size, value) => format!("store {space} {at:#x} {size} {value:#0w$x}", w = 2 + 2 * *size as usize),
        Effect::Call(target, vals) => format!("call {target:#x}{}", args(vals)),
        Effect::Fault => "fault".to_string(),
        Effect::Port(write, port, size, value) => format!("{} {port:#x} {size} {value:#x}", if *write { "out" } else { "in" }),
        Effect::Swi(n, vals) => format!("swi {n:#x}{}", args(vals)),
    }
}

/// The `emulation` answer: the outcome, every register the final state holds, every run of bytes
/// it holds in memory, and — when the run recorded them — its effects in order.
fn emulation_table(spec: &Spec, run: &Run) -> Table {
    let mut b = TableBuilder::new(&EMULATION);
    let (stop, address) = match run.stop {
        Stop::Returned => ("returned", None),
        Stop::Fault => ("fault", None),
        Stop::NoInstruction(a) => ("no-instruction", Some(a)),
        Stop::StepCap => ("step-cap", None),
    };
    b.row().str("outcome").str("stop").str(stop);
    if let Some(a) = address {
        b.row().str("outcome").str("address").str(&format!("{a:#x}"));
    }
    b.row().str("outcome").str("steps").str(&run.steps.to_string());
    b.row().str("outcome").str("unmodeled").str(&run.machine.unmodeled.to_string());
    for name in &run.machine.unmodeled_ops {
        b.row().str("outcome").str("unmodeled-op").str(name);
    }
    // Every register the final state holds in full, widest first at each offset; a register
    // inside one already reported (AX inside EAX) is not repeated. Wider than a machine word is
    // beyond what the interpreter reads (its 80-bit and vector registers are not modelled).
    let mut regs = spec.register_table();
    regs.sort_by(|a, b| (a.0 .0, std::cmp::Reverse(a.0 .1), &a.1).cmp(&(b.0 .0, std::cmp::Reverse(b.0 .1), &b.1)));
    let held = run.machine.written("register");
    let holds = |off: u64, size: u32| held.iter().any(|(start, bytes)| off >= *start && off + u64::from(size) <= *start + bytes.len() as u64);
    let mut reported: Vec<(u64, u32)> = Vec::new();
    for ((off, size), name) in &regs {
        if *size > 8 || !holds(*off, *size) || reported.iter().any(|(o, s)| *off >= *o && *off + u64::from(*size) <= *o + u64::from(*s)) {
            continue;
        }
        b.row().str("register").str(name).str(&format!("{:#0w$x}", run.machine.read("register", *off, *size), w = 2 + 2 * *size as usize));
        reported.push((*off, *size));
    }
    for (addr, bytes) in run.machine.written(memory_space(spec)) {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        b.row().str("memory").str(&format!("{addr:#x}")).str(&hex);
    }
    for (i, e) in run.machine.effects.iter().enumerate() {
        b.row().str("effect").str(&(i + 1).to_string()).str(&effect_text(e));
    }
    b.finish(false)
}

/// `sleigh.emulate`: the bytes given, from base (or `emulate.entry`).
fn sleigh_emulate(s: &mut Session, o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    let i = inputs(o)?;
    let entry = match o.get(keys::EMULATE_ENTRY)? {
        "" => None,
        e => Some(parse_hex(e).ok_or_else(|| Error::InvalidArg(format!("`{}` is not an address: {e}", keys::EMULATE_ENTRY)))?),
    };
    let settings = settings(o)?;
    let seeds = seeds(o, i.spec, &i.lang)?;
    // The bytes are the machine's memory as well as its code, as a loaded program's are.
    let state = stored_state(s, o)?;
    let mut image = Image::new(i.spec, &i.bytes, i.base, &i.ctx).with_image_memory();
    let m = prepare(&image, i.spec, &state, &seeds);
    let run = image.resume(m, &settings.run_options(entry));
    save_state(s, o, &run)?;
    Ok(emulation_table(i.spec, &run))
}

/// `function.emulate`: a function of a session program, with its loaded image as memory.
fn function_emulate(s: &mut Session, o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    let (_, p) = program_of(s, o)?;
    let entry = entry_of(&p, o)?;
    let (spec, ctx) = mosura_core::lang::load_cached(&p.language_id).ok_or_else(|| Error::NotFound(format!("language `{}` (tables unavailable)", p.language_id)))?;
    let settings = settings(o)?;
    let seeds = seeds(o, spec, &p.language_id)?;
    let state = stored_state(s, o)?;
    let blocks = program_blocks(&p);
    let mut image = Image::from_blocks(spec, &blocks, ctx).with_image_memory();
    let m = prepare(&image, spec, &state, &seeds);
    let run = image.resume(m, &settings.run_options(Some(entry)));
    save_state(s, o, &run)?;
    Ok(emulation_table(spec, &run))
}
