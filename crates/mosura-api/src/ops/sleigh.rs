//! The SLEIGH operations over bytes: `sleigh.disassemble` (instructions with their text),
//! `sleigh.lift` (the raw p-code of each instruction, `PcodeOp::render()` as the golden text) and
//! `sleigh.emulate` (execute that p-code over an initial state; `docs/emulation.md`). The decode
//! context is the language's `.pspec` defaults, overridden by `ctx` (`name=value;…`).

use crate::error::{Error, Result};
use crate::options::{keys, parse_bool, parse_hex, Options};
use crate::ops::schemas::{EMULATION, INSTRUCTIONS, PCODE};
use crate::ops::{Cache, Op, Progress, Tier};
use crate::session::Session;
use crate::table::builder::TableBuilder;
use crate::table::Table;
use mosura_core::sleigh::emu::{self, RunOptions, Stop};
use mosura_core::sleigh::engine::Spec;
use mosura_core::sleigh::pcode::PArg;
use mosura_core::sleigh::Instruction;

const PARAMS: &[&str] = &["lang", "bytes", "base", "ctx"];
const EMULATE_PARAMS: &[&str] = &["lang", "bytes", "base", "ctx", keys::EMULATE_ENTRY, keys::EMULATE_REGISTERS, keys::EMULATE_MEMORY, keys::EMULATE_FOLLOW_CALLS, keys::EMULATE_MAX_STEPS];

pub static DISASSEMBLE: Op = Op { name: "sleigh.disassemble", doc: "disassemble raw bytes (hex) for a language at base, under the language's default context overridden by ctx", since: "0.1", tier: Tier::Product, params: PARAMS, result: "instructions", cache: Cache::Transient, run: disassemble };
pub static LIFT: Op = Op { name: "sleigh.lift", doc: "disassemble raw bytes and lift each instruction to raw p-code (one row per op; text is the golden form)", since: "0.1", tier: Tier::Product, params: PARAMS, result: "pcode", cache: Cache::Transient, run: lift };
pub static EMULATE: Op = Op { name: "sleigh.emulate", doc: "execute the p-code of raw bytes from base (or emulate.entry) over an initial state (emulate.registers, emulate.memory) until the routine returns, faults, reaches an address with no instruction, or spends emulate.max-steps; a call is an event unless emulate.follow-calls. Rows: outcome (stop = returned | fault | no-instruction | step-cap, address, steps, unmodeled, unmodeled-op), register (every register the final state holds, widest first), memory (every run of bytes it holds, as hex)", since: "0.1", tier: Tier::Product, params: EMULATE_PARAMS, result: "emulation", cache: Cache::Transient, run: emulate };

/// Hex text to bytes: `0x` prefix, spaces and underscores ignored; an odd digit count refused.
pub fn parse_bytes(s: &str) -> Result<Vec<u8>> {
    let t: String = s.trim().trim_start_matches("0x").chars().filter(|c| !c.is_whitespace() && *c != '_').collect();
    if t.is_empty() {
        return Err(Error::InvalidArg("`bytes` is required (hex)".into()));
    }
    if t.len() % 2 != 0 || !t.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::InvalidArg(format!("`bytes` is not an even run of hex digits: {s}")));
    }
    Ok((0..t.len() / 2).map(|i| u8::from_str_radix(&t[2 * i..2 * i + 2], 16).unwrap()).collect())
}

/// The `lang`, `bytes`, `base`, `ctx` parameters, resolved.
struct Inputs {
    lang: String,
    spec: &'static Spec,
    ctx: Vec<u32>,
    bytes: Vec<u8>,
    base: u64,
}

/// Decode the `lang`, `bytes`, `base`, `ctx` parameters into instructions.
fn decode(o: &Options) -> Result<(String, Vec<Instruction>)> {
    let i = inputs(o)?;
    let insns = i.spec.disassemble_ctx(&i.bytes, i.base, &i.ctx);
    Ok((i.lang, insns))
}

/// Resolve the `lang`, `bytes`, `base`, `ctx` parameters.
fn inputs(o: &Options) -> Result<Inputs> {
    let lang = o.get("lang")?;
    if lang.is_empty() {
        return Err(Error::InvalidArg("`lang` is required (a SLEIGH language id)".into()));
    }
    let bytes = parse_bytes(o.get("bytes")?)?;
    let base = match o.get("base")? {
        "" => 0,
        b => parse_hex(b).ok_or_else(|| Error::InvalidArg(format!("`base` is not an address: {b}")))?,
    };
    let (spec, default_ctx) = mosura_core::lang::load_cached(lang).ok_or_else(|| Error::NotFound(format!("language `{lang}` (tables unavailable)")))?;
    let ctx_spec = o.get("ctx")?;
    let ctx = if ctx_spec.trim().is_empty() {
        default_ctx.to_vec()
    } else {
        // the .pspec defaults, then the caller's overrides by name
        let (_, pspec) = mosura_core::lang::resolve(lang).ok_or_else(|| Error::NotFound(format!("language `{lang}`")))?;
        let mut sets: Vec<(String, u64)> = mosura_core::lang::pspec_context_sets(&pspec).unwrap_or_default();
        let known = spec.context_var_names();
        for part in ctx_spec.split(';').map(str::trim).filter(|p| !p.is_empty()) {
            let (name, value) = part.split_once('=').ok_or_else(|| Error::InvalidArg(format!("`ctx` entry `{part}` is not name=value")))?;
            let (name, value) = (name.trim(), value.trim());
            if !known.contains(&name) {
                return Err(Error::InvalidArg(format!("`ctx`: `{name}` is not a context variable of {lang} (one of {})", known.join(", "))));
            }
            let v = if let Some(h) = value.strip_prefix("0x") { u64::from_str_radix(h, 16).ok() } else { value.parse::<u64>().ok() }.ok_or_else(|| Error::InvalidArg(format!("`ctx`: `{value}` is not a number")))?;
            sets.retain(|(n, _)| n != name);
            sets.push((name.to_string(), v));
        }
        let refs: Vec<(&str, u64)> = sets.iter().map(|(n, v)| (n.as_str(), *v)).collect();
        spec.context_from_sets(&refs)
    };
    Ok(Inputs { lang: lang.to_string(), spec, ctx, bytes, base })
}

fn disassemble(_s: &mut Session, o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    let (_, insns) = decode(o)?;
    let mut b = TableBuilder::new(&INSTRUCTIONS);
    for i in &insns {
        b.row().u64(i.address).u32(i.bytes.len() as u32).bytes(&i.bytes).str(&i.mnemonic).str(&i.body).str("").bool(false).bool(false).u64(0).list_u64(&[]);
    }
    Ok(b.finish(true))
}

fn lift(_s: &mut Session, o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    let (_, insns) = decode(o)?;
    let mut b = TableBuilder::new(&PCODE);
    for i in &insns {
        for (seq, op) in i.ops.iter().enumerate() {
            let mut spaces: Vec<&str> = Vec::with_capacity(op.ins.len());
            let mut offsets: Vec<u64> = Vec::with_capacity(op.ins.len());
            let mut sizes: Vec<u32> = Vec::with_capacity(op.ins.len());
            for a in &op.ins {
                match a {
                    PArg::Var(v) => {
                        spaces.push(&v.space);
                        offsets.push(v.offset);
                        sizes.push(v.size);
                    }
                    PArg::Space(name) => {
                        spaces.push(name);
                        offsets.push(0);
                        sizes.push(0);
                    }
                }
            }
            let out = op.out.as_ref();
            b.row().u64(i.address).u32(seq as u32).u32(op.opcode).str(op.name()).bool(out.is_some()).str(out.map(|v| v.space.as_str()).unwrap_or("")).u64(out.map(|v| v.offset).unwrap_or(0)).u32(out.map(|v| v.size).unwrap_or(0)).str(&spaces.join(",")).list_u64(&offsets).list_u32(&sizes).str(&op.render());
        }
    }
    Ok(b.finish(false))
}

/// `sleigh.emulate`: run the interpreter (`sleigh::emu::run_with`) and report the outcome, the
/// registers and the memory the final state holds. See `docs/emulation.md`.
fn emulate(_s: &mut Session, o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    let i = inputs(o)?;
    let entry = match o.get(keys::EMULATE_ENTRY)? {
        "" => None,
        e => Some(parse_hex(e).ok_or_else(|| Error::InvalidArg(format!("`{}` is not an address: {e}", keys::EMULATE_ENTRY)))?),
    };
    let follow_calls = match o.get(keys::EMULATE_FOLLOW_CALLS)? {
        "" => false,
        v => parse_bool(v).ok_or_else(|| Error::InvalidArg(format!("`{}` is not a boolean: {v}", keys::EMULATE_FOLLOW_CALLS)))?,
    };
    let max_steps = match o.get(keys::EMULATE_MAX_STEPS)? {
        "" => RunOptions::default().max_steps,
        v => v.trim().parse::<usize>().map_err(|_| Error::InvalidArg(format!("`{}` is not a count: {v}", keys::EMULATE_MAX_STEPS)))?,
    };
    let mut seeds: Vec<(&str, u64, u64, u32)> = Vec::new();
    for part in o.get(keys::EMULATE_REGISTERS)?.split([',', ';']).map(str::trim).filter(|p| !p.is_empty()) {
        let (name, value) = part.split_once('=').ok_or_else(|| Error::InvalidArg(format!("`{}` entry `{part}` is not NAME=hex", keys::EMULATE_REGISTERS)))?;
        let (name, value) = (name.trim(), value.trim());
        let (Some(off), Some(size)) = (i.spec.register_offset(name), i.spec.register_size(name)) else {
            return Err(Error::InvalidArg(format!("`{}`: `{name}` is not a register of {}", keys::EMULATE_REGISTERS, i.lang)));
        };
        let v = parse_hex(value).ok_or_else(|| Error::InvalidArg(format!("`{}`: `{value}` is not a hex value", keys::EMULATE_REGISTERS)))?;
        seeds.push(("register", off, v, size));
    }
    for part in o.get(keys::EMULATE_MEMORY)?.split(';').map(str::trim).filter(|p| !p.is_empty()) {
        let (addr, hex) = part.split_once('=').ok_or_else(|| Error::InvalidArg(format!("`{}` entry `{part}` is not hexaddr=hexbytes", keys::EMULATE_MEMORY)))?;
        let addr = parse_hex(addr).ok_or_else(|| Error::InvalidArg(format!("`{}`: `{addr}` is not an address", keys::EMULATE_MEMORY)))?;
        for (k, b) in parse_bytes(hex)?.into_iter().enumerate() {
            seeds.push(("ram", addr + k as u64, u64::from(b), 1));
        }
    }
    let run = emu::run_with(i.spec, &i.bytes, i.base, &i.ctx, &seeds, &RunOptions { entry, follow_calls, max_steps, ..RunOptions::default() });
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
    let mut regs = i.spec.register_table();
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
    for (addr, bytes) in run.machine.written("ram") {
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        b.row().str("memory").str(&format!("{addr:#x}")).str(&hex);
    }
    Ok(b.finish(false))
}
