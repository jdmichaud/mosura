//! The SLEIGH operations over bytes: `sleigh.disassemble` (instructions with their text) and
//! `sleigh.lift` (the raw p-code of each instruction, `PcodeOp::render()` as the golden text). The
//! decode context is the language's `.pspec` defaults, overridden by `ctx` (`name=value;…`).

use crate::error::{Error, Result};
use crate::options::{parse_hex, Options};
use crate::ops::schemas::{INSTRUCTIONS, PCODE};
use crate::ops::{Cache, Op, Progress, Tier};
use crate::session::Session;
use crate::table::builder::TableBuilder;
use crate::table::Table;
use mosura_core::sleigh::pcode::PArg;
use mosura_core::sleigh::Instruction;

const PARAMS: &[&str] = &["lang", "bytes", "base", "ctx"];

pub static DISASSEMBLE: Op = Op { name: "sleigh.disassemble", doc: "disassemble raw bytes (hex) for a language at base, under the language's default context overridden by ctx", since: "0.1", tier: Tier::Product, params: PARAMS, result: "instructions", cache: Cache::Transient, run: disassemble };
pub static LIFT: Op = Op { name: "sleigh.lift", doc: "disassemble raw bytes and lift each instruction to raw p-code (one row per op; text is the golden form)", since: "0.1", tier: Tier::Product, params: PARAMS, result: "pcode", cache: Cache::Transient, run: lift };

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

/// Decode the `lang`, `bytes`, `base`, `ctx` parameters into instructions.
fn decode(o: &Options) -> Result<(String, Vec<Instruction>)> {
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
    let insns = if ctx_spec.trim().is_empty() {
        spec.disassemble_ctx(&bytes, base, default_ctx)
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
        let ctx = spec.context_from_sets(&refs);
        spec.disassemble_ctx(&bytes, base, &ctx)
    };
    Ok((lang.to_string(), insns))
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
