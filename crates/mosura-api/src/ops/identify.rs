//! `identify`: everything the loaders can say about an input WITHOUT analysis, as rows
//! `key value evidence` — the container and which loader claims it, the compiler evidence in the
//! bytes, the load-only facts (language, spec, compiler opinion, version, base, blocks, entries,
//! counts), and the FID databases a program of that language and spec would be matched against.

use crate::error::Result;
use crate::options::{keys, Options};
use crate::ops::schemas::IDENTIFY as IDENTIFY_SCHEMA;
use crate::ops::{program::{input_of, loader_of}, Cache, Op, Progress, Tier};
use crate::session::Session;
use crate::table::builder::TableBuilder;
use crate::table::Table;
use mosura_core::analysis::{self, loader};

pub static IDENTIFY: Op = Op {
    name: "identify",
    doc: "what the input is: container, claiming loaders, compiler evidence, load-only facts, FID databases (no analysis)",
    since: "0.1",
    tier: Tier::Product,
    params: &["input", keys::LOAD_LOADER, keys::LOAD_LANGUAGE, keys::LOAD_BASE, keys::LOAD_CSPEC_X86_32],
    result: "identify",
    cache: Cache::Transient,
    run: identify,
};

fn truncate(s: &str, n: usize) -> String {
    let s = s.replace(['\r', '\n'], " ");
    if s.chars().count() <= n { s } else { s.chars().take(n).collect::<String>() + "…" }
}

fn magic(d: &[u8]) -> &'static str {
    match d {
        _ if d.starts_with(b"\x7fELF") => "ELF",
        _ if d.starts_with(b"MZ") => {
            let pe = d.get(0x3c..0x40).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize).filter(|&o| d.get(o..o + 4) == Some(b"PE\0\0")).is_some();
            if pe { "MZ + PE" } else { "MZ (DOS)" }
        }
        _ if matches!(d.first(), Some(0x80 | 0x82)) => "OMF object",
        _ if d.starts_with(b"\xf0") => "OMF library",
        _ => "none",
    }
}

fn identify(s: &mut Session, o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    let digest = input_of(s, o)?;
    let data = s.input_bytes(&digest)?;
    let filename = s.input_filename(&digest).unwrap_or("").to_string();
    let mut b = TableBuilder::new(&IDENTIFY_SCHEMA);
    let mut row = |k: &str, v: &str, e: &str| {
        b.row().str(k).str(v).str(e);
    };
    row("input", &filename, &format!("{} bytes", data.len()));
    row("input.digest", &crate::fingerprint::hex(&digest), "blake3");
    // container
    row("container", magic(&data), "");
    match analysis::native_loader_name(&data) {
        Some(n) => row("native.loader", n, "beyond-Ghidra; load.loader=native for its view"),
        None => row("native.loader", "none", "the default dispatch owns this file"),
    }
    if let Some(off) = loader::detect_le(&data) {
        let bound = data.get(0x3c..0x40).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as usize != off).unwrap_or(true);
        let flavour = match loader::le::le_flavour(&data, off) { loader::le::LeFlavour::Le => "LE", loader::le::LeFlavour::Lx => "LX" };
        row("le.header", &format!("{off:#x}"), &format!("{flavour}; {}", if bound { "bound — e_lfanew invalid, found by scanning" } else { "standalone — e_lfanew points at it" }));
    }
    if let Some(l) = loader::detect_x32(&data) {
        row("x32.container", &format!("inner MZ {:#x}, image {:#x}", l.inner, l.flat), &format!("base {:#x}, entry {:#x}", l.base, l.entry));
    }
    // compiler evidence in the bytes
    match loader::compiler_version::detect(&data) {
        Some(id) => row("compiler.version", &id.label(), &format!("{:?}: {}", id.precision, truncate(&id.evidence, 92))),
        None => row("compiler.version", "none", "no version marker found"),
    }
    if let Some(w) = loader::watcom::detect(&data) {
        row("compiler.watcom", &w.compiler_label(), &truncate(&w.banner, 66));
    }
    if let Some(m) = loader::metaware::detect(&data) {
        row("compiler.metaware", &m.compiler_label(), &truncate(&m.banner, 66));
    }
    // load-only facts
    let knobs = o.knobs()?;
    let (language, base) = (o.get(keys::LOAD_LANGUAGE)?.to_string(), o.get(keys::LOAD_BASE)?.to_string());
    let which = loader_of(o, &language, &base)?;
    match analysis::load_bytes_with(&data, Some(&filename), which, &knobs) {
        Err(e) => row("load", "failed", &e.to_string()),
        Ok(p) => {
            row("load", o.get(keys::LOAD_LOADER)?, "loaded, not analyzed");
            row("language", &p.language_id, "");
            row("cspec", &p.compiler_spec_id, if mosura_core::lang::resolve_cspec(&p.language_id, &p.compiler_spec_id).is_some() { "resolved" } else { "UNRESOLVED — prototype recovery uses defaults" });
            row("compiler.opinion", &p.compiler, "Ghidra CompilerOpinion label");
            row("compiler.detected", p.compiler_version.as_deref().unwrap_or("none"), "the version marker as the loader recorded it");
            row("base", &format!("{:#x}", p.image_base.offset), &format!("{} bits", p.addr_size_bits));
            row("endian", if p.big_endian { "big" } else { "little" }, "");
            for blk in p.memory.blocks() {
                row("block", blk.name(), &format!("{:#010x}..{:#010x} {}{}{}{}", blk.start().offset, blk.end().offset, if blk.is_read() { 'r' } else { '-' }, if blk.is_write() { 'w' } else { '-' }, if blk.is_execute() { 'x' } else { '-' }, if blk.is_initialized() { "" } else { " (uninitialized)" }));
            }
            for a in &p.entry_points {
                row("entry", &format!("{:#x}", a.offset), "");
            }
            row("functions", &p.function_manager.function_count().to_string(), "loader-stage");
            row("symbols", &p.symbol_table.symbols().count().to_string(), "loader-stage");
            row("relocations", &p.relocation_table.relocations().count().to_string(), if p.relocation_table.is_relocatable() { "relocatable" } else { "" });
            // FID: databases selected by language AND compiler spec
            let service = mosura_core::analysis::fid::query::FidQueryService::load_matching_resources(&p.language_id, &p.compiler_spec_id);
            for db in service.databases() {
                row("fid.database", db.name(), &format!("{} records, {} libraries", db.function_count(), db.libraries().len()));
            }
            row("fid.records", &service.function_count().to_string(), if service.is_empty() { "no database matches this language and spec" } else { "" });
        }
    }
    Ok(b.finish(false))
}
