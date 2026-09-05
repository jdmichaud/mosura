//! `dev.omf.dump` — an OMF object's structure as mosura's parser sees it: segments, publics, the
//! code segments' fixups, externals; with `dev.symbol` (at `base`) also the extraction the verifier
//! performs (`load_object_function`), the relinked bytes and the normalized instructions.
//! Diagnostic for the candidate loader: what the verifier slices is only as good as this parse.
//! (Was `examples/omfdump.rs`.)

use std::path::PathBuf;

use mosura_api::ops::{Cache, Op, Progress, Tier};
use mosura_api::{Error, Options, Result, Session, Table, TableBuilder};
use mosura_core::analysis::loader::omf;
use mosura_core::recompile::candidate::load_object_function;
use mosura_core::recompile::insn::{normalize, NoReloc};

use crate::keys;
use crate::schemas::OMF_DUMP;

pub static DUMP: Op = Op {
    name: "dev.omf.dump",
    doc: "an OMF object's structure as the candidate loader parses it (segments, publics, code fixups, externals); with dev.symbol the function's extraction at base, its relinked bytes and normalized instructions",
    since: "0.1",
    tier: Tier::Dev,
    params: &[keys::DEV_PATH, keys::DEV_SYMBOL, "base"],
    result: "omf_dump",
    cache: Cache::Transient,
    run: dump,
};

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect::<Vec<_>>().join(" ")
}

fn dump(_s: &mut Session, o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    let path = o.get(keys::DEV_PATH)?;
    if path.is_empty() {
        return Err(Error::InvalidArg(format!("`{}` is required: the object file to dump", keys::DEV_PATH)));
    }
    let data = std::fs::read(path).map_err(|e| Error::io(e, PathBuf::from(path)))?;
    let m = omf::parse_module(&data);
    let mut b = TableBuilder::new(&OMF_DUMP);
    for (i, s) in m.segments.iter().enumerate() {
        let head = hex(&s.data[..s.data.len().min(0x20)]);
        let detail = if head.is_empty() { (if s.is_code() { "code" } else { "data" }).to_string() } else { format!("{}; bytes {head}", if s.is_code() { "code" } else { "data" }) };
        b.row().str("segment").str(&s.name).u32((i + 1) as u32).u64(0).u64(s.data.len() as u64).str(&detail);
    }
    for (n, seg, off) in &m.publics {
        b.row().str("public").str(n).u32(*seg as u32).u64(*off).u64(0).str("");
    }
    for f in &m.fixups {
        if m.segments.get(f.segment.wrapping_sub(1)).map(|s| s.is_code()).unwrap_or(false) {
            b.row().str("fixup").str("").u32(f.segment as u32).u64(f.offset as u64).u64(0).str(&format!("loc={} wide={} selfrel={} target={:?} disp={:#x}", f.location, f.wide, f.self_relative, f.target, f.displacement));
        }
    }
    for e in &m.externals {
        b.row().str("external").str(e).u32(0).u64(0).u64(0).str("");
    }
    let sym = o.get(keys::DEV_SYMBOL)?;
    if !sym.is_empty() {
        let base_s = o.get("base")?;
        let base = if base_s.is_empty() { 0 } else { u64::from_str_radix(base_s.trim().trim_start_matches("0x"), 16).map_err(|_| Error::InvalidArg(format!("`base`: `{base_s}` is not hex")))? };
        let lang = m.language_id();
        // the extraction the verifier performs, with every external placed at one fixed address
        let resolver = |_: &str| -> Option<u64> { Some(0xdead_0000) };
        match load_object_function(&data, sym, base, &resolver) {
            Ok(c) => {
                let rl = c.relinked_bytes();
                b.row().str("candidate").str(sym).u32(0).u64(base).u64(c.bytes.len() as u64).str(&format!("fixups={} unresolved={} lang={lang}; relinked {}", c.fixups.len(), c.unresolved.len(), hex(&rl[..rl.len().min(24)])));
                match normalize(lang, &rl, base, &NoReloc) {
                    Ok(insns) => {
                        for i in &insns {
                            b.row().str("insn").str(&i.mnemonic).u32(0).u64(i.addr).u64(i.bytes.len() as u64).str(&i.text);
                        }
                    }
                    Err(e) => {
                        b.row().str("error").str("normalize").u32(0).u64(base).u64(0).str(&format!("{e:?}"));
                    }
                }
            }
            Err(e) => {
                b.row().str("error").str("load_object_function").u32(0).u64(base).u64(0).str(&e.to_string());
            }
        }
    }
    Ok(b.finish(false))
}
