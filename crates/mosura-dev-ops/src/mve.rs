//! `dev.mve.fixtures` — generate the committed Watcom fixtures from SELF-COMPILED minimal examples
//! (`recompile::mve::MVES`) — no third-party bytes (repository policy). Compiles each MVE with the
//! in-house Watcom 10.0a through the recompile toolchain, extracts the function's code from the
//! OMF object, and writes the fixture XML with the source embedded as a comment. With `dev.check`
//! it regenerates into a temp dir and compares against `oracle/fixtures`: any difference, a missing
//! product, or an ORPHAN (a committed fixture carrying the generator's header that is not a product
//! of this generator — nothing could regenerate it) is a row with `ok = false` (the CLI exits 1)
//! and the temp dir is kept. The manual pre-landing step for anything that touches a fixture (it
//! needs the in-house wcc386, so it is not a unit test). (Was `examples/watcom_mve_fixtures.rs`.)

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use mosura_api::ops::{Cache, Op, Progress, Tier};
use mosura_api::{Error, Options, Result, Session, Table, TableBuilder};
use mosura_core::recompile::candidate::{load_object_function, CandTable};
use mosura_core::recompile::mve::{extern_kinds, MVES};
use mosura_core::recompile::toolchain::{spec, CompileUnit, CompilerDriver, DriverRole, Toolchain};

use crate::keys;
use crate::schemas::MVE_FIXTURES;

pub static FIXTURES: Op = Op {
    name: "dev.mve.fixtures",
    doc: "generate the self-compiled Watcom oracle fixtures from the MVE table into dev.out (toolchain.install = the WATCOM dir), or with dev.check=true regenerate into a temp dir and compare against oracle/fixtures (rows: written | same | DIFFERS | MISSING | ORPHAN; ok=false on any problem)",
    since: "0.1",
    tier: Tier::Dev,
    params: &["toolchain.install", keys::DEV_OUT, keys::DEV_CHECK],
    result: "mve_fixtures",
    cache: Cache::Transient,
    run: fixtures,
};

/// The first line of every product; `tests/fixture_provenance.rs` keys the generator-product bar on it.
pub const GENERATED_MARKER: &str = "<!-- SELF-COMPILED fixture: wcc386";

/// The watcom_10_0a profile's own flag knowledge (`buildconfig.rs`): `-d1+` is what makes 10.0a
/// emit the BP frame on the subject's path — saves pushed BEFORE the frame (`52 55 89e5`), which
/// is the whole point of the callee-save fixture: the saved-EBP slot carves the ownership hole
/// BELOW the register save. `-of`/`-of+` force the other prologue path (frame first) and are
/// evidence-rejected for the subject.
const FLAGS: &[&str] = &["-5r", "-fpi87", "-s", "-onatx", "-d1+", "-zq"];

fn fixtures(s: &mut Session, o: &Options, p: &mut dyn Progress) -> Result<Table> {
    let watcom = o.get("toolchain.install")?;
    if watcom.is_empty() {
        return Err(Error::InvalidArg("`toolchain.install` is required: the WATCOM directory of the in-house wcc386".into()));
    }
    let check = crate::flag(o, keys::DEV_CHECK)?;
    let out = if check {
        let base = crate::out_dir(s, o, "mve").ok().unwrap_or_else(std::env::temp_dir);
        base.join(format!("mve-check-{}", std::process::id()))
    } else {
        let out = o.get(keys::DEV_OUT)?;
        if out.is_empty() {
            return Err(Error::InvalidArg(format!("`{}` is required: where the fixtures are written (or dev.check=true)", keys::DEV_OUT)));
        }
        PathBuf::from(out)
    };
    // absolute paths throughout: the compiler runs under a DOS emulator whose drive mapping is
    // built from them; the work dir is the session's (never inside the fixture directory)
    let out = std::path::absolute(&out).map_err(|e| Error::io(e, out.clone()))?;
    std::fs::create_dir_all(&out).map_err(|e| Error::io(e, out.clone()))?;
    let work = match s.work_dir() {
        Ok(w) => w.join("mve"),
        Err(_) => out.join(format!("work-{}", std::process::id())),
    };
    // Through the generic driver. Role DEVELOPMENT-ASSISTANCE: this builds oracle fixtures offline,
    // which is the compiler helping us do the work rather than standing in for it. Every unit
    // carries EXPLICIT flags, so the spec's profile fallback never fires.
    let tc = CompilerDriver::new(spec::watcom_10_0a_dos(""), Path::new(watcom), &work, DriverRole::DevelopmentAssistance).map_err(|e| Error::Unsupported(format!("toolchain: {e}")))?.owning_work_dir();
    let flags: Vec<String> = FLAGS.iter().map(|s| s.to_string()).collect();
    let mut t = TableBuilder::new(&MVE_FIXTURES);
    let mut products: Vec<&str> = Vec::new();
    let total = MVES.len() as u64;
    for (i, m) in MVES.iter().enumerate() {
        if !p.report(FIXTURES.name, i as u64, total) {
            return Err(Error::Cancelled);
        }
        let (key, sym, src, file, base) = (m.key, m.sym, m.source, m.fixture, m.base);
        let outp = tc.compile(&CompileUnit { key: key.into(), source: src.into(), flags: flags.clone() });
        let obj = outp.object.ok_or_else(|| Error::Format(format!("{key} failed to compile:\n{}", outp.log)))?;
        // Externs resolve INSIDE the fixture image: code symbols to a RET stub, data to a plain
        // address — an unresolvable (zero) call target aborts flow analysis and the fixture
        // decompiles to nothing. Every extern gets its OWN address (data 0x100 apart, code stubs
        // 0x10 apart, in order of first reference): two globals never alias and two callees never
        // merge. The KIND of an extern comes from the MVE source (an `extern` declarator followed
        // by `(` is a function, anything else data) — never from its name.
        let stub = base + 0x1000;
        let data = base + 0x2000;
        let seen = Rc::new(RefCell::new(HashMap::<String, u64>::new()));
        let seen_r = Rc::clone(&seen);
        let (code_names, data_names) = extern_kinds(src);
        let resolver = move |sym: &str| {
            // Watcom's register convention: functions are `name_`, data `_name`
            let bare = sym.trim_start_matches('_').trim_end_matches('_');
            let is_data = data_names.contains(bare);
            if !is_data && !code_names.contains(bare) {
                mosura_core::debug::warn(format!("{key}: `{sym}` is not declared extern in the MVE source — placed as a callee stub"));
            }
            let mut m = seen_r.borrow_mut();
            let n_data = m.values().filter(|&&a| a >= data).count() as u64;
            let n_code = m.values().filter(|&&a| a < data).count() as u64;
            Some(*m.entry(sym.to_string()).or_insert(if is_data { data + 0x100 * n_data } else { stub + 0x10 * n_code }))
        };
        let mut cand = load_object_function(&obj, sym, base, &resolver).map_err(|e| Error::Format(format!("{key}: {e}\nlog:\n{}", outp.log)))?;
        // A switch's jump table lives outside the function's extent (Watcom emits it at the front
        // of `_TEXT`): emit each table as its own chunk at `base + 0x800 + ..` and resolve the
        // function's reference to it, so the fixture carries a decodable BRANCHIND.
        let mut extra_chunks = String::new();
        if !cand.tables.is_empty() {
            let tables = cand.tables.clone();
            let mut addrs = Vec::new();
            let mut next = base + 0x800;
            for tb in &tables {
                addrs.push(next);
                next += 4 * tb.entries_fnrel.len() as u64;
            }
            let entries = |tb: &CandTable| -> Vec<u8> { tb.entries_fnrel.iter().flat_map(|k| ((base + k) as u32).to_le_bytes()).collect() };
            cand.resolve_tables(&|bytes| tables.iter().position(|tb| entries(tb) == bytes).map(|i| addrs[i]));
            for (i, tb) in tables.iter().enumerate() {
                extra_chunks += &format!("  <bytechunk space=\"ram\" offset=\"{:#x}\" readonly=\"true\">\n{}\n  </bytechunk>\n", addrs[i], crate::hex_bytes(&entries(tb)));
            }
        }
        let hex = crate::hex_bytes(&cand.relinked_bytes());
        // one RET stub per code extern referenced (plus the default one)
        let mut stubs: Vec<u64> = seen.borrow().values().copied().filter(|&a| a < data).collect();
        stubs.push(stub);
        stubs.sort_unstable();
        stubs.dedup();
        let stub_chunks: String = stubs.iter().map(|a| format!("  <bytechunk space=\"ram\" offset=\"{a:#x}\" readonly=\"true\">\nc3\n  </bytechunk>\n")).collect();
        let src_comment: String = src.trim().lines().map(|l| format!("  {l}\n")).collect();
        // the layout this object was built with — every extern the object references, by the bare
        // name, at the address the resolver assigned it, in ADDRESS order = the object's RELOCATION
        // order, not the source's (the twin build binds `func_0x..` and the address-named globals
        // to the MVE's externs through this line)
        let externs_line: String = {
            let mut v: Vec<(u64, String)> = seen.borrow().iter().map(|(s, &a)| (a, s.trim_start_matches('_').trim_end_matches('_').to_string())).collect();
            v.sort();
            v.iter().map(|(a, n)| format!("{n}={a:#x}")).collect::<Vec<_>>().join(" ")
        };
        let xml = format!(
            "<!-- SELF-COMPILED fixture: wcc386 10.0a (in-house), flags {fl}. No third-party\n\
             \x20    bytes — the source is this comment; regenerate with `mosura dev mve.fixtures`.\n\
             \x20    Externs: code from {stub:#x} (one RET stub per callee, 0x10 apart), data from {data:#x} (0x100 apart).\n\
             \x20    externs: {externs_line}\n\
             {src_comment}-->\n\
             <binaryimage arch=\"x86:LE:32:default:watcom\">\n\
             \x20 <bytechunk space=\"ram\" offset=\"{base:#x}\" readonly=\"true\">\n{hex}\n  </bytechunk>\n\
             {extra_chunks}\
             {stub_chunks}</binaryimage>\n",
            fl = FLAGS.join(" "),
        );
        debug_assert!(xml.starts_with(GENERATED_MARKER), "the product header must carry the marker");
        std::fs::write(out.join(file), &xml).map_err(|e| Error::io(e, out.join(file)))?;
        if !check {
            t.row().str(file).u64(cand.bytes.len() as u64).str("written").bool(true);
        }
        products.push(file);
    }
    if !check {
        return Ok(t.finish(false));
    }
    // every product must match the committed fixture byte for byte ...
    let committed = mosura_core::paths::oracle_fixtures_dir();
    let mut problems = 0usize;
    for file in &products {
        let ours = std::fs::read(out.join(file)).map_err(|e| Error::io(e, out.join(file)))?;
        let (status, ok) = match std::fs::read(committed.join(file)) {
            Ok(theirs) if theirs == ours => ("same", true),
            Ok(_) => ("DIFFERS", false),
            Err(_) => ("MISSING", false),
        };
        problems += usize::from(!ok);
        t.row().str(file).u64(ours.len() as u64).str(status).bool(ok);
    }
    // ... and every committed fixture that carries the generator's header must be one of the
    // products: a file the generator once wrote and no longer does would otherwise pass silently,
    // with nothing left that can regenerate it.
    let mut marked = 0usize;
    let mut entries: Vec<PathBuf> = std::fs::read_dir(&committed).map_err(|e| Error::io(e, committed.clone()))?.filter_map(|e| e.ok()).map(|e| e.path()).collect();
    entries.sort();
    for path in entries {
        if path.extension().and_then(|e| e.to_str()) != Some("xml") {
            continue;
        }
        let name = path.file_name().unwrap_or_default().to_string_lossy().to_string();
        if !std::fs::read_to_string(&path).map(|s| s.starts_with(GENERATED_MARKER)).unwrap_or(false) {
            continue;
        }
        marked += 1;
        if !products.iter().any(|p| *p == name) {
            problems += 1;
            t.row().str(&name).u64(0).str("ORPHAN").bool(false);
        }
    }
    drop(tc);
    if problems == 0 {
        let _ = std::fs::remove_dir_all(&out);
        t.row().str("*check*").u64(products.len() as u64).str(&format!("all {} products match oracle/fixtures; all {marked} generator-marked fixtures there are products (no orphans)", products.len())).bool(true);
    } else {
        t.row().str("*check*").u64(products.len() as u64).str(&format!("{problems} problem(s) against oracle/fixtures; the regenerated products are kept in {}", out.display())).bool(false);
    }
    Ok(t.finish(false))
}
