//! The toolchain operations: the specs the library knows, opening one in the session (the
//! cached, locked driver), listing the open ones, and the explicit liveness probe.

use std::path::PathBuf;

use crate::error::{Error, Result};
use crate::options::{keys, Options};
use crate::ops::schemas::{CHECK, TOOLCHAINS, TOOLCHAIN_SPECS};
use crate::ops::{Cache, Op, Progress, Tier};
use crate::session::{OpenToolchain, Session};
use crate::table::builder::TableBuilder;
use crate::table::Table;
use mosura_core::recompile::toolchain::{spec, Cached, CompileUnit, CompilerDriver, DriverRole, Locked, Toolchain};

pub static SPECS: Op = Op { name: "toolchain.specs", doc: "the compiler specs the library knows (name, host, doc)", since: "0.1", tier: Tier::Product, params: &[], result: "toolchain_specs", cache: Cache::Transient, run: |_s, _o, _p| Ok(specs_table()) };
pub static OPEN: Op = Op { name: "toolchain.open", doc: "open a toolchain in this session under a name: toolchain.spec + toolchain.install (+ compile.cache, default <session>/compile); the driver is cached on source content and locked per install directory", since: "0.1", tier: Tier::Product, params: &["toolchain", keys::TOOLCHAIN_SPEC, keys::TOOLCHAIN_INSTALL, keys::COMPILE_CACHE], result: "toolchains", cache: Cache::Transient, run: open };
pub static LIST: Op = Op { name: "toolchain.list", doc: "the toolchains open in this session", since: "0.1", tier: Tier::Product, params: &[], result: "toolchains", cache: Cache::Transient, run: |s, _o, _p| Ok(list_table(s)) };
pub static CHECK_OP: Op = Op { name: "toolchain.check", doc: "compile one tiny unit through the named toolchain: the explicit liveness probe (an effect)", since: "0.1", tier: Tier::Product, params: &["toolchain"], result: "check", cache: Cache::Transient, run: check };

pub fn specs_table() -> Table {
    let mut b = TableBuilder::new(&TOOLCHAIN_SPECS);
    for (name, host, doc) in spec::ALL {
        b.row().str(name).str(host).str(doc);
    }
    b.finish(false)
}

fn list_table(s: &Session) -> Table {
    let mut b = TableBuilder::new(&TOOLCHAINS);
    for (name, t) in &s.toolchains {
        b.row().str(name).str(&t.spec).str(&t.id).str(&t.install.display().to_string()).str(&t.cache.display().to_string()).str(&t.lock.display().to_string());
    }
    b.finish(true)
}

/// The toolchain named by `toolchain` (the only open one when omitted).
pub fn toolchain_of<'a>(s: &'a Session, o: &Options) -> Result<(&'a str, &'a OpenToolchain)> {
    let name = o.get("toolchain")?;
    if name.is_empty() {
        return match s.toolchains.len() {
            1 => Ok(s.toolchains.iter().next().map(|(k, v)| (k.as_str(), v)).expect("one")),
            0 => Err(Error::NotFound("no toolchain is open in this session (toolchain.open)".into())),
            n => Err(Error::InvalidArg(format!("{n} toolchains are open; name one with `toolchain`"))),
        };
    }
    s.toolchains.get_key_value(name).map(|(k, v)| (k.as_str(), v)).ok_or_else(|| Error::NotFound(format!("toolchain `{name}` is not open (toolchain.open)")))
}

fn open(s: &mut Session, o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    let name = o.get("toolchain")?;
    if name.is_empty() {
        return Err(Error::InvalidArg("`toolchain` (a name for the open toolchain) is required".into()));
    }
    let spec_name = o.get(keys::TOOLCHAIN_SPEC)?;
    if spec_name.is_empty() {
        return Err(Error::InvalidArg(format!("`{}` is required (toolchain.specs lists them)", keys::TOOLCHAIN_SPEC)));
    }
    let install = o.get(keys::TOOLCHAIN_INSTALL)?;
    if install.is_empty() {
        return Err(Error::InvalidArg(format!("`{}` is required: where the toolchain is installed on this machine", keys::TOOLCHAIN_INSTALL)));
    }
    let prelude = mosura_core::recompile::tu::build_prelude();
    let cspec = spec::by_name(spec_name, install, prelude).ok_or_else(|| Error::NotFound(format!("compiler spec `{spec_name}` (one of: {})", spec::ALL.iter().map(|(n, _, _)| *n).collect::<Vec<_>>().join(", "))))?;
    let work = s.work_dir()?;
    let cache = match o.get(keys::COMPILE_CACHE)? {
        "" => s.dir().expect("work_dir succeeded").join("compile"),
        c => PathBuf::from(c),
    };
    std::fs::create_dir_all(&cache).map_err(|e| Error::io(e, cache.clone()))?;
    let driver = CompilerDriver::new(cspec, install, &work, DriverRole::Validation).map_err(|e| Error::io(e, work.clone()))?.owning_work_dir();
    let id = driver.id();
    let note = s.dir().map(|d| d.display().to_string()).unwrap_or_default();
    let locked = Locked::new(driver, std::path::Path::new(install), &note, Some(&cache)).map_err(|e| Error::io(e, PathBuf::from(install)))?;
    let lock = locked.lock_path().to_path_buf();
    let cached = Cached::new(locked, &cache).map_err(|e| Error::io(e, cache.clone()))?;
    s.toolchains.insert(name.to_string(), OpenToolchain { spec: spec_name.to_string(), install: PathBuf::from(install), cache, lock, id, driver: cached });
    Ok(list_table(s))
}

fn check(s: &mut Session, o: &Options, _p: &mut dyn Progress) -> Result<Table> {
    let (name, tc) = toolchain_of(s, o)?;
    let unit = CompileUnit { key: "MOSCHK".into(), source: "int mosura_check(int x) { return x + 1; }\n".into(), flags: Vec::new() };
    let out = tc.driver.compile(&unit);
    let mut b = TableBuilder::new(&CHECK);
    b.row().str(name).bool(out.ok()).bool(out.adjudicated).str(out.log.trim());
    Ok(b.finish(false))
}

/// Compile units through the named toolchain (the typed `mosura_toolchain_compile`): the `flags`
/// column is space-separated. Answers `compile_outputs` (key, ok, adjudicated, object, log).
pub fn compile_table(s: &Session, name: &str, units: &Table) -> Result<Table> {
    let tc = s.toolchains.get(name).ok_or_else(|| Error::NotFound(format!("toolchain `{name}` is not open")))?;
    let mut list = Vec::with_capacity(units.rows() as usize);
    let (kc, sc, fc) = (units.col("key").ok_or_else(|| Error::InvalidArg("units: no `key` column".into()))?, units.col("source").ok_or_else(|| Error::InvalidArg("units: no `source` column".into()))?, units.col("flags"));
    for r in 0..units.rows() {
        let flags = match fc {
            Some(c) => units.str(r, c)?.split_whitespace().map(str::to_string).collect(),
            None => Vec::new(),
        };
        list.push(CompileUnit { key: units.str(r, kc)?.to_string(), source: units.str(r, sc)?.to_string(), flags });
    }
    let outs = tc.driver.compile_batch(&list);
    let mut b = TableBuilder::new(&crate::ops::schemas::COMPILE_OUTPUTS);
    for o in &outs {
        b.row().str(&o.key).bool(o.ok()).bool(o.adjudicated).bytes(o.object.as_deref().unwrap_or(&[])).str(&o.log);
    }
    Ok(b.finish(false))
}
