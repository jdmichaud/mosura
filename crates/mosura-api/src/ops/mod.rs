//! The operation registry and dispatcher (design §4.1): every capability is one registered `Op`
//! — a name, the keys it accepts, the schema it answers, its cache class and a body that
//! orchestrates core calls and decides nothing. `dispatch` looks the op up, validates the
//! parameters against the registry, runs the body under `catch_unwind` (unless the context says
//! abort) and hands back one table. New capability = one more entry in `REGISTRY`, or — for a
//! tier built as another crate (the dev tier) — one `Extension` handed to `register` when the
//! context is built.

pub mod emit;
pub mod equiv;
pub mod fid;
pub mod function;
pub mod identify;
pub mod language;
pub mod program;
pub mod round;
pub mod schemas;
pub mod session;
pub mod sleigh;
pub mod toolchain;
pub mod toolchain_evidence;

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::RwLock;

use crate::ctx::Context;
use crate::error::{Error, Result};
use crate::fingerprint::Stage;
use crate::options::{keys, registry as optreg, Affects, OptionSpec, Options};
use crate::schema::Schema;
use crate::session::{Session, SetKind};
use crate::table::builder::TableBuilder;
use crate::table::Table;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Tier {
    Product,
    Dev,
}

/// Whether a result is a content-addressed set (`Pure`: same key → same tables, served from the
/// store) or recomputed every call (`Transient`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cache {
    Pure { stage: Stage, set: SetKind },
    Transient,
}

/// Progress from a long operation; `false` from `report` cancels it (`Error::Cancelled`).
pub trait Progress {
    fn report(&mut self, what: &str, done: u64, total: u64) -> bool;
}

pub struct NoProgress;
impl Progress for NoProgress {
    fn report(&mut self, _what: &str, _done: u64, _total: u64) -> bool {
        true
    }
}

pub type Run = fn(&mut Session, &Options, &mut dyn Progress) -> Result<Table>;

pub struct Op {
    pub name: &'static str,
    pub doc: &'static str,
    pub since: &'static str,
    pub tier: Tier,
    /// The option keys the op accepts besides `debug.*` (which every op accepts).
    pub params: &'static [&'static str],
    /// The schema of the answer.
    pub result: &'static str,
    pub cache: Cache,
    pub run: Run,
}

impl Op {
    pub fn cache_name(&self) -> String {
        match self.cache {
            Cache::Pure { stage, set } => format!("pure:{}:{}", stage.name(), set.dir_name()),
            Cache::Transient => "transient".to_string(),
        }
    }
}

/// Every operation, sorted by name (a test pins order and uniqueness).
pub static REGISTRY: &[&Op] = &[
    &fid::IDENTIFY,
    &round::BUILDCONFIG_OP,
    &function::DECOMPILE,
    &emit::EMIT,
    &equiv::EQUIV,
    &round::RECOMPILE,
    &round::VERIFY,
    &identify::IDENTIFY,
    &program::ANALYZE,
    &program::DISASSEMBLE,
    &emit::PROGRAM_EMIT,
    &equiv::PROGRAM_EQUIV,
    &program::LOAD,
    &emit::PASSES,
    &program::READ,
    &program::TABLES,
    &toolchain_evidence::EVIDENCE,
    &round::COMPARE_OP,
    &round::EXPORT,
    &round::GATES_OP,
    &round::IMPORT,
    &round::LIST,
    &round::RUN,
    &round::SHOW,
    &session::CONFIG,
    &session::CONFIG_SET,
    &sleigh::DISASSEMBLE,
    &sleigh::LIFT,
    &toolchain::CHECK_OP,
    &toolchain::LIST,
    &toolchain::OPEN,
    &toolchain::SPECS,
];

/// Operations registered at runtime (an `Extension`), and the result schemas they answer.
static EXTRA_OPS: RwLock<Vec<&'static Op>> = RwLock::new(Vec::new());
static EXTRA_SCHEMAS: RwLock<Vec<&'static Schema>> = RwLock::new(Vec::new());

/// A tier registered as one unit: its operations, the result schemas they answer and the option
/// keys they take. The dev tier is one (`mosura-dev-ops`); `mosura-capi` registers it under its
/// `dev-tools` feature when the context is built.
pub struct Extension {
    pub ops: &'static [&'static Op],
    pub schemas: &'static [&'static Schema],
    pub options: Vec<OptionSpec>,
}

/// Add an extension to the process's registries. Every name must be new (an operation, a schema
/// or an option key already registered is `InvalidArg`), every operation's parameters must be
/// registered keys and its result a known schema — the invariants the compiled registry's test
/// pins, checked here at run time. Never undone: call it once per process, before the first
/// dispatch (a failure part-way leaves what was registered before it).
pub fn register(ext: Extension) -> Result<()> {
    optreg::register(ext.options)?;
    {
        let mut schemas = EXTRA_SCHEMAS.write().unwrap_or_else(|e| e.into_inner());
        for s in ext.schemas {
            if compiled_schema(s.name).is_some() || schemas.iter().any(|x| x.name == s.name) {
                return Err(Error::InvalidArg(format!("schema `{}` is already registered", s.name)));
            }
            schemas.push(s);
        }
    }
    let mut ops = EXTRA_OPS.write().unwrap_or_else(|e| e.into_inner());
    for op in ext.ops {
        if REGISTRY.iter().chain(ops.iter()).any(|o| o.name == op.name) {
            return Err(Error::InvalidArg(format!("operation `{}` is already registered", op.name)));
        }
        for p in op.params {
            if *p != function::EMIT_KEYS && optreg::lookup(p).is_none() {
                return Err(Error::InvalidArg(format!("{}: param `{p}` is not a registered option key", op.name)));
            }
        }
        if schema(op.result).is_none() {
            return Err(Error::InvalidArg(format!("{}: result schema `{}` unknown", op.name, op.result)));
        }
        ops.push(op);
    }
    Ok(())
}

/// Every operation — the compiled registry plus the registered extensions — sorted by name.
pub fn registry() -> Vec<&'static Op> {
    let mut all: Vec<&'static Op> = REGISTRY.to_vec();
    all.extend(EXTRA_OPS.read().unwrap_or_else(|e| e.into_inner()).iter().copied());
    all.sort_by(|a, b| a.name.cmp(b.name));
    all
}

pub fn lookup(name: &str) -> Option<&'static Op> {
    REGISTRY.iter().find(|o| o.name == name).copied().or_else(|| EXTRA_OPS.read().unwrap_or_else(|e| e.into_inner()).iter().find(|o| o.name == name).copied())
}

/// Whether any registered operation belongs to the dev tier (the `dev-tools` build).
pub fn has_dev_tier() -> bool {
    EXTRA_OPS.read().unwrap_or_else(|e| e.into_inner()).iter().any(|o| o.tier == Tier::Dev)
}

/// The operation named, or the error for an unknown name: a `dev.*` name in a build without the
/// dev tier is `Unsupported` ("not built in"); anything else is `NotFound`.
fn find(name: &str) -> Result<&'static Op> {
    lookup(name).ok_or_else(|| {
        if name.starts_with("dev.") && !has_dev_tier() {
            Error::Unsupported(format!("operation `{name}`: the dev tier is not built in (build with the `dev-tools` feature)"))
        } else {
            Error::NotFound(format!("operation `{name}` (see `mosura ops`)"))
        }
    })
}

/// The registry as a table (`mosura ops`).
pub fn ops_table(tier: Option<Tier>) -> Table {
    let mut b = TableBuilder::new(&schemas::OPS);
    for op in registry().into_iter().filter(|o| tier.is_none_or(|t| o.tier == t)) {
        b.row().str(op.name).str(match op.tier { Tier::Product => "product", Tier::Dev => "dev" }).str(op.since).str(&op.cache_name()).str(&op.params.join(",")).str(op.result).str(op.doc);
    }
    b.finish(true)
}

/// Every compiled schema by name: program tables, session tables, op results, `text`.
fn compiled_schema(name: &str) -> Option<&'static Schema> {
    crate::program::schemas::by_name(name).or_else(|| crate::session::schemas::by_name(name)).or_else(|| schemas::by_name(name)).or_else(|| (name == crate::render::TEXT_SCHEMA).then_some(&crate::render::TEXT))
}

/// Every schema by name: the compiled ones plus the registered extensions'.
pub fn schema(name: &str) -> Option<&'static Schema> {
    compiled_schema(name).or_else(|| EXTRA_SCHEMAS.read().unwrap_or_else(|e| e.into_inner()).iter().copied().find(|s| s.name == name))
}

/// A schema as a table (`mosura schema <name>`).
pub fn schema_table(name: &str) -> Result<Table> {
    let s = schema(name).ok_or_else(|| Error::NotFound(format!("schema `{name}`")))?;
    let mut b = TableBuilder::new(&schemas::SCHEMA);
    for c in s.columns {
        b.row().str(c.name).str(c.ty.name()).str(match c.hint { crate::schema::ColHint::Hex => "hex", crate::schema::ColHint::Dec => "dec" });
    }
    Ok(b.finish(false))
}

/// Write the embedded data into `dir` (`what` = specs | fid | all); the files written.
pub fn export_data(ctx: &Context, dir: &std::path::Path, what: &str, overwrite: bool) -> Result<Table> {
    let written = ctx.resources.export(dir, what, overwrite).map_err(|e| Error::io(e, dir.to_path_buf()))?;
    let mut b = TableBuilder::new(&schemas::FILES);
    for p in written {
        b.row().str(&p.display().to_string());
    }
    Ok(b.finish(false))
}

/// Every resource in effect and where it comes from (`embedded`, or the overriding directory).
pub fn data_list(ctx: &Context) -> Table {
    let mut b = TableBuilder::new(&schemas::DATA);
    for (name, source) in ctx.resources.in_effect() {
        let from = match source {
            mosura_core::resources::Source::Embedded => "embedded".to_string(),
            mosura_core::resources::Source::Dir(d) => d.display().to_string(),
        };
        b.row().str(&name).str(&from);
    }
    b.finish(true)
}

/// Does `op` accept `key`? Its own parameters, the `emit.*` marker, and every Diagnostic key.
pub fn accepts(op: &Op, key: &str) -> bool {
    let diagnostic = optreg::lookup(key).is_some_and(|s| s.affects == Affects::Diagnostic);
    let emit = op.params.contains(&function::EMIT_KEYS) && key.starts_with("emit.") && key != keys::EMIT_ARMS_OFF;
    diagnostic || emit || op.params.contains(&key)
}

/// The parameters an op accepts: its own list, plus every Diagnostic key.
fn validate_params(op: &Op, params: &Options) -> Result<()> {
    for (k, _) in params.explicit() {
        if !accepts(op, k) {
            return Err(Error::InvalidArg(format!("`{k}` is not a parameter of `{}` (accepts: {})", op.name, op.params.join(", "))));
        }
    }
    Ok(())
}

/// Run an operation from inside another (the caller already runs under the boundary): the
/// parameters are projected onto what the op accepts, so a composite op passes its own set along.
pub fn dispatch_inner(s: &mut Session, op: &str, params: &Options) -> Result<Table> {
    let spec = find(op)?;
    let mut o = Options::new();
    for (k, v) in params.explicit() {
        if accepts(spec, k) {
            o.set(k, v)?;
        }
    }
    (spec.run)(s, &o, &mut NoProgress)
}

/// Run one operation: NotFound for an unknown name, InvalidArg for a key the op does not take, a
/// panic inside the body → `Error::Internal` carrying its message (unless the context aborts).
pub fn dispatch(ctx: &Context, s: &mut Session, op: &str, params: &Options, progress: &mut dyn Progress) -> Result<Table> {
    // The DIAGNOSTIC keys (`debug.*`) are the caller's choice for THIS operation — they never
    // enter a cache key — and this is where they reach the library: `Options::debug_config`
    // was built and tested, then never called, so `mosura analyze --debug analysis` printed
    // nothing (measured: the analysis manager's own per-analyzer tracing stayed silent).
    mosura_core::debug::configure(params.debug_config()?);
    let op = find(op)?;
    validate_params(op, params)?;
    if ctx.abort_on_panic {
        return (op.run)(s, params, progress);
    }
    match catch_unwind(AssertUnwindSafe(|| (op.run)(s, params, progress))) {
        Ok(r) => r,
        Err(payload) => {
            let msg = payload.downcast_ref::<String>().cloned().or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_else(|| "panic".to_string());
            Err(Error::Internal(format!("{}: {msg}", op.name)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_sorted_unique_and_every_param_and_result_is_registered() {
        let names: Vec<&str> = REGISTRY.iter().map(|o| o.name).collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(names, sorted, "REGISTRY is sorted by name and unique");
        for op in REGISTRY {
            for p in op.params {
                assert!(*p == function::EMIT_KEYS || optreg::lookup(p).is_some(), "{}: param `{p}` is not a registered option key", op.name);
            }
            assert!(schema(op.result).is_some(), "{}: result schema `{}` unknown", op.name, op.result);
        }
        // the table lists every compiled op (an extension test in this process may add more)
        let listed: Vec<String> = { let t = ops_table(None); (0..t.rows()).map(|r| t.str(r, 0).unwrap().to_string()).collect() };
        assert!(names.iter().all(|n| listed.iter().any(|l| l == n)), "{listed:?}");
        assert!(schema_table("identify").unwrap().rows() == 3);
        assert!(schema_table("nope").is_err());
    }

    /// An extension's names must be new and its parameters/result registered; once in, its op is
    /// looked up, listed and dispatched like a compiled one. Without a dev tier a `dev.*` name is
    /// "not built in", not "not found".
    #[test]
    fn an_extension_registers_once_and_is_validated() {
        use crate::schema::{ColType, Column};
        static ECHO_SCHEMA: Schema = Schema { name: "test_echo", version: 1, columns: &[Column::new("value", ColType::Str)] };
        static ECHO: Op = Op { name: "test.echo", doc: "answers test.value", since: "0.1", tier: Tier::Product, params: &["test.value"], result: "test_echo", cache: Cache::Transient, run: |_s, o, _p| { let mut b = TableBuilder::new(&ECHO_SCHEMA); b.row().str(o.get("test.value")?); Ok(b.finish(false)) } };
        static BAD_PARAM: Op = Op { name: "test.bad", doc: "", since: "0.1", tier: Tier::Product, params: &["test.nope"], result: "test_echo", cache: Cache::Transient, run: |_s, _o, _p| Err(Error::Cancelled) };
        static BAD_RESULT: Op = Op { name: "test.bad2", doc: "", since: "0.1", tier: Tier::Product, params: &[], result: "test_nope", cache: Cache::Transient, run: |_s, _o, _p| Err(Error::Cancelled) };
        static ECHO_OPS: &[&Op] = &[&ECHO];
        static ECHO_SCHEMAS: &[&Schema] = &[&ECHO_SCHEMA];
        static BAD_PARAM_OPS: &[&Op] = &[&BAD_PARAM];
        static BAD_RESULT_OPS: &[&Op] = &[&BAD_RESULT];
        let key = || OptionSpec { key: "test.value", ty: crate::options::OptType::Str, default: "", doc: "a test value", since: "0.1", affects: Affects::Input };
        assert!(matches!(dispatch_inner(&mut Session::open(None).unwrap(), "dev.zzz", &Options::new()), Err(Error::Unsupported(m)) if m.contains("not built in")));
        assert!(matches!(dispatch_inner(&mut Session::open(None).unwrap(), "nope.zzz", &Options::new()), Err(Error::NotFound(_))));
        register(Extension { ops: ECHO_OPS, schemas: ECHO_SCHEMAS, options: vec![key()] }).unwrap();
        assert!(matches!(register(Extension { ops: ECHO_OPS, schemas: &[], options: vec![] }), Err(Error::InvalidArg(m)) if m.contains("already registered")));
        assert!(matches!(register(Extension { ops: &[], schemas: ECHO_SCHEMAS, options: vec![] }), Err(Error::InvalidArg(m)) if m.contains("schema `test_echo`")));
        assert!(matches!(register(Extension { ops: &[], schemas: &[], options: vec![key()] }), Err(Error::InvalidArg(m)) if m.contains("option key `test.value`")));
        assert!(matches!(register(Extension { ops: BAD_PARAM_OPS, schemas: &[], options: vec![] }), Err(Error::InvalidArg(m)) if m.contains("test.nope")));
        assert!(matches!(register(Extension { ops: BAD_RESULT_OPS, schemas: &[], options: vec![] }), Err(Error::InvalidArg(m)) if m.contains("test_nope")));
        assert_eq!(lookup("test.echo").map(|o| o.name), Some("test.echo"));
        assert!(schema("test_echo").is_some() && schema_table("test_echo").unwrap().rows() == 1);
        let names: Vec<&str> = registry().iter().map(|o| o.name).collect();
        assert!(names.contains(&"test.echo") && names.windows(2).all(|w| w[0] < w[1]));
        assert_eq!(ops_table(None).rows() as usize, REGISTRY.len() + 1);
        assert_eq!(ops_table(Some(Tier::Dev)).rows(), 0);
        let mut s = Session::open(None).unwrap();
        let mut o = Options::new();
        o.set("test.value", "hello").unwrap();
        let t = dispatch_inner(&mut s, "test.echo", &o).unwrap();
        assert_eq!(t.str(0, 0).unwrap(), "hello");
        assert!(matches!(o.set("test.other", "x"), Err(Error::InvalidArg(_))));
    }
}
