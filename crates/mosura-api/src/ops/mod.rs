//! The operation registry and dispatcher (design §4.1): every capability is one registered `Op`
//! — a name, the keys it accepts, the schema it answers, its cache class and a body that
//! orchestrates core calls and decides nothing. `dispatch` looks the op up, validates the
//! parameters against the registry, runs the body under `catch_unwind` (unless the context says
//! abort) and hands back one table. New capability = one more entry in `REGISTRY`.

pub mod emit;
pub mod function;
pub mod identify;
pub mod program;
pub mod schemas;
pub mod sleigh;

use std::panic::{catch_unwind, AssertUnwindSafe};

use crate::ctx::Context;
use crate::error::{Error, Result};
use crate::fingerprint::Stage;
use crate::options::{keys, registry as optreg, Affects, Options};
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
    &function::DECOMPILE,
    &emit::EMIT,
    &identify::IDENTIFY,
    &program::ANALYZE,
    &program::DISASSEMBLE,
    &program::LOAD,
    &emit::PASSES,
    &program::READ,
    &program::TABLES,
    &sleigh::DISASSEMBLE,
    &sleigh::LIFT,
];

pub fn registry() -> &'static [&'static Op] {
    REGISTRY
}

pub fn lookup(name: &str) -> Option<&'static Op> {
    REGISTRY.iter().find(|o| o.name == name).copied()
}

/// The registry as a table (`mosura ops`).
pub fn ops_table(tier: Option<Tier>) -> Table {
    let mut b = TableBuilder::new(&schemas::OPS);
    for op in REGISTRY.iter().filter(|o| tier.is_none_or(|t| o.tier == t)) {
        b.row().str(op.name).str(match op.tier { Tier::Product => "product", Tier::Dev => "dev" }).str(op.since).str(&op.cache_name()).str(&op.params.join(",")).str(op.result).str(op.doc);
    }
    b.finish(true)
}

/// Every compiled schema by name: program tables, session tables, op results, `text`.
pub fn schema(name: &str) -> Option<&'static Schema> {
    crate::program::schemas::by_name(name).or_else(|| crate::session::schemas::by_name(name)).or_else(|| schemas::by_name(name)).or_else(|| (name == crate::render::TEXT_SCHEMA).then_some(&crate::render::TEXT))
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

/// The parameters an op accepts: its own list, plus every Diagnostic key.
fn validate_params(op: &Op, params: &Options) -> Result<()> {
    let emit_keys = op.params.contains(&function::EMIT_KEYS);
    for (k, _) in params.explicit() {
        let diagnostic = optreg::lookup(k).is_some_and(|s| s.affects == Affects::Diagnostic);
        let emit = emit_keys && k.starts_with("emit.") && k != keys::EMIT_ARMS_OFF;
        if !diagnostic && !emit && !op.params.contains(&k) {
            return Err(Error::InvalidArg(format!("`{k}` is not a parameter of `{}` (accepts: {})", op.name, op.params.join(", "))));
        }
    }
    Ok(())
}

/// Run one operation: NotFound for an unknown name, InvalidArg for a key the op does not take, a
/// panic inside the body → `Error::Internal` carrying its message (unless the context aborts).
pub fn dispatch(ctx: &Context, s: &mut Session, op: &str, params: &Options, progress: &mut dyn Progress) -> Result<Table> {
    let op = lookup(op).ok_or_else(|| Error::NotFound(format!("operation `{op}` (see `mosura ops`)")))?;
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
        assert_eq!(ops_table(None).rows() as usize, REGISTRY.len());
        assert!(schema_table("identify").unwrap().rows() == 3);
        assert!(schema_table("nope").is_err());
    }
}
