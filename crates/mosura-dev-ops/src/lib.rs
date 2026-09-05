//! mosura-dev-ops — the dev tier (`docs/product/architecture.md` §6.4; plan WP7 §3 P4): the
//! oracle sweeps, censuses, ground truth, fixtures and probes that develop mosura against its
//! oracles, as operations in the same registry as the product's (`tier: Dev`, names `dev.*`).
//! `mosura-capi` registers them when the context is built, under its `dev-tools` feature; a
//! release library has none of them and answers a `dev.*` name with "not built in". The tier
//! reads the developer configuration (`dev-config.toml`) and the workspace through
//! `mosura-core`'s own dev tier (`feature = "dev"`) — never the environment.
//!
//! Conventions: a dev operation answers one typed table; files it writes go under `dev.out`
//! (or the session's `dev/` directory); a table with an `ok` column reports per-row success and
//! `mosura dev` exits 1 when any row is false.

pub mod bench;
pub mod groundtruth;
pub mod keys;
pub mod mve;
pub mod omf;
pub mod oracle;
pub mod schemas;

use std::path::PathBuf;
use std::sync::OnceLock;

use mosura_api::ops::{Extension, Op};
use mosura_api::{Error, Options, Result, Session};

/// Every dev operation, sorted by name (the test pins order, uniqueness and validity).
pub static OPS: &[&Op] = &[&bench::BENCH, &groundtruth::RECOMPILE, &mve::FIXTURES, &omf::DUMP, &oracle::SWEEP];

/// Register the dev tier into the process's registries. Idempotent: the first call registers,
/// later calls answer its result (a context is built more than once per process in tests).
pub fn register() -> Result<()> {
    static DONE: OnceLock<std::result::Result<(), String>> = OnceLock::new();
    DONE.get_or_init(|| mosura_api::ops::register(Extension { ops: OPS, schemas: schemas::ALL, options: keys::all() }).map_err(|e| e.to_string()))
        .clone()
        .map_err(|m| Error::Internal(format!("dev tier registration: {m}")))
}

/// A Bool option (`1/true/on/yes` as the registry accepts them).
pub(crate) fn flag(o: &Options, key: &str) -> Result<bool> {
    Ok(matches!(o.get(key)?.trim(), "1" | "true" | "on" | "yes"))
}

/// The list elements of a `List` option, trimmed, empties dropped.
pub(crate) fn list(o: &Options, key: &str) -> Result<Vec<String>> {
    Ok(o.get(key)?.split(',').map(str::trim).filter(|t| !t.is_empty()).map(str::to_string).collect())
}

/// The directory a dev operation writes under: `dev.out` when set, else `<session>/dev/<sub>`;
/// an in-memory session without `dev.out` has nowhere to write.
pub(crate) fn out_dir(s: &Session, o: &Options, sub: &str) -> Result<PathBuf> {
    let out = o.get(keys::DEV_OUT)?;
    let dir = if !out.is_empty() {
        PathBuf::from(out)
    } else {
        s.dir().ok_or_else(|| Error::Unsupported(format!("`{}` is required for an in-memory session (or open the session with a directory)", keys::DEV_OUT)))?.join("dev").join(sub)
    };
    std::fs::create_dir_all(&dir).map_err(|e| Error::io(e, dir.clone()))?;
    Ok(dir)
}

pub(crate) fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
