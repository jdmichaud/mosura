//! mosura-dev-ops — the dev tier (`docs/product/architecture.md` §6.4; plan WP7 §3 P4): the
//! oracle sweeps, censuses, ground truth, fixtures and probes that develop mosura against its
//! oracles, as operations in the same registry as the product's (`tier: Dev`, names `dev.*`).
//! `mosura-capi` registers them when the context is built, under its `dev-tools` feature; a
//! release library has none of them and answers a `dev.*` name with "not built in". The tier
//! reads the developer configuration (`dev-config.toml`) and the workspace through
//! `mosura-core`'s own dev tier (`feature = "dev"`) — never the environment.

pub mod keys;
pub mod omf;
pub mod schemas;

use std::sync::OnceLock;

use mosura_api::ops::{Extension, Op};

/// Every dev operation, sorted by name (the test pins order, uniqueness and validity).
pub static OPS: &[&Op] = &[&omf::DUMP];

/// Register the dev tier into the process's registries. Idempotent: the first call registers,
/// later calls answer its result (a context is built more than once per process in tests).
pub fn register() -> mosura_api::Result<()> {
    static DONE: OnceLock<Result<(), String>> = OnceLock::new();
    DONE.get_or_init(|| mosura_api::ops::register(Extension { ops: OPS, schemas: schemas::ALL, options: keys::all() }).map_err(|e| e.to_string()))
        .clone()
        .map_err(|m| mosura_api::Error::Internal(format!("dev tier registration: {m}")))
}
