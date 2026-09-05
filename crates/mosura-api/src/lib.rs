//! mosura-api — sessions, operations, options, tables and the flat session store over
//! `mosura-core` (`docs/product/architecture.md` §3–§5). INTERNAL: `pub` so it is unit-tested in
//! Rust without FFI, but nothing outside `mosura-capi` links it, and it promises nothing. The
//! library reads no environment variable and no configuration file; it receives values.

pub mod ctx;
pub mod error;
pub mod fingerprint;
pub mod key;
pub mod ops;
pub mod options;
pub mod program;
pub mod render;
pub mod schema;
pub mod session;
pub mod set;
pub mod table;
pub mod tbl;

pub use ctx::{Context, ContextConfig};
pub use error::{Error, Result};
pub use fingerprint::Stage;
pub use key::Key;
pub use ops::{dispatch, Cache, Extension, NoProgress, Op, Progress, Tier};
pub use options::{Affects, OptType, OptionSpec, Options};
pub use render::{render, Format};
pub use set::TableSet;
pub use schema::{ColHint, ColType, Column, Schema, SchemaRef};
pub use session::{Provenance, Session, SetKind};
pub use table::{builder::TableBuilder, Table};
