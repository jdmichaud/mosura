//! mosura-api — sessions, operations, options, tables and the flat session store over
//! `mosura-core` (`docs/product/architecture.md` §3–§5). INTERNAL: `pub` so it is unit-tested in
//! Rust without FFI, but nothing outside `mosura-capi` links it, and it promises nothing. The
//! library reads no environment variable and no configuration file; it receives values.

pub mod error;
pub mod render;
pub mod schema;
pub mod table;
pub mod tbl;

pub use error::{Error, Result};
pub use render::{render, Format};
pub use schema::{ColHint, ColType, Column, Schema, SchemaRef};
pub use table::{builder::TableBuilder, Table};
