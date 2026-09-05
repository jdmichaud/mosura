//! Result schemas of the dev operations.

use mosura_api::{ColType as T, Column as C, Schema};

/// `dev.omf.dump`: one row per segment, public, code fixup, external; with a symbol, the
/// extracted candidate and its normalized instructions.
pub static OMF_DUMP: Schema = Schema { name: "omf_dump", version: 1, columns: &[C::new("kind", T::Str), C::new("name", T::Str), C::new("seg", T::U32), C::hex("off", T::U64), C::new("size", T::U64), C::new("detail", T::Str)] };

/// `dev.oracle.sweep`: one row per swept function — the legacy `sweep.tsv` columns.
pub static ORACLE_SWEEP: Schema = Schema { name: "oracle_sweep", version: 1, columns: &[C::new("idx", T::U32), C::hex("va", T::U64), C::new("name", T::Str), C::new("status", T::Str), C::new("score", T::F64), C::new("mosura_lines", T::U64), C::new("ghidra_lines", T::U64)] };

/// `dev.bench`: per-fixture wall times, worst first, then the `*total*` and `*spec-load*` rows.
pub static BENCH: Schema = Schema { name: "bench", version: 1, columns: &[C::new("fixture", T::Str), C::new("total_ms", T::F64), C::new("build_ms", T::F64), C::new("decompile_ms", T::F64), C::new("print_ms", T::F64)] };

/// `dev.groundtruth.recompile`: one row per function, a `*summary*` row per program, an `ALL` row.
pub static GT_REPORT: Schema = Schema { name: "gt_report", version: 1, columns: &[C::new("program", T::Str), C::new("symbol", T::Str), C::hex("va", T::U64), C::new("verdict", T::Str), C::new("sim", T::F64), C::new("weight", T::U64), C::new("classes", T::Str), C::new("note", T::Str)] };

/// `dev.mve.fixtures`: one row per product (written | same | DIFFERS | MISSING | ORPHAN) and a
/// `*check*` summary row; `ok` false on any problem (the CLI exits 1).
pub static MVE_FIXTURES: Schema = Schema { name: "mve_fixtures", version: 1, columns: &[C::new("file", T::Str), C::new("size", T::U64), C::new("status", T::Str), C::new("ok", T::Bool)] };

pub static ALL: &[&Schema] = &[&OMF_DUMP, &ORACLE_SWEEP, &BENCH, &GT_REPORT, &MVE_FIXTURES];
