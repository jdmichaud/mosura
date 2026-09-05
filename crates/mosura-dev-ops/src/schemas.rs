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

/// `dev.census.over-decode`: the self-test row, the instruction/block rows, one summary row per
/// check (count, its denominator) and up to 20 detail rows each.
pub static OVER_DECODE: Schema = Schema { name: "over_decode", version: 1, columns: &[C::new("check", T::Str), C::new("count", T::U64), C::new("denominator", T::U64), C::new("detail", T::Str)] };

/// `dev.census.terminator-rate`: the truth row, BOTH arms (control first), the diag row, the
/// reading rule, then failure rows when asked.
pub static TERMINATOR_RATE: Schema = Schema { name: "terminator_rate", version: 1, columns: &[C::new("arm", T::Str), C::new("terminating", T::U64), C::new("total", T::U64), C::new("rate_pct", T::F64), C::new("detail", T::Str)] };

/// `dev.census.watsched`: one row per emitted function.
pub static WATSCHED_CENSUS: Schema = Schema { name: "watsched_census", version: 1, columns: &[C::new("idx", T::U32), C::hex("va", T::U64), C::new("insns", T::U64), C::new("windows", T::U64), C::new("moving", T::U64), C::new("max_moved", T::U64), C::new("unexplained", T::U64)] };

/// `dev.census.split-store`: one row per emitted function (`first_pc`/`swap_pc` 0 when none).
pub static SPLIT_STORE: Schema = Schema { name: "split_store", version: 1, columns: &[C::new("idx", T::U32), C::hex("va", T::U64), C::new("stores", T::U64), C::new("separated", T::U64), C::hex("first_pc", T::U64), C::new("reg", T::Str), C::new("load_swaps", T::U64), C::hex("swap_pc", T::U64), C::new("rule", T::Str)] };

/// `dev.foreign.facts`: the engine's per-function facts.
pub static FOREIGN_FACTS: Schema = Schema { name: "foreign_facts", version: 1, columns: &[C::hex("va", T::U64), C::new("size", T::U64), C::hex("lo", T::U64), C::hex("hi", T::U64), C::new("fid", T::Bool), C::new("ncallers", T::U64), C::new("ncallees", T::U64), C::new("ffp", T::Bool), C::new("prologue", T::Str), C::new("anchor", T::Str)] };

/// `dev.foreign.propose`: the locality bands, ranked by seed count.
pub static FOREIGN_BANDS: Schema = Schema { name: "foreign_bands", version: 1, columns: &[C::new("label", T::Str), C::new("class", T::Str), C::new("seeds", T::U64), C::new("span", T::U64), C::new("ffp_pct", T::F64), C::new("fid_in_span", T::U64), C::hex("lo", T::U64), C::hex("hi", T::U64), C::new("example", T::Str)] };

pub static ALL: &[&Schema] = &[&OMF_DUMP, &ORACLE_SWEEP, &BENCH, &GT_REPORT, &MVE_FIXTURES, &OVER_DECODE, &TERMINATOR_RATE, &WATSCHED_CENSUS, &SPLIT_STORE, &FOREIGN_FACTS, &FOREIGN_BANDS];
