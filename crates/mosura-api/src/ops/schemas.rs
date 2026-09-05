//! Result schemas of the operations (design §4.3); the program tables are in `program::schemas`.

use crate::schema::{ColType as T, Column as C, Schema};

pub static OPS: Schema = Schema { name: "ops", version: 1, columns: &[C::new("name", T::Str), C::new("tier", T::Str), C::new("since", T::Str), C::new("cache", T::Str), C::new("params", T::Str), C::new("result", T::Str), C::new("doc", T::Str)] };
pub static SCHEMA: Schema = Schema { name: "schema", version: 1, columns: &[C::new("col", T::Str), C::new("type", T::Str), C::new("hint", T::Str)] };
pub static IDENTIFY: Schema = Schema { name: "identify", version: 1, columns: &[C::new("key", T::Str), C::new("value", T::Str), C::new("evidence", T::Str)] };
pub static PROGRAM_SUMMARY: Schema = Schema { name: "program_summary", version: 1, columns: &[C::new("key", T::Str), C::new("language", T::Str), C::new("cspec", T::Str), C::new("compiler", T::Str), C::new("version", T::Str), C::hex("base", T::U64), C::new("addr_size", T::U32), C::new("blocks", T::U64), C::new("functions", T::U64), C::new("symbols", T::U64), C::new("refs", T::U64), C::new("insns", T::U64)] };
pub static TABLES: Schema = Schema { name: "tables", version: 1, columns: &[C::new("name", T::Str), C::new("rows", T::U64), C::new("digest", T::Str)] };
pub static BYTES: Schema = Schema { name: "bytes", version: 1, columns: &[C::hex("addr", T::U64), C::new("bytes", T::Bytes)] };
pub static INSTRUCTIONS: Schema = Schema { name: "instructions", version: 1, columns: &[C::hex("addr", T::U64), C::new("len", T::U32), C::new("bytes", T::Bytes), C::new("mnemonic", T::Str), C::new("operands", T::Str), C::new("flow_kind", T::Str), C::new("ends_flow", T::Bool), C::new("has_call_target", T::Bool), C::hex("call_target", T::U64), C::hex("flows", T::ListU64)] };

pub static PCODE: Schema = Schema { name: "pcode", version: 1, columns: &[C::hex("addr", T::U64), C::new("seq", T::U32), C::new("opcode", T::U32), C::new("mnemonic", T::Str), C::new("has_out", T::Bool), C::new("out_space", T::Str), C::hex("out_offset", T::U64), C::new("out_size", T::U32), C::new("in_spaces", T::Str), C::hex("in_offsets", T::ListU64), C::new("in_sizes", T::ListU32), C::new("text", T::Str)] };

pub static PROTOTYPE: Schema = Schema { name: "prototype", version: 1, columns: &[C::new("idx", T::U32), C::new("kind", T::Str), C::new("space", T::U32), C::hex("offset", T::U64), C::new("size", T::U32), C::new("model", T::Str)] };
pub static JUMPTABLES: Schema = Schema { name: "jumptables", version: 1, columns: &[C::hex("op_addr", T::U64), C::new("idx", T::U32), C::hex("target", T::U64), C::new("label", T::I64), C::new("is_default", T::Bool)] };
pub static CALLS: Schema = Schema { name: "calls", version: 1, columns: &[C::hex("op_pc", T::U64), C::hex("target", T::U64), C::new("has_static_target", T::Bool)] };

pub static GLOBAL_WIDTHS: Schema = Schema { name: "global_widths", version: 1, columns: &[C::hex("addr", T::U64), C::new("store_w", T::U32), C::new("read_w", T::U32)] };
pub static EMIT_REPORT: Schema = Schema { name: "emit_report", version: 1, columns: &[C::new("key", T::Str), C::new("value", T::Str)] };

pub static OPTION_REGISTRY: Schema = Schema { name: "option_registry", version: 1, columns: &[C::new("key", T::Str), C::new("type", T::Str), C::new("default", T::Str), C::new("doc", T::Str), C::new("since", T::Str), C::new("affects", T::Str)] };
pub static FILES: Schema = Schema { name: "files", version: 1, columns: &[C::new("path", T::Str)] };
pub static DATA: Schema = Schema { name: "data", version: 1, columns: &[C::new("name", T::Str), C::new("source", T::Str)] };

pub static LANGUAGES: Schema = Schema { name: "languages", version: 1, columns: &[C::new("id", T::Str), C::new("processor", T::Str), C::new("endian", T::Str), C::new("size", T::U32), C::new("variant", T::Str), C::new("version", T::Str), C::new("description", T::Str), C::new("cspecs", T::Str)] };
pub static REGISTERS: Schema = Schema { name: "registers", version: 1, columns: &[C::new("name", T::Str), C::new("space", T::Str), C::hex("offset", T::U64), C::new("size", T::U32)] };
pub static EMIT_AXES: Schema = Schema { name: "emit_axes", version: 1, columns: &[C::new("name", T::Str), C::new("values", T::Str), C::new("default", T::Str), C::new("doc", T::Str)] };
pub static EMIT_ARMS: Schema = Schema { name: "emit_arms", version: 1, columns: &[C::new("name", T::Str)] };

pub static TOOLCHAIN_SPECS: Schema = Schema { name: "toolchain_specs", version: 1, columns: &[C::new("name", T::Str), C::new("host", T::Str), C::new("doc", T::Str)] };
pub static TOOLCHAINS: Schema = Schema { name: "toolchains", version: 1, columns: &[C::new("name", T::Str), C::new("spec", T::Str), C::new("id", T::Str), C::new("install", T::Str), C::new("cache", T::Str), C::new("lock", T::Str)] };
pub static CHECK: Schema = Schema { name: "check", version: 1, columns: &[C::new("name", T::Str), C::new("ok", T::Bool), C::new("adjudicated", T::Bool), C::new("log", T::Str)] };
pub static EMISSION: Schema = Schema { name: "emission", version: 1, columns: &[C::new("idx", T::U32), C::hex("va", T::U64), C::new("name", T::Str), C::new("status", T::Str), C::new("kind", T::Str), C::new("orig_len", T::U64), C::new("tu", T::Str), C::new("row", T::Str)] };

pub static ALL: &[&Schema] = &[&OPS, &SCHEMA, &IDENTIFY, &PROGRAM_SUMMARY, &TABLES, &BYTES, &INSTRUCTIONS, &PCODE, &PROTOTYPE, &JUMPTABLES, &CALLS, &GLOBAL_WIDTHS, &EMIT_REPORT, &OPTION_REGISTRY, &FILES, &DATA, &LANGUAGES, &REGISTERS, &EMIT_AXES, &EMIT_ARMS, &TOOLCHAIN_SPECS, &TOOLCHAINS, &CHECK, &EMISSION];

pub fn by_name(name: &str) -> Option<&'static Schema> {
    ALL.iter().copied().find(|s| s.name == name)
}
