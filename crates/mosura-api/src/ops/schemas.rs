//! Result schemas of the operations (design §4.3); the program tables are in `program::schemas`.

use crate::schema::{ColType as T, Column as C, Schema};

pub static OPS: Schema = Schema { name: "ops", version: 1, columns: &[C::new("name", T::Str), C::new("tier", T::Str), C::new("since", T::Str), C::new("cache", T::Str), C::new("params", T::Str), C::new("result", T::Str), C::new("doc", T::Str)] };
pub static SCHEMA: Schema = Schema { name: "schema", version: 1, columns: &[C::new("col", T::Str), C::new("type", T::Str), C::new("hint", T::Str)] };
pub static IDENTIFY: Schema = Schema { name: "identify", version: 1, columns: &[C::new("key", T::Str), C::new("value", T::Str), C::new("evidence", T::Str)] };
pub static PROGRAM_SUMMARY: Schema = Schema { name: "program_summary", version: 1, columns: &[C::new("key", T::Str), C::new("language", T::Str), C::new("cspec", T::Str), C::new("compiler", T::Str), C::new("version", T::Str), C::hex("base", T::U64), C::new("addr_size", T::U32), C::new("blocks", T::U64), C::new("functions", T::U64), C::new("symbols", T::U64), C::new("refs", T::U64), C::new("insns", T::U64)] };
pub static TABLES: Schema = Schema { name: "tables", version: 1, columns: &[C::new("name", T::Str), C::new("rows", T::U64), C::new("digest", T::Str)] };
pub static BYTES: Schema = Schema { name: "bytes", version: 1, columns: &[C::hex("addr", T::U64), C::new("bytes", T::Bytes)] };
pub static INSTRUCTIONS: Schema = Schema { name: "instructions", version: 1, columns: &[C::hex("addr", T::U64), C::new("len", T::U32), C::new("bytes", T::Bytes), C::new("mnemonic", T::Str), C::new("operands", T::Str), C::new("flow_kind", T::Str), C::new("ends_flow", T::Bool), C::new("has_call_target", T::Bool), C::hex("call_target", T::U64), C::hex("flows", T::ListU64)] };

pub static ALL: &[&Schema] = &[&OPS, &SCHEMA, &IDENTIFY, &PROGRAM_SUMMARY, &TABLES, &BYTES, &INSTRUCTIONS];

pub fn by_name(name: &str) -> Option<&'static Schema> {
    ALL.iter().copied().find(|s| s.name == name)
}
