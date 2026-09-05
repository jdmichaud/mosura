//! The program table schemas (design §5.6), v1 each. Column order is the row layout.

use crate::schema::{ColType as T, Column as C, Schema};

pub static PROGRAM: Schema = Schema { name: "program", version: 1, columns: &[C::new("language_id", T::Str), C::new("compiler_spec_id", T::Str), C::new("compiler", T::Str), C::new("compiler_version", T::Str), C::new("has_version", T::Bool), C::new("compiler_signature", T::Str), C::new("has_signature", T::Bool), C::new("image_space", T::U32), C::hex("image_base", T::U64), C::new("big_endian", T::Bool), C::new("addr_size_bits", T::U32), C::new("default_space", T::U32), C::new("relocatable", T::Bool), C::new("options_tag", T::Str)] };
pub static SPACES: Schema = Schema { name: "spaces", version: 1, columns: &[C::new("id", T::U32), C::new("name", T::Str), C::new("kind", T::U8), C::new("addr_size", T::U32), C::new("big_endian", T::Bool), C::new("wordsize", T::U32), C::new("delay", T::I64), C::new("deadcodedelay", T::I64), C::new("has_contain", T::Bool), C::new("contain", T::U32), C::hex("spacebase", T::ListU64)] };
pub static BLOCKS: Schema = Schema { name: "blocks", version: 1, columns: &[C::new("space", T::U32), C::hex("start", T::U64), C::hex("end", T::U64), C::new("name", T::Str), C::new("read", T::Bool), C::new("write", T::Bool), C::new("execute", T::Bool), C::new("initialized", T::Bool), C::new("blob_off", T::U64), C::new("blob_len", T::U64)] };
pub static FUNCTIONS: Schema = Schema { name: "functions", version: 1, columns: &[C::new("space", T::U32), C::hex("entry", T::U64), C::new("name", T::Str)] };
pub static BODIES: Schema = Schema { name: "bodies", version: 1, columns: &[C::new("fn_space", T::U32), C::hex("fn_entry", T::U64), C::new("space", T::U32), C::hex("min", T::U64), C::hex("max", T::U64)] };
pub static SYMBOLS: Schema = Schema { name: "symbols", version: 1, columns: &[C::new("space", T::U32), C::hex("addr", T::U64), C::new("name", T::Str), C::new("type", T::U8), C::new("primary", T::Bool), C::new("external", T::Bool)] };
pub static REFERENCES: Schema = Schema { name: "references", version: 1, columns: &[C::new("from_space", T::U32), C::hex("from", T::U64), C::new("to_space", T::U32), C::hex("to", T::U64), C::new("type", T::U8), C::new("op_index", T::I64)] };
pub static LISTING: Schema = Schema { name: "listing", version: 1, columns: &[C::new("space", T::U32), C::hex("addr", T::U64), C::new("len", T::U32), C::new("kind", T::U8), C::new("flow_kind", T::U8), C::new("flow_ref", T::U8), C::new("ends_flow", T::Bool), C::new("has_call_target", T::Bool), C::hex("call_target", T::U64), C::hex("flows", T::ListU64), C::new("type_name", T::Str)] };
pub static RELOCATIONS: Schema = Schema { name: "relocations", version: 1, columns: &[C::new("space", T::U32), C::hex("addr", T::U64), C::hex("value", T::U64)] };
pub static ENTRY_POINTS: Schema = Schema { name: "entry_points", version: 1, columns: &[C::new("space", T::U32), C::hex("addr", T::U64)] };
pub static COMMENTS: Schema = Schema { name: "comments", version: 1, columns: &[C::hex("addr", T::U64), C::new("kind", T::U8), C::new("text", T::Str)] };
pub static INDIRECT_BRANCHES: Schema = Schema { name: "indirect_branches", version: 1, columns: &[C::hex("addr", T::U64)] };
pub static NORETURN: Schema = Schema { name: "noreturn", version: 1, columns: &[C::new("space", T::U32), C::hex("addr", T::U64)] };
pub static DEFINED_DATA: Schema = Schema { name: "defined_data", version: 1, columns: &[C::new("space", T::U32), C::hex("addr", T::U64), C::new("type_name", T::Str), C::new("len", T::U32)] };
pub static FLOW_OVERRIDES: Schema = Schema { name: "flow_overrides", version: 1, columns: &[C::new("space", T::U32), C::hex("addr", T::U64), C::new("kind", T::U8)] };
pub static FACTS: Schema = Schema { name: "facts", version: 1, columns: &[C::hex("fn", T::U64), C::new("kind", T::U8), C::new("payload", T::Str)] };
pub static PROTOS: Schema = Schema { name: "protos", version: 1, columns: &[C::hex("fn", T::U64), C::new("has_output", T::Bool), C::new("out_space", T::U32), C::hex("out_offset", T::U64), C::new("out_size", T::U32), C::new("has_model", T::Bool), C::new("model", T::U32)] };
pub static PROTO_SLOTS: Schema = Schema { name: "proto_slots", version: 1, columns: &[C::hex("fn", T::U64), C::new("idx", T::U32), C::new("space", T::U32), C::hex("offset", T::U64), C::new("size", T::U32)] };
pub static PROTO_MODELS: Schema = Schema { name: "proto_models", version: 1, columns: &[C::new("id", T::U32), C::new("parent", T::I64), C::new("name", T::Str), C::new("print_in_decl", T::Bool), C::new("extrapop", T::I64), C::new("custom_conventions", T::Bool), C::new("has_input", T::Bool), C::new("has_output", T::Bool)] };
pub static PARAM_LISTS: Schema = Schema { name: "param_lists", version: 1, columns: &[C::new("model", T::U32), C::new("which", T::U8), C::new("is_output", T::Bool), C::new("resource_start", T::ListU32)] };
pub static PARAM_ENTRIES: Schema = Schema { name: "param_entries", version: 1, columns: &[C::new("model", T::U32), C::new("which", T::U8), C::new("idx", T::U32), C::new("group", T::U32), C::new("type_class", T::U8), C::new("space", T::U32), C::hex("addressbase", T::U64), C::new("size", T::U32), C::new("minsize", T::U32), C::new("alignment", T::U32)] };
pub static EFFECTS: Schema = Schema { name: "effects", version: 1, columns: &[C::new("model", T::U32), C::new("idx", T::U32), C::new("space", T::U32), C::hex("offset", T::U64), C::new("size", T::U32), C::new("effect", T::U8)] };
pub static MODEL_RANGES: Schema = Schema { name: "model_ranges", version: 1, columns: &[C::new("model", T::U32), C::new("which", T::U8), C::new("spc", T::U32), C::hex("first", T::U64), C::hex("last", T::U64)] };
pub static LIKELYTRASH: Schema = Schema { name: "likelytrash", version: 1, columns: &[C::new("model", T::U32), C::new("idx", T::U32), C::new("space", T::U32), C::hex("offset", T::U64), C::new("size", T::U32)] };
pub static TYPES: Schema = Schema { name: "types", version: 1, columns: &[C::new("id", T::U32), C::new("kind", T::U8), C::new("size", T::U32), C::new("sub", T::I64), C::new("count", T::U64), C::new("fields", T::ListU64)] };
pub static SRET_FACTS: Schema = Schema { name: "sret_facts", version: 1, columns: &[C::hex("fn", T::U64), C::new("has_shape", T::Bool), C::new("slot_space", T::U32), C::hex("slot_offset", T::U64), C::new("size", T::U32), C::new("has_ret_pop", T::Bool), C::new("ret_pop", T::U32)] };
pub static SRET_FIELDS: Schema = Schema { name: "sret_fields", version: 1, columns: &[C::hex("fn", T::U64), C::new("idx", T::U32), C::new("offset", T::U32), C::new("size", T::U32), C::new("type", T::U32)] };
pub static SRET_CALLERS: Schema = Schema { name: "sret_callers", version: 1, columns: &[C::hex("callee", T::U64), C::new("idx", T::U32), C::new("output_dead", T::Bool), C::new("arg0_local_addr", T::Bool)] };
pub static MANIFEST: Schema = Schema { name: "manifest", version: 1, columns: &[C::new("kind", T::Str), C::new("name", T::Str), C::new("value", T::Str)] };

/// Every program-set schema, by table name.
pub static ALL: &[&Schema] = &[&PROGRAM, &SPACES, &BLOCKS, &FUNCTIONS, &BODIES, &SYMBOLS, &REFERENCES, &LISTING, &RELOCATIONS, &ENTRY_POINTS, &COMMENTS, &INDIRECT_BRANCHES, &NORETURN, &DEFINED_DATA, &FLOW_OVERRIDES, &FACTS, &PROTOS, &PROTO_SLOTS, &PROTO_MODELS, &PARAM_LISTS, &PARAM_ENTRIES, &EFFECTS, &MODEL_RANGES, &LIKELYTRASH, &TYPES, &SRET_FACTS, &SRET_FIELDS, &SRET_CALLERS, &MANIFEST];

pub fn by_name(name: &str) -> Option<&'static Schema> {
    ALL.iter().copied().find(|s| s.name == name)
}
