//! Result schemas of the dev operations.

use mosura_api::{ColType as T, Column as C, Schema};

/// `dev.omf.dump`: one row per segment, public, code fixup, external; with a symbol, the
/// extracted candidate and its normalized instructions.
pub static OMF_DUMP: Schema = Schema { name: "omf_dump", version: 1, columns: &[C::new("kind", T::Str), C::new("name", T::Str), C::new("seg", T::U32), C::hex("off", T::U64), C::new("size", T::U64), C::new("detail", T::Str)] };

pub static ALL: &[&Schema] = &[&OMF_DUMP];
