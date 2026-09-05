//! §5 Tables — every result. Cell views are valid for the table's life (tables are immutable).
//! Cell accessors: a type mismatch is MOSURA_ERR_INVALID_ARG, a row past the end MOSURA_ERR_NOT_FOUND.

use std::ffi::{c_char, c_int, c_void};

use crate::boundary::guard;
use crate::ctx::{ctx_of, mosura_ctx};
use crate::handle::{self, Kind};
use crate::mem::{bytes, cstr, out_ptr, view, view_bytes, mosura_bytes, mosura_view};
use crate::status::{self, mosura_status};
use mosura_api::{ColType, Error, Format, Result, Table};

/// An immutable result table with a schema (opaque).
#[repr(C)]
pub struct mosura_table {
    _private: [u8; 0],
}

/// Column types (the `.tbl` codes).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum mosura_col_type {
    MOSURA_COL_U8 = 1,
    MOSURA_COL_U16,
    MOSURA_COL_U32,
    MOSURA_COL_U64,
    MOSURA_COL_I64,
    MOSURA_COL_F64,
    MOSURA_COL_BOOL,
    /// UTF-8, in the blob
    MOSURA_COL_STR,
    /// raw bytes, in the blob
    MOSURA_COL_BYTES,
    /// variable-length list, in the blob
    MOSURA_COL_LIST_U32,
    MOSURA_COL_LIST_U64,
}

/// Renderings of a table.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum mosura_format {
    MOSURA_FMT_TEXT = 0,
    MOSURA_FMT_TSV,
    MOSURA_FMT_JSON,
}

fn col_type(c: ColType) -> mosura_col_type {
    use mosura_col_type::*;
    match c {
        ColType::U8 => MOSURA_COL_U8,
        ColType::U16 => MOSURA_COL_U16,
        ColType::U32 => MOSURA_COL_U32,
        ColType::U64 => MOSURA_COL_U64,
        ColType::I64 => MOSURA_COL_I64,
        ColType::F64 => MOSURA_COL_F64,
        ColType::Bool => MOSURA_COL_BOOL,
        ColType::Str => MOSURA_COL_STR,
        ColType::Bytes => MOSURA_COL_BYTES,
        ColType::ListU32 => MOSURA_COL_LIST_U32,
        ColType::ListU64 => MOSURA_COL_LIST_U64,
    }
}

pub(crate) fn new_table(t: Table) -> *mut mosura_table {
    handle::new(Kind::Table, t) as *mut mosura_table
}

pub(crate) unsafe fn table_of<'a>(p: *const mosura_table) -> Result<&'a Table> {
    handle::as_ref::<Table>(p as *const c_void, Kind::Table)
}

/// Schema identity: name (e.g. "functions"), version, column count.
#[no_mangle]
pub unsafe extern "C" fn mosura_table_schema(t: *const mosura_table, name: *mut mosura_view, version: *mut u32, ncols: *mut u32) -> mosura_status {
    guard(|| {
        let t = table_of(t)?;
        if !name.is_null() {
            *name = view(t.schema().name().as_bytes());
        }
        if !version.is_null() {
            *version = t.schema().version();
        }
        if !ncols.is_null() {
            *ncols = t.ncols();
        }
        Ok(())
    })
}

/// A column's name and type.
#[no_mangle]
pub unsafe extern "C" fn mosura_table_column_info(t: *const mosura_table, col: u32, name: *mut mosura_view, ty: *mut mosura_col_type) -> mosura_status {
    guard(|| {
        let t = table_of(t)?;
        let n = t.col_name(col).ok_or_else(|| Error::InvalidArg(format!("column {col} of {} ({} columns)", t.schema().name(), t.ncols())))?;
        if !name.is_null() {
            *name = view(n.as_bytes());
        }
        if !ty.is_null() {
            *ty = col_type(t.col_type(col).expect("a named column has a type"));
        }
        Ok(())
    })
}

/// Column index by name, or MOSURA_ERR_NOT_FOUND — the way a client survives appended columns.
#[no_mangle]
pub unsafe extern "C" fn mosura_table_column_index(t: *const mosura_table, name: *const c_char, col: *mut u32) -> mosura_status {
    guard(|| {
        let t = table_of(t)?;
        let name = cstr(name, "name")?;
        let col = out_ptr(col, "col")?;
        *col = t.col(name).ok_or_else(|| Error::NotFound(format!("column `{name}` of {}", t.schema().name())))?;
        Ok(())
    })
}

/// The row count (0 and a recorded error for a bad handle).
#[no_mangle]
pub unsafe extern "C" fn mosura_table_rows(t: *const mosura_table) -> u64 {
    match table_of(t) {
        Ok(t) => {
            status::clear();
            t.rows()
        }
        Err(e) => {
            status::set(mosura_status::from(&e), &e.to_string());
            0
        }
    }
}

macro_rules! cell {
    ($name:ident, $ty:ty, $get:ident) => {
        #[no_mangle]
        pub unsafe extern "C" fn $name(t: *const mosura_table, row: u64, col: u32, out: *mut $ty) -> mosura_status {
            guard(|| {
                let t = table_of(t)?;
                let out = out_ptr(out, "out")?;
                *out = t.$get(row, col)?;
                Ok(())
            })
        }
    };
}
cell!(mosura_table_u64, u64, u64);
cell!(mosura_table_i64, i64, i64);
cell!(mosura_table_f64, f64, f64);

/// A Bool cell (0/1).
#[no_mangle]
pub unsafe extern "C" fn mosura_table_bool(t: *const mosura_table, row: u64, col: u32, out: *mut c_int) -> mosura_status {
    guard(|| {
        let t = table_of(t)?;
        let out = out_ptr(out, "out")?;
        *out = t.bool(row, col)? as c_int;
        Ok(())
    })
}

/// A Str cell (UTF-8, not NUL-terminated; the view is valid for the table's life).
#[no_mangle]
pub unsafe extern "C" fn mosura_table_str(t: *const mosura_table, row: u64, col: u32, out: *mut mosura_view) -> mosura_status {
    guard(|| {
        let t = table_of(t)?;
        let out = out_ptr(out, "out")?;
        *out = view(t.str(row, col)?.as_bytes());
        Ok(())
    })
}

/// A Bytes cell.
#[no_mangle]
pub unsafe extern "C" fn mosura_table_bytes(t: *const mosura_table, row: u64, col: u32, out: *mut mosura_view) -> mosura_status {
    guard(|| {
        let t = table_of(t)?;
        let out = out_ptr(out, "out")?;
        *out = view(t.bytes(row, col)?);
        Ok(())
    })
}

/// A list cell as a view over `count` little-endian elements of the column's element width
/// (4 for LIST_U32, 8 for LIST_U64).
#[no_mangle]
pub unsafe extern "C" fn mosura_table_list(t: *const mosura_table, row: u64, col: u32, out: *mut mosura_view, count: *mut u64) -> mosura_status {
    guard(|| {
        let t = table_of(t)?;
        let out = out_ptr(out, "out")?;
        let (raw, n) = t.list_raw(row, col)?;
        *out = view(raw);
        if !count.is_null() {
            *count = n;
        }
        Ok(())
    })
}

/// Bulk, zero-copy access to a fixed-width column: `out` spans all rows, `stride` is the row size
/// in bytes (row-major storage; a client builds a strided array view).
#[no_mangle]
pub unsafe extern "C" fn mosura_table_column(t: *const mosura_table, col: u32, out: *mut mosura_view, stride: *mut u32) -> mosura_status {
    guard(|| {
        let t = table_of(t)?;
        let out = out_ptr(out, "out")?;
        let (raw, s) = t.column(col)?;
        *out = view(raw);
        if !stride.is_null() {
            *stride = s;
        }
        Ok(())
    })
}

/// Binary search on a sorted key column (a table sorted on column 0 says so in its flags; other
/// columns are scanned). MOSURA_ERR_NOT_FOUND when no row carries `key`.
#[no_mangle]
pub unsafe extern "C" fn mosura_table_find(t: *const mosura_table, col: u32, key: u64, row: *mut u64) -> mosura_status {
    guard(|| {
        let t = table_of(t)?;
        let row = out_ptr(row, "row")?;
        *row = t.find(col, key).ok_or_else(|| Error::NotFound(format!("no row with {key:#x} in column {col}")))?;
        Ok(())
    })
}

/// Render the whole table: TEXT (the human form; a `text` table prints bare), TSV (header row),
/// JSON (an array of objects). UTF-8, not NUL-terminated.
#[no_mangle]
pub unsafe extern "C" fn mosura_table_render(t: *const mosura_table, format: mosura_format, out: *mut mosura_bytes) -> mosura_status {
    guard(|| {
        let t = table_of(t)?;
        let out = out_ptr(out, "out")?;
        let f = match format {
            mosura_format::MOSURA_FMT_TEXT => Format::Text,
            mosura_format::MOSURA_FMT_TSV => Format::Tsv,
            mosura_format::MOSURA_FMT_JSON => Format::Json,
        };
        *out = bytes(mosura_api::render(t, f)?.into_bytes());
        Ok(())
    })
}

/// The flat `.tbl` image — what the session store writes.
#[no_mangle]
pub unsafe extern "C" fn mosura_table_serialize(t: *const mosura_table, out: *mut mosura_bytes) -> mosura_status {
    guard(|| {
        let t = table_of(t)?;
        let out = out_ptr(out, "out")?;
        *out = bytes(mosura_api::tbl::write(t));
        Ok(())
    })
}

/// Open a `.tbl` image. The bytes are copied in this version (`borrow` is accepted and treated as
/// copy); the digest is verified; a schema name the library knows with another version is
/// refused (MOSURA_ERR_FORMAT), an unknown name is served with the file's own schema.
#[no_mangle]
pub unsafe extern "C" fn mosura_table_open(ctx: *mut mosura_ctx, image: mosura_view, _borrow: c_int, out: *mut *mut mosura_table) -> mosura_status {
    guard(|| {
        let _ = ctx_of(ctx)?;
        let out = out_ptr(out, "out")?;
        let data = view_bytes(image, "image")?.to_vec();
        let t = mosura_api::tbl::open_owned(data, None, true)?;
        *out = new_table(t);
        Ok(())
    })
}
