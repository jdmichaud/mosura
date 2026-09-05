//! An immutable result table with a schema. Cell views borrow from the table.

use std::ffi::{c_int, CString};

use crate::ctx::Ctx;
use crate::error::{check, Result};
use crate::handle::{empty_bytes, slice_of, take_bytes, take_string, view_of, Raw};
use mosura_capi::{mosura_table, mosura_view};

pub use mosura_capi::mosura_col_type as ColType;
pub use mosura_capi::mosura_format as Format;

pub struct Table {
    raw: Raw<mosura_table>,
}

impl Table {
    pub(crate) fn from_raw(p: *mut mosura_table) -> Table {
        Table { raw: Raw::new(p) }
    }

    pub(crate) fn ptr(&self) -> *mut mosura_table {
        self.raw.ptr()
    }

    /// Open a `.tbl` image (copied).
    pub fn open(ctx: &Ctx, image: &[u8]) -> Result<Table> {
        let mut out: *mut mosura_table = std::ptr::null_mut();
        check(unsafe { mosura_capi::mosura_table_open(ctx.ptr(), view_of(image), 0, &mut out) })?;
        Ok(Table::from_raw(out))
    }

    /// (schema name, schema version, column count).
    pub fn schema(&self) -> Result<(String, u32, u32)> {
        let mut name = mosura_view { ptr: std::ptr::null(), len: 0 };
        let (mut version, mut ncols) = (0u32, 0u32);
        check(unsafe { mosura_capi::mosura_table_schema(self.ptr(), &mut name, &mut version, &mut ncols) })?;
        Ok((String::from_utf8_lossy(unsafe { slice_of(name) }).into_owned(), version, ncols))
    }

    pub fn column_info(&self, col: u32) -> Result<(String, ColType)> {
        let mut name = mosura_view { ptr: std::ptr::null(), len: 0 };
        let mut ty = ColType::MOSURA_COL_U8;
        check(unsafe { mosura_capi::mosura_table_column_info(self.ptr(), col, &mut name, &mut ty) })?;
        Ok((String::from_utf8_lossy(unsafe { slice_of(name) }).into_owned(), ty))
    }

    pub fn column_index(&self, name: &str) -> Result<u32> {
        let n = CString::new(name).unwrap_or_default();
        let mut col = 0u32;
        check(unsafe { mosura_capi::mosura_table_column_index(self.ptr(), n.as_ptr(), &mut col) })?;
        Ok(col)
    }

    pub fn rows(&self) -> u64 {
        unsafe { mosura_capi::mosura_table_rows(self.ptr()) }
    }

    pub fn u64(&self, row: u64, col: u32) -> Result<u64> {
        let mut v = 0u64;
        check(unsafe { mosura_capi::mosura_table_u64(self.ptr(), row, col, &mut v) })?;
        Ok(v)
    }

    pub fn i64(&self, row: u64, col: u32) -> Result<i64> {
        let mut v = 0i64;
        check(unsafe { mosura_capi::mosura_table_i64(self.ptr(), row, col, &mut v) })?;
        Ok(v)
    }

    pub fn f64(&self, row: u64, col: u32) -> Result<f64> {
        let mut v = 0f64;
        check(unsafe { mosura_capi::mosura_table_f64(self.ptr(), row, col, &mut v) })?;
        Ok(v)
    }

    pub fn bool(&self, row: u64, col: u32) -> Result<bool> {
        let mut v: c_int = 0;
        check(unsafe { mosura_capi::mosura_table_bool(self.ptr(), row, col, &mut v) })?;
        Ok(v != 0)
    }

    /// A Str cell, borrowed from the table.
    pub fn str(&self, row: u64, col: u32) -> Result<&str> {
        let mut v = mosura_view { ptr: std::ptr::null(), len: 0 };
        check(unsafe { mosura_capi::mosura_table_str(self.ptr(), row, col, &mut v) })?;
        Ok(std::str::from_utf8(unsafe { slice_of(v) }).unwrap_or(""))
    }

    /// A Bytes cell, borrowed from the table.
    pub fn bytes(&self, row: u64, col: u32) -> Result<&[u8]> {
        let mut v = mosura_view { ptr: std::ptr::null(), len: 0 };
        check(unsafe { mosura_capi::mosura_table_bytes(self.ptr(), row, col, &mut v) })?;
        Ok(unsafe { slice_of(v) })
    }

    fn list_raw(&self, row: u64, col: u32) -> Result<(&[u8], u64)> {
        let mut v = mosura_view { ptr: std::ptr::null(), len: 0 };
        let mut count = 0u64;
        check(unsafe { mosura_capi::mosura_table_list(self.ptr(), row, col, &mut v, &mut count) })?;
        Ok((unsafe { slice_of(v) }, count))
    }

    pub fn list_u32(&self, row: u64, col: u32) -> Result<Vec<u32>> {
        let (raw, count) = self.list_raw(row, col)?;
        Ok(raw.chunks_exact(4).take(count as usize).map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect())
    }

    pub fn list_u64(&self, row: u64, col: u32) -> Result<Vec<u64>> {
        let (raw, count) = self.list_raw(row, col)?;
        Ok(raw.chunks_exact(8).take(count as usize).map(|c| u64::from_le_bytes(c.try_into().unwrap())).collect())
    }

    /// A fixed-width column as (the bytes spanning all rows, the row stride).
    pub fn column(&self, col: u32) -> Result<(&[u8], u32)> {
        let mut v = mosura_view { ptr: std::ptr::null(), len: 0 };
        let mut stride = 0u32;
        check(unsafe { mosura_capi::mosura_table_column(self.ptr(), col, &mut v, &mut stride) })?;
        Ok((unsafe { slice_of(v) }, stride))
    }

    /// The row holding `key` in `col`, if any.
    pub fn find(&self, col: u32, key: u64) -> Option<u64> {
        let mut row = 0u64;
        match unsafe { mosura_capi::mosura_table_find(self.ptr(), col, key, &mut row) } {
            mosura_capi::mosura_status::MOSURA_OK => Some(row),
            _ => None,
        }
    }

    pub fn render(&self, format: Format) -> Result<String> {
        let mut b = empty_bytes();
        check(unsafe { mosura_capi::mosura_table_render(self.ptr(), format, &mut b) })?;
        Ok(take_string(b))
    }

    /// The `.tbl` image.
    pub fn serialize(&self) -> Result<Vec<u8>> {
        let mut b = empty_bytes();
        check(unsafe { mosura_capi::mosura_table_serialize(self.ptr(), &mut b) })?;
        Ok(take_bytes(b))
    }
}

impl std::fmt::Debug for Table {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.schema() {
            Ok((name, version, ncols)) => write!(f, "Table({name} v{version}, {ncols} columns, {} rows)", self.rows()),
            Err(e) => write!(f, "Table(<{e}>)"),
        }
    }
}
