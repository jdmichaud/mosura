//! Tables: every result of an operation, and every file of the session store, is a table of
//! fixed-size rows plus one blob for the variable-length cells (`docs/product/architecture.md`
//! §4.3, §5.3). A table in memory IS the `.tbl` image plus its schema: rows are read in place from
//! an owned buffer or a mapped file, and writing one is a copy.

pub mod builder;

use std::ops::Range;
use std::sync::Arc;

use crate::error::{Error, Result};
use crate::schema::{layout, ColHint, ColType, SchemaRef};

/// Where a table's bytes live: an owned buffer (a table just built, or read whole), or a range of
/// one mapped file shared with the other tables of the set.
#[derive(Clone)]
pub enum Storage {
    Owned(Vec<u8>),
    Mapped { map: Arc<memmap2::Mmap>, range: Range<usize> },
}

impl Storage {
    pub fn bytes(&self) -> &[u8] {
        match self {
            Storage::Owned(v) => v,
            Storage::Mapped { map, range } => &map[range.clone()],
        }
    }
    pub fn len(&self) -> usize {
        self.bytes().len()
    }
}

impl std::fmt::Debug for Storage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Storage::Owned(v) => write!(f, "Owned({} bytes)", v.len()),
            Storage::Mapped { range, .. } => write!(f, "Mapped({} bytes)", range.len()),
        }
    }
}

/// An immutable table with a schema. Cell accessors check the column's type; views into the blob
/// are valid for the table's lifetime (nothing is ever mutated).
#[derive(Debug, Clone)]
pub struct Table {
    pub(crate) schema: SchemaRef,
    pub(crate) nrows: u64,
    pub(crate) row_size: u32,
    pub(crate) offsets: Vec<u16>,
    pub(crate) rows: Storage,
    pub(crate) blob: Storage,
    pub(crate) sorted: bool,
    pub(crate) digest: [u8; 32],
}

impl Table {
    pub(crate) fn assemble(schema: SchemaRef, nrows: u64, rows: Storage, blob: Storage, sorted: bool) -> Result<Table> {
        let l = layout(schema.types().into_iter());
        if rows.len() as u64 != nrows * l.row_size as u64 {
            return Err(Error::Format(format!("rows buffer is {} bytes, {} rows × {} expected", rows.len(), nrows, l.row_size)));
        }
        let digest = digest_of(rows.bytes(), blob.bytes());
        Ok(Table { schema, nrows, row_size: l.row_size, offsets: l.offsets, rows, blob, sorted, digest })
    }

    pub fn schema(&self) -> &SchemaRef {
        &self.schema
    }
    pub fn rows(&self) -> u64 {
        self.nrows
    }
    pub fn ncols(&self) -> u32 {
        self.schema.ncols() as u32
    }
    pub fn row_size(&self) -> u32 {
        self.row_size
    }
    pub fn sorted(&self) -> bool {
        self.sorted
    }
    /// blake3 over rows ‖ blob — the content identity of the table.
    pub fn digest(&self) -> [u8; 32] {
        self.digest
    }
    pub fn col(&self, name: &str) -> Option<u32> {
        self.schema.index_of(name).map(|i| i as u32)
    }
    pub fn col_type(&self, c: u32) -> Option<ColType> {
        self.schema.col_type(c as usize)
    }
    pub fn col_name(&self, c: u32) -> Option<&str> {
        self.schema.col_name(c as usize)
    }
    pub fn col_hint(&self, c: u32) -> ColHint {
        self.schema.col_hint(c as usize)
    }
    pub(crate) fn rows_bytes(&self) -> &[u8] {
        self.rows.bytes()
    }
    pub(crate) fn blob_bytes(&self) -> &[u8] {
        self.blob.bytes()
    }

    fn cell(&self, r: u64, c: u32, want: &[ColType]) -> Result<&[u8]> {
        let ty = self.col_type(c).ok_or_else(|| Error::NotFound(format!("column {c} of {}", self.schema.name())))?;
        if !want.contains(&ty) {
            return Err(Error::InvalidArg(format!("column {c} ({}) of {} is {}, not {}", self.col_name(c).unwrap_or("?"), self.schema.name(), ty.name(), want.iter().map(|t| t.name()).collect::<Vec<_>>().join("/"))));
        }
        if r >= self.nrows {
            return Err(Error::NotFound(format!("row {r} of {} ({} rows)", self.schema.name(), self.nrows)));
        }
        let start = r as usize * self.row_size as usize + self.offsets[c as usize] as usize;
        Ok(&self.rows_bytes()[start..start + ty.cell_size() as usize])
    }

    pub fn u64(&self, r: u64, c: u32) -> Result<u64> {
        let b = self.cell(r, c, &[ColType::U8, ColType::U16, ColType::U32, ColType::U64])?;
        Ok(match b.len() {
            1 => b[0] as u64,
            2 => u16::from_le_bytes([b[0], b[1]]) as u64,
            4 => u32::from_le_bytes(b.try_into().unwrap()) as u64,
            _ => u64::from_le_bytes(b.try_into().unwrap()),
        })
    }
    pub fn i64(&self, r: u64, c: u32) -> Result<i64> {
        let b = self.cell(r, c, &[ColType::I64])?;
        Ok(i64::from_le_bytes(b.try_into().unwrap()))
    }
    pub fn f64(&self, r: u64, c: u32) -> Result<f64> {
        let b = self.cell(r, c, &[ColType::F64])?;
        Ok(f64::from_le_bytes(b.try_into().unwrap()))
    }
    pub fn bool(&self, r: u64, c: u32) -> Result<bool> {
        let b = self.cell(r, c, &[ColType::Bool])?;
        Ok(b[0] != 0)
    }
    fn blob_ref(&self, r: u64, c: u32, want: &[ColType]) -> Result<&[u8]> {
        let b = self.cell(r, c, want)?;
        let off = u32::from_le_bytes(b[0..4].try_into().unwrap()) as usize;
        let len = u32::from_le_bytes(b[4..8].try_into().unwrap()) as usize;
        self.blob_bytes().get(off..off + len).ok_or_else(|| Error::Format(format!("blob reference {off}+{len} outside the blob ({} bytes)", self.blob.len())))
    }
    pub fn str(&self, r: u64, c: u32) -> Result<&str> {
        let b = self.blob_ref(r, c, &[ColType::Str])?;
        std::str::from_utf8(b).map_err(|e| Error::Format(format!("string cell is not UTF-8: {e}")))
    }
    pub fn bytes(&self, r: u64, c: u32) -> Result<&[u8]> {
        self.blob_ref(r, c, &[ColType::Bytes])
    }
    pub fn list_u32(&self, r: u64, c: u32) -> Result<impl Iterator<Item = u32> + '_> {
        let b = self.blob_ref(r, c, &[ColType::ListU32])?;
        Ok(b.chunks_exact(4).map(|x| u32::from_le_bytes(x.try_into().unwrap())))
    }
    pub fn list_u64(&self, r: u64, c: u32) -> Result<impl Iterator<Item = u64> + '_> {
        let b = self.blob_ref(r, c, &[ColType::ListU64])?;
        Ok(b.chunks_exact(8).map(|x| u64::from_le_bytes(x.try_into().unwrap())))
    }
    /// The raw list bytes and element count (the C `mosura_table_list` view).
    pub fn list_raw(&self, r: u64, c: u32) -> Result<(&[u8], u64)> {
        let ty = self.col_type(c).ok_or_else(|| Error::NotFound(format!("column {c}")))?;
        let b = self.blob_ref(r, c, &[ColType::ListU32, ColType::ListU64])?;
        let w = if ty == ColType::ListU32 { 4 } else { 8 };
        Ok((b, (b.len() / w) as u64))
    }

    /// Bulk, zero-copy access to a fixed-width column: the whole rows buffer starting at the
    /// column's offset in row 0, with the row size as the stride (the C `mosura_table_column`).
    pub fn column(&self, c: u32) -> Result<(&[u8], u32)> {
        let ty = self.col_type(c).ok_or_else(|| Error::NotFound(format!("column {c}")))?;
        if ty.is_variable() {
            return Err(Error::InvalidArg(format!("column {c} is variable-length; use the cell accessors")));
        }
        let off = self.offsets[c as usize] as usize;
        let rows = self.rows_bytes();
        Ok((if rows.is_empty() { rows } else { &rows[off..] }, self.row_size))
    }

    /// The row whose column `c` equals `key`: binary search when the table is sorted by column 0
    /// and `c == 0`, a linear scan otherwise.
    pub fn find(&self, c: u32, key: u64) -> Option<u64> {
        if self.sorted && c == 0 {
            let (mut lo, mut hi) = (0u64, self.nrows);
            while lo < hi {
                let mid = lo + (hi - lo) / 2;
                match self.u64(mid, c).ok()?.cmp(&key) {
                    std::cmp::Ordering::Less => lo = mid + 1,
                    std::cmp::Ordering::Greater => hi = mid,
                    std::cmp::Ordering::Equal => return Some(mid),
                }
            }
            None
        } else {
            (0..self.nrows).find(|&r| self.u64(r, c).ok() == Some(key))
        }
    }
}

pub(crate) fn digest_of(rows: &[u8], blob: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(rows);
    h.update(blob);
    *h.finalize().as_bytes()
}
