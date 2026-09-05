//! Building a table row by row. The writer is typed and ordered: every column of the schema is
//! written exactly once per row, in declaration order (debug-asserted), so a schema change that is
//! not mirrored in its producer fails loudly. Identical strings and byte runs share one blob range.

use std::collections::HashMap;

use super::{Storage, Table};
use crate::schema::{layout, ColType, Schema, SchemaRef};

pub struct TableBuilder {
    schema: &'static Schema,
    types: Vec<ColType>,
    offsets: Vec<u16>,
    row_size: u32,
    rows: Vec<u8>,
    blob: Vec<u8>,
    nrows: u64,
    dedup: HashMap<Vec<u8>, (u32, u32)>,
}

impl TableBuilder {
    pub fn new(schema: &'static Schema) -> TableBuilder {
        let types: Vec<ColType> = schema.columns.iter().map(|c| c.ty).collect();
        let l = layout(types.iter().copied());
        TableBuilder { schema, types, offsets: l.offsets, row_size: l.row_size, rows: Vec::new(), blob: Vec::new(), nrows: 0, dedup: HashMap::new() }
    }

    /// Start a row; write its cells in column order; the row is complete when the writer drops.
    pub fn row(&mut self) -> RowWriter<'_> {
        let start = self.rows.len();
        self.rows.resize(start + self.row_size as usize, 0);
        self.nrows += 1;
        RowWriter { b: self, start, next: 0 }
    }

    fn blob_ref(&mut self, bytes: &[u8]) -> (u32, u32) {
        if let Some(&r) = self.dedup.get(bytes) {
            return r;
        }
        let off = self.blob.len() as u32;
        self.blob.extend_from_slice(bytes);
        let r = (off, bytes.len() as u32);
        if bytes.len() <= 4096 {
            self.dedup.insert(bytes.to_vec(), r);
        }
        r
    }

    /// Finish: `sorted` asserts (in debug) and records that column 0 is ascending, so `find` may
    /// binary-search.
    pub fn finish(self, sorted: bool) -> Table {
        let table = Table::assemble(SchemaRef::Static(self.schema), self.nrows, Storage::Owned(self.rows), Storage::Owned(self.blob), sorted)
            .expect("a builder produces consistent buffers");
        debug_assert!(!sorted || (1..table.nrows).all(|r| table.u64(r - 1, 0).ok() <= table.u64(r, 0).ok()), "finish(sorted = true) on an unsorted column 0");
        table
    }
}

pub struct RowWriter<'b> {
    b: &'b mut TableBuilder,
    start: usize,
    next: usize,
}

impl RowWriter<'_> {
    fn slot(&mut self, want: ColType) -> &mut [u8] {
        let c = self.next;
        assert!(c < self.b.types.len(), "row of {} has only {} columns", self.b.schema.name, self.b.types.len());
        let ty = self.b.types[c];
        assert_eq!(ty, want, "column {c} ({}) of {} is {}, written as {}", self.b.schema.columns[c].name, self.b.schema.name, ty.name(), want.name());
        self.next += 1;
        let off = self.start + self.b.offsets[c] as usize;
        let size = ty.cell_size() as usize;
        &mut self.b.rows[off..off + size]
    }
    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.slot(ColType::U8)[0] = v;
        self
    }
    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.slot(ColType::U16).copy_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.slot(ColType::U32).copy_from_slice(&v.to_le_bytes());
        self
    }
    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.slot(ColType::U64).copy_from_slice(&v.to_le_bytes());
        self
    }
    pub fn i64(&mut self, v: i64) -> &mut Self {
        self.slot(ColType::I64).copy_from_slice(&v.to_le_bytes());
        self
    }
    pub fn f64(&mut self, v: f64) -> &mut Self {
        self.slot(ColType::F64).copy_from_slice(&v.to_le_bytes());
        self
    }
    pub fn bool(&mut self, v: bool) -> &mut Self {
        self.slot(ColType::Bool)[0] = v as u8;
        self
    }
    fn var(&mut self, ty: ColType, bytes: &[u8]) -> &mut Self {
        let (off, len) = self.b.blob_ref(bytes);
        let s = self.slot(ty);
        s[0..4].copy_from_slice(&off.to_le_bytes());
        s[4..8].copy_from_slice(&len.to_le_bytes());
        self
    }
    pub fn str(&mut self, v: &str) -> &mut Self {
        self.var(ColType::Str, v.as_bytes())
    }
    pub fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.var(ColType::Bytes, v)
    }
    pub fn list_u32(&mut self, v: &[u32]) -> &mut Self {
        let bytes: Vec<u8> = v.iter().flat_map(|x| x.to_le_bytes()).collect();
        self.var(ColType::ListU32, &bytes)
    }
    pub fn list_u64(&mut self, v: &[u64]) -> &mut Self {
        let bytes: Vec<u8> = v.iter().flat_map(|x| x.to_le_bytes()).collect();
        self.var(ColType::ListU64, &bytes)
    }
}

impl Drop for RowWriter<'_> {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            assert_eq!(self.next, self.b.types.len(), "row of {} written with {} of {} columns", self.b.schema.name, self.next, self.b.types.len());
        }
    }
}
