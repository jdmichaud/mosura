//! Schemas: every result is a table of a fixed record type with a declared, versioned column list
//! (`docs/product/architecture.md` §4.3). One declaration drives the C accessors, the renderings and
//! the `.tbl` file. Evolution rule (after 1.0): columns are appended, never removed or retyped; the
//! version bumps on append. Before 1.0 a version mismatch is refused, never read (decision D6).

/// The closed set of column types — `mosura_col_type` in the C header, the `type u8` of a `.tbl`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ColType {
    U8 = 1,
    U16 = 2,
    U32 = 3,
    U64 = 4,
    I64 = 5,
    F64 = 6,
    Bool = 7,
    /// UTF-8, in the blob.
    Str = 8,
    /// Raw bytes, in the blob.
    Bytes = 9,
    /// A variable-length list of little-endian `u32`, in the blob.
    ListU32 = 10,
    /// A variable-length list of little-endian `u64`, in the blob.
    ListU64 = 11,
}

impl ColType {
    pub fn from_u8(v: u8) -> Option<ColType> {
        Some(match v {
            1 => ColType::U8,
            2 => ColType::U16,
            3 => ColType::U32,
            4 => ColType::U64,
            5 => ColType::I64,
            6 => ColType::F64,
            7 => ColType::Bool,
            8 => ColType::Str,
            9 => ColType::Bytes,
            10 => ColType::ListU32,
            11 => ColType::ListU64,
            _ => return None,
        })
    }

    /// The fixed cell width in a row. Variable-length columns store `{u32 blob_off, u32 len}`.
    pub fn cell_size(self) -> u16 {
        match self {
            ColType::U8 | ColType::Bool => 1,
            ColType::U16 => 2,
            ColType::U32 => 4,
            ColType::U64 | ColType::I64 | ColType::F64 => 8,
            ColType::Str | ColType::Bytes | ColType::ListU32 | ColType::ListU64 => 8,
        }
    }

    /// The cell's alignment in a row (natural for scalars; the two `u32` halves of a blob reference).
    pub fn align(self) -> u16 {
        match self {
            ColType::U8 | ColType::Bool => 1,
            ColType::U16 => 2,
            ColType::U32 => 4,
            ColType::U64 | ColType::I64 | ColType::F64 => 8,
            ColType::Str | ColType::Bytes | ColType::ListU32 | ColType::ListU64 => 4,
        }
    }

    pub fn is_variable(self) -> bool {
        matches!(self, ColType::Str | ColType::Bytes | ColType::ListU32 | ColType::ListU64)
    }

    pub fn name(self) -> &'static str {
        match self {
            ColType::U8 => "u8",
            ColType::U16 => "u16",
            ColType::U32 => "u32",
            ColType::U64 => "u64",
            ColType::I64 => "i64",
            ColType::F64 => "f64",
            ColType::Bool => "bool",
            ColType::Str => "str",
            ColType::Bytes => "bytes",
            ColType::ListU32 => "list<u32>",
            ColType::ListU64 => "list<u64>",
        }
    }
}

/// How a numeric column prints in the TEXT/TSV renderings (an address in hex, a count in decimal).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ColHint {
    Dec,
    Hex,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Column {
    pub name: &'static str,
    pub ty: ColType,
    pub hint: ColHint,
}

impl Column {
    pub const fn new(name: &'static str, ty: ColType) -> Column {
        Column { name, ty, hint: ColHint::Dec }
    }
    pub const fn hex(name: &'static str, ty: ColType) -> Column {
        Column { name, ty, hint: ColHint::Hex }
    }
}

/// A compiled-in schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schema {
    pub name: &'static str,
    pub version: u32,
    pub columns: &'static [Column],
}

/// A schema read from a `.tbl` whose name this build does not know (served render-only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedSchema {
    pub name: String,
    pub version: u32,
    pub columns: Vec<(String, ColType)>,
}

/// One row layout: each column's byte offset within a row, and the row size (a multiple of 8).
/// Columns are laid out in declaration order at their natural alignment — no reordering, so a
/// client that read the schema can address cells arithmetically, and a `column()` view is one stride.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Layout {
    pub offsets: Vec<u16>,
    pub row_size: u32,
}

pub fn layout(types: impl Iterator<Item = ColType>) -> Layout {
    let mut off: u32 = 0;
    let mut offsets = Vec::new();
    for ty in types {
        let a = ty.align() as u32;
        off = (off + a - 1) / a * a;
        offsets.push(off as u16);
        off += ty.cell_size() as u32;
    }
    let row_size = (off + 7) / 8 * 8;
    Layout { offsets, row_size }
}

/// A view of a schema that is either compiled in or read from a file.
#[derive(Debug, Clone)]
pub enum SchemaRef {
    Static(&'static Schema),
    Owned(OwnedSchema),
}

impl SchemaRef {
    pub fn name(&self) -> &str {
        match self {
            SchemaRef::Static(s) => s.name,
            SchemaRef::Owned(o) => &o.name,
        }
    }
    pub fn version(&self) -> u32 {
        match self {
            SchemaRef::Static(s) => s.version,
            SchemaRef::Owned(o) => o.version,
        }
    }
    pub fn ncols(&self) -> usize {
        match self {
            SchemaRef::Static(s) => s.columns.len(),
            SchemaRef::Owned(o) => o.columns.len(),
        }
    }
    pub fn col_name(&self, i: usize) -> Option<&str> {
        match self {
            SchemaRef::Static(s) => s.columns.get(i).map(|c| c.name),
            SchemaRef::Owned(o) => o.columns.get(i).map(|c| c.0.as_str()),
        }
    }
    pub fn col_type(&self, i: usize) -> Option<ColType> {
        match self {
            SchemaRef::Static(s) => s.columns.get(i).map(|c| c.ty),
            SchemaRef::Owned(o) => o.columns.get(i).map(|c| c.1),
        }
    }
    pub fn col_hint(&self, i: usize) -> ColHint {
        match self {
            SchemaRef::Static(s) => s.columns.get(i).map(|c| c.hint).unwrap_or(ColHint::Dec),
            SchemaRef::Owned(_) => ColHint::Dec,
        }
    }
    pub fn types(&self) -> Vec<ColType> {
        (0..self.ncols()).filter_map(|i| self.col_type(i)).collect()
    }
    pub fn index_of(&self, name: &str) -> Option<usize> {
        (0..self.ncols()).find(|&i| self.col_name(i) == Some(name))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Natural alignment, declaration order, rows padded to 8: `u8, u64, u16, str` lays out at
    /// 0, 8, 16, 20 in a 32-byte row; every type code round-trips.
    #[test]
    fn layout_is_naturally_aligned_and_rows_are_padded_to_eight() {
        let l = layout([ColType::U8, ColType::U64, ColType::U16, ColType::Str].into_iter());
        assert_eq!(l.offsets, vec![0, 8, 16, 20]);
        assert_eq!(l.row_size, 32);
        let l = layout([ColType::U32].into_iter());
        assert_eq!((l.offsets, l.row_size), (vec![0], 8));
        assert_eq!(layout(std::iter::empty()).row_size, 0);
        for v in 1..=11u8 {
            let t = ColType::from_u8(v).expect("a type code");
            assert_eq!(t as u8, v);
            assert!(t.cell_size() % t.align() == 0);
        }
        assert_eq!(ColType::from_u8(0), None);
        assert_eq!(ColType::from_u8(12), None);
    }
}
