//! The `.tbl` file (`docs/product/architecture.md` §5.3): a fixed 96-byte header, the schema, the
//! rows, the blob. Little-endian only. There is deliberately no nesting and no pointer: a row refers
//! to another table by a key column, and variable-length per-row data is `(offset, len)` into the
//! blob. A reader maps the file and views rows in place.
//!
//! ```text
//! 0    8   magic "MOSTBL01"        (the format version is in the magic)
//! 8    4   header_len              (the fixed header + the schema block)
//! 12   4   schema_version
//! 16   4   ncols
//! 20   4   row_size                (bytes, a multiple of 8)
//! 24   4   flags                   (bit 0: rows sorted by column 0 — binary search allowed)
//! 28   4   reserved
//! 32   8   nrows
//! 40   8   rows_off                (8-aligned)
//! 48   8   blob_off                (8-aligned)
//! 56   8   blob_len
//! 64   32  digest                  blake3(rows ‖ blob)
//! 96   var schema name (u32 len + UTF-8), then ncols × { name (u32 len + UTF-8), type u8, offset u16, size u16 }
//! ```
//!
//! Before 1.0 nothing is compatible (decision D6): a foreign magic, an unknown format version, or a
//! schema version other than the compiled schema's is REFUSED, never misread. A file whose schema
//! name this build does not know is served render-only with the file's own schema.

use std::path::Path;
use std::sync::Arc;

use crate::error::{Error, Result};
use crate::schema::{layout, ColType, OwnedSchema, Schema, SchemaRef};
use crate::table::{digest_of, Storage, Table};

pub const MAGIC: &[u8; 8] = b"MOSTBL01";
const FIXED: usize = 96;
pub const FLAG_SORTED: u32 = 1;

fn align8(n: usize) -> usize {
    (n + 7) / 8 * 8
}

/// The `.tbl` image of a table (a copy of rows + blob behind a fresh header).
pub fn write(t: &Table) -> Vec<u8> {
    let schema = t.schema();
    let mut sb: Vec<u8> = Vec::new();
    let name = schema.name().as_bytes();
    sb.extend_from_slice(&(name.len() as u32).to_le_bytes());
    sb.extend_from_slice(name);
    let types = schema.types();
    let l = layout(types.iter().copied());
    for (i, ty) in types.iter().enumerate() {
        let n = schema.col_name(i).unwrap_or("").as_bytes();
        sb.extend_from_slice(&(n.len() as u32).to_le_bytes());
        sb.extend_from_slice(n);
        sb.push(*ty as u8);
        sb.extend_from_slice(&l.offsets[i].to_le_bytes());
        sb.extend_from_slice(&ty.cell_size().to_le_bytes());
    }
    let header_len = FIXED + sb.len();
    let rows_off = align8(header_len);
    let rows = t.rows_bytes();
    let blob = t.blob_bytes();
    let blob_off = align8(rows_off + rows.len());
    let mut out = Vec::with_capacity(blob_off + blob.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&(header_len as u32).to_le_bytes());
    out.extend_from_slice(&schema.version().to_le_bytes());
    out.extend_from_slice(&(types.len() as u32).to_le_bytes());
    out.extend_from_slice(&t.row_size().to_le_bytes());
    out.extend_from_slice(&(if t.sorted() { FLAG_SORTED } else { 0 }).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&t.rows().to_le_bytes());
    out.extend_from_slice(&(rows_off as u64).to_le_bytes());
    out.extend_from_slice(&(blob_off as u64).to_le_bytes());
    out.extend_from_slice(&(blob.len() as u64).to_le_bytes());
    out.extend_from_slice(&t.digest());
    debug_assert_eq!(out.len(), FIXED);
    out.extend_from_slice(&sb);
    out.resize(rows_off, 0);
    out.extend_from_slice(rows);
    out.resize(blob_off, 0);
    out.extend_from_slice(blob);
    out
}

struct Header {
    header_len: usize,
    schema_version: u32,
    ncols: usize,
    row_size: u32,
    sorted: bool,
    nrows: u64,
    rows_off: usize,
    blob_off: usize,
    blob_len: usize,
    digest: [u8; 32],
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().unwrap())
}

fn parse_header(b: &[u8]) -> Result<(Header, OwnedSchema)> {
    if b.len() < FIXED {
        return Err(Error::Format(format!("{} bytes is shorter than a .tbl header", b.len())));
    }
    if &b[0..8] != MAGIC {
        return Err(Error::Version {
            found: String::from_utf8_lossy(&b[0..8]).into_owned(),
            expected: String::from_utf8_lossy(MAGIC).into_owned(),
        });
    }
    let h = Header {
        header_len: u32_at(b, 8) as usize,
        schema_version: u32_at(b, 12),
        ncols: u32_at(b, 16) as usize,
        row_size: u32_at(b, 20),
        sorted: u32_at(b, 24) & FLAG_SORTED != 0,
        nrows: u64_at(b, 32),
        rows_off: u64_at(b, 40) as usize,
        blob_off: u64_at(b, 48) as usize,
        blob_len: u64_at(b, 56) as usize,
        digest: b[64..96].try_into().unwrap(),
    };
    if h.header_len > b.len() || h.rows_off > b.len() || h.blob_off > b.len() || h.blob_off + h.blob_len > b.len() {
        return Err(Error::Format("a .tbl header points outside the file".into()));
    }
    // the schema block
    let mut at = FIXED;
    let take_str = |at: &mut usize| -> Result<String> {
        if *at + 4 > b.len() {
            return Err(Error::Format("truncated schema block".into()));
        }
        let n = u32_at(b, *at) as usize;
        *at += 4;
        let s = b.get(*at..*at + n).ok_or_else(|| Error::Format("truncated schema name".into()))?;
        *at += n;
        String::from_utf8(s.to_vec()).map_err(|e| Error::Format(format!("schema name is not UTF-8: {e}")))
    };
    let name = take_str(&mut at)?;
    let mut columns = Vec::with_capacity(h.ncols);
    for _ in 0..h.ncols {
        let cname = take_str(&mut at)?;
        if at + 5 > b.len() {
            return Err(Error::Format("truncated column record".into()));
        }
        let ty = ColType::from_u8(b[at]).ok_or_else(|| Error::Format(format!("column {cname}: unknown type code {}", b[at])))?;
        at += 5; // type u8 + offset u16 + size u16 (recomputed from the types; must agree)
        columns.push((cname, ty));
    }
    if at != h.header_len {
        return Err(Error::Format(format!("schema block ends at {at}, header says {}", h.header_len)));
    }
    let l = layout(columns.iter().map(|c| c.1));
    if l.row_size != h.row_size {
        return Err(Error::Format(format!("row size {} in the header, {} from the column types", h.row_size, l.row_size)));
    }
    let version = h.schema_version;
    Ok((h, OwnedSchema { name, version, columns }))
}

/// Resolve the file's schema against this build: a known name must match the compiled version
/// exactly (D6), an unknown name is served with the file's own schema.
fn resolve_schema(own: OwnedSchema, known: Option<&'static Schema>) -> Result<SchemaRef> {
    match known {
        Some(s) => {
            if s.version != own.version {
                return Err(Error::Version { found: format!("{} v{}", own.name, own.version), expected: format!("{} v{}", s.name, s.version) });
            }
            let same_columns = s.columns.len() == own.columns.len() && s.columns.iter().zip(&own.columns).all(|(a, b)| a.name == b.0 && a.ty == b.1);
            if !same_columns {
                return Err(Error::Version { found: format!("{} v{} with other columns", own.name, own.version), expected: format!("{} v{}", s.name, s.version) });
            }
            Ok(SchemaRef::Static(s))
        }
        None => Ok(SchemaRef::Owned(own)),
    }
}

fn check_digest(h: &Header, rows: &[u8], blob: &[u8]) -> Result<()> {
    let d = digest_of(rows, blob);
    if d != h.digest {
        return Err(Error::Format("content digest mismatch: the file is corrupt or was altered".into()));
    }
    Ok(())
}

/// Open a `.tbl` image held in memory. `known` = the compiled schema of that name, if any;
/// `verify` = check the content digest (on for a set read from disk, off for an image just written).
pub fn open_owned(bytes: Vec<u8>, known: Option<&'static Schema>, verify: bool) -> Result<Table> {
    let (h, own) = parse_header(&bytes)?;
    let rows_len = h.nrows as usize * h.row_size as usize;
    if h.rows_off + rows_len > bytes.len() {
        return Err(Error::Format("rows extend past the end of the file".into()));
    }
    let rows = bytes[h.rows_off..h.rows_off + rows_len].to_vec();
    let blob = bytes[h.blob_off..h.blob_off + h.blob_len].to_vec();
    if verify {
        check_digest(&h, &rows, &blob)?;
    }
    let schema = resolve_schema(own, known)?;
    Table::assemble(schema, h.nrows, Storage::Owned(rows), Storage::Owned(blob), h.sorted)
}

/// Open a `.tbl` file by mapping it: rows and blob are read in place (`Storage::Mapped`).
pub fn open_mapped(path: &Path, known: Option<&'static Schema>, verify: bool) -> Result<Table> {
    let file = std::fs::File::open(path).map_err(|e| Error::io(e, path))?;
    // SAFETY: the file is a session artifact written whole and renamed into place, never modified
    // afterwards (the store's immutability rule); a concurrent truncation would be a store violation.
    let map = unsafe { memmap2::Mmap::map(&file) }.map_err(|e| Error::io(e, path))?;
    let map = Arc::new(map);
    let (h, own) = parse_header(&map)?;
    let rows_len = h.nrows as usize * h.row_size as usize;
    if h.rows_off + rows_len > map.len() {
        return Err(Error::Format(format!("{}: rows extend past the end of the file", path.display())));
    }
    let rows = Storage::Mapped { map: Arc::clone(&map), range: h.rows_off..h.rows_off + rows_len };
    let blob = Storage::Mapped { map: Arc::clone(&map), range: h.blob_off..h.blob_off + h.blob_len };
    if verify {
        check_digest(&h, rows.bytes(), blob.bytes())?;
    }
    let schema = resolve_schema(own, known)?;
    Table::assemble(schema, h.nrows, rows, blob, h.sorted)
}
