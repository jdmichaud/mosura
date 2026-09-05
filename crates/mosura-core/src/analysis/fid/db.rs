//! Ghidra's `db` package — the read-only slice needed to enumerate records.
//!
//! A faithful port of `db/{DBParms,MasterTable,TableRecord,Schema,Field,ChainedBuffer}.java`
//! plus the long-key B-tree nodes (`LongKeyNode`, `LongKeyInteriorNode`, `LongKeyRecordNode`,
//! `VarRecNode`, `FixedRecNode`). Everything is big-endian, matching Java's `DataInput`.
//!
//! Only the read path is ported: no allocation, no splitting, no transactions. That is the
//! whole of what reading a shipped `.fidb` requires.

use std::collections::HashMap;

use super::bufferfile::{be_u16, be_u32, be_u64, BufferFile};

// ---------------------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbError(pub String);

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "db: {}", self.0)
    }
}

impl std::error::Error for DbError {}

fn err<T>(msg: impl Into<String>) -> Result<T, DbError> {
    Err(DbError(msg.into()))
}

// ---------------------------------------------------------------------------------------
// Node type tags (NodeMgr.java:65-119)
// ---------------------------------------------------------------------------------------

const LONGKEY_INTERIOR_NODE: u8 = 0;
const LONGKEY_VAR_REC_NODE: u8 = 1;
const LONGKEY_FIXED_REC_NODE: u8 = 2;
const VARKEY_INTERIOR_NODE: u8 = 3;
const VARKEY_REC_NODE: u8 = 4;
const FIXEDKEY_INTERIOR_NODE: u8 = 5;
const FIXEDKEY_VAR_REC_NODE: u8 = 6;
const FIXEDKEY_FIXED_REC_NODE: u8 = 7;
const CHAINED_BUFFER_INDEX_NODE: u8 = 8;
const CHAINED_BUFFER_DATA_NODE: u8 = 9;

/// `NodeMgr.NODE_HEADER_SIZE` — the one-byte node type.
const NODE_HEADER_SIZE: usize = 1;
/// `LongKeyNode.LONGKEY_NODE_HEADER_SIZE` — node type(1) + key count(4).
const LONGKEY_NODE_HEADER_SIZE: usize = NODE_HEADER_SIZE + 4;
/// `LongKeyRecordNode.RECORD_LEAF_HEADER_SIZE` — plus prev/next leaf IDs.
const RECORD_LEAF_HEADER_SIZE: usize = LONGKEY_NODE_HEADER_SIZE + 8;

// ---------------------------------------------------------------------------------------
// Fields (db/Field.java + the per-type read methods)
// ---------------------------------------------------------------------------------------

/// `Field` type codes (`Field.java:63-104`). The low nibble of an encoded field type.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldType {
    Byte,
    Short,
    Int,
    Long,
    String,
    Binary,
    Boolean,
    Fixed10,
}

impl FieldType {
    fn from_code(code: u8) -> Result<FieldType, DbError> {
        Ok(match code & 0x0f {
            0 => FieldType::Byte,
            1 => FieldType::Short,
            2 => FieldType::Int,
            3 => FieldType::Long,
            4 => FieldType::String,
            5 => FieldType::Binary,
            6 => FieldType::Boolean,
            7 => FieldType::Fixed10,
            other => return err(format!("unsupported field type {other}")),
        })
    }

    /// `Field.isVariableLength` — a string or a binary blob carries its own length.
    pub fn is_variable_length(self) -> bool {
        matches!(self, FieldType::String | FieldType::Binary)
    }

    /// `Field.length()` for the fixed-length types.
    fn fixed_length(self) -> usize {
        match self {
            FieldType::Byte | FieldType::Boolean => 1,
            FieldType::Short => 2,
            FieldType::Int => 4,
            FieldType::Long => 8,
            FieldType::Fixed10 => 10,
            // A variable-length field stores a 4-byte length even when empty.
            FieldType::String | FieldType::Binary => 4,
        }
    }
}

/// One decoded field value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldValue {
    Byte(i8),
    Short(i16),
    Int(i32),
    Long(i64),
    /// `null` is distinct from the empty string (`StringField.write` stores length `-1`).
    String(Option<String>),
    Binary(Option<Vec<u8>>),
    Boolean(bool),
    Fixed10([u8; 10]),
}

impl FieldValue {
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            FieldValue::Byte(v) => Some(i64::from(*v)),
            FieldValue::Short(v) => Some(i64::from(*v)),
            FieldValue::Int(v) => Some(i64::from(*v)),
            FieldValue::Long(v) => Some(*v),
            FieldValue::Boolean(v) => Some(i64::from(*v)),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            FieldValue::String(s) => s.as_deref(),
            _ => None,
        }
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            FieldValue::Binary(b) => b.as_deref(),
            FieldValue::Fixed10(b) => Some(b),
            _ => None,
        }
    }
}

/// Read one field, returning it and the offset just past it.
fn read_field(ty: FieldType, data: &[u8], at: usize) -> Result<(FieldValue, usize), DbError> {
    let need = |n: usize| -> Result<(), DbError> {
        if at + n > data.len() {
            return err(format!("truncated {ty:?} field at {at}"));
        }
        Ok(())
    };
    Ok(match ty {
        FieldType::Byte => {
            need(1)?;
            (FieldValue::Byte(data[at] as i8), at + 1)
        }
        FieldType::Boolean => {
            need(1)?;
            (FieldValue::Boolean(data[at] != 0), at + 1)
        }
        FieldType::Short => {
            need(2)?;
            (FieldValue::Short(be_u16(data, at) as i16), at + 2)
        }
        FieldType::Int => {
            need(4)?;
            (FieldValue::Int(be_u32(data, at) as i32), at + 4)
        }
        FieldType::Long => {
            need(8)?;
            (FieldValue::Long(be_u64(data, at) as i64), at + 8)
        }
        FieldType::Fixed10 => {
            need(10)?;
            let mut b = [0u8; 10];
            b.copy_from_slice(&data[at..at + 10]);
            (FieldValue::Fixed10(b), at + 10)
        }
        // `StringField.read` / `BinaryField.read`: a 4-byte length, `-1` meaning null.
        FieldType::String | FieldType::Binary => {
            need(4)?;
            let len = be_u32(data, at) as i32;
            if len < 0 {
                let v = if ty == FieldType::String {
                    FieldValue::String(None)
                } else {
                    FieldValue::Binary(None)
                };
                (v, at + 4)
            } else {
                let start = at + 4;
                let end = start + len as usize;
                if end > data.len() {
                    return err(format!("truncated {ty:?} payload at {start} ({len} bytes)"));
                }
                let bytes = &data[start..end];
                let v = if ty == FieldType::String {
                    // `StringField`: "Strings are always encoded as UTF-8" (`:26`).
                    match std::str::from_utf8(bytes) {
                        Ok(s) => FieldValue::String(Some(s.to_string())),
                        Err(e) => return err(format!("non-UTF-8 string at {start}: {e}")),
                    }
                } else {
                    FieldValue::Binary(Some(bytes.to_vec()))
                };
                (v, end)
            }
        }
    })
}

// ---------------------------------------------------------------------------------------
// Schema (db/Schema.java)
// ---------------------------------------------------------------------------------------

/// `Schema.FIELD_EXTENSION_INDICATOR` (`:32`).
const FIELD_EXTENSION_INDICATOR: u8 = 0xff;
/// `Schema.NAME_SEPARATOR` (`:30`).
const NAME_SEPARATOR: char = ';';

#[derive(Debug, Clone)]
pub struct Schema {
    pub version: i32,
    pub key_type: FieldType,
    pub key_name: String,
    pub field_types: Vec<FieldType>,
    pub field_names: Vec<String>,
}

impl Schema {
    /// `initializeFields` (`:250-283`) + `parseNames` (`:438-447`).
    fn decode(
        version: i32,
        encoded_key_type: u8,
        encoded_field_types: &[u8],
        packed_names: &str,
    ) -> Result<Schema, DbError> {
        let mut field_types = Vec::new();
        for &b in encoded_field_types {
            if b == FIELD_EXTENSION_INDICATOR {
                // Extensions (only the sparse-column list exists) follow; none of the FID
                // tables use them, and stopping here matches Ghidra's field loop.
                break;
            }
            field_types.push(FieldType::from_code(b)?);
        }

        let mut names: Vec<String> =
            packed_names.split(NAME_SEPARATOR).filter(|s| !s.is_empty()).map(String::from).collect();
        if names.is_empty() {
            return err("schema has no key name");
        }
        let key_name = names.remove(0);

        Ok(Schema {
            version,
            key_type: FieldType::from_code(encoded_key_type)?,
            key_name,
            field_types,
            field_names: names,
        })
    }

    /// Whether records under this schema are variable-length — which decides whether a leaf
    /// is a `VarRecNode` or a `FixedRecNode`.
    pub fn is_variable_length(&self) -> bool {
        self.field_types.iter().any(|f| f.is_variable_length())
    }

    /// `Schema.getFixedLength` — the record length when every field is fixed.
    pub fn fixed_length(&self) -> usize {
        self.field_types.iter().map(|f| f.fixed_length()).sum()
    }

    /// Index of a column by name, for callers that would rather not hard-code positions.
    pub fn column(&self, name: &str) -> Option<usize> {
        self.field_names.iter().position(|n| n == name)
    }
}

// ---------------------------------------------------------------------------------------
// Records
// ---------------------------------------------------------------------------------------

/// One stored record: its primary key plus the decoded column values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    pub key: i64,
    pub fields: Vec<FieldValue>,
}

impl Record {
    pub fn i64_at(&self, col: usize) -> Option<i64> {
        self.fields.get(col).and_then(FieldValue::as_i64)
    }
    pub fn str_at(&self, col: usize) -> Option<&str> {
        self.fields.get(col).and_then(FieldValue::as_str)
    }
    pub fn bytes_at(&self, col: usize) -> Option<&[u8]> {
        self.fields.get(col).and_then(FieldValue::as_bytes)
    }
}

fn decode_record(schema: &Schema, key: i64, data: &[u8]) -> Result<Record, DbError> {
    let mut fields = Vec::with_capacity(schema.field_types.len());
    let mut at = 0usize;
    for &ty in &schema.field_types {
        let (value, next) = read_field(ty, data, at)?;
        fields.push(value);
        at = next;
    }
    Ok(Record { key, fields })
}

// ---------------------------------------------------------------------------------------
// ChainedBuffer (db/ChainedBuffer.java)
// ---------------------------------------------------------------------------------------

/// Reassemble a record that was too large for its leaf and was spilled into a chained buffer
/// (`ChainedBuffer.java:39-53`).
///
/// ```text
/// data node   | 9 (1) | Obfuscation/DataLength(4) | Data ...
/// index node  | 8 (1) | Obfuscation/DataLength(4) | NextIndexId(4) | BufferId(4) ... |
/// ```
/// The top bit of the length word flags XOR obfuscation.
fn read_chained_buffer(bf: &BufferFile, first_id: i32) -> Result<Vec<u8>, DbError> {
    let Some(first) = bf.buffer(first_id).map_err(|e| DbError(e.0))? else {
        return err(format!("chained buffer {first_id} is empty"));
    };
    let node_type = first[0];
    let raw_len = be_u32(first, 1);
    let obfuscated = raw_len & 0x8000_0000 != 0;
    let size = (raw_len & 0x7fff_ffff) as usize;
    if obfuscated {
        // Ghidra only sets this for databases created with obfuscation enabled; the shipped
        // FID databases are not. Refuse rather than return silently wrong bytes.
        return err("obfuscated chained buffer is not supported");
    }

    let mut out = Vec::with_capacity(size);
    match node_type {
        CHAINED_BUFFER_DATA_NODE => {
            // Single buffer: data follows the type and length words.
            let base = 1 + 4;
            let take = size.min(first.len() - base);
            out.extend_from_slice(&first[base..base + take]);
        }
        CHAINED_BUFFER_INDEX_NODE => {
            // Walk the index chain, appending each data buffer's payload. An indexed data
            // buffer's payload starts right after its one-byte node type.
            let mut index_id = first_id;
            let mut first_index = true;
            while index_id >= 0 && out.len() < size {
                let Some(index_buf) = bf.buffer(index_id).map_err(|e| DbError(e.0))? else {
                    return err(format!("chained index buffer {index_id} is empty"));
                };
                let next_index_id = be_u32(index_buf, 5) as i32;
                // The first index node carries the length word; subsequent ones do not
                // differ in layout — ids begin after type + length + next-index.
                let base = 1 + 4 + 4;
                let mut at = base;
                while at + 4 <= index_buf.len() && out.len() < size {
                    let data_id = be_u32(index_buf, at) as i32;
                    at += 4;
                    if data_id < 0 {
                        break;
                    }
                    let Some(chunk) = bf.buffer(data_id).map_err(|e| DbError(e.0))? else {
                        return err(format!("chained data buffer {data_id} is empty"));
                    };
                    let payload = &chunk[1..];
                    let take = (size - out.len()).min(payload.len());
                    out.extend_from_slice(&payload[..take]);
                }
                let _ = first_index;
                first_index = false;
                index_id = next_index_id;
            }
        }
        other => return err(format!("buffer {first_id} is not a chained buffer (node type {other})")),
    }

    if out.len() != size {
        return err(format!("chained buffer yielded {} bytes, expected {size}", out.len()));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------------------
// Table (db/Table.java + the node classes)
// ---------------------------------------------------------------------------------------

/// A table's metadata, as stored in the master table (`TableRecord.java:28-55`).
#[derive(Debug, Clone)]
pub struct TableInfo {
    pub table_num: i64,
    pub name: String,
    pub root_buffer_id: i32,
    /// `-1` for a primary table; otherwise the column of the table it indexes.
    pub indexed_column: i32,
    pub record_count: i32,
    pub schema: Schema,
}

/// A database opened from a buffer file.
pub struct Database {
    bf: BufferFile,
    tables: Vec<TableInfo>,
}

/// `DBParms.MASTER_TABLE_ROOT_BUFFER_ID_PARM` (`:36`) — parameter 0 of buffer 0.
const MASTER_TABLE_ROOT_BUFFER_ID_PARM: usize = 0;
/// `DBParms.PARM_BASE_OFFSET` (`:48`) — node type(1) + data length(4) + version(1).
const DBPARMS_BASE_OFFSET: usize = 6;

impl Database {
    /// Open a database over an unpacked buffer file: read `DBParms` from buffer 0, follow it
    /// to the master table, and decode every table record (`MasterTable.java:46-68`).
    pub fn open(bf: BufferFile) -> Result<Database, DbError> {
        let Some(parms) = bf.buffer(0).map_err(|e| DbError(e.0))? else {
            return err("DBParms buffer (id 0) is empty");
        };
        if parms[0] != CHAINED_BUFFER_DATA_NODE {
            return err(format!("DBParms buffer has node type {}, expected a data node", parms[0]));
        }
        let at = DBPARMS_BASE_OFFSET + MASTER_TABLE_ROOT_BUFFER_ID_PARM * 4;
        let master_root = be_u32(parms, at) as i32;

        // The master table's own schema is hard-coded (`TableRecord.java:40-55`).
        let master_schema = Schema {
            version: 0,
            key_type: FieldType::Long,
            key_name: "TableNum".to_string(),
            field_types: vec![
                FieldType::String, // 0 table name
                FieldType::Int,    // 1 schema version
                FieldType::Int,    // 2 root buffer ID
                FieldType::Byte,   // 3 key field type
                FieldType::Binary, // 4 encoded field types
                FieldType::String, // 5 packed field names
                FieldType::Int,    // 6 indexed column (-1 = primary)
                FieldType::Long,   // 7 max key ever used
                FieldType::Int,    // 8 record count
            ],
            field_names: [
                "TableName",
                "SchemaVersion",
                "RootBufferId",
                "KeyType",
                "FieldTypes",
                "FieldNames",
                "IndexColumn",
                "MaxKey",
                "RecordCount",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
        };

        let master_records = collect_records(&bf, master_root, &master_schema)?;
        let mut tables = Vec::with_capacity(master_records.len());
        for rec in master_records {
            let name = rec.str_at(0).unwrap_or_default().to_string();
            let version = rec.i64_at(1).unwrap_or(0) as i32;
            let root_buffer_id = rec.i64_at(2).unwrap_or(-1) as i32;
            let key_type = rec.i64_at(3).unwrap_or(3) as u8;
            let encoded_types = rec.bytes_at(4).unwrap_or_default().to_vec();
            let packed_names = rec.str_at(5).unwrap_or_default().to_string();
            let indexed_column = rec.i64_at(6).unwrap_or(-1) as i32;
            let record_count = rec.i64_at(8).unwrap_or(0) as i32;

            let schema = Schema::decode(version, key_type, &encoded_types, &packed_names)?;
            tables.push(TableInfo {
                table_num: rec.key,
                name,
                root_buffer_id,
                indexed_column,
                record_count,
                schema,
            });
        }

        Ok(Database { bf, tables })
    }

    pub fn tables(&self) -> &[TableInfo] {
        &self.tables
    }

    /// The **primary** table of the given name (`indexed_column == -1`). Ghidra stores index
    /// tables under the same name as the table they index, distinguished by that column.
    pub fn table(&self, name: &str) -> Option<&TableInfo> {
        self.tables.iter().find(|t| t.name == name && t.indexed_column < 0)
    }

    /// Every record of a table, in key order.
    pub fn records(&self, table: &TableInfo) -> Result<Vec<Record>, DbError> {
        collect_records(&self.bf, table.root_buffer_id, &table.schema)
    }

    pub fn buffer_file(&self) -> &BufferFile {
        &self.bf
    }
}

/// Walk a long-key B-tree from `root_id`, collecting every record in key order.
///
/// Interior nodes (`LongKeyInteriorNode.java:27-30`):
/// `| NodeType(1) | KeyCount(4) | Key0(8) | ID0(4) | ... |`
///
/// Leaves are either variable-length (`VarRecNode.java:28-36`):
/// `| NodeType(1) | KeyCount(4) | PrevLeafId(4) | NextLeafId(4) | Key0(8) | RecOffset0(4) | IndFlag0(1) | ... records laid down from the end |`
/// or fixed-length (`FixedRecNode.java:26-33`):
/// `| NodeType(1) | KeyCount(4) | PrevLeafId(4) | NextLeafId(4) | Key0(8) | Rec0 | ... |`
fn collect_records(bf: &BufferFile, root_id: i32, schema: &Schema) -> Result<Vec<Record>, DbError> {
    let mut out = Vec::new();
    if root_id < 0 {
        // `TableRecord` stores -1 when no buffer has been allocated: an empty table.
        return Ok(out);
    }
    let mut visited = 0usize;
    let limit = bf.buffer_count() + 1;
    walk_node(bf, root_id, schema, &mut out, &mut visited, limit)?;
    Ok(out)
}

fn walk_node(
    bf: &BufferFile,
    id: i32,
    schema: &Schema,
    out: &mut Vec<Record>,
    visited: &mut usize,
    limit: usize,
) -> Result<(), DbError> {
    // A malformed tree must terminate rather than loop; every node is visited once in a
    // well-formed tree, so exceeding the buffer count means the structure is wrong.
    *visited += 1;
    if *visited > limit {
        return err("b-tree walk exceeded the buffer count (cycle or corruption)");
    }

    let Some(buf) = bf.buffer(id).map_err(|e| DbError(e.0))? else {
        return err(format!("node buffer {id} is empty"));
    };
    let node_type = buf[0];
    let key_count = be_u32(buf, NODE_HEADER_SIZE) as usize;

    match node_type {
        LONGKEY_INTERIOR_NODE => {
            const ENTRY: usize = 8 + 4;
            for i in 0..key_count {
                let at = LONGKEY_NODE_HEADER_SIZE + i * ENTRY;
                if at + ENTRY > buf.len() {
                    return err(format!("interior node {id} entry {i} overruns the buffer"));
                }
                let child = be_u32(buf, at + 8) as i32;
                walk_node(bf, child, schema, out, visited, limit)?;
            }
        }
        LONGKEY_VAR_REC_NODE => {
            const ENTRY: usize = 8 + 4 + 1;
            for i in 0..key_count {
                let at = RECORD_LEAF_HEADER_SIZE + i * ENTRY;
                if at + ENTRY > buf.len() {
                    return err(format!("var-rec node {id} entry {i} overruns the buffer"));
                }
                let key = be_u64(buf, at) as i64;
                let offset = be_u32(buf, at + 8) as usize;
                let indirect = buf[at + 12] != 0;
                if indirect {
                    // The leaf holds a 4-byte chained-buffer ID in place of the record.
                    let chained_id = be_u32(buf, offset) as i32;
                    let data = read_chained_buffer(bf, chained_id)?;
                    out.push(decode_record(schema, key, &data)?);
                } else {
                    if offset > buf.len() {
                        return err(format!("var-rec node {id} record offset {offset} is out of range"));
                    }
                    out.push(decode_record(schema, key, &buf[offset..])?);
                }
            }
        }
        LONGKEY_FIXED_REC_NODE => {
            let record_length = schema.fixed_length();
            let entry = 8 + record_length;
            for i in 0..key_count {
                let at = RECORD_LEAF_HEADER_SIZE + i * entry;
                if at + entry > buf.len() {
                    return err(format!("fixed-rec node {id} entry {i} overruns the buffer"));
                }
                let key = be_u64(buf, at) as i64;
                out.push(decode_record(schema, key, &buf[at + 8..at + entry])?);
            }
        }
        VARKEY_INTERIOR_NODE | VARKEY_REC_NODE | FIXEDKEY_INTERIOR_NODE
        | FIXEDKEY_VAR_REC_NODE | FIXEDKEY_FIXED_REC_NODE => {
            // Index tables use these. FID's primary tables are all long-keyed; the secondary
            // full-hash index is rebuilt in memory from the functions table instead of being
            // decoded (see `docs/fid-port-plan.md` §5 Stage 2).
            return err(format!("node type {node_type} (non-long-key) is not decoded"));
        }
        other => return err(format!("unexpected node type {other} in buffer {id}")),
    }
    Ok(())
}

/// Convenience: open a packed `.fidb` straight from bytes.
pub fn open_packed(data: &[u8]) -> Result<Database, DbError> {
    let unpacked = super::packed::unpack(data).map_err(|e| DbError(e.0))?;
    let bf = BufferFile::open(unpacked).map_err(|e| DbError(e.0))?;
    Database::open(bf)
}

/// Table names → their record counts, for a quick structural summary.
pub fn table_summary(db: &Database) -> HashMap<String, i32> {
    db.tables().iter().map(|t| (t.name.clone(), t.record_count)).collect()
}
