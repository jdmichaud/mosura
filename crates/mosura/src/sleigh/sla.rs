//! Loader for compiled SLEIGH tables (`.sla`) — the entry point of the SLEIGH
//! runtime (stage 1b).
//!
//! A `.sla` file is a 4-byte header (`s l a` + format version) followed by a
//! zlib-deflated **PackedDecode** stream (Ghidra's `marshal` format). This module
//! decompresses and decodes that stream into a generic element tree of *numeric
//! ids* — the same ids Ghidra compares against internally (names exist only for
//! the XML serializer). Higher layers interpret the ids per element.
//!
//! PackedDecode record format (see `marshal.cc`): each record begins with a
//! header byte — top two bits select element-start (`0x40`), element-end (`0x80`),
//! or attribute (`0xc0`); bit `0x20` means the id continues into the next byte;
//! the low 5 bits hold (part of) the id. Continuation/data bytes carry 7 bits
//! each. An attribute header is followed by a type byte (4-bit type code + 4-bit
//! length code) and then its value.

use std::io::Read;

/// The `.sla` format version this loader understands (matches Ghidra 12.0.3).
pub const FORMAT_VERSION: u8 = 4;

/// A few `sla`-format ids referenced by name. Full vocabulary: `slaformat.cc`
/// (`namespace sla`). Element ids and attribute ids are separate id spaces, so
/// equal numbers in the two groups are unrelated.
pub mod id {
    pub const ELEM_SLEIGH: u32 = 33;
    pub const ELEM_SPACES: u32 = 34;
    pub const ELEM_SPACE: u32 = 37;
    pub const ELEM_SPACE_OTHER: u32 = 45;
    pub const ELEM_SPACE_UNIQUE: u32 = 46;

    pub const ATTRIB_NAME: u32 = 12;
    pub const ATTRIB_VERSION: u32 = 34;
    pub const ATTRIB_BIGENDIAN: u32 = 35;
    pub const ATTRIB_ALIGN: u32 = 36;
    pub const ATTRIB_DEFAULTSPACE: u32 = 41;
}

/// A decoded attribute value.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Bool(bool),
    Int(i64),
    Uint(u64),
    /// Address space referenced by index.
    Space(u64),
    /// A "special" space (stack/join/fspec/iop/spacebase), by code.
    SpecialSpace(u32),
    Str(String),
}

impl Value {
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(v) => Some(*v),
            Value::Uint(v) => Some(*v as i64),
            // address-space attributes carry a space index
            Value::Space(v) => Some(*v as i64),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        if let Value::Bool(b) = self { Some(*b) } else { None }
    }
    pub fn as_str(&self) -> Option<&str> {
        if let Value::Str(s) = self { Some(s) } else { None }
    }
}

#[derive(Debug, Clone)]
pub struct Attr {
    pub id: u32,
    pub value: Value,
}

/// A decoded element: numeric id, ordered attributes, ordered children.
#[derive(Debug, Clone)]
pub struct Element {
    pub id: u32,
    pub attrs: Vec<Attr>,
    pub children: Vec<Element>,
}

impl Element {
    pub fn attr(&self, id: u32) -> Option<&Value> {
        self.attrs.iter().find(|a| a.id == id).map(|a| &a.value)
    }
    pub fn attr_int(&self, id: u32) -> Option<i64> {
        self.attr(id).and_then(Value::as_int)
    }
    pub fn attr_bool(&self, id: u32) -> Option<bool> {
        self.attr(id).and_then(Value::as_bool)
    }
    pub fn attr_str(&self, id: u32) -> Option<&str> {
        self.attr(id).and_then(Value::as_str)
    }
    /// First direct child with the given element id.
    pub fn child(&self, id: u32) -> Option<&Element> {
        self.children.iter().find(|c| c.id == id)
    }
    /// Total number of elements in this subtree (including `self`).
    pub fn count(&self) -> usize {
        1 + self.children.iter().map(Element::count).sum::<usize>()
    }
}

#[derive(Debug)]
pub enum Error {
    BadMagic,
    BadVersion(u8),
    Decompress(std::io::Error),
    Truncated,
    /// Unexpected record/type byte at a position where another kind was required.
    BadRecord(u8),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::BadMagic => write!(f, "not a .sla file (bad magic)"),
            Error::BadVersion(v) => write!(f, "unsupported .sla format version {v} (expected {FORMAT_VERSION})"),
            Error::Decompress(e) => write!(f, "decompress: {e}"),
            Error::Truncated => write!(f, "truncated packed stream"),
            Error::BadRecord(b) => write!(f, "unexpected record byte {b:#04x}"),
        }
    }
}
impl std::error::Error for Error {}

const HEADER_MASK: u8 = 0xc0;
const ELEMENT_START: u8 = 0x40;
const ELEMENT_END: u8 = 0x80;
const ATTRIBUTE: u8 = 0xc0;
const HEADEREXTEND: u8 = 0x20;
const ELEMENTID_MASK: u8 = 0x1f;
const RAWDATA_MASK: u8 = 0x7f;

// Type codes (high nibble of an attribute's type byte).
const TYPE_BOOL: u8 = 1;
const TYPE_SINT_POS: u8 = 2;
const TYPE_SINT_NEG: u8 = 3;
const TYPE_UINT: u8 = 4;
const TYPE_ADDRSPACE: u8 = 5;
const TYPE_SPECIALSPACE: u8 = 6;
const TYPE_STRING: u8 = 7;

/// Decode the full bytes of a `.sla` file into its root element.
pub fn decode(bytes: &[u8]) -> Result<Element, Error> {
    if bytes.len() < 4 || &bytes[0..3] != b"sla" {
        return Err(Error::BadMagic);
    }
    if bytes[3] != FORMAT_VERSION {
        return Err(Error::BadVersion(bytes[3]));
    }
    let mut raw = Vec::new();
    flate2::read::ZlibDecoder::new(&bytes[4..])
        .read_to_end(&mut raw)
        .map_err(Error::Decompress)?;
    parse_element(&mut Cursor { buf: &raw, pos: 0 })
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn next(&mut self) -> Result<u8, Error> {
        let b = *self.buf.get(self.pos).ok_or(Error::Truncated)?;
        self.pos += 1;
        Ok(b)
    }
    fn peek(&self) -> Option<u8> {
        self.buf.get(self.pos).copied()
    }
    /// Read `len` 7-bit continuation bytes into an integer.
    fn read_int(&mut self, len: u32) -> Result<u64, Error> {
        let mut res = 0u64;
        for _ in 0..len {
            res = (res << 7) | u64::from(self.next()? & RAWDATA_MASK);
        }
        Ok(res)
    }
    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], Error> {
        let end = self.pos.checked_add(len).ok_or(Error::Truncated)?;
        let s = self.buf.get(self.pos..end).ok_or(Error::Truncated)?;
        self.pos = end;
        Ok(s)
    }
}

/// Read a record header's id (handling the one-byte extension).
fn read_id(c: &mut Cursor, header: u8) -> Result<u32, Error> {
    let mut id = u32::from(header & ELEMENTID_MASK);
    if header & HEADEREXTEND != 0 {
        id = (id << 7) | u32::from(c.next()? & RAWDATA_MASK);
    }
    Ok(id)
}

fn parse_attribute(c: &mut Cursor) -> Result<Attr, Error> {
    let header = c.next()?;
    let id = read_id(c, header)?;
    let type_byte = c.next()?;
    let typecode = type_byte >> 4;
    let lengthcode = u32::from(type_byte & 0x0f);
    let value = match typecode {
        TYPE_BOOL => Value::Bool(lengthcode != 0),
        TYPE_SINT_POS => Value::Int(c.read_int(lengthcode)? as i64),
        TYPE_SINT_NEG => Value::Int(-(c.read_int(lengthcode)? as i64)),
        TYPE_UINT => Value::Uint(c.read_int(lengthcode)?),
        TYPE_ADDRSPACE => Value::Space(c.read_int(lengthcode)?),
        TYPE_SPECIALSPACE => Value::SpecialSpace(lengthcode),
        TYPE_STRING => {
            let len = c.read_int(lengthcode)? as usize;
            Value::Str(String::from_utf8_lossy(c.read_bytes(len)?).into_owned())
        }
        other => return Err(Error::BadRecord(other)),
    };
    Ok(Attr { id, value })
}

fn parse_element(c: &mut Cursor) -> Result<Element, Error> {
    let header = c.next()?;
    if header & HEADER_MASK != ELEMENT_START {
        return Err(Error::BadRecord(header));
    }
    let id = read_id(c, header)?;

    let mut attrs = Vec::new();
    while let Some(p) = c.peek() {
        if p & HEADER_MASK != ATTRIBUTE {
            break;
        }
        attrs.push(parse_attribute(c)?);
    }

    let mut children = Vec::new();
    loop {
        let p = c.peek().ok_or(Error::Truncated)?;
        match p & HEADER_MASK {
            ELEMENT_START => children.push(parse_element(c)?),
            ELEMENT_END => {
                let header = c.next()?;
                read_id(c, header)?; // consume the close id
                break;
            }
            _ => return Err(Error::BadRecord(p)),
        }
    }
    Ok(Element { id, attrs, children })
}
