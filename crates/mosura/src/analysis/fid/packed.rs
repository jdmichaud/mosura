//! Unpacking a `.fidb` — a faithful read-side port of Ghidra's
//! `framework/store/local/ItemSerializer.java`.
//!
//! A `.fidb` is a *packed folder item*: a small header followed by the DEFLATE-compressed
//! payload. The payload is the raw `LocalBufferFile` that Ghidra's own module build writes
//! out as `.fidbf` — so unpacking here is exactly the step
//! `FunctionID/build.gradle:46` performs ahead of time.
//!
//! The header is produced by a Java `ObjectOutputStream` (`ItemSerializer.java:72-79`), but no
//! Java object graph is involved: the writes are all primitives, so they land in a single
//! *block data* record, and reading them back is a fixed walk. Layout, verified against the
//! shipped databases:
//!
//! ```text
//! AC ED 00 05    ObjectOutputStream STREAM_MAGIC + STREAM_VERSION
//! 77 44          TC_BLOCKDATA, length 0x44 = 68
//!   int64        MAGIC_NUMBER  0x2e30212634e92c20   <- ItemSerializer.java:43, at offset 6
//!   int32        FORMAT_VERSION = 1
//!   utf          item name       ("Function ID Database")
//!   utf          content type    ("Function ID Database")
//!   int32        file type
//!   int64        unpacked length
//! 50 4B 03 04    the ZIP stream: one DEFLATED entry named "FOLDER_ITEM"
//! ```
//!
//! The 68 bytes are `8 + 4 + (2+20) + (2+20) + 4 + 8`, which is why the block-data length is
//! tied to the string lengths rather than being a constant.

use std::io::Read;

/// `ItemSerializer.MAGIC_NUMBER` (`:43`).
pub const ITEM_MAGIC_NUMBER: u64 = 0x2e30_2126_34e9_2c20;
/// `ItemSerializer.MAGIC_NUMBER_POS` (`:40`) — where that magic sits in the file.
pub const ITEM_MAGIC_NUMBER_POS: usize = 6;
/// `ItemSerializer.FORMAT_VERSION` (`:44`).
pub const ITEM_FORMAT_VERSION: i32 = 1;
/// `ItemSerializer.ZIP_ENTRY_NAME` (`:45`).
pub const ZIP_ENTRY_NAME: &str = "FOLDER_ITEM";

/// Java `ObjectStreamConstants.STREAM_MAGIC` / `STREAM_VERSION`.
const STREAM_MAGIC: u16 = 0xaced;
const STREAM_VERSION: u16 = 0x0005;
/// Java `ObjectStreamConstants.TC_BLOCKDATA` / `TC_BLOCKDATALONG`.
const TC_BLOCKDATA: u8 = 0x77;
const TC_BLOCKDATALONG: u8 = 0x7a;

/// The header metadata `ItemSerializer` records ahead of the payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedHeader {
    pub item_name: String,
    pub content_type: String,
    pub file_type: i32,
    /// The **unpacked** payload length in bytes. A decode that does not produce exactly this
    /// many bytes is wrong.
    pub length: u64,
    /// Offset at which the ZIP stream begins.
    pub payload_offset: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PackedError(pub String);

impl std::fmt::Display for PackedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "packed item: {}", self.0)
    }
}

impl std::error::Error for PackedError {}

fn err<T>(msg: impl Into<String>) -> Result<T, PackedError> {
    Err(PackedError(msg.into()))
}

/// `ItemSerializer.isPackedFile` (`:166-172`) — the magic at [`ITEM_MAGIC_NUMBER_POS`].
pub fn is_packed_file(data: &[u8]) -> bool {
    read_u64(data, ITEM_MAGIC_NUMBER_POS) == Some(ITEM_MAGIC_NUMBER)
}

fn read_u16(data: &[u8], at: usize) -> Option<u16> {
    let b = data.get(at..at + 2)?;
    Some(u16::from_be_bytes([b[0], b[1]]))
}

fn read_u32(data: &[u8], at: usize) -> Option<u32> {
    let b = data.get(at..at + 4)?;
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u64(data: &[u8], at: usize) -> Option<u64> {
    let b = data.get(at..at + 8)?;
    Some(u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
}

/// Java `DataInput.readUTF` — a big-endian `u16` length followed by that many bytes of
/// modified UTF-8. Ghidra writes plain ASCII names here, so a strict UTF-8 decode suffices;
/// anything else is reported rather than silently lossy-converted.
fn read_utf(data: &[u8], at: usize) -> Result<(String, usize), PackedError> {
    let Some(len) = read_u16(data, at) else {
        return err(format!("truncated UTF length at {at}"));
    };
    let start = at + 2;
    let end = start + usize::from(len);
    let Some(bytes) = data.get(start..end) else {
        return err(format!("truncated UTF payload at {start} ({len} bytes)"));
    };
    match std::str::from_utf8(bytes) {
        Ok(s) => Ok((s.to_string(), end)),
        Err(e) => err(format!("non-UTF-8 string at {start}: {e}")),
    }
}

/// Parse the `ItemSerializer` header and locate the compressed payload.
pub fn parse_header(data: &[u8]) -> Result<PackedHeader, PackedError> {
    if read_u16(data, 0) != Some(STREAM_MAGIC) || read_u16(data, 2) != Some(STREAM_VERSION) {
        return err("not a Java ObjectOutputStream (bad STREAM_MAGIC/VERSION)");
    }

    // The block-data record holding every primitive the header writes.
    let (block_len, mut pos) = match data.get(4) {
        Some(&TC_BLOCKDATA) => {
            let Some(&len) = data.get(5) else { return err("truncated block-data length") };
            (u32::from(len), 6usize)
        }
        Some(&TC_BLOCKDATALONG) => {
            let Some(len) = read_u32(data, 5) else { return err("truncated long block-data length") };
            (len, 9usize)
        }
        other => return err(format!("expected TC_BLOCKDATA, found {other:?}")),
    };
    let block_end = pos + block_len as usize;

    let Some(magic) = read_u64(data, pos) else { return err("truncated magic") };
    if magic != ITEM_MAGIC_NUMBER {
        return err(format!("bad ItemSerializer magic {magic:#x}"));
    }
    pos += 8;

    let Some(version) = read_u32(data, pos) else { return err("truncated format version") };
    if version as i32 != ITEM_FORMAT_VERSION {
        return err(format!("unsupported packed format version {version}"));
    }
    pos += 4;

    let (item_name, next) = read_utf(data, pos)?;
    let (content_type, next) = read_utf(data, next)?;
    pos = next;

    let Some(file_type) = read_u32(data, pos) else { return err("truncated file type") };
    pos += 4;
    let Some(length) = read_u64(data, pos) else { return err("truncated length") };
    pos += 8;

    if pos != block_end {
        return err(format!("header consumed {pos} bytes, block declared {block_end}"));
    }

    Ok(PackedHeader {
        item_name,
        content_type,
        file_type: file_type as i32,
        length,
        payload_offset: block_end,
    })
}

/// Unpack a `.fidb` into the raw `LocalBufferFile` bytes it wraps (what Ghidra writes as
/// `.fidbf`).
///
/// The ZIP holds exactly one DEFLATED entry. `ZipOutputStream` cannot know the compressed
/// size or CRC in advance, so it sets the data-descriptor flag, writes zeros in the local
/// header, and appends the real values after the compressed data (APPNOTE 4.3.9). The decode
/// is therefore driven by the deflate stream's own end marker, then **checked three ways**:
/// against the length the item header declared, against the descriptor's uncompressed size,
/// and against its CRC-32.
///
/// The CRC check is what makes corruption an error rather than a plausible-looking buffer —
/// a raw inflate happily produces garbage of the right shape from a flipped bit.
pub fn unpack(data: &[u8]) -> Result<Vec<u8>, PackedError> {
    let header = parse_header(data)?;
    let zip = header.payload_offset;

    if data.get(zip..zip + 4) != Some(&[0x50, 0x4b, 0x03, 0x04][..]) {
        return err("payload is not a ZIP local file header (PK\\x03\\x04)");
    }
    let Some(flags) = read_u16_le(data, zip + 6) else { return err("truncated ZIP flags") };
    let Some(method) = read_u16_le(data, zip + 8) else { return err("truncated ZIP method") };
    if method != 8 {
        return err(format!("ZIP entry is not DEFLATED (method {method})"));
    }
    let Some(header_crc) = read_u32_le(data, zip + 14) else { return err("truncated ZIP crc") };
    let Some(name_len) = read_u16_le(data, zip + 26) else { return err("truncated ZIP name length") };
    let Some(extra_len) = read_u16_le(data, zip + 28) else { return err("truncated ZIP extra length") };

    let name_at = zip + 30;
    let name_end = name_at + usize::from(name_len);
    let Some(name) = data.get(name_at..name_end) else { return err("truncated ZIP entry name") };
    if name != ZIP_ENTRY_NAME.as_bytes() {
        return err(format!("unexpected ZIP entry name {:?}", String::from_utf8_lossy(name)));
    }

    let deflate_at = name_end + usize::from(extra_len);
    let Some(compressed) = data.get(deflate_at..) else { return err("truncated ZIP payload") };

    let mut out = Vec::with_capacity(header.length as usize);
    let mut decoder = flate2::read::DeflateDecoder::new(compressed);
    if let Err(e) = decoder.read_to_end(&mut out) {
        return err(format!("inflate failed: {e}"));
    }

    if out.len() as u64 != header.length {
        return err(format!(
            "inflated {} bytes, item header declared {}",
            out.len(),
            header.length
        ));
    }

    // Locate the authoritative CRC: in the trailing data descriptor when bit 3 of the general
    // purpose flags is set (always, for a streamed entry), otherwise in the local header.
    let expected_crc = if flags & 0x0008 != 0 {
        let mut at = deflate_at + decoder.total_in() as usize;
        // The descriptor signature is optional (APPNOTE 4.3.9.3).
        if read_u32_le(data, at) == Some(0x0807_4b50) {
            at += 4;
        }
        let (Some(crc), Some(size)) = (read_u32_le(data, at), read_u32_le(data, at + 8)) else {
            return err("truncated ZIP data descriptor");
        };
        if u64::from(size) != header.length {
            return err(format!(
                "data descriptor says {size} uncompressed bytes, item header says {}",
                header.length
            ));
        }
        crc
    } else {
        header_crc
    };

    let mut crc = flate2::Crc::new();
    crc.update(&out);
    if crc.sum() != expected_crc {
        return err(format!("CRC mismatch: computed {:#010x}, expected {expected_crc:#010x}", crc.sum()));
    }

    Ok(out)
}

fn read_u32_le(data: &[u8], at: usize) -> Option<u32> {
    let b = data.get(at..at + 4)?;
    Some(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_u16_le(data: &[u8], at: usize) -> Option<u16> {
    let b = data.get(at..at + 2)?;
    Some(u16::from_le_bytes([b[0], b[1]]))
}
