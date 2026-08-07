//! `LocalBufferFile` — a read-only port of Ghidra's
//! `db/buffers/LocalBufferFile.java`, the block-oriented container every Ghidra database
//! sits in.
//!
//! Layout (`LocalBufferFile.java:60-86`, all fields **big-endian**):
//!
//! ```text
//! block 0 = the file header
//!   0   int64  MAGIC_NUMBER 0x2f30312c34292c2a
//!   8   int64  file ID
//!   16  int32  header format version (= 1)
//!   20  int32  block size            (= 0x4000 for the FID databases)
//!   24  int32  first free block index
//!   28  int32  user parameter count, then that many { int32 nameLen, name, int32 value }
//!
//! block N (N >= 1) = one buffer, `blockSize` bytes
//!   0   int8   flags — bit 0 set means an empty block
//!   1   int32  buffer ID (or the next empty index when empty)
//!   5   ...    `bufferSize = blockSize - 5` bytes of buffer data
//! ```
//!
//! Buffer index 0 lives in block 1 (`seekBufferBlock`, `:407-413`) — the header block shifts
//! everything by one.

use std::collections::HashMap;

/// `LocalBufferFile.MAGIC_NUMBER` (`:36`).
pub const MAGIC_NUMBER: u64 = 0x2f30_312c_3429_2c2a;
/// `LocalBufferFile.HEADER_FORMAT_VERSION` (`:56`).
pub const HEADER_FORMAT_VERSION: i32 = 1;
/// `LocalBufferFile.BUFFER_PREFIX_SIZE` (`:93`) — flags(1) + buffer ID(4).
pub const BUFFER_PREFIX_SIZE: usize = 5;
/// `LocalBufferFile.EMPTY_BUFFER` (`:99`).
const EMPTY_BUFFER: u8 = 0x01;
/// `LocalBufferFile.VER1_FIXED_HEADER_LENGTH` (`:96`).
const VER1_FIXED_HEADER_LENGTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BufferFileError(pub String);

impl std::fmt::Display for BufferFileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "buffer file: {}", self.0)
    }
}

impl std::error::Error for BufferFileError {}

fn err<T>(msg: impl Into<String>) -> Result<T, BufferFileError> {
    Err(BufferFileError(msg.into()))
}

/// An unpacked buffer file, held in memory.
///
/// The FID databases are 10–41 MB unpacked, which is small enough to keep resident and lets
/// every buffer fetch be a slice rather than a seek. Ghidra's `BufferMgr` cache exists to
/// avoid re-reading from disk; holding the whole image is the same idea taken to its limit.
pub struct BufferFile {
    data: Vec<u8>,
    block_size: usize,
    buffer_size: usize,
    buffer_count: usize,
    parameters: HashMap<String, i32>,
}

impl BufferFile {
    /// `readHeader` (`:437-473`).
    pub fn open(data: Vec<u8>) -> Result<BufferFile, BufferFileError> {
        if data.len() < VER1_FIXED_HEADER_LENGTH {
            return err("shorter than the fixed header");
        }
        if be_u64(&data, 0) != MAGIC_NUMBER {
            return err("unrecognized file format (bad magic)");
        }
        let version = be_u32(&data, 16) as i32;
        if version != HEADER_FORMAT_VERSION {
            return err(format!("unrecognized header format version {version}"));
        }
        let block_size = be_u32(&data, 20) as usize;
        if block_size <= BUFFER_PREFIX_SIZE {
            return err(format!("implausible block size {block_size}"));
        }
        if !data.len().is_multiple_of(block_size) {
            return err("corrupt file: length is not a whole number of blocks");
        }

        let buffer_size = block_size - BUFFER_PREFIX_SIZE;
        let buffer_count = data.len() / block_size - 1;

        // User-defined parameters (`:465-472`).
        let mut parameters = HashMap::new();
        let count = be_u32(&data, 28) as usize;
        let mut at = VER1_FIXED_HEADER_LENGTH;
        for _ in 0..count {
            if at + 4 > block_size {
                return err("parameter list overruns the header block");
            }
            let name_len = be_u32(&data, at) as usize;
            at += 4;
            let Some(name_bytes) = data.get(at..at + name_len) else {
                return err("truncated parameter name");
            };
            at += name_len;
            let Ok(name) = std::str::from_utf8(name_bytes) else {
                return err("non-UTF-8 parameter name");
            };
            if at + 4 > block_size {
                return err("truncated parameter value");
            }
            parameters.insert(name.to_string(), be_u32(&data, at) as i32);
            at += 4;
        }

        Ok(BufferFile { data, block_size, buffer_size, buffer_count, parameters })
    }

    /// `getBufferSize` — the usable bytes per buffer, i.e. block size minus the prefix.
    pub fn buffer_size(&self) -> usize {
        self.buffer_size
    }

    /// `getIndexCount` — the number of buffers (blocks minus the header block).
    pub fn buffer_count(&self) -> usize {
        self.buffer_count
    }

    pub fn parameters(&self) -> &HashMap<String, i32> {
        &self.parameters
    }

    /// `get(DataBuffer, int index)` (`:635-671`). Returns `None` for an empty buffer, which is
    /// how Ghidra signals a free block rather than an error.
    pub fn buffer(&self, index: i32) -> Result<Option<&[u8]>, BufferFileError> {
        if index < 0 || index as usize > self.buffer_count {
            return err(format!("buffer index out of range ({index} > {})", self.buffer_count));
        }
        // `seekBufferBlock` (`:407-413`): buffer #0 is block #1.
        let at = (index as usize + 1) * self.block_size;
        let flags = self.data[at];
        if flags & EMPTY_BUFFER != 0 {
            return Ok(None);
        }
        let start = at + BUFFER_PREFIX_SIZE;
        Ok(Some(&self.data[start..start + self.buffer_size]))
    }

    /// The buffer ID stored in a block's prefix. Ghidra reads this into `DataBuffer.setId`; a
    /// consistency check, since for a non-empty block it equals the index.
    pub fn buffer_id(&self, index: i32) -> Result<i32, BufferFileError> {
        if index < 0 || index as usize > self.buffer_count {
            return err(format!("buffer index out of range ({index})"));
        }
        let at = (index as usize + 1) * self.block_size;
        Ok(be_u32(&self.data, at + 1) as i32)
    }
}

pub(crate) fn be_u16(data: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([data[at], data[at + 1]])
}

pub(crate) fn be_u32(data: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([data[at], data[at + 1], data[at + 2], data[at + 3]])
}

pub(crate) fn be_u64(data: &[u8], at: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&data[at..at + 8]);
    u64::from_be_bytes(b)
}
