//! `Memory` / `MemoryBlock` — a port of Ghidra's `program/model/mem/`. The program's
//! address space as the loader lays it down: named blocks with permissions, each
//! either initialized (backed by bytes) or not (e.g. `.bss`).
//!
//! Accessors mirror `MemoryBlock`: [`MemoryBlock::start`], [`end`](MemoryBlock::end),
//! [`size`](MemoryBlock::size), [`name`](MemoryBlock::name),
//! [`is_read`](MemoryBlock::is_read)/`is_write`/`is_execute`/`is_initialized`.

use crate::decompile::space::Address;

/// One named, contiguous region of the address space (Ghidra `MemoryBlock`).
#[derive(Clone, Debug)]
pub struct MemoryBlock {
    pub name: String,
    /// First address (inclusive).
    pub start: Address,
    /// Last address (inclusive) — `start.offset + size - 1`.
    pub end: Address,
    pub read: bool,
    pub write: bool,
    pub execute: bool,
    /// Initialized bytes, or `None` for uninitialized blocks (`.bss`).
    pub bytes: Option<Vec<u8>>,
}

impl MemoryBlock {
    pub fn start(&self) -> Address {
        self.start
    }
    pub fn end(&self) -> Address {
        self.end
    }
    pub fn size(&self) -> u64 {
        self.end.offset - self.start.offset + 1
    }
    pub fn name(&self) -> &str {
        &self.name
    }
    pub fn is_read(&self) -> bool {
        self.read
    }
    pub fn is_write(&self) -> bool {
        self.write
    }
    pub fn is_execute(&self) -> bool {
        self.execute
    }
    pub fn is_initialized(&self) -> bool {
        self.bytes.is_some()
    }
    pub fn contains(&self, addr: Address) -> bool {
        addr.space == self.start.space
            && self.start.offset <= addr.offset
            && addr.offset <= self.end.offset
    }
    /// The byte at `addr`, if this block is initialized and covers it.
    pub fn byte_at(&self, addr: Address) -> Option<u8> {
        if !self.contains(addr) {
            return None;
        }
        self.bytes
            .as_ref()
            .and_then(|b| b.get((addr.offset - self.start.offset) as usize).copied())
    }
}

/// The program's memory map (Ghidra `Memory`).
#[derive(Clone, Default, Debug)]
pub struct Memory {
    blocks: Vec<MemoryBlock>,
}

impl Memory {
    pub fn new() -> Memory {
        Memory { blocks: Vec::new() }
    }

    /// Create a block spanning `[start, start+len-1]`. `bytes` is `None` for an
    /// uninitialized block, else must be `len` long.
    pub fn add_block(
        &mut self,
        name: &str,
        start: Address,
        len: u64,
        read: bool,
        write: bool,
        execute: bool,
        bytes: Option<Vec<u8>>,
    ) {
        debug_assert!(len > 0, "memory block must be non-empty");
        if let Some(b) = &bytes {
            debug_assert_eq!(b.len() as u64, len, "initialized block bytes must match len");
        }
        let end = Address::new(start.space, start.offset + len - 1);
        self.blocks.push(MemoryBlock { name: name.to_string(), start, end, read, write, execute, bytes });
        self.blocks.sort_by_key(|b| (b.start.space.0, b.start.offset));
    }

    /// All blocks, ordered by `(space, start)`.
    pub fn blocks(&self) -> impl Iterator<Item = &MemoryBlock> {
        self.blocks.iter()
    }

    pub fn block_at(&self, addr: Address) -> Option<&MemoryBlock> {
        self.blocks.iter().find(|b| b.contains(addr))
    }

    /// True if `addr` lies in the artificial `EXTERNAL` block — a port of Ghidra
    /// `Memory.isExternalBlockAddress` (which tests `MemoryBlock.EXTERNAL_BLOCK_NAME`,
    /// the string `"EXTERNAL"`).
    pub fn is_external_block_address(&self, addr: Address) -> bool {
        self.block_at(addr).is_some_and(|b| b.name() == "EXTERNAL")
    }

    /// Read up to `len` consecutive initialized bytes starting at `addr`, stopping at the
    /// first uncovered/uninitialized byte (a decode window for the disassembler).
    pub fn read_window(&self, addr: Address, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        for i in 0..len as u64 {
            match self.byte_at(Address::new(addr.space, addr.offset + i)) {
                Some(b) => out.push(b),
                None => break,
            }
        }
        out
    }

    pub fn contains(&self, addr: Address) -> bool {
        self.block_at(addr).is_some()
    }

    /// Read one byte from whichever initialized block covers `addr`.
    pub fn byte_at(&self, addr: Address) -> Option<u8> {
        self.block_at(addr).and_then(|b| b.byte_at(addr))
    }

    /// Write a little-endian `u64` into whichever initialized block covers `addr` (used to
    /// apply relocations, like Ghidra patching the image). No-op if the address is
    /// uncovered/uninitialized or the value would overrun the block.
    pub fn write_u64(&mut self, addr: Address, value: u64) {
        if let Some(block) = self.blocks.iter_mut().find(|b| b.contains(addr)) {
            if let Some(bytes) = block.bytes.as_mut() {
                let off = (addr.offset - block.start.offset) as usize;
                if off + 8 <= bytes.len() {
                    bytes[off..off + 8].copy_from_slice(&value.to_le_bytes());
                }
            }
        }
    }

    /// Find the (default-space) block by name.
    pub fn block_by_name(&self, name: &str) -> Option<&MemoryBlock> {
        self.blocks.iter().find(|b| b.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::space::SpaceId;
    const RAM: SpaceId = SpaceId(1);

    #[test]
    fn block_ranges_and_bytes() {
        let mut m = Memory::new();
        m.add_block(".text", Address::new(RAM, 0x1000), 4, true, false, true, Some(vec![0xde, 0xad, 0xbe, 0xef]));
        m.add_block(".bss", Address::new(RAM, 0x2000), 16, true, true, false, None);

        let text = m.block_by_name(".text").unwrap();
        assert_eq!(text.end().offset, 0x1003);
        assert_eq!(text.size(), 4);
        assert!(text.is_execute() && !text.is_write() && text.is_initialized());
        assert_eq!(m.byte_at(Address::new(RAM, 0x1002)), Some(0xbe));
        assert_eq!(m.byte_at(Address::new(RAM, 0x1004)), None); // past end

        let bss = m.block_by_name(".bss").unwrap();
        assert!(!bss.is_initialized() && bss.is_write());
        assert_eq!(m.byte_at(Address::new(RAM, 0x2000)), None); // uninitialized
        assert!(m.contains(Address::new(RAM, 0x2005)));
    }

    #[test]
    fn blocks_sorted_by_start() {
        let mut m = Memory::new();
        m.add_block("b", Address::new(RAM, 0x2000), 8, true, false, false, None);
        m.add_block("a", Address::new(RAM, 0x1000), 8, true, false, false, None);
        let names: Vec<_> = m.blocks().map(|b| b.name()).collect();
        assert_eq!(names, vec!["a", "b"]);
    }
}
