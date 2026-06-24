//! PE loader — a port of the *output* of Ghidra's `PeLoader` (`app/util/opinion/`).
//! Bytes of a Portable Executable → a [`Program`] memory map matching Ghidra:
//!
//! - a `Headers` block at the image base, sized like Ghidra's `getVirtualSize`
//!   (`max(0xF0 + 0x14 + 4 + e_lfanew, SizeOfHeaders)`, capped at the file length);
//! - one block per section, named after the section, spanning its **virtual size**
//!   (`SizeOfRawData` initialized bytes + uninitialized padding joined to the virtual
//!   size), with permissions from the section characteristics.
//!
//! Inter-section gaps are left unmapped (Ghidra does not fill them). The artificial
//! `tdb` (ThreadEnvironmentBlock) block is created by a Windows *analyzer*, not the
//! loader, so it is not produced here. PE container decoding uses the `object` crate.

use object::pe;
use object::read::pe::{ImageNtHeaders, ImageOptionalHeader, PeFile64};
use object::LittleEndian as LE;

use super::elf::LoadError;
use crate::analysis::program::{AddressSet, Memory, Program, SymbolType};
use crate::decompile::space::{Address, SpaceId, SpaceKind, SpaceManager};

/// `IMAGE_SIZEOF_NT_OPTIONAL64_HEADER` — size of the 64-bit optional header.
const OPTIONAL64_HEADER_SIZE: u64 = 0xF0;
/// `IMAGE_SIZEOF_FILE_HEADER`.
const FILE_HEADER_SIZE: u64 = 0x14;

/// Parse a PE image and build the [`Program`] memory map (A2).
pub fn load_pe(data: &[u8]) -> Result<Program, LoadError> {
    let pe = PeFile64::parse(data)?;
    let oh = pe.nt_headers().optional_header();
    let image_base = oh.image_base();
    let size_of_headers = u64::from(oh.size_of_headers());
    let e_lfanew = u64::from(pe.dos_header().nt_headers_offset());

    // x86-64 PE only for now (the corpus); 32-bit PE maps a different language id.
    let machine = pe.nt_headers().file_header().machine.get(LE);
    if machine != pe::IMAGE_FILE_MACHINE_AMD64 {
        return Err(LoadError::Unsupported(format!("PE machine={machine:#x} (A2 supports x86-64)")));
    }
    let language_id = "x86:LE:64:default";
    let compiler_spec_id = "clangwindows"; // Ghidra's default cspec for this corpus

    let mut spaces = SpaceManager::standard();
    let ram = spaces.add("ram", SpaceKind::Processor, 8, 1);
    let mut memory = Memory::new();

    // Headers block (Ghidra getVirtualSize, capped at file length).
    let mut hdr_size = OPTIONAL64_HEADER_SIZE + FILE_HEADER_SIZE + 4 + e_lfanew;
    if size_of_headers > hdr_size {
        hdr_size = size_of_headers;
    }
    hdr_size = hdr_size.min(data.len() as u64);
    if hdr_size > 0 {
        let bytes = data.get(0..hdr_size as usize).map(|s| s.to_vec());
        memory.add_block("Headers", Address::new(ram, image_base), hdr_size, true, false, false, bytes);
    }

    // Section blocks.
    let sections = pe.section_table();
    for (i, section) in sections.iter().enumerate() {
        let va = u64::from(section.virtual_address.get(LE));
        let vsize = u64::from(section.virtual_size.get(LE));
        let raw_size = u64::from(section.size_of_raw_data.get(LE));
        let raw_ptr = section.pointer_to_raw_data.get(LE) as usize;
        let chars = section.characteristics.get(LE);

        // Ghidra's block spans the larger of the virtual extent and the (file-aligned)
        // raw data: initialized raw bytes joined with uninitialized padding up to the
        // virtual size, but never shorter than the raw data on disk.
        let block_size = vsize.max(raw_size);
        if block_size == 0 {
            continue;
        }
        // Short names live in the raw 8-byte field; long `/NNN` names (string-table
        // indirection) are not used by this corpus.
        let name = std::str::from_utf8(section.raw_name())
            .ok()
            .map(|n| n.trim_end_matches('\0').to_string())
            .filter(|n| !n.is_empty())
            .unwrap_or_else(|| format!("SECTION.{i}"));

        let read = chars & pe::IMAGE_SCN_MEM_READ != 0;
        let write = chars & pe::IMAGE_SCN_MEM_WRITE != 0;
        let execute = chars & pe::IMAGE_SCN_MEM_EXECUTE != 0;
        // Initialized bytes from the file (up to min(raw_size, block_size)); None if the
        // section has no raw data.
        let bytes = if raw_size != 0 && raw_ptr != 0 {
            let n = raw_size.min(block_size) as usize;
            data.get(raw_ptr..raw_ptr + n).map(|init| {
                let mut v = init.to_vec();
                v.resize(block_size as usize, 0); // pad uninit tail to virtual size
                v
            })
        } else {
            None
        };
        memory.add_block(&name, Address::new(ram, image_base + va), block_size, read, write, execute, bytes);
    }

    let mut program = Program::new(
        spaces,
        ram,
        language_id,
        compiler_spec_id,
        Address::new(ram, image_base),
        false,
        64,
    );
    program.memory = memory;
    recover_pe(&pe, image_base, ram, &mut program);
    Ok(program)
}

/// Recover functions, the entry point, and symbols from PE data directories — a port of
/// the slices of Ghidra's `PeLoader` that run during load (`datadir.markup` +
/// `processEntryPoints`):
///
/// - **entry point** (`AddressOfEntryPoint`) → an `entry` function + symbol + external
///   entry point (created first, so it predates and names the `.pdata` function there);
/// - **`.pdata`** (EXCEPTION directory, `ImageRuntimeFunctionEntries_X86`) → a `FUN_<addr>`
///   function + symbol at `ImageBase+BeginAddress` for each non-chained RUNTIME_FUNCTION;
/// - **`_tls_index`** (TLS directory `AddressOfIndex`) → a `Label`.
fn recover_pe(pe: &PeFile64, image_base: u64, ram: SpaceId, program: &mut Program) {
    let oh = pe.nt_headers().optional_header();
    let dirs = pe.data_directories();

    let entry_rva = u64::from(oh.address_of_entry_point());
    if entry_rva != 0 {
        let eaddr = Address::new(ram, image_base + entry_rva);
        program.function_manager.create_function(eaddr, "entry", AddressSet::new());
        program.symbol_table.add_with_primary(eaddr, "entry", SymbolType::Function, true);
        program.entry_points.push(eaddr);
    }

    if let Some(dir) = dirs.get(pe::IMAGE_DIRECTORY_ENTRY_EXCEPTION) {
        let base = image_base + u64::from(dir.virtual_address.get(LE));
        let count = u64::from(dir.size.get(LE)) / 12; // RUNTIME_FUNCTION is 12 bytes
        for i in 0..count {
            let rec = base + i * 12;
            let (Some(begin), Some(unwind)) = (
                read_u32(&program.memory, Address::new(ram, rec)),
                read_u32(&program.memory, Address::new(ram, rec + 8)),
            ) else {
                continue;
            };
            if begin == 0 {
                continue;
            }
            // Skip chained entries (UNW_FLAG_CHAININFO = 0x4 in the unwind-info flags,
            // which are bits [3..8) of the first byte): their function is the chain head's.
            let chained = program
                .memory
                .byte_at(Address::new(ram, image_base + u64::from(unwind)))
                .is_some_and(|b| (b >> 3) & 0x4 != 0);
            if chained {
                continue;
            }
            let faddr = Address::new(ram, image_base + u64::from(begin));
            let name = format!("FUN_{:08x}", faddr.offset);
            program.function_manager.create_function(faddr, &name, AddressSet::new());
            // Ghidra's default `FUN_` symbol is only added when nothing is named there yet
            // (so the entry function keeps its `entry` name).
            if !program.symbol_table.has_symbol_at(faddr) {
                program.symbol_table.add_with_primary(faddr, &name, SymbolType::Function, true);
            }
        }
    }

    if let Some(dir) = dirs.get(pe::IMAGE_DIRECTORY_ENTRY_TLS) {
        let va = u64::from(dir.virtual_address.get(LE));
        if va != 0 {
            // IMAGE_TLS_DIRECTORY64.AddressOfIndex (a VA) is at offset 16.
            if let Some(idx) = read_u64(&program.memory, Address::new(ram, image_base + va + 16)) {
                if idx != 0 {
                    program.symbol_table.add_symbol(Address::new(ram, idx), "_tls_index", SymbolType::Label);
                }
            }
        }
    }
}

fn read_u32(memory: &Memory, addr: Address) -> Option<u32> {
    let mut bytes = [0u8; 4];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = memory.byte_at(Address::new(addr.space, addr.offset + i as u64))?;
    }
    Some(u32::from_le_bytes(bytes))
}

fn read_u64(memory: &Memory, addr: Address) -> Option<u64> {
    let mut bytes = [0u8; 8];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = memory.byte_at(Address::new(addr.space, addr.offset + i as u64))?;
    }
    Some(u64::from_le_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// cnv.exe is a user-provided PE (not committed); skip if absent.
    fn cnv() -> Option<Vec<u8>> {
        std::fs::read("/home/jd/cnv.exe").ok()
    }

    #[test]
    fn cnv_memory_map_matches_loader_golden() {
        let Some(data) = cnv() else {
            eprintln!("skip: /home/jd/cnv.exe not present");
            return;
        };
        let prog = load_pe(&data).expect("load cnv.exe");
        let snap = prog.snapshot();
        assert_eq!(snap.base, 0x1_4000_0000);
        assert_eq!(snap.compiler, "clangwindows");
        let golden = crate::analysis::snapshot::parse(
            &std::fs::read_to_string(crate::paths::analysis_goldens_dir().join("cnv.loaded.snapshot"))
                .unwrap(),
        );
        assert_eq!(snap.blocks, golden.blocks, "cnv PE memory map mismatch");
        // loader detail: .pdata functions + entry + _tls_index
        let summarize = |a: usize, b: usize, what: &str| {
            if a != b {
                eprintln!("cnv {what}: produced {a}, golden {b}");
            }
        };
        summarize(snap.functions.len(), golden.functions.len(), "functions");
        summarize(snap.entries.len(), golden.entries.len(), "entries");
        summarize(snap.symbols.len(), golden.symbols.len(), "symbols");
        assert_eq!(snap.functions, golden.functions, "cnv PE functions mismatch");
        assert_eq!(snap.entries, golden.entries, "cnv PE entry points mismatch");
        assert_eq!(snap.symbols, golden.symbols, "cnv PE symbols mismatch");
    }
}
