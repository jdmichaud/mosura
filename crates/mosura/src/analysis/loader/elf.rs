//! ELF loader — a port of the *output* of Ghidra's `ElfProgramBuilder`
//! (`app/util/opinion/`): bytes of an ELF file → a [`Program`] with the same memory
//! map Ghidra lays down. The ELF container is decoded with the `object` crate; the
//! faithful part is the **block layout**, reproduced to match the analyzeHeadless
//! oracle (`goldens/analysis/*.snapshot`):
//!
//! - every allocated section (`SHF_ALLOC`, `sh_addr != 0`) becomes a named block;
//! - the parts of each `PT_LOAD` segment **not** covered by a section become
//!   `segment_<phdrIndex>.<n>` blocks (Ghidra `getSegmentName` + fragmentation;
//!   computed here via [`AddressSet::subtract`]);
//! - external (undefined dynamic) symbols get an artificial `EXTERNAL` block,
//!   placed after the image on a linkage-alignment boundary (Ghidra
//!   `allocateLinkageBlock`/`createExternalBlock`).
//!
//! A1/A2 scope: x86-64 little-endian ELF (the corpus). Other arches map their
//! language id later.

use std::collections::BTreeSet;

use object::elf;
use object::read::elf::{ElfFile64, FileHeader, ProgramHeader};
use object::{Endianness, Object, ObjectSection, ObjectSymbol, SectionFlags, SymbolKind};

use crate::analysis::program::{AddressSet, Memory, Program, SymbolType};
use crate::decompile::space::{Address, SpaceId, SpaceManager, SpaceKind};

/// Linkage-block alignment for the EXTERNAL block on x86-64 (Ghidra
/// `getLinkageBlockAlignment` → page size).
const LINKAGE_ALIGNMENT: u64 = 0x1000;

/// Ghidra `DEFAULT_DISCARDABLE_SEGMENT_SIZE` — a `segment_*` filler fragment that is
/// this small *and* entirely zero-filled is discarded (`isDiscardableFillerSegment`),
/// which drops inter-section alignment padding while keeping the ELF-header fragment.
const MAX_DISCARDABLE_SEGMENT_SIZE: u64 = 0xff;

#[derive(Debug)]
pub enum LoadError {
    Parse(object::Error),
    Unsupported(String),
}
impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LoadError::Parse(e) => write!(f, "elf parse: {e}"),
            LoadError::Unsupported(s) => write!(f, "unsupported: {s}"),
        }
    }
}
impl std::error::Error for LoadError {}
impl From<object::Error> for LoadError {
    fn from(e: object::Error) -> Self {
        LoadError::Parse(e)
    }
}

type Elf<'a> = ElfFile64<'a, Endianness>;

/// Parse an ELF image and build the [`Program`] memory map (A2).
pub fn load_elf(data: &[u8]) -> Result<Program, LoadError> {
    let elf = Elf::parse(data)?;
    let endian = elf.endian();
    let header = elf.elf_header();

    // --- language / compiler (x86-64 LE only for now) ---
    let machine = header.e_machine(endian);
    let big_endian = matches!(endian, Endianness::Big);
    if machine != elf::EM_X86_64 || big_endian {
        return Err(LoadError::Unsupported(format!(
            "e_machine={machine} big_endian={big_endian} (A2 supports x86-64 LE)"
        )));
    }
    let language_id = "x86:LE:64:default";
    let compiler_spec_id = "gcc";

    let mut spaces = SpaceManager::standard();
    let ram = spaces.add("ram", SpaceKind::Processor, 8, 1);

    // --- collect PT_LOAD segments (with phdr index) and allocated sections ---
    let phdrs = elf.elf_program_headers();
    let mut loads: Vec<(usize, u64, u64, u64, u32)> = Vec::new(); // (idx, vaddr, filesz, offset, flags)
    let mut image_base: Option<u64> = None;
    for (i, ph) in phdrs.iter().enumerate() {
        if ph.p_type(endian) != elf::PT_LOAD {
            continue;
        }
        let vaddr = ph.p_vaddr(endian);
        loads.push((i, vaddr, ph.p_filesz(endian), ph.p_offset(endian), ph.p_flags(endian)));
        image_base = Some(image_base.map_or(vaddr, |b| b.min(vaddr)));
    }
    let image_base = Address::new(ram, image_base.unwrap_or(0));

    let mut memory = Memory::new();
    let mut section_cover = AddressSet::new(); // union of allocated-section ranges

    // --- named blocks for allocated sections ---
    for section in elf.sections() {
        let sh_flags = match section.flags() {
            SectionFlags::Elf { sh_flags } => sh_flags,
            _ => 0,
        };
        let addr = section.address();
        if sh_flags & u64::from(elf::SHF_ALLOC) == 0 || addr == 0 {
            continue;
        }
        let size = section.size();
        if size == 0 {
            continue;
        }
        let name = section.name().unwrap_or("<noname>").to_string();
        let write = sh_flags & u64::from(elf::SHF_WRITE) != 0;
        let execute = sh_flags & u64::from(elf::SHF_EXECINSTR) != 0;
        // SHT_NOBITS (.bss) is uninitialized; everything else is file-backed.
        let bytes = if section.kind() == object::SectionKind::UninitializedData {
            None
        } else {
            section.data().ok().map(|d| d.to_vec())
        };
        memory.add_block(&name, Address::new(ram, addr), size, true, write, execute, bytes);
        section_cover.add_range(ram, addr, addr + size - 1);
    }

    // --- segment_<idx>.<n> blocks for PT_LOAD bytes not covered by a section ---
    // Ghidra prunes discardable filler fragments only when both section and program
    // headers are present.
    let prune_fillers = elf.sections().next().is_some() && !loads.is_empty();
    for &(idx, vaddr, filesz, offset, flags) in &loads {
        if filesz == 0 {
            continue;
        }
        let mut seg = AddressSet::new();
        seg.add_range(ram, vaddr, vaddr + filesz - 1);
        let leftover = seg.subtract(&section_cover);
        let read = flags & elf::PF_R != 0;
        let write = flags & elf::PF_W != 0;
        let execute = flags & elf::PF_X != 0;
        // Number fragments by their position within the segment (Ghidra numbers during
        // fragmentation, before discarding), then drop the discardable zero-fill ones.
        for (n, range) in leftover.ranges().enumerate() {
            let len = range.max - range.min + 1;
            let file_off = (offset + (range.min - vaddr)) as usize;
            let bytes = data.get(file_off..file_off + len as usize).map(|s| s.to_vec());
            let discardable = prune_fillers
                && len <= MAX_DISCARDABLE_SEGMENT_SIZE
                && bytes.as_deref().is_some_and(|b| b.iter().all(|&x| x == 0));
            if discardable {
                continue;
            }
            memory.add_block(
                &format!("segment_{idx}.{}", n + 1),
                Address::new(ram, range.min),
                len,
                read,
                write,
                execute,
                bytes,
            );
        }
    }

    // --- EXTERNAL block + its undefined-symbol slots ---
    // Undefined dynamic symbols (deduped by name, in table order) each take one
    // pointer-sized slot in an artificial EXTERNAL block placed after the image
    // (Ghidra `allocateExternalSymbol` / `createExternalBlock`).
    let mut externals: Vec<(String, SymbolKind)> = Vec::new();
    let mut seen_ext: std::collections::HashSet<String> = std::collections::HashSet::new();
    for s in elf.dynamic_symbols() {
        if !s.is_undefined() {
            continue;
        }
        let Ok(name) = s.name() else { continue };
        if name.is_empty() || matches!(s.kind(), SymbolKind::Section | SymbolKind::File) {
            continue;
        }
        if seen_ext.insert(name.to_string()) {
            externals.push((name.to_string(), s.kind()));
        }
    }
    let ext_start = if externals.is_empty() {
        None
    } else {
        let max_end = memory.blocks().map(|b| b.end().offset).max().unwrap_or(image_base.offset);
        let start = align_up(max_end + 1, LINKAGE_ALIGNMENT);
        memory.add_block("EXTERNAL", Address::new(ram, start), externals.len() as u64 * 8, true, true, false, None);
        Some(start)
    };

    let mut program = Program::new(spaces, ram, language_id, compiler_spec_id, image_base, false, 64);
    program.memory = memory;
    recover_symbols(&elf, ram, &externals, ext_start, &mut program);
    Ok(program)
}

/// Recover symbols, functions, and entry points — a port of Ghidra `ElfProgramBuilder`'s
/// symbol processing (`markupDynamicTable` + `processSymbolTables`/`evaluateElfSymbol`):
///
/// 1. dynamic-table markup first: `_DYNAMIC` + a `__DT_<NAME>` label at each
///    address-valued `.dynamic` entry (so they predate, and coexist with, symtab symbols);
/// 2. undefined `.dynsym` symbols → sequential `EXTERNAL`-block slots (fake-external:
///    `STT_FUNC` → a thunk `Function`, others → `Label`; never entry points);
/// 3. defined `.symtab` symbols → a `Symbol` (`STT_FUNC` → `Function`, else `Label`) with
///    Ghidra's `isPrimary` rule; `STT_FUNC` → a `Function`; `e_entry` + every global/weak
///    symbol's address → external entry points.
fn recover_symbols(
    elf: &Elf,
    ram: SpaceId,
    externals: &[(String, SymbolKind)],
    ext_start: Option<u64>,
    program: &mut Program,
) {
    let (dyn_addr, dyn_entries) = dynamic_entries(elf);
    markup_dynamic(ram, dyn_addr, &dyn_entries, program);

    if let Some(start) = ext_start {
        for (i, (name, kind)) in externals.iter().enumerate() {
            let addr = Address::new(ram, start + i as u64 * 8);
            if *kind == SymbolKind::Text {
                program.symbol_table.add_with_primary(addr, name, SymbolType::Function, true);
                program.function_manager.create_function(addr, name, AddressSet::new());
            } else {
                program.symbol_table.add_with_primary(addr, name, SymbolType::Label, true);
            }
        }
    }

    let mut entry_addrs: BTreeSet<u64> = BTreeSet::new();
    let e_entry = elf.entry();
    if e_entry != 0 {
        entry_addrs.insert(e_entry);
    }
    for sym in elf.symbols() {
        let Ok(name) = sym.name() else { continue };
        if name.is_empty() || sym.is_undefined() {
            continue;
        }
        let kind = sym.kind();
        if matches!(kind, SymbolKind::Section | SymbolKind::File) {
            continue;
        }
        let addr = Address::new(ram, sym.address());
        let (stype, is_func) = match kind {
            SymbolKind::Text => (SymbolType::Function, true),
            _ => (SymbolType::Label, false),
        };
        // Ghidra isPrimary: a function/object/sized symbol is primary; a versioned
        // (`@`) symbol never is; otherwise a global/weak symbol is primary only if no
        // symbol exists at the address yet.
        let mut is_primary = is_func || kind == SymbolKind::Data || sym.size() != 0;
        if name.contains('@') {
            is_primary = false;
        } else if !is_primary && sym.is_global() {
            is_primary = !program.symbol_table.has_symbol_at(addr);
        }
        program.symbol_table.add_with_primary(addr, name, stype, is_primary);
        if is_func {
            program.function_manager.create_function(addr, name, AddressSet::new());
        }
        if sym.is_global() {
            entry_addrs.insert(sym.address());
        }
    }

    // Init/fini/preinit-array targets are entry points too (Ghidra `createDynamicEntryPoints`):
    // each array is pointer-sized function addresses; an executable target is marked an entry.
    let dt_val = |t: u64| dyn_entries.iter().find(|(tag, _)| *tag == t).map(|(_, v)| *v);
    for (array_tag, size_tag) in [(25u64, 27u64), (32, 33), (26, 28)] {
        let (Some(base), Some(size)) = (dt_val(array_tag), dt_val(size_tag)) else { continue };
        let mut off = 0;
        while off + 8 <= size {
            if let Some(target) = read_u64(&program.memory, Address::new(ram, base + off)) {
                if program.memory.block_at(Address::new(ram, target)).is_some_and(|b| b.is_execute()) {
                    entry_addrs.insert(target);
                }
            }
            off += 8;
        }
    }

    for a in entry_addrs {
        program.entry_points.push(Address::new(ram, a));
    }
}

/// Read a little-endian `u64` from initialized program memory at `addr`.
fn read_u64(memory: &Memory, addr: Address) -> Option<u64> {
    let mut bytes = [0u8; 8];
    for (i, b) in bytes.iter_mut().enumerate() {
        *b = memory.byte_at(Address::new(addr.space, addr.offset + i as u64))?;
    }
    Some(u64::from_le_bytes(bytes))
}

/// Parse the `.dynamic` table: returns its load address and the `(tag, value)` entries
/// (up to `DT_NULL`).
fn dynamic_entries(elf: &Elf) -> (Option<u64>, Vec<(u64, u64)>) {
    let Some(dynamic) = elf.section_by_name(".dynamic") else { return (None, Vec::new()) };
    let mut entries = Vec::new();
    if let Ok(data) = dynamic.data() {
        for e in data.chunks_exact(16) {
            let tag = u64::from_le_bytes(e[0..8].try_into().unwrap());
            let val = u64::from_le_bytes(e[8..16].try_into().unwrap());
            if tag == 0 {
                break; // DT_NULL terminates the table
            }
            entries.push((tag, val));
        }
    }
    (Some(dynamic.address()), entries)
}

/// `_DYNAMIC` + `__DT_<NAME>` labels from the `.dynamic` table (Ghidra `markupDynamicTable`).
fn markup_dynamic(ram: SpaceId, dyn_addr: Option<u64>, entries: &[(u64, u64)], program: &mut Program) {
    let Some(addr) = dyn_addr else { return };
    program.symbol_table.add_with_primary(Address::new(ram, addr), "_DYNAMIC", SymbolType::Label, false);
    for &(tag, val) in entries {
        if val == 0 {
            continue;
        }
        if let Some(dt) = dt_address_name(tag) {
            program.symbol_table.add_with_primary(Address::new(ram, val), &format!("__{dt}"), SymbolType::Label, false);
        }
    }
}

/// ELF `DT_*` tags whose value is an address (Ghidra `ElfDynamicValueType.ADDRESS`),
/// mapped to the name Ghidra labels them with (`__<name>`).
fn dt_address_name(tag: u64) -> Option<&'static str> {
    Some(match tag {
        3 => "DT_PLTGOT",
        4 => "DT_HASH",
        5 => "DT_STRTAB",
        6 => "DT_SYMTAB",
        7 => "DT_RELA",
        12 => "DT_INIT",
        13 => "DT_FINI",
        17 => "DT_REL",
        23 => "DT_JMPREL",
        25 => "DT_INIT_ARRAY",
        26 => "DT_FINI_ARRAY",
        0x6fff_fef5 => "DT_GNU_HASH",
        0x6fff_fff0 => "DT_VERSYM",
        0x6fff_fffc => "DT_VERDEF",
        0x6fff_fffe => "DT_VERNEED",
        _ => return None,
    })
}

fn align_up(value: u64, alignment: u64) -> u64 {
    if alignment == 0 {
        return value;
    }
    value.div_ceil(alignment) * alignment
}

#[cfg(test)]
mod tests {
    use super::*;

    fn corpus(name: &str) -> Vec<u8> {
        let p = crate::paths::analysis_corpus_dir().join(format!("{name}.elf"));
        std::fs::read(&p).unwrap_or_else(|e| panic!("read {}: {e}", p.display()))
    }

    #[test]
    fn freestanding_memory_map_matches_golden() {
        let prog = load_elf(&corpus("freestanding")).expect("load freestanding");
        let snap = prog.snapshot();
        // header
        assert_eq!(snap.lang, "x86:LE:64:default");
        assert_eq!(snap.base, 0x0040_0000);
        // exact memory map vs the committed golden's blocks
        let golden = crate::analysis::snapshot::parse(
            &std::fs::read_to_string(crate::paths::analysis_goldens_dir().join("freestanding.snapshot"))
                .unwrap(),
        );
        assert_eq!(snap.blocks, golden.blocks, "freestanding memory map mismatch");
    }

    #[test]
    fn freestanding_symbols_and_entries_match_golden() {
        let prog = load_elf(&corpus("freestanding")).expect("load freestanding");
        let snap = prog.snapshot();
        let golden = crate::analysis::snapshot::parse(
            &std::fs::read_to_string(crate::paths::analysis_goldens_dir().join("freestanding.loaded.snapshot"))
                .unwrap(),
        );
        assert_eq!(snap.functions, golden.functions, "functions mismatch");
        assert_eq!(snap.symbols, golden.symbols, "symbols mismatch");
        assert_eq!(snap.entries, golden.entries, "entry points mismatch");
    }

    #[test]
    fn align_up_works() {
        assert_eq!(align_up(0x40_4020, 0x1000), 0x40_5000);
        assert_eq!(align_up(0x1000, 0x1000), 0x1000);
    }
}

