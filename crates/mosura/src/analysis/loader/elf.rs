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
//! Arch scope: ELF for x86-64, AArch64, RISC-V (little-endian, 64-bit) and m68k
//! (**big-endian, 32-bit**). The ELF container markup (`ElfN_Ehdr`/`Phdr`/`Sym`/`Rela`/…)
//! is arch-neutral in structure but class/endian-parameterized in geometry: the loader
//! is generic over the `object` crate's [`FileHeader`] (32- or 64-bit) and threads the
//! file's endianness through every raw-byte read (header/phdr field offsets, note
//! parsing, `.dynamic`/`.gnu.hash`). The `e_machine → (language id, compiler-spec id)`
//! map distinguishes the CPUs. See `docs/multi-arch-plan.md`.

use std::collections::BTreeSet;

use object::elf;
use object::read::elf::{ElfFile, FileHeader, ProgramHeader, SectionHeader};
use object::{
    Endianness, FileKind, Object, ObjectSection, ObjectSymbol, ObjectSymbolTable,
    RelocationTarget, SectionFlags, SymbolKind,
};

use crate::analysis::program::{AddressSet, Memory, Program, RefType, SymbolType};
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

/// ELF class + endianness geometry — the only things that differ between an `Elf32` and
/// `Elf64` container. Ghidra reads the same fields from each; only their byte offsets,
/// struct sizes, and the endianness of the raw reads change. Derived once per load from
/// the file header (`FileHeader::is_type_64`) and `elf.endian()`.
#[derive(Clone, Copy)]
struct Geom {
    is64: bool,
    endian: Endianness,
}

impl Geom {
    fn big_endian(&self) -> bool {
        matches!(self.endian, Endianness::Big)
    }
    /// Pointer / word size (`getDefaultPointerSize`): 8 for ELF64, 4 for ELF32.
    fn ptr_len(&self) -> u64 {
        if self.is64 { 8 } else { 4 }
    }
    /// `ElfN_Ehdr` size: 64 (Elf64) / 52 (Elf32).
    fn ehdr_len(&self) -> u32 {
        if self.is64 { 64 } else { 52 }
    }
    /// `ElfN_Phdr` size: 56 (Elf64) / 32 (Elf32).
    fn phdr_len(&self) -> u64 {
        if self.is64 { 56 } else { 32 }
    }
    /// `ElfN_Sym` size: 24 (Elf64) / 16 (Elf32).
    fn sym_len(&self) -> u64 {
        if self.is64 { 24 } else { 16 }
    }
    /// `ElfN_Rela` size: 24 (Elf64) / 12 (Elf32).
    fn rela_len(&self) -> u64 {
        if self.is64 { 24 } else { 12 }
    }
    /// `ElfN_Dyn` entry size: 16 (Elf64) / 8 (Elf32).
    fn dyn_len(&self) -> usize {
        if self.is64 { 16 } else { 8 }
    }
    /// Offset of `e_phoff` within `ElfN_Ehdr`: 0x20 (Elf64) / 0x1c (Elf32). `e_entry`
    /// precedes it at 0x18 in both.
    fn e_phoff_field(&self) -> u64 {
        if self.is64 { 0x20 } else { 0x1c }
    }
    /// Offset of `p_vaddr` within `ElfN_Phdr`: 0x10 (Elf64) / 0x08 (Elf32).
    fn p_vaddr_field(&self) -> u64 {
        if self.is64 { 0x10 } else { 0x08 }
    }
    /// Struct-name prefix Ghidra uses for the container markup: `Elf64` / `Elf32`.
    fn struct_prefix(&self) -> &'static str {
        if self.is64 { "Elf64" } else { "Elf32" }
    }
    /// Read a 32-bit value with the file's endianness.
    fn u32(&self, b: &[u8]) -> u32 {
        let a: [u8; 4] = b[0..4].try_into().unwrap();
        if self.big_endian() { u32::from_be_bytes(a) } else { u32::from_le_bytes(a) }
    }
    /// Read a 64-bit value with the file's endianness.
    fn u64(&self, b: &[u8]) -> u64 {
        let a: [u8; 8] = b[0..8].try_into().unwrap();
        if self.big_endian() { u64::from_be_bytes(a) } else { u64::from_le_bytes(a) }
    }
    /// Read one pointer-sized word (a `.dynamic`/array slot) with the file's endianness.
    fn uword(&self, b: &[u8]) -> u64 {
        if self.is64 { self.u64(b) } else { u64::from(self.u32(b)) }
    }
}

/// Parse an ELF image and build the [`Program`] memory map (A2). Dispatches on the ELF
/// class (32- vs 64-bit) into the generic [`load_elf_inner`]; both classes share every
/// step, parameterized by [`Geom`] geometry and the file's endianness.
pub fn load_elf(data: &[u8]) -> Result<Program, LoadError> {
    match FileKind::parse(data) {
        Ok(FileKind::Elf32) => load_elf_inner::<elf::FileHeader32<Endianness>>(data),
        Ok(FileKind::Elf64) => load_elf_inner::<elf::FileHeader64<Endianness>>(data),
        Ok(other) => Err(LoadError::Unsupported(format!("not an ELF file: {other:?}"))),
        Err(e) => Err(LoadError::Parse(e)),
    }
}

fn load_elf_inner<H>(data: &[u8]) -> Result<Program, LoadError>
where
    H: FileHeader<Endian = Endianness>,
{
    let elf = ElfFile::<H>::parse(data)?;
    let endian = elf.endian();
    let header = elf.elf_header();
    let geom = Geom { is64: header.is_type_64(), endian };

    // --- language / compiler (e_machine → Ghidra language + compiler-spec id) ---
    // The compiler-spec id is the one Ghidra's per-arch `.opinion` declares for an ELF
    // (`compilerSpecID=...`) and `.ldefs` resolves: x86-64 → "gcc", AArch64 → "default",
    // RISC-V → "gcc", 68k → "default". 68k maps to the **Coldfire** variant, not "default":
    // 68000.opinion's ELF constraint (`primary="4"` = EM_68K, `endian="big" size="32"`,
    // `compilerSpecID="default"`) specifies no processor *variant*, so all four 68000:BE:32
    // languages match. Ghidra collects them into a `HashSet<QueryResult>`
    // (QueryOpinionService.java) and — with no sort, and `QueryResult` not `Comparable` —
    // `ElfLoader.findSupportedLoadSpecs` takes them in a stable iteration order that lands on
    // `68000:BE:32:Coldfire` (confirmed empirically against analyzeHeadless across repeated
    // runs; the selection is *not* alphabetical). This variant label is **output-neutral**:
    // real `m68k-linux-gnu` code stays in the integer subset Coldfire and the golden's
    // `default`(=68040) model decode identically, proven byte-for-byte across the ground-truth
    // corpus by `coverage_68k::m68k_coldfire_matches_default_variant`. The big-endian/32-bit
    // read paths below are class/endian-parameterized.
    let machine = header.e_machine(endian);
    let big_endian = geom.big_endian();
    let arch = match (machine, big_endian, geom.is64) {
        (elf::EM_X86_64, false, true) => Some(("x86:LE:64:default", "gcc")),
        // 32-bit x86 ELF (EM_386). Ghidra's x86 ELF opinion resolves EM_386 (little, 32-bit)
        // to `x86:LE:32:default`; the generic GNU secondary gives the "gcc" compiler spec. Used
        // by the ground-truth corpus for the Open Watcom `wcc386 -bt=linux` column (a standard
        // ELF32 i386 — the Watcom-ness lives in the code/runtime, not the container/e_machine).
        (elf::EM_386, false, false) => Some(("x86:LE:32:default", "gcc")),
        (elf::EM_AARCH64, false, true) => Some(("AARCH64:LE:64:v8A", "default")),
        (elf::EM_RISCV, false, true) => Some(("RISCV:LE:64:default", "gcc")),
        (elf::EM_68K, true, false) => Some(("68000:BE:32:Coldfire", "default")),
        _ => None,
    };
    let Some((language_id, compiler_spec_id)) = arch else {
        return Err(LoadError::Unsupported(format!(
            "e_machine={machine} big_endian={big_endian} is64={} \
             (supported: x86 LE 32/64-bit, AArch64/RISC-V LE 64-bit, m68k BE 32-bit)",
            geom.is64
        )));
    };
    let addr_size_bits = if geom.is64 { 64 } else { 32 };

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
        let vaddr: u64 = ph.p_vaddr(endian).into();
        loads.push((i, vaddr, ph.p_filesz(endian).into(), ph.p_offset(endian).into(), ph.p_flags(endian)));
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

    let mut program =
        Program::new(spaces, ram, language_id, compiler_spec_id, image_base, big_endian, addr_size_bits);
    program.memory = memory;
    recover_symbols(&elf, geom, ram, &externals, ext_start, &mut program);
    markup_elf_structures(&elf, geom, ram, &mut program);
    Ok(program)
}

/// Mark up the ELF header + program-header table with the DATA references Ghidra's loader
/// emits (`ElfProgramBuilder.markupElfHeader`/`markupProgramHeaders`): `e_entry` → entry,
/// `e_phoff` → the program-header table, and each loaded segment's `p_vaddr` → its load
/// address. The header sits at the image base (where file offset 0 loads).
fn markup_elf_structures<H>(elf: &ElfFile<H>, geom: Geom, ram: SpaceId, program: &mut Program)
where
    H: FileHeader<Endian = Endianness>,
{
    let endian = elf.endian();
    let header = elf.elf_header();
    let base = program.image_base.offset;
    let mapped = |program: &Program, off: u64| program.memory.contains(Address::new(ram, off));
    let data_ref = |program: &mut Program, from: u64, to: u64| {
        program.reference_manager.add(Address::new(ram, from), Address::new(ram, to), RefType::Data, -1);
    };

    // ElfN_Ehdr: e_entry @ 0x18 in both classes; e_phoff @ 0x20 (Elf64) / 0x1c (Elf32).
    let e_entry: u64 = header.e_entry(endian).into();
    if e_entry != 0 && mapped(program, e_entry) {
        data_ref(program, base + 0x18, e_entry);
    }
    let e_phoff: u64 = header.e_phoff(endian).into();
    let phentsize = u64::from(header.e_phentsize(endian));
    let phdr_vaddr = base + e_phoff; // file offset e_phoff loads at base + e_phoff
    if e_phoff != 0 && mapped(program, phdr_vaddr) {
        data_ref(program, base + geom.e_phoff_field(), phdr_vaddr);
    }

    // Each program header's p_vaddr (@ 0x10 in Elf64_Phdr / 0x08 in Elf32_Phdr) → its load
    // address. Skip PT_NULL and offset-0 segments (the latter is the file-start LOAD —
    // Ghidra's `p_offset == 0` skip), and segments whose target isn't loaded.
    for (i, ph) in elf.elf_program_headers().iter().enumerate() {
        if ph.p_type(endian) == elf::PT_NULL || ph.p_offset(endian).into() == 0 {
            continue;
        }
        let pvaddr: u64 = ph.p_vaddr(endian).into();
        if pvaddr != 0 && mapped(program, pvaddr) {
            data_ref(program, phdr_vaddr + i as u64 * phentsize + geom.p_vaddr_field(), pvaddr);
        }
    }

    // Defined-data markup (Ghidra `ElfProgramBuilder.markupElfHeader`/`markupProgramHeaders`):
    // create the `ElfN_Ehdr` struct at the image base and the `ElfN_Phdr[e_phnum]` array at
    // `e_phoff`, at their loaded addresses, only when the structure lies in loaded memory
    // (Ghidra's `headerAddr` reachability check). The datatype names + lengths are Ghidra's
    // fixed structures: Ehdr = 64 (Elf64) / 52 (Elf32) bytes, Phdr = 56 / 32 bytes each.
    let prefix = geom.struct_prefix();
    if mapped(program, base) {
        program.defined_data.push((Address::new(ram, base), format!("{prefix}_Ehdr"), geom.ehdr_len()));
    }
    let e_phnum = u64::from(header.e_phnum(endian));
    if e_phoff != 0 && e_phnum != 0 && mapped(program, phdr_vaddr) {
        let len = (e_phnum * geom.phdr_len()) as u32;
        program
            .defined_data
            .push((Address::new(ram, phdr_vaddr), format!("{prefix}_Phdr[{e_phnum}]"), len));
    }

    // Section-table defined-data markup (Ghidra `ElfProgramBuilder` symbol/relocation-table
    // markup): a symbol table (`SHT_SYMTAB`/`SHT_DYNSYM`) → an `ElfN_Sym[n]` array, a RELA
    // relocation table (`SHT_RELA`) → an `ElfN_Rela[n]` array, at the section's loaded
    // `sh_addr` (driven by `sh_type`, as Ghidra does — not section names). Sym = 24 (Elf64) /
    // 16 (Elf32) bytes; Rela = 24 / 12 bytes.
    for section in elf.sections() {
        let sh = section.elf_section_header();
        let sh_type = sh.sh_type(endian);
        let sh_addr: u64 = sh.sh_addr(endian).into();
        let sh_size: u64 = sh.sh_size(endian).into();
        if sh_addr == 0 || sh_size == 0 || !mapped(program, sh_addr) {
            continue;
        }
        let unit = match sh_type {
            elf::SHT_SYMTAB | elf::SHT_DYNSYM => {
                Some((format!("{prefix}_Sym[{}]", sh_size / geom.sym_len()), sh_size as u32))
            }
            elf::SHT_RELA => {
                Some((format!("{prefix}_Rela[{}]", sh_size / geom.rela_len()), sh_size as u32))
            }
            _ => None,
        };
        if let Some((ty, len)) = unit {
            program.defined_data.push((Address::new(ram, sh_addr), ty, len));
        }
    }

    // .dynamic table (Ghidra `ElfProgramBuilder.markupDynamicTable` → `createData(addr,
    // dynamicTable.toDataType())`): an `ElfN_Dyn[n]` array at the table's load address.
    // `n` is the entry count `ElfDynamicTable` parses — it reads entries until and
    // **including** the first `DT_NULL` (tag == 0) and stops — so it does NOT span the whole
    // section (trailing zero padding is left undefined). `ElfN_Dyn` = 16 (Elf64) / 8 (Elf32)
    // bytes; the tag is the leading pointer-sized word.
    if let Some(dynamic) = elf.section_by_name(".dynamic") {
        let addr = dynamic.address();
        let dyn_len = geom.dyn_len();
        if let Ok(data) = dynamic.data() {
            if mapped(program, addr) && data.len() >= dyn_len {
                let mut n = 0u64;
                for e in data.chunks_exact(dyn_len) {
                    n += 1;
                    if geom.uword(e) == 0 {
                        break; // DT_NULL terminates the table (inclusive — see ElfDynamicTable)
                    }
                }
                program
                    .defined_data
                    .push((Address::new(ram, addr), format!("{prefix}_Dyn[{n}]"), (n * dyn_len as u64) as u32));
            }
        }
    }

    // GOT / .got.plt pointer markup (Ghidra `ElfDefaultGotPltMarkup.processGOTSections` →
    // `processGOT`): every initialized memory block whose name begins with `.got` is filled
    // with `pointer` units — `createPointer` per `pointerSize`-byte slot across the block,
    // `while (gotSizeRemaining >= pointerSize)`. Pointer size = 8 (Elf64) / 4 (Elf32).
    let ptr_len = geom.ptr_len();
    let got_blocks: Vec<(u64, u64)> = program
        .memory
        .blocks()
        .filter(|b| b.name().starts_with(".got") && b.is_initialized())
        .map(|b| (b.start().offset, b.end().offset))
        .collect();
    for (start, end) in got_blocks {
        let size = end - start + 1;
        let mut off = 0;
        while off + ptr_len <= size {
            program.defined_data.push((Address::new(ram, start + off), "pointer".to_string(), ptr_len as u32));
            off += ptr_len;
        }
    }

    // .gnu.hash table (Ghidra `markupGnuHashTable`; located via `DT_GNU_HASH`, whose address is
    // the `.gnu.hash` section): 4 header `dword`s (nbucket, symbase, bloom_size, bloom_shift),
    // then a `qword[bloom_size]` bloom filter and a `dword[nbucket]` bucket array. The trailing
    // chain array is left undefined (Ghidra only comments it).
    if let Some(gh) = elf.section_by_name(".gnu.hash") {
        let addr = gh.address();
        if let Ok(data) = gh.data() {
            if data.len() >= 16 && mapped(program, addr) {
                let rd = |o: usize| u64::from(geom.u32(&data[o..o + 4]));
                let (nbucket, bloom_size) = (rd(0), rd(8));
                for i in 0..4u64 {
                    program.defined_data.push((Address::new(ram, addr + i * 4), "dword".to_string(), 4));
                }
                let bloom = addr + 16;
                program.defined_data.push((
                    Address::new(ram, bloom),
                    format!("qword[{bloom_size}]"),
                    (bloom_size * 8) as u32,
                ));
                let buckets = bloom + bloom_size * 8;
                program.defined_data.push((
                    Address::new(ram, buckets),
                    format!("dword[{nbucket}]"),
                    (nbucket * 4) as u32,
                ));
            }
        }
    }

    // .gnu.version (Ghidra `processGnuVersion`, `DT_VERSYM`): one `word` (Elf_Versym, 2 bytes)
    // per dynamic symbol — `maxCnt = min(tableBytes/2, dynsymCount)`.
    if let Some(gv) = elf.section_by_name(".gnu.version") {
        let addr = gv.address();
        let dynsym_count = elf.section_by_name(".dynsym").map_or(0, |s| s.size() / geom.sym_len());
        let count = (gv.size() / 2).min(dynsym_count);
        if count > 0 && mapped(program, addr) {
            for i in 0..count {
                program.defined_data.push((Address::new(ram, addr + i * 2), "word".to_string(), 2));
            }
        }
    }

    // .dynstr (Ghidra `markupStringTable`, `DT_STRTAB`): starting just past the leading null,
    // each null-terminated string → a `string-utf8` unit (length includes the terminator),
    // laid back-to-back across the table.
    if let Some(ds) = elf.section_by_name(".dynstr") {
        let addr = ds.address();
        if let Ok(data) = ds.data() {
            if mapped(program, addr) && data.len() > 1 {
                let mut off = 1usize; // Ghidra skips the leading null (`address.addNoWrap(1)`)
                while off < data.len() {
                    let start = off;
                    while off < data.len() && data[off] != 0 {
                        off += 1;
                    }
                    if off < data.len() {
                        off += 1; // include the terminator
                    }
                    program.defined_data.push((
                        Address::new(ram, addr + start as u64),
                        "string-utf8".to_string(),
                        (off - start) as u32,
                    ));
                }
            }
        }
    }

    // .interp (Ghidra `markupInterpreter`, `PT_INTERP`): the program interpreter path as a
    // single `TerminatedCString` (auto-length to the null terminator).
    if let Some(interp) = elf.section_by_name(".interp") {
        let addr = interp.address();
        if let Ok(data) = interp.data() {
            if mapped(program, addr) && !data.is_empty() {
                let len = data.iter().position(|&b| b == 0).map_or(data.len(), |p| p + 1);
                program.defined_data.push((
                    Address::new(ram, addr),
                    "TerminatedCString".to_string(),
                    len as u32,
                ));
            }
        }
    }

    markup_elf_notes(elf, geom, ram, program);

    // Undefined data for sized OBJECT symbols (Ghidra `ElfProgramBuilder.processSymbols` builds
    // a `dataAllocationMap` of `address -> size` for every `elfSymbol.isObject()` (STT_OBJECT)
    // with `0 < size < INT_MAX` in mapped memory, then `allocateUndefinedSymbolData` does
    // `listing.createData(addr, Undefined.getUndefinedDataType(size))` — `undefined<size>` for
    // 1..=8, `undefined1[size]` for >8). `createData` throws `CodeUnitInsertionException` on a
    // conflict (caught + ignored); and later structured markup (e.g. the GNU notes, which use
    // `ClearDataMode.CLEAR_ALL_UNDEFINED_CONFLICT_DATA`) clears+overrides any undefined unit it
    // collides with. We reproduce that *net* defined-data state by running this last and
    // skipping any symbol whose range overlaps an already-defined unit (so e.g. `__abi_tag`
    // yields to `NoteAbiTag`).
    markup_undefined_symbol_data(elf, ram, program);
}

/// Port of Ghidra `ElfProgramBuilder.processSymbols` (`dataAllocationMap`) +
/// `allocateUndefinedSymbolData`: one `undefined<size>` unit per sized STT_OBJECT symbol,
/// from both the `.symtab` (`Object::symbols`) and `.dynamic` (`Object::dynamic_symbols`)
/// tables, skipping addresses already covered by structured markup. Runs after all other
/// markup so the conflict skip mirrors Ghidra's clear-and-override net result (see caller).
fn markup_undefined_symbol_data<H>(elf: &ElfFile<H>, ram: SpaceId, program: &mut Program)
where
    H: FileHeader<Endian = Endianness>,
{
    // address -> size, deduped across both symbol tables (Ghidra's shared HashMap).
    let mut alloc: std::collections::BTreeMap<u64, u64> = std::collections::BTreeMap::new();
    let mut collect = |syms: &mut dyn Iterator<Item = (SymbolKind, u64, u64)>| {
        for (kind, addr, size) in syms {
            // `elfSymbol.isObject()` == STT_OBJECT, surfaced by the `object` crate as
            // `SymbolKind::Data`; size must be `0 < size < INT_MAX` and land in mapped memory.
            if kind != SymbolKind::Data || size == 0 || size >= i32::MAX as u64 {
                continue;
            }
            if program.memory.contains(Address::new(ram, addr)) {
                alloc.insert(addr, size);
            }
        }
    };
    collect(&mut elf.symbols().map(|s| (s.kind(), s.address(), s.size())));
    collect(&mut elf.dynamic_symbols().map(|s| (s.kind(), s.address(), s.size())));

    for (addr, size) in alloc {
        // Skip if any already-defined unit overlaps `[addr, addr+size)` (the
        // `CodeUnitInsertionException` / clear-override net state, see caller).
        let conflict = program.defined_data.iter().any(|(da, _, dl)| {
            da.space == ram && addr < da.offset + u64::from(*dl) && da.offset < addr + size
        });
        if conflict {
            continue;
        }
        let name = if size <= 8 {
            format!("undefined{size}") // Undefined1..8DataType.getName()
        } else {
            format!("undefined1[{size}]") // ArrayDataType(Undefined1, size)
        };
        program.defined_data.push((Address::new(ram, addr), name, size as u32));
    }
}

/// ELF note-section markup — a port of Ghidra `StandardElfInfoProducer.markupElfInfo`
/// (`Ghidra/Features/Base/.../elf/info/StandardElfInfoProducer.java`), which iterates the
/// known note sections and, via `ElfInfoItem.markupElfInfoItemSection`, reads each note
/// (`ElfNote.read`) and marks it up at the section start. Each note's defined-data struct
/// name + length matches Ghidra's `ElfNote.createNoteStructure` / the subclass
/// `toStructure`/`markupProgram`:
///   * `.note.gnu.property` → `NoteGnuProperty_<padNameLen>` header + a
///     `NoteGnuPropertyElement_<prDatasz>` per property element (`NoteGnuProperty.java`),
///   * `.note.gnu.build-id` → `GnuBuildId` (`NoteGnuBuildId.java`),
///   * `.note.ABI-tag` → `NoteAbiTag` (`NoteAbiTag.java`).
/// `markupPtNoteSegments` (the PT_NOTE fallback) re-marks only *undefined* note addresses,
/// so on these binaries (each note is its own named section) it is a no-op and is omitted.
fn markup_elf_notes<H>(elf: &ElfFile<H>, geom: Geom, ram: SpaceId, program: &mut Program)
where
    H: FileHeader<Endian = Endianness>,
{
    // `program.getDefaultPointerSize()` for the property-element inter-element alignment
    // (`readNextNotePropertyElement` align(intSize)): 8 (Elf64) / 4 (Elf32).
    let ptr_size: u64 = geom.ptr_len();
    let mapped = |program: &Program, off: u64| program.memory.contains(Address::new(ram, off));

    // `ElfNote.read`: parse the generic note header (DWORD namesz, DWORD descsz, DWORD type),
    // the `namesz`-byte name (ascii up to NUL), then `nameLen += align(4)` (pad the name field
    // up to a 4-byte boundary — the header is already 4-aligned), then the `descsz`-byte desc
    // blob. The header DWORDs are read with the file's endianness. Returns `(padded_name_len,
    // name, desc_len, desc_offset_in_section)`, or `None` (the IOException paths — bad/short
    // data) so no spurious unit is emitted.
    let parse_note = |data: &[u8]| -> Option<(u32, String, u32, usize)> {
        if data.len() < 12 {
            return None;
        }
        let namesz = geom.u32(&data[0..4]);
        let descsz = geom.u32(&data[4..8]);
        // data[8..12] = vendorType (unused for markup geometry).
        let name_start = 12usize;
        let name_end = name_start.checked_add(namesz as usize)?;
        if name_end > data.len() {
            return None;
        }
        let name_bytes = &data[name_start..name_end];
        let nul = name_bytes.iter().position(|&b| b == 0).unwrap_or(name_bytes.len());
        let name = String::from_utf8_lossy(&name_bytes[..nul]).into_owned();
        let pad = (4 - (namesz % 4)) % 4; // reader.align(4) from offset 12 + namesz
        let name_len = namesz + pad;
        let desc_off = name_start.checked_add(name_len as usize)?;
        if desc_off.checked_add(descsz as usize)? > data.len() {
            return None; // readNextByteArray would overrun — bail
        }
        Some((name_len, name, descsz, desc_off))
    };

    // .note.gnu.property (NoteGnuProperty.markupProgram): the `NoteGnuProperty_<nameLen>`
    // header struct (`createNoteStructure(..., nameLen, 0)` = 12 + nameLen, no desc field)
    // followed by one `NoteGnuPropertyElement_<prDatasz>` struct per property element
    // (`getElementDataType` = DWORD prType + DWORD prDatasz + BYTE[prDatasz] = 8 + prDatasz).
    // The element structs are laid back-to-back from the header's end (markupProgram:
    // `address = elementData.getMaxAddress().next()`), while the element *list* is parsed from
    // the desc blob advancing `setPointerIndex(dataStart + prDatasz); align(intSize)`.
    if let Some(sec) = elf.section_by_name(".note.gnu.property") {
        let addr = sec.address();
        if mapped(program, addr) {
            if let Ok(data) = sec.data() {
                if let Some((name_len, _name, desc_len, desc_off)) = parse_note(data) {
                    let hdr_len = 12 + name_len;
                    program.defined_data.push((
                        Address::new(ram, addr),
                        format!("NoteGnuProperty_{name_len}"),
                        hdr_len,
                    ));
                    let desc = &data[desc_off..desc_off + desc_len as usize];
                    let mut elem_addr = addr + hdr_len as u64;
                    let mut p = 0usize; // desc-reader pointer (NoteGnuProperty.read)
                    while p + 8 <= desc.len() {
                        // prType @ p (4), prDatasz @ p+4 (4)
                        let pr_datasz = geom.u32(&desc[p + 4..p + 8]);
                        let elem_len = 8 + pr_datasz;
                        program.defined_data.push((
                            Address::new(ram, elem_addr),
                            format!("NoteGnuPropertyElement_{pr_datasz}"),
                            elem_len,
                        ));
                        elem_addr += elem_len as u64;
                        let data_start = p + 8;
                        let next = data_start + pr_datasz as usize;
                        p = align_up(next as u64, ptr_size) as usize;
                    }
                }
            }
        }
    }

    // .note.gnu.build-id (NoteGnuBuildId): guarded by `isGnu() && descLen != 0`. The
    // `GnuBuildId` struct = createNoteStructure(..., nameLen, 0) + BYTE[descLen]
    // = 12 + nameLen + descLen.
    if let Some(sec) = elf.section_by_name(".note.gnu.build-id") {
        let addr = sec.address();
        if mapped(program, addr) {
            if let Ok(data) = sec.data() {
                if let Some((name_len, name, desc_len, _)) = parse_note(data) {
                    if name == "GNU" && desc_len != 0 {
                        let len = 12 + name_len + desc_len;
                        program.defined_data.push((
                            Address::new(ram, addr),
                            "GnuBuildId".to_string(),
                            len,
                        ));
                    }
                }
            }
        }
    }

    // .note.ABI-tag (NoteAbiTag): guarded by `isGnu() && descLen >= MIN_ABI_TAB_LEN (0x10)`.
    // The `NoteAbiTag` struct = createNoteStructure(..., nameLen, 0) + DWORD abiType
    // + DWORD[3] requiredKernelVersion = 12 + nameLen + 4 + 12.
    if let Some(sec) = elf.section_by_name(".note.ABI-tag") {
        let addr = sec.address();
        if mapped(program, addr) {
            if let Ok(data) = sec.data() {
                if let Some((name_len, name, desc_len, _)) = parse_note(data) {
                    if name == "GNU" && desc_len >= 0x10 {
                        let len = 12 + name_len + 4 + 12;
                        program.defined_data.push((
                            Address::new(ram, addr),
                            "NoteAbiTag".to_string(),
                            len,
                        ));
                    }
                }
            }
        }
    }
}

/// Apply dynamic relocations that bind a GOT/PLT slot to an undefined (external) symbol —
/// a port of Ghidra's `ElfRelocationHandler` for the slot relocations (`R_X86_64_GLOB_DAT`,
/// `R_X86_64_JUMP_SLOT`): set the slot to the symbol's EXTERNAL-block address and record
/// the DATA reference Ghidra's loader emits. Relocations against non-external symbols (and
/// addend-only kinds like `R_X86_64_RELATIVE`) are left for the full relocation port.
fn apply_external_relocations<H>(
    elf: &ElfFile<H>,
    ram: SpaceId,
    externals: &[(String, SymbolKind)],
    ext_start: u64,
    program: &mut Program,
) where
    H: FileHeader<Endian = Endianness>,
{
    let slot_of: std::collections::HashMap<&str, u64> = externals
        .iter()
        .enumerate()
        .map(|(i, (name, _))| (name.as_str(), ext_start + i as u64 * 8))
        .collect();
    let (Some(dynsyms), Some(relocs)) = (elf.dynamic_symbol_table(), elf.dynamic_relocations())
    else {
        return;
    };
    for (offset, reloc) in relocs {
        let RelocationTarget::Symbol(idx) = reloc.target() else { continue };
        let Ok(sym) = dynsyms.symbol_by_index(idx) else { continue };
        let Ok(name) = sym.name() else { continue };
        let Some(&slot) = slot_of.get(name) else { continue };
        program.memory.write_u64(Address::new(ram, offset), slot);
        program.reference_manager.add(
            Address::new(ram, offset),
            Address::new(ram, slot),
            RefType::Data,
            -1,
        );
    }
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
fn recover_symbols<H>(
    elf: &ElfFile<H>,
    geom: Geom,
    ram: SpaceId,
    externals: &[(String, SymbolKind)],
    ext_start: Option<u64>,
    program: &mut Program,
) where
    H: FileHeader<Endian = Endianness>,
{
    let (dyn_addr, dyn_entries) = dynamic_entries(elf, geom);
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
        // Apply dynamic relocations against external symbols (Ghidra `ElfRelocationHandler`):
        // each GOT/PLT slot is pointed at its symbol's EXTERNAL-block address — patch the
        // slot value and create the DATA reference Ghidra's loader emits.
        apply_external_relocations(elf, ram, externals, start, program);
    }

    let machine = elf.elf_header().e_machine(elf.endian());
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
        // Per-arch ELF symbol filtering (Ghidra `ElfExtension.evaluateElfSymbol`): AArch64
        // drops the ARM mapping symbols, so they are not retained as program symbols.
        if is_dropped_elf_symbol(machine, name) {
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
    let ptr_len = geom.ptr_len();
    for (array_tag, size_tag) in [(25u64, 27u64), (32, 33), (26, 28)] {
        let (Some(base), Some(size)) = (dt_val(array_tag), dt_val(size_tag)) else { continue };
        let mut off = 0;
        while off + ptr_len <= size {
            // Each array element is laid down as a `pointer` data unit (Ghidra
            // `ElfProgramBuilder.createDynamicEntryPoints`: `createData(addr, dt)` with
            // `dt = PointerDataType` since non-prelinked binaries take the
            // `getImageBaseWordAdjustmentOffset() == 0` branch). `elementCount = size / ptrSize`.
            program.defined_data.push((Address::new(ram, base + off), "pointer".to_string(), ptr_len as u32));
            if let Some(target) = read_ptr(&program.memory, Address::new(ram, base + off), geom) {
                // Each array slot is a function pointer → a DATA reference (Ghidra's
                // pointer-array markup); an executable target is also an entry point.
                if target != 0 && program.memory.contains(Address::new(ram, target)) {
                    program.reference_manager.add(
                        Address::new(ram, base + off),
                        Address::new(ram, target),
                        RefType::Data,
                        -1,
                    );
                }
                if program.memory.block_at(Address::new(ram, target)).is_some_and(|b| b.is_execute()) {
                    entry_addrs.insert(target);
                }
            }
            off += ptr_len;
        }
    }

    // DT_PLTGOT's first slot holds &_DYNAMIC (the dynamic-linker convention) — a DATA
    // reference (Ghidra's GOT pointer markup).
    if let Some(gotplt) = dt_val(3) {
        if let Some(target) = read_ptr(&program.memory, Address::new(ram, gotplt), geom) {
            if target != 0 && program.memory.contains(Address::new(ram, target)) {
                program.reference_manager.add(
                    Address::new(ram, gotplt),
                    Address::new(ram, target),
                    RefType::Data,
                    -1,
                );
            }
        }
    }

    for a in entry_addrs {
        program.entry_points.push(Address::new(ram, a));
    }
}

/// Per-arch ELF symbol filtering — a port of Ghidra `ElfExtension.evaluateElfSymbol`
/// returning `null` (drop the symbol). Today only AArch64 (`AARCH64_ElfExtension`,
/// `e_machine == EM_AARCH64`) drops symbols: the ARM mapping symbols `$x`/`$x.*` (A64
/// code) and `$d`/`$d.*` (data) are *not* retained in the program ("do not retain … due
/// to potential function/thunk naming interference … excessive duplicate symbols"). The
/// base `evaluateElfSymbol` keeps every symbol, so other arches (x86-64) are unaffected.
fn is_dropped_elf_symbol(machine: u16, name: &str) -> bool {
    machine == elf::EM_AARCH64
        && (name == "$x" || name.starts_with("$x.") || name == "$d" || name.starts_with("$d."))
}

/// Read a pointer-sized value from initialized program memory at `addr`, with the
/// program's ELF class + endianness (a loaded function pointer / GOT slot). 8 bytes for
/// ELF64, 4 for ELF32.
fn read_ptr(memory: &Memory, addr: Address, geom: Geom) -> Option<u64> {
    let n = geom.ptr_len() as usize;
    let mut bytes = [0u8; 8];
    for (i, b) in bytes.iter_mut().take(n).enumerate() {
        *b = memory.byte_at(Address::new(addr.space, addr.offset + i as u64))?;
    }
    Some(geom.uword(&bytes))
}

/// Parse the `.dynamic` table: returns its load address and the `(tag, value)` entries
/// (up to `DT_NULL`). `ElfN_Dyn` entries are 16 (Elf64) / 8 (Elf32) bytes, two
/// pointer-sized words each, read with the file's endianness.
fn dynamic_entries<H>(elf: &ElfFile<H>, geom: Geom) -> (Option<u64>, Vec<(u64, u64)>)
where
    H: FileHeader<Endian = Endianness>,
{
    let Some(dynamic) = elf.section_by_name(".dynamic") else { return (None, Vec::new()) };
    let mut entries = Vec::new();
    let dyn_len = geom.dyn_len();
    let w = geom.ptr_len() as usize;
    if let Ok(data) = dynamic.data() {
        for e in data.chunks_exact(dyn_len) {
            let tag = geom.uword(&e[0..w]);
            let val = geom.uword(&e[w..2 * w]);
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
    for (i, &(tag, val)) in entries.iter().enumerate() {
        if val == 0 {
            continue;
        }
        if let Some(dt) = dt_address_name(tag) {
            program.symbol_table.add_with_primary(Address::new(ram, val), &format!("__{dt}"), SymbolType::Label, false);
            // DATA reference from the entry's address-valued `d_un` field (offset +8 in the
            // 16-byte Elf64_Dyn) to its target — Ghidra's `Elf64_Dyn` pointer-field markup.
            let field = addr + i as u64 * 16 + 8;
            program.reference_manager.add(Address::new(ram, field), Address::new(ram, val), RefType::Data, -1);
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

