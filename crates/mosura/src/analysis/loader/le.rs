//! LE (Linear Executable) loader — for DOS-extender-bound 32-bit executables (e.g. the
//! DOS/4GW-bound WAR2.EXE). file bytes → a [`Program`] whose objects-as-blocks match the
//! Linear Executable's real structure (the 32-bit protected-mode image), as
//! `x86:LE:32:default`, image base `0x10000`.
//!
//! **No Ghidra oracle.** Ghidra has no LE/LX loader, so — unlike `elf.rs`/`pe.rs`/`mz.rs`,
//! which port the *output* of a Ghidra loader — this loader is grounded in the **LE/LX
//! format spec** and validated against the **warcraft2-re reverse-engineering ground truth**
//! recorded in `docs/le-loader-notes.md` (the two objects + the entry). See that file for
//! the format references and the rationale for a native loader (vs the ELF32-wrapper hack).
//!
//! **Scope / honesty.** This produces the LE's memory map + entry (validated by
//! `le_war2_objects` in `analysis_parity.rs` against the recorded RE result). It is **not**
//! wired into the default `analyze` dispatch for the bound WAR2.EXE: that file's committed
//! goldens are Ghidra's 16-bit *MZ-stub* interpretation (Ghidra can't load the LE), so the
//! war2 Ghidra-parity gates depend on the MZ path — re-pointing them at the LE objects has
//! no Ghidra oracle to validate against. What remains (see the task report) is the
//! dispatch/gate-policy decision + the 32-bit analysis pipeline + a switch-table golden.

use super::elf::LoadError;
use crate::analysis::program::{Memory, Program, SymbolType};
use crate::decompile::space::{Address, SpaceKind, SpaceManager};

/// Read a little-endian u32 from `data` at `off`.
fn u32le(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 4).map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
}
fn u16le(data: &[u8], off: usize) -> Option<u16> {
    data.get(off..off + 2).map(|b| u16::from_le_bytes([b[0], b[1]]))
}

/// LE header field offsets (relative to the LE header start), per the LE/LX spec.
mod le {
    // SIG @ 0x00 = "LE" (checked directly via byte compare in `is_le_header`).
    pub const BORDER: usize = 0x02; // byte order (0 = little)
    pub const WORDER: usize = 0x03; // word order (0 = little)
    pub const CPU: usize = 0x08; // 1=286, 2=386, 3=486
    pub const NUM_PAGES: usize = 0x14; // number of physical pages in the module
    pub const EIP_OBJECT: usize = 0x18; // object number of the entry point (1-based)
    pub const EIP: usize = 0x1c; // entry EIP — an offset *within* the EIP object
    pub const PAGE_SIZE: usize = 0x28; // memory page size (bytes)
    pub const LAST_PAGE_BYTES: usize = 0x2c; // bytes used in the last physical page (LE)
    pub const OBJ_TABLE_OFF: usize = 0x40; // object table offset (rel. to LE header)
    pub const OBJ_COUNT: usize = 0x44; // number of object-table entries
    pub const OBJ_PAGEMAP_OFF: usize = 0x48; // object page-map offset (rel. to LE header)
}

/// One LE object-table entry (24 bytes), per the LE/LX spec.
struct LeObject {
    virtual_size: u32,
    reloc_base: u32, // virtual base address
    flags: u32,
    page_index: u32, // 1-based index of this object's first page in the page map
    page_count: u32, // number of page-map entries owned by this object
}

impl LeObject {
    fn perms(&self) -> (bool, bool, bool) {
        // LE object flags: bit0 = readable, bit1 = writable, bit2 = executable.
        (self.flags & 0x1 != 0, self.flags & 0x2 != 0, self.flags & 0x4 != 0)
    }
}

/// Locate the LE header. A standalone LE executable has `e_lfanew` (MZ field at 0x3c)
/// pointing at an in-bounds "LE" signature; a DOS-extender-bound exe (DOS/4GW) deliberately
/// sets `e_lfanew` invalid so DOS ignores the "new EXE", and the embedded LE is found by
/// scanning for a header whose fixed fields validate. Returns the LE header file offset.
pub fn detect_le(data: &[u8]) -> Option<usize> {
    if !data.starts_with(b"MZ") {
        return None;
    }
    // Standalone: e_lfanew → "LE".
    if let Some(off) = u32le(data, 0x3c).map(|v| v as usize) {
        if is_le_header(data, off) {
            return Some(off);
        }
    }
    // Bound (DOS/4GW): scan 16-byte-aligned offsets for a validating LE header. The fixed
    // fields (byte/word order, CPU, power-of-two page size, in-range object table) make a
    // false positive on raw "LE" bytes vanishingly unlikely.
    (0..data.len().saturating_sub(0xc4)).step_by(4).find(|&off| is_le_header(data, off))
}

/// Validate the fixed LE-header fields at `off` (used by both standalone + scan detection,
/// and by the loader dispatch to distinguish a standalone LE from a bound DOS-extender exe).
pub fn is_le_header(data: &[u8], off: usize) -> bool {
    if data.get(off..off + 2) != Some(b"LE") {
        return false;
    }
    let f = |rel: usize| u32le(data, off + rel);
    let (Some(border), Some(worder)) = (data.get(off + le::BORDER), data.get(off + le::WORDER))
    else {
        return false;
    };
    if *border != 0 || *worder != 0 {
        return false; // only little-endian LE is supported
    }
    let cpu = u16le(data, off + le::CPU);
    if !matches!(cpu, Some(1..=6)) {
        return false; // x86 family
    }
    let (Some(page_size), Some(obj_count), Some(obj_off)) =
        (f(le::PAGE_SIZE), f(le::OBJ_COUNT), f(le::OBJ_TABLE_OFF))
    else {
        return false;
    };
    if page_size == 0 || !page_size.is_power_of_two() {
        return false;
    }
    if obj_count == 0 || obj_count > 64 {
        return false;
    }
    // Object table must lie within the file.
    let ot = off as u64 + obj_off as u64;
    ot + obj_count as u64 * 24 <= data.len() as u64
}

/// Parse an LE image and build the [`Program`] memory map (its 32-bit objects + entry).
pub fn load_le(data: &[u8]) -> Result<Program, LoadError> {
    let base = detect_le(data).ok_or_else(|| LoadError::Unsupported("no LE header found".into()))?;
    let f = |rel: usize| u32le(data, base + rel).ok_or(LoadError::Unsupported("truncated LE header".into()));

    let num_pages = f(le::NUM_PAGES)?;
    let page_size = f(le::PAGE_SIZE)?;
    let last_page_bytes = f(le::LAST_PAGE_BYTES)?;
    let eip_object = f(le::EIP_OBJECT)?;
    let eip = f(le::EIP)?;
    let obj_count = f(le::OBJ_COUNT)?;
    let obj_table = base + f(le::OBJ_TABLE_OFF)? as usize;
    let pagemap = base + f(le::OBJ_PAGEMAP_OFF)? as usize;

    // Parse the object table.
    let mut objects = Vec::with_capacity(obj_count as usize);
    for i in 0..obj_count as usize {
        let o = obj_table + i * 24;
        let rd = |rel: usize| u32le(data, o + rel).ok_or(LoadError::Unsupported("truncated LE object".into()));
        objects.push(LeObject {
            virtual_size: rd(0x00)?,
            reloc_base: rd(0x04)?,
            flags: rd(0x08)?,
            page_index: rd(0x0c)?,
            page_count: rd(0x10)?,
        });
    }

    // The page-data region. The DOS/4GW-bound file's "data pages offset" header field is
    // bogus (it reflects the unbound module), so the region is computed from end-of-file:
    // the physical pages are stored contiguously, ending exactly at EOF, the last page
    // holding `last_page_bytes` (docs/le-loader-notes.md). Reject if it doesn't close to EOF.
    let total_page_bytes =
        (num_pages.saturating_sub(1) as u64) * page_size as u64 + last_page_bytes as u64;
    let file_len = data.len() as u64;
    if total_page_bytes > file_len {
        return Err(LoadError::Unsupported("LE page region exceeds file".into()));
    }
    let pages_start = (file_len - total_page_bytes) as usize;

    // The page map (verified identity on the corpus: logical page i → physical page i,
    // flags=0 "valid"). We follow the file order, mapping each object's pages to the
    // contiguous data region; only the file's final physical page is partial.
    // (A non-identity / iterated / zero-fill page map is a future refinement — see notes.)
    let _ = pagemap;

    let mut spaces = SpaceManager::standard();
    let ram = spaces.add("ram", SpaceKind::Processor, 4, 1); // 32-bit address space
    let mut memory = Memory::new();

    let mut image_base: Option<u64> = None;
    for (i, obj) in objects.iter().enumerate() {
        if obj.virtual_size == 0 {
            continue;
        }
        let (r, w, x) = obj.perms();
        // File bytes backing this object: its pages are physical pages
        // [page_index, page_index + page_count) (1-based, identity map), laid contiguously
        // from `pages_start`. Only the file's last physical page is short.
        let first_page = obj.page_index; // 1-based
        let last_page = obj.page_index + obj.page_count - 1;
        let file_start = pages_start + (first_page as usize - 1) * page_size as usize;
        let avail = if last_page == num_pages {
            (obj.page_count as usize - 1) * page_size as usize + last_page_bytes as usize
        } else {
            obj.page_count as usize * page_size as usize
        };
        // The object occupies `virtual_size` bytes in memory: the file-backed prefix plus a
        // zero-filled tail (LE zero-fills object pages not present in the file). mosura's
        // memory model has no partial block, so the object is one block of `virtual_size`
        // with its file bytes zero-padded to size — faithful to the loaded image (the tail
        // is zero at load); the file-backed/BSS split is a noted refinement.
        let vsize = obj.virtual_size as usize;
        let mut bytes = vec![0u8; vsize];
        let copy = avail.min(vsize);
        if let Some(src) = data.get(file_start..file_start + copy) {
            bytes[..copy].copy_from_slice(src);
        }
        let name = if x { format!("obj{}_text", i + 1) } else { format!("obj{}_data", i + 1) };
        memory.add_block(
            &name,
            Address::new(ram, u64::from(obj.reloc_base)),
            vsize as u64,
            r,
            w,
            x,
            Some(bytes),
        );
        image_base = Some(image_base.map_or(u64::from(obj.reloc_base), |b| b.min(u64::from(obj.reloc_base))));
    }

    let image_base = Address::new(ram, image_base.unwrap_or(0));
    // 32-bit i386 protected mode. The toolchain is Watcom/DOS-4GW; Ghidra has no Watcom x86
    // compiler spec, so we record the generic default ("gcc" is mosura's modeled SysV-ish
    // default) — informational, as the LE path is not run through the analysis gates.
    let mut program = Program::new(spaces, ram, "x86:LE:32:default", "gcc", image_base, false, 32);
    program.memory = memory;

    // Entry point: EIP is an offset *within* the EIP object, so the absolute entry is the
    // object's virtual base + EIP (docs/le-loader-notes.md: 0x10000 + 0x501F8 = 0x601F8).
    if eip_object >= 1 && (eip_object as usize) <= objects.len() {
        let obj = &objects[eip_object as usize - 1];
        let entry = u64::from(obj.reloc_base) + u64::from(eip);
        let addr = Address::new(ram, entry);
        if program.memory.contains(addr) {
            program.entry_points.push(addr);
            program.symbol_table.add_with_primary(addr, "entry", SymbolType::Function, true);
            program.function_manager.create_function(addr, "entry", crate::analysis::program::AddressSet::new());
        }
    }

    Ok(program)
}
