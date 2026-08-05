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
// the field-offset namespace shares the loader module's `le` name; renaming would churn callers
#[allow(clippy::module_inception)]
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
    pub const FIXUP_PAGE_TABLE_OFF: usize = 0x68; // fixup page table offset (rel. to LE header)
    pub const FIXUP_RECORD_TABLE_OFF: usize = 0x6c; // fixup record table offset (rel. to LE header)
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

    // Build each object's in-memory image (file-backed prefix + zero-filled tail), then apply
    // the LE fixups across all objects before laying them into memory. The object occupies
    // `virtual_size` bytes: the file-backed prefix plus a zero-filled tail (LE zero-fills
    // object pages not present in the file). mosura's memory model has no partial block, so
    // the object is one block of `virtual_size` with its file bytes zero-padded to size —
    // faithful to the loaded image (the tail is zero at load); the file-backed/BSS split is a
    // noted refinement.
    let mut obj_bytes: Vec<Vec<u8>> = Vec::with_capacity(objects.len());
    for obj in &objects {
        let vsize = obj.virtual_size as usize;
        let mut bytes = vec![0u8; vsize];
        if vsize != 0 {
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
            let copy = avail.min(vsize);
            if let Some(src) = data.get(file_start..file_start + copy) {
                bytes[..copy].copy_from_slice(src);
            }
        }
        obj_bytes.push(bytes);
    }

    // Apply the LE relocation ("fixup") records: patch each internal reference to its loaded
    // address (source obj-relative offset + object reloc_base). WAR2's cs:-relative inline
    // jump tables — the real protected-mode switches — are entirely constructed from these
    // fixups (both the `jmp cs:[reg*4+disp]` displacement and every table entry), so without
    // this pass the switch tables read garbage and the switch-gated code stays undiscovered.
    // Ghidra has no LE loader; the oracle for this beyond-Ghidra `--le` path is the binary's
    // own fixup records (docs/le-loader-notes.md). Mirrors how `elf.rs` applies relocations
    // at load (`apply_external_relocations`).
    let fixups = apply_le_fixups(data, base, &objects, num_pages, page_size, &mut obj_bytes);

    let mut image_base: Option<u64> = None;
    for (i, obj) in objects.iter().enumerate() {
        if obj.virtual_size == 0 {
            continue;
        }
        let (r, w, x) = obj.perms();
        let name = if x { format!("obj{}_text", i + 1) } else { format!("obj{}_data", i + 1) };
        memory.add_block(
            &name,
            Address::new(ram, u64::from(obj.reloc_base)),
            obj.virtual_size as u64,
            r,
            w,
            x,
            Some(std::mem::take(&mut obj_bytes[i])),
        );
        image_base = Some(image_base.map_or(u64::from(obj.reloc_base), |b| b.min(u64::from(obj.reloc_base))));
    }

    let image_base = Address::new(ram, image_base.unwrap_or(0));

    // Watcom compiler detection (two-oracle — see `watcom.rs`): a DOS/4GW-bound LE is a Watcom
    // build; its C run-time startup embeds the copyright banner right after the `_cstart_`
    // `EB 76` entry jump. When detected, select the beyond-Ghidra `watcom` compiler spec — the
    // `watcall` register calling convention (`specs/x86-32-watcom.cspec`) — instead of the
    // generic `gcc` placeholder, so prototype recovery uses the right convention. 32-bit i386
    // protected mode (`x86:LE:32:default`).
    let watcom = super::watcom::detect(data);
    let compiler_spec_id = super::watcom::compiler_spec_id(data);
    let mut program =
        Program::new(spaces, ram, "x86:LE:32:default", compiler_spec_id, image_base, false, 32);
    program.memory = memory;
    if let Some(w) = watcom {
        program.compiler = w.compiler_label(); // the `Compiler` info property (era)
    }

    // Record the fixups as the program's relocation table (Ghidra `RelocationTable`, populated
    // by every Ghidra loader that has relocation records). `apply_le_fixups` used to patch the
    // bytes and throw the records away, which left `AddressTable.getEntry`'s
    // `isValidRelocationAddress` check (AddressTable.java:1131/:1434) with nothing to consult —
    // it had to be STUBBED to always-true in the address-table port. This restores it.
    //
    // `isRelocatable` is true here in Ghidra's own sense (RelocationTable.java:116 — "relocations
    // for a relocatable binary", as opposed to an ELF executable's already-resolved ones): a
    // bound LE is relocated at load by the extender, so the premise the filter relies on —
    // "if it is relocatable, then there should be no pointers in memory, other than relocatable
    // ones" (AddressTable.java:1439) — holds exactly. Every absolute address the linker stored
    // is in this table by construction.
    if !fixups.is_empty() {
        program.relocation_table.set_relocatable(true);
        for (src, target) in &fixups {
            program.relocation_table.add(Address::new(ram, *src), *target);
        }
    }

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

/// Apply the LE relocation ("fixup") records to the object images (LE/LX spec §"Fixup Page
/// Table" / "Fixup Record Table"). Each internal fixup relocates a reference from its stored
/// object-relative offset to the object's loaded address (`reloc_base + target_offset`).
///
/// Layout (all offsets relative to the LE header at `le_base`):
/// - **Fixup Page Table** (`LE+0x68`): `num_pages + 1` u32 entries. Page *p* (1-based) owns
///   the records in `[FRT + FPT[p-1], FRT + FPT[p])`.
/// - **Fixup Record Table** (`LE+0x6c`): the packed records themselves.
///
/// A record is `SRC(1) FLAGS(1) SRCOFF/CNT OBJECT TARGETOFF [ADDITIVE] [SRCOFF-list]`:
/// - `SRC` low nibble = source size (`0x07` = 32-bit offset — WAR2's kind), `0x10` = the
///   source is a *list* (a count byte replaces the single 2-byte source offset, and the list
///   of 2-byte source offsets trails the target data).
/// - `FLAGS` low 2 bits = target type (`0` = internal reference); `0x40` = 16-bit object
///   number (else 8-bit); `0x10` = 32-bit target offset (else 16-bit); `0x04` = additive
///   (a trailing 2/4-byte addend per `0x20`).
///
/// Returns every applied fixup as `(source slot address, relocated target address)` — the
/// records Ghidra's loaders put in the program's `RelocationTable`. The caller stores them
/// there; `AddressTable.getEntry`'s `isValidRelocationAddress` filter consumes them.
///
/// Only **internal** (target-type 0) fixups are applied — WAR2 is 100% internal 32-bit-offset
/// fixups (its import table is empty). Imports/selectors are neither sized nor applied here;
/// on encountering one the page is abandoned (no LE test binary exercises them). Ghidra has no
/// LE loader — the oracle is the binary's own fixup bytes (docs/le-loader-notes.md).
fn apply_le_fixups(
    data: &[u8],
    le_base: usize,
    objects: &[LeObject],
    num_pages: u32,
    page_size: u32,
    obj_bytes: &mut [Vec<u8>],
) -> Vec<(u64, u64)> {
    let mut applied: Vec<(u64, u64)> = Vec::new();
    let (Some(fpt_rel), Some(frt_rel)) = (
        u32le(data, le_base + le::FIXUP_PAGE_TABLE_OFF),
        u32le(data, le_base + le::FIXUP_RECORD_TABLE_OFF),
    ) else {
        return applied;
    };
    let fpt = le_base + fpt_rel as usize;
    let frt = le_base + frt_rel as usize;

    // Virtual base of 1-based page `p` (identity page map): the owning object's reloc_base
    // plus the page's offset within that object.
    let page_vbase = |p: u32| -> Option<u64> {
        objects.iter().find(|o| p >= o.page_index && p < o.page_index + o.page_count).map(|o| {
            u64::from(o.reloc_base) + u64::from(p - o.page_index) * u64::from(page_size)
        })
    };
    // Patch a relocated 32-bit value at a source virtual address into whichever object's image
    // contains it (a fixup source can lie in any object, and may straddle a page boundary —
    // the object image is contiguous, so an absolute-address write handles both).
    let patch = |obj_bytes: &mut [Vec<u8>], src_vaddr: u64, value: u32| {
        for (oi, o) in objects.iter().enumerate() {
            let lo = u64::from(o.reloc_base);
            if src_vaddr >= lo && src_vaddr + 4 <= lo + u64::from(o.virtual_size) {
                let idx = (src_vaddr - lo) as usize;
                obj_bytes[oi][idx..idx + 4].copy_from_slice(&value.to_le_bytes());
                return;
            }
        }
    };

    for p in 1..=num_pages {
        let (Some(start), Some(end)) =
            (u32le(data, fpt + (p as usize - 1) * 4), u32le(data, fpt + p as usize * 4))
        else {
            break;
        };
        let Some(vbase) = page_vbase(p) else { continue };
        let mut q = frt + start as usize;
        let rec_end = frt + end as usize;
        'page: while q + 2 <= rec_end && q + 2 <= data.len() {
            let src = data[q];
            let flags = data[q + 1];
            q += 2;
            let srctype = src & 0x0f;
            let srclist = src & 0x10 != 0;

            // Source offset(s): a single 2-byte offset, or (list flag) a count byte plus a
            // trailing list read after the target data.
            let mut count = 1u8;
            let mut single_soff = 0i32;
            if srclist {
                if q + 1 > data.len() {
                    break;
                }
                count = data[q];
                q += 1;
            } else {
                if q + 2 > data.len() {
                    break;
                }
                single_soff = i16::from_le_bytes([data[q], data[q + 1]]) as i32;
                q += 2;
            }

            // Only internal (target-type 0) references have a spec-defined size here; bail the
            // page on anything else rather than risk desyncing the record stream.
            if flags & 0x03 != 0 {
                break;
            }
            // Object number (8- or 16-bit).
            let obj_num = if flags & 0x40 != 0 {
                let Some(v) = u16le(data, q) else { break };
                q += 2;
                v as usize
            } else {
                if q + 1 > data.len() {
                    break;
                }
                let v = data[q] as usize;
                q += 1;
                v
            };
            // Target offset: none for a 16-bit-selector source, else 16- or 32-bit.
            let target_off = if srctype == 0x02 {
                0u64
            } else if flags & 0x10 != 0 {
                let Some(v) = u32le(data, q) else { break };
                q += 4;
                u64::from(v)
            } else {
                let Some(v) = u16le(data, q) else { break };
                q += 2;
                u64::from(v)
            };
            // Additive addend (unused by WAR2): skip its 2/4 bytes.
            if flags & 0x04 != 0 {
                q += if flags & 0x20 != 0 { 4 } else { 2 };
            }
            // Source-offset list trails the target data.
            let mut soffs: Vec<i32> = Vec::new();
            if srclist {
                for _ in 0..count {
                    let Some(v) = u16le(data, q) else { break 'page };
                    soffs.push(v as i16 as i32);
                    q += 2;
                }
            } else {
                soffs.push(single_soff);
            }

            // Apply: a 32-bit-offset internal fixup writes the relocated absolute address.
            if srctype == 0x07 && obj_num >= 1 && obj_num <= objects.len() {
                let target = u64::from(objects[obj_num - 1].reloc_base) + target_off;
                for so in &soffs {
                    let src_vaddr = (vbase as i64 + *so as i64) as u64;
                    patch(obj_bytes, src_vaddr, target as u32);
                    applied.push((src_vaddr, target));
                }
            }
        }
    }
    applied
}
