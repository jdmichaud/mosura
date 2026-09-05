//! X-32 loader — for FlashTek X-32 / X-32VM-bound 32-bit DOS executables. File bytes → a
//! [`Program`] whose single flat block matches the container's own description of the 32-bit
//! protected-mode image, as `x86:LE:32:default`.
//!
//! **No Ghidra oracle.** Ghidra has no X-32 loader (its `app/util/opinion/` has no such
//! `Loader`), so — like [`super::le`] — this is grounded in the container's own metadata rather
//! than in Ghidra's output, plus agreement across two independent samples. The full derivation,
//! the evidence for each field, and the two constants deliberately *not* hardcoded are in
//! `docs/x32-loader-notes.md`.
//!
//! Layout, all of it read from the file:
//!
//! ```text
//!   file[0 .. inner)      FlashTek X-32 extender stub, 16-bit real mode
//!   file[inner]           inner MZ header; its e_cp/e_cblp image closes exactly to EOF
//!   image = inner + e_cparhdr*16
//!   image[0x00] u16       the 32-bit image start, IN PARAGRAPHS, relative to `image`
//!   image[0x02] u16       byte size of the descriptor table
//!   image[0x18 ..]        descriptor table — flat, base 0 (checked, not assumed)
//!   image[0x12c] u32      end of BSS as a flat address, i.e. the memory size
//!   image[0 .. flat)      the 16-bit X-32 runtime, ending in the transfer idiom
//!   image[flat .. EOF]    the 32-bit flat program, mapped at its descriptor base (0)
//! ```
//!
//! The **entry point is not a header field**: the 16-bit runtime fakes a far return into the
//! 32-bit selector, and the entry is the `imm32` it pushes. Both samples yield `0xd`, and both
//! place the selector slot at `flat - 0x3bb8` — and neither is hardcoded here, because both are
//! artefacts of one end-aligned runtime build. The idiom is parsed; if it is absent the load is
//! **refused** rather than guessing an entry.
//!
//! Unlike LE there are **no fixups**: every inner-MZ relocation lies strictly below the 32-bit
//! image start, because the 32-bit code references absolute flat addresses directly. That is
//! asserted at load, not assumed — a relocation at or above the boundary means this
//! understanding of the format is wrong, and the caller gets an error instead of a wrong map.

use super::elf::LoadError;
use super::read::{u16le, u32le};
use crate::analysis::program::{Memory, Program, SymbolType};
use crate::decompile::space::{Address, SpaceKind, SpaceManager};

/// Inner-image header field offsets, relative to the start of the inner MZ's load image.
mod hdr {
    /// The 32-bit image start, in paragraphs.
    pub const FLAT_PARA: usize = 0x00;
    /// Byte size of the descriptor table at [`DESCRIPTORS`].
    pub const DESC_BYTES: usize = 0x02;
    /// First descriptor of the GDT/LDT image.
    pub const DESCRIPTORS: usize = 0x18;
    /// End of BSS, as a flat address — the memory size the program expects.
    pub const BSS_END: usize = 0x12c;
}

/// MZ header field offsets.
mod mz {
    pub const CBLP: usize = 0x02; // bytes used in the last page
    pub const CP: usize = 0x04; // pages in the file
    pub const CRLC: usize = 0x06; // relocation count
    pub const CPARHDR: usize = 0x08; // header size, in paragraphs
    pub const LFARLC: usize = 0x18; // relocation table offset
}

/// One 8-byte x86 segment descriptor, only as far as this loader needs it.
struct Descriptor {
    base: u32,
    access: u8,
    flags: u8,
}

impl Descriptor {
    fn parse(d: &[u8], off: usize) -> Option<Descriptor> {
        let raw = d.get(off..off + 8)?;
        Some(Descriptor {
            base: u32::from_le_bytes([raw[2], raw[3], raw[4], raw[7]]),
            access: raw[5],
            flags: raw[6],
        })
    }
    /// Present, code or data (`S`=1), i.e. a descriptor a program image would use.
    fn is_memory(&self) -> bool {
        self.access & 0x90 == 0x90
    }
    /// `D/B` set — a 32-bit segment.
    fn is_32bit(&self) -> bool {
        self.flags & 0x40 != 0
    }
}

/// Everything the loader reads out of an X-32 container.
pub struct X32Layout {
    /// File offset of the inner MZ header.
    pub inner: usize,
    /// File offset of the inner MZ's load image.
    pub image: usize,
    /// File offset of the 32-bit flat image.
    pub flat: usize,
    /// Flat base address the 32-bit image is mapped at, from the descriptor table.
    pub base: u32,
    /// Entry point, as a flat offset — the `imm32` of the transfer idiom.
    pub entry: u32,
    /// Memory size (image + BSS), from `image[0x12c]`; falls back to the file image size.
    pub memsz: u32,
}

impl X32Layout {
    /// Bytes of the 32-bit image present in the file.
    pub fn file_size(&self, data: &[u8]) -> usize {
        data.len().saturating_sub(self.flat)
    }
}

/// The 16-bit runtime's transfer into the 32-bit code:
///
/// ```text
///   2e 66 ff 36 <disp16>   pushl %cs:[disp16]   ; the selector, filled in at load time
///   66 68 <imm32>          pushl <imm32>        ; THE ENTRY — lretl pops EIP from the top
///   66 cb                  lretl
/// ```
const IDIOM_PUSH_CS: [u8; 4] = [0x2e, 0x66, 0xff, 0x36];
const IDIOM_PUSH_IMM: [u8; 2] = [0x66, 0x68];
const IDIOM_LRETL: [u8; 2] = [0x66, 0xcb];

/// Find the transfer idiom in the 16-bit region and return the entry `imm32` it pushes.
fn entry_from_idiom(sixteen: &[u8]) -> Option<u32> {
    // `pushl cs:[disp16]` (6) + `pushl imm32` (6) + `lretl` (2)
    for i in 0..sixteen.len().saturating_sub(13) {
        if sixteen[i..i + 4] != IDIOM_PUSH_CS {
            continue;
        }
        if sixteen[i + 6..i + 8] != IDIOM_PUSH_IMM {
            continue;
        }
        if sixteen[i + 12..i + 14] != IDIOM_LRETL {
            continue;
        }
        return u32le(sixteen, i + 8);
    }
    None
}

/// Locate the inner MZ: the first `MZ` past offset 0 whose `e_cp`/`e_cblp` image closes exactly
/// to end of file, which is what distinguishes the bound application from the extender stub in
/// front of it (and from an `MZ` that merely occurs in data).
fn find_inner_mz(data: &[u8]) -> Option<usize> {
    let mut off = 1;
    while let Some(rel) = data[off..].windows(2).position(|w| w == b"MZ") {
        let o = off + rel;
        if let (Some(cblp), Some(cp), Some(cparhdr)) =
            (u16le(data, o + mz::CBLP), u16le(data, o + mz::CP), u16le(data, o + mz::CPARHDR))
        {
            let image = (cp as usize).saturating_sub(1) * 512 + if cblp == 0 { 512 } else { cblp as usize };
            if (2..=4096).contains(&cparhdr) && cp > 0 && image == data.len() - o {
                return Some(o);
            }
        }
        off = o + 1;
    }
    None
}

/// True when `data` looks like an X-32 container: an inner MZ that closes to EOF, a 32-bit image
/// start inside the file, a plausible descriptor table, and the transfer idiom present.
///
/// Deliberately strict, for [`super::le::is_le_header`]'s reason: a wrong detection is worse
/// than none. In particular the idiom check is what keeps a plain DOS MZ or a DOS/4GW-bound LE
/// from being claimed here.
pub fn is_x32_image(data: &[u8]) -> bool {
    detect_x32(data).is_some()
}

/// Read the layout out of an X-32 container, or `None` if this is not one.
pub fn detect_x32(data: &[u8]) -> Option<X32Layout> {
    if !data.starts_with(b"MZ") {
        return None; // the extender stub is itself an MZ
    }
    let inner = find_inner_mz(data)?;
    let cparhdr = u16le(data, inner + mz::CPARHDR)? as usize;
    let image = inner + cparhdr * 16;
    if image >= data.len() {
        return None;
    }
    let img = data.get(image..)?;

    // The 32-bit image start, in paragraphs relative to the inner image.
    let flat_rel = u16le(img, hdr::FLAT_PARA)? as usize * 16;
    if flat_rel == 0 || flat_rel >= img.len() {
        return None;
    }
    // A descriptor table with at least one 32-bit memory descriptor, which is also where the
    // flat base comes from.
    let desc_bytes = u16le(img, hdr::DESC_BYTES)? as usize;
    if desc_bytes < 8 || desc_bytes > flat_rel {
        return None;
    }
    let base = flat_base(img, desc_bytes)?;

    // The entry: parsed from the idiom, never assumed.
    let entry = entry_from_idiom(img.get(..flat_rel)?)?;
    let flat = image + flat_rel;
    let file_size = data.len() - flat;
    if entry as usize >= file_size {
        return None; // an entry outside the mapped image is not a container we understand
    }

    // Memory size: end-of-BSS as a flat address. Two-sample support only, so it is sanity
    // checked and falls back to the file image size rather than trusted blindly
    // (docs/x32-loader-notes.md, open items).
    let memsz = match u32le(img, hdr::BSS_END) {
        Some(v) if v as usize >= file_size && (v as u64) < base as u64 + 0x4000_0000 => v,
        _ => file_size as u32,
    };

    Some(X32Layout { inner, image, flat, base, entry, memsz })
}

/// The flat base, read from the first 32-bit memory descriptor. Not assumed to be 0: if a
/// sample ever carries a non-zero descriptor base, that is the base to map at.
fn flat_base(img: &[u8], desc_bytes: usize) -> Option<u32> {
    let mut fallback = None;
    for off in (hdr::DESCRIPTORS..hdr::DESCRIPTORS + desc_bytes).step_by(8) {
        let Some(d) = Descriptor::parse(img, off) else { break };
        if !d.is_memory() {
            continue;
        }
        if d.is_32bit() {
            return Some(d.base);
        }
        fallback.get_or_insert(d.base);
    }
    fallback
}

/// Every inner-MZ relocation must lie strictly below the 32-bit image start: the 32-bit code
/// uses absolute flat addresses and is not relocated. A relocation at or above the boundary
/// means the format understanding is wrong, so this is an error rather than an assumption.
fn check_no_fixups_in_flat(data: &[u8], l: &X32Layout) -> Result<(), LoadError> {
    let n = u16le(data, l.inner + mz::CRLC).unwrap_or(0) as usize;
    let table = l.inner + u16le(data, l.inner + mz::LFARLC).unwrap_or(0) as usize;
    let boundary = l.flat - l.image; // image-relative
    for i in 0..n {
        let e = table + i * 4;
        let (Some(off), Some(seg)) = (u16le(data, e), u16le(data, e + 2)) else { break };
        let linear = seg as usize * 16 + off as usize;
        if linear >= boundary {
            return Err(LoadError::Unsupported(format!(
                "X-32 relocation at image+{linear:#x} is at or above the 32-bit image start \
                 ({boundary:#x}); the 32-bit image is not supposed to be relocated"
            )));
        }
    }
    Ok(())
}

/// Parse an X-32 image and build the [`Program`]: its single flat 32-bit block and its entry.
pub fn load_x32(data: &[u8]) -> Result<Program, LoadError> {
    load_x32_with(data, &crate::switches::Knobs::default())
}

/// [`load_x32`] under explicit [`Knobs`](crate::switches::Knobs) (see `load_le_with`).
pub fn load_x32_with(data: &[u8], knobs: &crate::switches::Knobs) -> Result<Program, LoadError> {
    let l = detect_x32(data)
        .ok_or_else(|| LoadError::Unsupported("no X-32 container found".into()))?;
    check_no_fixups_in_flat(data, &l)?;

    let file_size = l.file_size(data);
    let memsz = l.memsz.max(file_size as u32) as usize;

    let mut spaces = SpaceManager::standard();
    let ram = spaces.add("ram", SpaceKind::Processor, 4, 1); // 32-bit address space
    let mut memory = Memory::new();

    // One block: the container describes one flat segment. The file-backed prefix is zero-padded
    // to `memsz` — faithful to the loaded image, whose BSS is zero at load — the same treatment
    // `le.rs` documents for an object whose virtual size exceeds its file pages.
    let mut bytes = vec![0u8; memsz];
    bytes[..file_size].copy_from_slice(&data[l.flat..]);
    memory.add_block(
        "flat_text",
        Address::new(ram, u64::from(l.base)),
        memsz as u64,
        true,
        true,
        true,
        Some(bytes),
    );

    let image_base = Address::new(ram, u64::from(l.base));
    // The compiler question is the ordinary detection path's: X-32 was a general-purpose
    // extender that several toolchains linked against, so the container says nothing about who
    // compiled the program (docs/x32-loader-notes.md).
    let cspec = super::watcom::compiler_spec_id(data, knobs.x86_32_cspec.as_deref());
    let mut program =
        Program::new(spaces, ram, "x86:LE:32:default", cspec, image_base, false, 32);
    program.knobs = knobs.clone();
    program.memory = memory;
    if let Some(w) = super::watcom::detect(data) {
        program.compiler = w.compiler_label();
    } else if let Some(m) = super::metaware::detect(data) {
        program.compiler = m.compiler_label();
    }

    // No relocation table: see `check_no_fixups_in_flat`. `set_relocatable` stays false, which
    // is what tells `AddressTable`'s filter that ordinary pointers in memory are meaningful.
    let entry = Address::new(ram, u64::from(l.base) + u64::from(l.entry));
    if program.memory.contains(entry) {
        program.entry_points.push(entry);
        program.symbol_table.add_with_primary(entry, "entry", SymbolType::Function, true);
        program.function_manager.create_function(
            entry,
            "entry",
            crate::analysis::program::AddressSet::new(),
        );
    }
    Ok(program)
}
