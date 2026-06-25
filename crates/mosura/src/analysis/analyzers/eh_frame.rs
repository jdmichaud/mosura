//! `EhFrameAnalyzer` (A7 Task 2) — a port of the `.eh_frame_hdr` FDE-table parsing in
//! Ghidra's `app/plugin/exceptionhandlers/gcc/` GCC exception-handler analyzer
//! (`GccExceptionAnalyzer` → `EhFrameHeaderSection.analyze` → `FdeTable.create`), with the
//! DWARF pointer-encoding decoder (`DwarfDecoderFactory` / `AbstractDwarfEHDecoder`).
//!
//! The `.eh_frame_hdr` section holds a binary-search table of FDE pointers used by the C++
//! runtime unwinder. Each table entry is a pair of DWARF-encoded pointers — `initial_loc`
//! (the function start) and `data_loc` (the FDE in `.eh_frame`). Ghidra:
//!   * `EhFrameHeaderSection`: parses the 4-byte header (`version`, `eh_frame_ptr_encoding`,
//!     `fde_count_encoding`, `table_encoding`); creates a DATA ref for the encoded
//!     `eh_frame_ptr`; reads the FDE count; then builds the table.
//!   * `FdeTable.create`: for each of `fdeCount` entries, decodes `initial_loc` (emitting an
//!     **INDIRECTION** ref — `FdeTable` hardcodes `RefType.INDIRECTION` for the code pointer)
//!     and `data_loc` (emitting a **DATA** ref).
//!
//! The DWARF encoding byte splits into a *format* (low nibble — the stored size/signedness)
//! and an *application mode* (bits 0x70 — how to turn the stored value into an address:
//! `pcrel`/`datarel`/`texrel`/`funcrel`/`absptr`), with bit 0x80 = indirect (dereference the
//! computed address). This mirrors `DwarfDecoderFactory.getDecoder` + the
//! `AbstractDwarfEHDecoder.decode`/`resolveRelativeOffset` pipeline.
//!
//! Ghidra runs this as a BYTE_ANALYZER at `FORMAT_ANALYSIS.after().after()`, gated by
//! `canAnalyze` (gcc/default compiler spec + a `.eh_frame_hdr`/`.eh_frame` block). mosura
//! runs it as a post-convergence pass (the references it adds are independent of the
//! disassembly worklist).

use crate::analysis::program::{Program, RefType};
use crate::decompile::space::Address;

const EH_FRAME_HDR_BLOCK: &str = ".eh_frame_hdr";

/// DWARF EH pointer-encoding format (low nibble; `DwarfEHDataDecodeFormat`). Only the
/// fixed-size formats arise in an FDE table / header; the LEB128 forms are unsupported here
/// (Ghidra would parse them but no gcc-emitted `.eh_frame_hdr` uses them for the table).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Format {
    Absptr, // 0x00 — pointer-sized
    Udata2, // 0x02
    Udata4, // 0x03
    Udata8, // 0x04
    Sdata2, // 0x0a
    Sdata4, // 0x0b
    Sdata8, // 0x0c
    Omit,   // 0x0f
    Unsupported,
}

/// DWARF EH application mode (bits 0x70; `DwarfEHDataApplicationMode`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum AppMode {
    Absptr,  // 0x00
    Pcrel,   // 0x10
    Texrel,  // 0x20
    Datarel, // 0x30
    Funcrel, // 0x40
    Aligned, // 0x50
}

/// A decoder for one encoding byte (`DwarfDecoderFactory.getDecoder`).
#[derive(Clone, Copy, Debug)]
struct Decoder {
    format: Format,
    app_mode: AppMode,
    indirect: bool,
}

impl Decoder {
    /// `DwarfDecoderFactory.getDecoder`: split the mode byte into format / app-mode /
    /// indirect. `0xFF` is the omit decoder.
    fn from_mode(mode: u8) -> Decoder {
        if mode == 0xFF {
            return Decoder { format: Format::Omit, app_mode: AppMode::Absptr, indirect: false };
        }
        let format = match mode & 0x0F {
            0x00 => Format::Absptr,
            0x02 => Format::Udata2,
            0x03 => Format::Udata4,
            0x04 => Format::Udata8,
            0x0a => Format::Sdata2,
            0x0b => Format::Sdata4,
            0x0c => Format::Sdata8,
            0x0f => Format::Omit,
            _ => Format::Unsupported, // uleb128/sleb128/signed — not in fixed-size tables
        };
        let app_mode = match mode & 0x70 {
            0x00 => AppMode::Absptr,
            0x10 => AppMode::Pcrel,
            0x20 => AppMode::Texrel,
            0x30 => AppMode::Datarel,
            0x40 => AppMode::Funcrel,
            0x50 => AppMode::Aligned,
            _ => AppMode::Absptr,
        };
        Decoder { format, app_mode, indirect: (mode & 0x80) == 0x80 }
    }

    /// The encoded size in bytes (`getDecodeSize`); `absptr` is pointer-sized.
    fn decode_size(&self, ptr_size: u32) -> Option<usize> {
        Some(match self.format {
            Format::Absptr => match ptr_size {
                3 => 4,
                5..=7 => 8,
                n => n as usize,
            },
            Format::Udata2 | Format::Sdata2 => 2,
            Format::Udata4 | Format::Sdata4 => 4,
            Format::Udata8 | Format::Sdata8 => 8,
            Format::Omit | Format::Unsupported => return None,
        })
    }

    fn is_signed(&self) -> bool {
        matches!(self.format, Format::Sdata2 | Format::Sdata4 | Format::Sdata8)
    }
}

/// Read a little-endian `size`-byte unsigned value from program memory, or `None` if any
/// byte is uninitialized/uncovered.
fn read_uint(program: &Program, addr: Address, size: usize) -> Option<u64> {
    let mut v: u64 = 0;
    for i in 0..size {
        let b = program.memory.byte_at(Address::new(addr.space, addr.offset.wrapping_add(i as u64)))?;
        v |= (b as u64) << (8 * i);
    }
    Some(v)
}

/// `AbstractDwarfEHDecoder.doDecode` — read the stored value (sign-extended for the signed
/// formats), returning `(raw_value_as_u64, length)`.
fn do_decode(program: &Program, decoder: &Decoder, addr: Address, ptr_size: u32) -> Option<(u64, usize)> {
    let size = decoder.decode_size(ptr_size)?;
    let raw = read_uint(program, addr, size)?;
    let val = if decoder.is_signed() {
        // Sign-extend from `size` bytes.
        let bits = (size * 8) as u32;
        let shift = 64 - bits;
        (((raw << shift) as i64) >> shift) as u64
    } else {
        raw
    };
    Some((val, size))
}

/// `AbstractDwarfEHDecoder.decode` + `resolveRelativeOffset` — apply the application mode to
/// the decoded value to produce the target offset, then (if indirect) dereference.
/// `field_addr` is the address the value was read from (for `pcrel`); `eh_block_start` is
/// the `.eh_frame_hdr` start (for `datarel`); `text_start` is the `.text` start (for
/// `texrel`).
fn resolve(
    program: &Program,
    decoder: &Decoder,
    val: u64,
    field_addr: Address,
    eh_block_start: u64,
    text_start: Option<u64>,
    ptr_size: u32,
) -> Option<u64> {
    // Ghidra: if val == 0 or val == addr and indirect, return val (avoid null/loop deref).
    if (val == 0 || val == field_addr.offset) && decoder.indirect {
        return Some(val);
    }
    let mut out = match decoder.app_mode {
        AppMode::Absptr | AppMode::Aligned => val,
        AppMode::Datarel => eh_block_start.wrapping_add(val),
        AppMode::Funcrel => return None, // no function-entry context in the FDE table path
        AppMode::Pcrel => field_addr.offset.wrapping_add(val),
        AppMode::Texrel => text_start?.wrapping_add(val),
    };
    if decoder.indirect {
        // Dereference a pointer-sized value at the computed address.
        let to = Address::new(field_addr.space, out);
        out = read_uint(program, to, ptr_size as usize)?;
    }
    Some(out)
}

/// Run the `.eh_frame_hdr` FDE-table analysis over `program`, adding the INDIRECTION /
/// DATA references Ghidra's `EhFrameHeaderSection` + `FdeTable` create. No-op if there is
/// no `.eh_frame_hdr` block (the analyzer's `canAnalyze` gate) or the header cannot be
/// decoded.
pub fn analyze(program: &mut Program) {
    // canAnalyze: gcc / default compiler spec.
    let cs = program.compiler_spec_id.to_ascii_lowercase();
    if cs != "gcc" && cs != "default" {
        return;
    }
    let ram = program.default_space;
    let ptr_size = program.addr_size_bits / 8;

    let Some((hdr_start, hdr_end)) = program
        .memory
        .block_by_name(EH_FRAME_HDR_BLOCK)
        .map(|b| (b.start().offset, b.end().offset))
    else {
        return;
    };
    let text_start = program.memory.block_by_name(".text").map(|b| b.start().offset);

    // EhFrameHeaderSection.analyzeSection: read the 4-byte header.
    let at = |off: u64| Address::new(ram, off);
    let Some(version) = program.memory.byte_at(at(hdr_start)) else { return };
    if version != 1 {
        // gcc emits version 1; bail rather than guess on an unfamiliar header.
        return;
    }
    let frame_ptr_enc = program.memory.byte_at(at(hdr_start + 1));
    let fde_count_enc = program.memory.byte_at(at(hdr_start + 2));
    let table_enc = program.memory.byte_at(at(hdr_start + 3));
    let (Some(frame_ptr_enc), Some(fde_count_enc), Some(table_enc)) =
        (frame_ptr_enc, fde_count_enc, table_enc)
    else {
        return;
    };

    // Refs to add (collected; applied after decoding to keep the borrow simple).
    let mut refs: Vec<(Address, Address, RefType)> = Vec::new();

    // header length = 4 bytes (version + 3 encoding bytes).
    let mut cur = hdr_start + 4;

    // processEncodedFramePointer: the encoded eh_frame_ptr → a DATA ref.
    let fp_decoder = Decoder::from_mode(frame_ptr_enc);
    let Some((fp_val, fp_len)) = do_decode(program, &fp_decoder, at(cur), ptr_size) else { return };
    if let Some(target) =
        resolve(program, &fp_decoder, fp_val, at(cur), hdr_start, text_start, ptr_size)
    {
        let to = at(target);
        if program.memory.contains(to) {
            refs.push((at(cur), to, RefType::Data));
        }
    }
    cur += fp_len as u64;

    // markupEncodedFdeCount + getFdeTableCount: the encoded FDE count.
    let count_decoder = Decoder::from_mode(fde_count_enc);
    let Some((fde_count, count_len)) = do_decode(program, &count_decoder, at(cur), ptr_size) else {
        return;
    };
    cur += count_len as u64;
    if fde_count == 0 {
        for (f, t, k) in refs {
            program.reference_manager.add(f, t, k, 0);
        }
        return;
    }

    // createFdeTable / FdeTable.create: each entry is two encoded values (initial_loc,
    // data_loc) with the table encoding. The fde_table_entry struct is 2 * decode_size.
    let table_decoder = Decoder::from_mode(table_enc);
    let Some(entry_field_size) = table_decoder.decode_size(ptr_size) else {
        for (f, t, k) in refs {
            program.reference_manager.add(f, t, k, 0);
        }
        return;
    };
    let entry_size = (entry_field_size * 2) as u64;

    let mut produced: u64 = 0;
    while cur < hdr_end && produced < fde_count {
        // initial_loc → INDIRECTION (code pointer).
        let loc_field = at(cur);
        let Some((loc_val, _)) = do_decode(program, &table_decoder, loc_field, ptr_size) else {
            break;
        };
        if let Some(target) =
            resolve(program, &table_decoder, loc_val, loc_field, hdr_start, text_start, ptr_size)
        {
            let to = at(target);
            if program.memory.contains(to) {
                refs.push((loc_field, to, RefType::Indirection));
            }
        }
        // data_loc → DATA (the FDE in .eh_frame).
        let data_field = at(cur + entry_field_size as u64);
        let Some((data_val, _)) = do_decode(program, &table_decoder, data_field, ptr_size) else {
            break;
        };
        if let Some(target) =
            resolve(program, &table_decoder, data_val, data_field, hdr_start, text_start, ptr_size)
        {
            let to = at(target);
            if program.memory.contains(to) {
                refs.push((data_field, to, RefType::Data));
            }
        }
        produced += 1;
        cur += entry_size;
    }

    // Ghidra's addMemoryReference uses operand index 0 for these data references.
    for (f, t, k) in refs {
        program.reference_manager.add(f, t, k, 0);
    }
}
