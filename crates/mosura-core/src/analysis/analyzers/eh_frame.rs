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
//! Besides the references, Ghidra also **defines data units** as it walks the header
//! (`CreateDataCmd` / `StructureDataType.create`): the `eh_frame_hdr` struct
//! (`ExceptionHandlerFrameHeader`, 4 bytes), the encoded `eh_frame_ptr` and `fde_count`
//! fields (each `DwarfEHDecoder.getDataType` → `word`/`dword`/`qword`), and the
//! `fde_table_entry` struct (`FdeTable`, `2 * field_size` bytes) for each table row. We
//! record these into `Program::defined_data` so the snapshot's `data` section reproduces
//! them — a faithful subset of Ghidra's defined-data set (the remaining ELF-structure and
//! `.eh_frame` CIE/FDE markup is loader / `EhFrameSection` territory, deferred).
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

use std::collections::HashMap;

use crate::analysis::program::{Program, RefType};
use crate::decompile::space::Address;

const EH_FRAME_HDR_BLOCK: &str = ".eh_frame_hdr";
const EH_FRAME_BLOCK: &str = ".eh_frame";

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

    /// The Ghidra datatype NAME for a field of this encoding (`DwarfEHDecoder.getDataType`):
    /// the udata/sdata 2/4/8 decoders return `WORD_DATA_TYPE`/`DWORD_DATA_TYPE`/
    /// `QWORD_DATA_TYPE` (names `word`/`dword`/`qword`); the absptr decoder switches on the
    /// pointer size and returns the same word/dword/qword by length. Keyed off the decode
    /// size so both paths agree. `None` for omit/unsupported (no data unit created).
    fn datatype_name(&self, ptr_size: u32) -> Option<&'static str> {
        Some(match self.decode_size(ptr_size)? {
            2 => "word",
            4 => "dword",
            8 => "qword",
            _ => return None,
        })
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
/// DATA references Ghidra's `EhFrameHeaderSection` + `FdeTable` create, and the
/// `eh_frame_hdr` / `word`/`dword`/`qword` / `fde_table_entry` data units it defines. No-op
/// if there is no `.eh_frame_hdr` block (the analyzer's `canAnalyze` gate) or the header
/// cannot be decoded.
pub fn analyze(program: &mut Program) {
    let (refs, data_units) = collect(program);
    // Ghidra's addMemoryReference uses operand index 0 for these data references.
    for (f, t, k) in refs {
        program.reference_manager.add(f, t, k, 0);
    }
    for d in data_units {
        program.defined_data.push(d);
    }
    // EhFrameSection.analyze: the field-level CIE/FDE markup in .eh_frame (data units only;
    // the references / function creation Ghidra also emits are out of scope for this pass).
    for d in collect_eh_frame(program) {
        program.defined_data.push(d);
    }
}

/// The pure decoding pass: walk the `.eh_frame_hdr` and return the `(references,
/// data_units)` Ghidra creates, without mutating the program (so the multiple
/// early-exit paths flush in one place). `data_units` are `(address, datatype-name,
/// byte-length)`.
#[allow(clippy::type_complexity)]
fn collect(
    program: &Program,
) -> (Vec<(Address, Address, RefType)>, Vec<(Address, String, u32)>) {
    let none = || (Vec::new(), Vec::new());
    // canAnalyze: gcc / default compiler spec.
    let cs = program.compiler_spec_id.to_ascii_lowercase();
    if cs != "gcc" && cs != "default" {
        return none();
    }
    let ram = program.default_space;
    let ptr_size = program.addr_size_bits / 8;

    let Some((hdr_start, hdr_end)) = program
        .memory
        .block_by_name(EH_FRAME_HDR_BLOCK)
        .map(|b| (b.start().offset, b.end().offset))
    else {
        return none();
    };
    let text_start = program.memory.block_by_name(".text").map(|b| b.start().offset);

    // EhFrameHeaderSection.analyzeSection: read the 4-byte header.
    let at = |off: u64| Address::new(ram, off);
    let Some(version) = program.memory.byte_at(at(hdr_start)) else { return none() };
    if version != 1 {
        // gcc emits version 1; bail rather than guess on an unfamiliar header.
        return none();
    }
    let frame_ptr_enc = program.memory.byte_at(at(hdr_start + 1));
    let fde_count_enc = program.memory.byte_at(at(hdr_start + 2));
    let table_enc = program.memory.byte_at(at(hdr_start + 3));
    let (Some(frame_ptr_enc), Some(fde_count_enc), Some(table_enc)) =
        (frame_ptr_enc, fde_count_enc, table_enc)
    else {
        return none();
    };

    // Refs + data units to add (collected; applied by `analyze` to keep the borrow simple).
    let mut refs: Vec<(Address, Address, RefType)> = Vec::new();
    let mut data: Vec<(Address, String, u32)> = Vec::new();

    // ExceptionHandlerFrameHeader.create: the `eh_frame_hdr` struct — a ByteDataType
    // (version) + 3 DwarfEncodingModeDataType (1 byte each) = 4 bytes.
    data.push((at(hdr_start), "eh_frame_hdr".to_string(), 4));

    // header length = 4 bytes (version + 3 encoding bytes).
    let mut cur = hdr_start + 4;

    // processEncodedFramePointer: the encoded eh_frame_ptr → a DATA ref + a data unit.
    let fp_decoder = Decoder::from_mode(frame_ptr_enc);
    let Some((fp_val, fp_len)) = do_decode(program, &fp_decoder, at(cur), ptr_size) else {
        return (refs, data);
    };
    if let Some(name) = fp_decoder.datatype_name(ptr_size) {
        data.push((at(cur), name.to_string(), fp_len as u32));
    }
    if let Some(target) =
        resolve(program, &fp_decoder, fp_val, at(cur), hdr_start, text_start, ptr_size)
    {
        let to = at(target);
        if program.memory.contains(to) {
            refs.push((at(cur), to, RefType::Data));
        }
    }
    cur += fp_len as u64;

    // markupEncodedFdeCount + getFdeTableCount: the encoded FDE count → a data unit.
    let count_decoder = Decoder::from_mode(fde_count_enc);
    let Some((fde_count, count_len)) = do_decode(program, &count_decoder, at(cur), ptr_size) else {
        return (refs, data);
    };
    if let Some(name) = count_decoder.datatype_name(ptr_size) {
        data.push((at(cur), name.to_string(), count_len as u32));
    }
    cur += count_len as u64;
    if fde_count == 0 {
        return (refs, data);
    }

    // createFdeTable / FdeTable.create: each entry is two encoded values (initial_loc,
    // data_loc) with the table encoding. The fde_table_entry struct is 2 * decode_size.
    let table_decoder = Decoder::from_mode(table_enc);
    let Some(entry_field_size) = table_decoder.decode_size(ptr_size) else {
        return (refs, data);
    };
    let entry_size = (entry_field_size * 2) as u64;

    let mut produced: u64 = 0;
    while cur < hdr_end && produced < fde_count {
        // The fde_table_entry struct (FdeTable.create) — 2 * field_size bytes.
        let loc_field = at(cur);
        data.push((loc_field, "fde_table_entry".to_string(), entry_size as u32));
        // initial_loc → INDIRECTION (code pointer).
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

    (refs, data)
}

// ---------------------------------------------------------------------------------------
// .eh_frame CIE/FDE field markup — a port of `EhFrameSection.analyze` / `Cie.create` /
// `FrameDescriptionEntry.create` (`app/plugin/exceptionhandlers/gcc/`). Emits the
// field-level defined-data units Ghidra creates as it walks the section's Common
// Information Entries and Frame Description Entries.
// ---------------------------------------------------------------------------------------

/// What an FDE needs from its CIE (`Cie.getAugmentationString` / `getFDEEncoding`).
struct CieInfo {
    augmentation: String,
    fde_encoding: u8,
}

/// Read a NUL-terminated ASCII string (`StringDataType`); returns `(string, unit_length)`
/// where `unit_length = chars + 1` (includes the NUL), matching
/// `Cie.processAugmentationString` (`augmentationString.length() + 1`). `None` if no NUL is
/// found within the section.
fn read_cstring(program: &Program, addr: Address, end: u64) -> Option<(String, usize)> {
    let mut bytes = Vec::new();
    let mut off = addr.offset;
    while off < end {
        let b = program.memory.byte_at(Address::new(addr.space, off))?;
        if b == 0 {
            return Some((String::from_utf8_lossy(&bytes).into_owned(), bytes.len() + 1));
        }
        bytes.push(b);
        off += 1;
    }
    None
}

/// Read a LEB128 value (unsigned), returning `(value, byte_length)` — the length is what
/// `LEB128Info.getLength()` reports and what the `uleb128`/`sleb128` data unit spans.
fn read_uleb128(program: &Program, addr: Address) -> Option<(u64, usize)> {
    let mut value: u64 = 0;
    let mut shift = 0u32;
    let mut len = 0usize;
    loop {
        let b = program.memory.byte_at(Address::new(addr.space, addr.offset + len as u64))?;
        if shift < 64 {
            value |= ((b & 0x7f) as u64) << shift;
        }
        len += 1;
        shift += 7;
        if b & 0x80 == 0 {
            break;
        }
        if len >= 16 {
            return None; // malformed
        }
    }
    Some((value, len))
}

/// The length in bytes of a LEB128 field (signed or unsigned — same continuation-bit rule).
fn leb128_len(program: &Program, addr: Address) -> Option<usize> {
    read_uleb128(program, addr).map(|(_, l)| l)
}

/// `getPointerDecodeSize` / `getAddressSizeDataType` — the FDE pc_range field is initially an
/// address-sized integer (a `qword` on x86-64), keyed off the program's default pointer size.
fn pointer_decode_size(ptr_size: u32) -> u32 {
    match ptr_size {
        3 => 4,
        5..=7 => 8,
        n => n,
    }
}

/// Walk `.eh_frame` and return the field-level CIE/FDE data units
/// (`(address, datatype-name, byte-length)`). Mirrors `EhFrameSection.analyzeSection`: read a
/// CIE (length field, then `Cie.create` fields), then its FDEs (`FrameDescriptionEntry.create`
/// fields), distinguishing the two by the second `dword` (the CIE id is 0; an FDE's CIE
/// pointer is a non-zero back-offset). A zero-length record is the end-of-frame marker.
fn collect_eh_frame(program: &Program) -> Vec<(Address, String, u32)> {
    let mut data: Vec<(Address, String, u32)> = Vec::new();
    let ram = program.default_space;
    let ptr_size = program.addr_size_bits / 8;
    let Some((start, end)) = program
        .memory
        .block_by_name(EH_FRAME_BLOCK)
        .map(|b| (b.start().offset, b.end().offset + 1)) // end() is inclusive
    else {
        return data;
    };
    let at = |off: u64| Address::new(ram, off);

    let mut cies: HashMap<u64, CieInfo> = HashMap::new();
    let mut cur = start;
    while cur + 4 <= end {
        let Some(length) = read_uint(program, at(cur), 4) else { break };
        // Cie.create / FrameDescriptionEntry.create: a zero length field is the end of frame
        // (`markEndOfFrame` → a `dword` "End of Frame").
        if length == 0 {
            data.push((at(cur), "dword".to_string(), 4));
            break;
        }
        // Extended (0xffffffff) length is not emitted by gcc's .eh_frame and not handled here.
        if length == 0xffff_ffff {
            break;
        }
        let entry_end = cur + 4 + length;
        if entry_end > end {
            break;
        }
        let Some(id) = read_uint(program, at(cur + 4), 4) else { break };
        if id == 0 {
            parse_cie(program, cur, entry_end, ptr_size, &mut data, &mut cies);
        } else {
            parse_fde(program, cur, entry_end, id, ptr_size, &cies, &mut data);
        }
        cur = entry_end;
    }
    data
}

/// `Cie.create`: emit the CIE field data units in order and record the CIE's augmentation
/// string + FDE encoding for its FDEs. `base` is the CIE start; `entry_end` is one past the
/// last CIE byte (`base + 4 + length`).
fn parse_cie(
    program: &Program,
    base: u64,
    entry_end: u64,
    ptr_size: u32,
    data: &mut Vec<(Address, String, u32)>,
    cies: &mut HashMap<u64, CieInfo>,
) {
    let ram = program.default_space;
    let at = |off: u64| Address::new(ram, off);
    let mut addr = base;

    // processCieLength + processCieId: two dwords.
    data.push((at(addr), "dword".to_string(), 4));
    addr += 4;
    data.push((at(addr), "dword".to_string(), 4));
    addr += 4;

    // processVersion: a byte.
    let Some(version) = program.memory.byte_at(at(addr)) else { return };
    data.push((at(addr), "byte".to_string(), 1));
    addr += 1;

    // processAugmentationString: a NUL-terminated string.
    let Some((augmentation, aug_str_len)) = read_cstring(program, at(addr), entry_end) else {
        return;
    };
    data.push((at(addr), "string".to_string(), aug_str_len as u32));
    addr += aug_str_len as u64;

    // version >= 4: processPointerSize + processSegmentSize (a byte each).
    if version >= 4 {
        data.push((at(addr), "byte".to_string(), 1));
        addr += 1;
        data.push((at(addr), "byte".to_string(), 1));
        addr += 1;
    }

    // processCodeAlign (uleb128) + processDataAlign (sleb128).
    let Some(l) = leb128_len(program, at(addr)) else { return };
    data.push((at(addr), "uleb128".to_string(), l as u32));
    addr += l as u64;
    let Some(l) = leb128_len(program, at(addr)) else { return };
    data.push((at(addr), "sleb128".to_string(), l as u32));
    addr += l as u64;

    // processReturnAddrRegister: version 1 → a byte; else a uleb128.
    if version == 1 {
        data.push((at(addr), "byte".to_string(), 1));
        addr += 1;
    } else {
        let Some(l) = leb128_len(program, at(addr)) else { return };
        data.push((at(addr), "uleb128".to_string(), l as u32));
        addr += l as u64;
    }

    // processAugmentationInfo: if the augmentation starts with 'z', an aug-data-length uleb128
    // and an aug-data blob (no unit for the blob); each encoding char ('L'/'R'/'P') marks a
    // `dwfenc` byte within the blob (and 'P' a personality pointer). The blob's byte count
    // governs where the initial instructions start, regardless of per-byte interpretation.
    let mut fde_encoding = 0u8;
    if augmentation.starts_with('z') {
        let Some((aug_data_len, l)) = read_uleb128(program, at(addr)) else { return };
        data.push((at(addr), "uleb128".to_string(), l as u32));
        addr += l as u64;
        let aug_data_addr = addr;
        addr += aug_data_len; // grabAugmentationData advances but creates no unit
        let mut idx: u64 = 0;
        for ch in augmentation.chars().skip(1) {
            if idx >= aug_data_len {
                break;
            }
            let Some(enc) = program.memory.byte_at(at(aug_data_addr + idx)) else { break };
            match ch {
                'L' => {
                    data.push((at(aug_data_addr + idx), "dwfenc".to_string(), 1));
                    idx += 1;
                }
                'R' => {
                    fde_encoding = enc;
                    data.push((at(aug_data_addr + idx), "dwfenc".to_string(), 1));
                    idx += 1;
                }
                'S' => {}
                'P' => {
                    data.push((at(aug_data_addr + idx), "dwfenc".to_string(), 1));
                    idx += 1;
                    // personality function pointer: decoder.getDataType / encoded length.
                    let dec = Decoder::from_mode(enc);
                    match (dec.datatype_name(ptr_size), dec.decode_size(ptr_size)) {
                        (Some(name), Some(sz)) => {
                            data.push((at(aug_data_addr + idx), name.to_string(), sz as u32));
                            idx += sz as u64;
                        }
                        _ => break,
                    }
                }
                _ => {}
            }
        }
    }

    // processInitialInstructions: the remaining CIE bytes as a byte[] (intLength - curSize,
    // i.e. up to the CIE end). Only created when bytes remain (`curSize < intLength`).
    if addr < entry_end {
        let n = entry_end - addr;
        data.push((at(addr), format!("byte[{n}]"), n as u32));
    }

    cies.insert(base, CieInfo { augmentation, fde_encoding });
}

/// `FrameDescriptionEntry.create`: emit the FDE field data units in order. `cie_ptr` is the
/// raw CIE-pointer value (a back-offset); the CIE is at `(cie-pointer field address) -
/// cie_ptr`.
fn parse_fde(
    program: &Program,
    base: u64,
    entry_end: u64,
    cie_ptr: u64,
    ptr_size: u32,
    cies: &HashMap<u64, CieInfo>,
    data: &mut Vec<(Address, String, u32)>,
) {
    let ram = program.default_space;
    let at = |off: u64| Address::new(ram, off);
    let mut addr = base;

    // createFdeLength + createCiePointer: two dwords.
    data.push((at(addr), "dword".to_string(), 4));
    addr += 4;
    let cie_ptr_field = addr;
    data.push((at(addr), "dword".to_string(), 4));
    addr += 4;

    // Resolve the CIE (cieAddr = ciePointerFieldAddr - intPtr, the .eh_frame relative ref).
    let cie_addr = cie_ptr_field.wrapping_sub(cie_ptr);
    let Some(cie) = cies.get(&cie_addr) else { return };

    // createPcBegin: cie.getFDEDecoder().getDataType / encoded length.
    let dec = Decoder::from_mode(cie.fde_encoding);
    let (Some(pc_name), Some(pc_size)) = (dec.datatype_name(ptr_size), dec.decode_size(ptr_size))
    else {
        return;
    };
    data.push((at(addr), pc_name.to_string(), pc_size as u32));
    addr += pc_size as u64;

    // createPcRange: an address-sized integer (a `qword` on x86-64). Ghidra shrinks it to a
    // `dword` when the upper 4 bytes are non-zero (they're really call-frame instructions, not
    // part of the range). A negative low-32 value aborts the FDE (createPcRange returns null).
    let mut range_size = pointer_decode_size(ptr_size);
    let Some(range_val) = read_uint(program, at(addr), range_size as usize) else { return };
    if (range_val as u32 as i32) < 0 {
        return;
    }
    if range_size == 8 {
        let next = (range_val >> 32) as u32;
        if next != 0 {
            range_size = 4;
        }
    }
    let range_name = match range_size {
        2 => "word",
        4 => "dword",
        8 => "qword",
        _ => return,
    };
    data.push((at(addr), range_name.to_string(), range_size));
    addr += range_size as u64;

    // If FDE bytes remain: createAugmentationFields (a uleb128 aug-data-length + an aug-data
    // blob with no unit, when the CIE augmentation starts with 'z') then
    // createCallFrameInstructions (the remaining bytes as a byte[]).
    if addr < entry_end {
        if cie.augmentation.starts_with('z') {
            let Some((aug_data_len, l)) = read_uleb128(program, at(addr)) else { return };
            data.push((at(addr), "uleb128".to_string(), l as u32));
            addr += l as u64;
            addr += aug_data_len; // createAugmentationData: no unit
        }
        if addr < entry_end {
            let n = entry_end - addr;
            data.push((at(addr), format!("byte[{n}]"), n as u32));
        }
    }
}
