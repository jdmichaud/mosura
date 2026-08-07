//! OMF object/library loader — the input side of FID library ingest for the Watcom and
//! Borland columns.
//!
//! An OMF (Relocatable Object Module Format) `.OBJ` is a stream of records; a `.LIB` is a
//! concatenation of such modules with a dictionary. Ghidra has an `OmfLoader`; this is the
//! slice of it FID needs — enough to lay a module's code segment in memory and attach the
//! names its `PUBDEF` records declare.
//!
//! **Why a loader at all.** Ingest needs an *analyzed program per object file*: the function
//! bodies to hash and the symbols to name them. Without this, the only route into a Watcom
//! runtime was a linked executable, which captures just the handful of routines one program
//! happens to pull in.
//!
//! Records used (Intel OMF, `TIS OMF 1.1`):
//!
//! | record | id | why |
//! | --- | --- | --- |
//! | `THEADR` / `LHEADR` | `0x80` / `0x82` | module name |
//! | `LNAMES` | `0x96` | the name pool `SEGDEF` indexes into |
//! | `SEGDEF` | `0x98`/`0x99` | segment sizes and their names (`_TEXT`, `_DATA`, …) |
//! | `LEDATA` | `0xA0`/`0xA1` | the segment's actual bytes |
//! | `LIDATA` | `0xA2`/`0xA3` | run-length-encoded bytes |
//! | `PUBDEF` | `0x90`/`0x91` | public symbols: `(name, segment, offset)` |
//! | `MODEND` | `0x8A`/`0x8B` | end of module |
//!
//! | `EXTDEF` | `0x8C` | external symbol names a call can target |
//! | `FIXUPP` | `0x9C`/`0x9D` | relocations — which call sites target which external |
//!
//! The odd id is the 32-bit variant: the low bit means offsets and lengths are 32-bit rather
//! than 16-bit.
//!
//! ## Easy OMF-386
//!
//! Watcom 9.01 (and other early 386 toolchains) emit a variant in which the record **ids stay
//! even** — `SEGDEF` is `0x98`, not `0x99` — while the length and offset fields inside are
//! nonetheless **32-bit**. It is announced by a `COMENT` of class `0xAA` whose text is
//! `"80386"`, which every such module carries near its head.
//!
//! Without honouring it, a `SEGDEF` body of `28 | 43 01 00 00 | 06 02 01` is read as a 16-bit
//! length followed by name indexes taken from the wrong offsets — the segment ends up unnamed,
//! so nothing is classified as code, and the whole library yields no functions. That is exactly
//! what Watcom 9.01's `clib3r.lib` did: 351 members parsed, 507 publics found, **0 code
//! bytes**.
//!
//! ## Why fixups must be applied
//!
//! An unlinked `call` to another module has a **zero displacement** — the linker has not filled
//! it in yet. In Watcom's `CLIB3R.LIB` that is 714 of 847 call sites. Left alone, `E8 00 00 00
//! 00` does not merely look odd: Ghidra's x86 spec has a *separate, more specific* constructor
//! for a zero displacement (`ia.sinc:2964`, `simm32=0`) whose semantics are `goto`, **not
//! `call`**. So every unresolved call would be hashed as a jump, would not be subtracted from
//! `codeUnitSize`, and would contribute no callee relation — making every signature in the
//! database systematically disagree with the same function in a linked binary.
//!
//! So external fixups are resolved: each external name gets a slot in a synthetic `EXTERNAL`
//! block (the same device `loader/elf.rs` uses for undefined symbols), and self-relative call
//! displacements are patched to reach it. The *hash* is unaffected by where that slot sits —
//! the full hash masks the displacement away entirely, and a slot address is far larger than
//! the 256 cutoff that would let the specific hash keep it — so this restores the call flow
//! without making a body's signature depend on our synthetic layout.

use super::elf::LoadError;
use crate::analysis::program::{Memory, Program, SymbolType};
use crate::decompile::space::{Address, SpaceKind, SpaceManager};

/// 32-bit modules (Watcom 386, Borland C++ 4.x/5 flat models).
const LANGUAGE_ID_32: &str = "x86:LE:32:default";
/// 16-bit modules (Turbo C, Borland C++ 2.x/3.x, and the small/compact/medium/large/huge
/// memory-model libraries every DOS-era Borland ships). Same language the MZ loader uses.
const LANGUAGE_ID_16: &str = "x86:LE:16:Real Mode";

/// Base address for the synthesised image. An object file has no load address — its segments
/// are position-independent until linked — so a nominal base is chosen. It cannot affect a
/// hash: the full hash masks every operand, and no relocation is applied.
const OBJ_BASE: u64 = 0x10000;

/// Bytes reserved per external symbol in the synthetic `EXTERNAL` block. Ghidra's ELF loader
/// uses one pointer per undefined symbol; the value only has to keep the slots distinct.
const EXTERNAL_SLOT: u64 = 8;

/// One record of the OMF stream.
struct Record<'a> {
    kind: u8,
    body: &'a [u8],
}

/// Split an OMF stream into records. Each is `type(1) length(2, LE) payload checksum(1)`,
/// where `length` counts the payload **plus** the checksum byte.
fn records(data: &[u8]) -> Vec<Record<'_>> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at + 3 <= data.len() {
        let kind = data[at];
        let len = u16::from_le_bytes([data[at + 1], data[at + 2]]) as usize;
        if len == 0 || at + 3 + len > data.len() {
            break;
        }
        // The trailing byte is the checksum, excluded from the payload.
        out.push(Record { kind, body: &data[at + 3..at + 3 + len - 1] });
        at += 3 + len;
        if kind == 0x8a || kind == 0x8b {
            break; // MODEND terminates the module
        }
    }
    out
}

/// A length-prefixed OMF string.
fn omf_name(data: &[u8], at: usize) -> Option<(String, usize)> {
    let len = *data.get(at)? as usize;
    let bytes = data.get(at + 1..at + 1 + len)?;
    Some((String::from_utf8_lossy(bytes).to_string(), at + 1 + len))
}

/// An OMF index: one byte, or two when the high bit of the first is set.
fn omf_index(data: &[u8], at: usize) -> Option<(usize, usize)> {
    let b = *data.get(at)? as usize;
    if b & 0x80 == 0 {
        Some((b, at + 1))
    } else {
        let b2 = *data.get(at + 1)? as usize;
        Some(((b & 0x7f) << 8 | b2, at + 2))
    }
}

/// One parsed module.
#[derive(Debug, Default)]
pub struct OmfModule {
    pub name: String,
    /// Per segment index (1-based): its name and reconstructed bytes.
    pub segments: Vec<OmfSegment>,
    /// `(name, segment index, offset)` from `PUBDEF`.
    pub publics: Vec<(String, usize, u64)>,
    /// `EXTDEF` names, in declaration order (the 1-based index fixups refer to).
    pub externals: Vec<String>,
    /// Self-relative fixups targeting an external: `(segment index, offset of the displacement
    /// field, external index, field width in bytes)`.
    pub external_fixups: Vec<(usize, usize, usize, usize)>,
}

#[derive(Debug, Default, Clone)]
pub struct OmfSegment {
    pub name: String,
    pub data: Vec<u8>,
    /// The `P` bit of the segment's ACBP attribute: a USE32 segment. This is how a 16-bit
    /// Turbo C object is told from a 32-bit one — the record ids do not say (and under Easy
    /// OMF-386 they actively mislead).
    pub use32: bool,
}

impl OmfSegment {
    /// Whether this segment holds code. Watcom and Borland both name it `_TEXT`; the
    /// convention is a `TEXT` suffix for any code segment (`BEGTEXT`, `FAR_TEXT`, …). Borland's
    /// 16-bit memory models also emit per-module `<module>_TEXT` segments, which this covers.
    pub fn is_code(&self) -> bool {
        self.name.ends_with("TEXT") || self.name.ends_with("CODE")
    }
}

impl OmfModule {
    /// The Ghidra language this module's code is written for, decided by its code segments'
    /// USE32 attribute rather than assumed. A DOS-era Borland or Turbo C library is 16-bit;
    /// Watcom 386 and Borland's flat models are 32-bit, and a library can hold either.
    pub fn language_id(&self) -> &'static str {
        let any32 = self.segments.iter().any(|s| s.is_code() && s.use32);
        if any32 {
            LANGUAGE_ID_32
        } else {
            LANGUAGE_ID_16
        }
    }
}

/// Parse one module out of an OMF record stream.
pub fn parse_module(data: &[u8]) -> OmfModule {
    let mut module = OmfModule::default();
    let mut names: Vec<String> = Vec::new(); // LNAMES pool, 1-based
    // A FIXUPP's offsets are relative to the LEDATA record immediately before it.
    let mut last_ledata: Option<(usize, usize)> = None;
    // Easy OMF-386: even record ids, 32-bit fields (see the module docs).
    let mut easy_omf_386 = false;

    for record in records(data) {
        let b = record.body;
        match record.kind {
            // THEADR / LHEADR
            0x80 | 0x82 => {
                if let Some((n, _)) = omf_name(b, 0) {
                    module.name = n;
                }
            }
            // COMENT — class 0xAA with text "80386" declares Easy OMF-386.
            0x88 => {
                // COMENT body: attributes(1), class(1), then the comment text.
                if b.len() >= 2 && b[1] == 0xaa && b[2..].starts_with(b"80386") {
                    easy_omf_386 = true;
                }
            }
            // LNAMES
            0x96 => {
                let mut at = 0;
                while let Some((n, next)) = omf_name(b, at) {
                    names.push(n);
                    at = next;
                    if at >= b.len() {
                        break;
                    }
                }
            }
            // SEGDEF / SEGDEF32
            0x98 | 0x99 => {
                let is32 = record.kind & 1 == 1 || easy_omf_386;
                let Some(&attr) = b.first() else { continue };
                let mut at = 1;
                // An ACBP byte with A=0 (absolute) carries frame+offset we skip.
                if attr >> 5 == 0 {
                    at += 3;
                }
                let length = if is32 {
                    let v = b.get(at..at + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as u64);
                    at += 4;
                    v
                } else {
                    let v = b.get(at..at + 2).map(|s| u16::from_le_bytes([s[0], s[1]]) as u64);
                    at += 2;
                    v
                };
                let Some(length) = length else { continue };
                let name = omf_index(b, at)
                    .and_then(|(idx, _)| names.get(idx.checked_sub(1)?).cloned())
                    .unwrap_or_default();
                module.segments.push(OmfSegment {
                    name,
                    data: vec![0u8; length as usize],
                    use32: attr & 0x01 != 0 || easy_omf_386,
                });
            }
            // LEDATA / LEDATA32 — enumerated data at an offset within a segment.
            0xa0 | 0xa1 => {
                let is32 = record.kind & 1 == 1 || easy_omf_386;
                let Some((seg, at)) = omf_index(b, 0) else { continue };
                let (offset, at) = if is32 {
                    let Some(s) = b.get(at..at + 4) else { continue };
                    (u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize, at + 4)
                } else {
                    let Some(s) = b.get(at..at + 2) else { continue };
                    (u16::from_le_bytes([s[0], s[1]]) as usize, at + 2)
                };
                let payload = &b[at.min(b.len())..];
                if let Some(segment) = seg.checked_sub(1).and_then(|i| module.segments.get_mut(i)) {
                    let end = (offset + payload.len()).min(segment.data.len());
                    if offset < end {
                        segment.data[offset..end].copy_from_slice(&payload[..end - offset]);
                    }
                }
            }
            // PUBDEF / PUBDEF32
            0x90 | 0x91 => {
                let is32 = record.kind & 1 == 1 || easy_omf_386;
                let Some((group, at)) = omf_index(b, 0) else { continue };
                let Some((seg, mut at)) = omf_index(b, at) else { continue };
                if group == 0 && seg == 0 {
                    at += 2; // an absolute PUBDEF carries a frame number
                }
                while at < b.len() {
                    let Some((name, next)) = omf_name(b, at) else { break };
                    at = next;
                    let offset = if is32 {
                        let Some(s) = b.get(at..at + 4) else { break };
                        at += 4;
                        u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as u64
                    } else {
                        let Some(s) = b.get(at..at + 2) else { break };
                        at += 2;
                        u16::from_le_bytes([s[0], s[1]]) as u64
                    };
                    let Some((_type, next)) = omf_index(b, at) else { break };
                    at = next;
                    module.publics.push((name, seg, offset));
                }
            }
            // EXTDEF — external names, 1-based in declaration order.
            0x8c => {
                let mut at = 0;
                while let Some((name, next)) = omf_name(b, at) {
                    module.externals.push(name);
                    // Each name is followed by a type index.
                    match omf_index(b, next) {
                        Some((_, n)) => at = n,
                        None => break,
                    }
                    if at >= b.len() {
                        break;
                    }
                }
            }
            // FIXUPP / FIXUPP32
            0x9c | 0x9d => parse_fixupp(b, last_ledata, easy_omf_386, &mut module),
            _ => {}
        }
        // A FIXUPP's offsets are relative to the LEDATA record it follows.
        if matches!(record.kind, 0xa0 | 0xa1) {
            if let Some((seg, at)) = omf_index(record.body, 0) {
                let is32 = record.kind & 1 == 1 || easy_omf_386;
                let offset = if is32 {
                    record.body.get(at..at + 4).map(|s| u32::from_le_bytes([s[0], s[1], s[2], s[3]]) as usize)
                } else {
                    record.body.get(at..at + 2).map(|s| u16::from_le_bytes([s[0], s[1]]) as usize)
                };
                last_ledata = offset.map(|o| (seg, o));
            }
        }
    }
    module
}

/// Parse a `FIXUPP` record, keeping the self-relative fixups that target an external symbol.
///
/// A subrecord with the high bit clear is a THREAD (a reusable frame/target specification); we
/// do not need them, because a call fixup states its target explicitly. With the high bit set
/// it is a FIXUP:
///
/// ```text
/// byte 0:  1 M LLLL OO      M = 1 segment-relative, 0 self-relative
///                           LLLL = location type (9 = 32-bit offset)
///                           OO = high 2 bits of the data-record offset
/// byte 1:  offset low 8 bits
/// byte 2:  F FRAME(3) T P TARGT(2)     the "fix dat" byte
///          then frame datum (if F=0), target datum (if T=0), displacement (if P=0)
/// ```
fn parse_fixupp(
    b: &[u8],
    last_ledata: Option<(usize, usize)>,
    easy_omf_386: bool,
    module: &mut OmfModule,
) {
    let Some((segment, data_offset)) = last_ledata else { return };
    let mut at = 0usize;
    while at < b.len() {
        let first = b[at];
        if first & 0x80 == 0 {
            // THREAD subrecord: a method byte, then its datum.
            let method = (first >> 2) & 0x07;
            at += 1;
            if method < 4 {
                match omf_index(b, at) {
                    Some((_, n)) => at = n,
                    None => return,
                }
            }
            continue;
        }
        let Some(&second) = b.get(at + 1) else { return };
        let self_relative = first & 0x40 == 0;
        let location = (first >> 2) & 0x0f;
        let record_offset = (usize::from(first & 0x03) << 8) | usize::from(second);
        at += 2;

        let Some(&fix_dat) = b.get(at) else { return };
        at += 1;
        let frame_explicit = fix_dat & 0x80 == 0;
        let frame_method = (fix_dat >> 4) & 0x07;
        let target_explicit = fix_dat & 0x08 == 0;
        let target_method = fix_dat & 0x03;
        let has_displacement = fix_dat & 0x04 == 0;

        if frame_explicit && frame_method < 3 {
            match omf_index(b, at) {
                Some((_, n)) => at = n,
                None => return,
            }
        }
        let mut target_datum = 0usize;
        if target_explicit {
            match omf_index(b, at) {
                Some((d, n)) => {
                    target_datum = d;
                    at = n;
                }
                None => return,
            }
        }
        if has_displacement {
            // 32-bit displacement in a FIXUPP32 record, 16-bit otherwise; both are skipped.
            at += if location == 9 || location == 13 || easy_omf_386 { 4 } else { 2 };
        }

        // Target method 2 = EXTDEF index. Location 9/13 = a 32-bit offset field, which is what
        // a `call rel32` carries.
        //
        // Location 9/13 are 32-bit offset fields, which is what a `call rel32` carries.
        // Locations 1 and 5 are the 16-bit plain and loader-resolved offsets — a `call rel16`,
        // as every DOS-era Borland and Turbo C library uses.
        //
        // Under Easy OMF-386 the location codes are reinterpreted along with everything else,
        // and those nominally-16-bit codes denote **32-bit** offsets. Watcom 9.01 emits
        // location 5 for its cross-module calls, so rejecting it left them unpatched — 391
        // functions but only 6 relations, against 426 for the same library built by 10.0a.
        let width = match location {
            9 | 13 => Some(4),
            1 | 5 if easy_omf_386 => Some(4),
            1 | 5 => Some(2),
            _ => None,
        };
        if let (true, true, true, Some(width)) =
            (target_explicit, target_method == 2, self_relative, width)
        {
            module.external_fixups.push((
                segment,
                data_offset + record_offset,
                target_datum,
                width,
            ));
        }
    }
}

/// Split an OMF `.LIB` into its member modules.
///
/// A Microsoft/Watcom OMF library begins with a `LIBHDR` (`0xF0`) whose record length gives
/// the page size; every member starts on a page boundary. Walking pages and parsing whatever
/// begins with `THEADR`/`LHEADR` is robust against the dictionary layout differences between
/// vendors.
pub fn split_library(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    if data.first() != Some(&0xf0) {
        return out;
    }
    let page = u16::from_le_bytes([data[1], data[2]]) as usize + 3;
    if page == 0 {
        return out;
    }
    let mut at = page;
    while at + 3 <= data.len() {
        match data[at] {
            0x80 | 0x82 => {
                out.push(&data[at..]);
                // Advance past this module: find its MODEND, then round up to a page.
                let mut cursor = at;
                while cursor + 3 <= data.len() {
                    let kind = data[cursor];
                    let len = u16::from_le_bytes([data[cursor + 1], data[cursor + 2]]) as usize;
                    if len == 0 {
                        break;
                    }
                    cursor += 3 + len;
                    if kind == 0x8a || kind == 0x8b {
                        break;
                    }
                }
                at = cursor.div_ceil(page) * page;
            }
            // 0xF1 is the library trailer/dictionary.
            0xf1 => break,
            _ => at += page,
        }
    }
    out
}

/// Load one OMF module as a program: its code segments laid out consecutively from
/// [`OBJ_BASE`], with a function symbol at every `PUBDEF`.
pub fn load_omf_object(data: &[u8]) -> Result<Program, LoadError> {
    let mut module = parse_module(data);
    if module.segments.is_empty() {
        return Err(LoadError::Unsupported("OMF module declares no segments".into()));
    }

    let mut spaces = SpaceManager::standard();
    let ram = spaces.add("ram", SpaceKind::Processor, 4, 1);
    // (address size stays 4 bytes: a 16-bit module's synthetic layout still uses linear
    // offsets, and the language decides how code is decoded)

    // Lay each non-empty segment at its own base, so a public's address is `base + offset`.
    let mut base_of: Vec<u64> = vec![0; module.segments.len() + 1];
    let mut next = OBJ_BASE;
    for (i, segment) in module.segments.iter().enumerate() {
        if segment.data.is_empty() {
            continue;
        }
        base_of[i + 1] = next;
        // Page-align the next segment so addresses stay readable.
        next = (next + segment.data.len() as u64).next_multiple_of(0x1000);
    }
    let external_base = next;

    // Resolve external call sites before the bytes are handed to memory. An unlinked call has
    // a zero displacement, which decodes as a `goto` rather than a `call` (see the module
    // docs); patching it to reach the symbol's slot restores the flow. The displacement of a
    // `call rel32` is relative to the end of its 4-byte field.
    let mut patched = 0usize;
    for &(segment, offset, external, width) in &module.external_fixups {
        let Some(base) = base_of.get(segment).copied().filter(|b| *b != 0) else { continue };
        let Some(index) = external.checked_sub(1) else { continue };
        if index >= module.externals.len() {
            continue;
        }
        let Some(seg) = segment.checked_sub(1).and_then(|i| module.segments.get_mut(i)) else {
            continue;
        };
        if offset + width > seg.data.len() {
            continue;
        }
        let target = external_base + index as u64 * EXTERNAL_SLOT;
        let site = base + offset as u64;
        let displacement = target as i64 - (site as i64 + width as i64);
        if width == 2 {
            // A 16-bit displacement can only reach ±32 KB. The slots sit just past the code,
            // so this holds for any realistic module; a fixup that cannot reach is left
            // unpatched rather than silently wrapped into a wrong target.
            let Ok(narrow) = i16::try_from(displacement) else { continue };
            seg.data[offset..offset + 2].copy_from_slice(&narrow.to_le_bytes());
        } else {
            seg.data[offset..offset + 4].copy_from_slice(&(displacement as i32).to_le_bytes());
        }
        patched += 1;
    }
    let _ = patched;

    let mut memory = Memory::new();
    for (i, segment) in module.segments.iter().enumerate() {
        if segment.data.is_empty() {
            continue;
        }
        memory.add_block(
            &segment.name,
            Address::new(ram, base_of[i + 1]),
            segment.data.len() as u64,
            true,
            !segment.is_code(),
            segment.is_code(),
            Some(segment.data.clone()),
        );
    }
    // One slot per external name, so a patched call has somewhere to land. Uninitialized, like
    // `loader/elf.rs`'s EXTERNAL block for undefined symbols.
    if !module.externals.is_empty() {
        memory.add_block(
            "EXTERNAL",
            Address::new(ram, external_base),
            module.externals.len() as u64 * EXTERNAL_SLOT,
            true,
            false,
            true,
            None,
        );
    }

    let language = module.language_id();
    let bits = if language == LANGUAGE_ID_32 { 32 } else { 16 };
    // The compiler spec is the caller's to declare — an OMF module does not reliably say
    // which vendor produced it, and `fid-build` knows because the operator names the library.
    // `watcom` is the default because it is the spec mosura ships for x86-32 OMF; a 16-bit
    // module takes `default`, matching the MZ loader.
    let cspec = if bits == 32 { "watcom" } else { "default" };
    let image_base = Address::new(ram, OBJ_BASE);
    let mut program = Program::new(spaces, ram, language, cspec, image_base, false, bits);
    program.memory = memory;

    // Publics in a code segment are function entry points; the rest are data labels.
    for (name, seg, offset) in &module.publics {
        let Some(segment) = seg.checked_sub(1).and_then(|i| module.segments.get(i)) else {
            continue;
        };
        let base = base_of.get(*seg).copied().unwrap_or(0);
        if base == 0 {
            continue;
        }
        let addr = Address::new(ram, base + offset);
        if segment.is_code() {
            program.symbol_table.add_symbol(addr, name, SymbolType::Function);
            program.entry_points.push(addr);
        } else {
            program.symbol_table.add_symbol(addr, name, SymbolType::Label);
        }
    }

    // Name each external slot, so a call to it resolves to that name during ingest. Marked
    // EXTERNAL: the slot is a name for a routine defined in another module, not a body we can
    // hash, and ingest must skip it rather than count it as an unhashable function.
    for (i, name) in module.externals.iter().enumerate() {
        let addr = Address::new(ram, external_base + i as u64 * EXTERNAL_SLOT);
        program.symbol_table.add_external_symbol(addr, name, SymbolType::Function);
    }

    Ok(program)
}

/// Whether these bytes look like an OMF object (`THEADR`/`LHEADR`) or library (`LIBHDR`).
pub fn is_omf(data: &[u8]) -> bool {
    matches!(data.first(), Some(0x80 | 0x82 | 0xf0))
}
