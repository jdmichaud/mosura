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
//! The odd id is the 32-bit variant: the low bit means offsets and lengths are 32-bit rather
//! than 16-bit. `FIXUPP` (`0x9C`) is deliberately **not** applied — relocated fields stay
//! zero, exactly as `scripts/extract-omf-code.py` leaves them, which is also what makes a
//! body's hash independent of where it would have been linked.

use super::elf::LoadError;
use crate::analysis::program::{Memory, Program, SymbolType};
use crate::decompile::space::{Address, SpaceId, SpaceKind, SpaceManager};

const LANGUAGE_ID: &str = "x86:LE:32:default";

/// Base address for the synthesised image. An object file has no load address — its segments
/// are position-independent until linked — so a nominal base is chosen. It cannot affect a
/// hash: the full hash masks every operand, and no relocation is applied.
const OBJ_BASE: u64 = 0x10000;

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
}

#[derive(Debug, Default, Clone)]
pub struct OmfSegment {
    pub name: String,
    pub data: Vec<u8>,
}

impl OmfSegment {
    /// Whether this segment holds code. Watcom and Borland both name it `_TEXT`; the
    /// convention is a `TEXT` suffix for any code segment (`BEGTEXT`, `FAR_TEXT`, …).
    pub fn is_code(&self) -> bool {
        self.name.ends_with("TEXT") || self.name.ends_with("CODE")
    }
}

/// Parse one module out of an OMF record stream.
pub fn parse_module(data: &[u8]) -> OmfModule {
    let mut module = OmfModule::default();
    let mut names: Vec<String> = Vec::new(); // LNAMES pool, 1-based

    for record in records(data) {
        let b = record.body;
        match record.kind {
            // THEADR / LHEADR
            0x80 | 0x82 => {
                if let Some((n, _)) = omf_name(b, 0) {
                    module.name = n;
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
                let is32 = record.kind & 1 == 1;
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
                module.segments.push(OmfSegment { name, data: vec![0u8; length as usize] });
            }
            // LEDATA / LEDATA32 — enumerated data at an offset within a segment.
            0xa0 | 0xa1 => {
                let is32 = record.kind & 1 == 1;
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
                let is32 = record.kind & 1 == 1;
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
            _ => {}
        }
    }
    module
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
    let module = parse_module(data);
    if module.segments.is_empty() {
        return Err(LoadError::Unsupported("OMF module declares no segments".into()));
    }

    let mut spaces = SpaceManager::standard();
    let ram = spaces.add("ram", SpaceKind::Processor, 4, 1);
    let mut memory = Memory::new();

    // Lay each non-empty segment at its own base, code first, so a public's address is
    // `segment_base + offset`.
    let mut base_of: Vec<u64> = vec![0; module.segments.len() + 1];
    let mut next = OBJ_BASE;
    for (i, segment) in module.segments.iter().enumerate() {
        if segment.data.is_empty() {
            continue;
        }
        base_of[i + 1] = next;
        memory.add_block(
            &segment.name,
            Address::new(ram, next),
            segment.data.len() as u64,
            true,
            !segment.is_code(),
            segment.is_code(),
            Some(segment.data.clone()),
        );
        // Page-align the next segment so addresses stay readable.
        next = (next + segment.data.len() as u64).next_multiple_of(0x1000);
    }

    let image_base = Address::new(ram, OBJ_BASE);
    let mut program = Program::new(spaces, ram, LANGUAGE_ID, "watcom", image_base, false, 32);
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

    Ok(program)
}

/// Whether these bytes look like an OMF object (`THEADR`/`LHEADR`) or library (`LIBHDR`).
pub fn is_omf(data: &[u8]) -> bool {
    matches!(data.first(), Some(0x80 | 0x82 | 0xf0))
}
