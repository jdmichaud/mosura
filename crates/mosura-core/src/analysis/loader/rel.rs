//! SDCC / ASxxxx `.rel` object loader — the input side of FID ingest for the sdcc columns.
//!
//! SDCC's linker objects are **ASCII**, not a binary container: a `.rel` file is a sequence of
//! one-letter records, and a `.lib` is a Unix `ar` archive of them. This is a third object
//! format alongside ELF and OMF, and it exists for the same reason as those readers — ingest
//! needs an analyzed program per object, with the function bodies to hash and the symbols to
//! name them.
//!
//! ```text
//! XL4                          radix/format header: X = hex, L = little-endian, 4 = 4-byte addresses
//! H 1 areas 5 global symbols   counts
//! M __itoa                     module name
//! O -mz80 sdcccall(1)          the options it was assembled with
//! S ___uitobcd Ref00000000     an external reference
//! A _CODE size D5 flags 0 addr 0   an area (segment); symbols after it belong to it
//! S ___itoa Def00000000        a symbol defined at that offset within the area
//! T 00 00 00 00 DD E5 ...      text: a 4-byte little-endian address, then data bytes
//! R 00 00 00 00                relocations for the preceding T; bytes 2..4 are the area index
//! ```
//!
//! Relocations against **external symbols are applied**, exactly as the OMF reader applies
//! `FIXUPP`: each referenced name gets a slot in a synthetic `EXTERNAL` block and the call's
//! operand is patched to reach it. Without that, every cross-module call points at address 0,
//! no callee is named, and no caller/callee relation is recorded — which cost this library all
//! 229 of its relations, leaving the 19% of functions that score below the 14.6 threshold on
//! body size alone unidentifiable.
//!
//! An `R` line's entries are 4 bytes each — `mode, offset, index-lo, index-hi` — where the
//! offset is measured from the start of the `T` line's payload (so it includes the 4 address
//! bytes) and `mode & 0x02` means the index selects a **symbol** rather than an area.

use super::elf::LoadError;
use crate::analysis::program::{Memory, Program, SymbolType};
use crate::decompile::space::{Address, SpaceKind, SpaceManager};

const LANGUAGE_ID: &str = "z80:LE:16:default";

/// One area (segment) of a `.rel` module.
#[derive(Debug, Default, Clone)]
pub struct RelArea {
    pub name: String,
    pub data: Vec<u8>,
}

impl RelArea {
    /// SDCC names its code area `_CODE`; `_HOME`/`_GSINIT`/`_GSFINAL` are also executable
    /// startup areas. Everything else (`_DATA`, `_BSS`, `_INITIALIZED`, …) is data.
    pub fn is_code(&self) -> bool {
        matches!(self.name.as_str(), "_CODE" | "_HOME" | "_GSINIT" | "_GSFINAL")
            || self.name.ends_with("CODE")
    }
}

/// One parsed `.rel` module.
#[derive(Debug, Default)]
pub struct RelModule {
    pub name: String,
    pub areas: Vec<RelArea>,
    /// `(name, area index, offset)` for each defined symbol.
    pub defined: Vec<(String, usize, u64)>,
    /// Names this module references but does not define.
    pub referenced: Vec<String>,
    /// Every symbol in file order — the order a relocation's index refers to.
    pub symbol_order: Vec<String>,
    /// Relocations against an external symbol: `(area index, offset, name)`.
    pub external_relocs: Vec<(usize, usize, String)>,
}

fn hex(s: &str) -> Option<u64> {
    u64::from_str_radix(s.trim(), 16).ok()
}

/// Parse one `.rel` module.
pub fn parse_module(text: &str) -> RelModule {
    let mut module = RelModule::default();
    // Symbols follow the area they belong to; `A` lines set the current one.
    let mut current_area: Option<usize> = None;
    // A `T` record's area comes from the `R` record that follows it, so the text is held
    // until that arrives.
    let mut pending: Option<(u64, Vec<u8>)> = None;

    for line in text.lines() {
        let f: Vec<&str> = line.split_whitespace().collect();
        let Some(&tag) = f.first() else { continue };
        match tag {
            "M" => module.name = f.get(1).copied().unwrap_or_default().to_string(),
            "A" => {
                // A <name> size <hex> flags <n> addr <hex>
                let name = f.get(1).copied().unwrap_or_default().to_string();
                let size = f
                    .iter()
                    .position(|&x| x == "size")
                    .and_then(|i| f.get(i + 1))
                    .and_then(|s| hex(s))
                    .unwrap_or(0);
                current_area = Some(module.areas.len());
                module.areas.push(RelArea { name, data: vec![0u8; size as usize] });
            }
            "S" => {
                // S <name> Def<hex8> | Ref<hex8>
                let (Some(name), Some(kind)) = (f.get(1), f.get(2)) else { continue };
                module.symbol_order.push((*name).to_string());
                if let Some(off) = kind.strip_prefix("Def") {
                    // `.__.ABS.` is the absolute-section marker, not a real symbol.
                    if *name == ".__.ABS." {
                        continue;
                    }
                    if let (Some(area), Some(off)) = (current_area, hex(off)) {
                        module.defined.push(((*name).to_string(), area, off));
                    }
                } else if kind.starts_with("Ref") {
                    module.referenced.push((*name).to_string());
                }
            }
            "T" => {
                // T <a0> <a1> <a2> <a3> <data…> — a 4-byte little-endian address, then bytes.
                if f.len() < 5 {
                    pending = None;
                    continue;
                }
                let bytes: Vec<u8> =
                    f[1..].iter().filter_map(|b| u8::from_str_radix(b, 16).ok()).collect();
                if bytes.len() < 4 {
                    pending = None;
                    continue;
                }
                let addr = u64::from(bytes[0])
                    | u64::from(bytes[1]) << 8
                    | u64::from(bytes[2]) << 16
                    | u64::from(bytes[3]) << 24;
                pending = Some((addr, bytes[4..].to_vec()));
            }
            "R" => {
                // R <flags-lo> <flags-hi> <area-lo> <area-hi> [relocation entries…]
                let Some((addr, data)) = pending.take() else { continue };
                let idx = f
                    .get(3)
                    .and_then(|b| u8::from_str_radix(b, 16).ok())
                    .map(usize::from)
                    .unwrap_or(0)
                    | f.get(4)
                        .and_then(|b| u8::from_str_radix(b, 16).ok())
                        .map(|b| usize::from(b) << 8)
                        .unwrap_or(0);
                // Relocation entries follow the 4-byte header, 4 bytes each.
                let entries: Vec<u8> =
                    f[5..].iter().filter_map(|b| u8::from_str_radix(b, 16).ok()).collect();
                for e in entries.chunks_exact(4) {
                    let (mode, offset, sym) =
                        (e[0], usize::from(e[1]), usize::from(e[2]) | usize::from(e[3]) << 8);
                    // `mode & 0x02` — the index is a symbol, not an area.
                    if mode & 0x02 == 0 {
                        continue;
                    }
                    let Some(name) = module.symbol_order.get(sym) else { continue };
                    if !module.referenced.iter().any(|r| r == name) {
                        continue; // defined here; the linker would resolve it locally
                    }
                    // The offset counts the T line's 4 address bytes.
                    let Some(field) = offset.checked_sub(4) else { continue };
                    module.external_relocs.push((idx, addr as usize + field, name.clone()));
                }

                let Some(area) = module.areas.get_mut(idx) else { continue };
                let start = addr as usize;
                let end = (start + data.len()).min(area.data.len());
                if start < end {
                    area.data[start..end].copy_from_slice(&data[..end - start]);
                }
            }
            _ => {}
        }
    }
    module
}

/// Split a Unix `ar` archive into its members' contents.
///
/// SDCC ships `z80.lib` and friends as plain `ar` archives, so this is the same 60-byte
/// header walk `ar x` performs — worth doing in-process so `fid-build` can be pointed at the
/// library rather than at a directory of extracted members.
pub fn split_archive(data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    if !data.starts_with(b"!<arch>\n") {
        return out;
    }
    let mut at = 8usize;
    while at + 60 <= data.len() {
        let size = std::str::from_utf8(&data[at + 48..at + 58])
            .ok()
            .and_then(|s| s.trim().parse::<usize>().ok());
        let Some(size) = size else { break };
        let start = at + 60;
        let end = start + size;
        if end > data.len() {
            break;
        }
        out.push(&data[start..end]);
        // Members are padded to an even offset.
        at = end + (end % 2);
    }
    out
}

/// Where a `.rel` module's areas are laid out. An object has no load address of its own; the
/// base only has to be non-zero and out of the way, and cannot affect a hash (the full hash
/// masks every operand).
const REL_BASE: u64 = 0x1000;

/// Bytes reserved per external symbol in the synthetic `EXTERNAL` block.
const EXTERNAL_SLOT: u64 = 2;

/// Load one `.rel` module as a program: its areas laid out consecutively, with a function
/// symbol at every defined symbol in a code area.
pub fn load_rel_object(text: &str) -> Result<Program, LoadError> {
    let mut module = parse_module(text);
    if module.areas.iter().all(|a| a.data.is_empty()) {
        return Err(LoadError::Unsupported("rel module has no area content".into()));
    }

    let mut spaces = SpaceManager::standard();
    let ram = spaces.add("ram", SpaceKind::Processor, 2, 1);
    let mut memory = Memory::new();

    let mut base_of = vec![0u64; module.areas.len()];
    let mut next = REL_BASE;
    for (i, area) in module.areas.iter().enumerate() {
        if area.data.is_empty() {
            continue;
        }
        base_of[i] = next;
        memory.add_block(
            &area.name,
            Address::new(ram, next),
            area.data.len() as u64,
            true,
            !area.is_code(),
            area.is_code(),
            Some(area.data.clone()),
        );
        next += area.data.len() as u64;
    }

    // One slot per referenced name, and patch each relocation to reach it — the same device
    // the ELF and OMF loaders use for undefined symbols. Without it a cross-module call
    // targets address 0 and contributes no relation.
    let external_base = next;
    let mut externals: Vec<String> = module.referenced.clone();
    externals.sort();
    externals.dedup();
    for (area_index, offset, name) in std::mem::take(&mut module.external_relocs) {
        let Some(slot) = externals.iter().position(|n| *n == name) else { continue };
        let target = external_base + slot as u64 * EXTERNAL_SLOT;
        let Some(area) = module.areas.get_mut(area_index) else { continue };
        if offset + 2 > area.data.len() {
            continue;
        }
        // Z80 `CALL nnnn` takes an absolute 16-bit operand.
        let Ok(word) = u16::try_from(target) else { continue };
        area.data[offset..offset + 2].copy_from_slice(&word.to_le_bytes());
    }
    // Re-emit the code blocks now that they carry the patched operands.
    let mut memory = Memory::new();
    for (i, area) in module.areas.iter().enumerate() {
        if area.data.is_empty() {
            continue;
        }
        memory.add_block(
            &area.name,
            Address::new(ram, base_of[i]),
            area.data.len() as u64,
            true,
            !area.is_code(),
            area.is_code(),
            Some(area.data.clone()),
        );
    }
    if !externals.is_empty() {
        memory.add_block(
            "EXTERNAL",
            Address::new(ram, external_base),
            externals.len() as u64 * EXTERNAL_SLOT,
            true,
            false,
            true,
            None,
        );
    }

    let image_base = Address::new(ram, REL_BASE);
    let mut program = Program::new(spaces, ram, LANGUAGE_ID, "default", image_base, false, 16);
    program.memory = memory;

    for (i, name) in externals.iter().enumerate() {
        let addr = Address::new(ram, external_base + i as u64 * EXTERNAL_SLOT);
        program.symbol_table.add_external_symbol(addr, name, SymbolType::Function);
    }

    for (name, area_index, offset) in &module.defined {
        let Some(area) = module.areas.get(*area_index) else { continue };
        let base = base_of.get(*area_index).copied().unwrap_or(0);
        if base == 0 {
            continue;
        }
        let addr = Address::new(ram, base + offset);
        if area.is_code() {
            program.symbol_table.add_symbol(addr, name, SymbolType::Function);
            program.entry_points.push(addr);
        } else {
            program.symbol_table.add_symbol(addr, name, SymbolType::Label);
        }
    }

    Ok(program)
}

/// Whether these bytes look like an SDCC/ASxxxx `.rel` object.
pub fn is_rel(data: &[u8]) -> bool {
    // The first record is the radix/format header, e.g. `XL4`.
    data.first().is_some_and(|&b| b == b'X')
        && data.get(1).is_some_and(|&b| b == b'L' || b == b'H')
}
