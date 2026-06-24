//! MZ loader — a port of Ghidra's `MzLoader` output (`app/util/opinion/MzLoader.java`):
//! an old-style 16-bit DOS MZ executable → a [`Program`] memory map matching Ghidra,
//! as `x86:LE:16:Real Mode`. (`object` doesn't decode the bare DOS load image, so the
//! MZ header + relocation table are parsed directly here.)
//!
//! Ghidra loads the image at segment `0x1000` and **discovers the segments in use from
//! the relocation table**: each relocation points at a far pointer in the image whose
//! segment word, after `+0x1000`, is a referenced segment. Those segments (plus the
//! initial `0x1000` and the entry `CS`) are sorted; each becomes a `CODE_<i>` block
//! spanning to the next segment, the last gets an uninitialized tail (`CODE_<i>u`) when
//! it runs past the file image, and a final `DATA` block of `e_minalloc` paragraphs is
//! appended. Addresses are flat-linear (`segment << 4`), matching Ghidra's
//! `SegmentedAddress.getOffset()`. Ghidra's `HEADER` block lives in a separate space
//! and so is not part of this (default-space) memory map.

use std::collections::BTreeSet;

use super::elf::LoadError;
use crate::analysis::program::{Memory, Program, SymbolType};
use crate::decompile::space::{Address, SpaceKind, SpaceManager};

/// Ghidra `INITIAL_SEGMENT_VAL` — the segment the image is loaded at.
const INITIAL_SEGMENT: u32 = 0x1000;

fn u16le(data: &[u8], off: usize) -> Option<u32> {
    data.get(off..off + 2).map(|b| u16::from_le_bytes([b[0], b[1]]) as u32)
}

/// Parse a DOS MZ image and build the [`Program`] memory map (A2).
pub fn load_mz(data: &[u8]) -> Result<Program, LoadError> {
    let field = |off: usize| u16le(data, off).ok_or(LoadError::Unsupported("truncated MZ header".into()));
    let e_cblp = field(0x02)?;
    let e_cp = field(0x04)?;
    let e_crlc = field(0x06)?;
    let e_cparhdr = field(0x08)?;
    let e_minalloc = field(0x0a)?;
    let e_ip = field(0x14)?;
    let e_cs = field(0x16)?;
    let e_lfarlc = field(0x18)?;

    let header_bytes = e_cparhdr << 4; // start of the load image in the file
    let addr_to_file_offset = |seg: u32| ((seg.wrapping_sub(INITIAL_SEGMENT) & 0xffff) << 4) + header_bytes;

    // Discover segments from valid relocation fixups (+ the initial and entry segments).
    let mut segments: BTreeSet<u32> = BTreeSet::new();
    for i in 0..e_crlc {
        let entry = e_lfarlc as usize + i as usize * 4;
        let (Some(off), Some(seg)) = (u16le(data, entry), u16le(data, entry + 2)) else { continue };
        let reloc_file_off = ((seg << 4) + off + header_bytes) as usize;
        if let Some(value) = u16le(data, reloc_file_off) {
            segments.insert((INITIAL_SEGMENT + value) & 0xffff);
        }
    }
    segments.insert(INITIAL_SEGMENT);
    if e_cs > 0 {
        segments.insert((INITIAL_SEGMENT + e_cs) & 0xffff);
    }

    // End of the file image (Ghidra: pagesToBytes(e_cp - 1) + e_cblp), capped at the file.
    let end_offset = (e_cp.saturating_sub(1) * 512 + e_cblp).min(data.len() as u32);

    let mut spaces = SpaceManager::standard();
    let ram = spaces.add("ram", SpaceKind::Processor, 8, 1);
    let mut memory = Memory::new();

    let ordered: Vec<u32> = segments.into_iter().collect();
    let mut last_end: Option<u32> = None;
    for (i, &seg) in ordered.iter().enumerate() {
        let seg_file_off = addr_to_file_offset(seg);
        let mut num_bytes: i64 = if i + 1 < ordered.len() {
            addr_to_file_offset(ordered[i + 1]) as i64 - seg_file_off as i64
        } else {
            end_offset as i64 - seg_file_off as i64
        };
        if num_bytes <= 0 {
            continue;
        }
        // Split into initialized + uninitialized when the segment runs past the image.
        let mut num_uninit: i64 = 0;
        if seg_file_off as i64 + num_bytes > end_offset as i64 {
            let calc = num_bytes;
            if seg_file_off as i64 > end_offset as i64 {
                num_bytes = 0;
                num_uninit = calc;
            } else {
                num_bytes = end_offset as i64 - seg_file_off as i64;
                num_uninit = calc - num_bytes;
            }
        }
        let linear = seg << 4; // segment:0 → flat-linear address
        if num_bytes > 0 {
            let off = seg_file_off as usize;
            let Some(bytes) = data.get(off..off + num_bytes as usize).map(|s| s.to_vec()) else {
                continue;
            };
            memory.add_block(&format!("CODE_{i}"), Address::new(ram, linear as u64), num_bytes as u64, true, true, true, Some(bytes));
            last_end = Some(linear + num_bytes as u32 - 1);
        }
        if num_uninit > 0 {
            let ustart = linear + num_bytes as u32;
            memory.add_block(&format!("CODE_{i}u"), Address::new(ram, ustart as u64), num_uninit as u64, true, true, false, None);
            last_end = Some(ustart + num_uninit as u32 - 1);
        }
    }

    // Minimum-allocation data space appended after the image (Ghidra's `DATA` block).
    if let Some(end) = last_end {
        let extra = e_minalloc << 4;
        if extra > 0 {
            memory.add_block("DATA", Address::new(ram, (end + 1) as u64), extra as u64, true, true, false, None);
        }
    }

    let mut program = Program::new(spaces, ram, "x86:LE:16:Real Mode", "default", Address::new(ram, 0), false, 16);
    program.memory = memory;

    // Entry point at CS:IP (Ghidra MzLoader.processEntryPoint): a label `entry`, also an
    // external entry point. Linear = ((0x1000 + e_cs) & 0xffff) << 4 + e_ip.
    let entry = Address::new(ram, ((((INITIAL_SEGMENT + e_cs) & 0xffff) << 4) + e_ip) as u64);
    program.symbol_table.add_symbol(entry, "entry", SymbolType::Label);
    program.entry_points.push(entry);

    Ok(program)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn external(path: &str, name: &str) -> Option<Vec<u8>> {
        std::fs::read(path).ok().or_else(|| {
            eprintln!("skip {name}: {path} not present");
            None
        })
    }

    fn check(path: &str, name: &str, golden: &str) {
        let Some(data) = external(path, name) else { return };
        let prog = load_mz(&data).unwrap_or_else(|e| panic!("load {name}: {e}"));
        let snap = prog.snapshot();
        assert_eq!(snap.addr_size, 16);
        let g = crate::analysis::snapshot::parse(
            &std::fs::read_to_string(crate::paths::analysis_goldens_dir().join(golden)).unwrap(),
        );
        assert_eq!(snap.blocks, g.blocks, "{name} MZ memory map mismatch");
        assert_eq!(snap.functions, g.functions, "{name} MZ functions mismatch");
        assert_eq!(snap.entries, g.entries, "{name} MZ entry points mismatch");
        assert_eq!(snap.symbols, g.symbols, "{name} MZ symbols mismatch");
    }

    #[test]
    fn comcom32_memory_map_matches_golden() {
        check("/home/jd/.local/share/comcom32/comcom32.exe", "comcom32", "comcom32.loaded.snapshot");
    }

    #[test]
    fn war2_memory_map_matches_golden() {
        check("/home/jd/WAR2.EXE", "war2", "war2.loaded.snapshot");
    }
}
