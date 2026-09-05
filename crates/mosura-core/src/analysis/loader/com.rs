//! CP/M `.COM` loader — a raw flat Z80 image (no container). CP/M loads a `.COM` file into
//! the Transient Program Area at `0x100` and begins execution there, so the whole file maps
//! contiguously at `0x100` in a single block and the entry point is `0x100`.
//!
//! **Ghidra parallel.** Ghidra has no `.COM` loader; a raw image is imported via the generic
//! `BinaryLoader` with the processor + load base set manually (`-processor z80:LE:16:default
//! -loader-baseAddr 0x100`) and the entry marked by hand (a headless pre-script, mirrored by
//! `SetComEntry.java` — see `scripts/capture-analysis.sh`). This loader encodes that same
//! knowledge: the language, the `0x100` base/entry, and — a port of
//! `AbstractProgramLoader.applyProcessorLabels` → `Language.getDefaultSymbols()` — the Z80
//! processor spec's default symbols (the RST/NMI vector labels), read from the `.pspec`.
//! Validated against the analyzeHeadless golden as a clean subset (`tests/analysis_parity.rs`).

use super::elf::LoadError;
use crate::analysis::program::{Memory, Program, SymbolType};
use crate::decompile::space::{Address, SpaceId, SpaceKind, SpaceManager};

/// CP/M Transient Program Area — a `.COM` loads here and execution starts here.
const CPM_TPA: u64 = 0x100;

const LANGUAGE_ID: &str = "z80:LE:16:default";
const COMPILER_SPEC_ID: &str = "default";

/// Load a raw CP/M `.COM` image into a [`Program`]: one `ram` block at `0x100`, the Z80
/// processor-spec default symbols, and the `0x100` entry point.
pub fn load_com(data: &[u8]) -> Result<Program, LoadError> {
    if data.is_empty() {
        return Err(LoadError::Unsupported("empty .COM image".into()));
    }

    let mut spaces = SpaceManager::standard();
    let ram = spaces.add("ram", SpaceKind::Processor, 2, 1); // 16-bit address space
    let mut memory = Memory::new();

    // The whole file loads contiguously at the TPA. CP/M has no memory protection: the TPA is
    // read/write/execute (code, data, and stack all live here).
    memory.add_block(
        "ram",
        Address::new(ram, CPM_TPA),
        data.len() as u64,
        true,
        true,
        true,
        Some(data.to_vec()),
    );

    // Ghidra's `BinaryLoader` leaves the program image base at 0 (the load address is a
    // separate option), so the analyzeHeadless golden reports base 0 — match it.
    let image_base = Address::new(ram, 0);
    let mut program =
        Program::new(spaces, ram, LANGUAGE_ID, COMPILER_SPEC_ID, image_base, false, 16);
    program.memory = memory;

    // Processor-spec default symbols (Ghidra `AbstractProgramLoader.applyProcessorLabels` →
    // `Language.getDefaultSymbols()`): the Z80 pspec declares the RST/NMI vector labels
    // (RST0..RST7 + NMI_ISR), each an entry point. Read them from the `.pspec` so this is a
    // faithful port of whatever the processor spec defines, not a hardcoded list.
    apply_default_symbols(ram, &mut program);

    // The CP/M entry point at the TPA (0x100). No symbol is created (Ghidra's loaded golden
    // has none — the entry renders as the dynamic `EXT_ram_0100`); auto-analysis creates the
    // function here from the entry seed.
    program.entry_points.push(Address::new(ram, CPM_TPA));

    Ok(program)
}

/// Apply the Z80 processor spec's `<default_symbols>` (Ghidra `Language.getDefaultSymbols()`):
/// each `<symbol name=.. address="ram:OFFSET" entry=..>` becomes a `Label`, and an entry
/// point when `entry="true"`. Parsed from the resolved `.pspec` so it tracks the spec.
fn apply_default_symbols(ram: SpaceId, program: &mut Program) {
    let Some((_, pspec_path)) = crate::lang::resolve(LANGUAGE_ID) else { return };
    let Some(text) = crate::resources::get().read_string(pspec_path.to_str().unwrap_or("")) else { return };
    let Ok(doc) = roxmltree::Document::parse(&text) else { return };
    for sym in doc
        .descendants()
        .filter(|n| n.tag_name().name() == "default_symbols")
        .flat_map(|ds| ds.children())
        .filter(|n| n.tag_name().name() == "symbol")
    {
        let (Some(name), Some(addr_str)) = (sym.attribute("name"), sym.attribute("address")) else {
            continue;
        };
        // Address is `space:offset` (e.g. `ram:0066`); only the ram-space defaults are modeled.
        let Some((space, off)) = addr_str.split_once(':') else { continue };
        if space != "ram" {
            continue;
        }
        let Ok(offset) = u64::from_str_radix(off, 16) else { continue };
        let addr = Address::new(ram, offset);
        program.symbol_table.add_with_primary(addr, name, SymbolType::Label, true);
        if sym.attribute("entry") == Some("true") {
            program.entry_points.push(addr);
        }
    }
}
