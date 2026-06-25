//! The `Program` database — a port of Ghidra's `program/model` aggregate
//! (`Program`/`Memory`/`Listing`/`SymbolTable`/`FunctionManager`), plus the
//! `AddressSet` algebra (A1; plan `docs/analysis-port-plan.md` §2, §6).
//!
//! This is the **shared mutable state every analyzer reads and writes** — the
//! `Funcdata`-equivalent foundation for the analysis port. Built on the decompiler's
//! [`Address`]/[`SpaceManager`](crate::decompile::space::SpaceManager), it adds the
//! memory map, code units, symbols, and functions a loaded program carries. The
//! loader (A2) populates [`Memory`]; disassembly/function-discovery (A4) populate
//! [`Listing`] and [`FunctionManager`]. [`Program::snapshot`] projects the converged
//! state into the oracle [`Snapshot`](crate::analysis::snapshot::Snapshot) the parity
//! harness diffs.

pub mod address_set;
pub mod function;
pub mod listing;
pub mod memory;
pub mod reference;
pub mod symbol;

pub use address_set::{AddressRange, AddressSet};
pub use function::{Function, FunctionManager};
pub use listing::{CodeUnit, Listing};
pub use memory::{Memory, MemoryBlock};
pub use reference::{RefType, Reference, ReferenceManager};
pub use symbol::{Symbol, SymbolTable, SymbolType};

use crate::analysis::snapshot::{self, Snapshot};
use crate::decompile::space::{Address, SpaceId, SpaceManager};

/// The whole-program database (Ghidra `Program`).
#[derive(Clone, Debug)]
pub struct Program {
    pub spaces: SpaceManager,
    /// The default (code/data) address space — `ram` on x86-64. The snapshot's loaded
    /// memory map is the blocks in this space.
    pub default_space: SpaceId,
    /// Language id, e.g. `x86:LE:64:default` (Ghidra `getLanguageID`).
    pub language_id: String,
    /// Compiler-spec id, e.g. `gcc` (Ghidra `getCompilerSpec().getCompilerSpecID()`).
    pub compiler_spec_id: String,
    pub image_base: Address,
    pub big_endian: bool,
    /// Address size in bits (e.g. 64).
    pub addr_size_bits: u32,
    pub memory: Memory,
    pub symbol_table: SymbolTable,
    pub function_manager: FunctionManager,
    pub listing: Listing,
    /// External entry points (Ghidra `SymbolTable.addExternalEntryPoint`) — the
    /// addresses analysis seeds disassembly from. Populated by the loader.
    pub entry_points: Vec<Address>,
    pub reference_manager: ReferenceManager,
    /// Offsets of disassembled indirect branches (`BRANCHIND`) — switch candidates the
    /// decompiler-driven switch analyzer (A6) decompiles to recover jump tables; recorded
    /// by the disassembler so the analyzer only decompiles functions that need it.
    pub indirect_branches: std::collections::HashSet<u64>,
    /// Addresses flagged "No Return" (Ghidra `Function.setNoReturn(true)`) by the
    /// non-returning-function analyzer — the function entry itself and any PLT thunk that
    /// resolves to it. A direct call to one of these does not fall through (the disassembler
    /// stops linear decode after the call). `(space, offset)` keys.
    pub noreturn_functions: std::collections::HashSet<(u32, u64)>,
}

impl Program {
    /// A fresh, empty program for the given language/space layout. The loader (A2)
    /// fills `memory`; later analyzers fill the rest.
    pub fn new(
        spaces: SpaceManager,
        default_space: SpaceId,
        language_id: &str,
        compiler_spec_id: &str,
        image_base: Address,
        big_endian: bool,
        addr_size_bits: u32,
    ) -> Program {
        Program {
            spaces,
            default_space,
            language_id: language_id.to_string(),
            compiler_spec_id: compiler_spec_id.to_string(),
            image_base,
            big_endian,
            addr_size_bits,
            memory: Memory::new(),
            symbol_table: SymbolTable::new(),
            function_manager: FunctionManager::new(),
            listing: Listing::new(),
            entry_points: Vec::new(),
            reference_manager: ReferenceManager::new(),
            indirect_branches: std::collections::HashSet::new(),
            noreturn_functions: std::collections::HashSet::new(),
        }
    }

    /// Whether the function at `addr` is flagged "No Return" (Ghidra `Function.isNoReturn`).
    pub fn is_noreturn(&self, addr: Address) -> bool {
        self.noreturn_functions.contains(&(addr.space.0, addr.offset))
    }

    /// Project the converged program into the v1 analysis [`Snapshot`] (the oracle
    /// format). Mirrors `oracle/ghidra_scripts/DumpAnalysisSnapshot.java`: the loaded
    /// memory map is the blocks in the default space; functions are every function.
    pub fn snapshot(&self) -> Snapshot {
        let blocks = self
            .memory
            .blocks()
            .filter(|b| b.start().space == self.default_space)
            .map(|b| snapshot::Block {
                start: b.start().offset,
                end: b.end().offset,
                name: b.name().to_string(),
            })
            .collect();
        let functions = self
            .function_manager
            .functions()
            .map(|f| snapshot::Function { entry: f.entry_point().offset, name: f.name().to_string() })
            .collect();
        let entries = self
            .entry_points
            .iter()
            .filter(|a| a.space == self.default_space)
            .map(|a| snapshot::EntryPoint {
                addr: a.offset,
                name: self.symbol_table.primary_at(*a).map(|s| s.name().to_string()).unwrap_or_default(),
            })
            .collect();
        let symbols = self
            .symbol_table
            .symbols()
            .filter(|s| s.address().space == self.default_space)
            .map(|s| snapshot::Symbol {
                addr: s.address().offset,
                name: s.name().to_string(),
                kind: match s.symbol_type() {
                    SymbolType::Function => "Function",
                    SymbolType::Label => "Label",
                    SymbolType::Data => "Data",
                }
                .to_string(),
            })
            .collect();
        let refs = self
            .reference_manager
            .references()
            .filter(|r| r.from.space == self.default_space && r.to.space == self.default_space)
            .map(|r| snapshot::Ref {
                from: r.from.offset,
                to: r.to.offset,
                kind: r.ref_type.name().to_string(),
            })
            .collect();
        let code_units = self
            .listing
            .code_units()
            .filter(|(a, u)| {
                a.space == self.default_space && matches!(u, listing::CodeUnit::Instruction { .. })
            })
            .map(|(a, _)| a.offset)
            .collect();
        let bodies = self
            .function_manager
            .functions()
            .filter(|f| f.entry_point().space == self.default_space)
            .filter(|f| !f.body().is_empty())
            .map(|f| snapshot::FnBody {
                entry: f.entry_point().offset,
                ranges: f
                    .body()
                    .ranges()
                    .filter(|r| r.space == self.default_space)
                    .map(|r| (r.min, r.max))
                    .collect(),
            })
            .collect();
        let mut snap = Snapshot {
            lang: self.language_id.clone(),
            compiler: self.compiler_spec_id.clone(),
            base: self.image_base.offset,
            endian: if self.big_endian { "big".into() } else { "little".into() },
            addr_size: self.addr_size_bits,
            blocks,
            functions,
            entries,
            symbols,
            refs,
            code_units,
            bodies,
        };
        snap.normalize();
        snap
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::space::SpaceKind;

    /// Build a Program mirroring freestanding.elf and confirm its snapshot projection
    /// reproduces the committed golden's body (header + block + func lines). This ties
    /// A1's projection to the A0 oracle without yet needing the loader (A2).
    #[test]
    fn snapshot_projection_matches_freestanding_golden_body() {
        let mut spaces = SpaceManager::standard();
        let ram = spaces.add("ram", SpaceKind::Processor, 8, 1);
        let base = Address::new(ram, 0x0040_0000);
        let mut p = Program::new(spaces, ram, "x86:LE:64:default", "gcc", base, false, 64);

        // 3 loaded blocks (as Ghidra's loader lays them down)
        p.memory.add_block("segment_0.1", Address::new(ram, 0x0040_0000), 0x120, true, false, false, None);
        p.memory.add_block(".note.gnu.build-id", Address::new(ram, 0x0040_0120), 0x24, true, false, false, None);
        p.memory.add_block(".text", Address::new(ram, 0x0040_1000), 0x79, true, false, true, None);

        // 3 recovered functions
        for (off, name) in [(0x0040_1000, "add"), (0x0040_1014, "sum_to"), (0x0040_1042, "_start")] {
            p.function_manager.create_function(Address::new(ram, off), name, AddressSet::new());
        }

        let produced = p.snapshot();

        // compare against the committed golden, ignoring `#` comment lines (header line is
        // generated/identical; the second comment records the capture source).
        let golden_text = std::fs::read_to_string(
            crate::paths::analysis_goldens_dir().join("freestanding.snapshot"),
        )
        .expect("freestanding golden");
        let golden = snapshot::parse(&golden_text);

        assert_eq!(produced.blocks, golden.blocks, "memory map mismatch");
        assert_eq!(produced.functions, golden.functions, "functions mismatch");
        // header fields project correctly
        assert_eq!((produced.lang, produced.base), (golden.lang, golden.base));
    }
}
