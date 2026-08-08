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
pub mod relocation;
pub mod symbol;

pub use address_set::{AddressRange, AddressSet};
pub use function::{Function, FunctionManager};
pub use listing::{CodeUnit, Listing};
pub use memory::{Memory, MemoryBlock};
pub use reference::{RefType, Reference, ReferenceManager};
pub use relocation::{Relocation, RelocationTable};
pub use symbol::{Symbol, SymbolTable, SymbolType};

use crate::analysis::snapshot::{self, Snapshot};
use crate::decompile::space::{Address, SpaceId, SpaceManager};

/// A listing comment's position, as Ghidra's `CodeUnit` constants name them
/// (`EOL_COMMENT`, `PRE_COMMENT`, `POST_COMMENT`, `PLATE_COMMENT`, `REPEATABLE_COMMENT`).
///
/// Only `Plate` has a producer today (FID's library-match markup); the rest exist so the key
/// space matches Ghidra's from the start rather than being widened later.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CommentKind {
    Eol,
    Pre,
    Post,
    Plate,
    Repeatable,
}

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
    /// The `ProgramInformation.Compiler` info property (Ghidra `Program.getCompiler()`), e.g.
    /// `clang:unknown` — the compiler *label* the PE opinion detects (distinct from the
    /// compiler-spec id). Defaults to `unknown` (Ghidra's default), overridden by the PE loader.
    pub compiler: String,
    /// Beyond-Ghidra: the specific compiler **version** read from the toolchain's embedded marker
    /// (`loader::compiler_version`), e.g. `msvc:6.0` / `gcc:14-win32` / `borland:c++:1994`. `None`
    /// when no marker is present. Refines the family opinion in `compiler`; never replaces it.
    pub compiler_version: Option<String>,
    /// Beyond-Ghidra: the compiler build identified by matching **library signatures**
    /// (`fid::detect`), e.g. `Borland tc2.0 cl` or `Visual Studio 1998 Release`.
    ///
    /// A second, independent line of evidence to [`Self::compiler_version`]'s embedded marker,
    /// and the *only* one available where a format carries no metadata — a raw z80 `.com` has
    /// no header, sections or symbol table, and sdcc writes no version string into compiled
    /// output. Set only on a confident vote; `None` otherwise. Refines, never replaces
    /// [`Self::compiler`].
    pub compiler_signature: Option<String>,
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
    /// The loader's relocation records (Ghidra `Program.getRelocationTable`). Empty and
    /// non-relocatable unless a loader populates it — in that state every consumer's filter is
    /// inert, so the ELF/PE/COM paths behave exactly as they did before it existed. Today only
    /// the LE loader fills it, from the binary's own fixup table.
    pub relocation_table: RelocationTable,
    /// Listing comments, keyed by `(address, kind)` — Ghidra `Listing.setComment`.
    ///
    /// Analysis results that are not a name. The first user is FID: when it recognises a
    /// function but the matches cannot be collapsed to one name, Ghidra deliberately does NOT
    /// rename, yet still records what it found as a plate comment. Without somewhere to put
    /// that, a recognised-but-ambiguous function is indistinguishable from an unrecognised one.
    ///
    /// Not part of [`Snapshot`], so it does not affect the Ghidra-compared goldens.
    pub comments: std::collections::BTreeMap<(u64, CommentKind), String>,
    /// Offsets of disassembled indirect branches (`BRANCHIND`) — switch candidates the
    /// decompiler-driven switch analyzer (A6) decompiles to recover jump tables; recorded
    /// by the disassembler so the analyzer only decompiles functions that need it.
    pub indirect_branches: std::collections::HashSet<u64>,
    /// Addresses flagged "No Return" (Ghidra `Function.setNoReturn(true)`) by the
    /// non-returning-function analyzer — the function entry itself and any PLT thunk that
    /// resolves to it. A direct call to one of these does not fall through (the disassembler
    /// stops linear decode after the call). `(space, offset)` keys.
    pub noreturn_functions: std::collections::HashSet<(u32, u64)>,
    /// Defined data units (Ghidra `Listing.getDefinedData`): `(address, datatype-name,
    /// byte-length)`. Populated by the data-markup analyzers (A7 Task 5) — e.g. the GCC
    /// exception-frame analyzer's `eh_frame_hdr` / `fde_table_entry` structures. The
    /// snapshot's `data` section is projected from this; the datatype names are Ghidra's
    /// (`DWordDataType.getName()` etc.), so a comparison is a clean subset of the oracle.
    pub defined_data: Vec<(Address, String, u32)>,
    /// Per-instruction FLOW OVERRIDES (Ghidra `Instruction.setFlowOverride` /
    /// `getFlowOverride`), keyed `(space, offset)`. Ghidra keeps this in the code unit's own
    /// flag bits (`InstructionDB.java:54`, `FLOW_OVERRIDE_SET_MASK`); mosura keeps it beside the
    /// listing, like `noreturn_functions` and `indirect_branches`.
    ///
    /// **It is what analysis decided, and it outranks the instruction's own bytes.** Ghidra's
    /// `getFlowType()` (:321) is `getModifiedFlowType(proto.getFlowType(this), flowOverride)`,
    /// and every fall-through decision goes through that (`getDefaultFallThrough`, :926). Only
    /// `FlowOverride::None` entries are absent; see
    /// [`overridden_flow_props`](crate::analysis::flowtype::overridden_flow_props).
    pub flow_overrides: std::collections::HashMap<(u32, u64), crate::analysis::flowtype::FlowOverride>,
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
            // Ghidra `Program.getCompiler()` defaults to "unknown"; the PE loader overrides it
            // with the compiler-opinion label.
            compiler: "unknown".to_string(),
            compiler_version: None,
            compiler_signature: None,
            image_base,
            big_endian,
            addr_size_bits,
            memory: Memory::new(),
            symbol_table: SymbolTable::new(),
            function_manager: FunctionManager::new(),
            listing: Listing::new(),
            entry_points: Vec::new(),
            reference_manager: ReferenceManager::new(),
            relocation_table: RelocationTable::new(),
            comments: std::collections::BTreeMap::new(),
            indirect_branches: std::collections::HashSet::new(),
            noreturn_functions: std::collections::HashSet::new(),
            defined_data: Vec::new(),
            flow_overrides: std::collections::HashMap::new(),
        }
    }

    /// Whether the function at `addr` is flagged "No Return" (Ghidra `Function.isNoReturn`).
    pub fn is_noreturn(&self, addr: Address) -> bool {
        self.noreturn_functions.contains(&(addr.space.0, addr.offset))
    }

    /// `Instruction.getFlowOverride()` — the flow override on the instruction at `addr`, or
    /// `FlowOverride::None` when analysis has set none.
    pub fn flow_override_at(&self, addr: Address) -> crate::analysis::flowtype::FlowOverride {
        self.flow_overrides
            .get(&(addr.space.0, addr.offset))
            .copied()
            .unwrap_or(crate::analysis::flowtype::FlowOverride::None)
    }

    /// `Instruction.setFlowOverride(flow)` (InstructionDB.java:615), as driven by
    /// `SetFlowOverrideCmd`. Returns `false` when the override is already what is being set —
    /// Ghidra's `if (flow == flowOverride) return;` (:622), which is also what lets a caller
    /// mirror `processFunctionJumpReferences`'s "already overridden, skip" guard (:417).
    pub fn set_flow_override(
        &mut self,
        addr: Address,
        flow: crate::analysis::flowtype::FlowOverride,
    ) -> bool {
        use crate::analysis::flowtype::FlowOverride;
        let key = (addr.space.0, addr.offset);
        if self.flow_override_at(addr) == flow {
            return false;
        }
        if flow == FlowOverride::None {
            self.flow_overrides.remove(&key);
        } else {
            self.flow_overrides.insert(key, flow);
        }
        true
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
        let data = self
            .defined_data
            .iter()
            .filter(|(a, _, _)| a.space == self.default_space)
            .map(|(a, ty, len)| snapshot::Data {
                addr: a.offset,
                type_name: ty.clone(),
                len: *len,
            })
            .collect();
        let mut snap = Snapshot {
            lang: self.language_id.clone(),
            compiler: self.compiler_spec_id.clone(),
            compiler_info: self.compiler.clone(),
            compiler_version: self.compiler_version.clone().unwrap_or_default(),
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
            data,
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
