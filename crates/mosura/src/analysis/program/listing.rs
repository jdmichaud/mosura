//! `Listing` / `CodeUnit` — a port of Ghidra's `program/model/listing/` code-unit
//! view: every address is either an `Instruction`, a `Data` item, or undefined.
//!
//! **Minimal in A1** — the container + types exist so analyzers have somewhere to lay
//! down code/data, but it is populated by **A4** (disassembly + function discovery).

use std::collections::HashMap;

use crate::analysis::flowtype::FlowKind;
use crate::decompile::space::Address;

/// The flow properties a laid-down instruction carries — Ghidra's `InstructionDB` record.
///
/// ⭐ **WHY THIS IS STORED, AND WHY IT IS THE PORT.** Ghidra never re-parses bytes to answer a
/// flow question. `InstructionDB` keeps the prototype's flow type and its static flow
/// destinations on the record, and every later reader asks the record: `FollowFlow`
/// (FollowFlow.java:534, :557) takes its targets from `getReferencesFrom()` and its fall-through
/// from `Instruction.getFallThrough()`, and `CreateFunctionCmd.getFunctionBody` (:613-627) is
/// nothing but a `FollowFlow`. mosura's `CodeUnit::Instruction` used to carry only `length`, so
/// every body walk had to run the SLEIGH decoder again over code it had already decoded —
/// **measured at 46 µs per instruction and 94% of the whole body-walk cost** (mingw_hello.exe:
/// 1.18 s of 1.25 s). That, multiplied by the number of body recomputations, is the quadratic in
/// task #5, and it is a missing field rather than a missing algorithm.
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct InstructionFlow {
    /// `SleighInstructionPrototype.getFlowType(instr)` — the prototype flow type, BEFORE any
    /// flow override (Ghidra applies the override at read time in `InstructionDB.getFlowType`,
    /// :321, so the stored value must be the un-overridden one).
    pub kind: FlowKind,
    /// `Instruction.getFlows()` — the prototype's static flow destinations in the default space,
    /// minus a self-target (SLEIGH lifts `hlt` to `BRANCH <self>`, for which Ghidra emits no
    /// flow edge). Empty for an instruction with no static flow.
    pub flows: Vec<u64>,
    /// Whether the LAST p-code op ends the flow (`RETURN`/`BRANCH`/`BRANCHIND`) — the input to
    /// mosura's un-overridden fall-through derivation.
    ///
    /// ⚠️ Deliberately NOT `kind.has_fallthrough()`. mosura derives the base case from the last
    /// p-code op while Ghidra derives it from the prototype flow type; the two disagree on any
    /// instruction with an internal p-code loop (`rep movs`). That divergence is pre-existing and
    /// documented on `analyzers::falls_through`; this field caches it verbatim so making the walk
    /// listing-driven changes *nothing* but the cost. Converting the base derivation is its own
    /// change.
    pub ends_flow: bool,
    /// The static target of the instruction's trailing `CALL` op, if the last op is a call — the
    /// input to the no-return check in `analyzers::falls_through`.
    pub call_target: Option<u64>,
}

/// A defined code unit at an address (Ghidra `CodeUnit`: `Instruction` or `Data`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CodeUnit {
    /// A disassembled instruction occupying `length` bytes, with the flow properties Ghidra's
    /// `InstructionDB` keeps on the record (see [`InstructionFlow`]).
    Instruction { length: u32, flow: InstructionFlow },
    /// A defined data item of `length` bytes, with its data-type name.
    Data { length: u32, type_name: String },
}

impl CodeUnit {
    pub fn length(&self) -> u32 {
        match self {
            CodeUnit::Instruction { length, .. } | CodeUnit::Data { length, .. } => *length,
        }
    }

    /// An instruction code unit with no flow — the plain fall-through case. For callers that only
    /// need "an instruction is defined here" (tests, and the pattern/table ports that probe
    /// `code_unit_at`); the disassembler always stores the real [`InstructionFlow`].
    pub fn instruction(length: u32) -> CodeUnit {
        CodeUnit::Instruction { length, flow: InstructionFlow::default() }
    }
}

/// The defined code units of the program, keyed by start address (Ghidra `Listing`).
///
/// Hash-keyed by `(space, offset)` so `define`/`code_unit_at` are O(1): the program can
/// hold hundreds of thousands of code units, and the disassembler probes `code_unit_at`
/// once per instruction — a Vec scan/sort made disassembly quadratic. Iteration order is
/// imposed by the snapshot.
#[derive(Clone, Default, Debug)]
pub struct Listing {
    units: HashMap<(u32, u64), (Address, CodeUnit)>,
    /// Ordered index of instruction start addresses — the backing for Ghidra's
    /// `Listing.getInstructionAfter`, which `AddressTable.getEntry` calls once per candidate
    /// table (a scan of the hash map is O(listing) and WAR2 holds >100k instructions).
    instruction_starts: std::collections::BTreeSet<(u32, u64)>,
}

impl Listing {
    pub fn new() -> Listing {
        Listing::default()
    }

    pub fn define(&mut self, addr: Address, unit: CodeUnit) {
        if matches!(unit, CodeUnit::Instruction { .. }) {
            self.instruction_starts.insert((addr.space.0, addr.offset));
        }
        self.units.insert((addr.space.0, addr.offset), (addr, unit));
    }

    /// Remove the code unit STARTING at `addr` (the unit half of Ghidra's `ClearCmd`, which
    /// `ClearFlowAndRepairCmd` drives). Returns whether a unit was removed. The caller owns
    /// the reference half (`ReferenceManager::remove_refs_from_set`) and any flow-override
    /// stored for the address — Ghidra keeps both on the instruction record, so clearing it
    /// clears them; mosura stores them beside the listing.
    pub fn undefine(&mut self, addr: Address) -> bool {
        self.instruction_starts.remove(&(addr.space.0, addr.offset));
        self.units.remove(&(addr.space.0, addr.offset)).is_some()
    }

    /// The first instruction starting strictly after `addr`, in `addr`'s space (Ghidra
    /// `Listing.getInstructionAfter`).
    pub fn instruction_after(&self, addr: Address) -> Option<Address> {
        self.instruction_starts
            .range((addr.space.0, addr.offset + 1)..)
            .next()
            .filter(|(s, _)| *s == addr.space.0)
            .map(|(s, o)| Address::new(crate::decompile::space::SpaceId(*s), *o))
    }

    pub fn code_unit_at(&self, addr: Address) -> Option<&CodeUnit> {
        self.units.get(&(addr.space.0, addr.offset)).map(|(_, u)| u)
    }

    /// The instruction starting exactly at `addr` — its length and stored flow properties
    /// (Ghidra `Listing.getInstructionAt`). `None` at an undefined address or on defined data,
    /// which is what makes a `FollowFlow` walk stop there.
    pub fn instruction_at(&self, addr: Address) -> Option<(u32, &InstructionFlow)> {
        match self.units.get(&(addr.space.0, addr.offset)).map(|(_, u)| u) {
            Some(CodeUnit::Instruction { length, flow }) => Some((*length, flow)),
            _ => None,
        }
    }

    /// The code unit whose `[start, start+length)` range contains `addr` (Ghidra
    /// `Listing.getCodeUnitContaining`), returning its start address and length. Probes
    /// backward within the maximum code-unit length (x86 instructions are ≤ 16 bytes; data
    /// items can be longer, but this is used only for instruction fall-through queries).
    pub fn code_unit_containing(&self, addr: Address, max_len: u64) -> Option<(Address, u64)> {
        for back in 0..=max_len {
            let off = addr.offset.checked_sub(back)?;
            if let Some((start, unit)) = self.units.get(&(addr.space.0, off)) {
                let len = u64::from(unit.length());
                if off + len > addr.offset {
                    return Some((*start, len));
                }
            }
        }
        None
    }

    pub fn code_units(&self) -> impl Iterator<Item = (Address, &CodeUnit)> {
        self.units.values().map(|(a, u)| (*a, u))
    }

    pub fn is_empty(&self) -> bool {
        self.units.is_empty()
    }

    /// Number of defined code units (Ghidra `Listing.getNumCodeUnits`). Used as half the
    /// staleness key of the analysis-time body refresh
    /// ([`crate::analysis::analyzers::refresh_function_bodies`]): a body goes stale when code is
    /// laid down, not only when the function set grows.
    pub fn len(&self) -> usize {
        self.units.len()
    }
}
