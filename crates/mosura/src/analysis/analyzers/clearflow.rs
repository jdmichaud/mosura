//! `ClearFlowAndRepairCmd` — a port of Ghidra's
//! `app/plugin/core/clear/ClearFlowAndRepairCmd.java`, scoped to the configuration its one
//! auto-analysis caller uses: `FindNoReturnFunctionsAnalyzer.repairDamagedLocations` (:187)
//! constructs `ClearFlowAndRepairCmd(clearInstSet, protectedSet, clearData=true,
//! clearLabels=false, repair=true)`.
//!
//! From each seed (the fall-through of a call to a non-returning function — wrong code laid
//! before the no-return verdict existed), the command:
//!
//!  1. builds the flow graph of basic blocks transitively reachable from the seed
//!     (`findInstructionFlow`, :645, over `SimpleBlockModel`);
//!  2. PRUNES every block justified from OUTSIDE the graph — a fall-from outside, a flow
//!     reference from outside, an unreferenced function at the block start (:755-796; prune
//!     keeps the block AND everything reachable from it, :997);
//!  3. clears what remains — code units plus their references (`ClearCmd`, :209);
//!  4. REPAIRS: re-disassembles fall-throughs into the cleared area (:501), flow-referenced
//!     destinations inside it (:433), and external entry points (:474). The re-disassembly
//!     requests ride the command queue, which is exactly Ghidra's shape (`DisassembleCommand`).
//!
//! **Scope reductions, each named** (nothing else is simplified):
//!  - defined-DATA clearing and `clearComputedTableRefs` (:255) are not ported — mosura's
//!    analysis listing holds data only from the loaders, never from bad flow;
//!  - the OFFCUT arms (`clearOffcutFlow`, :821; the destAddrs offcut filter, :730) are not
//!    ported — seeds arrive at unit starts (`findRepairLocations` checks
//!    `getInstructionAt`), and mosura's listing refuses overlapping definitions;
//!  - `addDereferencedInstructionStarts` (:286) is not ported — it extends the clear through
//!    DATA pointers dereferenced by cleared code, a class the corpus has not exhibited;
//!  - delay slots (SPARC/MIPS) do not exist on x86;
//!  - bookmarks and label clearing (`clearLabels=false` here anyway) have no mosura model;
//!  - the seed-context repair (:449-457) is not ported — Ghidra's own TODO at :454 records
//!    that the collected context "is never used by the disassembler".
//!  - Ghidra skips a destination whose function symbol source is ≥ IMPORTED (:719-728);
//!    mosura has no symbol-source model, so the guard is "a function with a non-default
//!    (non-`FUN_`) name" — the loader/user-named set, which is what the source check means.

use crate::analysis::analyzers::falls_through_stored;
use crate::analysis::manager::Scheduling;
use crate::analysis::program::{AddressSet, CodeUnit, Program};
use crate::decompile::space::Address;
use std::collections::{BTreeMap, BTreeSet};

/// `FALLTHROUGH_SEARCH_LIMIT` (:41) — how far `repairFallThroughsInto` scans backward for
/// the instruction that fell into a cleared range.
const FALLTHROUGH_SEARCH_LIMIT: u64 = 12;

/// `ClearFlowAndRepairCmd(startAddrs, protectedSet, true, false, true).applyTo` (:76).
pub fn clear_flow_and_repair(
    program: &mut Program,
    start_addrs: &AddressSet,
    protected: &AddressSet,
    sched: &mut Scheduling,
) {
    let ram = program.default_space;
    let mut clear_set = AddressSet::new();

    // :83-152 — collect the todo starts from the code units at the start addresses.
    let mut todo: Vec<u64> = Vec::new();
    for off in start_addrs.ranges().flat_map(|r| r.min..=r.max) {
        let addr = Address::new(ram, off);
        match program.listing.code_unit_at(addr) {
            Some(CodeUnit::Instruction { .. }) => {
                // :111 — a function at the start will be picked up by flow if appropriate.
                if program.function_manager.function_at(addr).is_some() {
                    continue;
                }
                // :116-119 — fall-from also in startAddrs: the flow walk covers it.
                if let Some(ff) = fall_from(program, addr) {
                    if start_addrs.contains(ff) {
                        continue;
                    }
                }
                todo.push(off);
            }
            Some(CodeUnit::Data { .. }) => {} // defined data: out of scope (module note)
            None => {
                // :141-144 — failed disassembly at a seed: "pretend we cleared it".
                clear_set.add(addr);
            }
        }
    }

    // :154 — with a single start, its own address must not be re-disassembled by repair.
    let do_not_repair: Option<u64> = if todo.len() == 1 { Some(todo[0]) } else { None };

    // :159-194 — grow the clear set from each start.
    while let Some(off) = todo.pop() {
        let addr = Address::new(ram, off);
        if clear_set.contains(addr) || protected.contains(addr) {
            continue;
        }
        if !matches!(program.listing.code_unit_at(addr), Some(CodeUnit::Instruction { .. })) {
            continue;
        }
        let block_set = find_instruction_flow(program, addr, &clear_set, start_addrs, protected);
        clear_set = clear_set.union(&block_set);
    }

    // :204 — protected locations survive no matter how they were reached.
    clear_set = clear_set.subtract(protected);
    if clear_set.is_empty() {
        return;
    }

    // :206-210 — ClearCmd: remove the units, their references, and their flow overrides
    // (Ghidra stores the override on the instruction record; clearing it clears both).
    for off in clear_set.ranges().flat_map(|r| r.min..=r.max) {
        let addr = Address::new(ram, off);
        if program.listing.undefine(addr) {
            program.flow_overrides.remove(&(ram.0, off));
        }
    }
    program.reference_manager.remove_refs_from_set(&clear_set);

    // :234-236 — repair flows into the cleared area.
    repair_flows_into(program, &clear_set, do_not_repair, sched);
    // :237-239 repairFunctions — body recomputation; `compute_function_bodies` runs to
    // convergence after the fixpoint, and the body-refresh memo observes both the listing
    // and the reference generation, so the cleared units invalidate it.
}

/// The instruction falling through INTO `addr`, if any — `Instruction.getFallFrom`.
fn fall_from(program: &Program, addr: Address) -> Option<Address> {
    let (start, _len) = program
        .listing
        .code_unit_containing(Address::new(addr.space, addr.offset.checked_sub(1)?), 16)?;
    let (_, flow) = program.listing.instruction_at(start)?;
    (start.offset + u64::from(program.listing.instruction_at(start)?.0) == addr.offset
        && falls_through_stored(program, start, flow, addr.space))
    .then_some(start)
}

/// One vertex of the flow graph — a `SimpleBlockModel` basic block (`BlockVertex`, :625).
struct Vertex {
    start: u64,
    /// Inclusive end of the block's address range.
    end: u64,
    srcs: BTreeSet<u64>,
    dests: BTreeSet<u64>,
}

/// `findInstructionFlow` (:645): follow flow from `first`, build the block graph, prune
/// blocks justified from outside, return what should be cleared.
fn find_instruction_flow(
    program: &Program,
    first: Address,
    clear_set: &AddressSet,
    start_addrs: &AddressSet,
    protected: &AddressSet,
) -> AddressSet {
    let ram = first.space;
    let mut block_set = AddressSet::new();
    let mut vertices: BTreeMap<u64, Vertex> = BTreeMap::new();
    let mut worklist: Vec<u64> = Vec::new();

    // :670-674 — the start vertex is the block CONTAINING `first`.
    let (start_lo, start_hi) = block_containing(program, first);
    block_set.add_range(ram, start_lo, start_hi);
    vertices.insert(start_lo, Vertex { start: start_lo, end: start_hi, srcs: BTreeSet::new(), dests: BTreeSet::new() });
    worklist.push(start_lo);
    let start_key = start_lo;

    // :676 — when the walk starts at a repair seed, incoming edges to the start block are
    // not recorded, so nothing can rescue it.
    let never_snip_start = start_addrs.contains(first);

    // :679-746 — follow block flow and build the graph.
    while let Some(from_key) = worklist.pop() {
        let (from_start, from_end) = {
            let v = &vertices[&from_key];
            (v.start, v.end)
        };
        if protected.contains(Address::new(ram, from_start)) {
            continue;
        }
        for dest in block_destinations(program, ram, from_start, from_end) {
            let dest_addr = Address::new(ram, dest);
            if protected.contains(dest_addr) || clear_set.contains(dest_addr) {
                continue;
            }
            // Resolve the destination to its containing block's vertex (Ghidra maps the
            // reference address to `destBlock`).
            let known = vertices
                .range(..=dest)
                .next_back()
                .filter(|(_, v)| v.end >= dest)
                .map(|(k, _)| *k);
            let dest_key = if let Some(k) = known {
                k
            } else {
                // :716 — do not include data (or undecoded bytes).
                if program.listing.instruction_at(dest_addr).is_none() {
                    continue;
                }
                // :719-728 — a loader/user-named function is never cleared (module note).
                if let Some(f) = program.function_manager.function_at(dest_addr) {
                    if !f.name().starts_with("FUN_") {
                        continue;
                    }
                }
                let (lo, hi) = block_containing(program, dest_addr);
                if never_snip_start && lo == start_key {
                    continue; // :710-712 — no incoming edges to the start vertex
                }
                if !vertices.contains_key(&lo) {
                    block_set.add_range(ram, lo, hi);
                    vertices.insert(
                        lo,
                        Vertex { start: lo, end: hi, srcs: BTreeSet::new(), dests: BTreeSet::new() },
                    );
                    worklist.push(lo);
                }
                lo
            };
            if never_snip_start && dest_key == start_key {
                continue;
            }
            if dest_key != from_key {
                vertices.get_mut(&from_key).unwrap().dests.insert(dest_key);
                vertices.get_mut(&dest_key).unwrap().srcs.insert(from_key);
            }
        }
    }

    // :749-751 — never clear the part of the start block before the seed.
    if first.offset > start_lo {
        let mut head = AddressSet::new();
        head.add_range(ram, start_lo, first.offset - 1);
        block_set = block_set.subtract(&head);
    }

    // :755-796 — prune every block justified from OUTSIDE the graph.
    let keys: Vec<u64> = vertices.keys().copied().collect();
    let mut pruned: BTreeSet<u64> = BTreeSet::new();
    for k in keys {
        if k == start_key || pruned.contains(&k) || vertices[&k].srcs.is_empty() {
            continue;
        }
        let addr = Address::new(ram, k);
        let justified = if let Some(ff) = fall_from(program, addr) {
            // :762-765 — an instruction outside the graph falls into this block.
            !block_set.contains(ff)
        } else {
            let has_refs = program.reference_manager.refs_to(addr).next().is_some();
            if !has_refs {
                // :774-777 — no references, but a function starts here: bad flow cannot
                // have created it.
                program.function_manager.function_at(addr).is_some()
            } else {
                // :778-787 — a flow reference from outside the graph and outside the
                // already-cleared set.
                program.reference_manager.refs_to(addr).any(|r| {
                    r.ref_type.is_flow()
                        && !block_set.contains(r.from)
                        && !clear_set.contains(r.from)
                })
            }
        };
        if justified {
            prune(&mut vertices, k, &mut block_set, &mut pruned, ram);
        }
    }

    block_set
}

/// `prune` (:997): keep this block (delete it from the CLEAR candidate set) and everything
/// transitively reachable from it — reachable-from-justified code is justified.
fn prune(
    vertices: &mut BTreeMap<u64, Vertex>,
    key: u64,
    block_set: &mut AddressSet,
    pruned: &mut BTreeSet<u64>,
    ram: crate::decompile::space::SpaceId,
) {
    let mut stack = vec![key];
    while let Some(k) = stack.pop() {
        if !pruned.insert(k) {
            continue;
        }
        let (start, end, dests, srcs) = {
            let v = &vertices[&k];
            (v.start, v.end, v.dests.clone(), v.srcs.clone())
        };
        let mut range = AddressSet::new();
        range.add_range(ram, start, end);
        *block_set = block_set.subtract(&range);
        for s in srcs {
            vertices.get_mut(&s).map(|v| v.dests.remove(&k));
        }
        vertices.get_mut(&k).map(|v| v.srcs.clear());
        for d in dests {
            stack.push(d);
        }
    }
}

/// The `SimpleBlockModel` basic block containing `addr` (`getFirstCodeBlockContaining`):
/// back up while the previous instruction falls into the current one and the current one
/// has no symbol and no flow references to it (SimpleBlockModel.java:500 — a block starts
/// where the previous instruction does not fall through, or ends a block); then extend
/// forward while the instruction only falls through, has no flow references from it, the
/// next instruction exists, and the next address carries no symbol (:168-182).
fn block_containing(program: &Program, addr: Address) -> (u64, u64) {
    let ram = addr.space;
    let mut lo = addr.offset;
    loop {
        if program.symbol_table.has_symbol_at(Address::new(ram, lo))
            || program
                .reference_manager
                .refs_to(Address::new(ram, lo))
                .any(|r| r.ref_type.is_flow())
        {
            break;
        }
        let Some(prev) = fall_from(program, Address::new(ram, lo)) else { break };
        if ends_block(program, prev) {
            break;
        }
        lo = prev.offset;
    }
    let mut end = {
        let (len, _) = program.listing.instruction_at(Address::new(ram, lo)).expect("block start is an instruction");
        lo + u64::from(len) - 1
    };
    let mut cur = lo;
    loop {
        let cur_addr = Address::new(ram, cur);
        if ends_block(program, cur_addr) {
            break;
        }
        let (len, flow) = program.listing.instruction_at(cur_addr).expect("cur is an instruction");
        if !falls_through_stored(program, cur_addr, flow, ram) {
            break;
        }
        let next = cur + u64::from(len);
        let next_addr = Address::new(ram, next);
        if program.listing.instruction_at(next_addr).is_none()
            || program.symbol_table.has_symbol_at(next_addr)
        {
            break;
        }
        cur = next;
        end = next + u64::from(program.listing.instruction_at(next_addr).expect("just checked").0) - 1;
    }
    (lo, end)
}

/// `hasEndOfBlockFlow` (SimpleBlockModel.java:244): any prototype flow other than plain
/// fall-through — a CALL ends a simple block — or any flow reference from the instruction.
fn ends_block(program: &Program, addr: Address) -> bool {
    let Some((_len, flow)) = program.listing.instruction_at(addr) else { return true };
    if !matches!(flow.kind, crate::analysis::flowtype::FlowKind::FallThrough) {
        return true;
    }
    program.reference_manager.refs_from(addr).any(|r| r.ref_type.is_flow())
}

/// A block's flow destinations (`SimpleBlockModel` `getDestinations`): the flow references
/// of the EXIT instruction plus its fall-through. Interior instructions only fall through,
/// by construction.
fn block_destinations(program: &Program, ram: crate::decompile::space::SpaceId, _lo: u64, hi: u64) -> Vec<u64> {
    // The exit instruction is the one whose range ends at `hi`.
    let Some((exit, _len)) = program.listing.code_unit_containing(Address::new(ram, hi), 16) else {
        return Vec::new();
    };
    let mut out: Vec<u64> = program
        .reference_manager
        .refs_from(exit)
        .filter(|r| r.ref_type.is_flow() && r.to.space == ram)
        .map(|r| r.to.offset)
        .collect();
    if let Some((len, flow)) = program.listing.instruction_at(exit) {
        if falls_through_stored(program, exit, flow, ram) {
            out.push(exit.offset + u64::from(len));
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// `repairFlowsInto` (:417) + `repairFallThroughsInto` (:501): queue re-disassembly for
/// every flow that enters the cleared area from outside.
fn repair_flows_into(
    program: &mut Program,
    clear_set: &AddressSet,
    do_not_repair: Option<u64>,
    sched: &mut Scheduling,
) {
    let ram = program.default_space;
    let mut points = AddressSet::new();
    let mut data_ref_sources = AddressSet::new();

    // :513-555 — for each cleared range, search backward (bounded) for the instruction that
    // fell into it; its fall-through is a re-disassembly seed.
    for r in clear_set.ranges() {
        let mut back = 0u64;
        let mut a = r.min;
        while back < FALLTHROUGH_SEARCH_LIMIT {
            let Some(prev) = a.checked_sub(1) else { break };
            a = prev;
            if let Some((start, _len)) = program.listing.code_unit_containing(Address::new(ram, a), 16) {
                if let Some((len, flow)) = program.listing.instruction_at(start) {
                    if falls_through_stored(program, start, flow, ram) {
                        let ft = start.offset + u64::from(len);
                        if do_not_repair != Some(ft) {
                            points.add_range(ram, ft, ft);
                        }
                    }
                }
                break; // found a code unit — instruction or data, the search ends (:530/:549)
            }
            if !program.memory.contains(Address::new(ram, a)) {
                break;
            }
            back += 1;
        }
    }

    // :433-471 — flow-referenced destinations inside the cleared area are re-disassembled;
    // a destination with only a data reference is queued for analysis instead.
    for dest in program.reference_manager.destinations_in(clear_set) {
        if Some(dest.offset) == do_not_repair {
            continue;
        }
        if points.contains(dest) {
            continue;
        }
        let mut flow = false;
        let mut data_src: Option<Address> = None;
        for r in program.reference_manager.refs_to(dest) {
            if r.ref_type.is_flow() {
                flow = true;
                break;
            }
            if data_src.is_none() {
                data_src = Some(r.from);
            }
        }
        if flow {
            points.add_range(ram, dest.offset, dest.offset);
        } else if let Some(src) = data_src {
            data_ref_sources.add_range(ram, src.offset, src.offset);
        }
    }

    // :474-481 — external entry points in the cleared area are always re-disassembled.
    for e in &program.entry_points {
        if clear_set.contains(*e) {
            points.add_range(ram, e.offset, e.offset);
        }
    }

    // :486-488 — `DisassembleCommand`; on the queue, as everywhere else post-1a81975.
    sched.disassemble(&points);
    // :492-494 — `analysisMgr.codeDefined(dataRefSet)`.
    if !data_ref_sources.is_empty() {
        sched.code_defined(&data_ref_sources);
    }
}
