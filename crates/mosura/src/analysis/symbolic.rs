//! `SymbolicPropogator` (A5) — a port of Ghidra's `program/util/SymbolicPropogator.java`
//! + `VarnodeContext`: an abstract interpreter over p-code that tracks values through
//! registers/temporaries and recovers data references when a load/store/data operand
//! resolves to a mapped memory address.
//!
//! **v1** tracks the constant lattice (`Const | Unknown`). That already covers x86-64's
//! dominant data-reference forms, because SLEIGH folds the address arithmetic:
//! `mov rax,[rip+d]` lifts to `RAX = COPY (ram,TARGET)` (a direct address operand →
//! READ), `mov [rip+d],rax` to `(ram,TARGET) = COPY RAX` (→ WRITE), `lea rdx,[rip+d]` to
//! `RDX = COPY (const,TARGET)` (→ DATA), and register-indirect `mov rcx,[rax]` to a
//! `LOAD` whose pointer we resolve from the tracked register value. Register-relative
//! (stack) values and the full ~40-op behaviour set are the documented next steps.

use std::collections::{HashMap, HashSet};

use crate::analysis::program::{Program, RefType};
use crate::decompile::opcode::OpCode;
use crate::decompile::space::{Address, SpaceId};
use crate::sleigh::engine::Spec;
use crate::sleigh::pcode::{PArg, PcodeOp, Varnode};

/// An abstract value (Ghidra `SymbolicPropogator.Value`, constant subset).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SymValue {
    Const(u64),
    Unknown,
}

/// Cheap, allocation-free key for a varnode's space. The p-code spaces are a tiny fixed
/// set, so the common ones map to small ids and anything else to an FNV-1a hash of the
/// name — keeping the [`VarnodeContext`] key `Copy` so per-branch context clones don't
/// allocate or copy strings (the hot path on large functions).
fn space_key(name: &str) -> u64 {
    match name {
        "const" => 0,
        "register" => 1,
        "unique" => 2,
        "ram" => 3,
        _ => {
            let mut h = 0xcbf2_9ce4_8422_2325u64;
            for b in name.bytes() {
                h ^= u64::from(b);
                h = h.wrapping_mul(0x0000_0100_0000_01b3);
            }
            h | (1 << 63) // set the top bit so it can't collide with the small ids
        }
    }
}

/// Per-location symbolic state (Ghidra `VarnodeContext`): the value of each register /
/// temporary, keyed by `(space_key, offset)`. `const` varnodes carry their value
/// intrinsically; `ram` varnodes are addresses, handled by the reference logic.
#[derive(Clone, Default)]
struct VarnodeContext {
    state: HashMap<(u64, u64), SymValue>,
}

impl VarnodeContext {
    fn get(&self, vn: &Varnode) -> SymValue {
        if vn.space == "const" {
            SymValue::Const(vn.offset)
        } else {
            self.state.get(&(space_key(&vn.space), vn.offset)).copied().unwrap_or(SymValue::Unknown)
        }
    }
    fn put(&mut self, vn: &Varnode, val: SymValue) {
        if vn.space != "const" {
            self.state.insert((space_key(&vn.space), vn.offset), val);
        }
    }
}

fn arg_var(a: &PArg) -> Option<&Varnode> {
    match a {
        PArg::Var(v) => Some(v),
        PArg::Space(_) => None,
    }
}

/// Read `size` little-endian bytes of initialized memory at `addr` as a constant value
/// (Ghidra `VarnodeContext.getValue` reading the program image — pointer-following). Any
/// uninitialized byte makes the value unknown.
fn read_mem_const(program: &Program, ram: SpaceId, addr: u64, size: u32) -> SymValue {
    if size == 0 || size > 8 {
        return SymValue::Unknown;
    }
    let bytes = program.memory.read_window(Address::new(ram, addr), size as usize);
    if bytes.len() != size as usize {
        return SymValue::Unknown;
    }
    let mut v = 0u64;
    for (i, b) in bytes.iter().enumerate() {
        v |= (*b as u64) << (i * 8);
    }
    SymValue::Const(v)
}

/// Mask a folded value to its varnode size (sub-register writes don't carry high bits).
fn mask(v: u64, size: u32) -> u64 {
    if size == 0 || size >= 8 {
        v
    } else {
        v & ((1u64 << (size * 8)) - 1)
    }
}

/// Ghidra `ConstantPropagationAnalyzer` reference-address thresholds (its option
/// defaults): a known/resolved address must clear `minStoreLoadRefAddress`; a
/// *speculative* constant-derived address (a bare immediate that might be an address)
/// must clear the larger `minSpeculativeRefAddress`.
const MIN_KNOWN_REF: u64 = 4;
const MIN_SPECULATIVE_REF: u64 = 1024;

/// Record a reference if the target lies in mapped memory at or above `min` (Ghidra's
/// `evaluateReference`: reject `!memory.contains(address)`, and addresses below the
/// applicable threshold).
fn make_ref(program: &mut Program, from: Address, ram: SpaceId, to_off: u64, ref_type: RefType, min: u64) {
    let to = Address::new(ram, to_off);
    if to_off < min || !program.memory.contains(to) {
        return;
    }
    program.reference_manager.add(from, to, ref_type, -1);
}

/// Interpret one p-code op: create references for resolved memory operands and update
/// the value of the output varnode.
fn process_op(program: &mut Program, vctx: &mut VarnodeContext, here: Address, ram: SpaceId, op: &PcodeOp) {
    let opcode = OpCode::from_u32(op.opcode);

    // Control-flow ops carry their *target* as a `ram` operand — that is a flow edge
    // (handled by the disassembler as a CALL/JUMP reference), not a data access. Only
    // data ops turn a literal `ram` operand into a data reference.
    let is_flow = matches!(
        opcode,
        Some(
            OpCode::Branch
                | OpCode::Cbranch
                | OpCode::Branchind
                | OpCode::Call
                | OpCode::Callind
                | OpCode::Callother
                | OpCode::Return
        )
    );

    // Direct `ram`-space operands are literal addresses: an input is read, an output
    // is written (Ghidra's COPY `in[0].isAddress()` / STORE-to-address paths). A literal
    // `const` operand whose value is a mapped address is a DATA reference (Ghidra
    // `evaluateConstant` — e.g. `lea`/`cmp`/`sub` against a global's address).
    if !is_flow {
        // A `const` that is a mapped address is a DATA reference — but not in a STORE,
        // whose value operand is often a return address pushed by a `call` (a valid code
        // address that is not a data reference; Ghidra accounts for it via call semantics).
        let const_is_data = !matches!(opcode, Some(OpCode::Store));
        for arg in &op.ins {
            if let PArg::Var(v) = arg {
                if v.space == "ram" {
                    make_ref(program, here, ram, v.offset, RefType::Read, MIN_KNOWN_REF);
                } else if v.space == "const" && const_is_data {
                    make_ref(program, here, ram, v.offset, RefType::Data, MIN_SPECULATIVE_REF);
                }
            }
        }
        if let Some(out) = &op.out {
            if out.space == "ram" {
                make_ref(program, here, ram, out.offset, RefType::Write, MIN_KNOWN_REF);
            }
        }
    }

    match opcode {
        Some(OpCode::Copy) => {
            // (The const-as-address DATA reference for `lea` is created by the operand
            // scan above.) Propagate the value — reading the image for a `ram` source so a
            // loaded pointer flows on (Ghidra `getValue` reads initialized memory).
            if let Some(v) = op.ins.first().and_then(arg_var) {
                let out_size = op.out.as_ref().map_or(v.size, |o| o.size);
                let val = if v.space == "ram" {
                    read_mem_const(program, ram, v.offset, out_size)
                } else {
                    vctx.get(v)
                };
                if let Some(out) = &op.out {
                    vctx.put(out, val);
                }
            }
        }
        Some(OpCode::Load) => {
            // in[0] = address space, in[1] = pointer.
            let mut loaded = SymValue::Unknown;
            if let Some(ptr) = op.ins.get(1).and_then(arg_var) {
                if let SymValue::Const(addr) = vctx.get(ptr) {
                    make_ref(program, here, ram, addr, RefType::Read, MIN_KNOWN_REF);
                    if let Some(out) = &op.out {
                        loaded = read_mem_const(program, ram, addr, out.size); // follow the pointer
                    }
                }
            }
            if let Some(out) = &op.out {
                vctx.put(out, loaded);
            }
        }
        Some(OpCode::Store) => {
            if let Some(ptr) = op.ins.get(1).and_then(arg_var) {
                if let SymValue::Const(addr) = vctx.get(ptr) {
                    make_ref(program, here, ram, addr, RefType::Write, MIN_KNOWN_REF);
                }
            }
        }
        // Constant-fold the address arithmetic so register-held addresses propagate.
        Some(OpCode::IntAdd) => fold2(vctx, op, u64::wrapping_add),
        Some(OpCode::IntSub) => fold2(vctx, op, u64::wrapping_sub),
        Some(OpCode::IntAnd) => fold2(vctx, op, |a, b| a & b),
        Some(OpCode::IntOr) => fold2(vctx, op, |a, b| a | b),
        Some(OpCode::IntZext | OpCode::IntSext) => {
            // Pass the (masked) value through a widening copy.
            let v = op.ins.first().and_then(arg_var).map(|v| vctx.get(v)).unwrap_or(SymValue::Unknown);
            if let Some(out) = &op.out {
                vctx.put(out, v);
            }
        }
        _ => {
            // Any other op makes its output unknown (conservative).
            if let Some(out) = &op.out {
                vctx.put(out, SymValue::Unknown);
            }
        }
    }
}

/// Constant-fold a binary op when both inputs are constants; otherwise unknown.
fn fold2(vctx: &mut VarnodeContext, op: &PcodeOp, f: impl Fn(u64, u64) -> u64) {
    let Some(out) = &op.out else { return };
    let a = op.ins.first().and_then(arg_var).map(|v| vctx.get(v));
    let b = op.ins.get(1).and_then(arg_var).map(|v| vctx.get(v));
    let val = match (a, b) {
        (Some(SymValue::Const(x)), Some(SymValue::Const(y))) => SymValue::Const(mask(f(x, y), out.size)),
        _ => SymValue::Unknown,
    };
    vctx.put(out, val);
}

fn ram_branch_target(op: &PcodeOp) -> Option<u64> {
    match op.ins.first() {
        Some(PArg::Var(v)) if v.space == "ram" => Some(v.offset),
        _ => None,
    }
}

/// Walk the function reachable from `start` following flow (Ghidra `flowConstants`),
/// maintaining the symbolic context along each path and recording data references.
/// Path-sensitive with a visited set (each instruction is interpreted once, first path
/// wins) — conservative: a reference is only made when the value is a definite constant
/// on the interpreted path, so it never invents a wrong reference.
pub fn flow_constants(
    spec: &Spec,
    ctx: &[u32],
    program: &mut Program,
    start: Address,
    entries: &HashSet<u64>,
) {
    let ram = start.space;
    let mut visited: HashSet<u64> = HashSet::new();
    let mut work: Vec<(u64, VarnodeContext)> = vec![(start.offset, VarnodeContext::default())];

    while let Some((a, mut vctx)) = work.pop() {
        if !visited.insert(a) {
            continue;
        }
        // Stay within this function — Ghidra `flowConstants` is bounded by the function's
        // restrict-set; without this each per-function call would walk the whole program.
        if a != start.offset && entries.contains(&a) {
            continue;
        }
        let window = program.memory.read_window(Address::new(ram, a), 16);
        let Some(insn) = spec.disassemble_ctx(&window, a, ctx).into_iter().next() else {
            continue;
        };
        let ilen = insn.bytes.len() as u64;
        if ilen == 0 {
            continue;
        }
        let here = Address::new(ram, a);

        let mut falls = true;
        let mut branch_targets: Vec<u64> = Vec::new();
        for op in &insn.ops {
            process_op(program, &mut vctx, here, ram, op);
            match OpCode::from_u32(op.opcode) {
                Some(OpCode::Branch) => {
                    falls = false;
                    if let Some(t) = ram_branch_target(op) {
                        branch_targets.push(t);
                    }
                }
                Some(OpCode::Cbranch) => {
                    if let Some(t) = ram_branch_target(op) {
                        branch_targets.push(t);
                    }
                }
                Some(OpCode::Return | OpCode::Branchind) => falls = false,
                _ => {}
            }
        }
        // Queue branch targets (each path gets its own context); skip already-interpreted
        // ones so we don't clone the context needlessly (back-edges of loops). The
        // fall-through path reuses this context by move — only branches need a clone.
        for t in branch_targets {
            if !visited.contains(&t) {
                work.push((t, vctx.clone()));
            }
        }
        if falls && !visited.contains(&(a + ilen)) {
            work.push((a + ilen, vctx));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::program::Program;
    use crate::decompile::space::{SpaceKind, SpaceManager};

    fn program_with_code(bytes: &[u8]) -> (Program, SpaceId) {
        let mut spaces = SpaceManager::standard();
        let ram = spaces.add("ram", SpaceKind::Processor, 8, 1);
        let mut program =
            Program::new(spaces, ram, "x86:LE:64:default", "gcc", Address::new(ram, 0x401000), false, 64);
        let mut img = vec![0u8; 0x1000];
        img[..bytes.len()].copy_from_slice(bytes);
        program.memory.add_block(
            "text",
            Address::new(ram, 0x401000),
            0x1000,
            true,
            false,
            true,
            Some(img),
        );
        (program, ram)
    }

    #[test]
    fn rip_relative_load_makes_read_reference() {
        let Some((spec, ctx)) = crate::lang::load("x86:LE:64:default") else {
            eprintln!("skip: SLEIGH tables unavailable");
            return;
        };
        // mov rax, [rip+0x10] ; ret   →  reads ram:0x401017 (next=0x401007 + 0x10)
        let (mut program, ram) = program_with_code(&[0x48, 0x8b, 0x05, 0x10, 0x00, 0x00, 0x00, 0xc3]);
        flow_constants(&spec, &ctx, &mut program, Address::new(ram, 0x401000), &std::collections::HashSet::new());
        let reads: Vec<u64> = program
            .reference_manager
            .references()
            .filter(|r| r.ref_type == RefType::Read)
            .map(|r| r.to.offset)
            .collect();
        assert!(reads.contains(&0x40_1017), "expected READ ref to 0x401017, got {reads:x?}");
    }

    #[test]
    fn lea_makes_data_reference_and_propagates_constant() {
        let Some((spec, ctx)) = crate::lang::load("x86:LE:64:default") else {
            return;
        };
        // lea rax, [rip+0x20] ; mov rcx, [rax] ; ret
        //   rax = 0x401027 (next of lea = 0x401007 + 0x20); [rax] reads 0x401027.
        let (mut program, ram) = program_with_code(&[
            0x48, 0x8d, 0x05, 0x20, 0x00, 0x00, 0x00, // lea rax,[rip+0x20]
            0x48, 0x8b, 0x08, // mov rcx,[rax]
            0xc3, // ret
        ]);
        flow_constants(&spec, &ctx, &mut program, Address::new(ram, 0x401000), &std::collections::HashSet::new());
        let has = |rt: RefType, to: u64| {
            program.reference_manager.references().any(|r| r.ref_type == rt && r.to.offset == to)
        };
        assert!(has(RefType::Data, 0x40_1027), "lea → DATA ref to 0x401027");
        // the LOAD through rax (resolved to the constant 0x401027) → a READ reference.
        assert!(has(RefType::Read, 0x40_1027), "load via rax → READ ref to 0x401027");
    }

    #[test]
    fn follows_a_pointer_through_memory() {
        let Some((spec, ctx)) = crate::lang::load("x86:LE:64:default") else {
            return;
        };
        // mov rax, [rip+0xf9] ; mov rcx, [rax] ; ret
        //   [rip+0xf9] = 0x401100 (a pointer slot holding 0x401200); reading it loads
        //   0x401200 into rax, so the second load must reference 0x401200.
        let mut img = vec![0u8; 0x1000];
        img[..0xb].copy_from_slice(&[
            0x48, 0x8b, 0x05, 0xf9, 0x00, 0x00, 0x00, // mov rax,[rip+0xf9] -> 0x401100
            0x48, 0x8b, 0x08, // mov rcx,[rax]
            0xc3, // ret
        ]);
        img[0x100..0x108].copy_from_slice(&0x0040_1200u64.to_le_bytes()); // *0x401100 = 0x401200

        let mut spaces = SpaceManager::standard();
        let ram = spaces.add("ram", SpaceKind::Processor, 8, 1);
        let mut program =
            Program::new(spaces, ram, "x86:LE:64:default", "gcc", Address::new(ram, 0x401000), false, 64);
        program.memory.add_block("text", Address::new(ram, 0x401000), 0x1000, true, false, true, Some(img));

        flow_constants(&spec, &ctx, &mut program, Address::new(ram, 0x401000), &std::collections::HashSet::new());
        let read_to = |to: u64| {
            program.reference_manager.references().any(|r| r.ref_type == RefType::Read && r.to.offset == to)
        };
        assert!(read_to(0x40_1100), "first load reads the pointer slot 0x401100");
        assert!(read_to(0x40_1200), "pointer followed: rax = *0x401100 = 0x401200, then read");
    }
}
