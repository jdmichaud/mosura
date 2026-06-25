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
///
/// `last_set` records, per varnode, the instruction address that last wrote it (Ghidra
/// `VarnodeContext.lastSet` via `addSetVarnodeToLastSetLocations`) — the from-address of a
/// recovered PARAM reference.
#[derive(Clone, Default)]
struct VarnodeContext {
    state: HashMap<(u64, u64), SymValue>,
    last_set: HashMap<(u64, u64), u64>,
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
    /// Like [`put`], also recording `at` as the last-set location of this varnode (Ghidra
    /// `propogateValue` → `addSetVarnodeToLastSetLocations`).
    fn put_at(&mut self, vn: &Varnode, val: SymValue, at: u64) {
        if vn.space != "const" {
            let key = (space_key(&vn.space), vn.offset);
            self.state.insert(key, val);
            self.last_set.insert(key, at);
        }
    }
    /// The instruction address that last set `(space, offset)`, if known.
    fn last_set_of(&self, space: &str, offset: u64) -> Option<u64> {
        self.last_set.get(&(space_key(space), offset)).copied()
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

/// The integer/pointer argument storage **registers** of the program's default calling
/// convention, in argument order — a port of Ghidra
/// `program.getCompilerSpec().getDefaultCallingConvention()` followed by
/// `PrototypeModel.getArgLocation(i, null, pointerSizedDT, …)` for successive pointer-sized
/// args. The registers are read out of the convention's `ParamList` resources
/// ([`fspec::sysv_input`]) — its GENERAL-class register entries, in resource order — rather
/// than a hardcoded list, so there is one source of truth shared with the decompiler's
/// prototype recovery. Stack-storage resources are excluded, matching Ghidra
/// `addParamReferences`' `var.isStackStorage()` skip.
///
/// mosura models only the System V AMD64 convention (the `gcc` compiler spec's default).
/// A different compiler spec supplies its own convention from its `.cspec` (the cspec
/// loader is not yet ported), so it yields no registers here — never applying the wrong
/// convention's storage, which would invent references on e.g. a MS-x64 PE.
fn integer_arg_registers(program: &Program) -> Vec<u64> {
    if program.compiler_spec_id != "gcc" {
        return Vec::new(); // only the System V (gcc) default convention is modeled
    }
    let spaces = crate::decompile::space::SpaceManager::standard();
    let (Some(reg), Some(conv)) =
        (spaces.by_name("register"), crate::decompile::fspec::sysv_input(&spaces))
    else {
        return Vec::new();
    };
    conv.entry
        .iter()
        .filter(|e| e.type_class == crate::decompile::fspec::type_class::GENERAL && e.space == reg)
        .map(|e| e.addressbase)
        .collect()
}

/// Recover PARAM references at a call site — a port of `SymbolicPropogator.addParamReferences`
/// → `createVariableStorageReference` → `makeVariableStorageReference` (the constant
/// propagator's parameter analysis, enabled for non-segmented spaces; x86-64 has
/// `checkParamRefs = true`, `checkPointerParamRefs = false`).
///
/// For the corpus the called externals have no recovered signature, so Ghidra takes the
/// "no defined params" branch: loop the argument locations (`getArgLocation`), skip stack
/// storage, and for each register holding a constant value emit a reference **from the
/// instruction that last set that register** (`getLastSetLocation`) to the value. With
/// `callOffset != 0` (a real call) the type is PARAM, else DATA
/// (`makeVariableStorageReference`); the value must not equal the call target
/// (`val == callOffset` is skipped) and clears the `minStoreLoadOffset` threshold via the
/// shared `make_ref` gate. `arg_regs` is the convention's integer-argument register order
/// (see [`integer_arg_registers`]); an empty slice (an unmodeled convention) recovers none.
fn add_param_references(
    program: &mut Program,
    vctx: &VarnodeContext,
    ram: SpaceId,
    here: Address,
    call_offset: u64,
    arg_regs: &[u64],
) {
    for &reg_off in arg_regs {
        let SymValue::Const(val) = vctx.get(&Varnode { space: "register".into(), offset: reg_off, size: 8 })
        else {
            // `createVariableStorageReference`: stop at the first register with no value
            // is not how Ghidra's no-signature loop works — it continues — but a
            // non-constant register simply yields no reference, so just skip it.
            continue;
        };
        // `makeVariableStorageReference`: skip when the value is the call target itself.
        if val == call_offset {
            continue;
        }
        // The from-address is where the register was last set (`getLastSetLocation`); if
        // unknown, Ghidra falls back to the instruction's max address — but without a
        // tracked set location we have no faithful from-address, so skip.
        let Some(from_off) = vctx.last_set_of("register", reg_off) else { continue };
        let from = Address::new(ram, from_off);
        let to = Address::new(ram, val);
        // The target must be a mapped address ≥ the known-ref threshold
        // (`evaluateReference` minStoreLoadOffset = 4); guard before mutating.
        if val < MIN_KNOWN_REF || !program.memory.contains(to) {
            continue;
        }
        // Ghidra's ScalarOperandAnalyzer skips an operand that already carries a reference,
        // so the speculative DATA ref the constant propagator made for the immediate at the
        // set instruction must not coexist with this PARAM — drop it (the param analysis
        // claims the operand). Then add the PARAM (callOffset != 0 → PARAM).
        program.reference_manager.remove(from, to, RefType::Data);
        program.reference_manager.add(from, to, RefType::Param, -1);
    }
    let _ = here;
}

/// Interpret one p-code op: create references for resolved memory operands and update
/// the value of the output varnode. `insn_flow` is the containing instruction's flow type
/// (Ghidra `instruction.getFlowType()`), used to type an indirect-flow target reference.
fn process_op(
    program: &mut Program,
    vctx: &mut VarnodeContext,
    here: Address,
    ram: SpaceId,
    op: &PcodeOp,
    insn_flow: Option<RefType>,
) {
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
                    vctx.put_at(out, val, here.offset);
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
                vctx.put_at(out, loaded, here.offset);
            }
        }
        Some(OpCode::Store) => {
            if let Some(ptr) = op.ins.get(1).and_then(arg_var) {
                if let SymValue::Const(addr) = vctx.get(ptr) {
                    make_ref(program, here, ram, addr, RefType::Write, MIN_KNOWN_REF);
                }
            }
        }
        Some(OpCode::Callind | OpCode::Branchind) => {
            // An indirect call/branch whose target resolves to a constant — e.g. a PLT
            // thunk's `call *[GOT]` / `jmp *[GOT]`, where the slot was relocated to the
            // external — is referenced with the instruction's flow type, faithful to
            // SymbolicPropogator.java:944-952 (BRANCHIND) / 994-1015 (CALLIND), both of
            // which call `makeReference(..., instruction.getFlowType(), ...)`. A CALLIND's
            // base flow type is COMPUTED_CALL; a BRANCHIND's is COMPUTED_JUMP (a tail-call
            // PLT jmp is later re-typed to COMPUTED_CALL_TERMINATOR by the shared-return
            // override). A register/table BRANCHIND (a switch) doesn't resolve to a single
            // constant here and is handled by the decompiler switch analyzer.
            if let Some(t) = op.ins.first().and_then(arg_var) {
                // The target value: a `ram` operand is the pointer slot itself (a `jmp
                // *[mem]` lifts to `BRANCHIND (ram,slot)`) — read the slot from the image
                // (Ghidra `VarnodeContext.getValue` reads memory for an address varnode);
                // any other operand uses the tracked symbolic value (e.g. CALLIND through a
                // register loaded by a preceding COPY).
                let val = if t.space == "ram" {
                    read_mem_const(program, ram, t.offset, t.size)
                } else {
                    vctx.get(t)
                };
                if let SymValue::Const(target) = val {
                    if let Some(rt) = insn_flow {
                        make_ref(program, here, ram, target, rt, MIN_KNOWN_REF);
                    }
                }
            }
        }
        // Constant-fold the address arithmetic so register-held addresses propagate.
        Some(OpCode::IntAdd) => fold2(vctx, op, here.offset, u64::wrapping_add),
        Some(OpCode::IntSub) => fold2(vctx, op, here.offset, u64::wrapping_sub),
        Some(OpCode::IntAnd) => fold2(vctx, op, here.offset, |a, b| a & b),
        Some(OpCode::IntOr) => fold2(vctx, op, here.offset, |a, b| a | b),
        Some(OpCode::IntZext | OpCode::IntSext) => {
            // Pass the (masked) value through a widening copy.
            let v = op.ins.first().and_then(arg_var).map(|v| vctx.get(v)).unwrap_or(SymValue::Unknown);
            if let Some(out) = &op.out {
                vctx.put_at(out, v, here.offset);
            }
        }
        _ => {
            // Any other op makes its output unknown (conservative).
            if let Some(out) = &op.out {
                vctx.put_at(out, SymValue::Unknown, here.offset);
            }
        }
    }
}

/// Constant-fold a binary op when both inputs are constants; otherwise unknown.
fn fold2(vctx: &mut VarnodeContext, op: &PcodeOp, at: u64, f: impl Fn(u64, u64) -> u64) {
    let Some(out) = &op.out else { return };
    let a = op.ins.first().and_then(arg_var).map(|v| vctx.get(v));
    let b = op.ins.get(1).and_then(arg_var).map(|v| vctx.get(v));
    let val = match (a, b) {
        (Some(SymValue::Const(x)), Some(SymValue::Const(y))) => SymValue::Const(mask(f(x, y), out.size)),
        _ => SymValue::Unknown,
    };
    vctx.put_at(out, val, at);
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
    // The default calling convention's integer-argument registers (Ghidra
    // `getDefaultCallingConvention` + `getArgLocation`), resolved once for the function.
    let arg_regs = integer_arg_registers(program);
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

        // The instruction's flow type (Ghidra `instruction.getFlowType()`), used to type a
        // resolved indirect-flow target. The shared-return flow override has not been
        // applied yet (that analyzer runs after constant propagation), so this is the base
        // type — a tail-call PLT `jmp *[GOT]` is COMPUTED_JUMP here, re-typed later.
        let insn_flow = crate::analysis::flowtype::flow_type(&insn.ops);

        let mut falls = true;
        let mut branch_targets: Vec<u64> = Vec::new();
        for op in &insn.ops {
            // On a call, recover PARAM references for the argument registers from the
            // register state *before* the call clobbers anything (Ghidra applies
            // `addParamReferences` via `handleFunctionSideEffects` while processing the CALL
            // pcode). The call target offset (`callOffset`): a direct CALL's `ram` operand,
            // or a CALLIND's resolved-constant target.
            match OpCode::from_u32(op.opcode) {
                Some(OpCode::Call) => {
                    let call_off = op.ins.first().and_then(arg_var).filter(|v| v.space == "ram").map(|v| v.offset).unwrap_or(0);
                    add_param_references(program, &vctx, ram, here, call_off, &arg_regs);
                }
                Some(OpCode::Callind) => {
                    let call_off = op.ins.first().and_then(arg_var).map(|t| match vctx.get(t) {
                        SymValue::Const(c) => c,
                        SymValue::Unknown => 0,
                    }).unwrap_or(0);
                    add_param_references(program, &vctx, ram, here, call_off, &arg_regs);
                }
                _ => {}
            }
            process_op(program, &mut vctx, here, ram, op, insn_flow);
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
    fn pointer_argument_makes_param_reference() {
        let Some((spec, ctx)) = crate::lang::load("x86:LE:64:default") else {
            return;
        };
        // mov rdi, 0x401800 ; call 0x401700   →  PARAM from the mov (0x401000) to 0x401800
        // (RDI = first integer arg; the value is a mapped address, the call is real).
        //   48 c7 c7 00 18 40 00  mov rdi, 0x401800   (7 bytes, at 0x401000)
        //   e8 f3 06 00 00        call 0x401700       (5 bytes, at 0x401007; rel32=0x6f3)
        let (mut program, ram) = program_with_code(&[
            0x48, 0xc7, 0xc7, 0x00, 0x18, 0x40, 0x00, // mov rdi, 0x401800
            0xe8, 0xf4, 0x06, 0x00, 0x00, // call 0x401800-... compute below
        ]);
        // Recompute the call target precisely: next ip after call = 0x40100c, + rel32.
        // We don't depend on the call target for PARAM (only that it's a real call), so any
        // mapped target works; flow_constants reads RDI's value (0x401800) at the call.
        flow_constants(&spec, &ctx, &mut program, Address::new(ram, 0x401000), &std::collections::HashSet::new());
        let params: Vec<(u64, u64)> = program
            .reference_manager
            .references()
            .filter(|r| r.ref_type == RefType::Param)
            .map(|r| (r.from.offset, r.to.offset))
            .collect();
        assert!(
            params.contains(&(0x40_1000, 0x40_1800)),
            "expected PARAM 0x401000 -> 0x401800 (RDI set at the mov), got {params:x?}"
        );
        // And no DATA ref coexists at the same site (the scalar analyzer would skip it).
        let data_at = program.reference_manager.references().any(|r| {
            r.ref_type == RefType::Data && r.from.offset == 0x40_1000 && r.to.offset == 0x40_1800
        });
        assert!(!data_at, "the speculative DATA ref must be dropped when PARAM is created");
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
