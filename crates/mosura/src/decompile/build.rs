//! Build a raw [`Funcdata`] from the SLEIGH lifter — the bridge from the kept engine
//! (`sleigh`) to the faithful decompiler model. This is the pre-heritage "raw p-code"
//! form: one varnode per operand occurrence (heritage links them into SSA in P1), the
//! analogue of Ghidra's `Funcdata::followFlow` result before `ActionHeritage`.

use crate::sleigh::engine::Spec;
use crate::sleigh::pcode::PArg;

use super::fspec::ProtoModel;
use super::funcdata::Funcdata;
use super::op::SeqNum;
use super::opcode::OpCode;
use super::space::{Address, SpaceKind, SpaceManager};
use super::transform::LanedRegisterSet;
use super::varnode::VarnodeId;

/// The corpus/test default language + compiler spec whose `<default_proto>` supplies the
/// calling-convention [`ProtoModel`] the pipeline consumes. The decompiler datatests are all
/// x86-64 SysV (`arch="x86:LE:64:default:gcc"`), and the retired `fspec::sysv_*` literals it
/// replaces were likewise unconditionally SysV — so resolving this cspec is behaviour-preserving
/// in scope. A `Program`-driven decompile threads its own `(language_id, compiler_id)` into
/// [`raw_funcdata_flow_image_overrides`] instead (see [`crate::analysis::decompiler`]), so a
/// Watcom LE binary decodes under the `__watcall` cspec while the corpus stays on this default.
const DEFAULT_LANG_ID: &str = "x86:LE:64:default";
const DEFAULT_COMPILER_ID: &str = "gcc";

/// Resolve the calling-convention [`ProtoModel`] of `(language_id, compiler_id)`: the compiler
/// spec's `<default_proto>`, decoded from the `.cspec` via the faithful
/// [`crate::analysis::cspec::default_proto_model`] (a port of Ghidra `ProtoModel::decode`).
/// Degrades to the empty model when the Ghidra tree / cspec is absent (a hand-built or
/// tree-less build recovers no convention), exactly as the retired `sysv_*` builders returned
/// `None`/empty off-tree. `spec` must be the SLEIGH spec of `language_id` (its register table
/// resolves the cspec's `<register name=…>` pentries).
fn resolve_proto_model(spec: &Spec, language_id: &str, compiler_id: &str) -> ProtoModel {
    let mut spaces = SpaceManager::standard();
    // The `<stackpointer>` is applied FIRST, because it is what sets the `stack` space's address
    // size (`Architecture::decodeStackPointer` → `addSpacebase`, architecture.cc:1008/1013) and the
    // model's default `<localrange>`/`<paramrange>` are derived from that size (fspec.cc:2263/2292).
    // Ghidra depends on the same ordering — `<stackpointer>` precedes `<default_proto>` in the
    // compiler spec and `decodeCompilerConfig` (architecture.cc:1257) processes them in document
    // order. Building the ranges against the x86-64 default 8 would put every 32-bit frame offset
    // outside the local window, and no stack local would be recovered at all.
    if let Some((space, offset, size)) =
        crate::analysis::cspec::default_stack_pointer(spec, language_id, compiler_id, &spaces)
    {
        spaces.set_stack_pointer(Address::new(space, offset), size);
    }
    crate::analysis::cspec::default_proto_model(spec, language_id, compiler_id, &spaces)
        .unwrap_or_else(|| ProtoModel::with_default_ranges(&spaces))
}

/// The stack pointer register from the compiler spec's `<stackpointer>`
/// ([`crate::analysis::cspec::default_stack_pointer`]) — target-specific, so never a constant.
fn resolve_stack_pointer(
    spec: &Spec,
    language_id: &str,
    compiler_id: &str,
) -> Option<(Address, u32)> {
    let spaces = SpaceManager::standard();
    let (space, offset, size) =
        crate::analysis::cspec::default_stack_pointer(spec, language_id, compiler_id, &spaces)?;
    Some((Address::new(space, offset), size))
}

/// The `ram` (default data) space's address size, read off the SLEIGH spec — Ghidra's
/// `getDefaultDataSpace()->getAddrSize()`. This is a LANGUAGE property, not a compiler-spec one,
/// which is why it travels beside [`CspecSettings`] rather than inside it. 0 (an absent/degenerate
/// spec) leaves `SpaceManager::standard()`'s seed untouched.
fn default_ram_addr_size(spec: &Spec) -> u32 {
    spec.spaces.get(spec.default_space).map_or(0, |s| s.size as u32)
}

/// Everything a [`Funcdata`] takes from the COMPILER SPEC, travelling together because it is one
/// decode of one `.cspec` and because splitting it is how a target-specific value ends up hardcoded:
/// each field here is wrong-by-default on some target mosura can build.
#[derive(Clone)]
struct CspecSettings {
    /// `<default_proto>` — the calling convention (input/output ParamLists + call effects).
    proto_model: ProtoModel,
    /// `<stackpointer>` — the spacebase register and its size.
    stack_pointer: Option<(Address, u32)>,
    /// `<aggressivetrim signext=>` — `RuleSubvarSext`'s `aggressive` argument.
    aggressive_ext_trim: bool,
    /// `<funcptr align=>` — `RuleFuncPtrEncoding`'s alignment, as a bit position.
    funcptr_align: i32,
}

impl CspecSettings {
    /// Decode all of it for `(language_id, compiler_id)`.
    fn resolve(spec: &Spec, language_id: &str, compiler_id: &str) -> CspecSettings {
        CspecSettings {
            proto_model: resolve_proto_model(spec, language_id, compiler_id),
            stack_pointer: resolve_stack_pointer(spec, language_id, compiler_id),
            aggressive_ext_trim: crate::analysis::cspec::aggressive_ext_trim(language_id, compiler_id),
            funcptr_align: crate::analysis::cspec::funcptr_align(language_id, compiler_id),
        }
    }

    /// The corpus/datatest default — the x86-64 SysV (`gcc`) compiler spec, used by the isolated
    /// build paths ([`raw_funcdata`], [`raw_funcdata_flow`], [`raw_funcdata_flow_image`]), which all
    /// lift x86-64 SysV fixtures. A `Program`-driven decompile threads its own ids into
    /// [`raw_funcdata_flow_image_overrides`] instead (see [`crate::analysis::decompiler`]).
    fn default_for(spec: &Spec) -> CspecSettings {
        CspecSettings::resolve(spec, DEFAULT_LANG_ID, DEFAULT_COMPILER_ID)
    }
}

/// Test-only: the SysV `<default_proto>` [`ProtoModel`] (x86-64-gcc.cspec) for the hand-built
/// `Funcdata` unit tests whose recovery machinery now reads `Funcdata::proto_model` (directwrite /
/// prototype recovery / guard_calls) rather than the retired `fspec::sysv_*` literals. `None` (the
/// caller skips) when the Ghidra tree isn't present — the same gate the corpus tests use.
#[cfg(test)]
pub(crate) fn test_sysv_proto_model() -> Option<ProtoModel> {
    let sla = crate::paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
    let spec = crate::speccache::get(&sla)?;
    let pm = CspecSettings::default_for(spec).proto_model;
    pm.input.is_some().then_some(pm)
}

impl Funcdata {
    /// Intern a lifter space name, adding it (with a kind guessed from the name) if new.
    fn intern_space(&mut self, name: &str) -> super::space::SpaceId {
        if let Some(id) = self.spaces.by_name(name) {
            return id;
        }
        let kind = match name {
            "const" => SpaceKind::Constant,
            "unique" => SpaceKind::Internal,
            "stack" => SpaceKind::Spacebase,
            _ => SpaceKind::Processor,
        };
        self.spaces.add(name, kind, 8, 1)
    }

    /// Create the varnode for one lifter operand.
    fn build_operand(&mut self, v: &crate::sleigh::pcode::Varnode) -> VarnodeId {
        if v.space == "const" {
            return self.new_const(v.size, v.offset);
        }
        let space = self.intern_space(&v.space);
        self.new_varnode(v.size, Address::new(space, v.offset))
    }
}

/// Build a raw [`Funcdata`] from a sequence of lifted instructions (in address order).
fn build_from_instrs(
    name: impl Into<String>,
    base: u64,
    instrs: impl IntoIterator<Item = crate::sleigh::Instruction>,
    laned: &[(i32, u32)],
    cspec: CspecSettings,
    ram_addr_size: u32,
    userops: &std::collections::HashMap<u64, String>,
) -> Funcdata {
    let mut spaces = SpaceManager::standard();
    // The `ram` (default data) space's address size, from the SLEIGH spec — Ghidra's
    // `getDefaultDataSpace()->getAddrSize()`. Applied BEFORE the `<stackpointer>` below, because the
    // stack space is contained in ram and the local/param ranges are derived from these sizes.
    spaces.set_ram_addr_size(ram_addr_size);
    // The `stack` space's spacebase register, from the compiler spec's `<stackpointer>`. This is
    // what `ActionSpacebase` marks and what lets a stack-relative access become a `stack` Varnode;
    // leaving the x86-64 default in place on another target yields no stack frame at all.
    if let Some((sp, size)) = cspec.stack_pointer {
        spaces.set_stack_pointer(sp, size);
    }
    let ram = spaces.by_name("ram").expect("standard ram space");
    let mut f = Funcdata::new(name, Address::new(ram, base), spaces);
    // The architecture's laned (vector) registers, wrapped for `ActionLaneDivide`. Sourced from the
    // processor spec's `vector_lane_sizes` via the loader ([`Spec::laned`]); empty ⇒ no lane splitting.
    f.laned = LanedRegisterSet::from_size_masks(laned.iter().copied());
    // The default calling convention (input/output ParamLists + call EffectRecord list), decoded
    // from the compiler spec's `<default_proto>`. Replaces the old hardcoded SysV `fspec::sysv_*`.
    f.proto_model = cspec.proto_model;
    // The stack pointer register from the compiler spec's `<stackpointer>`; keyed on by stack
    // recovery, the alias probe and ActionDirectWrite. Target-specific, hence never a constant.
    f.stack_pointer = cspec.stack_pointer.map(|(a, _)| a);
    // The compiler spec's `<aggressivetrim signext=>`, which `RuleSubvarSext` passes as
    // SubvariableFlow's `aggressive` argument (Ghidra `Architecture::aggressive_ext_trim`).
    f.aggressive_ext_trim = cspec.aggressive_ext_trim;
    // RuleFuncPtrEncoding's alignment (Ghidra `Architecture::funcptr_align`).
    f.funcptr_align = cspec.funcptr_align;
    // The user-op (`define pcodeop`) index→name table (Ghidra `Architecture::userops`), so
    // `PrintC::opCallother` can render a CALLOTHER as its userop name rather than `CALLOTHER(...)`.
    f.userops = userops.clone();

    let mut uniq: u32 = 0;
    for insn in instrs {
        let pc = Address::new(ram, insn.address);
        for op in insn.ops {
            let Some(opcode) = OpCode::from_u32(op.opcode) else { continue };
            let seqnum = SeqNum { pc, uniq };
            uniq += 1;

            // inputs: PArg::Var → a varnode; PArg::Space → a constant annotation holding
            // the space id (Ghidra encodes the AddrSpace* as a constant on LOAD/STORE in0).
            let inputs: Vec<VarnodeId> = op
                .ins
                .iter()
                .map(|a| match a {
                    PArg::Var(v) => f.build_operand(v),
                    PArg::Space(s) => {
                        let sid = f.intern_space(s);
                        f.new_const(8, sid.0 as u64)
                    }
                })
                .collect();

            let id = f.new_op(opcode, seqnum, inputs);
            if let Some(out) = &op.out {
                let space = f.intern_space(&out.space);
                f.new_output(id, out.size, Address::new(space, out.offset));
            }
        }
    }
    f
}

/// Lift `bytes` at `base` by **linear sweep** and build the raw [`Funcdata`]. Simple, but
/// drifts out of alignment where code and data interleave; prefer [`raw_funcdata_flow`].
pub fn raw_funcdata(
    spec: &Spec,
    name: impl Into<String>,
    bytes: &[u8],
    base: u64,
    context: &[u32],
) -> Funcdata {
    build_from_instrs(
        name,
        base,
        spec.disassemble_ctx(bytes, base, context),
        &spec.laned,
        CspecSettings::default_for(spec),
        default_ram_addr_size(spec),
        &spec.userops,
    )
}

/// Lift by **flow-following** from `base` (Ghidra's `followFlow`): decode only the
/// instructions reachable from the entry, following fall-through and branch targets, so
/// the instruction boundaries match Ghidra's even when code and data interleave. Calls
/// fall through (their callee is not followed); indirect branches contribute no static
/// targets (resolved in P7).
pub fn raw_funcdata_flow(
    spec: &Spec,
    name: impl Into<String>,
    bytes: &[u8],
    base: u64,
    context: &[u32],
) -> Funcdata {
    use std::collections::BTreeMap;
    let len = bytes.len() as u64;
    let mut decoded: BTreeMap<u64, crate::sleigh::Instruction> = BTreeMap::new();
    let mut worklist = vec![base];
    while let Some(a) = worklist.pop() {
        if a < base || a >= base + len || decoded.contains_key(&a) {
            continue;
        }
        let off = (a - base) as usize;
        let window = &bytes[off..(off + 16).min(bytes.len())]; // max x86-64 insn length
        let Some(insn) = spec.disassemble_ctx(window, a, context).into_iter().next() else {
            continue;
        };
        let ilen = insn.bytes.len() as u64;

        // Does control fall through past this instruction? Not after a return, an
        // unconditional branch, or an indirect jump.
        let falls = !matches!(
            insn.ops.last().and_then(|o| OpCode::from_u32(o.opcode)),
            Some(OpCode::Return) | Some(OpCode::Branch) | Some(OpCode::Branchind)
        );
        // Static branch targets to other instructions (ram addresses; calls excluded).
        let mut succs: Vec<u64> = insn
            .ops
            .iter()
            .filter(|o| matches!(OpCode::from_u32(o.opcode), Some(OpCode::Branch) | Some(OpCode::Cbranch)))
            .filter_map(|o| match o.ins.first() {
                Some(PArg::Var(v)) if v.space == "ram" => Some(v.offset),
                _ => None,
            })
            .collect();
        if falls && ilen > 0 {
            succs.push(a + ilen);
        }
        decoded.insert(a, insn);
        worklist.extend(succs);
    }
    build_from_instrs(
        name,
        base,
        decoded.into_values(),
        &spec.laned,
        CspecSettings::default_for(spec),
        default_ram_addr_size(spec),
        &spec.userops,
    )
}

/// Like [`raw_funcdata_flow`] but over a multi-chunk memory image, and recovering jump
/// tables: at a `BRANCHIND`, find the table base (a constant addressing a data chunk in the
/// preceding code), read its relative 4-byte entries, and follow the case targets. Records
/// the per-case targets on the Funcdata for the CFG/structurer. The common gcc switch form.
pub fn raw_funcdata_flow_image(
    spec: &Spec,
    name: impl Into<String>,
    chunks: &[(u64, &[u8])],
    entry: u64,
    context: &[u32],
) -> Funcdata {
    raw_funcdata_flow_image_overrides(
        spec,
        name,
        chunks,
        entry,
        context,
        &std::collections::HashSet::new(),
        DEFAULT_LANG_ID,
        DEFAULT_COMPILER_ID,
    )
}

/// Like [`raw_funcdata_flow_image`] but resolving the calling convention from a datatest's
/// declared `<binaryimage arch="…">` string instead of the corpus default. Ghidra's harness
/// decompiles each savefile under ITS OWN language/cspec pair — `SleighArchitecture::
/// resolveArchitecture` (sleigh_arch.cc) splits the archid at the last `:` into language id and
/// compiler spec id — so a `x86:LE:64:default:windows` fixture (mixfloatint, statuscmp) runs
/// under the Win64 `__fastcall` groups, not gcc SysV. Building those under the gcc default
/// mis-read the parameter storage wholesale: EDX/R9D became mid-list SysV entries whose leading
/// holes (RDI/RSI/RCX/R8) filled in as phantom unreferenced parameters, and the real stack args
/// at 0x28/0x30 — Win64's first slots past the shadow space, but four holes deep into gcc's
/// stack entry — died to the inactive-chain rule.
pub fn raw_funcdata_flow_image_arch(
    spec: &Spec,
    name: impl Into<String>,
    chunks: &[(u64, &[u8])],
    entry: u64,
    context: &[u32],
    arch: &str,
) -> Funcdata {
    let (language_id, compiler_id) = match arch.rfind(':') {
        Some(i) => (&arch[..i], &arch[i + 1..]),
        None => (DEFAULT_LANG_ID, DEFAULT_COMPILER_ID),
    };
    raw_funcdata_flow_image_overrides(
        spec,
        name,
        chunks,
        entry,
        context,
        &std::collections::HashSet::new(),
        language_id,
        compiler_id,
    )
}

/// Like [`raw_funcdata_flow_image`] but honoring `call_return` — the instruction addresses the
/// analysis marked with a `FlowOverride::CALL_RETURN` (shared-return tail calls: a `jmp` whose flow
/// reference was retyped to a call by `SharedReturnAnalyzer`). At such an address the terminal
/// `BRANCH` is rewritten to `CALL` + a trailing `RETURN` (Ghidra `Funcdata::overrideFlow`,
/// funcdata_op.cc:997-1009), so the tail-called function's body is NOT followed as intra-function
/// flow — mirroring Ghidra's flow-override handling (flow.cc:416/475). The isolated datatest path
/// passes an empty set, so the corpus is byte-neutral; only the multi-function analysis bridge
/// ([`crate::analysis::decompiler::decompile_function`]) supplies overrides.
///
/// `language_id`/`compiler_id` select the `.cspec` whose `<default_proto>` supplies the
/// calling-convention [`ProtoModel`]: the datatest path passes the x86-64 SysV default, while the
/// analysis bridge threads the `Program`'s own ids (so a Watcom LE binary decodes under the
/// `__watcall` register model, `specs/x86-32-watcom.cspec`). `spec` must be the SLEIGH spec of
/// `language_id` — its register table resolves the cspec's register pentries.
#[allow(clippy::too_many_arguments)]
pub fn raw_funcdata_flow_image_overrides(
    spec: &Spec,
    name: impl Into<String>,
    chunks: &[(u64, &[u8])],
    entry: u64,
    context: &[u32],
    call_return: &std::collections::HashSet<u64>,
    language_id: &str,
    compiler_id: &str,
) -> Funcdata {
    use std::collections::{BTreeMap, HashMap};
    // Resolve an address to whichever loaded chunk holds it. Flow may cross between chunks: a
    // tail-call `jmp` from one function into another (longdouble's `pass` -> `writeLongDouble`,
    // in a separate chunk) is intra-image flow Ghidra's `FlowInfo` follows because its
    // `LoadImage` can supply bytes for the target. Restricting flow to only the entry's chunk
    // dropped that edge, leaving the tail-called body unreached (and dead-code-eliminated).
    let chunk_of = |a: u64| chunks.iter().find(|(b, by)| a >= *b && a < b + by.len() as u64).copied();
    let in_code = |a: u64| chunk_of(a).is_some();

    // The calling convention, decoded once from `(language_id, compiler_id)`'s compiler spec and
    // shared by the jump-table recovery probe clone and the final build.
    let cspec = CspecSettings::resolve(spec, language_id, compiler_id);
    let ram_addr_size = default_ram_addr_size(spec);
    let name: String = name.into();
    let mut decoded: BTreeMap<u64, crate::sleigh::Instruction> = BTreeMap::new();
    let mut switch_targets: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut switch_defaults: HashMap<u64, u64> = HashMap::new();
    // The persistent recovered-table set (Ghidra `Funcdata::jumpvec`): survives across the flow
    // passes below, so a table recovered complete is FROZEN and only a 1-entry (multistage
    // suspect) table is ever re-recovered — see `jumptable::recover_staged`.
    let mut jumpvec: std::collections::BTreeMap<u64, super::jumptable::JumpTable> =
        std::collections::BTreeMap::new();
    let mut worklist = vec![entry];
    // The order instructions are first decoded during flow-following — Ghidra's `PcodeOpBank`
    // \e deadlist is in op-creation order (op.cc:947 appends at the end), NOT address order, and
    // `FlowInfo::connectBasic` (flow.cc:1021) builds each block's in-edge list by iterating that
    // deadlist. We record the same creation order here so `build_from_instrs` emits ops in it, and
    // `cfg::build_cfg` builds in_edges in it (retiring the block-index in_edge sort). `decoded` stays
    // the address-keyed lookup/dedup map (Ghidra's `optree`).
    let mut flow_order: Vec<u64> = Vec::new();
    // Multistage flow recovery — Ghidra `FlowInfo::recoverJumpTables` / `generateOps`: follow flow,
    // then faithfully recover any indirect-branch jump tables on a simplified partial function (the
    // real `JumpBasic` recovery, see `jumptable.rs`) and feed the case targets back into the flow,
    // repeating until the table set is stable. This replaces the old build-time table-base read
    // heuristic — the case targets now come from the faithful recovery, not a pattern guess.
    loop {
        while let Some(a) = worklist.pop() {
            if decoded.contains_key(&a) {
                continue;
            }
            let Some((cbase, cbytes)) = chunk_of(a) else { continue };
            let off = (a - cbase) as usize;
            let window = &cbytes[off..(off + 16).min(cbytes.len())];
            let Some(mut insn) = spec.disassemble_ctx(window, a, context).into_iter().next() else {
                continue;
            };
            // FlowOverride::CALL_RETURN (Ghidra `overrideFlow`, funcdata_op.cc:997-1009): a
            // shared-return tail call — a `jmp` whose flow the analysis retyped to a call
            // (`SharedReturnAnalyzer`) — is rewritten to CALL + trailing RETURN. Applied before the
            // fall-through/successor scan so the tail-called body is NOT followed as flow (Ghidra
            // does not follow a call target as intra-function flow).
            if call_return.contains(&a) {
                if let Some(last_op) = insn.ops.last_mut() {
                    if OpCode::from_u32(last_op.opcode) == Some(OpCode::Branch) {
                        last_op.opcode = OpCode::Call as u32;
                        insn.ops.push(crate::sleigh::pcode::PcodeOp {
                            opcode: OpCode::Return as u32,
                            out: None,
                            ins: vec![PArg::Var(crate::sleigh::pcode::Varnode {
                                space: "const".into(),
                                offset: 1,
                                size: 4,
                            })],
                        });
                    }
                }
            }
            let ilen = insn.bytes.len() as u64;
            let last = insn.ops.last().and_then(|o| OpCode::from_u32(o.opcode));
            let falls = !matches!(last, Some(OpCode::Return) | Some(OpCode::Branch) | Some(OpCode::Branchind));
            let mut succs: Vec<u64> = insn
                .ops
                .iter()
                .filter(|o| matches!(OpCode::from_u32(o.opcode), Some(OpCode::Branch) | Some(OpCode::Cbranch)))
                .filter_map(|o| match o.ins.first() {
                    Some(PArg::Var(v)) if v.space == "ram" => Some(v.offset),
                    _ => None,
                })
                .collect();
            if falls && ilen > 0 {
                succs.push(a + ilen);
            }
            decoded.insert(a, insn);
            flow_order.push(a); // creation order (deadlist), only reached for a newly-decoded, in-code addr
            worklist.extend(succs);
        }
        // recover jump tables on a simplified partial — but only when there's an indirect branch to
        // resolve, so non-switch functions don't pay for an extra decompile
        let has_indirect = decoded.values().any(|i| {
            matches!(i.ops.last().and_then(|o| OpCode::from_u32(o.opcode)), Some(OpCode::Branchind))
        });
        if !has_indirect {
            break;
        }
        let mut partial =
            build_from_instrs(
                name.clone(),
                entry,
                decoded.values().cloned(),
                &spec.laned,
                cspec.clone(),
                ram_addr_size,
                &spec.userops,
            );
        partial.image = chunks.iter().map(|(a, b)| (*a, b.to_vec())).collect();
        // Ghidra `FlowInfo::recoverJumpTables` -> `newAddress` (flow.cc:806): feed the targets
        // recovered by prior passes back as the BRANCHIND's flow edges before re-simplifying. This
        // makes the discovered case blocks reachable, so their state updates (e.g. a loop switch
        // variable `iVar = <case>`) reach the loop-header MULTIEQUAL and widen its realized value
        // range pass-over-pass — the range `JumpBasic::findSmallestNormal` reads to size the switch
        // (switchloop: without the edges the phi stays {0,1} and recovery collapses to one case).
        // Targets only, NOT `switch_defaults`: Ghidra folds the out-of-range guard (`foldInOneGuard`)
        // only after recovery completes; folding it here would destroy the guard the range analysis
        // pulls back through on every pass.
        partial.switch_targets = switch_targets.clone();
        partial.table_recovery_probe = true; // skip late branch-orientation during table recovery
        super::pipeline::decompile(&mut partial);
        // Recover under the faithful table-lifecycle protocol (Ghidra `Funcdata::recoverJumpTable`,
        // funcdata_block.cc:639-673): a complete (>1 entry) table in `jumpvec` is FROZEN; a 1-entry
        // table is re-checked (`matchModel`) and, when the model disagrees, re-recovered with the
        // nzmask OFF (`recoverMultistage`, jumptable.cc:2653 / `analyzeGuards` usenzmask,
        // jumptable.cc:1052) so the guard comparison bounds the switch — not the realized value set
        // of the partially-wired flow. The frozen tables make the recovery robust to simplification
        // changes in later passes (a perturbed graph can't shrink an already-recovered table).
        super::jumptable::recover_staged(&mut partial, &mut jumpvec);
        let mut added = false;
        for jt in jumpvec.values() {
            for &t in &jt.targets {
                if in_code(t) && !decoded.contains_key(&t) {
                    worklist.push(t);
                    added = true;
                }
            }
            if let Some(d) = jt.default {
                switch_defaults.insert(jt.op_addr, d);
            }
            switch_targets.insert(jt.op_addr, jt.targets.clone());
        }
        if !added {
            break;
        }
    }
    // Ghidra `FlowInfo::truncateIndirectJump` (flow.cc:727, via recoverJumpTables:1445): a BRANCHIND
    // whose jump table could not be recovered ("Too many branches") is treated as an indirect call.
    // Any BRANCHIND still without recovered targets after the multistage loop is such a decline —
    // turn it into a CALLIND and append an artificial return (`artificialHalt`, flow.cc:592: a
    // RETURN of a placeholder constant). The call-arg/return/effect recovery then models it like any
    // indirect call, and the appended RETURN carries the call's result (RAX) out of the function.
    for (&addr, insn) in decoded.iter_mut() {
        let Some(last) = insn.ops.last() else { continue };
        if OpCode::from_u32(last.opcode) != Some(OpCode::Branchind) || switch_targets.contains_key(&addr) {
            continue;
        }
        insn.ops.last_mut().unwrap().opcode = OpCode::Callind as u32;
        insn.ops.push(crate::sleigh::pcode::PcodeOp {
            opcode: OpCode::Return as u32,
            out: None,
            ins: vec![PArg::Var(crate::sleigh::pcode::Varnode { space: "const".into(), offset: 1, size: 4 })],
        });
    }
    // Emit ops in flow-decode (creation) order, not address order — Ghidra's PcodeOpBank deadlist.
    // `flow_order` is a bijection with `decoded`'s keys (pushed once per newly-decoded in-code addr),
    // so draining it yields every decoded instruction exactly once, in creation order.
    let ordered: Vec<crate::sleigh::Instruction> = flow_order.iter().filter_map(|a| decoded.remove(a)).collect();
    let mut f =
        build_from_instrs(name, entry, ordered, &spec.laned, cspec, ram_addr_size, &spec.userops);
    f.switch_targets = switch_targets;
    f.switch_defaults = switch_defaults;
    f.jumptables = jumpvec.into_values().collect();
    f.image = chunks.iter().map(|(a, b)| (*a, b.to_vec())).collect();
    f
}

#[cfg(test)]
mod tests {
    use crate::sleigh::engine::Spec;
    use crate::{datatest, paths};

    fn x86_64() -> Option<(Spec, Vec<u32>)> {
        let sla = paths::ghidra_src().join("Ghidra/Processors/x86/data/languages/x86-64.sla");
        if !sla.exists() {
            eprintln!("skip: {} not found", sla.display());
            return None;
        }
        let spec = Spec::from_sla(&std::fs::read(&sla).unwrap()).ok()?;
        let ctx = spec.context_from_sets(&[("addrsize", 2), ("opsize", 1), ("rexprefix", 0), ("longMode", 1)]);
        Some((spec, ctx))
    }

    #[test]
    fn recovers_jump_table() {
        let Some((spec, ctx)) = x86_64() else { return };
        let dt = datatest::parse_file(&paths::datatests_dir().join("switchind.xml")).unwrap();
        let chunks: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
        let f = super::raw_funcdata_flow_image(&spec, "func", &chunks, dt.chunks[0].offset, &ctx);
        // the 11-entry relative jump table is recovered, every target in code
        let targets = f.switch_targets.values().next().expect("a switch was recovered");
        assert_eq!(targets.len(), 11);
        let (cb, cl) = (dt.chunks[0].offset, dt.chunks[0].bytes.len() as u64);
        assert!(targets.iter().all(|&t| t >= cb && t < cb + cl));
    }

    #[test]
    fn resolves_indirect_call_target() {
        let Some((spec, ctx)) = x86_64() else { return };
        let dt = datatest::parse_file(&paths::datatests_dir().join("deindirect.xml")).unwrap();
        let chunks: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
        let mut f = super::raw_funcdata_flow_image(&spec, "func", &chunks, dt.chunks[0].offset, &ctx);
        crate::decompile::pipeline::decompile(&mut f);
        let c = crate::decompile::printc::print_c(&f);
        // heritaging the CALLIND target forwards the stack store to the call site
        assert!(c.contains("(*(code *)0x1006ca)"), "indirect target should resolve to the constant:\n{c}");
    }

    #[test]
    fn recovers_in_code_jump_table() {
        let Some((spec, ctx)) = x86_64() else { return };
        let dt = datatest::parse_file(&paths::datatests_dir().join("ifswitch.xml")).unwrap();
        let chunks: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
        let f = super::raw_funcdata_flow_image(&spec, "func", &chunks, dt.chunks[0].offset, &ctx);
        // ifswitch's table is embedded in the single code chunk (no separate data chunk)
        assert!(f.switch_targets.values().any(|t| t.len() >= 10), "in-code table recovered: {:?}", f.switch_targets);
    }

    #[test]
    fn switch_in_loop_structures() {
        let Some((spec, ctx)) = x86_64() else { return };
        let dt = datatest::parse_file(&paths::datatests_dir().join("switchloop.xml")).unwrap();
        let chunks: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
        let mut f = super::raw_funcdata_flow_image(&spec, "func", &chunks, dt.chunks[0].offset, &ctx);
        crate::decompile::pipeline::decompile(&mut f);
        let c = crate::decompile::printc::print_c(&f);
        // single-exit switch-in-loop recovers as `while { switch { case …: …; break; } }`
        assert!(c.contains("while (") && c.contains("switch ("), "switch-in-loop should structure:\n{c}");
        assert!(c.contains("case ") && c.contains("break;"), "cases with breaks expected:\n{c}");
    }

    #[test]
    fn loop_header_with_terminal_exit_forms_loop() {
        let Some((spec, ctx)) = x86_64() else { return };
        let dt = datatest::parse_file(&paths::datatests_dir().join("forloop_varused.xml")).unwrap();
        let chunks: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
        let mut f = super::raw_funcdata_flow_image(&spec, "func", &chunks, dt.chunks[0].offset, &ctx);
        crate::decompile::pipeline::decompile(&mut f);
        let c = crate::decompile::printc::print_c(&f);
        // the loop is recovered, not dissolved into guarded ifs by rule_if_no_exit
        assert!(c.contains("for (") || c.contains("while ("), "loop should be recovered:\n{c}");
    }

    #[test]
    fn call_clobber_drops_leftover_args() {
        let Some((spec, ctx)) = x86_64() else { return };
        let dt = datatest::parse_file(&paths::datatests_dir().join("deindirect.xml")).unwrap();
        let chunks: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
        let mut f = super::raw_funcdata_flow_image(&spec, "func", &chunks, dt.chunks[0].offset, &ctx);
        crate::decompile::pipeline::decompile(&mut f);
        let c = crate::decompile::printc::print_c(&f);
        // the second call doesn't inherit the first call's (now clobbered) arg registers
        assert!(c.contains("func_0x00100580(0x10088a)"), "leftover args should be dropped:\n{c}");
    }

    #[test]
    fn recovers_float_return() {
        let Some((spec, ctx)) = x86_64() else { return };
        let dt = datatest::parse_file(&paths::datatests_dir().join("floatconv.xml")).unwrap();
        let chunks: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
        let mut f = super::raw_funcdata_flow_image(&spec, "func", &chunks, dt.chunks[0].offset, &ctx);
        crate::decompile::pipeline::decompile(&mut f);
        let c = crate::decompile::printc::print_c(&f);
        // the float multiply is returned (XMM0 low lane), not an empty `return;`. After heritage
        // refinement the 16-byte XMM is rebuilt as `CONCAT(0, mul)` (Ghidra's `axVar1._0_8_`), so
        // assert the multiply is present and the function is not void rather than a literal prefix.
        assert!(c.contains('*') && !c.contains("return;"), "float return recovered:\n{c}");
    }

    #[test]
    fn emits_switch_statement() {
        let Some((spec, ctx)) = x86_64() else { return };
        let dt = datatest::parse_file(&paths::datatests_dir().join("switchind.xml")).unwrap();
        let chunks: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
        let mut f = super::raw_funcdata_flow_image(&spec, "func", &chunks, dt.chunks[0].offset, &ctx);
        crate::decompile::pipeline::decompile(&mut f);
        let c = crate::decompile::printc::print_c(&f);
        assert!(c.contains("switch ("), "expected a switch statement:\n{c}");
        assert!(c.contains("case 0:") && c.contains("case 10:"), "expected grouped case labels:\n{c}");
    }

    /// Stage 1 (WAR2): the analysis-path proto-model threading. The isolated datatest builders keep
    /// resolving the x86-64 SysV `<default_proto>` (RDI,RSI,RDX,RCX,R8,R9 integer args), while the
    /// analysis bridge threads a `Program`'s own `(language_id, compiler_id)` — so a WAR2-style
    /// Watcom LE binary resolves the beyond-Ghidra `__watcall` register model (EAX,EDX,EBX,ECX) and
    /// its recovery reads parameters instead of decompiling everything as `void(void)`. Asserts both
    /// the resolution and that the built `Funcdata::proto_model` actually carries the threaded model.
    #[test]
    fn analysis_path_threads_compiler_convention() {
        use crate::decompile::fspec::{type_class, ProtoModel};
        let reg = crate::decompile::space::SpaceManager::standard().by_name("register").unwrap();
        // GENERAL register-class arg addressbases of a resolved model's input list.
        let gen_regs = |pm: &ProtoModel| -> Vec<u64> {
            pm.input
                .as_ref()
                .map(|pl| {
                    pl.entry
                        .iter()
                        .filter(|e| e.type_class == type_class::GENERAL && e.space == reg)
                        .map(|e| e.addressbase)
                        .collect()
                })
                .unwrap_or_default()
        };

        // Datatest default: x86-64 SysV.
        let Some((spec64, _)) = x86_64() else { return };
        let sysv = gen_regs(&super::CspecSettings::default_for(&spec64).proto_model);
        if sysv.is_empty() {
            eprintln!("skip: sysv default proto absent (tree missing)");
            return;
        }
        let off64 = |n: &str| spec64.register_offset(n).unwrap();
        assert_eq!(
            sysv,
            vec![off64("RDI"), off64("RSI"), off64("RDX"), off64("RCX"), off64("R8"), off64("R9")],
            "datatest default must stay x86-64 SysV"
        );

        // Analysis path with WAR2's ids: Watcom __watcall (EAX,EDX,EBX,ECX).
        if crate::lang::resolve_cspec("x86:LE:32:default", "watcom").is_none() {
            eprintln!("skip: watcom cspec absent");
            return;
        }
        let Some((spec32, ctx32)) = crate::lang::load_cached("x86:LE:32:default") else { return };
        let off32 = |n: &str| spec32.register_offset(n).unwrap();
        let want = vec![off32("EAX"), off32("EDX"), off32("EBX"), off32("ECX")];
        assert_eq!(
            gen_regs(&super::resolve_proto_model(spec32, "x86:LE:32:default", "watcom")),
            want,
            "analysis path must resolve the __watcall register convention"
        );

        // End-to-end: the threaded ids reach the built Funcdata's proto_model (a `ret` stub).
        let f = super::raw_funcdata_flow_image_overrides(
            spec32,
            "func",
            &[(0x10000, &[0xC3u8])],
            0x10000,
            ctx32,
            &std::collections::HashSet::new(),
            "x86:LE:32:default",
            "watcom",
        );
        assert_eq!(gen_regs(&f.proto_model), want, "built Funcdata must carry the threaded __watcall model");
    }

    /// Build the raw Funcdata for a real function and check the Varnode graph is
    /// internally consistent: every written varnode points back at its defining op, and
    /// every op appears in each of its inputs' descendant lists.
    #[test]
    fn raw_funcdata_graph_is_consistent() {
        let Some((spec, ctx)) = x86_64() else { return };
        let dt = datatest::parse_file(&paths::oracle_fixtures_dir().join("x86_64_sem.xml")).expect("fixture");
        let f = super::raw_funcdata(&spec, "func", &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);

        assert!(f.num_ops() > 0, "no ops lifted");
        for id in f.op_ids() {
            let op = f.op(id).clone();
            if let Some(out) = op.output {
                assert_eq!(f.vn(out).def, Some(id), "output's def must be its op");
                assert!(f.vn(out).is_written());
            }
            for inp in op.inrefs {
                assert!(f.vn(inp).descend.contains(&id), "op must be in each input's descend");
            }
        }
        assert!(f.print_raw().lines().count() > 1);
    }
}
