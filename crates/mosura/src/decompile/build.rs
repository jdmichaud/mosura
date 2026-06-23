//! Build a raw [`Funcdata`] from the SLEIGH lifter — the bridge from the kept engine
//! (`sleigh`) to the faithful decompiler model. This is the pre-heritage "raw p-code"
//! form: one varnode per operand occurrence (heritage links them into SSA in P1), the
//! analogue of Ghidra's `Funcdata::followFlow` result before `ActionHeritage`.

use crate::sleigh::engine::Spec;
use crate::sleigh::pcode::PArg;

use super::funcdata::Funcdata;
use super::op::SeqNum;
use super::opcode::OpCode;
use super::space::{Address, SpaceKind, SpaceManager};
use super::varnode::VarnodeId;

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
) -> Funcdata {
    let spaces = SpaceManager::standard();
    let ram = spaces.by_name("ram").expect("standard ram space");
    let mut f = Funcdata::new(name, Address::new(ram, base), spaces);

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
    build_from_instrs(name, base, spec.disassemble_ctx(bytes, base, context))
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
    build_from_instrs(name, base, decoded.into_values())
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
    use std::collections::{BTreeMap, HashMap};
    // the chunk holding code (the entry), and a reader/classifier over all chunks
    let (cbase, cbytes) = *chunks.iter().find(|(b, by)| entry >= *b && entry < b + by.len() as u64).unwrap_or(&chunks[0]);
    let in_code = |a: u64| a >= cbase && a < cbase + cbytes.len() as u64;
    let in_chunk = |a: u64| chunks.iter().any(|(b, by)| a >= *b && a < b + by.len() as u64);
    let read_i32 = |a: u64| -> Option<i32> {
        chunks.iter().find(|(b, by)| a >= *b && a + 4 <= b + by.len() as u64).map(|(b, by)| {
            let o = (a - b) as usize;
            i32::from_le_bytes([by[o], by[o + 1], by[o + 2], by[o + 3]])
        })
    };

    let mut decoded: BTreeMap<u64, crate::sleigh::Instruction> = BTreeMap::new();
    let mut switch_targets: HashMap<u64, Vec<u64>> = HashMap::new();
    let mut worklist = vec![entry];
    while let Some(a) = worklist.pop() {
        if !in_code(a) || decoded.contains_key(&a) {
            continue;
        }
        let off = (a - cbase) as usize;
        let window = &cbytes[off..(off + 16).min(cbytes.len())];
        let Some(insn) = spec.disassemble_ctx(window, a, context).into_iter().next() else { continue };
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

        // A real jump table has a bounded index: Ghidra only recovers one when the BRANCHIND
        // is guarded by a range check (`index < N`). Without it (e.g. an indirect call guarded
        // by `!= 0`) Ghidra treats the jump as a call — so we decline to recover, too.
        let has_bound = decoded
            .values()
            .chain(std::iter::once(&insn))
            .flat_map(|i| i.ops.iter())
            .any(|o| {
                matches!(
                    OpCode::from_u32(o.opcode),
                    Some(OpCode::IntLess) | Some(OpCode::IntLessequal) | Some(OpCode::IntSless) | Some(OpCode::IntSlessequal)
                )
            });
        if last == Some(OpCode::Branchind) && has_bound {
            // The table read from base `tbl`: 4-byte relative entries, while they stay in code.
            let read_table = |tbl: u64| -> Vec<u64> {
                let mut t = Vec::new();
                let mut i = 0u64;
                while let Some(rel) = read_i32(tbl + i * 4) {
                    let target = tbl.wrapping_add(rel as i64 as u64);
                    if !in_code(target) {
                        break;
                    }
                    t.push(target);
                    i += 1;
                }
                t
            };
            // table base = the constant (in the decoded code so far) whose relative table
            // decodes to the most in-code targets — the `lea` of the jump table. Validating by
            // the decoded entries (rather than requiring a separate data chunk) also finds
            // tables embedded in the code chunk after the function body.
            let best = decoded
                .values()
                .chain(std::iter::once(&insn))
                .flat_map(|i| i.ops.iter())
                .flat_map(|o| o.ins.iter())
                .filter_map(|p| match p {
                    PArg::Var(v) if v.space == "const" && in_chunk(v.offset) => Some(v.offset),
                    _ => None,
                })
                .map(|tbl| (read_table(tbl).len(), tbl))
                .filter(|&(cnt, _)| cnt >= 2)
                .max();
            if let Some((_, tbl)) = best {
                let targets = read_table(tbl);
                for &t in &targets {
                    worklist.push(t);
                }
                switch_targets.insert(a, targets);
            }
        }
        if falls && ilen > 0 {
            succs.push(a + ilen);
        }
        decoded.insert(a, insn);
        worklist.extend(succs);
    }
    let mut f = build_from_instrs(name, cbase, decoded.into_values());
    f.switch_targets = switch_targets;
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
        // the float multiply is returned (XMM0 low lane), not an empty `return;`
        assert!(c.contains('*') && c.contains("return ("), "float return recovered:\n{c}");
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
