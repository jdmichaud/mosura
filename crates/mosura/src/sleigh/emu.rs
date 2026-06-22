//! A minimal p-code interpreter — the semantic oracle for stage 1b (design §3.5).
//!
//! Disassembly-text matching can't catch a *semantically* wrong lift that still
//! prints the right mnemonic (e.g. a bad flag computation). This executes the
//! lifted structured p-code ([`super::pcode`]) over a byte-addressable machine
//! state and lets tests assert the *computed result*, exactly as the `pcodetest`
//! suite intends. Follows branches/loops until `RETURN`; calls are not entered.

use super::engine::Spec;
use super::pcode::{opcode_name, PArg, PcodeOp};
use std::collections::HashMap;

/// The control-flow effect of executing one p-code op.
enum Flow {
    Next,
    Rel(i64),
    Jump(u64),
    Stop,
}

fn mask(v: u64, size: u32) -> u64 {
    if size >= 8 || size == 0 {
        v
    } else {
        v & ((1u64 << (size * 8)) - 1)
    }
}

fn sext(v: u64, size: u32) -> i64 {
    if size == 0 || size >= 8 {
        return v as i64;
    }
    let bits = size * 8;
    let sign = 1u64 << (bits - 1);
    let m = mask(v, size);
    ((m ^ sign).wrapping_sub(sign)) as i64
}

/// A byte-addressable machine state, one byte-map per address space.
#[derive(Default)]
pub struct Machine {
    mem: HashMap<String, HashMap<u64, u8>>,
}

impl Machine {
    /// Read a `(space, offset, size)` location as a little-endian value.
    pub fn read(&self, space: &str, offset: u64, size: u32) -> u64 {
        if space == "const" {
            return mask(offset, size);
        }
        let bank = self.mem.get(space);
        let mut v = 0u64;
        for i in 0..size.min(8) {
            let b = bank.and_then(|m| m.get(&(offset + i as u64))).copied().unwrap_or(0);
            v |= (b as u64) << (8 * i);
        }
        v
    }

    /// Write `value` to a `(space, offset, size)` location, little-endian.
    pub fn write(&mut self, space: &str, offset: u64, size: u32, value: u64) {
        if space == "const" {
            return;
        }
        let bank = self.mem.entry(space.to_string()).or_default();
        for i in 0..size.min(8) {
            bank.insert(offset + i as u64, ((value >> (8 * i)) & 0xff) as u8);
        }
    }

    fn read_arg(&self, a: &PArg) -> u64 {
        match a {
            PArg::Var(v) => self.read(&v.space, v.offset, v.size),
            PArg::Space(_) => 0,
        }
    }
    fn sread_arg(&self, a: &PArg) -> i64 {
        match a {
            PArg::Var(v) => sext(self.read_arg(a), v.size),
            PArg::Space(_) => 0,
        }
    }

    /// Execute one p-code op, returning its control-flow effect.
    fn step(&mut self, op: &PcodeOp) -> Flow {
        let n = op.ins.len();
        let a = |i: usize| if i < n { self.read_arg(&op.ins[i]) } else { 0 };
        let sa = |i: usize| if i < n { self.sread_arg(&op.ins[i]) } else { 0 };
        let osize = op.out.as_ref().map_or(0, |v| v.size);
        let res: u64 = match opcode_name(op.opcode) {
            "RETURN" => return Flow::Stop,
            "BRANCH" => return Self::branch_to(op.ins.first()),
            "CBRANCH" => {
                return if a(1) & 1 != 0 { Self::branch_to(op.ins.first()) } else { Flow::Next };
            }
            "BRANCHIND" => return Flow::Jump(a(0)),
            "CALL" | "CALLIND" => return Flow::Next, // single-function: don't follow calls
            "COPY" => a(0),
            "INT_ADD" => a(0).wrapping_add(a(1)),
            "INT_SUB" => a(0).wrapping_sub(a(1)),
            "INT_MULT" => a(0).wrapping_mul(a(1)),
            "INT_AND" => a(0) & a(1),
            "INT_OR" => a(0) | a(1),
            "INT_XOR" => a(0) ^ a(1),
            "INT_LEFT" => a(0).wrapping_shl(a(1) as u32),
            "INT_RIGHT" => a(0).wrapping_shr(a(1) as u32),
            "INT_SRIGHT" => (sa(0) >> (a(1) as u32).min(63)) as u64,
            "INT_NEGATE" => !a(0),
            "INT_2COMP" => a(0).wrapping_neg(),
            "INT_ZEXT" => a(0),
            "INT_SEXT" => sa(0) as u64,
            "SUBPIECE" => a(0) >> (a(1) * 8),
            "INT_EQUAL" => (a(0) == a(1)) as u64,
            "INT_NOTEQUAL" => (a(0) != a(1)) as u64,
            "INT_LESS" => (a(0) < a(1)) as u64,
            "INT_LESSEQUAL" => (a(0) <= a(1)) as u64,
            "INT_SLESS" => (sa(0) < sa(1)) as u64,
            "INT_SLESSEQUAL" => (sa(0) <= sa(1)) as u64,
            "INT_CARRY" => (a(0).checked_add(a(1)).is_none() || mask(a(0), osize).wrapping_add(mask(a(1), osize)) > mask(u64::MAX, osize)) as u64,
            "INT_SCARRY" => sa(0).overflowing_add(sa(1)).1 as u64,
            "INT_SBORROW" => sa(0).overflowing_sub(sa(1)).1 as u64,
            "BOOL_NEGATE" => (a(0) == 0) as u64,
            "BOOL_AND" => ((a(0) & 1) & (a(1) & 1)) as u64,
            "BOOL_OR" => ((a(0) & 1) | (a(1) & 1)) as u64,
            "BOOL_XOR" => ((a(0) & 1) ^ (a(1) & 1)) as u64,
            "POPCOUNT" => a(0).count_ones() as u64,
            "LZCOUNT" => a(0).leading_zeros() as u64,
            "LOAD" => {
                if let (Some(PArg::Space(spc)), Some(ptr)) = (op.ins.first(), op.ins.get(1)) {
                    self.read(spc, self.read_arg(ptr), osize)
                } else {
                    0
                }
            }
            "STORE" => {
                if let (Some(PArg::Space(spc)), Some(ptr), Some(val)) = (op.ins.first(), op.ins.get(1), op.ins.get(2)) {
                    let (addr, v) = (self.read_arg(ptr), self.read_arg(val));
                    let sz = val.as_var().map_or(0, |vn| vn.size);
                    self.write(spc, addr, sz, v);
                }
                return Flow::Next;
            }
            _ => 0, // unmodeled op: no effect (keeps going)
        };
        if let Some(v) = &op.out {
            self.write(&v.space, v.offset, v.size, mask(res, v.size));
        }
        Flow::Next
    }

    /// Resolve a BRANCH/CBRANCH target operand into a control-flow effect: a
    /// const-space target is a p-code-relative hop within the instruction; any
    /// other (ram/code) is a direct address jump.
    fn branch_to(target: Option<&PArg>) -> Flow {
        match target.and_then(PArg::as_var) {
            Some(v) if v.is_const() => Flow::Rel(v.offset as i64),
            Some(v) => Flow::Jump(v.offset),
            None => Flow::Next,
        }
    }
}

/// Disassemble `bytes` and execute the lifted p-code from `base`, following
/// branches/loops until `RETURN` (or a step cap), returning the final machine
/// state. `inputs` seed registers (space, offset, value, size) — e.g. the
/// calling-convention argument registers (and a stack pointer for `-O0` code).
pub fn run(spec: &Spec, bytes: &[u8], base: u64, context: &[u32], inputs: &[(&str, u64, u64, u32)]) -> Machine {
    // address → (structured ops, fall-through addr)
    let prog: HashMap<u64, (Vec<PcodeOp>, u64)> = spec
        .disassemble_ctx(bytes, base, context)
        .into_iter()
        .map(|insn| {
            let next = insn.address + insn.bytes.len() as u64;
            (insn.address, (insn.ops, next))
        })
        .collect();

    let mut m = Machine::default();
    for &(space, offset, value, size) in inputs {
        m.write(space, offset, size, value);
    }

    const MAX_STEPS: usize = 5_000_000;
    let mut pc = base;
    let mut steps = 0usize;
    'run: while let Some((ops, next)) = prog.get(&pc) {
        let mut i = 0usize;
        let mut jump = None;
        while i < ops.len() {
            steps += 1;
            if steps > MAX_STEPS {
                break 'run;
            }
            match m.step(&ops[i]) {
                Flow::Next => i += 1,
                Flow::Rel(d) => i = (i as i64 + d).max(0) as usize,
                Flow::Jump(t) => {
                    jump = Some(t);
                    break;
                }
                Flow::Stop => break 'run,
            }
        }
        pc = jump.unwrap_or(*next);
    }
    m
}
