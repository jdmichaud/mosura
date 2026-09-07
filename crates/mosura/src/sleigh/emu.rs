//! A minimal p-code interpreter — the semantic oracle for stage 1b (design §3.5).
//!
//! Disassembly-text matching can't catch a *semantically* wrong lift that still
//! prints the right mnemonic (e.g. a bad flag computation). This executes the
//! lifted structured p-code ([`super::pcode`]) over a byte-addressable machine
//! state and lets tests assert the *computed result*, exactly as the `pcodetest`
//! suite intends. Follows branches/loops until `RETURN`; calls are not entered.

use super::engine::Spec;
use super::pcode::{opcode_name, PArg, PcodeOp};
use std::collections::{BTreeSet, HashMap};

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

/// The `define pcodeop`s this interpreter models, resolved from a `CALLOTHER`'s user-op index.
/// The names are x86's (`ia.sinc:764`, `:765`, `:779`, `:781`, `:782`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum UserOp {
    /// `LOCK()` / `UNLOCK()` — the bus-lock bracket around `XCHG`.
    Lock,
    /// `in(port)` — read a hardware I/O port.
    In,
    /// `out(port, value)` — write a hardware I/O port.
    Out,
    /// `swi(n)` — take software interrupt `n`.
    Swi,
    /// Something else this interpreter does not model.
    Unknown,
}

/// The address a modelled software interrupt hands back as its vector. Far above any address in a
/// 32-bit DOS image, so it cannot be mistaken for a real callee.
const SWI_VECTOR: u64 = 0xffff_ff00;

/// The IEEE format `size` bytes selects, or `None` when this interpreter has none for it.
///
/// Ghidra asks `Translate::getFloatFormat(size)` for the target's format at that width
/// (opbehavior.cc:571) and falls back to the integer behaviour when there is none. Here the only
/// formats are the host's own: 4-byte binary32 and 8-byte binary64. x87's 10-byte `float10` gets
/// `None` — see [`Machine::float_op`] for why that is a refusal rather than an omission.
fn ieee_size(size: u32) -> Option<u32> {
    (size == 4 || size == 8).then_some(size)
}

/// `FloatFormat::getHostFloat` (float.cc:228): decode a `size`-byte IEEE encoding to a host
/// `double`. `None` at any width this interpreter has no format for.
fn host_float(encoding: u64, size: u32) -> Option<f64> {
    match ieee_size(size)? {
        4 => Some(f32::from_bits(encoding as u32) as f64),
        _ => Some(f64::from_bits(encoding)),
    }
}

/// `FloatFormat::getEncoding` (float.cc:365): encode a host `double` into a `size`-byte IEEE
/// pattern. `size` must already have passed [`ieee_size`].
fn float_encode(host: f64, size: u32) -> u64 {
    match size {
        4 => (host as f32).to_bits() as u64,
        _ => host.to_bits(),
    }
}

/// A byte-addressable machine state, one byte-map per address space.
#[derive(Default)]
pub struct Machine {
    mem: HashMap<String, HashMap<u64, u8>>,
    /// When set, a byte that was never written reads as a deterministic function of its address
    /// instead of zero. That is what makes DIFFERENTIAL execution possible: two programs run over
    /// the "same" unbounded memory without anyone having to enumerate which addresses they touch,
    /// and a pointer arriving in a register is dereferenceable wherever it points.
    fill: Option<u64>,
    /// Interesting values the fill draws from (see [`fill_dword`]).
    pool: Vec<u64>,
    /// How many p-code operations this interpreter does not model were executed. Any non-zero
    /// count invalidates a same/differs judgement built on this run.
    pub unmodeled: usize,
    /// WHICH operations those were. A bare count says "no evidence" and stops there; the set says
    /// what would have to be built to turn this function into evidence, so the hole in the
    /// instrument can be measured and closed rather than merely noted. A `CALLOTHER` is recorded
    /// as `CALLOTHER:<name>` — the whole point of that opcode is that the NAME is the operation.
    pub unmodeled_ops: BTreeSet<String>,
    /// `define pcodeop` index -> name, copied from the [`Spec`] so a `CALLOTHER` can be named.
    /// Empty in a bare [`Machine`]; then a `CALLOTHER` is recorded by index.
    userops: HashMap<u64, String>,
    /// The registers recorded as the arguments of a software interrupt ([`Effect::Swi`]), from
    /// [`RunConfig::default_args`]. Empty in a bare [`Machine`]: then only the number is recorded.
    swi_args: Vec<(u64, u32)>,
    /// Observable effects, in order (see [`Effect`]). Recorded only when `trace` is on.
    pub effects: Vec<Effect>,
    trace: bool,
    /// Stores inside this half-open range are the program's own scratch (its stack frame) and are
    /// NOT recorded: two implementations of the same function may lay their frames out differently.
    quiet: Option<(u64, u64)>,
}

/// One observable effect of running a function: what a caller could tell apart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// A store outside the scratch window: `(space, address, size, value)`.
    Store(String, u64, u32, u64),
    /// A call, with the argument registers the caller's contract names: `(target, args)`.
    Call(u64, Vec<u64>),
    /// The program trapped — a division by zero. It is an EVENT, not a value: two implementations
    /// that both trap at the same point agree, and whatever their registers hold afterwards is not
    /// defined by anything.
    Fault,
    /// A hardware I/O port access — x86 `IN`/`OUT`: `(is_write, port, size, value)`.
    ///
    /// An `OUT` is as observable as any store: it is how this program talks to the PIT, the PIC and
    /// the sound hardware, and two implementations that write different bytes to port 0x43 are not
    /// the same program. A port READ is recorded too, because on real hardware reading a port is
    /// itself an action (reading 0x60 acknowledges the keyboard controller), so a candidate that
    /// drops the read is not equivalent either — recording it can only turn a false SAME into a
    /// DIFFERS, never the reverse.
    Port(bool, u64, u32, u64),
    /// A software interrupt — x86 `INT n`: `(number, argument registers)`.
    ///
    /// The handler is not entered (it is DOS or the BIOS, which is not in this image), so the
    /// interrupt is an EVENT, exactly like a call. The recorded arguments are the registers
    /// [`RunConfig::default_args`] names — the same policy this harness already applies to a call
    /// whose target declares no contract — because an `INT 0x21` with `AH = 0x4c` and one with
    /// `AH = 0x3d` are different programs and comparing the number alone would not tell them apart.
    Swi(u64, Vec<u64>),
}

/// A cheap deterministic mix — not a hash, just a spreader.
fn mix(seed: u64, a: u64, b: u64) -> u64 {
    let mut x = seed ^ a.wrapping_mul(0x9e37_79b9_7f4a_7c15) ^ b.wrapping_mul(0x1000_0000_1b3);
    x ^= x >> 33;
    x = x.wrapping_mul(0xff51_afd7_ed55_8ccd);
    x ^= x >> 29;
    x
}

/// The value a never-written 4-byte block reads as.
///
/// Uniformly random words are a poor test oracle: a program that branches on `x >= 9` behaves the
/// same under almost every random `x`, so a wrong threshold survives thousands of trials. Most of
/// the memory here is therefore drawn from a POOL of interesting values — the constants the
/// function under test compares against, and their neighbours — with the rest random so that
/// address arithmetic and wide values are still exercised. The choice is a function of the address,
/// so both sides of a differential run see the same memory.
fn fill_dword(seed: u64, space: &str, block: u64, pool: &[u64]) -> u64 {
    let h = mix(seed, block, space.len() as u64);
    if !pool.is_empty() && h % 4 != 0 {
        pool[(h >> 8) as usize % pool.len()]
    } else {
        h
    }
}

/// Deterministic byte for an address that was never written.
fn fill_byte_pool(seed: u64, space: &str, offset: u64, pool: &[u64]) -> u8 {
    let block = offset & !3;
    let w = fill_dword(seed, space, block, pool);
    ((w >> (8 * (offset - block))) & 0xff) as u8
}

/// Deterministic byte for an address that was never written — a cheap mix, not a hash.
fn fill_byte(seed: u64, space: &str, offset: u64) -> u8 {
    (mix(seed, offset, space.len() as u64) & 0xff) as u8
}

/// The ONE BIT the `calls`-th call to `target` leaves in the one-bit register at `off`.
///
/// This is the callee's "answer" for a flag, and it exists as a named function because it has TWO
/// consumers that must not be allowed to drift apart: the flag CLOBBER
/// ([`RunConfig::call_flag_clobbers`], which is what the ORIGINAL's `JC` reads) and the flag
/// RETURN delivery ([`RunConfig::call_flag_returns`], which is what the CANDIDATE reads out of a
/// general register). Computing them separately — even from the same ingredients — would let one
/// side's bit be repaired without the other's, and a differential harness whose two sides get
/// their "same" value from two expressions is one edit away from agreeing for free.
///
/// It varies with the seed, with the call TARGET and with the call's ordinal, so a callee asked
/// twice answers twice, independently, and across seeds both answers occur.
fn call_flag_bit(seed: u64, target: u64, calls: u64, off: u64) -> u64 {
    (fill_byte(seed ^ target ^ (calls << 8) ^ off, "flag", off) & 1) as u64
}

/// The VALUE the `calls`-th call to `target` leaves in the general register at `off`.
///
/// A CALL is an EVENT here, not a descent, so the registers the callee's contract says it destroys
/// are given this deterministic replicated byte instead of whatever the real callee would have
/// computed. It exists as a named function for exactly the reason [`call_flag_bit`] does: it has
/// TWO consumers that must not be allowed to drift apart. The clobber loop gives it to the
/// ORIGINAL's register, and [`RunConfig::call_reg_returns`] gives THE SAME EXPRESSION, at THE SAME
/// `off`, to the register the CANDIDATE's C reads that callee's answer out of. Two expressions
/// that "obviously" compute the same value are one edit away from a harness whose two sides agree
/// for free.
///
/// It depends on `off`, and that is the whole reason the delivery has to be explicit rather than
/// implied: the fill EBX gets is NOT the fill EAX gets, so a candidate that reads the answer out
/// of the wrong register disagrees.
fn call_clobber_fill(seed: u64, target: u64, calls: u64, off: u64) -> u64 {
    let v = fill_byte(seed ^ target ^ (calls << 8) ^ off, "call", off) as u64;
    v | (v << 8) | (v << 16) | (v << 24)
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
            let at = offset + i as u64;
            let b = match bank.and_then(|m| m.get(&at)).copied() {
                Some(b) => b,
                None => match self.fill {
                    Some(seed) if space != "register" && space != "unique" => {
                        fill_byte_pool(seed, space, at, &self.pool)
                    }
                    _ => 0,
                },
            };
            v |= (b as u64) << (8 * i);
        }
        v
    }

    /// Write `value` to a `(space, offset, size)` location, little-endian.
    pub fn write(&mut self, space: &str, offset: u64, size: u32, value: u64) {
        if space == "const" {
            return;
        }
        if self.trace && space != "register" && space != "unique" {
            let scratch = self.quiet.is_some_and(|(lo, hi)| offset >= lo && offset < hi);
            if !scratch {
                self.effects.push(Effect::Store(space.to_string(), offset, size, mask(value, size)));
            }
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
        let opname = opcode_name(op.opcode);
        let res: u64 = match opname {
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
            // The carry is a property of the ADDITION, so it is evaluated at the size of the
            // INPUTS. Using the output size was wrong: an INT_CARRY writing a 1-byte flag (which
            // is every x86 `ADD`/`ADC` flag computation) masked its 4-byte operands to a byte, so
            // `ADD EAX,EBX ; ADC EDX,ECX` carried out of bit 7. Found 2026-09-06 by three
            // independent 64-bit conversions whose only disagreement with the original was that
            // carry, each proved by a twin source carrying at bit 7 and matching exactly.
            "INT_CARRY" => {
                let isize_ = op.ins.first().and_then(PArg::as_var).map_or(osize, |v| v.size);
                let (x, y) = (mask(a(0), isize_), mask(a(1), isize_));
                (x.wrapping_add(y) > mask(u64::MAX, isize_) || x.checked_add(y).is_none()) as u64
            }
            // The SIGNED overflow of an addition/subtraction is a property of the OPERANDS' width,
            // like INT_CARRY above. `sa()` sign-extends its argument to i64, so an i64
            // `overflowing_add` of two 4-byte values NEVER overflows and OF was always 0: x86's
            // JG/JL/JLE/JGE after any 32-bit ADD/ADC/SUB/SBB/CMP degenerated to the SIGN of the
            // WRAPPED result. Found 2026-09-06 on a fixed-point chain whose `ADC EDX,mem / JG`
            // tests whether the exact 33-bit sum is positive; a C source computing that exactly
            // disagreed with the original on exactly the 2 seeds in 128 where the sum overflowed.
            "INT_SCARRY" => {
                let isize_ = op.ins.first().and_then(PArg::as_var).map_or(osize, |v| v.size);
                let s = sa(0).wrapping_add(sa(1));
                (sext(mask(s as u64, isize_), isize_) != s) as u64
            }
            "INT_SBORROW" => {
                let isize_ = op.ins.first().and_then(PArg::as_var).map_or(osize, |v| v.size);
                let s = sa(0).wrapping_sub(sa(1));
                (sext(mask(s as u64, isize_), isize_) != s) as u64
            }
            "BOOL_NEGATE" => (a(0) == 0) as u64,
            "BOOL_AND" => (a(0) & 1) & (a(1) & 1),
            "BOOL_OR" => (a(0) & 1) | (a(1) & 1),
            "BOOL_XOR" => (a(0) & 1) ^ (a(1) & 1),
            // Integer division. Absent until 2026-09-06, when every divide in the subject was
            // silently computing 0 on BOTH sides of a differential run — which makes two different
            // implementations look equal. A division by zero is a FAULT on this target, so the run
            // stops there rather than inventing a value; two equivalent programs fault together.
            "INT_DIV" => {
                if a(1) == 0 {
                    if self.trace {
                        self.effects.push(Effect::Fault);
                    }
                    return Flow::Stop;
                }
                mask(a(0), osize) / mask(a(1), osize)
            }
            "INT_REM" => {
                if a(1) == 0 {
                    if self.trace {
                        self.effects.push(Effect::Fault);
                    }
                    return Flow::Stop;
                }
                mask(a(0), osize) % mask(a(1), osize)
            }
            "INT_SDIV" => {
                if a(1) == 0 {
                    if self.trace {
                        self.effects.push(Effect::Fault);
                    }
                    return Flow::Stop;
                }
                sa(0).wrapping_div(sa(1)) as u64
            }
            "INT_SREM" => {
                if a(1) == 0 {
                    if self.trace {
                        self.effects.push(Effect::Fault);
                    }
                    return Flow::Stop;
                }
                sa(0).wrapping_rem(sa(1)) as u64
            }
            "POPCOUNT" => a(0).count_ones() as u64,
            // `OpBehaviorLzcount::evaluateUnary` (opbehavior.cc:788) is
            // `count_leading_zeros(in1) - 8*(sizeof(uintb) - sizein)`: the count is of the INPUT's
            // own width, not of the 64-bit word it is carried in. Without the correction a 4-byte
            // `LZCOUNT 0x00000001` answered 63 where the hardware (and Ghidra) answer 31 — every
            // width but 8 was wrong by `8*(8-sizein)`. Unreachable on this subject (an i386 has no
            // `LZCNT`), which is why it survived; fixed because a model that is wrong when it does
            // fire is worse than one that is absent.
            "LZCOUNT" => {
                let isize_ = op.ins.first().and_then(PArg::as_var).map_or(8, |v| v.size);
                a(0).leading_zeros() as u64 - 8 * (8 - isize_.min(8)) as u64
            }
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
            // A `define pcodeop` — the language's own escape hatch for an instruction SLEIGH
            // does not express in p-code. Which one it is decides everything, so it is dispatched
            // by name (see [`UserOp`]); anything not named there stays unmodelled.
            "CALLOTHER" => return self.callother(op, osize),
            // The float family. Modelled only at the IEEE widths a `u64` machine word carries
            // exactly; see [`Machine::float_op`] for what that excludes and why.
            "FLOAT_ADD" | "FLOAT_SUB" | "FLOAT_MULT" | "FLOAT_DIV" | "FLOAT_NEG" | "FLOAT_ABS"
            | "FLOAT_SQRT" | "FLOAT_CEIL" | "FLOAT_FLOOR" | "FLOAT_ROUND" | "FLOAT_EQUAL"
            | "FLOAT_NOTEQUAL" | "FLOAT_LESS" | "FLOAT_LESSEQUAL" | "FLOAT_NAN" | "FLOAT_INT2FLOAT"
            | "FLOAT_FLOAT2FLOAT" | "FLOAT_TRUNC" => match self.float_op(opname, op, osize) {
                Some(v) => v,
                None => {
                    self.unmodeled += 1;
                    self.note_unmodeled(opname, op);
                    0
                }
            },
            // An opcode this interpreter does not model (the exotica, and whatever the subject's
            // language lifts to a `CALLOTHER`). Writing 0 and carrying on would make a REAL
            // difference invisible, so the fact is recorded: a caller comparing two runs must treat
            // a verdict with `unmodeled` set as no evidence at all.
            _ => {
                self.unmodeled += 1;
                self.note_unmodeled(opname, op);
                0
            }
        };
        if let Some(v) = &op.out {
            self.write(&v.space, v.offset, v.size, mask(res, v.size));
        }
        Flow::Next
    }

    /// One `CALLOTHER` — a `define pcodeop`, the language's escape hatch for an instruction its
    /// SLEIGH spec does not express in p-code.
    ///
    /// Dispatching BY NAME is Ghidra's own design, not a special case invented here: its emulator
    /// refuses `CALLOTHER` outright (`EmulatePcodeOp::executeCallother`, emulate.cc:295 — *"CALLOTHER
    /// emulation not currently supported"*) and the supported route is
    /// `BreakTableCallBack::registerPcodeCallback(const string &nm, …)` (emulate.hh:146), whose own
    /// comment says the table *"needs a translator object so user-defined pcode ops can be
    /// registered against by name"*. This is that table, with the entries the subject needs.
    ///
    /// The five x86 user-ops handled here are the ones the subject actually executes; every other
    /// language's user-ops, and x86's own remainder (`cpuid`, the MMX/SSE helpers, `fsin`, …),
    /// stay unmodelled and are reported by name. Keying on the NAME is safe: no other processor in
    /// Ghidra's tree defines a `pcodeop` called `in`, `out`, `swi`, `LOCK` or `UNLOCK` (checked
    /// across `Ghidra/Processors/*/data/languages/*.sinc`), so a name cannot mean two things.
    fn callother(&mut self, op: &PcodeOp, osize: u32) -> Flow {
        let res = match self.userop_kind(op) {
            // `LOCK()` / `UNLOCK()` bracket every `XCHG` with memory (ia.sinc:1578-1586 — SLEIGH
            // emits them even with no `LOCK` prefix, since `XCHG` locks the bus implicitly). They
            // assert the bus lock and nothing else. This interpreter runs one program, with no
            // concurrent agent and no memory model, so the bracket has NO observable effect and a
            // no-op is not an approximation of it — it is exactly what it does here. Modelling
            // them is what makes an `XCHG`-using function comparable at all.
            UserOp::Lock => return Flow::Next,
            // `out(port, value)` (ia.sinc:4178-4183). Recorded as an effect: see [`Effect::Port`].
            UserOp::Out => {
                let port = op.ins.get(1).map_or(0, |a| self.read_arg(a));
                let val = op.ins.get(2).map_or(0, |a| self.read_arg(a));
                let sz = op.ins.get(2).and_then(PArg::as_var).map_or(0, |v| v.size);
                if self.trace {
                    self.effects.push(Effect::Port(true, port, sz, val));
                }
                return Flow::Next;
            }
            // `in(port)` (ia.sinc:3627-3637). What the hardware hands back is not in this image, so
            // it is drawn from the seed the same way never-written memory is: a pure function of
            // the PORT, so both sides of a differential run read the same byte. It is deliberately
            // NOT a function of how many reads came before — the harness lets two implementations
            // order independent work differently, and a read-counter would punish that. The cost is
            // that a poll loop (`in al,0x60` until a bit clears) never terminates and both runs are
            // cut off by the step/effect budget, which the verdict already reports as `finished=`.
            UserOp::In => {
                let port = op.ins.get(1).map_or(0, |a| self.read_arg(a));
                // 0x494e is 'IN': a tag that keeps port space from aliasing the memory fill.
                let v = self.fill.map_or(0, |seed| mask(mix(seed, port, 0x494e), osize));
                if self.trace {
                    self.effects.push(Effect::Port(false, port, osize, v));
                }
                v
            }
            // `swi(n)` — the `INT n` instruction (ia.sinc:3656-3658, which lifts to
            // `intloc = swi(n); call [intloc];`). Recorded as an effect: see [`Effect::Swi`]. The
            // value handed back stands for the interrupt VECTOR, which is what the instruction's
            // own indirect call then jumps through; a synthetic address encoding `n` keeps that
            // call deterministic and far above any address in this image.
            UserOp::Swi => {
                let n = op.ins.get(1).map_or(0, |a| self.read_arg(a));
                let mut args = Vec::with_capacity(self.swi_args.len());
                for i in 0..self.swi_args.len() {
                    let (off, sz) = self.swi_args[i];
                    args.push(self.read("register", off, sz));
                }
                if self.trace {
                    self.effects.push(Effect::Swi(n, args));
                }
                SWI_VECTOR | (n & 0xff)
            }
            UserOp::Unknown => {
                self.unmodeled += 1;
                self.note_unmodeled("CALLOTHER", op);
                0
            }
        };
        if let Some(v) = &op.out {
            self.write(&v.space, v.offset, v.size, mask(res, v.size));
        }
        Flow::Next
    }

    /// Which `define pcodeop` this `CALLOTHER` is. Input 0 is the constant user-op index (Ghidra
    /// `opcodes.hh` CPUI_CALLOTHER; the index is a `UserOpSymbol`, slghsymbol.cc:377).
    fn userop_kind(&self, op: &PcodeOp) -> UserOp {
        let idx = op.ins.first().and_then(PArg::as_var).map_or(u64::MAX, |v| v.offset);
        match self.userops.get(&idx).map(String::as_str) {
            Some("LOCK") | Some("UNLOCK") => UserOp::Lock,
            Some("in") => UserOp::In,
            Some("out") => UserOp::Out,
            Some("swi") => UserOp::Swi,
            _ => UserOp::Unknown,
        }
    }

    /// One op of the float family, or `None` when it cannot be modelled FAITHFULLY at these widths.
    ///
    /// Ghidra emulates a target float op by decoding both operands into a HOST `double`, doing the
    /// arithmetic on the host FPU and re-encoding the result — `float.cc:462`: *"Currently we
    /// emulate floating point operations on the target by converting the encoding to the host's
    /// encoding and then performing the operation using the host's floating point unit"*. Each op
    /// below is that same two-step, ported from `FloatFormat::op*` (float.cc:470-680) as reached
    /// through `OpBehaviorFloat*::evaluate*` (opbehavior.cc:569-750), which picks the format from
    /// the INPUT size for everything except `INT2FLOAT` (output size) and `FLOAT2FLOAT` (both).
    ///
    /// WHAT IS MODELLED: `float4` (IEEE binary32) and `float8` (IEEE binary64). Those are the
    /// host's own formats, so the decode/encode is exact and the arithmetic is the same hardware
    /// Ghidra would use.
    ///
    /// WHAT IS NOT, AND WHY: x87 80-bit extended (`float10`). A [`Machine`] value is a `u64` and
    /// [`Machine::read`] stops at 8 bytes, so a 10-byte `ST0` arrives here with its sign and
    /// exponent — the top two bytes — already gone; what is left is the significand alone. There is
    /// no faithful float in that. Worse, the two sides of a differential run would lose the SAME
    /// two bytes and go on agreeing, so a wrong candidate would come back SAME: false evidence,
    /// which is the one outcome this instrument must never produce. So a float op with any 10-byte
    /// operand returns `None` here and is counted as unmodelled, labelled with its width
    /// (`FLOAT_DIV@10`) so the census says plainly that it is the 80-bit case that is missing.
    /// Closing it needs a wider machine word and a soft-float `float10`, not a wider `match`.
    fn float_op(&self, name: &str, op: &PcodeOp, osize: u32) -> Option<u64> {
        let isz = op.ins.first().and_then(PArg::as_var)?.size;
        let x = self.read_arg(op.ins.first()?);
        let bin = |f: fn(f64, f64) -> f64| -> Option<u64> {
            // A binary op is evaluated in the input's format and its result is re-encoded in that
            // same format (opbehavior.cc:619 + float.cc:533).
            let (a, b) = (host_float(x, isz)?, host_float(self.read_arg(op.ins.get(1)?), isz)?);
            (osize == isz).then(|| float_encode(f(a, b), isz))
        };
        let cmp = |f: fn(f64, f64) -> bool| -> Option<u64> {
            let (a, b) = (host_float(x, isz)?, host_float(self.read_arg(op.ins.get(1)?), isz)?);
            Some(f(a, b) as u64)
        };
        let un = |f: fn(f64) -> f64| -> Option<u64> {
            let a = host_float(x, isz)?;
            (osize == isz).then(|| float_encode(f(a), isz))
        };
        match name {
            "FLOAT_ADD" => bin(|a, b| a + b),
            "FLOAT_SUB" => bin(|a, b| a - b),
            "FLOAT_MULT" => bin(|a, b| a * b),
            "FLOAT_DIV" => bin(|a, b| a / b),
            "FLOAT_NEG" => un(|a| -a),
            "FLOAT_ABS" => un(f64::abs),
            "FLOAT_SQRT" => un(f64::sqrt),
            "FLOAT_CEIL" => un(f64::ceil),
            "FLOAT_FLOOR" => un(f64::floor),
            // float.cc:664 chose `round()` — half away from zero — over the `floor(val+.5)` it
            // used to use, and says so in a comment left in the source. Rust's `f64::round` is the
            // same rule.
            "FLOAT_ROUND" => un(f64::round),
            "FLOAT_EQUAL" => cmp(|a, b| a == b),
            "FLOAT_NOTEQUAL" => cmp(|a, b| a != b),
            "FLOAT_LESS" => cmp(|a, b| a < b),
            "FLOAT_LESSEQUAL" => cmp(|a, b| a <= b),
            // float.cc:521 asks the DECODER for the class, so a NaN encoding the host cannot
            // represent still answers true; here the host formats are the target formats.
            "FLOAT_NAN" => Some(host_float(x, isz)?.is_nan() as u64),
            // float.cc:611: the INPUT is a signed integer of `sizein` bytes and the format is the
            // OUTPUT's. The input width is an integer width, so it is not restricted to 4 and 8.
            "FLOAT_INT2FLOAT" => Some(float_encode(sext(x, isz) as f64, ieee_size(osize)?)),
            // float.cc:622: decode in the input's format, re-encode in the output's.
            "FLOAT_FLOAT2FLOAT" => Some(float_encode(host_float(x, isz)?, ieee_size(osize)?)),
            // float.cc:631: truncate toward zero into an integer of `sizeout` bytes. C++'s
            // `(intb)val` is undefined when `val` does not fit; on every host Ghidra runs on that
            // compiles to `cvttsd2si`, which yields the "integer indefinite" value. Rust's `as`
            // saturates instead, so the x86 answer is spelled out rather than inherited.
            "FLOAT_TRUNC" => {
                let v = host_float(x, isz)?;
                let ival = if v.is_nan() || v < -(2f64.powi(63)) || v >= 2f64.powi(63) {
                    i64::MIN
                } else {
                    v as i64
                };
                Some(mask(ival as u64, osize))
            }
            _ => None,
        }
    }

    /// Record an opcode this interpreter met but does not model.
    ///
    /// Only the FIRST sighting allocates: an unmodelled op inside a hot loop is met millions of
    /// times and the set must not cost a `String` each time.
    fn note_unmodeled(&mut self, name: &str, op: &PcodeOp) {
        if name != "CALLOTHER" {
            // For the float family the WIDTH is the whole question — a 4- or 8-byte IEEE operand is
            // modelled and a 10-byte x87 extended one is not — so it is part of the label.
            let label = match name.starts_with("FLOAT_") {
                true => format!("{name}@{}", op.ins.first().and_then(PArg::as_var).map_or(0, |v| v.size)),
                false => name.to_string(),
            };
            if !self.unmodeled_ops.contains(label.as_str()) {
                self.unmodeled_ops.insert(label);
            }
            return;
        }
        // `CALLOTHER`'s first input is the constant index of a `define pcodeop` (Ghidra
        // `opcodes.hh` CPUI_CALLOTHER; the index convention is `UserOpSymbol`, slghsymbol.cc:377).
        // Reporting them all as "CALLOTHER" would merge `swi` with `fsin` with `cpuid`, which is
        // exactly the distinction a census needs.
        let idx = op.ins.first().and_then(PArg::as_var).map_or(u64::MAX, |v| v.offset);
        let label = match self.userops.get(&idx) {
            Some(n) => format!("CALLOTHER:{n}"),
            None => format!("CALLOTHER:#{idx}"),
        };
        if !self.unmodeled_ops.contains(label.as_str()) {
            self.unmodeled_ops.insert(label);
        }
    }

    /// Resolve a BRANCH/CBRANCH target operand into a control-flow effect: a
    /// const-space target is a p-code-relative hop within the instruction; any
    /// other (ram/code) is a direct address jump.
    ///
    /// The relative displacement is SIGN-EXTENDED from the operand's width.
    /// `PcodeCacher::resolveRelatives` (sleigh.cc:130) masks it to that width, so the backward
    /// branch that closes a SLEIGH `<loop>` arrives as `0xfffffffc`, and Ghidra's own interpreter
    /// adds it to the op index in 32-bit arithmetic (`EmulatePcodeCache::executeBranch`,
    /// emulate.cc:404: `uintm id = destaddr.getOffset(); id = id + (uintm)current_op;`). Taking it
    /// as a huge positive would step off the end of the instruction instead of round the loop.
    fn branch_to(target: Option<&PArg>) -> Flow {
        match target.and_then(PArg::as_var) {
            Some(v) if v.is_const() => Flow::Rel(sext(v.offset, v.size)),
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

    let mut m = Machine { userops: spec.userops.clone(), ..Machine::default() };
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
