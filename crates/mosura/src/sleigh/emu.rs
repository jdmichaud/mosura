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
    /// The call ORDINALs at which a SITE-keyed flag contract fired, with the contract
    /// ([`RunConfig::site_flag_returns`]).
    ///
    /// This is how a site-keyed contract crosses from one run to the other. A site is an address
    /// in the ORIGINAL's text and the candidate's compiled code has no such address, so the
    /// original's run reports WHICH CALLS the named site turned out to be — the 1-based ordinal
    /// among all calls — and the candidate's run is given those ordinals
    /// ([`RunConfig::ordinal_flag_returns`]). The ordinal is exactly the correspondence the
    /// verdict already uses: two effect traces are compared element by element, so if they agree
    /// at all then the candidate's k-th call IS the original's k-th call, and if they do not the
    /// seed is already counted as a disagreement.
    pub flag_return_ordinals: Vec<(u64, FlagReturn)>,
    /// The call ORDINALs at which a SITE-keyed REGISTER contract fired, with the contract
    /// ([`RunConfig::site_reg_returns`]). The twin of `flag_return_ordinals`, and it crosses
    /// between the two runs the same way and for the same reason.
    pub reg_return_ordinals: Vec<(u64, RegReturn)>,
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

/// A callee that answers in a FLAG, and the general register a C model of it answers in.
///
/// This subject's calling convention returns booleans in the carry flag — `STC`/`CLC` in the
/// callee, `CALL` then `JC`/`JNC`/`JB`/`JAE` in the caller — and it does so pervasively. No C
/// compiler can express that: Watcom 10.0a rejects `#pragma aux f value [cf]`, and there is no C
/// construct that reads the flags a call left. A candidate must therefore model the callee as
/// returning a VALUE, and the two runs then read the callee's answer out of two different places:
/// the original out of `flag`, the candidate out of `reg`.
///
/// The harness makes those two places hold the same bit (see [`call_flag_bit`]). That is what
/// makes the branch a TEST again rather than a coin: the original's `JC` and the candidate's
/// `if (f())` are given the same answer, so they agree exactly when the candidate uses the
/// condition the way the original does, and a candidate that inverts it or ignores it disagrees on
/// the seeds where the answer differs from the arm it hard-wired.
///
/// `reg` must be a register the callee's clobber set already destroys — it is written on the
/// candidate side only, and writing a register the original still holds live would make the two
/// runs differ for a reason that is not about the candidate.
///
/// This models nothing in Ghidra: Ghidra has no differential-execution harness and no notion of a
/// C source standing in for a function. It is TESTING POLICY, and the honest limits of it are:
///
/// * only a flag the harness can name (`equiv_check`'s `NAMED_FLAGS`: CF, ZF and SF);
/// * keyed by call TARGET, or by call SITE ([`RunConfig::site_flag_returns`]) when the call is
///   indirect and has no static target;
/// * under [`FlagSource::Bit`], a callee that answers in a flag AND leaves a value the caller
///   reads in a register is NOT expressible: `reg` holds the clobber fill on the original side, so
///   it can only be a register whose contents nobody reads. One flag answer per callee. Where the
///   flag is a PREDICATE on the returned value — the callee ends `TEST EAX,EAX` — say so with
///   [`FlagSource::IsZero`] instead and both are available.
///
/// A callee that answers in a REGISTER the candidate cannot name is the other half of the same
/// wall; see [`RegReturn`], which is keyed and delivered the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FlagReturn {
    /// The one-bit register the ORIGINAL's callee answers in: `(register-space offset, 1)`.
    pub flag: (u64, u32),
    /// The general register the CANDIDATE's model answers in: `(register-space offset, size)`.
    pub reg: (u64, u32),
    /// Where the answer comes from — see [`FlagSource`].
    pub from: FlagSource,
}

/// WHERE a flag-answering callee's answer comes from.
///
/// The two are not interchangeable and the difference is the difference between modelling a
/// callee and guessing at it. [`FlagSource::Bit`] says "this callee's answer is a boolean nobody
/// can see in a register"; the derived forms say "this callee's answer is a PREDICATE on the value
/// it already returns", which is what a callee ending `TEST EAX,EAX ; RET` actually does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlagSource {
    /// An independent per-call bit ([`call_flag_bit`]): delivered to the flag on BOTH runs (where
    /// it is the same value the clobber would have left) and, on the CANDIDATE's run only, to the
    /// general register its C model reads the answer out of.
    ///
    /// This is the `STC`/`CLC` convention: the answer exists nowhere but the flag, so the two runs
    /// must be handed it in two different places.
    Bit,
    /// The flag is set when the register is ZERO — a callee that ends `TEST reg,reg ; RET`.
    ///
    /// NOTHING is delivered in a register here, and the model is symmetric: the flag is COMPUTED,
    /// on both runs, from a register both runs already hold the same value in (the call's clobber
    /// fill). That is strictly more faithful than [`FlagSource::Bit`] where it applies, and it is
    /// the only way to express a callee that answers in a flag AND leaves a value the caller
    /// reads — with `Bit` the register would have to carry the flag instead of the value.
    IsZero,
    /// The flag is the register's SIGN bit — the other predicate `TEST reg,reg` leaves.
    IsNegative,
}

/// A callee that leaves its answer in a REGISTER THE CANDIDATE'S C CANNOT NAME, and the register
/// the candidate reads it out of instead.
///
/// This is [`FlagReturn`]'s twin, for the other half of the same wall. An INDIRECT call has no
/// static target, so no `#pragma aux` can give it a convention: Watcom 10.0a ignores every aux
/// form on a function POINTER and a `code *` call returns `int` in EAX, which is all such a call
/// can express. When the original's callee leaves its answer somewhere else — `FUN_00020dba`'s
/// boundary-push routine, reached through `CALL CS:[EDI*4+0x20e42]`, hands back the clipped point
/// as X in EAX and Y in EBX, and the caller publishes both with a pair of `XCHG mem,reg` — the C
/// has no way to READ the second half. The `double (*)(void)` trick buys one more register (under
/// `-fpc` a double comes back in EDX:EAX), and this says which of the original's registers that
/// second channel is standing in for.
///
/// The delivery is the mirror of [`FlagSource::Bit`]'s. `src` is filled on BOTH runs by the
/// ordinary clobber loop — that IS the callee's answer, since a call is an event here — and on the
/// CANDIDATE's run only, `dst` is written with [`call_clobber_fill`] AT `src`'s OFFSET: the same
/// expression, so the two sides provably cannot drift.
///
/// BOTH registers must be ones the call's clobber set destroys, and `equiv_check` stops the run if
/// they are not. For `src`, because otherwise the original still holds the CALLER's own live value
/// there and the fill delivered to the candidate models nothing that happened. For `dst`, because
/// otherwise the delivery would overwrite a value the original still needs, and the two runs would
/// differ for a reason that is not about the candidate — the same condition [`FlagReturn`] is held
/// to. `src` and `dst` must also differ: naming one register on both sides delivers nothing, since
/// both runs already hold that register's fill.
///
/// Like [`FlagReturn`] this models nothing in Ghidra. It is TESTING POLICY, and its honest limits
/// are:
///
/// * it says WHERE a callee's answer lives, not WHAT it is. The answer itself is still the
///   harness's own deterministic fill, shared by both runs, so what is under test is that the
///   candidate reads the right register and does the right thing with it. An INDIRECT call is also
///   still compared BY TARGET ONLY, so the registers going INTO such a call are unchecked.
/// * `equiv_check` holds the two registers to the clobber set it can KNOW at annotation time,
///   which for an indirect call is [`RunConfig::call_clobbers`]. If such a call resolves at run
///   time to a target the source declared a narrower `modify` clause for, the clobber loop follows
///   the declaration and `src` may not be filled after all — the delivery then hands the candidate
///   a value the original does not have, and the run DIFFERS. That fails in the safe direction (a
///   missed agreement, never a false one), and it is the same gap the flag guard has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegReturn {
    /// The register the ORIGINAL's callee leaves its answer in: `(register-space offset, size)`.
    pub src: (u64, u32),
    /// The register the CANDIDATE's C reads that answer out of: `(register-space offset, size)`.
    pub dst: (u64, u32),
}

/// How a differential run is set up: the seed for unset memory, the scratch (stack) window whose
/// stores are not observable, and the argument registers each call target's contract names.
pub struct RunConfig<'a> {
    /// Seed for the deterministic fill of never-written memory. Two runs with the same seed see
    /// the same memory, which is what makes their effects comparable.
    pub seed: u64,
    /// Half-open `(lo, hi)` byte range treated as the program's own frame: stores there are not
    /// recorded.
    pub scratch: (u64, u64),
    /// `target -> (register space offset, size)` list: the registers that carry that callee's
    /// arguments. A target absent from the map uses `default_args`.
    pub call_args: &'a HashMap<u64, Vec<(u64, u32)>>,
    /// The convention to assume for a call whose target has no entry in `call_args`.
    pub default_args: &'a [(u64, u32)],
    /// Targets whose contract passes arguments on the STACK. Their arguments live in the caller's
    /// frame, which two implementations lay out differently, and their count is not recoverable
    /// from the contract — so such a call is compared by TARGET ONLY. The count of these is
    /// reported with the verdict, because a run full of them is weaker evidence.
    pub stack_targets: &'a std::collections::HashSet<u64>,
    /// The stack pointer, `(register offset, size)`. A CALL is an event here, not a descent, but
    /// the instruction's own p-code has already PUSHED the return address by the time the CALL op
    /// is reached — and nothing ever pops it, so every later stack reference in the caller is off
    /// by a word. Popping it here is what makes `PUSH x ; CALL f ; POP x` behave as written.
    pub sp: (u64, u32),
    /// Registers a call is assumed to clobber when its target declares nothing, set to a
    /// deterministic value after each call so the two runs agree on what the callee "returned"
    /// without either program's contract being privileged.
    pub call_clobbers: &'a [(u64, u32)],
    /// `target -> registers that target's own contract says it modifies`, overriding
    /// `call_clobbers` for that callee.
    ///
    /// A fixed clobber set OVERRULES the source: a candidate that truthfully declares
    /// `#pragma aux f modify [eax]` was still told, after every call to `f`, that EBX had been
    /// destroyed — so a value the original legitimately keeps in EBX across the call could not be
    /// expressed, and the only way through was to write a contract known to be false. The declared
    /// list is the candidate's claim about the callee and the harness holds it to it: if the callee
    /// really does clobber EBX, the original's behaviour will disagree somewhere else and the
    /// verdict is still DIFFERS.
    ///
    /// An INDIRECT call's target is not known before the run, so it always falls back.
    pub call_modifies: &'a HashMap<u64, Vec<(u64, u32)>>,
    /// ONE-BIT registers — the arithmetic flags — a call is assumed to clobber.
    ///
    /// Kept apart from `call_clobbers` because a flag is not a byte: filling `ZF` with `0x37`
    /// would make `SETZ` write `0x37`, and every consumer that zero-extends a flag would carry
    /// the noise into arithmetic. These get a single deterministic BIT instead.
    ///
    /// A call MUST clobber them. Without this the arithmetic flags survived a call untouched, and
    /// this subject has a whole band of functions that return a boolean in CF — the `STC`/`CLC`
    /// then `CALL`-then-`JC` idiom — whose verdicts were therefore hollow: a candidate leaving a
    /// different CF was silently agreed with, because on BOTH sides the flag still held whatever
    /// the caller's own last arithmetic had put there. Found 2026-09-06 on FUN_0001effd, which
    /// ends `MOV byte[0x44edb],0 ; JAE ; CALL 0x1e380` — on hardware the `JAE` tests the CF the
    /// PREVIOUS call returned, and nothing in the emulated state made that so.
    pub call_flag_clobbers: &'a [(u64, u32)],
    /// `target -> the flag that callee answers in, and the register a C model answers in`.
    ///
    /// Declared by the candidate's source (see [`FlagReturn`]). After such a call the named flag
    /// gets the callee's answer on BOTH runs — the same bit the clobber would have left there, by
    /// construction — and `is_candidate_run` decides whether the register gets it too.
    ///
    /// Empty by default: a callee not named here is clobbered and nothing more, exactly as before.
    pub call_flag_returns: &'a HashMap<u64, FlagReturn>,
    /// `address of a CALL instruction in THIS run's text -> the flag contract for that ONE call`.
    ///
    /// The alternative key to `call_flag_returns`, and the only one that can reach an INDIRECT
    /// call: a call through a function pointer has no static target, so `CALL [0x45320] ; JAE`
    /// cannot be named by callee at all — the runtime target is a different word on every seed.
    ///
    /// A site belongs to ONE program's text, so this map is given to the ORIGINAL's run only. What
    /// it does there is record the ordinals it fired at ([`Machine::flag_return_ordinals`]) for
    /// the candidate's run to pick up as `ordinal_flag_returns`.
    pub site_flag_returns: &'a HashMap<u64, FlagReturn>,
    /// `call ORDINAL (1-based) -> the flag contract for that call`, the CANDIDATE's side of
    /// `site_flag_returns`.
    ///
    /// Empty on the original's run. See [`Machine::flag_return_ordinals`] for why an ordinal is
    /// the right correspondence between the two runs and cannot launder a disagreement.
    pub ordinal_flag_returns: &'a HashMap<u64, FlagReturn>,
    /// `target -> the register that callee leaves its answer in, and the register a C model reads
    /// it out of` (see [`RegReturn`]).
    ///
    /// Empty by default: a callee not named here is clobbered and nothing more, exactly as before.
    pub call_reg_returns: &'a HashMap<u64, RegReturn>,
    /// `address of a CALL instruction in THIS run's text -> the register contract for that ONE
    /// call` — the only key an INDIRECT call has, and the case [`RegReturn`] exists for.
    ///
    /// Given to the ORIGINAL's run only, exactly like [`RunConfig::site_flag_returns`]: a site is
    /// an address in ITS text. What it does there is record the ordinals it fired at
    /// ([`Machine::reg_return_ordinals`]) for the candidate's run to pick up as
    /// `ordinal_reg_returns`.
    pub site_reg_returns: &'a HashMap<u64, RegReturn>,
    /// `call ORDINAL (1-based) -> the register contract for that call`, the CANDIDATE's side of
    /// `site_reg_returns`. Empty on the original's run.
    pub ordinal_reg_returns: &'a HashMap<u64, RegReturn>,
    /// Is this the CANDIDATE's run? Then a [`FlagReturn`] callee's answer is ALSO delivered in the
    /// general register the candidate reads it from, and a [`RegReturn`] callee's answer in the
    /// register the candidate reads THAT out of.
    ///
    /// This is the one asymmetry in the whole instrument, and it is the point: the two programs
    /// disagree about WHERE a callee's answer lives, and about nothing else. The original run
    /// leaves a flag answer in the flag alone, which is what its `JC` reads; the candidate run
    /// additionally puts it in the register its `#pragma aux ... value [reg]` names, which is what
    /// its `if` reads. Both come from one [`call_flag_bit`], so the branch condition is genuinely
    /// shared — and a register answer crosses the same way through one [`call_clobber_fill`].
    ///
    /// (Named `flag_return_in_register` while a flag was the only thing that could be delivered.)
    pub is_candidate_run: bool,
    /// Give up after this many p-code steps (a wrong candidate can loop forever).
    pub max_steps: usize,
    /// Interesting values for the memory fill — typically the constants the function compares
    /// against, so boundary behaviour is actually exercised (see [`fill_dword`]).
    pub pool: &'a [u64],
    /// Bytes of the ORIGINAL program to place in the data space before the run, as
    /// `(address, bytes)`.
    ///
    /// A function's own extent is DATA as well as code — an inline jump table, a constant pool
    /// between basic blocks, a `MOV EAX,[here]` — and without this it read as the seeded fill
    /// instead of the byte that is actually there.
    ///
    /// It is the ORIGINAL's bytes on BOTH sides, deliberately. Writing each run its OWN code would
    /// compare the two programs by their ENCODING, which is the one thing this harness declares
    /// free to differ: measured over the verified corpus it turned 14 correct sources into DIFFERS,
    /// every one of them a seed whose pointer happened to land inside the function's extent, where
    /// the original read its own opcodes and the candidate read its own — different bytes for a
    /// reason that is not a difference in behaviour. The memory image is the ENVIRONMENT the
    /// candidate is judged in, and the original is what that environment actually contains.
    pub image: &'a [(u64, &'a [u8])],
    /// Stop after this many recorded effects. A step budget alone is UNFAIR between two
    /// implementations of one function: the one whose loop body lifts to more p-code ops completes
    /// fewer iterations, and their traces then differ for a reason that is not a difference in
    /// behaviour. Counting effects makes the budget mean the same thing on both sides.
    pub max_effects: usize,
}

/// Execute `bytes` from `base` recording the effects a caller could observe, with calls treated
/// as events rather than followed.
///
/// This is the semantic-equivalence instrument: run the ORIGINAL function and a CANDIDATE
/// implementation of it over the same seeded state and compare the effect traces. It deliberately
/// does NOT compare register allocation, frame layout, or instruction selection — only the stores
/// the function makes outside its own frame, the calls it makes with the arguments its contract
/// says it passes, and (left to the caller) whatever register the contract names as the result.
pub fn run_traced(
    spec: &Spec,
    bytes: &[u8],
    base: u64,
    context: &[u32],
    inputs: &[(&str, u64, u64, u32)],
    cfg: &RunConfig<'_>,
) -> (Machine, bool) {
    let mut prog: HashMap<u64, (Vec<PcodeOp>, u64)> = spec
        .disassemble_ctx(bytes, base, context)
        .into_iter()
        .map(|insn| {
            let next = insn.address + insn.bytes.len() as u64;
            (insn.address, (insn.ops, next))
        })
        .collect();

    let mut m = Machine {
        fill: Some(cfg.seed),
        pool: cfg.pool.to_vec(),
        trace: true,
        quiet: Some(cfg.scratch),
        userops: spec.userops.clone(),
        // A software interrupt's handler is not in this image, so it has no declared contract —
        // exactly the situation `default_args` exists for. See [`Effect::Swi`].
        swi_args: cfg.default_args.to_vec(),
        ..Machine::default()
    };
    // The memory image, as DATA — see [`RunConfig::image`]. Only what the caller hands over is
    // written; the rest of the address space is still fill, which is a separate and larger gap.
    let data = spec.spaces.get(spec.default_space).map(|s| s.name.clone()).unwrap_or_default();
    for &(at, chunk) in cfg.image {
        for (i, b) in chunk.iter().enumerate() {
            m.write(&data, at + i as u64, 1, *b as u64);
        }
    }
    for &(space, offset, value, size) in inputs {
        m.write(space, offset, size, value);
    }
    // The seeding writes above are setup, not effects.
    m.effects.clear();

    let mut pc = base;
    let mut steps = 0usize;
    let mut calls = 0u64;
    let mut finished = false;
    'run: loop {
        // `prog` is a LINEAR sweep from `base`, so any DATA embedded in the code -- a jump table,
        // most of all -- throws the sweep out of phase and the real instruction boundaries after
        // it are simply absent from the map. A `BRANCHIND` into one of them used to miss and the
        // function silently STOPPED: no call, no store, its entry registers still in place, and
        // the run counted only as `finished=false`. FUN_0000054b (corpus 00011) is the witness --
        // its four-entry table at 0x55d puts the q==3 arm at 0x56d, which the sweep swallows
        // inside the `ADD EAX,0xd8f70000` it decodes at 0x56a, so the original lost that whole
        // quadrant on exactly the 32 seeds in 128 that take it. Decode such an address on demand;
        // that cannot change any address the sweep already reached, and costs nothing until a
        // branch actually lands off-phase.
        if !prog.contains_key(&pc) {
            let Some(off) = pc.checked_sub(base).filter(|o| (*o as usize) < bytes.len()) else {
                break 'run;
            };
            let Some(insn) = spec.disassemble_ctx(&bytes[off as usize..], pc, context).into_iter().next()
            else {
                break 'run;
            };
            let nxt = insn.address + insn.bytes.len() as u64;
            prog.insert(pc, (insn.ops, nxt));
        }
        let (ops, next) = &prog[&pc];
        let mut i = 0usize;
        let mut jump = None;
        while i < ops.len() {
            steps += 1;
            if steps > cfg.max_steps || m.effects.len() > cfg.max_effects {
                break 'run;
            }
            let op = &ops[i];
            match opcode_name(op.opcode) {
                // A CALL is an EVENT: record the target and the arguments its contract names,
                // then apply a deterministic "callee effect" so both runs continue from the same
                // state without either side's return-value convention being assumed correct.
                "CALL" | "CALLIND" => {
                    let indirect = opcode_name(op.opcode) == "CALLIND";
                    // A DIRECT call names its destination in the varnode's OFFSET (the operand is
                    // `(ram,0x23118,4)`). An INDIRECT call names a varnode whose VALUE is the
                    // destination — `CALLIND (register,0x0,4)` is `CALL EAX`. Taking the offset
                    // there compared two runs by the varnode's IDENTITY: the same computed target
                    // reached through a different register looked like a different callee, and two
                    // different targets through the same register looked like the same one. Found
                    // 2026-09-06 from two directions at once — a convergence wave on 00748, and a
                    // software interrupt, where every `INT n` in the subject came out as a call to
                    // the `unique` slot the lifter happened to allocate for the vector.
                    let target = if indirect {
                        m.read_arg(op.ins.first().unwrap_or(&PArg::Space(String::new())))
                    } else {
                        match op.ins.first().and_then(PArg::as_var) {
                            Some(v) if !v.is_const() => v.offset,
                            _ => m.read_arg(op.ins.first().unwrap_or(&PArg::Space(String::new()))),
                        }
                    };
                    // An INDIRECT call's callee is not known until run time, so neither is its
                    // contract: comparing a fixed set of registers there fails correct programs for
                    // holding different values in registers that are not arguments at all. Such a
                    // call is compared by TARGET only, and counted, so the weakening is visible.
                    let vals: Vec<u64> = if indirect || cfg.stack_targets.contains(&target) {
                        Vec::new()
                    } else {
                        let args = cfg.call_args.get(&target).map(|v| v.as_slice()).unwrap_or(cfg.default_args);
                        args.iter().map(|&(off, sz)| m.read("register", off, sz)).collect()
                    };
                    m.effects.push(Effect::Call(target, vals));
                    calls += 1;
                    // The callee returned: take its return address back off the stack.
                    let (spoff, spsz) = cfg.sp;
                    let espv = m.read("register", spoff, spsz);
                    m.write("register", spoff, spsz, espv.wrapping_add(spsz as u64));
                    let clobbers =
                        cfg.call_modifies.get(&target).map(|v| v.as_slice()).unwrap_or(cfg.call_clobbers);
                    for &(off, sz) in clobbers {
                        m.write("register", off, sz, call_clobber_fill(cfg.seed, target, calls, off));
                    }
                    // ...and the arithmetic flags, which a call leaves undefined WHATEVER its
                    // contract says: Watcom's `modify` clause describes registers, and there is no
                    // spelling in it for "preserves the flags". One BIT each — see
                    // [`RunConfig::call_flag_clobbers`].
                    for &(off, sz) in cfg.call_flag_clobbers {
                        m.write("register", off, sz, call_flag_bit(cfg.seed, target, calls, off));
                    }
                    // ...and if this callee ANSWERS in a flag, that flag's clobber IS its answer,
                    // and the candidate is handed the same bit in the register it models the
                    // answer as living in. Writing the flag here as well as in the loop above is
                    // deliberate: it is the same value ([`call_flag_bit`]) either way, and it
                    // makes the answer independent of whether the flag happens to be in
                    // `call_flag_clobbers`. See [`RunConfig::call_flag_returns`].
                    // A contract may be keyed by the callee's TARGET, by this call's SITE (the
                    // address of the CALL instruction, the only key an indirect call can have) or
                    // — on the candidate's run — by the call's ORDINAL, which is what a site
                    // resolved to on the original's. The three key spaces are disjoint by
                    // construction: `equiv_check` rejects a site that names a call whose target is
                    // already named, and gives the site map to one run and the ordinal map to the
                    // other.
                    let by_site = cfg.site_flag_returns.get(&pc);
                    if let Some(fr) = by_site {
                        m.flag_return_ordinals.push((calls, *fr));
                    }
                    let fr = cfg
                        .call_flag_returns
                        .get(&target)
                        .or(by_site)
                        .or_else(|| cfg.ordinal_flag_returns.get(&calls));
                    if let Some(fr) = fr {
                        match fr.from {
                            FlagSource::Bit => {
                                let bit = call_flag_bit(cfg.seed, target, calls, fr.flag.0);
                                m.write("register", fr.flag.0, fr.flag.1, bit);
                                if cfg.is_candidate_run {
                                    m.write("register", fr.reg.0, fr.reg.1, bit);
                                }
                            }
                            // ...and a callee whose answer is a PREDICATE on the value it returns
                            // (`TEST EAX,EAX ; RET`) needs no delivery at all: the register holds
                            // the same clobber fill on both runs, so computing the flag from it
                            // here gives the original's `JE` exactly what the candidate's
                            // `if (k == 0)` computes for itself. Symmetric, so it runs on both
                            // sides regardless of `is_candidate_run`.
                            FlagSource::IsZero | FlagSource::IsNegative => {
                                let v = m.read("register", fr.reg.0, fr.reg.1);
                                let bit = match fr.from {
                                    FlagSource::IsZero => u64::from(v == 0),
                                    _ => (v >> (8 * fr.reg.1 - 1)) & 1,
                                };
                                m.write("register", fr.flag.0, fr.flag.1, bit);
                            }
                        }
                    }
                    // ...and if this callee leaves its answer in a REGISTER the candidate's C
                    // cannot name — the indirect-call case, where no `#pragma aux` reaches — the
                    // candidate is handed that same answer in the register it CAN name. The
                    // original's `src` was filled by the clobber loop above; this writes the
                    // candidate's `dst` from the SAME [`call_clobber_fill`] at the SAME offset, so
                    // both runs read one value out of two places. See [`RegReturn`].
                    //
                    // Keyed exactly as the flag contract is, and run AFTER it deliberately: a
                    // DERIVED flag ([`FlagSource::IsZero`]) is COMPUTED from a register, and that
                    // computation must see the ordinary clobber fill on BOTH runs. `equiv_check`
                    // refuses a contract whose `dst` is a flag contract's register for the same
                    // call, so in practice the two deliveries never touch one register.
                    let reg_by_site = cfg.site_reg_returns.get(&pc);
                    if let Some(rr) = reg_by_site {
                        m.reg_return_ordinals.push((calls, *rr));
                    }
                    let rr = cfg
                        .call_reg_returns
                        .get(&target)
                        .or(reg_by_site)
                        .or_else(|| cfg.ordinal_reg_returns.get(&calls));
                    if let (Some(rr), true) = (rr, cfg.is_candidate_run) {
                        let v = call_clobber_fill(cfg.seed, target, calls, rr.src.0);
                        m.write("register", rr.dst.0, rr.dst.1, v);
                    }
                    i += 1;
                }
                "RETURN" => {
                    finished = true;
                    break 'run;
                }
                _ => match m.step(op) {
                    Flow::Next => i += 1,
                    Flow::Rel(d) => i = (i as i64 + d).max(0) as usize,
                    Flow::Jump(t) => {
                        jump = Some(t);
                        break;
                    }
                    Flow::Stop => {
                        finished = true;
                        break 'run;
                    }
                },
            }
        }
        pc = jump.unwrap_or(*next);
    }
    (m, finished)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sleigh::pcode::Varnode;

    /// Opcode NUMBER for a mnemonic, by inverting [`opcode_name`] — so these tests and the
    /// interpreter read the same table (`opcodes.hh`) and cannot drift apart.
    fn opcode(name: &str) -> u32 {
        (1..=73).find(|&n| opcode_name(n) == name).unwrap_or_else(|| panic!("no opcode {name}"))
    }

    fn vn(space: &str, offset: u64, size: u32) -> Varnode {
        Varnode { space: space.to_string(), offset, size }
    }
    fn arg(space: &str, offset: u64, size: u32) -> PArg {
        PArg::Var(vn(space, offset, size))
    }
    fn konst(value: u64, size: u32) -> PArg {
        arg("const", value, size)
    }
    fn pcode(name: &str, out: Option<Varnode>, ins: Vec<PArg>) -> PcodeOp {
        PcodeOp { opcode: opcode(name), out, ins }
    }

    /// A machine set up the way [`run_traced`] sets one up: recording effects, unset memory drawn
    /// from a seed, and x86's user-op indices (`ia.sinc:764-782`, as emitted by `x86.sla`).
    fn traced() -> Machine {
        let mut userops = HashMap::new();
        for (i, n) in [(1u64, "in"), (2, "out"), (0x10, "swi"), (0x11, "LOCK"), (0x12, "UNLOCK"), (0x13, "cpuid")] {
            userops.insert(i, n.to_string());
        }
        Machine {
            fill: Some(0x5eed_1234),
            trace: true,
            userops,
            // x86 register-space offsets of EAX/EDX/EBX/ECX — the harness's `default_args`.
            swi_args: vec![(0, 4), (8, 4), (12, 4), (4, 4)],
            ..Machine::default()
        }
    }

    /// `XCHG` with memory lifts to `LOCK() … UNLOCK()` (ia.sinc:1578-1586) whether or not a `LOCK`
    /// prefix is present. On one program with no concurrent agent that bracket asserts nothing an
    /// observer could see, so it must execute silently — not be counted as evidence-destroying.
    #[test]
    fn bus_lock_bracket_is_silent() {
        let mut m = traced();
        for idx in [0x11u64, 0x12] {
            m.step(&pcode("CALLOTHER", None, vec![konst(idx, 4)]));
        }
        assert_eq!(m.unmodeled, 0, "the lock bracket must not invalidate a run");
        assert!(m.effects.is_empty(), "it is not an observable effect either");
    }

    /// `out(port, value)` (ia.sinc:4178) is how this program drives the PIT and the PIC. It is as
    /// observable as a store, so it is recorded with its port, width and value.
    #[test]
    fn port_write_is_an_observable_effect() {
        let mut m = traced();
        // OUT 0x43,AL — `CALLOTHER (const,0x2,4) (const,0x43,1) (register,0x0,1)`.
        m.write("register", 0, 1, 0x34);
        m.step(&pcode("CALLOTHER", None, vec![konst(2, 4), konst(0x43, 1), arg("register", 0, 1)]));
        assert_eq!(m.effects, vec![Effect::Port(true, 0x43, 1, 0x34)]);
        assert_eq!(m.unmodeled, 0);
    }

    /// `in(port)` (ia.sinc:3633) has no answer inside this image, so it is drawn from the seed as a
    /// pure function of the PORT — the same rule as never-written memory, and for the same reason:
    /// both sides of a differential run must read the same byte without anyone enumerating what the
    /// hardware would have said. Two reads of one port agree; two ports (almost surely) do not.
    #[test]
    fn port_read_is_deterministic_per_port_and_recorded() {
        let mut m = traced();
        let read = |m: &mut Machine, port: u64| {
            m.step(&pcode("CALLOTHER", Some(vn("register", 0, 1)), vec![konst(1, 4), konst(port, 1)]));
            m.read("register", 0, 1)
        };
        let a = read(&mut m, 0x60);
        let b = read(&mut m, 0x60);
        let c = read(&mut m, 0x40);
        assert_eq!(a, b, "the same port must read the same on both sides of a differential run");
        assert_ne!(a, c, "different ports must not collapse to one value");
        assert_eq!(m.unmodeled, 0);
        assert_eq!(m.effects.len(), 3, "a port READ is an action on real hardware, so it is recorded");
        assert_eq!(m.effects[0], Effect::Port(false, 0x60, 1, a));
    }

    /// `INT n` lifts to `intloc = swi(n); call [intloc];` (ia.sinc:3658). The interrupt is an event:
    /// its NUMBER and the registers the harness's contract-less-call convention names are recorded,
    /// so `INT 0x21` with `AH=0x4c` and one with `AH=0x3d` are told apart. The value handed back is
    /// the synthetic vector the instruction's own indirect call then jumps through.
    #[test]
    fn software_interrupt_records_number_and_argument_registers() {
        let mut m = traced();
        for (off, val) in [(0u64, 0x4c00u64), (8, 0x1111), (12, 0x2222), (4, 0x3333)] {
            m.write("register", off, 4, val);
        }
        m.step(&pcode("CALLOTHER", Some(vn("unique", 0x100, 4)), vec![konst(0x10, 4), konst(0x21, 1)]));
        assert_eq!(m.effects, vec![Effect::Swi(0x21, vec![0x4c00, 0x1111, 0x2222, 0x3333])]);
        assert_eq!(m.read("unique", 0x100, 4), SWI_VECTOR | 0x21);
        assert_eq!(m.unmodeled, 0);
    }

    /// The point of the whole change: an unmodelled op says WHICH one it was, so a blocked function
    /// reports what would unblock it. A `CALLOTHER` is named by its user-op — merging `cpuid` into a
    /// bare "CALLOTHER" would hide exactly the distinction a census needs — and an index the
    /// language table does not know is reported as an index rather than guessed at.
    #[test]
    fn an_unmodeled_op_is_reported_by_name() {
        let mut m = traced();
        m.step(&pcode("CALLOTHER", Some(vn("register", 0, 4)), vec![konst(0x13, 4), konst(0, 4)]));
        m.step(&pcode("CALLOTHER", Some(vn("register", 0, 4)), vec![konst(0xbeef, 4)]));
        m.step(&pcode("SEGMENTOP", Some(vn("register", 0, 4)), vec![konst(0, 4)]));
        assert_eq!(m.unmodeled, 3);
        let got: Vec<&str> = m.unmodeled_ops.iter().map(String::as_str).collect();
        assert_eq!(got, vec!["CALLOTHER:#48879", "CALLOTHER:cpuid", "SEGMENTOP"]);
    }

    /// `OpBehaviorLzcount::evaluateUnary` (opbehavior.cc:788) counts within the INPUT's width:
    /// `count_leading_zeros(in1) - 8*(sizeof(uintb) - sizein)`. Before the fix a 4-byte input was
    /// counted across the whole 64-bit carrier and every answer was 32 too large.
    #[test]
    fn lzcount_counts_within_the_input_width() {
        let mut m = traced();
        for (val, size, want) in [(1u64, 4u32, 31u64), (0, 4, 32), (0x8000_0000, 4, 0), (1, 1, 7), (1, 8, 63)] {
            m.write("register", 0, size, val);
            m.step(&pcode("LZCOUNT", Some(vn("register", 32, 4)), vec![arg("register", 0, size)]));
            assert_eq!(m.read("register", 32, 4), want, "lzcount({val:#x}) at {size} bytes");
        }
    }

    /// The float family is Ghidra's own two-step (float.cc:462): decode both operands to a host
    /// `double`, use the host FPU, re-encode. At `float4`/`float8` the host's formats ARE the
    /// target's, so the answer is the IEEE one and can be checked against Rust's own arithmetic.
    #[test]
    fn float_arithmetic_matches_host_ieee_at_4_and_8_bytes() {
        let mut m = traced();
        for (name, f) in [
            ("FLOAT_ADD", (|a: f64, b: f64| a + b) as fn(f64, f64) -> f64),
            ("FLOAT_SUB", |a, b| a - b),
            ("FLOAT_MULT", |a, b| a * b),
            ("FLOAT_DIV", |a, b| a / b),
        ] {
            for (x, y) in [(1.5f64, 0.25f64), (-3.0, 7.0), (1e300, 1e-300), (0.0, 3.0)] {
                m.write("register", 0, 8, x.to_bits());
                m.write("register", 8, 8, y.to_bits());
                m.step(&pcode(name, Some(vn("register", 16, 8)), vec![arg("register", 0, 8), arg("register", 8, 8)]));
                let (got, want) = (f64::from_bits(m.read("register", 16, 8)), f(x, y));
                // `1e300 * 1e-300` in `float4` is `inf * 0` = NaN, and NaN is not equal to itself:
                // the operands stay because overflow/underflow to infinity is exactly the corner
                // this is meant to exercise.
                assert!(got == want || (got.is_nan() && want.is_nan()), "{name} f8 {x} {y}: {got} != {want}");

                let (xs, ys) = (x as f32, y as f32);
                m.write("register", 0, 4, xs.to_bits() as u64);
                m.write("register", 8, 4, ys.to_bits() as u64);
                m.step(&pcode(name, Some(vn("register", 16, 4)), vec![arg("register", 0, 4), arg("register", 8, 4)]));
                let got = f32::from_bits(m.read("register", 16, 4) as u32);
                let want = f(xs as f64, ys as f64) as f32;
                assert!(got == want || (got.is_nan() && want.is_nan()), "{name} f4 {xs} {ys}: {got} != {want}");
            }
        }
        assert_eq!(m.unmodeled, 0);
    }

    /// The unary and comparison halves, and the conversions. `FLOAT_NAN` (float.cc:521) is the one
    /// that cannot be spelled as a comparison, and `FLOAT_TRUNC` (float.cc:631) truncates TOWARD
    /// ZERO into an integer of the output's width, which is not the same as `FLOOR`.
    #[test]
    fn float_unary_comparison_and_conversion() {
        let mut m = traced();
        let mut unary = |name: &str, x: f64| {
            m.write("register", 0, 8, x.to_bits());
            m.step(&pcode(name, Some(vn("register", 16, 8)), vec![arg("register", 0, 8)]));
            f64::from_bits(m.read("register", 16, 8))
        };
        assert_eq!(unary("FLOAT_NEG", 2.5), -2.5);
        assert_eq!(unary("FLOAT_ABS", -2.5), 2.5);
        assert_eq!(unary("FLOAT_SQRT", 9.0), 3.0);
        assert_eq!(unary("FLOAT_CEIL", -1.5), -1.0);
        assert_eq!(unary("FLOAT_FLOOR", -1.5), -2.0);
        // float.cc:664 picked round-half-AWAY-from-zero over the `floor(val+.5)` it replaced.
        assert_eq!(unary("FLOAT_ROUND", -1.5), -2.0);
        assert_eq!(unary("FLOAT_ROUND", 2.5), 3.0);

        let mut cmp = |name: &str, x: f64, y: f64| {
            m.write("register", 0, 8, x.to_bits());
            m.write("register", 8, 8, y.to_bits());
            m.step(&pcode(name, Some(vn("register", 16, 1)), vec![arg("register", 0, 8), arg("register", 8, 8)]));
            m.read("register", 16, 1)
        };
        assert_eq!(cmp("FLOAT_EQUAL", 1.0, 1.0), 1);
        assert_eq!(cmp("FLOAT_NOTEQUAL", 1.0, 2.0), 1);
        assert_eq!(cmp("FLOAT_LESS", 1.0, 2.0), 1);
        assert_eq!(cmp("FLOAT_LESSEQUAL", 2.0, 2.0), 1);
        // Every ordered comparison against a NaN is false — including equality with itself, which
        // is what makes `FLOAT_NAN` a separate opcode.
        assert_eq!(cmp("FLOAT_EQUAL", f64::NAN, f64::NAN), 0);
        assert_eq!(cmp("FLOAT_LESS", f64::NAN, 1.0), 0);

        m.write("register", 0, 8, f64::NAN.to_bits());
        m.step(&pcode("FLOAT_NAN", Some(vn("register", 16, 1)), vec![arg("register", 0, 8)]));
        assert_eq!(m.read("register", 16, 1), 1);

        // float.cc:611 sign-extends the integer input first: a 4-byte 0xffffffff is -1.0, not 4e9.
        m.write("register", 0, 4, 0xffff_ffff);
        m.step(&pcode("FLOAT_INT2FLOAT", Some(vn("register", 16, 8)), vec![arg("register", 0, 4)]));
        assert_eq!(f64::from_bits(m.read("register", 16, 8)), -1.0);

        m.write("register", 0, 4, (0.5f32).to_bits() as u64);
        m.step(&pcode("FLOAT_FLOAT2FLOAT", Some(vn("register", 16, 8)), vec![arg("register", 0, 4)]));
        assert_eq!(f64::from_bits(m.read("register", 16, 8)), 0.5);

        for (x, want) in [(2.9f64, 2u64), (-2.9, (-2i64) as u64 & 0xffff_ffff), (0.0, 0)] {
            m.write("register", 0, 8, x.to_bits());
            m.step(&pcode("FLOAT_TRUNC", Some(vn("register", 16, 4)), vec![arg("register", 0, 8)]));
            assert_eq!(m.read("register", 16, 4), want, "trunc({x})");
        }
        assert_eq!(m.unmodeled, 0);
    }

    /// The refusal that matters. x87 arithmetic in Ghidra's x86 spec runs on 10-byte `ST` varnodes
    /// (ia.sinc:93, `FADD` at ia.sinc:5082), and a [`Machine`] value is a `u64`: the sign and
    /// exponent of an 80-bit operand are gone before this code ever sees it. Both sides of a
    /// differential run would lose the same two bytes and keep agreeing, so a wrong candidate would
    /// come back SAME. It is left unmodelled ON PURPOSE, and labelled with the width so the census
    /// reports the 80-bit case by name instead of blaming the opcode.
    #[test]
    fn x87_extended_precision_is_refused_not_approximated() {
        let mut m = traced();
        m.step(&pcode(
            "FLOAT_ADD",
            Some(vn("register", 0x1100, 10)),
            vec![arg("register", 0x1100, 10), arg("register", 0x110a, 10)],
        ));
        assert_eq!(m.unmodeled, 1, "an 80-bit float op must still invalidate the run");
        assert_eq!(m.unmodeled_ops.iter().map(String::as_str).collect::<Vec<_>>(), vec!["FLOAT_ADD@10"]);
    }
}
