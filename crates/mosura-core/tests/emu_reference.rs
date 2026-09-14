//! Reference execution: what a client capturing the ORIGINAL's results needs the interpreter to
//! say, on source-built routines whose behaviour is known from their own text
//! (`oracle/ground-truth/src/{divide_fault,spin_until_zero,call_chain}.S`, both x86 widths).
//!
//! Each property was a gap a downstream reference executor hit: a routine that ran into the step
//! cap reported its registers as if they were a result; a division the hardware traps on handed
//! back a truncated quotient.

use mosura_core::analysis;
use mosura_core::decompile::space::Address;
use mosura_core::paths::ground_truth_dir;
use mosura_core::sleigh::emu::{self, Run, RunOptions, Stop};
use mosura_core::sleigh::engine::Spec;

struct Fixture {
    bits: u32,
    spec: &'static Spec,
    ctx: &'static [u32],
    /// `(entry, size, name)` from the build-derived truth file.
    funcs: Vec<(u64, u64, String)>,
    /// The text from the lowest routine to the end of the highest one.
    image: Vec<u8>,
    image_base: u64,
}

fn fixture(program: &str, bits: u32) -> Fixture {
    let stem = format!("{program}.gcc-x86-{bits}");
    let truth = std::fs::read_to_string(ground_truth_dir().join(format!("{stem}.truth"))).unwrap();
    let mut funcs = Vec::new();
    for line in truth.lines() {
        if let Some(rest) = line.strip_prefix("func ") {
            let mut it = rest.split_whitespace();
            let addr = u64::from_str_radix(it.next().unwrap(), 16).unwrap();
            let size = u64::from_str_radix(it.next().unwrap(), 16).unwrap();
            funcs.push((addr, size, it.next().unwrap().to_string()));
        }
    }
    let p = analysis::analyze_file(&ground_truth_dir().join(&stem)).unwrap();
    let lo = funcs.iter().map(|f| f.0).min().unwrap();
    let hi = funcs.iter().map(|f| f.0 + f.1).max().unwrap();
    let image = p.memory.read_window(Address::new(p.default_space, lo), (hi - lo) as usize);
    let (spec, ctx) = mosura_core::lang::load_cached(&format!("x86:LE:{bits}:default")).expect("x86 language tables");
    Fixture { bits, spec, ctx, funcs, image, image_base: lo }
}

impl Fixture {
    fn entry(&self, name: &str) -> u64 {
        self.funcs.iter().find(|f| f.2 == name).unwrap_or_else(|| panic!("no routine {name}")).0
    }
    /// The bytes of one routine alone.
    fn body(&self, name: &str) -> &[u8] {
        let (entry, size, _) = self.funcs.iter().find(|f| f.2 == name).unwrap();
        let at = (entry - self.image_base) as usize;
        &self.image[at..at + *size as usize]
    }
    /// The bytes from a routine's entry to the end of the text: its callees placed after it too.
    fn from(&self, name: &str) -> &[u8] {
        &self.image[(self.entry(name) - self.image_base) as usize..]
    }
    fn reg(&self, name: &str) -> (u64, u32) {
        (self.spec.register_offset(name).unwrap(), self.spec.register_size(name).unwrap())
    }
    /// The stack pointer of this width.
    fn sp(&self) -> &'static str {
        if self.bits == 64 { "RSP" } else { "ESP" }
    }
    fn run(&self, bytes: &[u8], base: u64, regs: &[(&str, u64)], opts: &RunOptions) -> Run {
        let inputs: Vec<(&str, u64, u64, u32)> = regs
            .iter()
            .map(|(n, v)| {
                let (off, size) = self.reg(n);
                ("register", off, *v, size)
            })
            .collect();
        emu::run_with(self.spec, bytes, base, self.ctx, &inputs, opts)
    }
    fn read(&self, r: &Run, name: &str) -> u64 {
        let (off, size) = self.reg(name);
        r.machine.read("register", off, size)
    }
}

const STACK: u64 = 0x0f00_0000;

#[test]
fn a_divide_by_zero_stops_as_a_fault_not_a_result() {
    for bits in [32, 64] {
        let f = fixture("divide_fault", bits);
        let e = f.entry("divide_pair");
        let r = f.run(f.body("divide_pair"), e, &[("EDX", 0), ("EAX", 100), ("ECX", 0)], &RunOptions::default());
        assert_eq!(r.stop, Stop::Fault, "x86-{bits}");
        // The control: the same bytes with a divisor return the quotient and the remainder.
        let r = f.run(f.body("divide_pair"), e, &[("EDX", 0), ("EAX", 100), ("ECX", 7)], &RunOptions::default());
        assert_eq!(r.stop, Stop::Returned, "x86-{bits}");
        assert_eq!((f.read(&r, "EAX"), f.read(&r, "EDX")), (14, 2), "x86-{bits}");
    }
}

#[test]
fn a_quotient_the_destination_cannot_hold_faults_like_the_hardware() {
    for bits in [32, 64] {
        let f = fixture("divide_fault", bits);
        // 32-bit DIV: EDX:EAX = 1:0 over 1 is 2^32, one bit too wide for EAX.
        let e = f.entry("divide_pair");
        let r = f.run(f.body("divide_pair"), e, &[("EDX", 1), ("EAX", 0), ("ECX", 1)], &RunOptions::default());
        assert_eq!(r.stop, Stop::Fault, "x86-{bits} divide_pair");
        // 16-bit DIV: DX:AX = 0xa0:0 over 1 is 0xa00000, too wide for AX — the operand size of a
        // #DE seen in the field. The same form divides 100 by 7 in its domain.
        let e = f.entry("divide_word");
        let r = f.run(f.body("divide_word"), e, &[("EDX", 0xa0), ("EAX", 0), ("ECX", 1)], &RunOptions::default());
        assert_eq!(r.stop, Stop::Fault, "x86-{bits} divide_word");
        let r = f.run(f.body("divide_word"), e, &[("EDX", 0), ("EAX", 100), ("ECX", 7)], &RunOptions::default());
        assert_eq!(r.stop, Stop::Returned, "x86-{bits} divide_word");
        assert_eq!((f.read(&r, "AX"), f.read(&r, "DX")), (14, 2), "x86-{bits} divide_word");
        // IDIV: -2^31 / -1 is +2^31, one past what EAX holds signed. The same bytes with EDX = 0
        // divide +2^31 by -1, whose -2^31 fits, so the sign matters and not the bit pattern.
        let e = f.entry("divide_signed");
        let r = f.run(f.body("divide_signed"), e, &[("EDX", 0xffff_ffff), ("EAX", 0x8000_0000), ("ECX", 0xffff_ffff)], &RunOptions::default());
        assert_eq!(r.stop, Stop::Fault, "x86-{bits} divide_signed");
        let r = f.run(f.body("divide_signed"), e, &[("EDX", 0), ("EAX", 0x8000_0000), ("ECX", 0xffff_ffff)], &RunOptions::default());
        assert_eq!(r.stop, Stop::Returned, "x86-{bits} divide_signed");
        assert_eq!(f.read(&r, "EAX"), 0x8000_0000, "x86-{bits} divide_signed");
    }
}

#[test]
fn a_run_that_never_returns_reports_the_step_cap() {
    for bits in [32, 64] {
        let f = fixture("spin_until_zero", bits);
        let e = f.entry("spin_until_zero");
        let cap = RunOptions { max_steps: 20_000, ..RunOptions::default() };
        // An upper bit set: the 16-bit decrement cycles and the test never sees zero.
        let r = f.run(f.body("spin_until_zero"), e, &[("EAX", 0x1_0000)], &cap);
        assert_eq!(r.stop, Stop::StepCap, "x86-{bits}");
        assert_eq!(r.steps, 20_000, "x86-{bits}: the count is of operations executed");
        // A small count returns, and the count of steps is a few operations per iteration.
        let r = f.run(f.body("spin_until_zero"), e, &[("EAX", 5)], &cap);
        assert_eq!(r.stop, Stop::Returned, "x86-{bits}");
        assert_eq!(f.read(&r, "EAX"), 0, "x86-{bits}");
        assert!(r.steps > 5 && r.steps < 200, "x86-{bits}: {} steps", r.steps);
    }
}

#[test]
fn a_returned_run_counts_its_steps() {
    for bits in [32, 64] {
        let f = fixture("divide_fault", bits);
        let e = f.entry("divide_pair");
        let body = f.body("divide_pair");
        // A straight-line routine executes every p-code operation of its instructions once.
        let expected: usize = f.spec.disassemble_ctx(body, e, f.ctx).iter().map(|i| i.ops.len()).sum();
        let r = f.run(body, e, &[("EDX", 0), ("EAX", 100), ("ECX", 7)], &RunOptions::default());
        assert_eq!((r.stop, r.steps), (Stop::Returned, expected), "x86-{bits}");
    }
}

#[test]
fn execution_can_start_inside_the_bytes() {
    for bits in [32, 64] {
        let f = fixture("call_chain", bits);
        let opts = RunOptions { entry: Some(f.entry("inner")), ..RunOptions::default() };
        let r = f.run(f.from("outer"), f.entry("outer"), &[(f.sp(), STACK)], &opts);
        assert_eq!((r.stop, f.read(&r, "EAX")), (Stop::Returned, 41), "x86-{bits}");
    }
}
