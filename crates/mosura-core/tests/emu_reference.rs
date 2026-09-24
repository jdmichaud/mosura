//! Reference execution: what a client capturing the ORIGINAL's results needs the interpreter to
//! say, on source-built routines whose behaviour is known from their own text
//! (`oracle/ground-truth/src/{divide_fault,spin_until_zero,call_chain}.S`, both x86 widths).
//!
//! Each property was a gap a downstream reference executor hit: a routine that ran into the step
//! cap reported its registers as if they were a result; a division the hardware traps on handed
//! back a truncated quotient; a callee was never entered, so only leaf routines could be captured.

use mosura_core::analysis;
use mosura_core::decompile::space::Address;
use mosura_core::paths::ground_truth_dir;
use mosura_core::sleigh::emu::{self, Effect, Run, RunOptions, Stop};
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
    /// Register seeds by name, as the interpreter takes them.
    fn seeds(&self, regs: &[(&str, u64)]) -> Vec<(&'static str, u64, u64, u32)> {
        regs.iter()
            .map(|(n, v)| {
                let (off, size) = self.reg(n);
                ("register", off, *v, size)
            })
            .collect()
    }
    fn run(&self, bytes: &[u8], base: u64, regs: &[(&str, u64)], opts: &RunOptions) -> Run {
        emu::run_with(self.spec, bytes, base, self.ctx, &self.seeds(regs), opts)
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
fn following_calls_runs_the_callee_and_returns_to_the_caller() {
    for bits in [32, 64] {
        let f = fixture("call_chain", bits);
        let e = f.entry("outer");
        let follow = RunOptions { follow_calls: true, ..RunOptions::default() };
        let r = f.run(f.from("outer"), e, &[(f.sp(), STACK), ("EAX", 0)], &follow);
        assert_eq!(r.stop, Stop::Returned, "x86-{bits}");
        assert_eq!(f.read(&r, "EAX"), 42, "x86-{bits}: inner's 41 plus outer's 1");
        // inner's RET popped inner's return address; outer's own RET then popped the caller's
        // slot, which the seeded frame never held, so the pointer ends one word above its entry.
        let word = u64::from(f.reg(f.sp()).1);
        assert_eq!(f.read(&r, f.sp()), STACK + word, "x86-{bits}: two CALL pushes, two RET pops, one caller slot");
        // The single-function mode is unchanged: the call is an event and the callee never runs,
        // so outer's RET pops the word its own CALL pushed and the pointer lands where it began.
        let r = f.run(f.from("outer"), e, &[(f.sp(), STACK), ("EAX", 0)], &RunOptions::default());
        assert_eq!(r.stop, Stop::Returned, "x86-{bits}");
        assert_eq!(f.read(&r, "EAX"), 1, "x86-{bits}: outer's 1 over the seeded 0");
        assert_eq!(f.read(&r, f.sp()), STACK, "x86-{bits}: the skipped call's push is what the RET popped");
    }
}

#[test]
fn a_call_whose_target_lies_outside_the_bytes_stops_at_that_target() {
    for bits in [32, 64] {
        let f = fixture("call_chain", bits);
        let e = f.entry("outer");
        let follow = RunOptions { follow_calls: true, ..RunOptions::default() };
        let r = f.run(f.body("outer"), e, &[(f.sp(), STACK), ("EAX", 0)], &follow);
        assert_eq!(r.stop, Stop::NoInstruction(f.entry("inner")), "x86-{bits}");
    }
}

#[test]
fn an_interrupt_stays_an_event_when_calls_are_followed() {
    for bits in [32, 64] {
        let f = fixture("call_chain", bits);
        let e = f.entry("interrupt_event");
        let follow = RunOptions { follow_calls: true, ..RunOptions::default() };
        let r = f.run(f.body("interrupt_event"), e, &[(f.sp(), STACK)], &follow);
        assert_eq!(r.stop, Stop::Returned, "x86-{bits}");
        assert_eq!(r.machine.unmodeled, 0, "x86-{bits}");
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

/// A routine planted in a large image decodes about what it executes, once, and nothing more on
/// the next run — the cost a reference executor pays per vector when it hands over a whole
/// image so a followed call can land anywhere. Before this, every run swept the image from its
/// base and then decoded from the reached address to the END of the bytes, on every vector.
#[test]
fn decoding_follows_the_run_and_is_kept_across_runs() {
    use mosura_core::sleigh::emu::Image;
    for bits in [32, 64] {
        let f = fixture("call_chain", bits);
        let routine = f.from("outer");
        // A 256 KiB image of deterministic noise with the routine planted well inside it.
        let mut image = vec![0u8; 256 * 1024];
        let mut x = 0x2545_f491_4f6c_dd1du64;
        for b in image.iter_mut() {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            *b = x as u8;
        }
        let at = 0x2_0000usize;
        image[at..at + routine.len()].copy_from_slice(routine);
        let mut img = Image::new(f.spec, &image, 0, f.ctx);
        let opts = RunOptions { entry: Some(at as u64), follow_calls: true, ..RunOptions::default() };
        let inputs = [("register", f.reg(f.sp()).0, STACK, f.reg(f.sp()).1), ("register", f.reg("EAX").0, 0, f.reg("EAX").1)];
        let r = img.run(&inputs, &opts);
        assert_eq!((r.stop, f.read(&r, "EAX")), (Stop::Returned, 42), "x86-{bits}");
        // outer is three instructions and inner two: two 64-byte windows decode those and the
        // noise after them, at most an instruction per byte — never the hundred thousand the
        // image holds.
        let decoded = img.decoded();
        assert!((5..=128).contains(&decoded), "x86-{bits}: {decoded} instructions decoded for 5 executed");
        let again = img.run(&inputs, &opts);
        assert_eq!((again.stop, again.steps), (r.stop, r.steps), "x86-{bits}");
        assert_eq!(img.decoded(), decoded, "x86-{bits}: the second run decoded nothing new");
        // The same routine over its own bytes runs the same way.
        let small = f.run(routine, f.entry("outer"), &[(f.sp(), STACK), ("EAX", 0)], &RunOptions { follow_calls: true, ..RunOptions::default() });
        assert_eq!((small.stop, small.steps, f.read(&small, "EAX")), (r.stop, r.steps, 42), "x86-{bits}");
        // And a thousand vectors cost interpretation, not decoding.
        let t0 = std::time::Instant::now();
        for _ in 0..1000 {
            img.run(&inputs, &opts);
        }
        let elapsed = t0.elapsed();
        assert!(elapsed.as_secs_f64() < 5.0, "x86-{bits}: 1000 runs took {elapsed:?}");
    }
}

/// A traced run records what the routine does, not how its machine was seeded: a seeded memory
/// byte is setup, exactly as `run_traced` treats its own seeding. Unfixed, the seed came back as
/// the run's first store.
#[test]
fn seeding_a_traced_run_is_not_an_effect() {
    for bits in [32, 64] {
        let f = fixture("divide_fault", bits);
        let e = f.entry("divide_pair");
        let mut inputs = f.seeds(&[("EDX", 0), ("EAX", 100), ("ECX", 7)]);
        inputs.push(("ram", 0x5000, 0xab, 1));
        let traced = RunOptions { trace: true, ..RunOptions::default() };
        let r = emu::run_with(f.spec, f.body("divide_pair"), e, f.ctx, &inputs, &traced);
        assert_eq!(r.stop, Stop::Returned, "x86-{bits}");
        assert_eq!(r.machine.effects, Vec::<Effect>::new(), "x86-{bits}: a division and a RET store nothing");
        assert_eq!(r.machine.read("ram", 0x5000, 1), 0xab, "x86-{bits}: the seed is in memory all the same");
    }
}

/// A traced run records its calls, followed or not: `RunOptions::trace` promises every call, and
/// unfixed the image run recorded none. A call is recorded by target only (no contract names its
/// arguments here). An `INT n` is a `Swi`, not a call through its vector.
#[test]
fn a_traced_run_records_its_calls() {
    for bits in [32, 64] {
        let f = fixture("call_chain", bits);
        let calls = |r: &Run| r.machine.effects.iter().filter(|e| matches!(e, Effect::Call(..))).cloned().collect::<Vec<_>>();
        for follow_calls in [true, false] {
            let opts = RunOptions { follow_calls, trace: true, ..RunOptions::default() };
            let r = f.run(f.from("outer"), f.entry("outer"), &[(f.sp(), STACK), ("EAX", 0)], &opts);
            assert_eq!(r.stop, Stop::Returned, "x86-{bits} follow={follow_calls}");
            assert_eq!(calls(&r), vec![Effect::Call(f.entry("inner"), vec![])], "x86-{bits} follow={follow_calls}");
        }
        let opts = RunOptions { follow_calls: true, trace: true, ..RunOptions::default() };
        let r = f.run(f.body("interrupt_event"), f.entry("interrupt_event"), &[(f.sp(), STACK)], &opts);
        assert_eq!(calls(&r), vec![], "x86-{bits}: the interrupt's vector is not a call");
        assert!(r.machine.effects.iter().any(|e| matches!(e, Effect::Swi(0x21, _))), "x86-{bits}: {:?}", r.machine.effects);
    }
}

/// A run can continue from the machine another run left, or from one the caller prepared: its
/// registers and memory are the next run's starting state, while the effects are each run's own.
#[test]
fn a_run_continues_from_a_machine() {
    use mosura_core::sleigh::emu::Image;
    for bits in [32, 64] {
        let f = fixture("divide_fault", bits);
        let e = f.entry("divide_pair");
        let mut img = Image::new(f.spec, f.body("divide_pair"), e, f.ctx);
        let seeds = f.seeds(&[("EDX", 0), ("EAX", 100), ("ECX", 7)]);
        let first = img.run(&seeds, &RunOptions::default());
        assert_eq!((first.stop, f.read(&first, "EAX"), f.read(&first, "EDX")), (Stop::Returned, 14, 2), "x86-{bits}");
        // EDX:EAX = 2:14 over the same ECX: 0x2_0000_000e / 7 = 0x4924_924b remainder 1.
        let second = img.resume(first.machine, &RunOptions::default());
        assert_eq!((second.stop, f.read(&second, "EAX"), f.read(&second, "EDX")), (Stop::Returned, 0x4924_924b, 1), "x86-{bits}");
        // A prepared machine: registers seeded one by one, memory in bulk; neither is an effect.
        let mut m = img.machine();
        for &(space, off, value, size) in &seeds {
            m.write(space, off, size, value);
        }
        m.write_bytes("ram", 0x5000, &[1, 2, 3]);
        let third = img.resume(m, &RunOptions { trace: true, ..RunOptions::default() });
        assert_eq!(third.stop, Stop::Returned, "x86-{bits}");
        assert_eq!(third.machine.effects, Vec::<Effect>::new(), "x86-{bits}: the seeds are setup");
        assert_eq!(third.machine.written("ram"), vec![(0x5000, vec![1, 2, 3])], "x86-{bits}");
        // `unique` holds the lifted instructions' temporaries, dead between instructions.
        assert_eq!(third.machine.spaces(), vec!["ram", "register", "unique"], "x86-{bits}");

        let f = fixture("call_chain", bits);
        let mut img = Image::new(f.spec, f.from("outer"), f.entry("outer"), f.ctx);
        let traced = RunOptions { trace: true, ..RunOptions::default() };
        let a = img.run(&f.seeds(&[(f.sp(), STACK), ("EAX", 0)]), &traced);
        let n = a.machine.effects.len();
        assert!(n > 0, "x86-{bits}: the CALL's push and the call itself");
        let b = img.resume(a.machine, &traced);
        assert_eq!(b.machine.effects.len(), n, "x86-{bits}: the second run's effects are its own");
        assert_eq!(f.read(&b, "EAX"), 2, "x86-{bits}: outer's +1 twice, the callee skipped both times");
    }
}
