//! The emulate operations over a session program (`docs/emulation.md`): source-built fixtures
//! whose behaviour is known from their own text, added to an in-memory session and analyzed.

use mosura_api::ops::{dispatch, NoProgress};
use mosura_api::table::Table;
use mosura_api::{Context, ContextConfig, Error, Options, Session};

fn ctx() -> Context {
    Context::new(ContextConfig::default()).unwrap()
}

fn opts(pairs: &[(&str, &str)]) -> Options {
    let mut o = Options::new();
    for (k, v) in pairs {
        o.set(k, v).unwrap();
    }
    o
}

/// A session holding one analyzed fixture, and its routines' entries by name (`0x…`).
fn session(c: &Context, program: &str, bits: u32) -> (Session, Vec<(String, String)>) {
    let dir = mosura_core::paths::ground_truth_dir();
    let stem = format!("{program}.gcc-x86-{bits}");
    let truth = std::fs::read_to_string(dir.join(format!("{stem}.truth"))).unwrap();
    let entries = truth
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.first() == Some(&"func")).then(|| (f[3].to_string(), format!("{:#x}", u64::from_str_radix(f[1], 16).unwrap())))
        })
        .collect();
    let mut s = Session::open(None).unwrap();
    s.add_input(&std::fs::read(dir.join(&stem)).unwrap(), &stem, None).unwrap();
    dispatch(c, &mut s, "program.analyze", &Options::new(), &mut NoProgress).unwrap();
    (s, entries)
}

fn entry<'a>(entries: &'a [(String, String)], name: &str) -> &'a str {
    &entries.iter().find(|(n, _)| n == name).unwrap_or_else(|| panic!("no routine {name}")).1
}

fn rows(t: &Table) -> Vec<(String, String, String)> {
    (0..t.rows()).map(|r| (t.str(r, 0).unwrap().to_string(), t.str(r, 1).unwrap().to_string(), t.str(r, 2).unwrap().to_string())).collect()
}

/// The value of the first of `names` the answer reports (EAX on i386, RAX on x86-64, where a
/// 32-bit write zero-extends into the whole register).
fn register(r: &[(String, String, String)], names: &[&str]) -> u64 {
    names
        .iter()
        .find_map(|n| r.iter().find(|(k, name, _)| k == "register" && name == n))
        .map(|(_, _, v)| u64::from_str_radix(v.trim_start_matches("0x"), 16).unwrap())
        .unwrap_or_else(|| panic!("none of {names:?} in {r:?}"))
}

fn stop(r: &[(String, String, String)]) -> &str {
    &r.iter().find(|(k, n, _)| k == "outcome" && n == "stop").unwrap().2
}

#[test]
fn function_emulate_runs_over_the_programs_loaded_image() {
    let c = ctx();
    for bits in [32, 64] {
        let sp = if bits == 64 { "RSP" } else { "ESP" };
        let (mut s, e) = session(&c, "image_data", bits);
        // The constants come from the program's data block, a different block from the code.
        let r = rows(&dispatch(&c, &mut s, "function.emulate", &opts(&[("entry", entry(&e, "table_sum")), ("emulate.registers", "ECX=5")]), &mut NoProgress).unwrap());
        assert_eq!(stop(&r), "returned", "x86-{bits}: {r:?}");
        assert_eq!(register(&r, &["EAX", "RAX"]), 0x3333_3338, "x86-{bits}");
        assert!(!r.iter().any(|(k, _, _)| k == "memory"), "x86-{bits}: reading the image writes nothing: {r:?}");
        // The counter is 41 as loaded; the one store is reported.
        let r = rows(&dispatch(&c, &mut s, "function.emulate", &opts(&[("entry", entry(&e, "bump"))]), &mut NoProgress).unwrap());
        assert_eq!(register(&r, &["EAX", "RAX"]), 42, "x86-{bits}");
        let memory: Vec<_> = r.iter().filter(|(k, _, _)| k == "memory").collect();
        assert_eq!(memory.len(), 1, "x86-{bits}: {r:?}");
        assert_eq!(memory[0].2, "2a000000", "x86-{bits}");

        // A callee elsewhere in the program runs when calls are followed.
        let (mut s, e) = session(&c, "call_chain", bits);
        let stack = format!("{sp}=0x0f000000,EAX=0");
        let followed = opts(&[("entry", entry(&e, "outer")), ("emulate.registers", &stack), ("emulate.follow-calls", "true")]);
        let r = rows(&dispatch(&c, &mut s, "function.emulate", &followed, &mut NoProgress).unwrap());
        assert_eq!((stop(&r), register(&r, &["EAX", "RAX"])), ("returned", 42), "x86-{bits}: {r:?}");
        let event = opts(&[("entry", entry(&e, "outer")), ("emulate.registers", &stack)]);
        let r = rows(&dispatch(&c, &mut s, "function.emulate", &event, &mut NoProgress).unwrap());
        assert_eq!(register(&r, &["EAX", "RAX"]), 1, "x86-{bits}: the call is an event by default");

        // Not a function of the program; not a register of its language.
        let e2 = dispatch(&c, &mut s, "function.emulate", &opts(&[("entry", "0x10")]), &mut NoProgress).unwrap_err();
        assert!(matches!(e2, Error::NotFound(_)), "x86-{bits}: {e2:?}");
        let e3 = dispatch(&c, &mut s, "function.emulate", &opts(&[("entry", entry(&e, "outer")), ("emulate.registers", "NOPE=1")]), &mut NoProgress).unwrap_err();
        assert!(matches!(e3, Error::InvalidArg(_)), "x86-{bits}: {e3:?}");
    }
}

fn effects(r: &[(String, String, String)]) -> Vec<String> {
    r.iter().filter(|(k, _, _)| k == "effect").map(|(_, _, v)| v.clone()).collect()
}

/// `emulate.effects` lists what the run did, in order: the CALL's push, the call itself, and an
/// interrupt as `swi`. Off (the default) there are no effect rows.
#[test]
fn function_emulate_lists_the_runs_effects_on_request() {
    let c = ctx();
    for bits in [32, 64] {
        let (sp, word) = if bits == 64 { ("RSP", 8) } else { ("ESP", 4) };
        let (mut s, e) = session(&c, "call_chain", bits);
        let stack = format!("{sp}=0x0f000000,EAX=0");
        let traced = opts(&[("entry", entry(&e, "outer")), ("emulate.registers", &stack), ("emulate.follow-calls", "true"), ("emulate.effects", "true")]);
        let r = rows(&dispatch(&c, &mut s, "function.emulate", &traced, &mut NoProgress).unwrap());
        let list = effects(&r);
        assert_eq!(list.len(), 2, "x86-{bits}: {r:?}");
        let push = format!("store ram {:#x} {word} ", 0x0f00_0000u64 - word);
        assert!(list[0].starts_with(&push), "x86-{bits}: {} does not start with {push}", list[0]);
        assert_eq!(list[1], format!("call {}", entry(&e, "inner")), "x86-{bits}");
        let names: Vec<&str> = r.iter().filter(|(k, _, _)| k == "effect").map(|(_, n, _)| n.as_str()).collect();
        assert_eq!(names, ["1", "2"], "x86-{bits}: effects are numbered in order");
        // Each effect row says where and when: the CALL instruction, its second and third operation.
        let t = dispatch(&c, &mut s, "function.emulate", &traced, &mut NoProgress).unwrap();
        let (at, step) = (t.col("at").expect("an `at` column"), t.col("step").expect("a `step` column"));
        let sites: Vec<(u64, u64)> = (0..t.rows()).filter(|&r| t.str(r, 0).unwrap() == "effect").map(|r| (t.u64(r, at).unwrap(), t.u64(r, step).unwrap())).collect();
        let outer = u64::from_str_radix(entry(&e, "outer").trim_start_matches("0x"), 16).unwrap();
        assert_eq!(sites, [(outer, 2), (outer, 3)], "x86-{bits}");
        let quiet = opts(&[("entry", entry(&e, "outer")), ("emulate.registers", &stack)]);
        let r = rows(&dispatch(&c, &mut s, "function.emulate", &quiet, &mut NoProgress).unwrap());
        assert!(effects(&r).is_empty(), "x86-{bits}: {r:?}");
        let interrupt = opts(&[("entry", entry(&e, "interrupt_event")), ("emulate.registers", &stack), ("emulate.effects", "true")]);
        let r = rows(&dispatch(&c, &mut s, "function.emulate", &interrupt, &mut NoProgress).unwrap());
        assert_eq!(effects(&r), ["swi 0x21"], "x86-{bits}");
    }
}

/// A run can start from the state another run stopped in, stored in the session: `bump` counts
/// 42, 43, 44 through one state name, and a run without it starts from the loaded image again.
/// The state holds registers too, and a seed given with it wins.
#[test]
fn a_run_continues_from_a_stored_machine_state() {
    let c = ctx();
    for bits in [32, 64] {
        let (mut s, e) = session(&c, "image_data", bits);
        let bump = entry(&e, "bump");
        let mut counts = Vec::new();
        let first = opts(&[("entry", bump), ("emulate.save-state", "counter")]);
        counts.push(register(&rows(&dispatch(&c, &mut s, "function.emulate", &first, &mut NoProgress).unwrap()), &["EAX", "RAX"]));
        let next = opts(&[("entry", bump), ("emulate.state", "counter"), ("emulate.save-state", "counter")]);
        for _ in 0..2 {
            counts.push(register(&rows(&dispatch(&c, &mut s, "function.emulate", &next, &mut NoProgress).unwrap()), &["EAX", "RAX"]));
        }
        assert_eq!(counts, [42, 43, 44], "x86-{bits}");
        let fresh = rows(&dispatch(&c, &mut s, "function.emulate", &opts(&[("entry", bump)]), &mut NoProgress).unwrap());
        assert_eq!(register(&fresh, &["EAX", "RAX"]), 42, "x86-{bits}: without a state the image is as loaded");

        let sum = entry(&e, "table_sum");
        dispatch(&c, &mut s, "function.emulate", &opts(&[("entry", sum), ("emulate.registers", "ECX=5"), ("emulate.save-state", "five")]), &mut NoProgress).unwrap();
        let r = rows(&dispatch(&c, &mut s, "function.emulate", &opts(&[("entry", sum), ("emulate.state", "five")]), &mut NoProgress).unwrap());
        assert_eq!(register(&r, &["EAX", "RAX"]), 0x3333_3338, "x86-{bits}: ECX = 5 from the state");
        let r = rows(&dispatch(&c, &mut s, "function.emulate", &opts(&[("entry", sum), ("emulate.state", "five"), ("emulate.registers", "ECX=7")]), &mut NoProgress).unwrap());
        assert_eq!(register(&r, &["EAX", "RAX"]), 0x3333_333a, "x86-{bits}: the seed wins over the state");
        let missing = dispatch(&c, &mut s, "function.emulate", &opts(&[("entry", sum), ("emulate.state", "nope")]), &mut NoProgress).unwrap_err();
        assert!(matches!(missing, Error::NotFound(_)), "x86-{bits}: {missing:?}");
    }
}

// ── function.capture ──

/// One `capture` row: (case, generator, inputs, outputs, stop, steps).
type Capture = (u64, u32, Vec<u64>, Vec<u64>, String, u64);

fn capture(c: &Context, s: &mut Session, entry: &str, spec: &serde_json::Value, extra: &[(&str, &str)]) -> mosura_api::Result<Vec<Capture>> {
    let text = spec.to_string();
    let mut pairs = vec![("entry", entry), ("capture.spec", text.as_str())];
    pairs.extend_from_slice(extra);
    let t = dispatch(c, s, "function.capture", &opts(&pairs), &mut NoProgress)?;
    Ok((0..t.rows())
        .map(|r| {
            (
                t.u64(r, 0).unwrap(),
                t.u64(r, 1).unwrap() as u32,
                t.list_u64(r, 2).unwrap().collect(),
                t.list_u64(r, 3).unwrap().collect(),
                t.str(r, 4).unwrap().to_string(),
                t.u64(r, 6).unwrap(),
            )
        })
        .collect())
}

fn reg_slot(name: &str, register: &str) -> serde_json::Value {
    serde_json::json!({ "name": name, "bits": 32, "pieces": [{ "register": register }] })
}

/// Every generator, over one image: explicit rows, an exhaustive range (a row already produced is
/// skipped), and seeded samples, uniform and log2-uniform, whose draws are the reference
/// executor's — the values below come from an independent implementation of its documented
/// splitmix64 (seed 0's first output is the published 0xe220a8397b1dcdaf).
#[test]
fn capture_runs_every_generated_vector_over_one_image() {
    let c = ctx();
    for bits in [32, 64] {
        let (mut s, e) = session(&c, "image_data", bits);
        let spec = serde_json::json!({
            "inputs": [reg_slot("ecx", "ECX")],
            "outputs": [reg_slot("eax", "EAX")],
            "cases": [
                { "kind": "explicit", "rows": [{ "ecx": "0x0" }, { "ecx": 5 }], "note": "the zero and a small value" },
                { "kind": "range", "input": "ecx", "from": 0, "to": "3" },
                { "kind": "sample", "count": 8, "seed": 0, "inputs": { "ecx": { "min": 0, "max": 255 } } },
                { "kind": "sample", "count": 8, "seed": 12345, "distribution": "log2-uniform", "inputs": { "ecx": { "min": 1, "max": "0xffffffff" } } },
            ],
        });
        let rows = capture(&c, &mut s, entry(&e, "table_sum"), &spec, &[]).unwrap();
        let expected: Vec<(u32, u64)> = [(0, 0), (0, 5), (1, 1), (1, 2), (1, 3)]
            .into_iter()
            .chain([226, 110, 6, 248, 27, 83, 44, 197].map(|v| (2, v)))
            .chain([0x1d, 0xa, 0x1f62e, 0xc, 0xfecf, 0x36, 0x1269a55, 0xd1caf6b6].map(|v| (3, v)))
            .collect();
        assert_eq!(rows.len(), expected.len(), "x86-{bits}: {rows:?}");
        for (i, ((g, v), row)) in expected.iter().zip(&rows).enumerate() {
            assert_eq!((row.0, row.1, &row.2), (i as u64 + 1, *g, &vec![*v]), "x86-{bits} case {}", i + 1);
            assert_eq!((row.4.as_str(), &row.3), ("returned", &vec![(0x3333_3333 + v) & 0xffff_ffff]), "x86-{bits} case {}", i + 1);
        }
    }
}

/// A run that does not return is a rejected row with no outputs, named by its stop; a chain feeds
/// each returned row's outputs into the next row's inputs and ends at the first rejected (or
/// repeated) row.
#[test]
fn capture_rejects_runs_that_did_not_return_and_ends_a_chain() {
    let c = ctx();
    for bits in [32, 64] {
        let (mut s, e) = session(&c, "divide_fault", bits);
        let spec = serde_json::json!({
            "inputs": [reg_slot("edx", "EDX"), reg_slot("eax", "EAX"), reg_slot("ecx", "ECX")],
            "outputs": [reg_slot("q", "EAX"), reg_slot("r", "EDX")],
            "cases": [
                { "kind": "explicit", "rows": [
                    { "edx": 0, "eax": 100, "ecx": 7 },
                    { "edx": 0, "eax": 100, "ecx": 0 },
                    { "edx": 1, "eax": 0, "ecx": 1 },
                ] },
                { "kind": "chain", "count": 4, "start": { "edx": 0, "eax": 1000, "ecx": 7 },
                  "feed": [{ "output": "q", "input": "eax" }, { "output": "r", "input": "edx" }] },
                { "kind": "chain", "count": 4, "start": { "edx": 0, "eax": 5, "ecx": 0 },
                  "feed": [{ "output": "q", "input": "eax" }] },
            ],
        });
        let rows = capture(&c, &mut s, entry(&e, "divide_pair"), &spec, &[]).unwrap();
        let stops: Vec<&str> = rows.iter().map(|r| r.4.as_str()).collect();
        assert_eq!(stops, ["returned", "fault", "fault", "returned", "returned", "returned", "returned", "fault"], "x86-{bits}: {rows:?}");
        assert_eq!(rows[0].3, vec![14, 2], "x86-{bits}");
        assert!(rows[1].3.is_empty() && rows[2].3.is_empty() && rows[7].3.is_empty(), "x86-{bits}: a rejected row has no outputs");
        let (mut edx, mut eax) = (0u64, 1000u64);
        for row in &rows[3..7] {
            assert_eq!(row.2, vec![edx, eax, 7], "x86-{bits}: the chain fed the last row's outputs back");
            let dividend = (edx << 32) | eax;
            (eax, edx) = (dividend / 7, dividend % 7);
            assert_eq!(row.3, vec![eax, edx], "x86-{bits}");
        }

        let (mut s, e) = session(&c, "spin_until_zero", bits);
        let spec = serde_json::json!({
            "max_steps": 1000,
            "inputs": [reg_slot("eax", "EAX")],
            "outputs": [reg_slot("eax", "EAX")],
            "cases": [{ "kind": "explicit", "rows": [{ "eax": "0x10000" }, { "eax": 5 }] }],
        });
        let rows = capture(&c, &mut s, entry(&e, "spin_until_zero"), &spec, &[]).unwrap();
        assert_eq!((rows[0].4.as_str(), rows[0].5), ("step-cap", 1000), "x86-{bits}");
        assert_eq!((rows[1].4.as_str(), &rows[1].3), ("returned", &vec![0]), "x86-{bits}");
    }
}

/// The fixed seeds of a specification — registers, memory, calls followed — apply to every vector,
/// a sample's `scale` maps its draws, and `emulate.state` is every vector's starting state.
#[test]
fn capture_uses_fixed_seeds_and_a_stored_state() {
    let c = ctx();
    for bits in [32, 64] {
        let sp = if bits == 64 { "RSP" } else { "ESP" };
        let (mut s, e) = session(&c, "divide_fault", bits);
        let spec = serde_json::json!({
            "registers": { "EDX": 0 },
            "inputs": [reg_slot("ecx", "ECX"), reg_slot("eax", "EAX")],
            "outputs": [reg_slot("q", "EAX")],
            "cases": [{ "kind": "sample", "count": 4, "seed": 7, "inputs": {
                "ecx": { "min": 0, "max": 15 },
                "eax": { "min": "0x100", "max": "0x1ff", "scale": -1 },
            } }],
        });
        let rows = capture(&c, &mut s, entry(&e, "divide_pair"), &spec, &[]).unwrap();
        let drawn: Vec<Vec<u64>> = rows.iter().map(|r| r.2.clone()).collect();
        assert_eq!(drawn, [vec![6, 0xfffffefc], vec![14, 0xfffffe6b], vec![7, 0xfffffec1], vec![7, 0xfffffead]], "x86-{bits}");
        for r in &rows {
            assert_eq!(r.3, vec![r.2[1] / r.2[0]], "x86-{bits}: EDX = 0 from the fixed registers");
        }

        let (mut s, e) = session(&c, "image_data", bits);
        let blocks = dispatch(&c, &mut s, "program.tables", &opts(&[("table", "blocks")]), &mut NoProgress).unwrap();
        let data = (0..blocks.rows()).find(|&r| blocks.str(r, 3).unwrap() == ".data").map(|r| blocks.u64(r, 1).unwrap()).unwrap();
        let spec = serde_json::json!({
            "memory": [{ "address": format!("{data:#x}"), "bytes": "01000000" }],
            "inputs": [reg_slot("ecx", "ECX")],
            "outputs": [reg_slot("eax", "EAX")],
            "cases": [{ "kind": "explicit", "rows": [{ "ecx": 0 }] }],
        });
        assert_eq!(capture(&c, &mut s, entry(&e, "table_sum"), &spec, &[]).unwrap()[0].3, vec![0x2222_2223], "x86-{bits}: the seed replaced table[0]");
        let once = serde_json::json!({
            "inputs": [], "outputs": [reg_slot("eax", "EAX")], "cases": [{ "kind": "explicit", "rows": [{}] }],
        });
        dispatch(&c, &mut s, "function.emulate", &opts(&[("entry", entry(&e, "bump")), ("emulate.save-state", "bumped")]), &mut NoProgress).unwrap();
        assert_eq!(capture(&c, &mut s, entry(&e, "bump"), &once, &[]).unwrap()[0].3, vec![42], "x86-{bits}");
        assert_eq!(capture(&c, &mut s, entry(&e, "bump"), &once, &[("emulate.state", "bumped")]).unwrap()[0].3, vec![43], "x86-{bits}");

        let (mut s, e) = session(&c, "call_chain", bits);
        let chain = |follow: bool| serde_json::json!({
            "registers": { sp: "0x0f000000", "EAX": 0 },
            "follow_calls": follow,
            "inputs": [], "outputs": [reg_slot("eax", "EAX")], "cases": [{ "kind": "explicit", "rows": [{}] }],
        });
        assert_eq!(capture(&c, &mut s, entry(&e, "outer"), &chain(true), &[]).unwrap()[0].3, vec![42], "x86-{bits}");
        assert_eq!(capture(&c, &mut s, entry(&e, "outer"), &chain(false), &[]).unwrap()[0].3, vec![1], "x86-{bits}");
    }
}

/// A malformed specification is refused before anything runs, naming what is wrong.
#[test]
fn capture_refuses_a_malformed_specification() {
    let c = ctx();
    let (mut s, e) = session(&c, "image_data", 32);
    let good = serde_json::json!({
        "inputs": [reg_slot("ecx", "ECX")], "outputs": [reg_slot("eax", "EAX")],
        "cases": [{ "kind": "explicit", "rows": [{ "ecx": 1 }] }],
    });
    assert_eq!(capture(&c, &mut s, entry(&e, "table_sum"), &good, &[]).unwrap().len(), 1);
    let broken = |edit: &dyn Fn(&mut serde_json::Value)| {
        let mut v = good.clone();
        edit(&mut v);
        v
    };
    let cases: Vec<(&str, serde_json::Value)> = vec![
        ("an unknown key", broken(&|v| v["input"] = serde_json::json!([]))),
        ("an unknown register", broken(&|v| v["inputs"][0]["pieces"][0]["register"] = "NOPE".into())),
        ("a nine-byte piece", broken(&|v| v["inputs"][0]["pieces"][0] = serde_json::json!({ "space": "register", "offset": 0, "size": 9 }))),
        ("a missing input", broken(&|v| v["cases"][0]["rows"][0] = serde_json::json!({}))),
        ("a value wider than its input", broken(&|v| v["cases"][0]["rows"][0]["ecx"] = "0x100000000".into())),
        ("an unknown generator", broken(&|v| v["cases"][0]["kind"] = "every".into())),
        ("no outputs", broken(&|v| v["outputs"] = serde_json::json!([]))),
    ];
    for (what, spec) in cases {
        let err = capture(&c, &mut s, entry(&e, "table_sum"), &spec, &[]).unwrap_err();
        assert!(matches!(err, Error::InvalidArg(_)), "{what}: {err:?}");
    }
    let err = dispatch(&c, &mut s, "function.capture", &opts(&[("entry", entry(&e, "table_sum")), ("capture.spec", "{ not json")]), &mut NoProgress).unwrap_err();
    assert!(matches!(err, Error::InvalidArg(_)), "{err:?}");
    let err = dispatch(&c, &mut s, "function.capture", &opts(&[("entry", entry(&e, "table_sum"))]), &mut NoProgress).unwrap_err();
    assert!(matches!(err, Error::InvalidArg(_)), "no specification: {err:?}");
}

/// A register the run read before anything wrote it is named: an `uninitialized` outcome row at
/// the site of its first read, and the `uninitialized` column of a capture row. A GS read with
/// its base unset reads from zero and says so; seeded, it reads the right memory and says nothing.
#[test]
fn a_register_read_before_anything_wrote_it_is_named() {
    let c = ctx();
    for bits in [32, 64] {
        let sp = if bits == 64 { "RSP" } else { "ESP" };
        let (mut s, e) = session(&c, "segment_base", bits);
        let gs = entry(&e, "read_gs");
        let memory = ("emulate.memory", "0x10=11111111;0x5010=22222222");
        let stack = format!("{sp}=0x0f000000");
        let t = dispatch(&c, &mut s, "function.emulate", &opts(&[("entry", gs), memory, ("emulate.registers", &stack)]), &mut NoProgress).unwrap();
        let r = rows(&t);
        assert_eq!(register(&r, &["EAX", "RAX"]), 0x1111_1111, "x86-{bits}: the base read as zero");
        let named: Vec<(String, u64, u64)> = (0..t.rows())
            .filter(|&i| t.str(i, 0).unwrap() == "outcome" && t.str(i, 1).unwrap() == "uninitialized")
            .map(|i| (t.str(i, 2).unwrap().to_string(), t.u64(i, 3).unwrap(), t.u64(i, 4).unwrap()))
            .collect();
        let at = u64::from_str_radix(gs.trim_start_matches("0x"), 16).unwrap();
        assert_eq!(named, [("GS_OFFSET".to_string(), at, 1)], "x86-{bits}");
        let seeded = format!("{stack},GS_OFFSET=0x5000");
        let r = rows(&dispatch(&c, &mut s, "function.emulate", &opts(&[("entry", gs), memory, ("emulate.registers", &seeded)]), &mut NoProgress).unwrap());
        assert_eq!(register(&r, &["EAX", "RAX"]), 0x2222_2222, "x86-{bits}");
        assert!(!r.iter().any(|(k, n, _)| k == "outcome" && n == "uninitialized"), "x86-{bits}: {r:?}");

        let spec = |registers: serde_json::Value| serde_json::json!({
            "registers": registers, "inputs": [], "outputs": [reg_slot("eax", "EAX")],
            "cases": [{ "kind": "explicit", "rows": [{}] }],
        });
        let column = |registers: serde_json::Value, s: &mut Session| {
            let text = spec(registers).to_string();
            let t = dispatch(&c, s, "function.capture", &opts(&[("entry", gs), ("capture.spec", &text)]), &mut NoProgress).unwrap();
            t.str(0, t.col("uninitialized").expect("an `uninitialized` column")).unwrap().to_string()
        };
        assert_eq!(column(serde_json::json!({ sp: "0x0f000000" }), &mut s), "GS_OFFSET", "x86-{bits}");
        assert_eq!(column(serde_json::json!({ sp: "0x0f000000", "GS_OFFSET": "0x5000" }), &mut s), "", "x86-{bits}");
        assert_eq!(column(serde_json::json!({}), &mut s), format!("GS_OFFSET,{sp}"), "x86-{bits}: in the order of their first read");
    }
}

/// `emulate.ports` answers `IN` per port (values in order, the last repeating), and a capture
/// specification's `ports` does the same for every vector. A port read with no answer is named: an
/// `unanswered-in` outcome row at its first read, the `unanswered` column of a capture row.
#[test]
fn in_is_answered_by_the_caller_and_an_unanswered_port_is_named() {
    let c = ctx();
    for bits in [32, 64] {
        let sp = if bits == 64 { "RSP" } else { "ESP" };
        let (mut s, e) = session(&c, "port_io", bits);
        let poll = entry(&e, "wait_ready");
        let stack = format!("{sp}=0x0f000000");
        let t = dispatch(&c, &mut s, "function.emulate", &opts(&[("entry", poll), ("emulate.registers", &stack), ("emulate.max-steps", "1000")]), &mut NoProgress).unwrap();
        let r = rows(&t);
        assert_eq!(stop(&r), "step-cap", "x86-{bits}: an unanswered status port never turns ready");
        let named: Vec<(String, u64)> = (0..t.rows())
            .filter(|&i| t.str(i, 0).unwrap() == "outcome" && t.str(i, 1).unwrap() == "unanswered-in")
            .map(|i| (t.str(i, 2).unwrap().to_string(), t.u64(i, 3).unwrap()))
            .collect();
        let poll_at = u64::from_str_radix(poll.trim_start_matches("0x"), 16).unwrap();
        assert_eq!(named, [("0x3da".to_string(), poll_at + 4)], "x86-{bits}: at the IN, after the 4-byte mov");

        let answered = opts(&[("entry", poll), ("emulate.registers", &stack), ("emulate.ports", "0x3da=0,0,8"), ("emulate.effects", "true")]);
        let r = rows(&dispatch(&c, &mut s, "function.emulate", &answered, &mut NoProgress).unwrap());
        assert_eq!((stop(&r), register(&r, &["AL"])), ("returned", 8), "x86-{bits}: {r:?}");
        assert_eq!(effects(&r), ["in 0x3da 1 0x0", "in 0x3da 1 0x0", "in 0x3da 1 0x8"], "x86-{bits}");
        assert!(!r.iter().any(|(k, n, _)| k == "outcome" && n == "unanswered-in"), "x86-{bits}: {r:?}");

        let spec = |ports: serde_json::Value| serde_json::json!({
            "registers": { sp: "0x0f000000" }, "ports": ports, "max_steps": 200,
            "inputs": [], "outputs": [{ "name": "al", "bits": 8, "pieces": [{ "register": "AL" }] }],
            "cases": [{ "kind": "explicit", "rows": [{}] }],
        });
        let capture_row = |ports: serde_json::Value, s: &mut Session| {
            let text = spec(ports).to_string();
            let t = dispatch(&c, s, "function.capture", &opts(&[("entry", poll), ("capture.spec", &text)]), &mut NoProgress).unwrap();
            let unanswered: Vec<u64> = t.list_u64(0, t.col("unanswered").expect("an `unanswered` column")).unwrap().collect();
            (t.str(0, 4).unwrap().to_string(), t.list_u64(0, 3).unwrap().collect::<Vec<u64>>(), unanswered)
        };
        assert_eq!(capture_row(serde_json::json!({ "0x3da": [0, "0x8"] }), &mut s), ("returned".to_string(), vec![8], vec![]), "x86-{bits}");
        assert_eq!(capture_row(serde_json::json!({ "0x3da": 8 }), &mut s), ("returned".to_string(), vec![8], vec![]), "x86-{bits}: a single value");
        assert_eq!(capture_row(serde_json::json!({}), &mut s), ("step-cap".to_string(), vec![], vec![0x3da]), "x86-{bits}");

        for bad in ["0x3da", "0x3da=", "zz=1", "0x3da=0,q"] {
            let err = dispatch(&c, &mut s, "function.emulate", &opts(&[("entry", poll), ("emulate.ports", bad)]), &mut NoProgress).unwrap_err();
            assert!(matches!(err, Error::InvalidArg(_)), "x86-{bits} {bad:?}: {err:?}");
        }
    }
}
