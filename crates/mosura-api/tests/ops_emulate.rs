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
