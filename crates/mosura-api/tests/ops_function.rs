//! `function.decompile`: the thawed program decompiles exactly as the live one (C and raw IR,
//! every function of three binaries), the set is served on the second call, an `emit.*` key is a
//! different key, the fact tables agree with the Funcdata, bad entries and formats are refused.

use mosura_api::ops::{dispatch, NoProgress};
use mosura_api::{Context, ContextConfig, Error, Format, Options, Session, SetKind};
use mosura_core::analysis;
use mosura_core::analysis::decompiler::decompile_function;
use mosura_core::decompile::printc::print_c;
use mosura_core::switches::Knobs;

fn ctx() -> Context {
    Context::new(ContextConfig::default()).unwrap()
}

fn corpus(name: &str) -> std::path::PathBuf {
    mosura_core::paths::analysis_corpus_dir().join(name)
}

fn opts(pairs: &[(&str, &str)]) -> Options {
    let mut o = Options::new();
    for (k, v) in pairs {
        o.set(k, v).unwrap();
    }
    o
}

#[test]
fn declared_function_inputs_are_typed_and_request_local() {
    let c = ctx();
    let dir = mosura_core::paths::ground_truth_dir();
    for bits in [32, 64] {
        let stem = format!("function_inputs.gcc-x86-{bits}");
        let truth = std::fs::read_to_string(dir.join(format!("{stem}.truth"))).unwrap();
        let entry = |name: &str| truth.lines().find_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            (fields.first() == Some(&"func") && fields.get(3) == Some(&name))
                .then(|| fields[1].to_string())
        }).unwrap();
        let target = entry("combine");
        let input_text = ["combine", "relay", "unused"].map(|n| format!("{}=EDI:uint4,AH:uint1", entry(n))).join(";");
        let output_text = ["combine", "relay", "unused"].map(|n| format!("{}=EAX:uint4", entry(n))).join(";");
        let declared = |target: &str| opts(&[("entry", target),
            ("decompile.function-inputs", &input_text), ("decompile.function-outputs", &output_text)]);
        let default = opts(&[("entry", &target)]);
        let mut s = Session::open(None).unwrap();
        s.add_input(&std::fs::read(dir.join(&stem)).unwrap(), &stem, None).unwrap();
        dispatch(&c, &mut s, "program.analyze", &Options::new(), &mut NoProgress).unwrap();
        let baseline = text(&dispatch(&c, &mut s, "function.decompile", &default, &mut NoProgress).unwrap());
        for name in ["combine", "relay", "unused"] {
            // Each fresh function after the first must thaw; its first request has no cached set.
            if name != "combine" { s.last_program = None; }
            let request = declared(&entry(name));
            let output = text(&dispatch(&c, &mut s, "function.decompile", &request, &mut NoProgress).unwrap());
            assert!(output.contains("uint4 param_1, uint1 param_2"), "{bits}/{name}: {output}");
            let keys = s.set_keys(SetKind::Function).unwrap();
            let cached = text(&dispatch(&c, &mut s, "function.decompile", &request, &mut NoProgress).unwrap());
            assert_eq!(cached, output);
            assert_eq!(s.set_keys(SetKind::Function).unwrap(), keys, "reuse the same result set");
        }
        let restored = text(&dispatch(&c, &mut s, "function.decompile", &default, &mut NoProgress).unwrap());
        assert_eq!(baseline, restored, "declarations must not leak into later requests");
        let keys = s.set_keys(SetKind::Function).unwrap().len();
        let swapped = format!("{target}=AH:uint1,EDI:uint4");
        let reordered = opts(&[("entry", &target), ("decompile.function-inputs", &swapped)]);
        let output = text(&dispatch(&c, &mut s, "function.decompile", &reordered, &mut NoProgress).unwrap());
        assert!(output.contains("uint1 param_1, uint4 param_2"), "{output}");
        let empty = format!("{target}=void");
        let request = opts(&[("entry", &target), ("decompile.function-inputs", &empty)]);
        let output = text(&dispatch(&c, &mut s, "function.decompile", &request, &mut NoProgress).unwrap());
        assert!(output.lines().next().unwrap().contains("(void)"), "{output}");
        assert_eq!(s.set_keys(SetKind::Function).unwrap().len(), keys + 2,
            "order and explicit empty declarations distinguish result keys");
        assert_eq!(s.set_keys(SetKind::Program).unwrap().len(), 1, "declarations are result facts");
        for suffix in ["NO_SUCH_REGISTER:uint4", "AH:uint4", "EAX:uint4,AH:uint1", "EDI:uint4,edi:uint4"] {
            let value = format!("{target}={suffix}");
            let request = opts(&[("entry", &target), ("decompile.function-inputs", &value)]);
            assert!(matches!(dispatch(&c, &mut s, "function.decompile", &request, &mut NoProgress),
                Err(Error::InvalidArg(_))), "must reject {value}");
        }
        assert!(matches!(dispatch(&c, &mut s, "function.emit", &declared(&target), &mut NoProgress),
            Err(Error::InvalidArg(_))), "unsupported compiler lowering must not be accepted");
    }
    for value in ["123=EDI", "123=EDI:wat", "123=AH:int0", "123=", "123=void,AH:uint1", "123=void;123=void"] {
        assert!(matches!(Options::new().set("decompile.function-inputs", value), Err(Error::InvalidArg(_))),
            "must reject {value}");
    }
}

#[test]
fn declared_function_outputs_are_typed_and_request_local() {
    let c = ctx();
    let dir = mosura_core::paths::ground_truth_dir();
    let truth = std::fs::read_to_string(dir.join("flag_result.gcc-x86-64.truth")).unwrap();
    let entry = |name: &str| truth.lines().find_map(|line| {
        let parts: Vec<_> = line.split_whitespace().collect();
        (parts.first() == Some(&"func") && parts.get(3) == Some(&name)).then(|| parts[1].to_string())
    }).unwrap();
    let target = entry("flag_test");
    let declaration = format!("{target}=ZF:bool");
    let declared = opts(&[("entry", &target), ("decompile.function-outputs", &declaration)]);
    let default = opts(&[("entry", &target)]);
    let mut s = Session::open(None).unwrap();
    s.add_input(&std::fs::read(dir.join("flag_result.gcc-x86-64")).unwrap(), "flag_result", None).unwrap();
    dispatch(&c, &mut s, "program.analyze", &Options::new(), &mut NoProgress).unwrap();
    for thaw in [false, true] {
        if thaw { s.last_program = None; }
        let baseline = text(&dispatch(&c, &mut s, "function.decompile", &default, &mut NoProgress).unwrap());
        assert!(baseline.starts_with("void "));
        let output = text(&dispatch(&c, &mut s, "function.decompile", &declared, &mut NoProgress).unwrap());
        assert!(output.starts_with("bool ") && output.contains("== 0"), "{output}");
        let restored = text(&dispatch(&c, &mut s, "function.decompile", &default, &mut NoProgress).unwrap());
        assert_eq!(baseline, restored, "declarations must not leak into later requests");
        let caller = entry("if_zero");
        let request = opts(&[("entry", &caller), ("decompile.function-outputs", &declaration)]);
        let output = text(&dispatch(&c, &mut s, "function.decompile", &request, &mut NoProgress).unwrap());
        assert!(output.contains("bool ") && output.contains("if ("), "{output}");
    }
    assert_eq!(s.set_keys(SetKind::Program).unwrap().len(), 1);
    assert_eq!(s.set_keys(SetKind::Function).unwrap().len(), 3,
        "default, declared callee and declared caller have distinct reusable keys");
    for value in [format!("{target}=NO_SUCH_REGISTER:bool"), format!("{target}=EAX:bool")] {
        let request = opts(&[("entry", &target), ("decompile.function-outputs", &value)]);
        assert!(matches!(dispatch(&c, &mut s, "function.decompile", &request, &mut NoProgress),
            Err(Error::InvalidArg(_))));
    }
    for value in ["123=ZF", "123=ZF:wat", "123=ZF:bool;123=ZF:bool", "123=ZF:int0"] {
        assert!(matches!(Options::new().set("decompile.function-outputs", value), Err(Error::InvalidArg(_))));
    }
    assert!(matches!(dispatch(&c, &mut s, "function.emit", &declared, &mut NoProgress),
        Err(Error::InvalidArg(_))), "an unsupported compiler lowering must not be accepted");
}

fn text(t: &mosura_api::Table) -> String {
    mosura_api::render::render(t, Format::Text).unwrap()
}

#[test]
fn a_thawed_decompile_is_the_live_one_for_every_function() {
    let c = ctx();
    for name in ["basic.elf", "switchtab.elf", "watcom_hello.exe"] {
        let live = analysis::analyze_file_with(&corpus(name), &Knobs::default()).unwrap();
        let mut s = Session::open(None).unwrap();
        s.add_input(&std::fs::read(corpus(name)).unwrap(), name, None).unwrap();
        dispatch(&c, &mut s, "program.analyze", &Options::new(), &mut NoProgress).unwrap();
        // force the function ops to THAW (the analyze call cached the live program)
        s.last_program = None;
        let mut checked = 0;
        for f in live.function_manager.functions() {
            let entry = f.entry_point();
            let Some(lf) = decompile_function(&live, entry) else { continue };
            let want_c = print_c(&lf);
            let want_raw = lf.print_raw();
            let e = format!("{:#x}", entry.offset);
            let got_c = dispatch(&c, &mut s, "function.decompile", &opts(&[("entry", &e)]), &mut NoProgress).unwrap_or_else(|err| panic!("{name} {e}: {err:?}"));
            assert_eq!(text(&got_c), want_c, "{name} {e}: C");
            let got_raw = dispatch(&c, &mut s, "function.decompile", &opts(&[("entry", &e), ("format", "raw")]), &mut NoProgress).unwrap();
            assert_eq!(text(&got_raw), want_raw, "{name} {e}: raw IR");
            // the fact tables agree with the Funcdata
            let calls = dispatch(&c, &mut s, "function.decompile", &opts(&[("entry", &e), ("format", "table:calls")]), &mut NoProgress).unwrap();
            let live_calls = lf.op_ids().filter(|&id| !lf.op(id).is_dead() && matches!(lf.op(id).code(), mosura_core::decompile::opcode::OpCode::Call | mosura_core::decompile::opcode::OpCode::Callind)).count();
            assert_eq!(calls.rows() as usize, live_calls, "{name} {e}: calls");
            let jts = dispatch(&c, &mut s, "function.decompile", &opts(&[("entry", &e), ("format", "table:jumptables")]), &mut NoProgress).unwrap();
            let live_targets: usize = lf.jumptables.iter().map(|j| j.targets.len() + j.default.filter(|d| !j.targets.contains(d)).map(|_| 1).unwrap_or(0)).sum();
            assert_eq!(jts.rows() as usize, live_targets, "{name} {e}: jump-table rows");
            let proto = dispatch(&c, &mut s, "function.decompile", &opts(&[("entry", &e), ("format", "table:prototype")]), &mut NoProgress).unwrap();
            let lp = mosura_core::analysis::interface::prototype_of(&lf);
            assert_eq!(proto.rows() as usize, lp.params.len() + lp.output.is_some() as usize, "{name} {e}: prototype rows");
            checked += 1;
        }
        assert!(checked >= 3, "{name}: {checked} functions checked");
        // one set per function (all formats read the same set)
        assert_eq!(s.set_keys(SetKind::Function).unwrap().len(), checked, "{name}: function sets");
    }
}

#[test]
fn the_set_is_served_and_an_emit_key_is_another_key() {
    let c = ctx();
    let live = analysis::analyze_file_with(&corpus("switchtab.elf"), &Knobs::default()).unwrap();
    let mut s = Session::open(None).unwrap();
    s.add_input(&std::fs::read(corpus("switchtab.elf")).unwrap(), "switchtab.elf", None).unwrap();
    dispatch(&c, &mut s, "program.analyze", &Options::new(), &mut NoProgress).unwrap();
    // the function with a jump table
    let (entry, lf) = live
        .function_manager
        .functions()
        .filter_map(|f| decompile_function(&live, f.entry_point()).map(|lf| (f.entry_point().offset, lf)))
        .find(|(_, lf)| !lf.jumptables.is_empty())
        .expect("switchtab has a switch");
    let e = format!("{entry:#x}");
    let t1 = dispatch(&c, &mut s, "function.decompile", &opts(&[("entry", &e)]), &mut NoProgress).unwrap();
    assert_eq!(s.set_keys(SetKind::Function).unwrap().len(), 1);
    let t2 = dispatch(&c, &mut s, "function.decompile", &opts(&[("entry", &e)]), &mut NoProgress).unwrap();
    assert_eq!(text(&t1), text(&t2));
    assert_eq!(s.set_keys(SetKind::Function).unwrap().len(), 1, "served from the set");
    let jt = dispatch(&c, &mut s, "function.decompile", &opts(&[("entry", &e), ("format", "table:jumptables")]), &mut NoProgress).unwrap();
    assert_eq!(jt.u64(0, 0).unwrap(), lf.jumptables[0].op_addr);
    assert_eq!(jt.u64(0, 2).unwrap(), lf.jumptables[0].targets[0]);
    // an emit axis: a second key (and the Ghidra-faithful default is what `print_c` prints)
    let t3 = dispatch(&c, &mut s, "function.decompile", &opts(&[("entry", &e), ("emit.arm-order", "address")]), &mut NoProgress).unwrap();
    assert_eq!(s.set_keys(SetKind::Function).unwrap().len(), 2, "another options tag, another set");
    let _ = t3;
    // refusals (a name is the front-end's to resolve: the key is typed Hex by the registry)
    assert!(matches!(dispatch(&c, &mut s, "function.decompile", &opts(&[("entry", "0x1")]), &mut NoProgress), Err(Error::NotFound(_))));
    assert!(matches!(Options::new().set("entry", "nosuchfn"), Err(Error::InvalidArg(_))));
    assert!(matches!(dispatch(&c, &mut s, "function.decompile", &Options::new(), &mut NoProgress), Err(Error::InvalidArg(_))));
    assert!(matches!(dispatch(&c, &mut s, "function.decompile", &opts(&[("entry", &e), ("format", "pdf")]), &mut NoProgress), Err(Error::InvalidArg(_))));
    assert!(matches!(dispatch(&c, &mut s, "function.decompile", &opts(&[("entry", &e), ("emit.arms-off", "cmp_sign")]), &mut NoProgress), Err(Error::InvalidArg(_))), "arms-off belongs to function.emit");
}

#[test]
fn declared_indirect_inputs_survive_cached_program_configuration() {
    use mosura_core::decompile::{opcode::OpCode, space::Address};
    let dir = mosura_core::paths::ground_truth_dir();
    let name = "indirect_contract.gcc-x86-64";
    let truth = std::fs::read_to_string(dir.join(format!("{name}.truth"))).unwrap();
    let entry = truth.lines().find_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        (fields.first() == Some(&"func") && fields.get(3) == Some(&"custom_writable"))
            .then(|| u64::from_str_radix(fields[1], 16).unwrap())
    }).unwrap();
    let live = analysis::analyze_file(&dir.join(name)).unwrap();
    let f = decompile_function(&live, Address::new(live.default_space, entry)).unwrap();
    let call = f.op_ids().find(|&id| !f.op(id).is_dead() && f.op(id).code() == OpCode::Callind).unwrap();
    let pointer = f.vn(f.op(call).input(0).unwrap()).loc;
    assert_eq!(pointer.space, live.default_space);
    let declaration = format!("{:#x}=BX,BP", pointer.offset);
    let e = format!("{entry:#x}");
    let c = ctx();
    let mut s = Session::open(None).unwrap();
    s.add_input(&std::fs::read(dir.join(name)).unwrap(), name, None).unwrap();
    dispatch(&c, &mut s, "program.analyze", &Options::new(), &mut NoProgress).unwrap();
    let plain = opts(&[("entry", &e)]);
    let declared = opts(&[("entry", &e), ("decompile.indirect-inputs", &declaration)]);
    assert_ne!(plain.tag(), declared.tag(), "declarations belong to the result cache key");
    let before = text(&dispatch(&c, &mut s, "function.decompile", &plain, &mut NoProgress).unwrap());
    let after = text(&dispatch(&c, &mut s, "function.decompile", &declared, &mut NoProgress).unwrap());
    assert_ne!(before, after, "the cached program must receive the new declaration");
    assert!(after.contains(")(0x21, 0x2c)"), "exact declared inputs: {after}");
    assert_eq!(s.set_keys(SetKind::Function).unwrap().len(), 2);
    assert!(matches!(dispatch(&c, &mut s, "function.emit", &declared, &mut NoProgress),
        Err(Error::InvalidArg(_))), "compiler lowering of custom pointer conventions is a separate contract");
    assert_eq!(before, text(&dispatch(&c, &mut s, "function.decompile", &plain, &mut NoProgress).unwrap()),
        "a declaration must not leak into requests that omit it");
    // Invalid declarations fail identically with a live or thawed program.
    for thaw in [false, true] {
        if thaw { s.last_program = None; }
        for regs in ["NO_SUCH_REGISTER", "AX,EAX"] {
            let value = format!("{:#x}={regs}", pointer.offset);
            let o = opts(&[("entry", &e), ("decompile.indirect-inputs", &value)]);
            assert!(matches!(dispatch(&c, &mut s, "function.decompile", &o, &mut NoProgress),
                Err(Error::InvalidArg(_))), "invalid register storage must be rejected");
        }
    }
    for value in ["no-address=BX", "123=BX,bx", "123=BX;123=BP", "123=BX,"] {
        assert!(matches!(Options::new().set("decompile.indirect-inputs", value), Err(Error::InvalidArg(_))));
    }
}
