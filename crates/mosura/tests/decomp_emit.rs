//! Decompiler D5 (thin slice): bytes → C for a straight-line function.

use mosura::decomp::Funcdata;
use mosura::sleigh::engine::Spec;
use mosura::{datatest, paths};

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
fn decompiles_straight_line_to_c() {
    let Some((spec, ctx)) = x86_64() else { return };
    let dt = datatest::parse_file(&paths::oracle_fixtures_dir().join("x86_64_sem.xml")).unwrap();
    let f = Funcdata::build(&spec, &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);

    let lo = [("register".to_string(), 0u64, 4u32), ("register".to_string(), 0u64, 8u32)]; // x86-64 SysV return register
    let c = f.decompile(&lo).expect("straight-line decompile");
    eprintln!("=== mosura decompiled C — source was f(a,b)=a*3+(b>>2)-5 ===\n{c}");

    assert!(c.contains("return"), "must return a value");
    assert!(c.contains("param_1 * 3"), "strength reduction a+a*2 → a*3");
    assert!(c.contains(">> 2") && c.contains("- 5"), "the (b>>2) and -5 terms must appear");
}

#[test]
fn decompiles_conditional_to_ternary() {
    let Some((spec, ctx)) = x86_64() else { return };
    // pick(a,b) = (a < b) ? a+1 : b*2 — gcc compiles it as a CMOV (branchless
    // select), which lifts to a phi at the merge → recovered as a ?: ternary.
    let dt = datatest::parse_file(&paths::oracle_fixtures_dir().join("x86_64_pick.xml")).unwrap();
    let f = Funcdata::build(&spec, &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);

    let lo = [("register".to_string(), 0u64, 4u32), ("register".to_string(), 0u64, 8u32)];
    let c = f.decompile(&lo).expect("conditional decompile");
    eprintln!("=== mosura decompiled C — source was pick(a,b)=(a<b)?a+1:b*2 ===\n{c}");

    assert!(c.contains("(param_1 < param_2) ? (param_1 + 1) : (param_2 * 2)"), "must recover (a<b)?a+1:b*2 exactly, got: {c}");
}

#[test]
fn decompiles_early_return_to_if_statement() {
    let Some((spec, ctx)) = x86_64() else { return };
    // if(a>100) return a*b; return a+b; — a real branch (two RETURNs, no merge).
    let dt = datatest::parse_file(&paths::oracle_fixtures_dir().join("x86_64_ifret.xml")).unwrap();
    let f = Funcdata::build(&spec, &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);

    let lo = [("register".to_string(), 0u64, 4u32), ("register".to_string(), 0u64, 8u32)];
    let c = f.decompile(&lo).expect("if-statement decompile");
    eprintln!("=== mosura decompiled C — source was if(a>100) return a*b; return a+b; ===\n{c}");

    assert!(c.contains("if ("), "must recover an if statement");
    assert!(c.matches("return").count() >= 2, "both return paths must appear");
    assert!(c.contains("param_1 * param_2"), "the a*b path must appear");
}

#[test]
fn decompiles_do_while_loop() {
    let Some((spec, ctx)) = x86_64() else { return };
    // int s=0; do { s+=n; n--; } while(n); return s;  — a real loop
    let dt = datatest::parse_file(&paths::oracle_fixtures_dir().join("x86_64_dowhile.xml")).unwrap();
    let f = Funcdata::build(&spec, &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);

    let lo = [("register".to_string(), 0u64, 4u32), ("register".to_string(), 0u64, 8u32)];
    let c = f.decompile(&lo).expect("loop decompile");
    eprintln!("=== mosura decompiled do-while loop ===\n{c}");

    assert!(c.contains("int func(int param_1)"), "one int parameter");
    assert!(c.contains("= 0;"), "accumulator initialized to 0");
    assert!(c.contains("= param_1;"), "counter initialized from the parameter");
    assert!(c.contains("do {") && c.contains("} while ("), "must recover a do-while loop");
    assert!(c.contains("- 1;"), "counter decrement n--");
    assert!(c.contains("!= 0"), "loop-exit condition while(n)");
    // accumulator update: var = var + var
    assert!(
        (0..3).any(|i| c.contains(&format!("var_{i} = var_{i} + var_"))),
        "accumulator update s += n, got:\n{c}"
    );
}

#[test]
fn decompiles_guarded_while_loop() {
    let Some((spec, ctx)) = x86_64() else { return };
    // while(n>0){ s+=n; n--; } return s; — gcc rotates this into a guarded do-while
    // (if the guard fails, return 0), which structures as if/else around the loop.
    let dt = datatest::parse_file(&paths::oracle_fixtures_dir().join("x86_64_while.xml")).unwrap();
    let f = Funcdata::build(&spec, &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);

    let lo = [("register".to_string(), 0u64, 4u32), ("register".to_string(), 0u64, 8u32)];
    let c = f.decompile(&lo).expect("guarded while decompile");
    eprintln!("=== mosura decompiled guarded while ===\n{c}");

    assert!(c.contains("if ("), "must recover the guard");
    assert!(c.contains("do {") && c.contains("} while ("), "must recover the loop");
    assert!(c.contains("return 0;"), "the guard's zero-iteration path returns 0, got:\n{c}");
    assert!((0..3).any(|i| c.contains(&format!("var_{i} = var_{i} + var_"))), "loop body");
}

#[test]
fn decompiles_o0_stack_frame() {
    let Some((spec, ctx)) = x86_64() else { return };
    // int f(int a, int b){ return a + b; } compiled at -O0: params are spilled to
    // [RBP-4]/[RBP-8] and reloaded. Needs stack-variable recovery to fold through.
    let dt = datatest::parse_file(&paths::oracle_fixtures_dir().join("x86_64_stackadd.xml")).unwrap();
    let f = Funcdata::build(&spec, &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);

    let lo = [("register".to_string(), 0u64, 4u32), ("register".to_string(), 0u64, 8u32)];
    let c = f.decompile(&lo).expect("-O0 stack decompile");
    eprintln!("=== mosura decompiled -O0 stack frame ===\n{c}");

    assert!(c.contains("int func(int param_1, int param_2)"), "two int params");
    assert!(
        c.contains("return param_2 + param_1;") || c.contains("return param_1 + param_2;"),
        "the stack-spilled a+b must fold to params, got:\n{c}"
    );
}

#[test]
fn decompiles_function_call() {
    let Some((spec, ctx)) = x86_64() else { return };
    // int f(int a){ return g(a + 1) + 2; } — a call with a computed argument.
    // (The target address is the unapplied relocation in the raw .o, not a bug.)
    let dt = datatest::parse_file(&paths::oracle_fixtures_dir().join("x86_64_call.xml")).unwrap();
    let f = Funcdata::build(&spec, &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);

    let lo = [("register".to_string(), 0u64, 4u32), ("register".to_string(), 0u64, 8u32)];
    let c = f.decompile(&lo).expect("call decompile");
    eprintln!("=== mosura decompiled a call ===\n{c}");

    assert!(c.contains("int func(int param_1)"), "one param (not the 6 arg-register reads)");
    assert!(c.contains("FUN_"), "the call must be recognized");
    assert!(c.contains("param_1 + 1"), "the computed argument g(a+1) must be recovered");
    assert!(c.contains(") + 2"), "the +2 applied to the call result");
}

#[test]
fn decompiles_general_while_loop() {
    let Some((spec, ctx)) = x86_64() else { return };
    // -O0 int f(int n){ int s=0; for(int i=0;i<n;i++) s+=i; return s; } — a general
    // loop (header≠latch, condition at the top) over stack variables → while form.
    let dt = datatest::parse_file(&paths::oracle_fixtures_dir().join("x86_64_for.xml")).unwrap();
    let f = Funcdata::build(&spec, &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);

    let lo = [("register".to_string(), 0u64, 4u32), ("register".to_string(), 0u64, 8u32)];
    let c = f.decompile(&lo).expect("for-loop decompile");
    eprintln!("=== mosura decompiled -O0 for-loop ===\n{c}");

    assert!(c.contains("for ("), "must recover a for loop");
    assert!(c.contains("< param_1"), "the loop condition i < n");
    assert!((0..3).any(|i| c.contains(&format!("var_{i} = var_{i} + var_"))), "accumulator s += i");
    assert!(c.contains("+ 1)"), "the counter increment in the for-header");
}

#[test]
fn decompiles_loop_with_call_statement() {
    let Some((spec, ctx)) = x86_64() else { return };
    // -O0 int f(int n){ int s=0; for(int i=0;i<n;i++){ g(i); s+=i; } return s; }
    // — the loop body has a void call statement g(i) alongside the accumulator.
    let dt = datatest::parse_file(&paths::oracle_fixtures_dir().join("x86_64_bodycall.xml")).unwrap();
    let f = Funcdata::build(&spec, &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);

    let lo = [("register".to_string(), 0u64, 4u32), ("register".to_string(), 0u64, 8u32)];
    let c = f.decompile(&lo).expect("body-call decompile");
    eprintln!("=== mosura decompiled loop with a body call ===\n{c}");

    assert!(c.contains("for (") || c.contains("while ("), "loop");
    assert!(c.contains("FUN_"), "the body call g(i) emitted as a statement");
    assert!(!c.contains("register_20") && !c.contains("- 8"), "RSP must not leak as a loop variable, got:\n{c}");
    assert!((0..3).any(|i| c.contains(&format!("var_{i} = var_{i} + var_"))), "accumulator s += i");
    assert!(c.contains("+ 1"), "counter i++");
}

#[test]
fn decompiles_straight_line_call_statement() {
    let Some((spec, ctx)) = x86_64() else { return };
    // int f(int x){ g(x); return x + 1; } — a call statement before the return,
    // with the parameter passed straight through as the argument.
    let dt = datatest::parse_file(&paths::oracle_fixtures_dir().join("x86_64_callstmt.xml")).unwrap();
    let f = Funcdata::build(&spec, &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);

    let lo = [("register".to_string(), 0u64, 4u32), ("register".to_string(), 0u64, 8u32)];
    let c = f.decompile(&lo).expect("call-statement decompile");
    eprintln!("=== mosura decompiled a straight-line call statement ===\n{c}");

    assert!(c.contains("FUN_") && c.contains("(param_1)"), "g(x) emitted as a statement with the passthrough arg, got:\n{c}");
    assert!(c.contains("return param_1 + 1;"), "the return x+1");
}

#[test]
fn decompiles_pointer_store() {
    let Some((spec, ctx)) = x86_64() else { return };
    // int f(int *p, int x){ *p = x; return x; } — a memory store statement.
    let dt = datatest::parse_file(&paths::oracle_fixtures_dir().join("x86_64_ptrstore.xml")).unwrap();
    let f = Funcdata::build(&spec, &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);

    let lo = [("register".to_string(), 0u64, 4u32), ("register".to_string(), 0u64, 8u32)];
    let c = f.decompile(&lo).expect("store decompile");
    eprintln!("=== mosura decompiled a pointer store ===\n{c}");

    assert!(c.contains("int *param_1"), "param_1 inferred as a pointer, got:\n{c}");
    assert!(c.contains("*param_1 = param_2;"), "the store *p = x, got:\n{c}");
    assert!(c.contains("return param_2;"), "return x");
}

#[test]
fn recovers_unsigned_param_types() {
    let Some((spec, ctx)) = x86_64() else { return };
    // unsigned f(unsigned a, unsigned b){ return a < b; } — the unsigned compare
    // (INT_LESS, not INT_SLESS) types both parameters as uint.
    let dt = datatest::parse_file(&paths::oracle_fixtures_dir().join("x86_64_ucmp.xml")).unwrap();
    let f = Funcdata::build(&spec, &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);

    let lo = [("register".to_string(), 0u64, 4u32), ("register".to_string(), 0u64, 8u32)];
    let c = f.decompile(&lo).expect("ucmp decompile");
    eprintln!("=== mosura decompiled an unsigned compare ===\n{c}");

    assert!(c.contains("uint param_1") && c.contains("uint param_2"), "unsigned params, got:\n{c}");
    assert!(c.contains("param_1 < param_2"), "the unsigned compare");
}

#[test]
fn names_a_multiply_used_value_once() {
    let Some((spec, ctx)) = x86_64() else { return };
    // twodim: a[j] = a[i] + 10; return a[i]; — the load of a[i] is used twice (the
    // store's right-hand side and the return). Ghidra's ActionMarkExplicit names such
    // a multiply-used value once (a temporary) instead of recomputing it at each use.
    let dt = datatest::parse_file(&paths::oracle_fixtures_dir().join("x86_64_cse.xml")).unwrap();
    let f = Funcdata::build(&spec, &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);

    let lo = [("register".to_string(), 0u64, 4u32), ("register".to_string(), 0u64, 8u32)];
    let c = f.decompile(&lo).expect("cse decompile");
    eprintln!("=== mosura named a multiply-used value once ===\n{c}");

    // a temporary is declared and the return references it (not a re-inlined load)
    assert!(c.contains("int var_0 = *("), "the load is named once, got:\n{c}");
    assert!(c.contains("return var_0;"), "the return references the temp, got:\n{c}");
    // the big address sub-expression (`<< 2`) appears for the load (once) and the
    // store (once) — not three times, as it did when the load was re-inlined.
    assert_eq!(c.matches("<< 2").count(), 2, "the load expression must not be duplicated, got:\n{c}");
}

#[test]
fn recovers_division_by_constant() {
    let Some((spec, ctx)) = x86_64() else { return };
    // divopt divides an array of values by small constants; the compiler emits each as
    // a magic-number multiply (`(x*magic) >> n` with an add-back correction), which
    // Ghidra's RuleDivOpt family recovers as `x / C`. Read it from the datatest corpus.
    let path = paths::datatests_dir().join("divopt.xml");
    let Ok(dt) = datatest::parse_file(&path) else { return };
    let f = Funcdata::build(&spec, &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);

    let lo = [("register".to_string(), 0u64, 4u32), ("register".to_string(), 0u64, 8u32)];
    let c = f.decompile(&lo).expect("divopt decompile");
    eprintln!("=== mosura recovered division by a constant ===\n{c}");

    // the divisions are recovered to `/ C` with the exact divisors Ghidra finds...
    assert!(c.contains("/ 0x51") && c.contains("/ 0x59") && c.contains("/ 99"), "divisors recovered, got:\n{c}");
    // ...and the magic multiplier no longer appears for the recovered forms
    assert!(!c.contains("0x948b0fcd6e9e0653"), "the magic multiply must be gone, got:\n{c}");
}

#[test]
fn recovers_signed_division_and_modulo() {
    let Some((spec, ctx)) = x86_64() else { return };
    // modulo computes `x % C` for signed values: the compiler emits a signed
    // magic-multiply division (`mulhi(x,magic) - (x >> 63)`) feeding `x - (x/C)*C`.
    // divrecover recovers the signed division; the modulo idiom folds in simplify.
    let path = paths::datatests_dir().join("modulo.xml");
    let Ok(dt) = datatest::parse_file(&path) else { return };
    let f = Funcdata::build(&spec, &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);

    let lo = [("register".to_string(), 0u64, 4u32), ("register".to_string(), 0u64, 8u32)];
    let c = f.decompile(&lo).expect("modulo decompile");
    eprintln!("=== mosura recovered signed division + modulo ===\n{c}");

    // remainders recovered to `% C` (including composite divisors via mult association)
    assert!(c.contains("% 3") && c.contains("% 5") && c.contains("% 6"), "modulo recovered, got:\n{c}");
    // the signed magic multiplier is gone for those forms
    assert!(!c.contains("0x5555555555555556"), "the magic multiply must be gone, got:\n{c}");
}

#[test]
fn loop_body_cse_names_a_carried_value_once() {
    let Some((spec, ctx)) = x86_64() else { return };
    // threedim's loop loads a value, stores it elsewhere, and carries it to the return.
    // The loaded value is used in the store AND carried by a loop variable; it must be
    // emitted once (`var = *(...)`) and referenced, not re-inlined at each use.
    let path = paths::datatests_dir().join("threedim.xml");
    let Ok(dt) = datatest::parse_file(&path) else { return };
    let f = Funcdata::build(&spec, &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);

    let lo = [("register".to_string(), 0u64, 4u32), ("register".to_string(), 0u64, 8u32)];
    let c = f.decompile(&lo).expect("threedim decompile");
    eprintln!("=== mosura loop-body CSE ===\n{c}");

    // the loaded value is named once and the store references it (a bare var, not a
    // re-inlined load) — so the big address sub-expression `<< 2` appears just twice
    // (the load and the store address), not three times. (Loop-var numbering is not
    // asserted — it varies with hash ordering.)
    assert!(c.contains("0x601060)) = var_"), "the store references the carried value, got:\n{c}");
    assert_eq!(c.matches("<< 2").count(), 2, "the loaded value must not be re-inlined, got:\n{c}");
}

#[test]
fn recovers_float_params_and_operators() {
    let Some((spec, ctx)) = x86_64() else { return };
    // floatcast takes float and int args (in XMM and integer registers) and subtracts
    // two conditionally-cast floats. F1: the XMM registers are recognized as parameters
    // and FLOAT_* ops render as C operators (not FLOAT_SUB(...) call style).
    let path = paths::datatests_dir().join("floatcast.xml");
    let Ok(dt) = datatest::parse_file(&path) else { return };
    let f = Funcdata::build(&spec, &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx);

    // x86-64 return registers incl. XMM0 (8-byte float return)
    let lo = [
        ("register".to_string(), 0u64, 4u32),
        ("register".to_string(), 0u64, 8u32),
        ("register".to_string(), 0x1200u64, 8u32),
    ];
    let c = f.decompile(&lo).expect("floatcast decompile");
    eprintln!("=== mosura float params + operators ===\n{c}");

    assert!(c.contains("param_7"), "an XMM register is recognized as a parameter, got:\n{c}");
    assert!(!c.contains("FLOAT_"), "FLOAT_* ops render as operators, not calls, got:\n{c}");
    assert!(c.contains(" - "), "the float subtraction renders as `-`, got:\n{c}");
}

#[test]
fn names_stack_slots_instead_of_raw_pointer_arithmetic() {
    let Some((spec, ctx)) = x86_64() else { return };
    let Ok(dt) = datatest::parse_file(&paths::datatests_dir().join("stackreturn.xml")) else { return };
    let image: Vec<(u64, &[u8])> = dt.chunks.iter().map(|c| (c.offset, c.bytes.as_slice())).collect();
    let f = Funcdata::build_image(&spec, &dt.chunks[0].bytes, dt.chunks[0].offset, &ctx, &image);
    let lo = [("register".to_string(), 0u64, 4u32), ("register".to_string(), 0u64, 8u32)];
    let c = f.decompile(&lo).expect("stackreturn decompile");
    eprintln!("=== stackreturn ===\n{c}");

    // frame-pointer-omitted locals are named (aStack_*), not raw `in_register_20` math
    assert!(c.contains("aStack_"), "stack slots must be named, got:\n{c}");
    assert!(!c.contains("in_register_20") && !c.contains("in_register_28"), "no raw stack-pointer arithmetic, got:\n{c}");
}
