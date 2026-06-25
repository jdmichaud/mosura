# Brief — wire the decompiler's prototype recovery to the cspec-loaded ParamList

> For the **decompiler-track agent** (works on `crates/mosura/src/decompile/` on
> `master`). The analysis track ported the cspec → `ParamList` loader but must NOT edit
> `decompile/fspec.rs`, so this last wiring step is handed off here. Status: **DEFERRED**.

## What already exists (analysis track, branch `analysis-port`)

- `crates/mosura/src/lang.rs::resolve_cspec(language_id, compiler_spec_id) -> PathBuf`
  — locates the `.cspec` file from the processor `.ldefs` `<language>/<compiler>` entries.
- `crates/mosura/src/sleigh/engine.rs::Spec::register_offset(name) -> Option<u64>`
  — read-only: resolves a register name (`RDI`) to its register-space offset (`0x38`).
- `crates/mosura/src/analysis/cspec.rs` — **C0/C1**:
  - `default_input_paramlist(spec, language_id, compiler_spec_id, spaces) -> Option<fspec::ParamList>`
    — a faithful port of `ParamListStandard::decode` (`fspec.cc:1451`): walks the
    `<default_proto><prototype><input>` `<pentry>`/`<group>` resources, assigning group ids
    exactly as `parsePentry`/`parseGroup` do, and builds a `fspec::ParamList` (the existing
    public type — constructed, not redefined).
  - `integer_arg_registers(list, reg_space)` — the analysis slice of `assignMap`.
- `crates/mosura/src/analysis/symbolic.rs::integer_arg_registers` now loads the convention
  from the cspec for **any** compiler spec (the `compiler_spec_id == "gcc"` gate is gone).

Validation (analysis side): `cspec` unit tests assert the cspec-loaded SysV input equals
`fspec::sysv_input` (`RDI,RSI,RDX,RCX,R8,R9`), MS-x64 = `RCX,RDX,R8,R9`, and x86-16
`default` = no register args (so a 16-bit binary invents nothing — comcom32/war2 stay
0-spurious).

## What is left (decompiler side — requires editing `decompile/`)

`decompile/recover.rs` (`recover_func_proto` / prototype recovery) currently obtains its
input/output `ParamList` from the hardcoded `fspec::sysv_input` / `fspec::sysv_output`.
To honor the program's actual compiler spec it should instead select the `ParamList` from
the cspec, i.e.:

1. Thread `(language_id, compiler_spec_id)` (and a `&Spec` for `register_offset`) into the
   prototype-recovery entry point. `Funcdata` already knows its language; plumb the
   compiler-spec id alongside it.
2. Replace the `sysv_input()`/`sysv_output()` calls with the cspec-loaded lists. The input
   loader is `analysis::cspec::default_input_paramlist`; add a sibling
   `default_output_paramlist` (same `decode_param_list` over the `<output>` element — the
   helper is already written to take either element and an `is_output` flag).
   - **Decision needed:** `analysis::cspec` lives under `analysis::`. The decompiler core
     shouldn't depend up into `analysis::`. Move `cspec.rs` (and the small
     `decode_param_list`/`decode_pentry` helpers) down next to `fspec.rs` in `decompile/`,
     or into a shared `lang`/`compiler` module both tracks import. This is the one real
     `decompile/` edit and the reason it's deferred to this track.
3. Cache the loaded `ParamList` per `(language, cspec)` — `decode` parses XML and should not
   run per function (the analysis side already resolves it once per function via the
   propagator's cached `Spec`; the decompiler should cache once per program).

### Beyond the GENERAL/FLOAT subset

`fspec::type_class` currently models only `GENERAL` and `FLOAT` (the x86 corpus uses only
`metatype="float"` + the default `general`). A faithful full `assignMap`/`fillinMap` for
other targets needs the remaining Ghidra storage classes (`ptr`, `hiddenret`,
`class1..4` — `type.cc:string2typeclass`) and the `<modelrule>` allocator, plus the
non-split-float / `<group>` interleaving (MS-x64) handling in `fillinMap`. Port these into
`fspec.rs` as the decompiler needs them; `cspec.rs::decode_pentry` maps any non-`float`
metatype to `GENERAL` today and would extend to the full set there.
