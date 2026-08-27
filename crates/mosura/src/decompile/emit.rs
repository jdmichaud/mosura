//! Emission choices — the θ in `IR × θ → C`.
//!
//! A decompiler emits *one* rendering of a function, chosen to be readable. Recovering source that
//! a compiler maps back to the original bytes needs a different power: the ability to ask for a
//! **different rendering of the same IR**. The set of renderings is what this type names.
//!
//! ## Why this is not a place to hide bugs
//!
//! The danger of a knob on the printer is obvious: any byte mismatch can be "fixed" by adding one,
//! and the result is a decompiler that reproduces one binary and understands none. Three rules keep
//! an axis honest, and every axis added here has to pass all three:
//!
//! 1. **Both values are faithful renderings of the same recovered IR.** If one value is simply a
//!    truer claim about the program than the other, this is a *bug with a switch on it* and belongs
//!    wherever the recovery went wrong. The test is whether a correct decompiler could legitimately
//!    print either.
//! 2. **Acceptance is the byte verdict, never a similarity score.** A θ is kept because the function
//!    reassembles *exactly*; a θ that merely scores better is noise, and optimizing the instrument
//!    instead of the goal is the documented way this work fails.
//! 3. **The axis is justified by measured compiler behaviour**, with the probe that established it.
//!
//! [`ReturnWidth`] is the worked example of rule 1, and of how easily it is misjudged. Declaring the
//! return storage width rather than the value's width looks like papering over a type-recovery
//! defect — until you ask the reference decompiler, which declares `undefined1` for exactly the
//! function whose original writes all four bytes of `EAX`. Both are true statements: the *value* is
//! one byte and the *storage* is four. C forces a choice between them, and which one the original
//! compiler was given is not derivable from the IR. That is an axis.
//!
//! ## Separation of concerns
//!
//! - [`EmitChoices::default`] is exactly the reference decompiler's behaviour, so the port is
//!   unaffected by θ existing and nothing downstream needs to know about it.
//! - No axis knows which compiler it is for. The axes are properties of C; the mapping from an
//!   attributed divergence to the axis worth perturbing is compiler-specific and lives with the
//!   codegen model in [`crate::recompile`]. An `if target == watcom` in this file is the failure
//!   mode the separation exists to prevent.
//! - **No axis encodes an ISA or ABI constant, either.** The subtler form of the same failure:
//!   an axis with no target conditional at all can still bake one target's facts into a
//!   literal — a `0x1f` shift mask (x86-32's, not x86-64's and not ARM's), a `4` for the width
//!   of `int` (not x86-16's). A gate must read the target's own properties
//!   ([`Funcdata::size_of_int`], Ghidra's `TypeFactory::getSizeOfInt`) or establish the fact by
//!   PROVENANCE (the shift mask is the hardware's iff the LIFTER emitted it as part of the shift
//!   instruction — same source address), never by matching a constant that happens to be right
//!   here. Audited 2026-08-18 after all five axes landed: three such constants were found and
//!   replaced; on x86-32 the emitted corpus was byte-identical before and after, which is what
//!   makes it parameterization rather than a behaviour change.
//! - Axes are reachable **by name** ([`EmitChoices::axes`], [`EmitChoices::set`]). A search that
//!   enumerates them reflectively keeps working when an axis is added; one that names its axes in
//!   code must be edited every time, which is the difference between a search that grows and a
//!   table of hand-written arms.

use std::fmt;

/// Whether a function's return type is declared at the width of the **value** or of the
/// **storage** it travels in.
///
/// A function may compute one byte and return it in a four-byte register. The reference decompiler
/// prints the value's width — measured, it emits `undefined1` for WAR2's `FUN_000570cc`, whose
/// original is `XOR EAX,EAX ; MOV AL,[m] ; RET`. That is a true statement about the value, and it
/// is also the rendering under which the compiler emits only the `MOV AL`, dropping the `XOR` that
/// materializes the other three bytes. Declaring the storage width recovers the `XOR` and breaks
/// the functions that really do return a byte. Neither rule wins everywhere; the original's own
/// choice is not recoverable from the IR, so it is searched.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnWidth {
    /// The width the return-value recovery found the function to produce
    /// (`Funcdata::output_storage_size`) — the current reference behaviour, and the default.
    Recovered,
    /// The returned Varnode's own width — what the reference decompiler prints, and the narrowest
    /// of the three. Under it the compiler materializes only the bytes the value occupies.
    Value,
    /// The full width of the calling convention's return storage entry — the widest. Under it the
    /// compiler materializes the whole register, recovering a zero-extension the original performs.
    Storage,
}

/// Whether a shift count renders with the **lifter's hardware mask** or without it.
///
/// x86's shift instructions mask their count to 5 bits themselves, and the SLEIGH semantics
/// say so: `SHL r32,CL` lifts with an explicit `CL & 0x1f` before the shift. The reference
/// decompiler prints that faithfully — `1 << (x & 0x1f)` — a true statement about the ISA.
/// `1 << x` is the *same computation* on any target whose shift instruction performs the
/// mask: the compiler emits the bare shift and the hardware masks. Both render the same
/// recovered IR; C forces a choice; which one the original source spelled is not derivable
/// from the IR (though no known period source spells the hardware's own mask). Measured
/// probe (rule 3): Watcom 10.0a materializes the printed mask as a real `AND CL,0x1f` —
/// WAR2 `FUN_00038d88`, whose original has none, and 64 functions / 94 divergence rows
/// corpus-wide on sb43-5r.
///
/// The elision applies only where the mask is provably the hardware's: an implied
/// `INT_AND(x, 0x1f)` feeding (possibly through the printer-transparent ZEXT/COPY) the
/// count of a shift whose shifted operand is 4 bytes or narrower, used only by that shift.
/// Anything else keeps the faithful rendering under either value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShiftMask {
    /// Print the count as recovered — the lifter's hardware mask included. The reference
    /// behaviour, and the default.
    Recovered,
    /// Elide the mask the shift instruction itself performs.
    Hardware,
}

/// Whether a narrow register-resident local declares at the width of its **value** or of
/// the register it lives in — [`ReturnWidth`]'s question, asked of locals.
///
/// The original of WAR2's `FUN_00031044` widens a byte global into a full register at the
/// def (`XOR EAX,EAX ; MOV AL,[m]`) — an int-typed local in the source; the reference
/// decompiler recovers the value's width (`xunknown1`), under which the compiler works in
/// the byte register and re-widens at every use (`AND EAX,0xff`). Declaring the local at
/// storage width reproduces the original byte-for-byte (measured probe: the one-token
/// retype turned the function EXACT). And the opposite choice is real too: of 18 EXACT
/// functions declaring narrow locals, blanket widening broke 6 — the original sometimes
/// used a genuinely narrow local. Not derivable from the IR, so searched (rule 1: both
/// are faithful renderings; the gate below keeps them value-identical).
///
/// Value-safety gate (enforced at the declaration site, not here): only locals whose
/// every def is narrow-valued — a narrow load, copy, or call return — widen. A def that
/// truncates a wider expression or wraps narrow arithmetic keeps the narrow declaration
/// under either value, because widening those changes the computed value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalWidth {
    /// Declare at the value's width — the reference behaviour, and the default.
    Recovered,
    /// Declare width-gated narrow register locals at their register's width.
    Storage,
}

/// Whether a comparison against a constant renders in its **canonical** or **complemented**
/// form.
///
/// The decompiler canonicalizes comparison constants (`x >= 4` and `3 < x` are one IR
/// object, and the reference rendering prints the strict form Ghidra's rules normalize to —
/// oracle-verified on WAR2 `FUN_000207b8`: both print `3 < u`). The original programmer
/// wrote whichever form they wrote, and the compiled bytes differ (`CMP EAX,4` vs
/// `CMP EAX,3` with complementary jump senses). Both renderings are the same predicate on
/// every input; which one the source used is not derivable from the IR, so it is searched.
/// Measured reach on sb53: 22 near-frontier `immediate CMP` divergence rows with the
/// constants off by one in both directions.
///
/// The complement applies only where it is value-identical: one operand a plain integer
/// constant, no required cast on that slot, and the ±1 adjustment representable at the
/// constant's width (no wrap at either bound).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompareForm {
    /// The canonical rendering — the reference behaviour, and the default.
    Recovered,
    /// The complemented rendering: `x < c` ⇄ `x <= c-1`, `c < x` ⇄ `c+1 <= x`.
    Complement,
}

/// Whether a boolean returned right after the `if` that tests it renders as the merged
/// expression or as per-path constant returns.
///
/// The decompiler's rules collapse "set 1 on this path, 0 on that" into a single boolean
/// (`return x != 0;` — the reference rendering, oracle-verified on WAR2 `FUN_000260c4`),
/// and Watcom materializes the boolean with `TEST/SETNZ/AND`. The original source returned
/// constants on separate paths, which compiles to a branch and lets the compiler reuse
/// known register values (the measured original returns the call's own EAX=0 on the zero
/// path). Splitting the return back is value-identical BY CONSTRUCTION when the returned
/// boolean is the very varnode the structured `if` just tested: on the taken path it is 1,
/// on the skip path 0. A ternary spelling was probed and does NOT reproduce the bytes —
/// the return must be structurally inside the branch. Measured probe: the split form is
/// EXACT on the specimen; 15 near-frontier functions share its exact signature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReturnSplit {
    /// The merged boolean return — the reference behaviour, and the default.
    Recovered,
    /// Split into per-path constant returns where the gate proves value-identity.
    Paths,
}

/// Whether a short-circuit condition whose inner clause carries statements renders
/// collapsed (`if (a && (stmt, b))`) or as nested ifs (`if (a) { stmt; if (b) ... }`).
///
/// The two are the same program by the definition of short-circuit evaluation, and the
/// reference decompiler prints the collapsed form its structuring rules built. Watcom
/// compiles the comma clause by MATERIALIZING the clause's boolean (`SETcc` + mask beside
/// the very branch that tests it — measured on WAR2 specimen `01304`), where the original
/// — written as nested ifs — stays branch-only; the nested hand probe removed every
/// materialization row. Applies only to a plain un-`else`'d `if` (nesting changes where an
/// else would fire) whose printed `&&` spine carries statement clauses; everything else
/// keeps the collapsed rendering under either value.
///
/// FAITHFULNESS TRAP (measured, first implementation reverted as wrong code): the split
/// must be driven THROUGH `render_cond_expr`'s own negation algebra — each condition node
/// carries `cond_flip` and per-operand orientation XORed into the effective negation — so
/// the clause list is collected by mirroring only the recursion-where-`&&` decision and
/// delegating every clause's TEXT to the real renderer at the collected effective
/// negation. A hand-rolled De Morgan flatten inverted a predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CondForm {
    /// The collapsed short-circuit — the reference behaviour, and the default.
    Collapsed,
    /// Nested ifs at statement-carrying clause boundaries.
    Nested,
}

/// The choice vector.
///
/// Adding an axis is: a field, an entry in [`EmitChoices::AXES`], and arms in [`EmitChoices::get`]
/// and [`EmitChoices::set`]. The compile fails until all four exist, which is deliberate — an axis
/// the search cannot enumerate is an axis that will never be tried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EmitChoices {
    pub return_width: ReturnWidth,
    pub shift_mask: ShiftMask,
    pub local_width: LocalWidth,
    pub compare_form: CompareForm,
    pub return_split: ReturnSplit,
    pub cond_form: CondForm,
    pub ext_cast: ExtCast,
    pub swi: SwiForm,
    pub arm_order: ArmOrder,
    pub struct_locals: StructLocals,
    pub narrow_tests: NarrowTests,
    pub join_width: JoinWidth,
    pub array_index: ArrayIndex,
    pub string_ops: StringOps,
    pub sdiv_pow2: SdivPow2,
    pub frame_fill: FrameFill,
    pub sparse_switch: SparseSwitch,
    pub struct_copy: StructCopy,
}

/// How an integer extension (INT_ZEXT/INT_SEXT) that C's promotion would perform anyway is
/// rendered. `Ghidra` is `PrintC::opIntZext/opIntSext` with `isExtensionCastImplied` — the
/// reference rendering (the oracle sweep and the datatests compare against it). `Promotion`
/// prints the bare operand for a zero-extension and `(intN)x` for a sign-extension, leaving the
/// widening to C's promotion: value-identical, and the rendering Watcom 10.0a compiles closest to
/// WAR2's bytes (zc42 vs zc46: the Ghidra casts moved −262 weighted; each shape wants the cast
/// on some sites and not others — the per-site evidence rule for the original's own
/// MOVZX/XOR forms is the open design, see docs/byte-exact-status.md zc42–zc46).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtCast {
    Ghidra,
    Promotion,
}

/// How an INT3 software interrupt — Ghidra's `pcVar = swi(3); (*pcVar)();` CALLOTHER pair — is
/// rendered. `Ghidra` is the reference form (the sweep and datatests compare against it); it is
/// not C that compiles (`swi` is not a declarable function). `Int3` prints the pair as one
/// `__int3();` statement, backed by the target prelude's `#pragma aux __int3 = 0xcc` so the
/// recompile inlines the literal breakpoint byte — WAR2's compiled C carries INT3 as the retail
/// assert-trap idiom (`TEST ; Jcc over ; INT3`) and as `app_fatal`'s body (the D5 audit rows).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SwiForm {
    Ghidra,
    Int3,
}

/// Which arm of a two-arm `if/else` prints first. `Ghidra` is the structurer's canonical order
/// (the reference rendering). `Address` prints the arm the ORIGINAL compiled first — the one at
/// the lower address, which sits directly after the conditional jump — swapping the arms and
/// negating the condition where they disagree (wc2src-reconciliation-2 A1: guard clauses and
/// if/else chains laid out in source order are the dominant structural residue; attack_can_hit
/// 0.800 → EXACT on this alone). Only single-block conditions qualify, so the negation is exact
/// (the 01304 deferred-negation caveat never applies to compound clauses here).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArmOrder {
    Ghidra,
    Address,
}

/// How a 4-byte stack local that the body writes as TWO 2-byte halves (`lo = (int2)v; hi =
/// (int2)(v >> 16)`) and reads by half is declared. `Ghidra` keeps the two `int2` slots the
/// restructure derives from the accesses (the reference rendering). `Coalesce` declares ONE
/// 4-byte local, writes it once (`local = v`) and reads the halves through its address
/// (`*((int2 *)&local + 1)`) — the source's `GPOINT pt = …; pt.x` shape, which Watcom compiles
/// to the original's single `MOV dword ptr [EBP-x],EAX` and two `MOVSX` (wc2src-reconciliation-2
/// A2ii: check_attack 0.571 → 0.957 in the probe).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StructLocals {
    Ghidra,
    Coalesce,
}

/// How a byte-of-word test the lifter spelled as a shift and mask — `(x >> 8 & 2) != 0` for the
/// source's `x & 0x200` — is rendered in a zero comparison. `Ghidra` keeps the shift form (the
/// reference). `Rewiden` prints the test at the operand's own width with the mask shifted up:
/// value-identical in the boolean, and the form Watcom compiles back to the original's
/// sub-register `TEST AH,2` / memory-direct `TEST byte ptr` (wc2src-reconciliation-2 A5:
/// 88 TUs carry the shift spelling; attack_dispatch_attack 0.548 → 0.589 in the probe).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NarrowTests {
    Ghidra,
    Rewiden,
}

/// How a constant-join local (a temporary fed only by constants, merged at a phi) is DECLARED
/// when it is passed to a call whose recovered prototype declares a NARROWER parameter. `Ghidra`
/// keeps the join's own width (the reference — Ghidra types it before the recovered prototype is
/// consulted). `Consumer` declares it at the callee's parameter width: value-identical (the
/// constants fit), and it makes Watcom load the sub-register the original does (`MOV DL,9` for the
/// declared byte, not `MOV EDX,9`) — wc2src-reconciliation-3 N1: 0x2c920 0.615 → EXACT on the
/// declaration alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinWidth {
    Ghidra,
    Consumer,
}

/// How a scaled-index access through a CONSTANT or GLOBAL base is rendered. `Ghidra` prints the
/// address arithmetic `*(T *)(base + idx * sizeof(T))` (the reference). `Spelled` prints the array
/// subscript `((T *)base)[idx]` — value-identical, and the form Watcom compiles to the original's
/// scaled-index operand (`MOV EDX,[EBX+EDX*4]`, `DEC word ptr [EAX*2+0x8fa50]`) instead of an
/// explicit `SHL`/`ADD` and a load through a register (wc2src-reconciliation-3 N3: count_remove
/// 0.520 → 0.622).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArrayIndex {
    Ghidra,
    Spelled,
}

/// A lifted `REP MOVS`/`REP STOS` renders as the Ghidra counted `for` loop (`Loop`), or as the
/// `memcpy`/`memset` intrinsic call (`Intrinsic`) the source used — which Watcom's `-oi` re-inlines
/// to `REP MOVS`, recovering the bytes (docs/rep-string-intrinsic-arm.md). Byte-witnessed on the
/// original instruction being `REP MOVS`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringOps {
    Loop,
    Intrinsic,
}

/// `sdiv-pow2`: Watcom 10.0a's signed power-of-two division template (`SAR EDX,0x1f; SHL EDX,n;
/// SBB EAX,EDX; SAR EAX,n`), which Ghidra lifts to an add/mult/zext chain around the shift (or,
/// for a provably non-negative dividend, folds to the bare shift). `div` renders a witnessed site
/// as `x / 2^n`, which Watcom compiles back to the template (docs/sdiv-pow2-arm.md); `shift` is
/// the reference rendering. Byte-witnessed on the original `SBB` + `SAR` at the shift's pc.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SdivPow2 {
    Shift,
    Div,
}

/// `frame-fill`: Watcom allocates exactly the locals the C declares, so a function whose original
/// frame (`SUB ESP,n`) is larger than the recovered locals recompiles with a smaller frame and a
/// different layout. `aggregate` declares the frame's locals as ONE byte aggregate at the frame
/// bottom sized to `n`, every slot a field access at its byte offset (fable-b's srcform12 form,
/// EXACT on WAR2 0x2dcd4 with the biased-EBP prologue reproduced); `ghidra` is the reference
/// per-symbol rendering. Witnessed on the original prologue bytes, gated on an escaping local and
/// >= 32 bytes of slack (docs/compilable-c-remediation.md Phase 10b).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameFill {
    Ghidra,
    Aggregate,
}

/// `sparse-switch`: Watcom compiles a sparse `switch` into a balanced compare tree (pivot = the
/// lower median of the sorted cases), which Ghidra structures as nested if/else on one scrutinee.
/// `switch` recognizes that tree and prints the `switch` the source wrote — the case set from the
/// tree (empty cases kept, since the tree is rebuilt from the case set), bodies in address order,
/// the scrutinee load inlined when single-use (fable-b's srcform4/16 probes: 0x14620 0.376 → 0.812,
/// docs/wc2src-reconciliation-4.md W5); `ghidra` is the reference if/else rendering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SparseSwitch {
    Ghidra,
    Switch,
}

/// `struct-copy`: a run of k plain `MOVSD` (no REP, no ECX) after an ESI/EDI setup is Watcom's
/// struct assignment at or below its unroll threshold (`*(struct pN *)d = *(struct pN *)s`, N = 4k);
/// Ghidra prints k dword copies, which recompile as k MOV pairs. `assign` prints the assignment
/// through `struct p8/p12/p16` (prelude types) at the sites a `MOVSD`-run witness names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StructCopy {
    Ghidra,
    Assign,
}

impl Default for EmitChoices {
    fn default() -> Self {
        Self {
            return_width: ReturnWidth::Recovered,
            shift_mask: ShiftMask::Recovered,
            local_width: LocalWidth::Recovered,
            compare_form: CompareForm::Recovered,
            return_split: ReturnSplit::Recovered,
            cond_form: CondForm::Collapsed,
            ext_cast: ExtCast::Ghidra,
            swi: SwiForm::Ghidra,
            arm_order: ArmOrder::Ghidra,
            struct_locals: StructLocals::Ghidra,
            narrow_tests: NarrowTests::Ghidra,
            join_width: JoinWidth::Ghidra,
            array_index: ArrayIndex::Ghidra,
            string_ops: StringOps::Loop,
            sdiv_pow2: SdivPow2::Shift,
            frame_fill: FrameFill::Ghidra,
            sparse_switch: SparseSwitch::Ghidra,
            struct_copy: StructCopy::Ghidra,
        }
    }
}

/// One axis: its name, and the values it accepts. The first value listed is the default.
#[derive(Debug, Clone, Copy)]
pub struct Axis {
    pub name: &'static str,
    pub values: &'static [&'static str],
    /// What this axis changes about the emitted C, for `--help` and for reports.
    pub doc: &'static str,
}

impl EmitChoices {
    /// Every axis this build knows about.
    pub const AXES: &'static [Axis] = &[
        Axis {
            name: "return-width",
            values: &["recovered", "value", "storage"],
            doc: "declare the return type at the width of the value, or of the convention's storage",
        },
        Axis {
            name: "shift-mask",
            values: &["recovered", "hardware"],
            doc: "print the shift count with the lifter's hardware mask, or elide the mask the \
                  shift instruction itself performs",
        },
        Axis {
            name: "local-width",
            values: &["recovered", "storage"],
            doc: "declare narrow register locals at the width of the value, or of the register \
                  they live in (value-safe defs only)",
        },
        Axis {
            name: "compare-form",
            values: &["recovered", "complement"],
            doc: "render constant comparisons canonically, or complemented (x < c as x <= c-1) \
                  where the adjustment is value-identical",
        },
        Axis {
            name: "return-split",
            values: &["recovered", "paths"],
            doc: "return a tail boolean as the merged expression, or as per-path constant \
                  returns when it is the varnode the preceding if just tested",
        },
        Axis {
            name: "cond-form",
            values: &["collapsed", "nested"],
            doc: "render statement-carrying short-circuit clauses collapsed (comma form) or \
                  as nested ifs",
        },
        Axis {
            name: "ext-cast",
            values: &["ghidra", "promotion"],
            doc: "render integer extensions as Ghidra's implied-cast rule (opIntZext/opIntSext) \
                  or leave the widening to C's promotion (bare zext, (intN) sext)",
        },
        Axis {
            name: "swi",
            values: &["ghidra", "int3"],
            doc: "render an INT3 software interrupt as Ghidra's swi(3) call pair, or as the \
                  target prelude's __int3() (#pragma aux = 0xcc, byte-exact breakpoint)",
        },
        Axis {
            name: "arm-order",
            values: &["ghidra", "address"],
            doc: "print if/else arms in the structurer's canonical order, or in the original's \
                  layout order (the lower-address arm first, condition negated to match)",
        },
        Axis {
            name: "struct-locals",
            values: &["ghidra", "coalesce"],
            doc: "keep a half-written 4-byte stack local as two 2-byte slots, or declare it once \
                  and read the halves through its address",
        },
        Axis {
            name: "narrow-tests",
            values: &["ghidra", "rewiden"],
            doc: "render a shifted byte-of-word zero test as the lifter's shift-and-mask, or at the \
                  operand's own width with the mask shifted up (x & 0x200)",
        },
        Axis {
            name: "join-width",
            values: &["ghidra", "consumer"],
            doc: "declare a constant-join local at its own width, or at the narrower width of the \
                  call parameter it feeds (value-identical; the sub-register load)",
        },
        Axis {
            name: "array-index",
            values: &["ghidra", "spelled"],
            doc: "render a scaled-index access through a constant/global base as address \
                  arithmetic *(T *)(base + i*sz), or as the array subscript ((T *)base)[i]",
        },
        Axis {
            name: "string-ops",
            values: &["loop", "intrinsic"],
            doc: "render a lifted REP MOVS/REP STOS as the Ghidra counted loop, or as the \
                  memcpy/memset intrinsic call the source used (witnessed on the original REP MOVS)",
        },
        Axis {
            name: "sdiv-pow2",
            values: &["shift", "div"],
            doc: "render Watcom's SBB template for a signed division by a power of two as the lifted \
                  shift arithmetic, or as the `x / 2^n` the source wrote (witnessed on the original SBB+SAR)",
        },
        Axis {
            name: "frame-fill",
            values: &["ghidra", "aggregate"],
            doc: "declare the frame's locals per symbol (Ghidra), or as one byte aggregate sized to the \
                  original SUB ESP frame with every slot a field at its byte offset (witnessed on the prologue)",
        },
        Axis {
            name: "struct-copy",
            values: &["ghidra", "assign"],
            doc: "a witnessed run of k plain MOVSD prints as a k-dword struct assignment",
        },
        Axis {
            name: "sparse-switch",
            values: &["ghidra", "switch"],
            doc: "render a compare tree on one scrutinee as Ghidra's nested if/else, or as the sparse \
                  `switch` the source wrote (case set from the tree, bodies in address order)",
        },
    ];

    /// Every axis, for a search that wants to enumerate rather than hardcode.
    pub fn axes() -> &'static [Axis] {
        Self::AXES
    }

    /// The value currently selected on `axis`, or `None` if there is no such axis.
    pub fn get(&self, axis: &str) -> Option<&'static str> {
        match axis {
            "return-width" => Some(match self.return_width {
                ReturnWidth::Recovered => "recovered",
                ReturnWidth::Value => "value",
                ReturnWidth::Storage => "storage",
            }),
            "shift-mask" => Some(match self.shift_mask {
                ShiftMask::Recovered => "recovered",
                ShiftMask::Hardware => "hardware",
            }),
            "local-width" => Some(match self.local_width {
                LocalWidth::Recovered => "recovered",
                LocalWidth::Storage => "storage",
            }),
            "compare-form" => Some(match self.compare_form {
                CompareForm::Recovered => "recovered",
                CompareForm::Complement => "complement",
            }),
            "return-split" => Some(match self.return_split {
                ReturnSplit::Recovered => "recovered",
                ReturnSplit::Paths => "paths",
            }),
            "cond-form" => Some(match self.cond_form {
                CondForm::Collapsed => "collapsed",
                CondForm::Nested => "nested",
            }),
            "ext-cast" => Some(match self.ext_cast {
                ExtCast::Ghidra => "ghidra",
                ExtCast::Promotion => "promotion",
            }),
            "swi" => Some(match self.swi {
                SwiForm::Ghidra => "ghidra",
                SwiForm::Int3 => "int3",
            }),
            "arm-order" => Some(match self.arm_order {
                ArmOrder::Ghidra => "ghidra",
                ArmOrder::Address => "address",
            }),
            "struct-locals" => Some(match self.struct_locals {
                StructLocals::Ghidra => "ghidra",
                StructLocals::Coalesce => "coalesce",
            }),
            "narrow-tests" => Some(match self.narrow_tests {
                NarrowTests::Ghidra => "ghidra",
                NarrowTests::Rewiden => "rewiden",
            }),
            "join-width" => Some(match self.join_width {
                JoinWidth::Ghidra => "ghidra",
                JoinWidth::Consumer => "consumer",
            }),
            "array-index" => Some(match self.array_index {
                ArrayIndex::Ghidra => "ghidra",
                ArrayIndex::Spelled => "spelled",
            }),
            "string-ops" => Some(match self.string_ops {
                StringOps::Loop => "loop",
                StringOps::Intrinsic => "intrinsic",
            }),
            "sdiv-pow2" => Some(match self.sdiv_pow2 {
                SdivPow2::Shift => "shift",
                SdivPow2::Div => "div",
            }),
            "frame-fill" => Some(match self.frame_fill {
                FrameFill::Ghidra => "ghidra",
                FrameFill::Aggregate => "aggregate",
            }),
            "struct-copy" => Some(match self.struct_copy {
                StructCopy::Ghidra => "ghidra",
                StructCopy::Assign => "assign",
            }),
            "sparse-switch" => Some(match self.sparse_switch {
                SparseSwitch::Ghidra => "ghidra",
                SparseSwitch::Switch => "switch",
            }),
            _ => None,
        }
    }

    /// Select `value` on `axis`. Returns an error naming what was wrong, so a bad choice on a
    /// command line fails loudly: a silently-ignored assignment makes a search report that an axis
    /// does not help when it was never applied.
    pub fn set(&mut self, axis: &str, value: &str) -> Result<(), ChoiceError> {
        match axis {
            "return-width" => {
                self.return_width = match value {
                    "recovered" => ReturnWidth::Recovered,
                    "value" => ReturnWidth::Value,
                    "storage" => ReturnWidth::Storage,
                    _ => return Err(ChoiceError::Value { axis: axis.to_string(), value: value.to_string() }),
                }
            }
            "shift-mask" => {
                self.shift_mask = match value {
                    "recovered" => ShiftMask::Recovered,
                    "hardware" => ShiftMask::Hardware,
                    _ => return Err(ChoiceError::Value { axis: axis.to_string(), value: value.to_string() }),
                }
            }
            "local-width" => {
                self.local_width = match value {
                    "recovered" => LocalWidth::Recovered,
                    "storage" => LocalWidth::Storage,
                    _ => return Err(ChoiceError::Value { axis: axis.to_string(), value: value.to_string() }),
                }
            }
            "compare-form" => {
                self.compare_form = match value {
                    "recovered" => CompareForm::Recovered,
                    "complement" => CompareForm::Complement,
                    _ => return Err(ChoiceError::Value { axis: axis.to_string(), value: value.to_string() }),
                }
            }
            "return-split" => {
                self.return_split = match value {
                    "recovered" => ReturnSplit::Recovered,
                    "paths" => ReturnSplit::Paths,
                    _ => return Err(ChoiceError::Value { axis: axis.to_string(), value: value.to_string() }),
                }
            }
            "cond-form" => {
                self.cond_form = match value {
                    "collapsed" => CondForm::Collapsed,
                    "nested" => CondForm::Nested,
                    _ => return Err(ChoiceError::Value { axis: axis.to_string(), value: value.to_string() }),
                }
            }
            "ext-cast" => {
                self.ext_cast = match value {
                    "ghidra" => ExtCast::Ghidra,
                    "promotion" => ExtCast::Promotion,
                    _ => return Err(ChoiceError::Value { axis: axis.to_string(), value: value.to_string() }),
                }
            }
            "swi" => {
                self.swi = match value {
                    "ghidra" => SwiForm::Ghidra,
                    "int3" => SwiForm::Int3,
                    _ => return Err(ChoiceError::Value { axis: axis.to_string(), value: value.to_string() }),
                }
            }
            "arm-order" => {
                self.arm_order = match value {
                    "ghidra" => ArmOrder::Ghidra,
                    "address" => ArmOrder::Address,
                    _ => return Err(ChoiceError::Value { axis: axis.to_string(), value: value.to_string() }),
                }
            }
            "struct-locals" => {
                self.struct_locals = match value {
                    "ghidra" => StructLocals::Ghidra,
                    "coalesce" => StructLocals::Coalesce,
                    _ => return Err(ChoiceError::Value { axis: axis.to_string(), value: value.to_string() }),
                }
            }
            "narrow-tests" => {
                self.narrow_tests = match value {
                    "ghidra" => NarrowTests::Ghidra,
                    "rewiden" => NarrowTests::Rewiden,
                    _ => return Err(ChoiceError::Value { axis: axis.to_string(), value: value.to_string() }),
                }
            }
            "join-width" => {
                self.join_width = match value {
                    "ghidra" => JoinWidth::Ghidra,
                    "consumer" => JoinWidth::Consumer,
                    _ => return Err(ChoiceError::Value { axis: axis.to_string(), value: value.to_string() }),
                }
            }
            "array-index" => {
                self.array_index = match value {
                    "ghidra" => ArrayIndex::Ghidra,
                    "spelled" => ArrayIndex::Spelled,
                    _ => return Err(ChoiceError::Value { axis: axis.to_string(), value: value.to_string() }),
                }
            }
            "string-ops" => {
                self.string_ops = match value {
                    "loop" => StringOps::Loop,
                    "intrinsic" => StringOps::Intrinsic,
                    _ => return Err(ChoiceError::Value { axis: axis.to_string(), value: value.to_string() }),
                }
            }
            "sdiv-pow2" => {
                self.sdiv_pow2 = match value {
                    "shift" => SdivPow2::Shift,
                    "div" => SdivPow2::Div,
                    _ => return Err(ChoiceError::Value { axis: axis.to_string(), value: value.to_string() }),
                }
            }
            "frame-fill" => {
                self.frame_fill = match value {
                    "ghidra" => FrameFill::Ghidra,
                    "aggregate" => FrameFill::Aggregate,
                    _ => return Err(ChoiceError::Value { axis: axis.to_string(), value: value.to_string() }),
                }
            }
            "struct-copy" => {
                self.struct_copy = match value {
                    "ghidra" => StructCopy::Ghidra,
                    "assign" => StructCopy::Assign,
                    _ => return Err(ChoiceError::Value { axis: axis.to_string(), value: value.to_string() }),
                }
            }
            "sparse-switch" => {
                self.sparse_switch = match value {
                    "ghidra" => SparseSwitch::Ghidra,
                    "switch" => SparseSwitch::Switch,
                    _ => return Err(ChoiceError::Value { axis: axis.to_string(), value: value.to_string() }),
                }
            }
            _ => return Err(ChoiceError::Axis(axis.to_string())),
        }
        Ok(())
    }

    /// Parse an `axis=value` assignment, as a command line spells one.
    pub fn assign(&mut self, spec: &str) -> Result<(), ChoiceError> {
        let (axis, value) = spec.split_once('=').ok_or_else(|| ChoiceError::Syntax(spec.to_string()))?;
        self.set(axis.trim(), value.trim())
    }

    /// Parse a whole vector from a comma-separated `axis=value` list. `"default"` and the empty
    /// string both mean the reference rendering.
    pub fn parse(spec: &str) -> Result<Self, ChoiceError> {
        let mut c = Self::default();
        for part in spec.split(',').map(str::trim).filter(|s| !s.is_empty() && *s != "default") {
            c.assign(part)?;
        }
        Ok(c)
    }

    /// The non-default axes, as `axis=value`. Empty for the default vector, so it reads as "the
    /// reference rendering" in a report rather than as a list of every axis.
    pub fn deviations(&self) -> Vec<String> {
        let d = Self::default();
        Self::AXES
            .iter()
            .filter_map(|a| {
                let (v, dv) = (self.get(a.name)?, d.get(a.name)?);
                (v != dv).then(|| format!("{}={}", a.name, v))
            })
            .collect()
    }

    /// A short name for this vector, usable as a directory or cache-key component.
    /// `"default"` for the reference rendering, else the deviations joined by `+`.
    pub fn tag(&self) -> String {
        let d = self.deviations();
        if d.is_empty() {
            "default".to_string()
        } else {
            d.join("+").replace('=', "-")
        }
    }

    /// Every vector obtained by moving exactly one axis off its current value — the neighbourhood a
    /// directed search steps through. Enumerated from [`Self::AXES`], so a new axis joins the
    /// search without the search being edited.
    pub fn neighbours(&self) -> Vec<Self> {
        let mut out = Vec::new();
        for a in Self::AXES {
            let cur = self.get(a.name);
            for v in a.values {
                if Some(*v) == cur {
                    continue;
                }
                let mut n = *self;
                if n.set(a.name, v).is_ok() {
                    out.push(n);
                }
            }
        }
        out
    }
}

/// A rendering of the whole vector, stable and order-independent: usable as a cache key.
impl fmt::Display for EmitChoices {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut first = true;
        for a in Self::AXES {
            if !first {
                f.write_str(",")?;
            }
            first = false;
            write!(f, "{}={}", a.name, self.get(a.name).unwrap_or("?"))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChoiceError {
    /// No axis by that name.
    Axis(String),
    /// The axis exists but does not take that value.
    Value { axis: String, value: String },
    /// Not an `axis=value` assignment.
    Syntax(String),
}

impl fmt::Display for ChoiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChoiceError::Axis(a) => {
                let names: Vec<&str> = EmitChoices::AXES.iter().map(|x| x.name).collect();
                write!(f, "no emission axis `{a}` (known: {})", names.join(", "))
            }
            ChoiceError::Value { axis, value } => {
                let vs = EmitChoices::AXES.iter().find(|x| x.name == axis).map(|x| x.values).unwrap_or(&[]);
                write!(f, "axis `{axis}` does not take `{value}` (accepts: {})", vs.join(", "))
            }
            ChoiceError::Syntax(s) => write!(f, "`{s}` is not an axis=value assignment"),
        }
    }
}

impl std::error::Error for ChoiceError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The default vector is the reference rendering: every axis sits on the first value its table
    /// lists, so the table and the `Default` impl cannot drift apart unnoticed.
    #[test]
    fn default_selects_the_first_value_of_every_axis() {
        let d = EmitChoices::default();
        for a in EmitChoices::AXES {
            assert_eq!(d.get(a.name), Some(a.values[0]), "axis {}", a.name);
        }
        assert!(d.deviations().is_empty(), "the default vector deviates from nothing");
        assert_eq!(d.tag(), "default");
    }

    /// Every axis is reachable by name in both directions. A search enumerates `AXES` and calls
    /// `set`; an axis present in the table but missing from `set` would be silently unsearchable.
    #[test]
    fn every_listed_axis_round_trips_through_name_and_value() {
        for a in EmitChoices::AXES {
            for v in a.values {
                let mut c = EmitChoices::default();
                c.set(a.name, v).unwrap_or_else(|e| panic!("set {}={v}: {e}", a.name));
                assert_eq!(c.get(a.name), Some(*v));
            }
        }
    }

    /// The neighbourhood covers every off-current value of every axis, and nothing else — this is
    /// the step set of the search, so a gap here is a rendering that is never tried.
    #[test]
    fn neighbours_cover_every_other_value_of_every_axis() {
        let d = EmitChoices::default();
        let n = d.neighbours();
        let expected: usize = EmitChoices::AXES.iter().map(|a| a.values.len() - 1).sum();
        assert_eq!(n.len(), expected);
        for a in EmitChoices::AXES {
            for v in a.values.iter().filter(|v| **v != a.values[0]) {
                assert!(n.iter().any(|c| c.get(a.name) == Some(*v)), "{}={v} unreachable", a.name);
            }
        }
        assert!(!n.contains(&d), "a neighbour is never the vector itself");
    }

    /// A misspelled axis or value is an error, not a no-op. A silently-dropped choice would make a
    /// search conclude the axis does not help when it was never applied.
    #[test]
    fn unknown_axes_and_values_are_rejected() {
        let mut c = EmitChoices::default();
        assert!(matches!(c.set("no-such-axis", "x"), Err(ChoiceError::Axis(_))));
        assert!(matches!(c.set("return-width", "nonsense"), Err(ChoiceError::Value { .. })));
        assert!(matches!(c.assign("return-width"), Err(ChoiceError::Syntax(_))));
        assert_eq!(c, EmitChoices::default(), "a rejected assignment changes nothing");
    }

    /// The error names the alternatives, because the first thing anyone does with a rejected
    /// choice is ask what the accepted ones are.
    #[test]
    fn errors_name_the_alternatives() {
        let e = EmitChoices::default().set("return-width", "nope").unwrap_err().to_string();
        assert!(e.contains("recovered") && e.contains("value") && e.contains("storage"), "{e}");
        let e = EmitChoices::default().set("bogus", "x").unwrap_err().to_string();
        assert!(e.contains("return-width"), "{e}");
    }

    /// `Display` covers every axis, so it identifies a rendering completely — which is what makes
    /// it safe as a cache key for "the C this θ produces".
    #[test]
    fn display_names_every_axis() {
        let s = EmitChoices::default().to_string();
        for a in EmitChoices::AXES {
            assert!(s.contains(a.name), "{s} omits {}", a.name);
        }
    }

    /// A vector round-trips through the spelling a command line and a directory name use.
    #[test]
    fn a_vector_round_trips_through_its_written_forms() {
        let mut c = EmitChoices::default();
        c.assign("return-width=storage").unwrap();
        assert_eq!(c.return_width, ReturnWidth::Storage);
        assert_eq!(c.deviations(), vec!["return-width=storage"]);
        assert_eq!(c.tag(), "return-width-storage");
        assert_eq!(EmitChoices::parse("return-width=storage").unwrap(), c);
        assert_eq!(EmitChoices::parse("default").unwrap(), EmitChoices::default());
        assert_eq!(EmitChoices::parse("").unwrap(), EmitChoices::default());
    }
}
