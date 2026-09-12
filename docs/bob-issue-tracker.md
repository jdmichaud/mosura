# Bob's issue tracker

Updated 2026-09-12. Owner: Alice. Working branch: `fix/secondary-result-contracts`.

Short checklist: [BOB_TASK.md](../BOB_TASK.md). Its markers are `[ ]` queued/triage,
`[>]` active, `[x]` fixed and validated for the stated scope, and `[-]` outside scope/not planned.

This tracks mosura work against Bob's numbered defect ledger. The latest local ledger has
**99 numbered entries** (counted from its numbered headings); the earlier handoff covered 85.
A downstream repair is not a mosura fix. Each numbered report stays open until its current
mosura behavior is checked, or triage establishes that it belongs solely to the downstream project.
The checklist below records completed work; the register below preserves every report ID.

## Completed package: explicit function inputs

Related reports: **#14**, with shared declaration gaps in **#21, #25, #32**.

- [x] Inspect current explicit high-byte call inputs against the reported instructions.
  All five AH call operands retain their loads/constants and the conditional selection.
  Before the function-input port, undeclared enclosing inputs kept #32 open; the completed
  scope validation below includes those declarations.
- [x] Reduce the function-definition input contract to source-built i386 and x86-64 MVEs.
  The protocol has EDI:uint4 and AH:uint1 inputs, an EAX:uint4 result, a nested direct call
  and an intentionally unused declared parameter. Both default analyses find all 4/4 functions.
  The existing source/build ground-truth gate passes with both added fixtures (1/1 test).
- [x] Dump the pinned C++ oracle with mapped parameters and results. Both architectures
  retain the exact input storage/order at definitions and calls, including the unused input.
  The i386 EDI offset is 0x1c; the x86-64 offset is 0x38, checked against the language tables.
  Before this port, mosura lacked the corresponding declarations and exposed missing incoming
  values. This established a feature gap, not a comparison under identical supplied facts.
- [x] Add the declaration-to-definition/caller regression before porting the locked-input
  branches of ActionPrototypeTypes and ActionInputPrototype. Retain declaration provenance
  so explicit inputs are not confused with speculative recovered prototypes.
  With the typed declaration data present but no consumers, the regression failed at the
  i386 definition: EAX:4 is recovered instead of the declared EDI:4, AH:1 pair.
- [x] Bind one declared input contract consistently at the definition and its direct calls
  (`e482d6a8`).
  The source-built regression passes for both architectures. Heritage now includes inputs
  with no descendants, and input justification consults the declared storage before the ABI.
  The graph is evaluated from the declared inputs, including boundary values and nested calls.
  The nested constant indirect target is now source-built too; both architectures preserve the
  contract through the resulting restart. A separate AArch64 fixture and mapped C++ oracle
  confirm the compiler specification's zero extension of a declared w0 input.
- [x] Expose and validate the declaration through the request-local API (`f4a4e7cd`).
  Live, cached and thawed requests preserve typed order and unused parameters. Missing,
  reordered and empty lists have distinct result keys; invalid storage is rejected.
- [x] Check unchanged default emission: 751/751 TUs are byte-identical to the prior package.
- [x] Complete workspace gates and validate the reported scopes.
  The final workspace exits 0: 1316/1316 tests pass, 23 ignored. IR parity is 9/9;
  ground truth 39/39 executed tests; disassembly golden 1/1, CLI goldens and all guards pass.
  Default emission is identical for 751/751 TUs and the stored arms tables agree.
  The two reported bodies retain all 2/2 and 5/5 calls respectively. The first has the
  incremented/restored four-input calls. The second retains both loop-carried input sets,
  packed bytes and its consistent four-input direct calls. #14 is closed for this declaration
  scope; automatic inference, compiler lowering and full typed-pointer interfaces remain open.
  See [function input contracts](function-input-contracts.md).

## Completed validation: high-byte call inputs

Related report: **#32**, validated for explicit input declarations. All 5/5 AH operands
across the three reported functions retain their native values: one indexed table load,
two fixed table loads, zero, and the conditional 0x0f/0x8f selection. The latter selects
0x8f exactly when the incoming EDI value is zero. Supplying the enclosing EDI/EBP/EBX input
list binds the selector and the two pointer walks to parameters in the two affected bodies.

The x86 source-built gate in `e482d6a8` independently evaluates AH from its declared storage
at boundary values, including the set sign bit, and retains it across a deindirection restart.
The report-specific byte/load witnesses agree. This closes the high-byte argument loss;
unrelated nested flag/multiple-result contracts and full typed-pointer interfaces remain open.
No whole-function semantic-equivalence claim is made for those remaining contracts.

## Completed validation: recursive helper inputs and shared callee order

Related report: **#25**, validated for explicit input declarations. The opt-in discovery
session contains all three reported bodies; the default call-reachable population does not.
The consumer's dispatch change belongs to its own implementation and is not a mosura fix.

Each recursive helper now accepts its EDI input, recursively passes the children at offsets
8 then 4, and forwards the unchanged value to the leaf callee through its declared EAX input.
All 6/6 direct calls across the two helpers remain, and the complementary leaf predicates
match the native instructions. The shared callee has the same ESI/EBX/ECX/AH four-input
contract at its definition and the reported caller. That caller retains both pointer values,
the count and high-byte value, plus its indexed pointer-slot input and counted loop.

This is validation of the declaration mechanism already source/oracle-gated in `e482d6a8`
and exposed by `f4a4e7cd`; it adds no production fix. Nested multi-register output contracts
inside the shared callee remain open under the results reports. This does not claim complete
semantic equivalence of that deeper call chain.

## Completed validation: shared helper input consistency

Related report: **#21**, validated for explicit input declarations. The current opt-in
listing establishes 31 unique direct call PCs across 11 owning function bodies, independently
of the report's inconsistent 29/28/20 counts. Decompilation follows additional shared tails:
35 call-context observations cover exactly those 31/31 native PCs, each with widths 4/4/4/1
in the declared order. The helper retains both incremented and restored four-input calls.

A straight-block native-instruction audit independently checks 98 known constant operands
across 30 call PCs, or 109 matching operands across the overlapping decompile contexts.
It resets at entries, branch targets and control transfers; it does not infer constants
across unknown paths. The remaining expressions were checked against the native loads,
selectors, incoming register contracts and computed positions. In particular, the width
queries retain their ESI input, and their results feed the successive additions rather
than being replaced with fixed positions. Entry views into shared code retain their own
explicit incoming inputs. A separate formatting helper receives its declared input tuple.

This is validation of `e482d6a8`/`f4a4e7cd`, not a new production change. The input scope is
closed; custom compiler lowering and unrelated output/platform contracts remain open.

## Active package: secondary result contracts

Related report: **#18**. Audit the source of both result fields through nested calls, then
check the caller's adjacent stores and uses under the same declaration. Distinguish result
storage from automatic ABI recovery and shared-global type/aliasing work.

- [>] Compare the current producer/caller graph and declarations with native instructions.
- [ ] Validate nested input/result contracts and both returned values across boundary inputs.
- [ ] Check the caller's paired stores and subsequent field uses.
- [ ] Reduce any new defect to a source-built MVE before changing production code.

## Completed validation: value and condition-flag results

Related report: **#6**, validated for explicit joined output declarations. The native
producer/caller storage protocol returns a value and flag together; the quoted consumer union
conversion was a separate downstream rewrite.

- [x] Compare native returns/calls with archived raw output and current declarations.
  The quoted integer-to-double union conversion was introduced by a consumer rewrite.
  The original protocol does return EDI plus CF; an explicit five-byte joined result
  preserves both channels in the current producers and callers.
- [x] Compile a generic value-and-flag MVE and capture the mapped C++ oracle.
  `value_flag_result.S` builds four functions on i386 and x86-64. With identical EDI input
  and join(CF, EDI) output declarations, the oracle retains both return fields, both
  flag-dependent result branches and the loop-carried value passed to the next call.
  The logical structure has size five and alignment one; physical flag storage is one byte.
- [x] Gate both channels at definitions and callers and complete workspace validation.
  The focused IR gate passes all 48 function/input cases and their call-input sequences.
  Recovered logical C also passes all 48 cases under host declarations. These checks validate
  the existing joined-result implementation; no new production change was needed.
  Source fixture: `768900d3`; semantic gate: `627d12ea`. Final `cargo test --workspace`
  exits zero: 1319/1319 executed tests pass, 23 ignored. Ground truth is 41/41, IR parity
  9/9 and disassembly golden 1/1; CLI goldens, repository guards and doc-tests pass.
  This package changes only source-built fixtures, tests and documentation. Prior production
  emission measurements remain carried evidence; no new emission identity claim is made.
- [x] Recheck the reported call chain and keep consumer rewrites outside the port.
  Both producers retain all six native exits: four decrement/CLC and two increment/STC.
  A raw-IR value audit passes 5040/5040 producer cases, covering ordinary, sign-boundary
  and wraparound values, each result and its two serial state updates. It also checks
  3168 callback operand cases, including the exchanged registers and byte input.
  All four reported caller sites extract the flag and value from the same five-byte CALL
  result. Their retry phis consume the previous result value; the other inputs retain the
  native exchange/order. All 48/48 caller result/flag cases pass the expression audit.
  Native return paths and call edges are supplied explicitly to this audit. Callback side
  effects, full outer-loop execution, automatic recovery and compiler lowering are excluded.
  The consumer-authored union conversion remains outside this declared result scope.

## Completed package: declared multiple register results

Related report: **#8**, with shared result-storage gaps in **#6, #18, #20, #22, #31** and
other result reports. Inspect actual producer/caller IR and the C++ join-storage mechanism,
then compile a minimal source-owned multi-result protocol and demonstrate its failing gate.
Do not infer an output contract from every register a function happens to write.

- [x] Inspect the current producer and caller IR against the native instructions.
  The caller still uses incoming EBX/ECX values; its producer has no return operand.
- [x] Compile a generic three-register producer/consumer MVE for i386 and x86-64.
  Both build-derived truth files contain the same three named functions. The protocol
  supplies one input and three independent outputs; the consumer uses every output.
- [x] Capture the pinned C++ oracle with identical explicit storage and type facts.
  Both architectures return a 12-byte aggregate in join storage (ECX, EBX, EAX in
  significance order). Each caller extracts offsets 8, 4 and 0 from that one CALL
  result. The producer and caller C agree on the aggregate and its three fields.
- [x] Add the declaration-to-producer/caller regression and port the join-storage consumers.
  With declaration storage present but no join heritage, the regression fails on a free
  12-byte return value. Heritage preserves the values; the required composite grouping,
  field extraction and nonprinting cast consumers then preserve the C representation too.
  The focused gate passes for both x86 modes and all six input values at both boundaries.
  See [joined result storage](joined-result-storage.md) for the ported path and its scope.
- [x] Validate default emission and workspace gates before committing the core port.
  Final isolated `cargo test --workspace`: exit 0, 1317/1317 executed tests pass, 23 ignored;
  ground truth 40/40 (one ignored), IR parity 9/9 and disassembly golden 1/1.
  One of 751 default TUs changes cast spelling. The full corpus has zero verdict flips,
  zero similarity movers, no membership drift, no EXACT lost and all eight gates green.
  The repeat caches 751/751 TUs with zero flips or movers. A signed-half execution check
  passes all 50 combinations; its former cast-spelling assertion now checks signed reads.
  Core port: `f40a563b`; source fixture: `2820467c`.
- [x] Expose and validate joined declarations through the public text option.
  `decompile.function-outputs` now accepts `join(REG,REG,...):structN(offset:scalar,...)`.
  The source-built i386/x86-64 API gate checks live, stored and thawed results, field types,
  register order, later undeclared requests, invalid storage/layouts and emission refusal.
  The `joins` table persists physical pieces and links them to logical prototype storage.
  API library 20/20, function operations 6/6, table round-trip 5/5 (one ignored), and the
  final focused joined-result gate 1/1 pass. Default emission remains byte-identical for
  751/751 TUs relative to the core port, with the same arms stamp.
- [x] Recheck the reported producer chain before closing the result scope.
  Explicit declarations bind the three-register producer and its two nested EBX-to-EAX
  transformations. The caller receives one aggregate and retains all three field uses:
  the stored byte result, both zero predicates, both additions, clamps and the early mask.
  A raw-IR expression evaluator passes 1280/1280 cases (15360 producer/consumer checks and
  20 early-return checks), covering both producer modes, optional transformations, five selected
  byte values and paired ordinary/sign-boundary/wraparound inputs. Phi predecessor choices
  are supplied from the native branches and checked against the printed conditions; this
  is a data-flow audit, not a native execution or interrupt/atomic-behavior test.
  The producer's byte/upper-zero field writes match the pinned C++ oracle on a separately
  compiled byte-extension variant. PrintC keeps that partial-field notation faithfully.
  Later callbacks, compiler lowering and automatic non-default output recovery remain open.


## Completed package: pointer records in mixed memory

Related report: **#87**. This concerns the existing opt-in `analysis.data-pointer-functions`
extension, whose deliberate function-creation policy remains separate from faithful Ghidra analysis.

- [x] Reproduce the omission with the same small assembly source in two memory layouts.
  Default analysis discovers 2/5 functions in either layout. The option discovers 5/5 with
  separate data, but still only 2/5 when code and writable records share an executable block.
- [x] Promote the source-built MVE and pin the failure before changing scan coverage.
  Both i386 and x86-64 layout pairs reproduce 2/5 versus 5/5 discovery. The source also
  embeds a code address in an instruction operand to reject scanning instruction bytes.
  The regression fails on the mixed i386 layout before the production change: 2/5 functions.
  The separate-data control passes, including its exact function-set check.
- [x] Apply the appropriate initialized-memory and instruction-range rules; retain strict
  subroutine validation and verify the option-off control and absence of spurious functions.
  The focused regression passes: all four option-on fixtures find exactly 5/5 functions,
  and all four default controls retain exactly the two directly reachable entries.
  The external population audit then exposed target instruction offcuts: terminating decode
  alone accepted 430 entries inside previously listed instructions. An extended source MVE
  reproduces this independently in separate data (6 entries for 5 source functions). The
  failing gate now pins a record pointing into a MOV operand whose bytes decode as NOP; RET.
  The target-boundary correction is committed separately as `11490ba0`; its isolated
  staged-tree regression passes for both architectures. Final discovery contains no new
  entries inside the default listing's instructions (0/993 added candidates).
- [x] Validate the reported callback entry and its complete native listing: 38/38 bytes,
  ten decoded instructions, preserving the increment, unsigned limit, reset, call and result.
- [x] Complete the final workspace and default-emission identity gates: exit 0,
  1313/1313 executed tests passed (23 ignored); IR parity 9/9, ground truth 37/37
  (one ignored), disassembly golden 1/1, CLI goldens and all repository guards green.
  The final default emission is byte-identical for 751/751 TUs, zero added or missing.
  The option-on population is 1744 entries versus 751 by default, with no lost default entry.
  These 993 additions are candidates, not a claim that every one is a source function.
  Mixed-memory coverage is committed as `a7186842`.
  [Mechanism, source MVE and policy boundary](data-pointer-discovery.md).

## Completed package: call-input phi placement

Related report: **#9**. Other loop/call data-flow reports require their own witnesses.

- [x] Reduce the loss to a self-compiled x86-32 example and preserve an x86-64 control.
- [x] Dump C++ oracle IR with matching EAX call inputs; record the three-input MULTIEQUAL.
- [x] Trace mosura: heritage substitutes an incoming register, then DCE removes the selection.
- [x] Add the repository MVE gate and show its failure before porting: x86-64 control passes,
  x86-32 fails because the callback receives an incoming register instead of the selected value.
- [x] Port phi placement from the full write set, following Ghidra's `calcMultiequals` input.
  The focused source-based gate now passes on both x86 variants (five selection boundaries each).
- [x] Validate the final workspace: 1312/1312 executed tests passed, 23 ignored; IR parity
  9/9, ground truth 36/36 (one ignored), disassembly golden 1/1, all repository guards green.
- [x] Resolve changed-emission compile failures and complete the eight corpus gates.
- [x] Finish the final workspace run (exit 0) and commit the phi fix.
- [x] Validate the external input/branch witness: all three selected addresses and both
  additional register inputs match the native instruction sequence.
- [x] Update the scope marker after the package gates and commit.

Default emission comparison: 751 TUs on each side; 17 changed, zero added or missing. This is
a behavior change and requires a compiled round, not the identity gate. The raw diff is retained
for per-function verdict investigation.
The first round attempt exposed a separate orchestration bug: a round-only scope option changes
the lookup key after `program.emit` has already projected it away. A strengthened API regression
fails at the missing emission set before compiler selection. The fix is committed independently as `a8e5c4a8`; the API round harness passes 4/4.
No verdicts from the failed attempt are counted.
The completed host rounds both attempted 751 TUs. Baseline: 14 EXACT, 14 SAME_SHAPE,
366 MISMATCH, 357 COMPILE_FAIL. Candidate: 14 EXACT, 14 SAME_SHAPE, 364 MISMATCH,
359 COMPILE_FAIL. Both new compilation failures are unsupported named-model keywords
in Watcom TUs whose parameter pragmas already encode their storage. A three-instruction
self-compiled register-convention MVE reproduces this; the C++ oracle retains the model name
and the new ground-truth gate fails before target declaration lowering. The correction is
confined to Watcom TU synthesis, with a representability check for the actual contract.
Both source-built functions recompile EXACT under Watcom (3/3 and 2/2 instructions).
A follow-up round exposed a separate cache dependency defect: TU/pragma changes were absent
from the emit fingerprint, so all 751 stale TUs were reused. The build fingerprint now includes
the recompile subtree consulted by emission. Its regression fails before the correction and
passes afterward (2/2 focused tests). A fresh-emission identity comparison before/after
only the fingerprint correction is byte-identical for 751/751 TUs, zero missing. Corpus results
from the stale-TU attempt do not measure target lowering.
Final isolated comparisons: target lowering changes 222/751 TUs only in model notation,
improves 190 compiled verdicts and loses no EXACT or compiled function. The phi change then
alters 17/751 TUs with zero verdict flips and zero new failures. Both final populations have
19 EXACT, 1 SAME_CODE, 16 SAME_SHAPE, 548 MISMATCH and 167 COMPILE_FAIL. All eight gates
pass. The repeated candidate uses 751/751 cached units and has zero flips, movers or membership
changes. The profile covers one native chain, two switch-label sets and 19 EXACT guards;
its string-operation user-classification bar is zero (all-TU counts remain memcpy 40, memset 5).
The final workspace run completed with exit 0; an earlier doctest link failure from overlapping
Cargo builds is superseded by this isolated run.

## Completed primitive: explicit scalar result contracts

Related reports: **#13, #23, #53**; multi-result contracts need their own validation.
[Generic mechanism and oracle evidence](flag-result-contracts.md).

- [x] Build a generic self-compiled flag-result fixture, independent of the survey application.
- [x] Reproduce the dropped predicate and disconnected caller condition with the current CLI.
- [x] Compare the pinned Ghidra C++ IR with and without an explicit ZF result declaration.
- [x] Add the failing declaration-to-caller/callee regression before implementing the port.
  The initial flag-result gate failed; an additional AArch64 MVE exposed missing result extension.
- [x] Implement the locked-output branches and check both predicate polarities in the MVE.
  Compiler-spec result extensions and constant-return prototype consumers are included.
  The constant-carry type regression failed before the consumer port and now passes the IR gate.
- [x] Commit the constant-carry fixture (`ec4732e3`) and the extension fixture (`ae494077`).
- [x] Compare final default emission: 751/751 translation units identical; equal arms stamps.
- [x] Finish final validation: workspace 1308/1308 executed tests passed (23 ignored),
  IR parity 9/9, ground-truth parity 34/34 (1 ignored), disassembly golden 1/1 and CLI golden
  harness 1/1 (1 ignored). All repository guards pass.
  The literal-spelling assertion exposed a separate existing printer gap; the result gate now
  compares Boolean IR types and exact 0/1 values. The generic constant printer remains open.
- [x] Commit the result-contract implementation with its gate results (`ff627430`).
- [ ] Validate the remaining external report scopes.

An arbitrary flag write does not establish a return contract. The generic problem is representing
and honoring an explicit result declaration consistently, with automatic recovery considered only
where the target's compiler specification and observable data flow support it.

## Completed package: indirect-call inputs

Related reports: **#1, #3, #7, #9, #11**. Partial-register scope #32 is validated below,
#10 was attributed to the consumer width/order, and #40 remains open. [Implementation scope and oracle evidence](indirect-call-contracts.md).

- [x] Read the repository rules and Bob's initial reports; inspect current CLI output.
- [x] Confirm that the old convention report is downstream data, not an existing mosura input.
- [x] Establish that mutable vector initializers do not prove permanent targets.
- [x] Build a self-compiled MVE and demonstrate failure before the fix.
- [x] Check Ghidra's IR with matching callee/prototype facts.
- [x] Implement constant-target resolution and restore contracts on restart.
- [x] Implement explicit register input declarations using the locked-input branch.
- [x] Verify the focused core and API regressions during development.
- [x] Finish the final regression run: workspace 1304/1304 executed tests passed (23 ignored);
  `ir_parity` 9/9, `ground_truth_parity` 32/32 (1 ignored), golden harness 1/1 (1 ignored).
- [x] Compare default emission with baseline: 751/751 translation units are byte-identical,
  with no added or missing units (`program.emit`, native loader, unchanged options).
- [x] Commit cached-program option handling independently: `0a5c36da`; isolated regression 1/1.
- [x] Commit constant-target recovery independently: `9e115c77`; isolated MVE regression 1/1.
- [x] Commit mutable-slot input declarations independently, with the package gate results.
  The workspace run preceded the extracted cache regression; that additional regression also
  passes 1/1 on the final package.
- [x] Ask Bob to validate the completed #1 input restoration against his reference.
- [x] Record Bob's validation: all four #1 calls match the reference with
  explicitly declared ordered register inputs. Only this slot's decompilation input layer is closed.

Additional scoped validation of the landed input implementation (`b0b1375a`):

- [x] **#7:** native instruction bytes and current IR agree at both reported calls. Declaring
  the byte register yields one size-1 argument from the value loaded immediately before each
  call. Both targets remain mutable. This closes only the missing input channel.
- [x] **#11:** the explicit descriptor register reaches all four reported calls. One call carries
  the first address and three carry the second, matching their native `MOV`/`CALL` sequences.
  Runtime hook installation and changed coordinate semantics belong to the consumer.
- [x] **#9:** the explicit three-register declaration now preserves all three selected pointer
  values and both additional loaded inputs, matching the native branch/call sequence. The
  source-built regression failed before the full-write-set phi port and passes on both x86
  variants afterward. C++ oracle IR, final workspace and all eight corpus gates are green.
- [ ] **#86:** seven declared register inputs appear at the call. Value-by-value validation
  is still pending; arity alone is not completion evidence.
- [ ] **Additional ordered-storage witness:** #7's first function already reorders two global
  assignments in the undeclared baseline, so its old saved value is lost. The input declaration
  preserves exactly that pre-existing behavior. Reduce the storage-order issue to its own MVE;
  the scoped input closure does not certify the surrounding function or its runtime behavior.

The declaration option is limited to decompilation. Compiler lowering of custom pointer
conventions, full typed-pointer propagation, outputs and clobbers remain open. Restoring inputs
alone does not close the entire indirect-call class.

## Completed triage

- [x] **#70: cleanup absent from the original exit path.** The native disassembly confirms the
  reported exit reads its result, adjusts a nesting counter and returns without any restore call.
  Current decompilation preserves that behavior. The ledger explains that its consumer changed
  the surrounding repaint sequence and added cleanup to compensate. Adding that call is an
  application change. Reopen only with a missing original call or changed control/data-flow witness.
- [x] **#77: shared save storage belongs to the original algorithm.** The native bytes store the
  active image and destination in single fixed locations and initialize the save pointer to one
  fixed buffer; the unmodified emission preserves those locations and the save loop. The report
  itself confirms both callers use this same routine. Separate save objects or extra erases alter
  the original ownership/sequencing policy. The former checklist description incorrectly assumed
  independent source objects; no such source objects are established. Reopen if distinct original
  addresses are conflated or an original call/store is lost.

- [x] **22 consumer issues/proofs withdrawn in the complete handoff.** The reporter explicitly
  excluded #19, #26, #29, #35, #38, #44, #50, #72, #75, #76, #78, #79, #81, #82, #83, #84,
  #85, #89, #91, #93, #97 and #99. Their ledger classifications and descriptions were checked
  against that withdrawal. These are scope closures, not mosura fixes. #26's naming concern was independently reviewed under #27; the original missing-input class mentioned in #99 remains open separately.
- [x] **Compound report #25 clarified and validated.** The consumer walker is outside scope.
  Explicit declarations now preserve both helpers' recursive inputs and the shared callee's
  argument order; the completed scope record above keeps nested outputs separate.


- [x] **#88: transparent-byte comparison.** The unmodified raw emission supplied with the
  report uses `char *` and compares its byte to `-1`. The current CLI does the same. The
  `(uint8_t)0xff` comparison quoted by the report is absent from both raw outputs, so the
  signed/unsigned mismatch was introduced downstream. No mosura printer change is indicated.
  Bob confirmed this triage and withdrew the mosura defect in his validation reply.

## Next work packages

- [ ] **Flag results (#13, #23, #53 and related reports).** The undeclared CLI drops the flag-only
  predicate in #13. The gated scalar-result implementation preserves the explicit typed result. Report validation
  remains open, including the nested callee's separate result channel.
  Bob is ready to validate this case once the work is complete.
- [ ] **Shared global storage (#4; distinguish downstream #26 and naming #27).** Reproduce
  overlapping reads/writes in self-compiled source and check the existing address-based linker
  aliases and typed views before deciding whether the emitter/TU layer needs a fix.
- [ ] **Multiple result registers (#18, #20, #22, #31 and related reports; #6/#8 declared scopes validated).**
  Audit each remaining protocol and its input/flag consumers using the joined-result mechanism.
- [ ] **Invented input parameters (#2 and related reports).** Separate missing return channels
  from unsupported external convention facts; validate against current code.
- [ ] **Partial registers and loops (#40, #66; #32 validated, #5 and #10 reviewed separately).** Distinguish mosura defects from
  downstream linear register-recovery mistakes; gate byte-lane and loop-carried behavior.
- [ ] **Missing control flow and discovery (#3, #42, #58–59, #67, #73; #9 and #87 validated).** Recheck
  current discovery and raw p-code before attributing missing branches or routines to DCE.
- [ ] **Finish triaging the remaining reports, including #86–99 added since the handoff.**

## Loop substitution scope review (#5)

- [-] The submitted witness is a downstream linear register interpreter replacing a callback's
  loop-dependent index and selected narrow argument with first-iteration constants. The archived
  raw mosura body retains the induction variable, indexed load and conditional selection. The
  consumer's own rewrite source documents this substitution and now excludes loop sites.
- Current raw decompilation also retains the induction variable in both callback arguments and
  indexed loads. Its incomplete callback contract is a separate open issue; this review does not
  claim that every current argument is correct or that other loop data-flow reports are closed.
- Reopen this item with an unmodified mosura output and matching original bytes that demonstrate
  the claimed loop-to-initial-constant substitution before consumer rewriting.

## Packed-register scope review (#10)

- [-] The submitted width/order failure belongs to the consumer's argument-recovery pass.
  The archived raw decompilation preserves all four packed words as `CONCAT11` expressions,
  matching the original low/high byte writes. The wider register's untouched upper half
  is not established by those writes; the consumer source explicitly documents that it
  requested that wider value and left these call sites in the wrong argument order.
- Current raw decompilation with the explicit word-sized input contract also retains all
  four packed values, in the declared order alongside their three full-register inputs.
  The four sites were counted from the native listing and output, independently of the
  historical repair script's reported totals.
- This closes the claimed byte-combination failure. The original undeclared callback's
  incomplete interface remains the separate input-contract work; no printer or data-flow
  workaround is warranted by this witness. Reopen with raw output that loses either byte
  under a matching declared input width.

## Naming scope review (#27)

The five reported self-loads occur in consumer C that introduces descriptive local names matching
its own renamed globals. The archived raw decompilation keeps those namespaces distinct: one
case loads a global into `iVar2`, another reads the global directly in its predicates, the packet
case separates `xVar2` from the global read, and the final state update reads its global directly.
All five current raw C bodies were also checked: their declarations are generated local names
(or there are no locals), without the consumer's colliding names. Missing inputs in a current
body remain separate reports and do not establish a naming defect.

The consumer's own naming table explicitly says it assigned the same name to a local and a
global in one case. Its repair script also renames struct tags and fields to accommodate its
address-backed object macros. Neither this renaming nor those macros are mosura output.
This closes the five submitted naming witnesses as consumer scope, without changing PrintC.
Reopen with an unmodified mosura output and matching symbol declarations that reproduce a
collision; that would need a source-controlled naming MVE.

## Report register

**Investigating** means evidence or a draft exists, not that the report is fixed.
**Queued** means current-version reproduction remains to be done.
**Downstream review** means the ledger attributes it to the downstream project; confirm that
classification before closing it as outside mosura. **Triage** means ownership is still unreviewed.
All fixes require a failing MVE, matching implementation evidence, required gates and a commit.

| Bob ID | Report | Current status |
| --- | --- | --- |
| #1 | Input contracts: preserve explicit ordered inputs at mutable pointer calls (validated scope). | Validated by Bob: explicit inputs restored at all four calls; compiler lowering remains open |
| #2 | Input contracts: reject parameters unsupported by caller/callee data flow. | Queued |
| #3 | Input contracts: propagate contracts through mutable function-pointer tables. | Investigating: input package; report validation pending |
| #4 | Storage: preserve aliasing between differently typed views of one address. | Queued: raw cross-width alias evidence received; existing linker alias support needs validation |
| #5 | Consumer loop-value substitution. | Outside scope: archived raw output preserves the loop expression; the consumer rewrite introduced the constant |
| #6 | Results: preserve an explicit value and condition flag together. | Validated declared result scope; source/IR/C gates and all four reported caller sites |
| #7 | Explicit byte inputs at indirect calls. | Validated input scope: both calls retain the original size-1 value; separate storage-order witness remains open |
| #8 | Results: preserve multiple register outputs consumed after a call. | Validated declaration scope: join heritage/composite consumers, public API, source-built gate and reported result chain; automatic recovery and compiler lowering remain open |
| #9 | Data flow: preserve branches whose operands come from indirect-call contracts. | Fixed: full-write-set phi placement; source MVE, external input/branch witness, workspace and corpus gates validated |
| #10 | Consumer packed-register width/order mismatch. | Outside scope: all four packed words already survive in archived raw output; the consumer requested the wider register and remapped arguments incorrectly |
| #11 | Explicit descriptor inputs through mutable hooks. | Validated input scope: all four calls match native argument setup; consumer installation/coordinate changes excluded |
| #12 | Platform models: recover external file-read calls, arguments and results. | Queued |
| #13 | Results: support an explicit condition-flag result consistently at callee and callers. | Partial: scalar result declarations gated; nested input/multiple-result contracts and report validation remain open |
| #14 | Input contracts: preserve explicit parameter sets at definitions and calls. | Validated: e482d6a8/f4a4e7cd; source/oracle, report witnesses and workspace gates pass |
| #15 | Results: propagate producer outputs to callers instead of uninitialized inputs. | Queued |
| #16 | Platform models: model directory-enumeration operations and termination conditions. | Queued |
| #17 | Input contracts: preserve non-default coordinate parameter storage and order. | Queued |
| #18 | Results: preserve a secondary scalar result from a multi-result call. | Active: nested producer and paired-store audit |
| #19 | Consumer review: validate application viewport dimensions; no generic defect established. | Closed scope: reporter withdrew the consumer issue/proof; reconciled with ledger |
| #20 | Results: bind multiple device-read outputs to their actual consumers. | Queued |
| #21 | Input contracts: retain shared declarations and caller values. | Validated declaration scope: 31/31 native call PCs, 35 contexts, constant and computed input witnesses |
| #22 | Results: represent multiple data results together with classification/clip results. | Queued |
| #23 | Results: support explicit carry-flag return contracts. | Queued |
| #24 | Input contracts: distinguish call-produced values from incoming function parameters. | Queued |
| #25 | Input contracts: preserve explicit recursive helper inputs and shared callee order. | Validated declaration scope: both recursive bodies and shared callee/caller; consumer dispatch is separate |
| #26 | Consumer review: validate linker placement and shared address-backed storage. | Closed scope: reporter withdrew the consumer issue/proof; reconciled with ledger; naming concern independently reviewed under #27 |
| #27 | Consumer local/global naming collisions. | Outside scope: all five collisions originate in downstream rewritten locals, absent from archived raw and current naming |
| #28 | Platform models: recover device detection and initialization call contracts. | Queued |
| #29 | Consumer review: validate application coordinate transforms and dimensions. | Closed scope: reporter withdrew the consumer issue/proof; reconciled with ledger |
| #30 | Input contracts: restore arguments across a series of vector-table calls. | Queued |
| #31 | Results: preserve multiple non-default register outputs as one consistent contract. | Queued |
| #32 | Input contracts: preserve explicit high-byte arguments and enclosing inputs. | Validated scope: 5/5 AH values, declared enclosing inputs and source-built storage/restart gate |
| #33 | Results: preserve the correct returned register in a caller's predicate. | Queued |
| #34 | Data flow: preserve cursor-like state across callbacks and nested calls. | Queued |
| #35 | Consumer review: verify that external thunks forward their declared parameters. | Closed scope: reporter withdrew the consumer issue/proof; reconciled with ledger |
| #36 | Data flow: preserve returned pointer state across a call. | Queued |
| #37 | Data flow: preserve distinct definitions across repeated computation stages. | Queued |
| #38 | Consumer review: validate remaining application dispatch classifications. | Closed scope: reporter withdrew the consumer issue/proof; reconciled with ledger |
| #39 | Discovery: recover callback entry points and verify their function boundaries. | Triage |
| #40 | Data flow: retain loop-dependent narrow-register values. | Queued |
| #41 | Results: preserve a carry-only return from a control routine. | Triage |
| #42 | Discovery/contracts: recover a missing body and its actual register inputs. | Triage |
| #43 | Indirect calls: model code addresses stored in action/dispatch records. | Triage |
| #44 | Consumer review: validate application spacing and layout logic. | Closed scope: reporter withdrew the consumer issue/proof; reconciled with ledger |
| #45 | Platform models: propagate a system-service register result to its consumer. | Triage |
| #46 | Platform models: recover external file-write calls, arguments and results. | Triage |
| #47 | Platform models: audit reconstructed device-configuration operations. | Triage |
| #48 | Input contracts: preserve per-call position arguments across repeated calls. | Queued |
| #49 | Input contracts: retain drawing inputs and per-iteration narrow values. | Triage |
| #50 | Consumer review: verify reported behavior is intentional rather than a tool defect. | Closed scope: reporter withdrew the consumer issue/proof; reconciled with ledger |
| #51 | Results: retain a narrow accumulator result used as a control signal. | Queued |
| #52 | Results: propagate a multi-register result through chained calls. | Queued |
| #53 | Results: retain a carry-only predicate used by subsequent control flow. | Queued |
| #54 | Input contracts: restore arguments to a shared annotation/output routine. | Queued |
| #55 | Contracts: audit several call boundaries in a larger computation chain. | Queued |
| #56 | Results: audit reconstructed predicate contracts against their producer bytes. | Triage |
| #57 | Results: preserve rejection predicates across a call chain. | Queued |
| #58 | Data flow: reduce reported algorithm reconstruction failures to independent MVEs. | Queued |
| #59 | Triage: attribute each witness to a generic mechanism and deduplicate reports. | Triage |
| #60 | Input contracts: restore inputs when caller setup precedes a nested call. | Queued |
| #61 | Results: keep flag status separate from a simultaneous floating-point result. | Queued |
| #62 | Input contracts: preserve a narrow event identifier passed to a service call. | Queued |
| #63 | Results: propagate both a flag and a non-default register result through a chain. | Queued |
| #64 | Results: preserve a call result consumed by a polling condition. | Queued |
| #65 | Contracts: recover state-selection arguments and sequencing across service calls. | Queued |
| #66 | Platform/data flow: preserve I/O port values and polling-loop state. | Queued |
| #67 | Control flow: represent tail transfers with the correct callee contract. | Queued |
| #68 | Input contracts: distinguish an object identifier from an iteration index. | Queued |
| #69 | Results: preserve a secondary register result used to update device state. | Queued |
| #70 | Consumer cleanup policy. | Outside scope: exit bytes contain no restore call; current output agrees |
| #71 | Results: retain a carry status that controls a downstream side effect. | Queued |
| #72 | Consumer review: verify reconstructed dispatch retains every original branch. | Closed scope: reporter withdrew the consumer issue/proof; reconciled with ledger |
| #73 | Discovery/contracts: recover an indirect producer, its inputs and its result. | Queued |
| #74 | Control flow: preserve reachable input-dependent branches. | Queued |
| #75 | Consumer review: validate application resource selection and scale factors. | Closed scope: reporter withdrew the consumer issue/proof; reconciled with ledger |
| #76 | Consumer review: validate application display-buffer selection. | Closed scope: reporter withdrew the consumer issue/proof; reconciled with ledger |
| #77 | Consumer ownership of shared save storage. | Outside scope: original bytes and raw output use one buffer; independent source objects were not established |
| #78 | Consumer review: validate application repaint-state transitions. | Closed scope: reporter withdrew the consumer issue/proof; reconciled with ledger |
| #79 | Consumer review: validate application state updates after configuration changes. | Closed scope: reporter withdrew the consumer issue/proof; reconciled with ledger |
| #80 | Results: distinguish returned numeric values from unrelated pointer state. | Queued |
| #81 | Consumer review: keep paired indices and pointers consistent in an adapter. | Closed scope: reporter withdrew the consumer issue/proof; reconciled with ledger |
| #82 | Consumer review: audit duplicate rendering callbacks and their ordering. | Closed scope: reporter withdrew the consumer issue/proof; reconciled with ledger |
| #83 | Consumer review: validate application cleanup when switching contexts. | Closed scope: reporter withdrew the consumer issue/proof; reconciled with ledger |
| #84 | Consumer review: audit validity/lifetime tracking for saved state. | Closed scope: reporter withdrew the consumer issue/proof; reconciled with ledger |
| #85 | Consumer review: audit repeated operations that overwrite saved state. | Closed scope: reporter withdrew the consumer issue/proof; reconciled with ledger |
| #86 | Input contracts: support complete declarations with many register inputs. | Queued: seven-register indirect input contract |
| #87 | Discovery: pointer-held callbacks in mixed memory. | Validated opt-in scope: source MVE, complete reported entry/body, workspace and default-emission identity |
| #88 | Comparison triage: confirmed signedness mismatch introduced by a consumer rewrite. | Closed triage, confirmed by Bob: raw and current CLI compare signed byte to -1; downstream rewrite |
| #89 | Consumer review: validate event accumulation independently of timing or resolution. | Closed scope: reporter withdrew the consumer issue/proof; reconciled with ledger |
| #90 | Results: consume device-read results instead of unrelated incoming parameters. | Queued: multiple result registers |
| #91 | Consumer review: inspect verification evidence; no independent defect alleged. | Closed scope: reporter withdrew the consumer issue/proof; reconciled with ledger |
| #92 | Input contracts: preserve declared indirect parameter order and widths. | Queued: indirect input order and widths |
| #93 | Consumer review: validate an adapter's memory-clear extent. | Closed scope: reporter withdrew the consumer issue/proof; reconciled with ledger |
| #94 | Contracts: preserve input order, multiple outputs and a flag result together. | Queued: register order plus multiple outputs and carry |
| #95 | Input contracts/control flow: recover missing indirect inputs and missing calls. | Queued: indirect inputs and missing-call census |
| #96 | Platform models/emission: represent external file I/O without semantic placeholders. | Queued: DOS interrupt modeling and emitter placeholders |
| #97 | Consumer review: verify result handling matches each exit path. | Closed scope: reporter withdrew the consumer issue/proof; reconciled with ledger |
| #98 | Results: retain a flag result used to continue or abandon an operation. | Queued: carry-result channel |
| #99 | Triage: separate consumer branch-repair errors from the original missing call input. | Closed scope: reporter withdrew the consumer issue/proof; reconciled with ledger; original missing inputs remain open in the input-contract class |
