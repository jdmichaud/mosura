# Bob's issue tracker

Updated 2026-09-12. Owner: Alice. Working branch: `fix/flag-result-contracts`.

Short checklist: [BOB_TASK.md](../BOB_TASK.md). Its markers are `[ ]` queued/triage,
`[>]` active, `[x]` fixed and validated for the stated scope, and `[-]` outside scope/not planned.

This tracks mosura work against Bob's numbered defect ledger. The latest local ledger has
**99 numbered entries** (counted from its numbered headings); the earlier handoff covered 85.
A downstream repair is not a mosura fix. Each numbered report stays open until its current
mosura behavior is checked, or triage establishes that it belongs solely to the downstream project.
The checklist below records completed work; the register below preserves every report ID.

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
- [x] Commit the result-contract implementation with its gate results (this package).
- [ ] Validate the remaining external report scopes.

An arbitrary flag write does not establish a return contract. The generic problem is representing
and honoring an explicit result declaration consistently, with automatic recovery considered only
where the target's compiler specification and observable data flow support it.

## Completed package: indirect-call inputs

Related reports: **#1, #3, #7, #9, #11**; partial-register variants **#10, #32, #40** need separate
case validation. [Implementation scope and oracle evidence](indirect-call-contracts.md).

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
- [ ] **#9:** an explicit three-register declaration restores the two loaded coordinates, but
  the selected immediate still becomes an incoming register and its branches disappear.
  A self-compiled three-way integer selection reproduces this on x86-32; the x86-64 control
  retains it. With the same EAX call input, Ghidra's C++ IR preserves the three-input MULTIEQUAL.
  The mosura action trace shows heritage replacing the call input with an incoming value before
  DCE removes the definitions. The MVE and trace are prepared; the next package must add the
  repository gate before changing phi placement.
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
  against that withdrawal. These are scope closures, not mosura fixes. #26's underlying naming
  issue remains #27; the original missing-input class mentioned in #99 remains open separately.
- [x] **Compound report #25 clarified.** The consumer walker is outside scope; the two helpers'
  missing register inputs remain open in #25. The checklist now tracks that generic contract gap.


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
- [ ] **Multiple result registers (#6, #8, #18, #20, #22, #31 and related reports).** Establish
  the prototype/return-storage gap and keep caller and callee contracts consistent.
- [ ] **Invented input parameters (#2 and related reports).** Separate missing return channels
  from unsupported external convention facts; validate against current code.
- [ ] **Partial registers and loops (#5, #10, #32, #40, #66).** Distinguish mosura defects from
  downstream linear register-recovery mistakes; gate byte-lane and loop-carried behavior.
- [ ] **Missing control flow and discovery (#3, #9, #42, #58–59, #67, #73, #87).** Recheck
  current discovery and raw p-code before attributing missing branches or routines to DCE.
- [ ] **Finish triaging the remaining reports, including #86–99 added since the handoff.**

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
| #5 | Data flow: preserve loop-carried values instead of folding them to initialization. | Queued |
| #6 | Results: represent a value and condition flag returned together. | Queued |
| #7 | Explicit byte inputs at indirect calls. | Validated input scope: both calls retain the original size-1 value; separate storage-order witness remains open |
| #8 | Results: preserve multiple register outputs consumed after a call. | Queued |
| #9 | Data flow: preserve branches whose operands come from indirect-call contracts. | Self-compiled x86-32 MVE and C++ IR comparison reproduce lost phi; repository gate and fix pending |
| #10 | Data flow: combine two byte writes into the correct wider register value. | Queued |
| #11 | Explicit descriptor inputs through mutable hooks. | Validated input scope: all four calls match native argument setup; consumer installation/coordinate changes excluded |
| #12 | Platform models: recover external file-read calls, arguments and results. | Queued |
| #13 | Results: support an explicit condition-flag result consistently at callee and callers. | Partial: scalar result declarations gated; nested input/multiple-result contracts and report validation remain open |
| #14 | Input contracts: recover missing non-default register parameter sets. | Queued |
| #15 | Results: propagate producer outputs to callers instead of uninitialized inputs. | Queued |
| #16 | Platform models: model directory-enumeration operations and termination conditions. | Queued |
| #17 | Input contracts: preserve non-default coordinate parameter storage and order. | Queued |
| #18 | Results: preserve a secondary scalar result from a multi-result call. | Queued |
| #19 | Consumer review: validate application viewport dimensions; no generic defect established. | Closed scope: reporter withdrew the consumer issue/proof; reconciled with ledger |
| #20 | Results: bind multiple device-read outputs to their actual consumers. | Queued |
| #21 | Input contracts: keep shared callee declarations consistent across call sites. | Queued |
| #22 | Results: represent multiple data results together with classification/clip results. | Queued |
| #23 | Results: support explicit carry-flag return contracts. | Queued |
| #24 | Input contracts: distinguish call-produced values from incoming function parameters. | Queued |
| #25 | Input contracts: preserve non-default register arguments in callback helpers. | Queued: helper input contracts; consumer walker excluded |
| #26 | Consumer review: validate linker placement and shared address-backed storage. | Closed scope: reporter withdrew the consumer issue/proof; reconciled with ledger; underlying #27 remains open |
| #27 | Naming: prevent local declarations from shadowing referenced globals. | Queued |
| #28 | Platform models: recover device detection and initialization call contracts. | Queued |
| #29 | Consumer review: validate application coordinate transforms and dimensions. | Closed scope: reporter withdrew the consumer issue/proof; reconciled with ledger |
| #30 | Input contracts: restore arguments across a series of vector-table calls. | Queued |
| #31 | Results: preserve multiple non-default register outputs as one consistent contract. | Queued |
| #32 | Input contracts: support parameter storage in high register bytes. | Queued |
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
| #87 | Discovery: find referenced functions in mixed executable/data memory blocks. | Reproduced: opt-in scan skips the native image’s mixed code/data block; MVE pending |
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
