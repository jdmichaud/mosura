# Bob's tasks

Updated 2026-09-12. Owner: Alice.

Report numbers are traceability links to the external ledger, not application-specific features
for mosura to implement. Each description names a generic capability or an ownership question.
Reports sharing a root cause should be solved together, with a separate commit for each separable
issue. Code, fixtures and commit messages describe the generic mechanism and self-compiled MVE.

Checked means the stated scope is fixed and validated, or confirmed outside mosura's scope.
Unchecked includes pending triage; it does not mean mosura accepts the report as its own defect.
Checked consumer items were explicitly withdrawn in the reporter's complete handoff and
reconciled with the ledger. Their closure does not claim a mosura code fix.
The [detailed tracker](docs/bob-issue-tracker.md) records evidence and commits; update both trackers.

Completed scopes: #1's explicit decompilation inputs; #88's verified consumer rewrite;
22 further consumer issues/proofs withdrawn in the complete handoff. Related generic defects
remain open: in particular #26 does not close #27, and #99 does not close missing call inputs.
Compiler lowering, full typed-pointer contracts, outputs and clobbers remain open.
Current work: #13's self-compiled flag-result MVE reproduces the loss. The C++ oracle preserves
both branch polarities with an explicit result declaration. Implementation and its regression gate
remain pending; default ABI recovery must not infer flag returns merely from flag writes.

- [x] **#1** Input contracts: preserve explicit ordered inputs at mutable pointer calls (validated scope).
- [ ] **#2** Input contracts: reject parameters unsupported by caller/callee data flow.
- [ ] **#3** Input contracts: propagate contracts through mutable function-pointer tables.
- [ ] **#4** Storage: preserve aliasing between differently typed views of one address.
- [ ] **#5** Data flow: preserve loop-carried values instead of folding them to initialization.
- [ ] **#6** Results: represent a value and condition flag returned together.
- [ ] **#7** Input contracts: validate explicit indirect inputs across additional call sites.
- [ ] **#8** Results: preserve multiple register outputs consumed after a call.
- [ ] **#9** Data flow: preserve branches whose operands come from indirect-call contracts.
- [ ] **#10** Data flow: combine two byte writes into the correct wider register value.
- [ ] **#11** Indirect calls: distinguish runtime pointer storage, target identity and call contracts.
- [ ] **#12** Platform models: recover external file-read calls, arguments and results.
- [ ] **#13** Results: support an explicit condition-flag result consistently at callee and callers.
- [ ] **#14** Input contracts: recover missing non-default register parameter sets.
- [ ] **#15** Results: propagate producer outputs to callers instead of uninitialized inputs.
- [ ] **#16** Platform models: model directory-enumeration operations and termination conditions.
- [ ] **#17** Input contracts: preserve non-default coordinate parameter storage and order.
- [ ] **#18** Results: preserve a secondary scalar result from a multi-result call.
- [x] **#19** Consumer scope: validate application viewport dimensions; no generic defect established. Withdrawn upstream.
- [ ] **#20** Results: bind multiple device-read outputs to their actual consumers.
- [ ] **#21** Input contracts: keep shared callee declarations consistent across call sites.
- [ ] **#22** Results: represent multiple data results together with classification/clip results.
- [ ] **#23** Results: support explicit carry-flag return contracts.
- [ ] **#24** Input contracts: distinguish call-produced values from incoming function parameters.
- [ ] **#25** Input contracts: preserve non-default register arguments in callback helpers.
- [x] **#26** Consumer scope: validate linker placement and shared address-backed storage. Withdrawn upstream.
- [ ] **#27** Naming: prevent local declarations from shadowing referenced globals.
- [ ] **#28** Platform models: recover device detection and initialization call contracts.
- [x] **#29** Consumer scope: validate application coordinate transforms and dimensions. Withdrawn upstream.
- [ ] **#30** Input contracts: restore arguments across a series of vector-table calls.
- [ ] **#31** Results: preserve multiple non-default register outputs as one consistent contract.
- [ ] **#32** Input contracts: support parameter storage in high register bytes.
- [ ] **#33** Results: preserve the correct returned register in a caller's predicate.
- [ ] **#34** Data flow: preserve cursor-like state across callbacks and nested calls.
- [x] **#35** Consumer scope: verify that external thunks forward their declared parameters. Withdrawn upstream.
- [ ] **#36** Data flow: preserve returned pointer state across a call.
- [ ] **#37** Data flow: preserve distinct definitions across repeated computation stages.
- [x] **#38** Consumer scope: validate remaining application dispatch classifications. Withdrawn upstream.
- [ ] **#39** Discovery: recover callback entry points and verify their function boundaries.
- [ ] **#40** Data flow: retain loop-dependent narrow-register values.
- [ ] **#41** Results: preserve a carry-only return from a control routine.
- [ ] **#42** Discovery/contracts: recover a missing body and its actual register inputs.
- [ ] **#43** Indirect calls: model code addresses stored in action/dispatch records.
- [x] **#44** Consumer scope: validate application spacing and layout logic. Withdrawn upstream.
- [ ] **#45** Platform models: propagate a system-service register result to its consumer.
- [ ] **#46** Platform models: recover external file-write calls, arguments and results.
- [ ] **#47** Platform models: audit reconstructed device-configuration operations.
- [ ] **#48** Input contracts: preserve per-call position arguments across repeated calls.
- [ ] **#49** Input contracts: retain drawing inputs and per-iteration narrow values.
- [x] **#50** Consumer scope: verify reported behavior is intentional rather than a tool defect. Withdrawn upstream.
- [ ] **#51** Results: retain a narrow accumulator result used as a control signal.
- [ ] **#52** Results: propagate a multi-register result through chained calls.
- [ ] **#53** Results: retain a carry-only predicate used by subsequent control flow.
- [ ] **#54** Input contracts: restore arguments to a shared annotation/output routine.
- [ ] **#55** Contracts: audit several call boundaries in a larger computation chain.
- [ ] **#56** Results: audit reconstructed predicate contracts against their producer bytes.
- [ ] **#57** Results: preserve rejection predicates across a call chain.
- [ ] **#58** Data flow: reduce reported algorithm reconstruction failures to independent MVEs.
- [ ] **#59** Triage: attribute each witness to a generic mechanism and deduplicate reports.
- [ ] **#60** Input contracts: restore inputs when caller setup precedes a nested call.
- [ ] **#61** Results: keep flag status separate from a simultaneous floating-point result.
- [ ] **#62** Input contracts: preserve a narrow event identifier passed to a service call.
- [ ] **#63** Results: propagate both a flag and a non-default register result through a chain.
- [ ] **#64** Results: preserve a call result consumed by a polling condition.
- [ ] **#65** Contracts: recover state-selection arguments and sequencing across service calls.
- [ ] **#66** Platform/data flow: preserve I/O port values and polling-loop state.
- [ ] **#67** Control flow: represent tail transfers with the correct callee contract.
- [ ] **#68** Input contracts: distinguish an object identifier from an iteration index.
- [ ] **#69** Results: preserve a secondary register result used to update device state.
- [ ] **#70** Triage: separate missing callback/state flow from consumer cleanup and repaint policy.
- [ ] **#71** Results: retain a carry status that controls a downstream side effect.
- [x] **#72** Consumer scope: verify reconstructed dispatch retains every original branch. Withdrawn upstream.
- [ ] **#73** Discovery/contracts: recover an indirect producer, its inputs and its result.
- [ ] **#74** Control flow: preserve reachable input-dependent branches.
- [x] **#75** Consumer scope: validate application resource selection and scale factors. Withdrawn upstream.
- [x] **#76** Consumer scope: validate application display-buffer selection. Withdrawn upstream.
- [ ] **#77** Storage/data flow: distinguish independent state objects and their saved contents.
- [x] **#78** Consumer scope: validate application repaint-state transitions. Withdrawn upstream.
- [x] **#79** Consumer scope: validate application state updates after configuration changes. Withdrawn upstream.
- [ ] **#80** Results: distinguish returned numeric values from unrelated pointer state.
- [x] **#81** Consumer scope: keep paired indices and pointers consistent in an adapter. Withdrawn upstream.
- [x] **#82** Consumer scope: audit duplicate rendering callbacks and their ordering. Withdrawn upstream.
- [x] **#83** Consumer scope: validate application cleanup when switching contexts. Withdrawn upstream.
- [x] **#84** Consumer scope: audit validity/lifetime tracking for saved state. Withdrawn upstream.
- [x] **#85** Consumer scope: audit repeated operations that overwrite saved state. Withdrawn upstream.
- [ ] **#86** Input contracts: support complete declarations with many register inputs.
- [ ] **#87** Discovery: find referenced functions in mixed executable/data memory blocks.
- [x] **#88** Comparison triage: confirmed signedness mismatch introduced by a consumer rewrite.
- [x] **#89** Consumer scope: validate event accumulation independently of timing or resolution. Withdrawn upstream.
- [ ] **#90** Results: consume device-read results instead of unrelated incoming parameters.
- [x] **#91** Consumer scope: inspect verification evidence; no independent defect alleged. Withdrawn upstream.
- [ ] **#92** Input contracts: preserve declared indirect parameter order and widths.
- [x] **#93** Consumer scope: validate an adapter's memory-clear extent. Withdrawn upstream.
- [ ] **#94** Contracts: preserve input order, multiple outputs and a flag result together.
- [ ] **#95** Input contracts/control flow: recover missing indirect inputs and missing calls.
- [ ] **#96** Platform models/emission: represent external file I/O without semantic placeholders.
- [x] **#97** Consumer scope: verify result handling matches each exit path. Withdrawn upstream.
- [ ] **#98** Results: retain a flag result used to continue or abandon an operation.
- [x] **#99** Triage: separate consumer branch-repair errors from the original missing call input. Withdrawn upstream.
