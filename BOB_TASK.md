# Bob's tasks

Updated 2026-09-12. Owner: Alice.

Checked means the stated scope is fixed and validated, or confirmed to be a downstream issue.
Unchecked means still open, including reports awaiting triage. The list contains all 99 reports
in Bob's current ledger. See [the detailed tracker](docs/bob-issue-tracker.md) for evidence and
commits. Update both trackers when an item's status changes.

Completed: #1's explicit decompilation inputs, validated by Bob; #88's downstream triage,
confirmed by Bob. Custom-convention compiler lowering, outputs and clobbers remain open.
Next: reproduce #13's flag result in a self-compiled MVE and compare Ghidra's IR.

- [x] **#1** Restore the box painter's five indirect-call inputs through explicit declarations.
- [ ] **#2** Remove register parameters that callers never supply.
- [ ] **#3** Restore inputs across the remaining driver-vector calls.
- [ ] **#4** Preserve shared storage across differently typed globals at one address.
- [ ] **#5** Preserve values carried across loop iterations.
- [ ] **#6** Preserve both the value and flag results of disc stepping.
- [ ] **#7** Restore indirect-call inputs in the box painter's sibling routines.
- [ ] **#8** Preserve all three mouse-read results.
- [ ] **#9** Restore cursor-redraw inputs and dependent control flow.
- [ ] **#10** Track a register assembled from two byte writes.
- [ ] **#11** Resolve the driver hook's contract and raw-image call.
- [ ] **#12** Recover configuration-file reading.
- [ ] **#13** Preserve the key predicate's flag result and caller interpretation.
- [ ] **#14** Restore the in-game menu's missing register inputs.
- [ ] **#15** Recover the key poll's outputs and its caller's locals.
- [ ] **#16** Model DOS directory searches and their loop exits.
- [ ] **#17** Restore centered-title positioning arguments.
- [ ] **#18** Preserve the aim-camera rebuild's cosine result.
- [ ] **#19** Triage the downstream viewport and status-strip dimensions.
- [ ] **#20** Recover mouse results used by the play-frame tick.
- [ ] **#21** Restore the shared text painter's call contracts.
- [ ] **#22** Preserve all projection and clipping results.
- [ ] **#23** Preserve carry results from hot-key handlers.
- [ ] **#24** Recover the camera-validation routine's actual inputs.
- [ ] **#25** Triage downstream scene-node classification.
- [ ] **#26** Confirm downstream placement preserves one object per storage location.
- [ ] **#27** Prevent locals from shadowing globals in self-assignments.
- [ ] **#28** Recover mouse detection and initialization contracts.
- [ ] **#29** Triage the downstream render viewport center.
- [ ] **#30** Restore the status strip's six vector-call inputs.
- [ ] **#31** Preserve the rotation routine's three register results.
- [ ] **#32** Recover shade inputs passed in AH.
- [ ] **#33** Recover the modal menu's correct mouse-button result.
- [ ] **#34** Preserve the table-scene handler's display-list cursor.
- [ ] **#35** Confirm the downstream span-begin thunk forwards its argument.
- [ ] **#36** Preserve the span-base pointer across page flipping.
- [ ] **#37** Preserve distinct normals for the second hemisphere.
- [ ] **#38** Confirm the downstream scene walker's remaining classifications.
- [ ] **#39** Triage recovered in-game menu handlers.
- [ ] **#40** Preserve row-dependent ink in menu repaint loops.
- [ ] **#41** Preserve the abort-to-menu routine's carry result.
- [ ] **#42** Recover the yes/no modal's body and correct input register.
- [ ] **#43** Recover the modal menu's action-vector call contract.
- [ ] **#44** Confirm the downstream text-kerning repair.
- [ ] **#45** Recover the DOS clock's DX result used for RNG seeding.
- [ ] **#46** Recover configuration-file writing.
- [ ] **#47** Triage video-setup reconstruction against the original bytes.
- [ ] **#48** Restore popup-frame glyph positions.
- [ ] **#49** Restore list-box painter inputs and row ink.
- [ ] **#50** Confirm left-button zoom is intended behavior.
- [ ] **#51** Preserve the table-input loop's AL result.
- [ ] **#52** Preserve rotation outputs used by camera recentering.
- [ ] **#53** Preserve the scheduler predicate's carry result.
- [ ] **#54** Recover the HUD's computer-progress counters.
- [ ] **#55** Audit the computer evaluation's four reported contract gaps.
- [ ] **#56** Triage the four reconstructed aim-search verdicts.
- [ ] **#57** Recover rejection results in the pocket-visibility chain.
- [ ] **#58** Recover the reported nine-ball computer-player behavior.
- [ ] **#59** Validate each nine-ball witness and attribute its defect.
- [ ] **#60** Restore camera-install arguments during shot recording.
- [ ] **#61** Preserve the root solver's carry result.
- [ ] **#62** Restore scan-code arguments in frame-boundary key handling.
- [ ] **#63** Preserve carry and EBP results through the re-spot chain.
- [ ] **#64** Restore the mouse-release wait during menu activation.
- [ ] **#65** Recover sound-voice slot selection and sequencer contracts.
- [ ] **#66** Preserve the sound-stop polling port and loop behavior.
- [ ] **#67** Recover the menu patcher's missing dispatch behavior.
- [ ] **#68** Recover the popup action's entry-ID argument.
- [ ] **#69** Preserve mouse position after popup setting changes.
- [ ] **#70** Recover popup cursor cleanup and menu repaint behavior.
- [ ] **#71** Preserve the ball-collision carry result used for sound.
- [ ] **#72** Triage downstream loss of frame-presentation branches.
- [ ] **#73** Recover save/load list discovery, arguments and EAX results.
- [ ] **#74** Recover reachable R/T key handling.
- [ ] **#75** Triage downstream font selection and scaling above 640 pixels.
- [ ] **#76** Triage downstream display-page selection during configuration.
- [ ] **#77** Preserve separate saved backgrounds for two cursors.
- [ ] **#78** Triage downstream Configure-page repainting.
- [ ] **#79** Triage downstream projection-center updates after mode changes.
- [ ] **#80** Recover tracking-line coordinate arguments.
- [ ] **#81** Triage downstream draw-page index and pointer synchronization.
- [ ] **#82** Triage duplicate downstream cursor drawing after Configure.
- [ ] **#83** Triage downstream status-strip cleanup on return to the front end.
- [ ] **#84** Triage downstream cursor-cover validity tracking.
- [ ] **#85** Triage downstream cursor-cover corruption after duplicate drawing.
- [ ] **#86** Restore the driver call's seven-register input contract.
- [ ] **#87** Discover the Preferences action in a mixed code/data block.
- [x] **#88** Confirm the transparent-byte comparison defect was introduced downstream.
- [ ] **#89** Triage downstream mouse-event accumulation and gain.
- [ ] **#90** Preserve mouse-delta results consumed by the play tick.
- [ ] **#91** Review the Preferences audit's non-defect classification.
- [ ] **#92** Recover input order and widths for Preferences repainting.
- [ ] **#93** Triage the downstream page-clear memory span.
- [ ] **#94** Recover line-clipper input order, multiple outputs and carry.
- [ ] **#95** Restore line-editor call inputs and missing calls.
- [ ] **#96** Recover DOS file I/O and replace unsupported emitter placeholders.
- [ ] **#97** Triage downstream load-result handling across exits.
- [ ] **#98** Preserve the line editor's carry result.
- [ ] **#99** Triage downstream branched-argument repair and restore missing inputs.
