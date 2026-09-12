# Bob's issue tracker

Updated 2026-09-12. Owner: Alice. Working branch: `fix/indirect-call-contracts`.

This tracks mosura work against Bob's numbered defect ledger. The latest local ledger has
**99 numbered entries** (counted from its numbered headings); the earlier handoff covered 85.
A downstream repair is not a mosura fix. Each numbered report stays open until its current
mosura behavior is checked, or triage establishes that it belongs solely to the downstream project.
The checklist below records completed work; the register below preserves every report ID.

## Current package: indirect-call inputs

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
- [ ] Record Bob’s validation and close only the reports it resolves.

The declaration option is limited to decompilation. Compiler lowering of custom pointer
conventions, full typed-pointer propagation, outputs and clobbers remain open. Restoring inputs
alone does not close the entire indirect-call class.

## Completed triage

- [x] **#88: transparent-byte comparison.** The unmodified raw emission supplied with the
  report uses `char *` and compares its byte to `-1`. The current CLI does the same. The
  `(uint8_t)0xff` comparison quoted by the report is absent from both raw outputs, so the
  signed/unsigned mismatch was introduced downstream. No mosura printer change is indicated.

## Next work packages

- [ ] **Shared global storage (#4; distinguish downstream #26 and naming #27).** Reproduce
  overlapping reads/writes in self-compiled source; implement compilable views in the emitter/TU
  layer while preserving the faithful printer.
- [ ] **Flag results (#13, #23, #53 and related reports).** The current CLI still drops the
  flag-only predicate in #13. Next: self-compiled caller/callee MVE and Ghidra IR comparison.
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
| #1 | `menuitem_draw_box` (0x12034) — four frame strokes emitted with no arguments | Investigating: input package; report validation pending |
| #2 | Register-named parameters that no caller ever passes | Queued |
| #3 | Indirect calls through the driver vector table lose their arguments wholesale | Investigating: input package; report validation pending |
| #4 | One address arriving as several independent C globals | Queued next: raw cross-width alias evidence received |
| #5 | Loop-carried values folded to their first iteration | Queued |
| #6 | `aa_disc_step_upper` / `aa_disc_step_lower` (0x21bd1, 0x21dad) — a value-and-flag answer emitted as an `int` | Queued |
| #7 | `menuitem_draw_box`'s siblings — the same shape, still open | Investigating: input package; report validation pending |
| #8 | `menu_mouse_poll_move_cursor` (0x11c0e) — all three results of the mouse read dropped | Queued |
| #9 | `menu_redraw_mouse_cursor` (0x11c97) — a lost argument takes its control flow with it | Investigating: input package; report validation pending |
| #10 | `draw_info_panel_frame` (0x1ccfe) — a register written as two byte halves is not followed | Queued |
| #11 | `0x45228` — a driver hook that was calling into the raw 1995 image | Investigating: input package; report validation pending |
| #12 | `cfg_read_pool_cfg` (0xde26) — the configuration file was never read at all | Queued |
| #13 | `key_is_down` (0x10251) — one function, two opposite conventions | Reproduced with current CLI; MVE pending |
| #14 | The in-game menu drew a blank box — two more lost register sets | Queued |
| #15 | `ui_poll_key` (0x12969) declared `void`, and the menu it drives read two uninitialised locals | Queued |
| #16 | `FUN_0000d934` — DOS FindFirst/FindNext as pseudo-ops, and an unbounded loop | Queued |
| #17 | `menupage_draw_title_centred` (0x11322) — the front end's title was painted somewhere else | Queued |
| #18 | `rebuild_aim_camera_frame` (0x54ea) — the cue's cosine was always zero | Queued |
| #19 | The screen was one 640x480 viewport; the original's is 640x400 with the strip in page 0 | Downstream review |
| #20 | `play_mode_frame_tick` (0x1bb9) — the aiming mouse read from parameters nobody passes | Queued |
| #21 | `draw_text_with_shadow` (0x1cce5) — the HUD's shared label painter, and 20 call sites repaired from the corpus's own comments | Queued |
| #22 | `project_point_with_clip` (0x15fa6) — three answers, none of them a C result | Queued |
| #23 | The hot-key handlers answer in the carry, and mosura emitted them `void` | Queued |
| #24 | `camera_shot_view_is_valid` (0x1796d) — the move target read from parameters no caller passes | Queued |
| #25 | The scene walker sent node kind 2 into the recursion; it is the overlay pass | Downstream review |
| #26 | One variable, two objects: the globals the placer left as C objects | Downstream review |
| #27 | A local named after the global it is loaded from: `x = (cast)x;` | Queued |
| #28 | `mouse_detect_present` (0x14450) and `mouse_init_or_warn` (0xe014) | Queued |
| #29 | The 3-D viewport was 640×480: `render_frame`'s centre eased to row 360 | Downstream review |
| #30 | The status strip: six vector calls with their registers dropped | Queued |
| #31 | The rotate's three results, read from parameters and cursors | Queued |
| #32 | Shades entered in AH: the cue's sections, the digits, the number circles | Queued |
| #33 | `menu_run_modal` (0x129da) tested the wrong register for the mouse button | Queued |
| #34 | The table-scene handler (0x1b46b) restored a display-list cursor of zero | Queued |
| #35 | Ours: the span-begin thunk ignored its argument | Downstream review |
| #36 | `page_flip_keep_span_base` (0x4576) stores the replay's pointer; the corpus restored it | Queued |
| #37 | The second hemisphere culled with the first hemisphere's normals | Queued |
| #38 | Ours: the scene walker's other seven classifiers | Downstream review |
| #39 | The in-game menu's handlers are recovered routines: the first sites | Triage |
| #40 | `menu_repaint_window` (0x127c1) painted every row in ink 0 | Queued |
| #41 | `abort_game_to_menu` (0x16aa8) answers `stc`; nothing published it | Triage |
| #42 | `yesno_box_run_modal` (0x136e4): EAX for ECX, and no body | Triage |
| #43 | The modal menu's action vector is an image code address | Triage |
| #44 | Ours: the text kerning code | Downstream review |
| #45 | `rng_seed_from_dos_clock` (0x370) took DX as a parameter no caller passes | Triage |
| #46 | `cfg_write_pool_cfg` (0xd604) never wrote | Triage |
| #47 | Video Setup (0xd934), written from the bytes | Triage |
| #48 | The pop-up window frame: four of its five glyph runs lost their positions | Queued |
| #49 | The list box painters: a bar with no registers, rows inked 0 | Triage |
| #50 | Not a defect: the left mouse button zooms | Downstream review |
| #51 | `table_screen_input_loop` (0x1dc6): the "play the shot" answer is AL = 0, unpublished | Queued |
| #52 | `camera_advance_and_recentre` (0x3883): the rotate's three results as parameters | Queued |
| #53 | `sched_pair_already_resolved` (0x11ea) answers only in the carry | Queued |
| #54 | `hud_draw_action_help_line` (0x1d79a): the computer's progress counters | Queued |
| #55 | The computer player's evaluation: four seams in the corpus | Queued |
| #56 | The four aim-search verdicts (0x66ba, 0x6741, 0x682d, 0x6861) — recovered, hand-written | Triage |
| #57 | The pocket visibility chain never rejected anything | Queued |
| #58 | The 9-ball computer player is raw emission: ported from the bytes, defects reported | Queued |
| #59 | Witness list for #58: what the emission of each computer-player unit gets wrong | Triage |
| #60 | `shot_begin_recording_with_camera_record` (0x745a) called the camera install with nothing | Queued |
| #61 | `setup_pocket_quartic` (0x1ecc0) read the root solver's carry off a double | Queued |
| #62 | `frame_boundary_service` (0x18d3) pushed its keys with no scan code | Queued |
| #63 | The re-spot chain in the verified corpus: a stale carry and a lost EBP result | Queued |
| #64 | `menu_activate_item` (0x11379) never waited for the mouse button to come up | Queued |
| #65 | `snd_start_effect_voice` (0x89d0) spliced the voice with the wrong slot, and the sequencer | Queued |
| #66 | `sb_stop_playback` (0x5bd5) polled port 0x0C, and the second sound effect was the last | Queued |
| #67 | `ui_patch_menu_then_dispatch_by_game` (0xba1d) stops before it lights anything | Queued |
| #68 | The pop-up handed a kind-4 action vector the row index, not the entry id | Queued |
| #69 | The pop-up threw the mouse to the top of the screen after a settings click | Queued |
| #70 | The pop-up leaves its cursor drawn, and the obvious fix stamps the menu on the table | Queued |
| #71 | The ball-pair collision response answers in the carry, and every ball-on-ball sound was lost | Queued |
| #72 | `present_frame` (0xbdd) has three arms and this build kept only the middle one | Downstream review |
| #73 | Save Game and Load Game: an unreachable list builder, scrambled arguments and a dropped EAX | Queued |
| #74 | The R and T keys test a branch that can never be taken | Queued |
| #75 | Above 640 the 2-D layer used the 640 font and doubled where it should triple | Downstream review |
| #76 | "Configure the game" left the screen on a page nothing shows | Downstream review |
| #77 | Two cursors, one saved cover | Queued |
| #78 | The front end's Configure page painted the game's furniture over the main menu | Downstream review |
| #79 | The projection centre did not follow a mode change | Downstream review |
| #80 | The tracking lines were drawn between two pointers | Queued |
| #81 | A mode set left the draw page's index and its pointer naming different pages | Downstream review |
| #82 | Two cursors again: the Configure tail drew a pointer that was about to be drawn anyway | Downstream review |
| #83 | The status strip a game drew stayed on screen behind the front end | Downstream review |
| #84 | The cursor cover did not say whether it still held anything (latent) | Downstream review |
| #85 | Drawing the cursor twice with no erase between poisons its own cover | Downstream review |
| #86 | A driver-table call went out with three of its seven arguments undefined | Queued: seven-register indirect input contract |
| #87 | The PREFERENCES page did nothing, because its action routine was never decompiled | Reproduced: opt-in scan skips the native image’s mixed code/data block; MVE pending |
| #88 | Every transparent pixel of every cached sprite was painted (the 320x240 ball rack) | Closed triage: supplied raw and current CLI both compare signed byte to -1; downstream rewrite |
| #89 | Mouse gain grew with the frame time, so the pointer's speed changed with the resolution | Downstream review: shim event accumulation |
| #90 | The play tick stored its own parameters where the mouse's deltas belonged | Queued: multiple result registers |
| #91 | The PREFERENCES audit (not a defect - a proof) | Downstream review |
| #92 | Every click in PREFERENCES blanked the window it was drawn in | Queued: indirect input order and widths |
| #93 | The page clear wiped one page of four, so a shrunken view kept the old screen around it | Downstream review: shim clears wrong memory span |
| #94 | The line clipper read its segment in the wrong register order, then drew it unclipped | Queued: register order plus multiple outputs and carry |
| #95 | The line editor drew neither its box nor anything typed into it | Queued: indirect inputs and missing-call census |
| #96 | Save Game never wrote its file, and Load Game never read one | Queued: DOS interrupt modeling and emitter placeholders |
| #97 | Load Game read the file and answered as if nothing had happened | Downstream review: repair pass pairs exits by position |
| #98 | The line editor abandoned itself or not on whatever the stack held | Queued: carry-result channel |
| #99 | Load Game with nothing saved gave every game the trick-shot message | Downstream review: linear repair of a branched argument; original missing input remains queued |
