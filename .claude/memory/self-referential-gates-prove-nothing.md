---
name: self-referential-gates-prove-nothing
description: A database scored against its own records can never fail; only a self-compiled linked binary is non-self-referential evidence for an identification column
metadata: 
  node_type: memory
  type: project
  originSessionId: 6a216fa6-e69f-4b20-b0bf-429f1307092c
  modified: 2026-08-09T06:36:59.789Z
---

**⭐ 2026-08-09 (`fba99de`).** The whole Watcom FID column had NO gate that could fail:

- `fid_detect_versions` scores each database against its **OWN** records — stale-vs-stale agrees
  perfectly, so drift is invisible.
- `fid_database_drift` proves a database **reproduces from its libraries** — says nothing about
  whether it matches a program.
- WAR2 was the only end-to-end evidence, and it is barred as a gate by the standing user rule
  (development guide / post-release validation only).

That is exactly why [[unlinked-zero-field-changes-the-decode]] survived: every check was green.

**THE FIX:** `oracle/fid/src/watprobe.c` + `tests/fid_watcom_identify.rs` — a program WE wrote,
compiled by a real Watcom 10.0a against static `clib3r`, asserting recall + precision with names
derived from the source.

**⭐ THE TRANSFERABLE PART — check the gate can FAIL before trusting it.** The first version
reused `crtprobe.c` and named the same **17 functions against the databases from BEFORE AND AFTER**
the fix. Green either way, measuring nothing. `watprobe.c` deliberately calls routines that read
STATIC TABLES (`strcspn`, `asctime`, `gmtime`, `raise`, `utoa`/`ultoa`) — the shape the fix
repaired — and scores 30 before / 38 after. Restoring the old databases turns it red with exactly
those names. Sibling of [[could-it-have-come-out-otherwise]] and
[[self-compiled-gate-measures-your-imagination]].

**Gotchas:** a 32-bit Watcom DOS exe is DOS/4GW **LE**, so the test needs `analyze_le_file` — the
default dispatch keeps a bound exe on the MZ-stub path and would identify nothing. Watcom 10.0a
has **no 64-bit integer type at all**, so `crtprobe.c` cannot compile there; do not "fix" that
source — its committed MSVC binary cannot be rebuilt without VC98, and editing it breaks the
binary/source correspondence. `setup-watcom-dosemu.sh` stages the dir holding WCC386 (`BINB`);
`WLINK.EXE` is in the sibling `BIN`, and `system dos4g` resolves via `$WATCOM/binb/wlsystem.lnk`.

Related: [[fid-port-track]], [[war2-pragmatism-over-faithfulness]], [[load-the-artifact-directly]].
