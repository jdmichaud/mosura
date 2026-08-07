---
name: corpus-oracle-ignores-prototypes
description: "RESOLVED: the corpus oracle (oracle/capture) was built with the wrong ABI flags (missing -DCPUI_DEBUG) and silently mis-decompiled vs canonical Ghidra; fixed in setup-oracle.sh (commit d5ae08d)."
metadata:
  node_type: memory
  type: project
  originSessionId: c0fe6b35-0fb2-4ed2-90d8-ec93de63680c
---

**ROOT CAUSE (pinned + FIXED, commit `d5ae08d`).** `oracle/capture` was compiled WITHOUT the
debug switches `libdecomp_dbg.a` is built with — Ghidra Makefile `COMMANDLINE_DEBUG =
-DCPUI_DEBUG -D__TERMINAL__` (CPUI_DEBUG = master switch → OPACTION_DEBUG etc.). Those switches
add INSTANCE members to core classes (Funcdata/PcodeOp/Action/Architecture…), so capture's
struct layouts were SMALLER than the library's = a silent ABI/field-offset mismatch (no crash)
that corrupted decompilation. The fix: build capture with `-DCPUI_DEBUG -D__TERMINAL__`
(updated `scripts/setup-oracle.sh` + a header comment in `oracle/capture.cc`). The binary is
gitignored, so rebuild via setup-oracle.sh. **LESSON: any tool linking libdecomp_dbg.a MUST
match its compile flags or it mis-behaves invisibly.**

Effect: capture's reference C now equals canonical Ghidra (`decomp_dbg`). divopt was the
clearest case — capture had emitted `xunknown8 func(xunknown8 param_1)` where decomp_dbg and
mosura emit `uint8 *param_1` + `param_1[i]`, so the gauge wrongly scored mosura's faithful
pointer/array output as a regression. With the fix, capture's C is byte-identical to
decomp_dbg's for divopt/modulo/indproto/pointerrel (only external-symbol *names* differ — e.g.
`puts` vs `func_0x1005e0` because capture doesn't `readLoaderSymbols` — which ccompare erases).

**New trustworthy corpus baseline** (`cargo test -q -p mosura --test decompile_corpus --
--nocapture`): avg **0.7792, >=0.70: 45/60** (was 0.7665 / 43). divopt **0.614 → 0.940**;
modulo unchanged. Full mosura suite stays **119 green** (no Rust source touched). See also
[[direction-faithful-port]]. The earlier "make divopt xunknown8" framing (Task #10) was
anti-faithful and is closed: mosura already matched canonical Ghidra; the oracle was the bug.

How the bug was pinned: TYPEPROP_DEBUG is compiled into the lib, so building capture with
`-DTYPEPROP_DEBUG -DOPACTION_DEBUG` + `TypeFactory::propagatedbg_on=true` +
`conf->setDebugStream(&cerr)` dumps the per-edge data-type propagation trace; the debug build
also *fixed the ABI*, which is what revealed the cause. `decomp_dbg` (in the ghidra cpp dir,
`SLEIGHHOME=<ghidra>`): `load test file <fx>.xml; execute test command 1-N` runs the datatest
script (typed prototypes → array output); `load addr <off> <name>; decompile; print C` is the
raw decompile. NOTE: `decomp_dbg` is built from individual objects, so a single-file rebuild of
`consolemain.cc` against the archive segfaults — don't try to add commands to it that way.
