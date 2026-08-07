# oracle/capture DecoderError catch (oraclefix1, 2026-07-18)

**Latent-bug fix, uncommitted in tree (lead gates commit).** `oracle/capture.cc` +17 lines.

## The bug
`ghidra::DecoderError` (`xml.hh:297`) is a plain struct that does NOT derive from
`LowlevelError` (`error.hh:74`). capture.cc's four try blocks only did
`catch(LowlevelError&)`, so ANY XML/marshal decode failure escaped → `terminate` /
Aborted (exit 134). Reproduce: feed malformed XML —
`oracle/capture $GHIDRA_SRC /tmp/malformed.xml --c` → `terminate called after throwing
'ghidra::DecoderError'`. (`store.openDocument` → `xml_parse` throws DecoderError on any
parse error.)

## The fix (faithful to Ghidra's own tools)
Added `catch(DecoderError &e){ cerr<<...<<e.explain; return 1; }` BEFORE each existing
`catch(LowlevelError&)` in all four blocks (openDocument / arch init / --ir / --c),
mirroring `testfunction.cc:160` + `consolemain.cc:89` which catch DecoderError alongside
LowlevelError (both have `.explain`). Now a bad XML surfaces its real message (`open
<file>: syntax error`) and clean-exits 1 instead of aborting.

## IMPORTANT: the "broken on every fixture" premise did NOT reproduce on HEAD
The task diagnosis (explicit1) said `--ir`/`--c` abort with DecoderError on every fixture.
FALSE on HEAD via the CORRECT invocation. The real harness (`oraclecache.rs:44`) calls
`capture <GHIDRA_SRC-root> <fixture> <args>` — first arg is the **ghidra source ROOT dir**,
NOT a `.sla` file. Passing the `.sla` directly (as the task's step-1 example did) gives a
*caught* `LowlevelError: No sleigh specification for x86:LE:64:default` (exit 1), never a
terminate. Swept all 79 datatests: 76 produce `--c`+`--ir` output, 3 give a clean caught
`LowlevelError` (multiret/sbyte/switchreturn: "Bytes not mapped" — first-bytechunk-offset
entry mismatch, unrelated), **0 terminates**. The ONLY terminate path is malformed XML —
which the fix now handles. So the fix is genuine robustness; the workflow was not actually
down.

## Verified post-fix (rebuilt with setup-oracle.sh flags)
- malformed XML → clean `syntax error` exit 1 (was abort 134).
- modulo/switchloop/longdouble `--c` byte-EXACT to `build/oracle-cache/`.
- multi-arch works: gp (MIPS:BE:32), ccmp (AARCH64:LE:64).
- full suite **507/0**, corpus **avg 0.9480, 57/60 @65ffa1f** (rebuild changed binary mtime
  → cache self-invalidated → re-captured identical → score unchanged).

## Bonus (switchloop phi order) — NOT obtainable with this tool
switchloop final IR (`--ir -` = run to completion) has **0 MULTIEQUAL**; even at the
`stackstall` break the phis are already collapsed by the in-mainloop `ActionDeadCode`. The
loop-carried variable resolves to `u0x1000006e:4` (defined at loop header 0x00100027; used
`EAX = u0x1000006e:4 + #0x1`). capture.cc's `setBreakPoint(break_start, name)` can't
uniquely target the post-`ActionHeritage`/pre-deadcode window because action names ("base",
"protorecovery", …) aren't unique (coreaction.cc:5490+). To expose phi-input order for the
processMultiplier campaign, capture.cc would need break_end or an occurrence-indexed break —
a separate small follow-up.
