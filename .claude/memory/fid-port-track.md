---
name: fid-port-track
description: "New track (user-opened 2026-07-23) — faithful port of Ghidra's FID function-fingerprinting; plan in docs/fid-port-plan.md"
metadata: 
  node_type: memory
  type: project
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-07-23T15:49:46.980Z
---

**Track: port Ghidra's FID (Function ID)** — identify statically-linked stdlib functions in
stripped binaries (Ghidra FID / IDA FLIRT equivalent) across all supported compiler runtimes.
User-opened 2026-07-23: "mosura, like Ghidra, should be able to identify standard functions from
various … supported compiler runtimes. We should not invent anything, Ghidra already does it well,
we just need to port it." → **faithful port**, byte-identical hashes.

Full plan (staged, `ghidra:line`-cited algorithm spec for all 3 pillars, constants, oracle
strategy) = **`docs/fid-port-plan.md`** (`7a0cb4c`). Source = `Ghidra/Features/FunctionID/`
(~9.2 kLOC) in the checkout.

**Distinct from `codegen_fingerprint`/`compiler_version`** — those ID the whole-binary COMPILER;
FID IDs an individual FUNCTION (body-hash → signature-DB lookup). Same word, opposite granularity.

**CRITICAL PATH = Stage 0 (cross-lane):** FID's hash masks operands using SLEIGH's
`getInstructionMask`/`getOperandValueMask`/`getOpObjects`/`getOperandType` — data mosura's engine
HAS (`engine.rs` `Pattern.mask` + constructor tree, used to render `body`) but does NOT surface on
`sleigh::Instruction` (`sleigh/mod.rs:26` = only address/bytes/mnemonic/body/pcode/ops). p-code is
NOT a faithful substitute (masking keys off the SLEIGH constructor pattern, not lifted semantics).
`sleigh/` is the **decompiler agent's** lane → needs a small additive read-only accessor
(coordination) OR in-lane derivation from engine internals if reachable. Nothing downstream is
byte-faithful until this is green. Resolve with user + decompiler agent before Stage 1.

**Key faithful facts** (so I don't re-study): digest = FNV-1a 64 (basis 0xcbf29ce484222325, prime
0x100000001b3, wrapping, ints fed big-endian, digestLong=raw state — NOT SHA); full hash masks all
operands (scalar placeholder 0xfeeddead, registers `(off+7654321)*98777`), specific hash folds real
small scalars (`(val+1234567)*67999`, whole-non-addr scalar or partial |val|<256, not on a reloc);
extent = body instructions ascending, min 4 code units; codeUnitSize = count − callCount; x86 NOP
skipper (17 patterns). Match: full-hash candidates only, score = codeUnitSize(floor 24 if autoPass)
+ 0.67·specificAddSize + Σchild/parent-relation code-units, reject <14.6, multi-name gate 30. DB:
5-table schema (functions/libraries/strings/superior+inferior relations), relations = empty-schema
tables keyed by hash-smash (`callerKey*FNV_PRIME ^ calleeFullHash`). **Deviation:** mosura-native
store of the schema, NOT Ghidra's `.fidb` BufferFile format (zero fidelity lost; Ghidra ships DBs
only for Windows VS 1998–2015, none for our runtimes, none even in the checkout). Signature DBs for
our runtimes built via the now-wired compilers (Watcom via setup-watcom-dosemu.sh, gcc crosses,
VC/Borland) — self-compiled ground truth. Payoff: Watcom clib (WAR2) + one gcc/glibc first.

Status: PLAN ONLY, not started; awaiting user GO + Stage-0 coordination. See
[[war2-issues-become-source-tests]], [[analysis-unblocked-sweep-0723]].
