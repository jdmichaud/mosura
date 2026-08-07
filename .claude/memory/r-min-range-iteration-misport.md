---
name: r-min-range-iteration-misport
description: Analyzers iterating set.ranges() and taking only r.min silently drop every adjacent address — Ghidra iterates ADDRESSES.
metadata: 
  node_type: memory
  type: project
  originSessionId: df001909-493d-4f50-92ac-53ef8ca6337d
  modified: 2026-08-06T18:19:26.556Z
---

⭐ Measured 2026-08-06. An `AddressSet` coalesces adjacent addresses into one range, so
`for r in set.ranges() { … r.min … }` processes only the FIRST of any run of adjacent entries.
`wprobe.watcom-x86-32` has three functions at three consecutive addresses (`08048110 sink_`,
`08048111 __CHK`, `08048112 p_leaf_`); `p_leaf_` was dropped and its 46-byte body never entered the
listing, **even though `main_` calls it directly** (`0804856c: e8 a1 fb ff ff  call 0x8048112`).

Ghidra iterates addresses: `CreateFunctionCmd.java:158` `origEntries.getAddresses(true)`.
`DisassembleCommand.java:235-266` drains each range one address at a time, and **:262 branches on
`addrsLeft <= 4`** — a SHORT range contributes every address as a seed, a LONG one is
flow-disassembled from its minimum and the decoded extent deleted.

⚠️ **Do not "fix" this by seeding every address of every range.** Measured: that turns the war2 MZ
over-decode bound from 8 to 53. The `<= 4` cut is the line that governs it, and it is Ghidra's.

Sites found: `Disassembler::added` and `FunctionCreator::added` (`analyzers/mod.rs`) — fixed;
**still open**: `ConstantPropagationAnalyzer` (`analyzers/mod.rs:439`), `DecompilerSwitchAnalyzer`
(`switch.rs:46`), `SharedReturnAnalyzer` (`shared_return.rs:342`). The last two treat `r.min` as a
function ENTRY, so they need an "is a function entry" guard, not a blind widening.

**How to apply:** grep `set.ranges()` in any analyzer before trusting it; ask whether the set is a
set of ADDRESSES (iterate all) or genuinely of extents. See [[command-vs-notification-channel]].
