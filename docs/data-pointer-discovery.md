# Pointer-record discovery

`analysis.data-pointer-functions` is an opt-in extension. Ghidra's data-pointer analyzers
can identify or disassemble a target without creating a function there; this extension makes
that additional decision explicitly. Default analysis does not run the scan.

The source location and the target have separate requirements:

- Scan initialized memory with a read, write or execute permission. Executable memory can
  contain records, so permission alone does not classify a byte as an instruction.
- Exclude every byte of each instruction already defined in the listing. Read pointer-sized
  windows only within each remaining contiguous range of one memory block. A window cannot
  cross an instruction or block boundary. Record fields may be unaligned.
- Require the target to lie in executable memory. If it falls within an existing instruction,
  it must be that instruction's start. Decoding an operand as an independent byte stream can
  terminate successfully without establishing a legitimate entry point.
- Retain the strict `PseudoDisassembler::is_valid_subroutine` check and the existing pointer
  width, byte order, address floor and duplicate/function checks. Newly accepted entries use
  the normal function-creation and direct-call analysis cascade.

The memory and source-range rules follow pinned `AddressTableAnalyzer.java`
`removeNonSearchableMemory` (:347) and the instruction arm of `removeDefined` (:316).
The target boundary rule follows `checkTable` (:423), as already represented by mosura's
address-table analyzer. Record data remains eligible: rejecting defined structures would
exclude the isolated fields this extension was created to scan. No compiler-specific
pattern or relaxed subroutine validator is introduced.

## Source-built regression

`oracle/ground-truth/src/mixed_record_pointer.S` builds as i386 and x86-64, each with separate
code/data sections or one initialized writable/executable section. All four stripped artifacts
have five build-derived functions and no relocations. A mutable selection reaches two handlers
through isolated record fields, and one handler directly calls a further function.

There are two negative controls. A defined instruction contains an address immediate pointing
at an interior RET. A record also holds an address inside a MOV operand whose bytes decode as
NOP; RET. The latter passes the subroutine decoder; only the listing establishes that it is
not an instruction boundary. Neither address is a source function.

`pointer_record_discovery_respects_instruction_boundaries` checks the exact function set,
not just recall. Each default analysis retains the two directly reachable entries; each
option-on analysis must find all five source functions and no additional entry.

The separate-data gate first failed with six functions for five source functions. The initial
mixed-memory gate failed with only two of five. Both failures were observed before their
respective corrections. This bounds the verified claim: discovering the reported pointer
record does not validate every additional candidate in an arbitrary flat image. The scan
continues to be an explicit extension, with source-owned exact-set gates and unchanged defaults.
