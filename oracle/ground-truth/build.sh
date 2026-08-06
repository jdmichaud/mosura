#!/usr/bin/env bash
#
# build.sh — build the cross-compiler self-compiled GROUND-TRUTH corpus (task #3).
#
# For each (program × compiler × arch) it: (1) compiles an UNSTRIPPED binary, (2) DERIVES the
# ground-truth facts from the build artifact itself — the toolchain's OWN `nm`/`objdump` (ELF) or
# linker map + relocated listing (z80) — never hand-authored, never Ghidra — into a diffable
# `.truth` file, then (3) STRIPS the binary to the analyzed artifact. The stripped binary + the
# `.truth` file are committed (the test surface); this script + the toolchains are dev-oracle
# (regeneration only) — docs/dependencies.md. `tests/ground_truth_parity.rs` checks mosura's
# analysis of the stripped binary against the truth (0 spurious + recall + switch dispatch).
#
# The truth is the ORACLE: it comes from the source/build we own, NOT from Ghidra (often wrong).
#
# Matrix (installed toolchains). ABSENT (documented gaps, never faked): clang, MSVC.
#   gcc      x86-64   x86:LE:64:default      (host)
#   gcc      aarch64  AARCH64:LE:64:v8A      (aarch64-linux-gnu-)
#   gcc      riscv64  RISCV:LE:64:default    (riscv64-linux-gnu-)
#   gcc      m68k     68000:BE:32:Coldfire   (m68k-linux-gnu-, big-endian)
#   sdcc     z80      z80:LE:16:default      (CP/M .COM; truth from sdcc map + relocated listing)
#   wcc386   x86-32   x86:LE:32:default      (Open Watcom -> freestanding ELF32 i386)
set -euo pipefail
cd "$(dirname "$0")"

log() { printf '\033[1;34m[gt]\033[0m %s\n' "$*"; }
have() { command -v "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------------------------
# ELF truth derivation (gcc x86-64/aarch64/riscv64/m68k + Watcom x86-32). Functions from the
# symbol table (`nm`), the switch dispatch from indirect jumps (`objdump`), the entry from the
# ELF header. All from the build artifact, not Ghidra. Handles both `nm -S` column shapes
# (gcc emits a size column; Watcom emits none) and every arch's indirect-jump mnemonic.
#   $1 unstripped binary  $2 program  $3 compiler  $4 arch  $5 mosura-lang  $6 tool prefix
derive_truth_elf() {
  local bin="$1" prog="$2" cc="$3" arch="$4" lang="$5" pfx="${6:-}"
  local nm="${pfx}nm" objdump="${pfx}objdump"
  local truth="$prog.$cc-$arch.truth"
  {
    echo "# mosura-ground-truth v1 program=$prog compiler=$cc arch=$arch lang=$lang"
    echo "# derived-from=$(basename "$bin") via=nm+objdump (build artifact, NOT Ghidra)"
    echo "compiler $cc"
    local entry
    entry=$("$objdump" -f "$bin" | awk '/start address/ {print $NF}')
    echo "entry ${entry#0x}"
    # Functions: defined text symbols (t/T/w/W) that lie INSIDE an executable section. The
    # in-section test drops linker-script boundary markers (`__bss_start`/`_edata`/`_end`), which
    # ld places at the data/bss boundary but binds to the .text section index so nm mistypes them
    # `T`. `nm -S` gives `addr [size] type name` — the size column is present (gcc) or absent
    # (Watcom emits no sizes), so the type field is detected by position. Hex math (which mawk
    # cannot do) is in python; exec ranges come from objdump -h CODE sections.
    #
    # Each `func` line carries a 4th field, its REACHABILITY CLASS, derived here and never
    # hand-written:
    #   code     — the symbol's address appears somewhere in the disassembly of an executable
    #              section (a call/jump target, or any operand mentioning it). This is the
    #              population `ground_truth_parity`'s recall assertion covers.
    #   dataptr  — the address appears NOWHERE in code, and DOES appear as a stored
    #              pointer-sized word inside a non-executable ALLOC section. The function is
    #              reachable only through a function pointer in data.
    # The distinction is the ASSERTION'S OWN CONTRACT, not an exception: a `dataptr` symbol is
    # by construction not call-reachable, and Ghidra deliberately creates no function at such a
    # target (AddressTableAnalyzer.java:281,294 "For Now, Never make functions from address
    # tables"; OperandReferenceAnalyzer.java:617 "don't ever create functions from pointed to
    # code"; DataOperandReferenceAnalyzer.java:39 "don't ever create a function from a data
    # pointer"). The code-mention test deliberately OVER-approximates (a plain immediate equal
    # to the address counts): over-approximation keeps a symbol IN the recall set, which is the
    # safe direction — it can never weaken a gate. Word size and endianness come from the ELF
    # header's EI_CLASS/EI_DATA, so this stays arch-neutral.
    # Truth files generated before this field exist without it; the test defaults them to `code`,
    # i.e. exactly the previous behaviour.
    local exec_ranges data_ranges code_refs
    exec_ranges=$("$objdump" -h "$bin" | awk '/^[ ]+[0-9]+ / { name=$2; sz=$3; vma=$4; getline fl; if (fl ~ /CODE/) print vma, sz }')
    data_ranges=$("$objdump" -h "$bin" | awk '/^[ ]+[0-9]+ / { sz=$3; vma=$4; off=$6; getline fl; if (fl ~ /ALLOC/ && fl ~ /CONTENTS/ && fl !~ /CODE/) print vma, sz, off }')
    code_refs=$("$objdump" -d "$bin" | sed -n 's/^[ ]*[0-9a-f]*:\t[^\t]*\t//p')
    "$nm" -S --defined-only "$bin" | GT_EXEC_RANGES="$exec_ranges" GT_DATA_RANGES="$data_ranges" \
        GT_CODE_REFS="$code_refs" GT_BIN="$bin" python3 -c '
import os, re, sys
ranges = []
for ln in os.environ.get("GT_EXEC_RANGES", "").splitlines():
    p = ln.split()
    if len(p) == 2:
        v = int(p[0], 16); s = int(p[1], 16); ranges.append((v, v + s))

# Every hex token in the operand column of the disassembly: the over-approximate "mentioned in
# code" set (call/jump targets, pc-relative annotations, and plain immediates alike).
mentioned = set()
for tok in re.findall(r"\b(?:0x)?([0-9a-f]{4,16})\b", os.environ.get("GT_CODE_REFS", "")):
    try:
        mentioned.add(int(tok, 16))
    except ValueError:
        pass

# Every pointer-sized word stored in a non-executable ALLOC section, read straight out of the
# file at the section`s file offset. EI_CLASS/EI_DATA give the word size and byte order.
stored = set()
try:
    blob = open(os.environ["GT_BIN"], "rb").read()
    psize = 8 if blob[4] == 2 else 4
    order = "big" if blob[5] == 2 else "little"
    for ln in os.environ.get("GT_DATA_RANGES", "").splitlines():
        p = ln.split()
        if len(p) != 3:
            continue
        vma = int(p[0], 16); size = int(p[1], 16); off = int(p[2], 16)
        for i in range(0, max(0, size - psize + 1)):
            w = int.from_bytes(blob[off + i:off + i + psize], order)
            if w:
                stored.add(w)
except (OSError, IndexError, KeyError):
    pass

out = []
for ln in sys.stdin:
    f = ln.split()
    if len(f) >= 3 and len(f[1]) == 1 and f[1].isalpha():
        typ, addr_s, name, size = f[1], f[0], f[2], "0"
    elif len(f) >= 4 and len(f[2]) == 1 and f[2].isalpha():
        typ, addr_s, name, size = f[2], f[0], f[3], f[1]
    else:
        continue
    addr = int(addr_s, 16)
    if typ.lower() in ("t", "w") and any(a <= addr < b for a, b in ranges):
        cls = "dataptr" if (addr not in mentioned and addr in stored) else "code"
        out.append("func %s %s %s %s" % (addr_s, size, name, cls))
print("\n".join(sorted(out)))'
    # Switch dispatches: indirect jumps. Union of every matrix arch`s mnemonic (all in the
    # objdump mnemonic column, preceded by a tab): x86 `jmp *`, RISC-V `jr`, AArch64 `br`,
    # m68k register-indexed/indirect `jmp` (a plain `jmp 0x..` or pc-relative `jmp %pc@(lbl)`
    # has no address/data register operand, so it is excluded).
    "$objdump" -d "$bin" | awk '
      /\tjmp[ \t]+\*/ ||
      /\tjr[ \t]/ ||
      /\tbr[ \t]/ ||
      (/\tjmp[ \t]/ && /%[ad][0-9]/) {
        a=$1; gsub(/:/,"",a); printf "switch %s\n", a
      }' | sort -u
  } > "$truth"
  log "  derived $truth ($(grep -c '^func ' "$truth") funcs, $(grep -c '^switch ' "$truth") switch)"
}

# Build one gcc/Watcom ELF cell: compile unstripped, derive truth, strip.
#   $1 program  $2 compiler-tag  $3 arch-tag  $4 mosura-lang  $5 compiler cmd  $6 tool prefix
build_elf() {
  local prog="$1" cc="$2" arch="$3" lang="$4" cmd="$5" pfx="${6:-}"
  local unstripped="$prog.$cc-$arch.unstripped" stripped="$prog.$cc-$arch"
  log "$prog [$cc/$arch]"
  # shellcheck disable=SC2086
  $cmd -o "$unstripped" "src/$prog.c"
  derive_truth_elf "$unstripped" "$prog" "$cc" "$arch" "$lang" "$pfx"
  "${pfx}strip" -o "$stripped" "$unstripped"
  rm -f "$unstripped"
}

# ---------------------------------------------------------------------------------------------
# --- gcc columns: x86-64 (host) + aarch64/riscv64/m68k (cross). One freestanding recipe, one
#     arch-neutral source per program; the per-arch process-exit shim is src/shim.h. -O2 so the
#     dense switches become jump tables. ------------------------------------------------------
GCC_FLAGS="-nostdlib -static -no-pie -O2 -ffreestanding -fno-asynchronous-unwind-tables"
# Core (A1) + construct-stressing (A7 bug-hunt): recursion, tail calls, sparse switch, computed
# goto, struct-by-value/return, deep call chain, byte/string loops, float/double.
ELF_PROGS_ALL="arith dispatch tables strdata fnptr recursion tailcall sparseswitch compgoto structval deepchain strloop floats"
# A8 bug-hunt round 2 — HARDER constructs, built on the DECOMPILER-validated 64-bit arches only
# (x86-64/aarch64/riscv64), so a decompiler divergence there is a genuine port bug, not an
# arch-support gap: varargs, bitfields+union, 64-bit arithmetic, irreducible CFG, nested loops,
# switch fall-through, pointer/array arithmetic.
ELF_PROGS_A8="varargs bitfields arith64 irreducible nestedloop fallthrough ptrarith"

# x86-64 (host gcc)
for prog in $ELF_PROGS_ALL $ELF_PROGS_A8; do
  build_elf "$prog" gcc x86-64 "x86:LE:64:default" "gcc $GCC_FLAGS" ""
done

# noret: the ONE dynamically-linked binary in the corpus, and the only thing that makes
# `analyzers/noreturn.rs` run at all. That analyzer picks its name list off the memory map and
# returns early unless a `.dynsym`, `.plt` or `EXTERNAL` block exists — and every other artifact
# here is freestanding (`-nostdlib -static`, `option nodefaultlib`) or a bare LE image, so
# `noreturn_functions` is EMPTY on all of them and the analyzer had zero coverage anywhere.
# Hence `-nostartfiles` and NO `-static`: `abort` must arrive as a real .dynsym/.plt import.
# Everything else matches the freestanding recipe (own `_start`, no libc startup).
# See src/noret.c for the four properties the program depends on.
build_elf noret gcc x86-64 "x86:LE:64:default" \
  "gcc -nostartfiles -no-pie -O2 -ffreestanding -fno-asynchronous-unwind-tables" ""

# aarch64 / riscv64: full program set (both fully recover under the standard ELF pipeline).
if have aarch64-linux-gnu-gcc; then
  for prog in $ELF_PROGS_ALL $ELF_PROGS_A8; do
    build_elf "$prog" gcc aarch64 "AARCH64:LE:64:v8A" "aarch64-linux-gnu-gcc $GCC_FLAGS" "aarch64-linux-gnu-"
  done
else
  log "SKIP aarch64 — aarch64-linux-gnu-gcc absent (documented gap)"
fi
if have riscv64-linux-gnu-gcc; then
  for prog in $ELF_PROGS_ALL $ELF_PROGS_A8; do
    build_elf "$prog" gcc riscv64 "RISCV:LE:64:default" "riscv64-linux-gnu-gcc $GCC_FLAGS" "riscv64-linux-gnu-"
  done
else
  log "SKIP riscv64 — riscv64-linux-gnu-gcc absent (documented gap)"
fi

# m68k: full program set. gcc -O2 on m68k hoists a repeated/loop call target's address into an
# address register and calls it register-indirect (`lea %pc@(fn),%aN; jsr %aN@`); the constant
# propagator resolves that constant target and the analyzer now creates a function at the
# resolved COMPUTED_CALL destination (Ghidra ConstantPropagationAnalyzer parity — see
# symbolic.rs / docs/ground-truth-corpus.md), so strdata/fnptr recover fully on m68k too.
if have m68k-linux-gnu-gcc; then
  for prog in $ELF_PROGS_ALL; do
    build_elf "$prog" gcc m68k "68000:BE:32:Coldfire" "m68k-linux-gnu-gcc $GCC_FLAGS" "m68k-linux-gnu-"
  done
else
  log "SKIP m68k — m68k-linux-gnu-gcc absent (documented gap)"
fi

# ---------------------------------------------------------------------------------------------
# --- sdcc / Z80 column: CP/M .COM (raw flat image, no ELF container; mosura loads via load_com).
#     nm/objdump do not apply to a raw z80 image, so the truth is derived from sdcc's OWN output:
#     functions from the linker map (`_CODE` area), the switch dispatch from the relocated
#     listing (`.rst`: a `jp (hl)` FOLLOWED by a `.dw` jump table — z80 also uses `jp (hl)` for
#     function return, which is excluded). The .com is committed with a `.com` suffix so
#     load_path selects the CP/M loader by extension. ------------------------------------------
build_z80() {
  local prog="$1"
  local com="$prog.sdcc-z80.com" truth="$prog.sdcc-z80.com.truth"
  log "$prog [sdcc/z80]"
  sdcc -mz80 -c --opt-code-size "src/$prog.c" -o "$prog.rel" >/dev/null 2>&1
  sdasz80 -l -o z80_crt0.rel "src/z80_crt0.s" >/dev/null 2>&1
  # -m map (-w wide: full names + module, one symbol per line), -u update the .rst listing.
  sdldz80 -n -i -m -w -u -b _CODE=0x100 "$prog.ihx" z80_crt0.rel "$prog.rel" >/dev/null 2>&1
  makebin -s 65536 "$prog.ihx" "$prog.full.bin" 2>/dev/null
  local end
  end=$(python3 -c "
mx=0
for l in open('$prog.ihx').read().splitlines():
    if l.startswith(':') and l[7:9]=='00':
        n=int(l[1:3],16); a=int(l[3:7],16); mx=max(mx,a+n)
print(mx)")
  dd if="$prog.full.bin" of="$com" bs=1 skip=256 count=$((end-0x100)) 2>/dev/null
  {
    echo "# mosura-ground-truth v1 program=$prog compiler=sdcc arch=z80 lang=z80:LE:16:default"
    echo "# derived-from=$prog.map + $prog.rst via=sdcc linker map + relocated listing (NOT Ghidra)"
    echo "compiler sdcc"
    echo "entry 0100"   # CP/M TPA — mosura's load_com seeds analysis here
    # Functions: the `_CODE` area block of the linker map (addr + `_name`), bounded strictly to
    # that block (any other column-0 line — a page header or the next area, e.g. `_DATA` — ends
    # it, so data symbols are excluded). `-w` gives full names + one symbol per line. Strip `_`.
    awk '
      /^_CODE / { incode=1; next }
      /^[^ ]/   { incode=0 }
      incode && $1 ~ /^[0-9A-Fa-f]{8}$/ && $2 ~ /^_[A-Za-z]/ {
        name=$2; sub(/^_/,"",name); printf "func %s 0 %s\n", $1, name
      }' "$prog.map" | sort
    # Switch dispatch: a `jp (hl)` with a `.dw` jump table within the next few listing lines.
    awk '
      /jp[ \t]+\(hl\)/ && /^[ \t]+[0-9A-Fa-f]{8} / { jp=$1; look=4; next }
      look>0 { if (index($0,".dw")>0) { printf "switch %s\n", tolower(jp); look=0 } else look-- }
    ' "$prog.rst" | sort -u
  } > "$truth"
  log "  derived $truth ($(grep -c '^func ' "$truth") funcs, $(grep -c '^switch ' "$truth") switch)"
  rm -f "$prog.rel" z80_crt0.rel "$prog.ihx" "$prog.full.bin" "$prog.lk" "$prog.map" "$prog.noi" \
        "$prog.rst" "$prog.lst" "$prog.sym" "$prog.asm" z80_crt0.lst z80_crt0.rst z80_crt0.sym 2>/dev/null
}
if have sdcc && have sdldz80 && have makebin; then
  build_z80 z80prog
else
  log "SKIP z80 — sdcc toolchain absent (documented gap)"
fi

# ---------------------------------------------------------------------------------------------
# --- Open Watcom / x86-32 column: wcc386 (a non-gcc compiler) compiles to an OMF object; a
#     hand-written wasm `_cstart_` stub provides the entry (no Watcom C run-time — keeps the
#     truth small); wlink emits a Linux ELF32 i386 (EM_386 -> x86:LE:32:default). Watcom writes
#     non-standard ELF section headers that mosura's ELF parser rejects, so host `objcopy`
#     normalizes it into a clean GNU ELF (also the source of the truth). Truth via the ELF path.
WATROOT="${GT_WATCOM:-$HOME/tools/open-watcom}"
#     $1 program  $2 optional wcc386 flags, replacing the default `-oc` (which DISABLES Watcom's
#     `call X; ret` -> `jmp X` rewrite — pass "" to let tail calls through, as `tailjmp` needs).
build_watcom() {
  # $3 = the stack-checking flag, default `-s` (suppress the stack-overflow probe). It is a
  # SEPARATE parameter from $2 because it changes the ENTRY SHAPE, not the body: without it
  # wcc386 opens every framed function with `push <framesize>; call __CHK`, which shifts the
  # true entry ahead of everything the pattern set anchors on (docs/function-discovery-backlog
  # §5 cell 1). A cell that drops it must also supply a `__CHK` stub in its `_cstart` asm, or
  # wlink fails `E2028: __CHK is an undefined reference`.
  local prog="$1" ccopt="${2--oc}" sflag="${3--s}"
  local stripped="$prog.watcom-x86-32" norm="$prog.watcom-x86-32.norm"
  log "$prog [wcc386/x86-32]"
  # binl on PATH so wlink finds its config file (wlink.lnk, which defines `system linux`).
  export WATCOM="$WATROOT" INCLUDE="$WATROOT/lh" PATH="$WATROOT/binl:$PATH"
  wcc386 "src/$prog.c" -bt=linux $sflag $ccopt -fo="$prog.obj" >/dev/null 2>&1
  wasm "src/${prog}_cstart.asm" -fo="$prog"_cstart.o >/dev/null 2>&1
  wlink system linux option quiet option nodefaultlib \
    file "$prog"_cstart.o file "$prog.obj" name "$prog.watcom-x86-32.raw" >/dev/null 2>&1
  # Normalize Watcom`s ELF into a standard GNU ELF (fixes section headers for the parser; keeps
  # the .symtab for truth derivation); then derive the truth from it and strip the analyzed one.
  objcopy "$prog.watcom-x86-32.raw" "$norm"
  derive_truth_elf "$norm" "$prog" watcom x86-32 "x86:LE:32:default" ""
  strip -o "$stripped" "$norm"
  rm -f "$prog.obj" "$prog"_cstart.o "$prog.watcom-x86-32.raw" "$norm"
}
# --- Open Watcom / LE column: the DOS-extender Linear Executable, mosura`s `load_le` path. -----
#     `wlink format os2 le` emits a bound MZ+LE with a real fixup table — the same container
#     family as WAR2.EXE, and the ONLY format in this corpus that carries relocation records.
#     LE has no symbol table, so (like the z80 column) the truth comes from the LINKER MAP:
#     wlink prints `SSSS:OOOOOOOO  name`, and the LE object table gives each segment`s base.
#
#     Reachability class: a code symbol is `dataptr` when its OFFSET WITHIN ITS OBJECT is stored
#     as a 32-bit word inside a NON-EXECUTABLE object. It is the offset, not the address: the LE
#     file image is PRE-RELOCATION, so a stored pointer holds the object-relative offset and the
#     fixup record supplies the object base at load. Comparing offsets is therefore exact for
#     internal fixups and needs no fixup-table parsing. Zero words are skipped (they would match
#     the first symbol of the object).
#     Two limitations, both harmless here and both pinned by the gate: this omits the ELF
#     derivation`s "mentioned in code" half (there is no objdump for LE), so it is only sound for
#     a fixture where no stored-pointer target is ALSO called; and a stored offset meant for a
#     different object could collide. `lestruct` satisfies both by construction, and
#     `data_pointer_le_seeding` asserts the resulting class set EXACTLY, so any drift trips it.
#   $1 program
build_watcom_le() {
  local prog="$1"
  local out="$prog.watcom-le" truth="$prog.watcom-le.truth"
  log "$prog [wcc386/LE]"
  export WATCOM="$WATROOT" INCLUDE="$WATROOT/lh" PATH="$WATROOT/binl:$PATH"
  wcc386 "src/$prog.c" -bt=dos -s -oc -fo="$prog.obj" >/dev/null 2>&1
  wasm "src/${prog}_cstart.asm" -fo="$prog"_cstart.o >/dev/null 2>&1
  wlink format os2 le option quiet option nodefaultlib option map \
    file "$prog"_cstart.o file "$prog.obj" name "$out" >/dev/null 2>&1
  {
    echo "# mosura-ground-truth v1 program=$prog compiler=watcom arch=x86-32 lang=x86:LE:32:default"
    echo "# derived-from=$prog.map + the LE object table via=wlink linker map (build artifact, NOT Ghidra)"
    echo "compiler watcom"
    GT_MAP="$prog.map" GT_BIN="$out" python3 -c '
import os, re, struct
d = open(os.environ["GT_BIN"], "rb").read()
le = struct.unpack_from("<I", d, 0x3c)[0]
nobj = struct.unpack_from("<I", d, le + 0x44)[0]
ot = le + struct.unpack_from("<I", d, le + 0x40)[0]
objs = []   # (base, vsize, executable)
for i in range(nobj):
    vs, rb, fl = struct.unpack_from("<III", d, ot + i * 24)[:3]
    objs.append((rb, vs, bool(fl & 0x4)))
print("entry %08x" % objs[0][0])
# every pointer-sized word stored in a non-executable object
stored = set()
psize = struct.unpack_from("<I", d, le + 0x28)[0]
npages = struct.unpack_from("<I", d, le + 0x14)[0]
lastb = struct.unpack_from("<I", d, le + 0x2c)[0]
total = (npages - 1) * psize + lastb
start = len(d) - total
for i in range(nobj):
    rb, vs, ex = objs[i]
    pi, pc = struct.unpack_from("<II", d, ot + i * 24 + 12)
    off = start + (pi - 1) * psize
    if ex:
        continue
    blob = d[off:off + min(vs, pc * psize)]
    for k in range(0, max(0, len(blob) - 3)):
        stored.add(int.from_bytes(blob[k:k+4], "little"))
out = []
for ln in open(os.environ["GT_MAP"], errors="replace"):
    m = re.match(r"^([0-9A-Fa-f]{4}):([0-9A-Fa-f]{8})[ +*]+([A-Za-z_][A-Za-z0-9_]*)\s*$", ln)
    if not m:
        continue
    seg, off_, name = int(m.group(1), 16), int(m.group(2), 16), m.group(3)
    if seg < 1 or seg > len(objs) or not objs[seg - 1][2]:
        continue          # code symbols only
    va = objs[seg - 1][0] + off_
    cls = "dataptr" if off_ in stored else "code"   # offsets: the image is pre-relocation
    out.append("func %08x 0 %s %s" % (va, name, cls))
print("\n".join(sorted(out)))'
  } > "$truth"
  rm -f "$prog.obj" "$prog"_cstart.o "$prog.map"
  log "  derived $truth ($(grep -c "^func " "$truth") funcs)"
}

if [ -x "$WATROOT/binl/wcc386" ] && have objcopy; then
  build_watcom watprog
  build_watcom narrowsw   # narrowed-switch decompiler-gap repro (war2-issues-become-source-tests)
  build_watcom war2gates  # trimOpInput INDIRECT-panic repro (war2-issues-become-source-tests)
  build_watcom forphi     # E1063 for-loop phi-init marker-leak repro (war2-issues-become-source-tests)
  build_watcom switchcall # EMPTY SWITCH BODY repro -- recovered table, dropped case bodies (war2-issues-become-source-tests)
  build_watcom loopcomma  # while-condition statement must print INSIDE the parens (comma_separate)
  build_watcom forcomma   # the same, on emitForLoop's header (printc.cc:2974) — loopcomma's sibling
  build_watcom loopphi    # for-recovery must backtrack past a wrong loop-head phi (block.cc:3164)
  build_watcom callclob   # an indirect call must not clobber a callee-saved loop counter (cspec killedbycall)
  build_watcom datafnptr  # code reachable ONLY through a function pointer in DATA (war2 analysis-gap §7)
  build_watcom_le lestruct # the LE column: a pointer stored ALONE, findable only via the fixup table
  # tailjmp: the SHARED-RETURN TAIL-CALL analysis repro (a function reachable only via `jmp`).
  # Built WITHOUT `-oc` on purpose — `-oc` suppresses the very `call X; ret` -> `jmp X` rewrite
  # under test (src/tailjmp.c property 1).
  # wprologue: the prologue-SHAPE spec for the watcom function-start patterns. `-of+`
  # (traceable stack frames) is REQUIRED — it is what makes wcc386 emit the `push ebp; mov ebp,esp`
  # frame WAR2 is full of. Without it the compiler omits the frame pointer and addresses locals off
  # ESP, producing prologues that look nothing like the target (measured: `53 51 83 ec` and
  # `53 51 52 56 b8`, no `89 e5` anywhere).
  build_watcom wprologue "-of+"
  # wprologue_sf: the SAVE-FIRST twin — the SAME source (src/wprologue_sf.c is a one-line include
  # of src/wprologue.c, so the two can never drift), with `-of+` REMOVED. That flag is the whole
  # difference: it demands a *traceable* frame, pinning `55 89 e5` to offset 0; a frame needed only
  # for *addressing* (which `-od` forces, every local spilled) is emitted AFTER the register saves.
  # Result, measured on native Open Watcom v2: all 15 functions save-first, run lengths 2..5, e.g.
  # p_leaf_ = `53 51 52 56 57 55 89 e5` — WAR2 0x16ed4's shape exactly. This is the only gate on
  # the save-first family, i.e. on 62 of the pattern file's 73 patterns.
  build_watcom wprologue_sf "-4r -fpi87 -od"
  # wprobe: §5 CELL 1 — stack checking. The SAME `-od` line as wprologue_sf with `-s` REMOVED
  # (third parameter ""), which makes wcc386 open every framed function with
  # `push <framesize>; call __CHK`. That shifts the true entry TEN BYTES ahead of what the
  # save-first family anchors on — the same class of defect that this pattern file was created
  # to fix, reintroduced by a flag WAR2 happened to use and most binaries do not.
  build_watcom wprobe "-4r -fpi87 -od" ""
  build_watcom tailjmp ""
  # fnpattern: the FUNCTION START SEARCH repro (a function reachable by NOTHING — no call, no
  # jump, no stored pointer — so only its prologue BYTE PATTERN can find it). `-of+` (generate
  # traceable stack frames) is load-bearing: it is what makes wcc386 emit the FRAME-FIRST prologue
  # `push ebp; mov ebp,esp; …` that the resolved pattern set anchors on exactly. See
  # src/fnpattern.c property 1 for the two prologue shapes and why this one is the gateable one.
  build_watcom fnpattern "-of+ -oc"
else
  log "SKIP x86-32 Watcom — wcc386 absent at $WATROOT/binl (documented gap)"
fi

# clang, MSVC: not installed — documented gaps in docs/ground-truth-corpus.md (never faked).
log "done — committed artifacts: *.<compiler>-<arch>[.com] (stripped) + *.truth"
