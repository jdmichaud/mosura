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
    local exec_ranges
    exec_ranges=$("$objdump" -h "$bin" | awk '/^[ ]+[0-9]+ / { name=$2; sz=$3; vma=$4; getline fl; if (fl ~ /CODE/) print vma, sz }')
    "$nm" -S --defined-only "$bin" | GT_EXEC_RANGES="$exec_ranges" python3 -c '
import os, sys
ranges = []
for ln in os.environ.get("GT_EXEC_RANGES", "").splitlines():
    p = ln.split()
    if len(p) == 2:
        v = int(p[0], 16); s = int(p[1], 16); ranges.append((v, v + s))
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
        out.append("func %s %s %s" % (addr_s, size, name))
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
WATROOT="${GT_WATCOM:-$HOME/tools/open-watcom-v2/rel}"
build_watcom() {
  local prog="$1"
  local stripped="$prog.watcom-x86-32" norm="$prog.watcom-x86-32.norm"
  log "$prog [wcc386/x86-32]"
  # binl on PATH so wlink finds its config file (wlink.lnk, which defines `system linux`).
  export WATCOM="$WATROOT" INCLUDE="$WATROOT/lh" PATH="$WATROOT/binl:$PATH"
  wcc386 "src/$prog.c" -bt=linux -s -oc -fo="$prog.obj" >/dev/null 2>&1
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
if [ -x "$WATROOT/binl/wcc386" ] && have objcopy; then
  build_watcom watprog
else
  log "SKIP x86-32 Watcom — wcc386 absent at $WATROOT/binl (documented gap)"
fi

# clang, MSVC: not installed — documented gaps in docs/ground-truth-corpus.md (never faked).
log "done — committed artifacts: *.<compiler>-<arch>[.com] (stripped) + *.truth"
