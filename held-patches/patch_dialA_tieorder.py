#!/usr/bin/env python3
"""Dial A (tie-order): flip wcc386 10.0a's equal-score register tie-break from FIRST-wins to
LAST-wins.

Source predicate -- Open Watcom 1.0.0 `bld/cg/c/regalloc.c:855-861`, inside `GiveBestReg`'s
scoring walk over `RegSets[tree->idx]`:

    if( ( saves > best_saves )
     || ( saves == best_saves
       && HW_Subset( GivenRegisters, reg )
       && !HW_Subset( GivenRegisters, best ) ) ) {
        best = reg;
        best_saves = saves;
    }

The walk visits the register list IN TABLE ORDER, so on a pure score tie (neither or both
candidates already in `GivenRegisters`) the EARLIER table entry wins.  Changing the strict `>`
to `>=` makes the LATER table entry win instead -- it reverses the tie-break direction without
disabling anything and without touching the table itself.

In the 10.0a binary that predicate is at file 0x59e9c (this image loads at base 0, so offset ==
address); verified by disassembly with mosura's own decoder:

    59e9c  MOV ECX,dword ptr [ESP]        ; best_saves
    59e9f  MOV EDX,EAX
    59ea1  CMP EAX,ECX                    ; saves vs best_saves
    59ea3  JG  0x59ec8                    ; saves >  best_saves  -> take        <-- PATCHED
    59ea5  JNZ 0x59ecd                    ; saves != best_saves  -> skip
    59ea7  MOV EDX,dword ptr [0x7f884]    ; GivenRegisters
    59ead  AND EDX,ESI                    ;  & reg
    59eaf  CMP EDX,ESI
    59eb1  JNZ 0x59ecd                    ; !HW_Subset(Given,reg) -> skip
    59eb3  MOV EDX,dword ptr [0x7f884]    ; GivenRegisters
    59eb9  AND EDX,EBP                    ;  & best
    59ebb  CMP EDX,EBP
    59ebd  SETNZ DL                       ; !HW_Subset(Given,best)
    59ec0  AND EDX,0xff
    59ec6  JZ  0x59ecd                    ; HW_Subset(Given,best) -> skip
    59ec8  MOV EBP,ESI                    ; best = reg
    59eca  MOV dword ptr [ESP],EAX        ; best_saves = saves

Corroboration that this is the right site and not a lookalike: the SAME absolute address
0x7f884 is loaded twice, matching the two `HW_Subset( GivenRegisters, ... )` calls in the
source, and the instruction immediately after the join is `CMP byte ptr [ESP+0x1c],0x1`, which
is the loop's following `if( greed != TRUE )` (regalloc.c:863).

Patch: one byte.  0x59ea3  7f (JG rel8) -> 7d (JGE rel8).  The rel8 displacement 0x23 is
unchanged, so no other instruction moves.

Idempotent: refuses to run unless the bytes are exactly stock or already exactly patched.
Never run this against the reference tree -- pass a COPY.
"""
import hashlib
import shutil
import sys

SITE = 0x59EA3
STOCK = bytes.fromhex('39c87f2375267526'[:8])   # 39 c8 7f 23  (cmp eax,ecx ; jg +0x23)
STOCK_WIN = bytes.fromhex('39c87f23')
PATCH_WIN = bytes.fromhex('39c87d23')
STOCK_SHA = 'c3666de94f6fa6800f452dae8acf45505ecdb62f0ade2cc27cc86c2d9e8e2b6b'
WIN = SITE - 2   # start of the CMP, so the assertion covers context, not just the flag byte


def main():
    if len(sys.argv) != 2:
        sys.exit('usage: patch_dialA_tieorder.py <copy-of>/BINB/WCC386.EXE')
    path = sys.argv[1]
    data = bytearray(open(path, 'rb').read())
    before_sha = hashlib.sha256(data).hexdigest()
    cur = bytes(data[WIN:WIN + 4])

    if cur == PATCH_WIN:
        print(f'already patched (sha256 {before_sha}); nothing to do')
        return
    if cur != STOCK_WIN:
        sys.exit(f'REFUSING: bytes at {WIN:#x} are neither stock nor patched:\n'
                 f'  found {cur.hex(" ")}\n  stock {STOCK_WIN.hex(" ")}')
    if before_sha != STOCK_SHA:
        print(f'note: whole-file sha256 {before_sha} != known stock {STOCK_SHA} '
              f'(site matched, continuing)')

    shutil.copy(path, path + '.stock')
    data[SITE] = 0x7D
    open(path, 'wb').write(data)
    after_sha = hashlib.sha256(data).hexdigest()
    print(f'patched {path}')
    print(f'  {SITE:#07x}  7f -> 7d   (JG -> JGE: equal-score ties now take the LATER '
          f'register in table order)')
    print(f'  sha256 before {before_sha}')
    print(f'  sha256 after  {after_sha}')


if __name__ == '__main__':
    main()
