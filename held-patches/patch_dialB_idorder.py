#!/usr/bin/env python3
"""Dial B (diagnostic): reverse wcc386 10.0a's FINAL scheduler tie-break — source order.

Source predicate -- Open Watcom 1.0.0 `bld/cg/c/inssched.c`, the last key of `ScheduleIns`'s
priority chain (its header comment: "Otherwise, choose the one that came last in the source
order"):

                        } else {
                            if( curr->ins->id > best->ins->id ) {
                                MARK_BEST;
                            }
                        }

Located in the 10.0a binary at file 0x661b1 (VA 0x63FB1), inside the chain that maps 1:1 onto
the source (`dag->height` at +0x14, `dag->stallable` at +0x10 masked to a byte, `dag->ins` at
+0x04, `ins->sequence` at +0x3a, `ins->id` at +0x34):

    6615a  MOV EAX,[EDI+0x14] / CMP EAX,[ECX+0x14] / JLE     ; curr->height > best->height
    66169  TEST byte [EAX+0x40],0x80 / CALL DataDependant     ; INS_INDEX_ADJUST special case
    66180  MOV EAX,[EDI+0x10] / AND 0xff / CMP / JA           ; curr->stallable > best->stallable
    66197  MOV AX,[EAX+0x3a] / CMP AX,[EBP-4]                 ; sequence == last_seq  (fxch)
    661b7  MOV EAX,[EAX+0x34] / CMP EAX,[EDX+0x34]            ; curr->ins->id vs best->ins->id
    661bd  JLE 0x661c7                                        ; take when id is GREATER   <-- site
    661c2  MOV ECX,EDI                                        ; best = curr

Patch: one byte.  0x661bd  7e (JLE rel8) -> 7d (JGE rel8), so the tie is taken when
`curr->ins->id < best->ins->id` — the instruction that came FIRST in source order wins instead
of the one that came last.

This is a DIAGNOSTIC, not a corpus candidate: it answers "is this pair's order decided by the
source-order key at all, or earlier in the chain (StallCost/height)?"  If the transposed pairs
flip, their order is a function of the IR order our C produces, and is therefore ours to
recover; if they do not, the decision is made before the tie-break ever runs.

Idempotent: asserts the pre-image.  Apply only to a COPY.
"""
import hashlib
import shutil
import sys

SITE = 0x661BD
STOCK_WIN = bytes.fromhex('8b40343b42347e08')   # mov eax,[eax+34]; cmp eax,[edx+34]; jle +8
PATCH_WIN = bytes.fromhex('8b40343b42347d08')
WIN = 0x661B7
STOCK_SHA = 'c3666de94f6fa6800f452dae8acf45505ecdb62f0ade2cc27cc86c2d9e8e2b6b'


def main():
    if len(sys.argv) != 2:
        sys.exit('usage: patch_dialB_idorder.py <copy-of>/BINB/WCC386.EXE')
    path = sys.argv[1]
    data = bytearray(open(path, 'rb').read())
    before_sha = hashlib.sha256(data).hexdigest()
    cur = bytes(data[WIN:WIN + len(STOCK_WIN)])
    if cur == PATCH_WIN:
        print(f'already patched (sha256 {before_sha}); nothing to do')
        return
    if cur != STOCK_WIN:
        sys.exit(f'REFUSING: bytes at {WIN:#x} are neither stock nor patched:\n'
                 f'  found {cur.hex(" ")}\n  stock {STOCK_WIN.hex(" ")}')
    if before_sha != STOCK_SHA:
        print(f'note: whole-file sha256 {before_sha} != known stock {STOCK_SHA}')
    shutil.copy(path, path + '.stock')
    data[SITE] = 0x7D
    open(path, 'wb').write(data)
    print(f'patched {path}')
    print(f'  {SITE:#07x}  7e -> 7d   (JLE -> JGE: earliest source order wins the final tie)')
    print(f'  sha256 before {before_sha}')
    print(f'  sha256 after  {hashlib.sha256(data).hexdigest()}')


if __name__ == '__main__':
    main()
