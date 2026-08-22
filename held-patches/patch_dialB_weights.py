#!/usr/bin/env python3
"""Dial B: change wcc386 10.0a's instruction-scheduler operand-stall weights.

Source predicate -- Open Watcom 1.0.0 `bld/cg/c/inssched.c:127-155`:

    static unsigned InsStallable( instruction *ins ) {
        stallable = 0;
        for( i = ins->num_operands - 1; i >= 0; --i ) {
            switch( ins->operands[i]->n.class ) {
            case N_INDEXED:  stallable += 3; break;
            case N_REGISTER: stallable += 2; break;
            case N_MEMORY:   stallable += 1; break;
            }
        }
        if( ins->result != NULL && ins->result->n.class == N_INDEXED ) stallable += 3;
        return( stallable );
    }

`stallable` is the FOURTH tie-break key in `ScheduleIns` (min StallCost, then max height, then
the INDEX_ADJUST special case, then max stallable, then the fxch check, then latest `ins->id`).
`name_class` is N_CONSTANT=0, N_MEMORY=1, N_TEMP=2, N_REGISTER=3, N_INDEXED=4 (`bld/cg/h/name.h:35`).

Located in the 10.0a binary at file 0x656d2 (VA 0x634d2), verified by disassembly with mosura's
own decoder -- the compiler strength-reduced the shared `+3` into a loop-carried LEA:

    656eb  MOV EDI,dword ptr [EBX + 0x44]   ; ins->operands[i]
    656ee  MOV CL,byte ptr [EDI + 0x4]      ; op->n.class
    656f1  CMP CL,0x3          /  656f4  JC 0x656ff   /  656f6  JBE 0x6570b
    656f8  CMP CL,0x4          /  656fb  JZ 0x65706   /  656fd  JMP 0x65710
    656ff  CMP CL,0x1          /  65702  JZ 0x6570f   /  65704  JMP 0x65710
    65706  MOV EDX,dword ptr [EBP + -0x4]   ; N_INDEXED : stallable = stallable + 3
    6570b  INC EDX / INC EDX                ; N_REGISTER: stallable += 2      <-- weight site
    6570f  INC EDX                          ; N_MEMORY  : stallable += 1      <-- weight site
    65714  LEA EDI,[EDX + 0x3]              ; the shared +3 immediate         <-- weight site
    6572d  MOV EDX,EDI                      ; result N_INDEXED: uses the same +3

Variants (each a minimal in-place edit; no instruction changes length):

  reg0   0x6570b  42 42 -> 90 90   N_REGISTER weight 2 -> 0
  reg1   0x6570b  42 42 -> 42 90   N_REGISTER weight 2 -> 1
  idx1   0x65716  03    -> 01      N_INDEXED  weight 3 -> 1 (operand AND result)
  idx5   0x65716  03    -> 05      N_INDEXED  weight 3 -> 5 (operand AND result)

Idempotent: asserts the pre-image, refuses on anything else.  Apply only to a COPY.
"""
import hashlib
import shutil
import sys

STOCK_SHA = 'c3666de94f6fa6800f452dae8acf45505ecdb62f0ade2cc27cc86c2d9e8e2b6b'

# name -> (file offset, stock bytes, patched bytes, description)
VARIANTS = {
    'reg0': (0x6570B, bytes.fromhex('4242'), bytes.fromhex('9090'),
             'N_REGISTER operand weight 2 -> 0'),
    'reg1': (0x6570B, bytes.fromhex('4242'), bytes.fromhex('4290'),
             'N_REGISTER operand weight 2 -> 1'),
    'idx1': (0x65716, bytes.fromhex('03'), bytes.fromhex('01'),
             'N_INDEXED weight 3 -> 1 (operand and result)'),
    'idx5': (0x65716, bytes.fromhex('03'), bytes.fromhex('05'),
             'N_INDEXED weight 3 -> 5 (operand and result)'),
}
# context asserted around every site so a wrong file cannot be silently half-patched
CONTEXT = (0x656F1, bytes.fromhex('80f903'))   # CMP CL,3 -- the switch head


def main():
    if len(sys.argv) != 3 or sys.argv[1] not in VARIANTS:
        sys.exit(f'usage: patch_dialB_weights.py <{"|".join(VARIANTS)}> '
                 f'<copy-of>/BINB/WCC386.EXE')
    name, path = sys.argv[1], sys.argv[2]
    off, stock, patched, desc = VARIANTS[name]
    data = bytearray(open(path, 'rb').read())
    before_sha = hashlib.sha256(data).hexdigest()

    coff, cbytes = CONTEXT
    if bytes(data[coff:coff + len(cbytes)]) != cbytes:
        sys.exit(f'REFUSING: InsStallable switch head not found at {coff:#x}')

    cur = bytes(data[off:off + len(stock)])
    if cur == patched:
        print(f'already patched with {name} (sha256 {before_sha}); nothing to do')
        return
    if cur != stock:
        sys.exit(f'REFUSING: bytes at {off:#x} are neither stock nor {name}-patched:\n'
                 f'  found {cur.hex(" ")}\n  stock {stock.hex(" ")}')
    if before_sha != STOCK_SHA:
        print(f'note: whole-file sha256 {before_sha} != known stock {STOCK_SHA}')

    shutil.copy(path, path + '.stock')
    data[off:off + len(patched)] = patched
    open(path, 'wb').write(data)
    print(f'patched {path} [{name}] {desc}')
    print(f'  {off:#07x}  {stock.hex(" ")} -> {patched.hex(" ")}')
    print(f'  sha256 before {before_sha}')
    print(f'  sha256 after  {hashlib.sha256(data).hexdigest()}')


if __name__ == '__main__':
    main()
