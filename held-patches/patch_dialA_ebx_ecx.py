#!/usr/bin/env python3
"""Dial A: swap EBX and ECX in wcc386 10.0a's 4-byte allocation-order table.

The table lives at FILE offset 0x7ba50; its runtime address is 0x79850 (this image's code and
rodata load at file - 0x2200, established by the accessor `MOV EAX,0x79850 ; RET` at file
0x4052b).  It is the `DoubleRegs`-family table of
bld/cg/intel/386/c/386rgtbl.c: nine `hw_reg_set` words, each one little-endian u32, terminated
by HW_EMPTY.

  stock 10.0a : EAX EDX EBX ECX ESI EDI BP SP EMPTY
  patched     : EAX EDX ECX EBX ESI EDI BP SP EMPTY   (= Open Watcom 1.0's DoubleRegs order)

Entries 2 and 3 (offsets 0x7ba58 and 0x7ba5c) are exchanged.  Nothing else changes.

Idempotent: refuses to run unless the bytes are exactly stock or already exactly patched.
Never run this against the reference tree -- pass a COPY.
"""
import hashlib
import shutil
import sys

TABLE = 0x7BA50
EBX_OFF = TABLE + 2 * 4          # 0x7ba58
ECX_OFF = TABLE + 3 * 4          # 0x7ba5c
EBX = bytes.fromhex('0c000002')  # HW_EBX = HW_EBXH|HW_BX = 0x0200000c
ECX = bytes.fromhex('30000004')  # HW_ECX = HW_ECXH|HW_CX = 0x04000030

STOCK_SHA = 'c3666de94f6fa6800f452dae8acf45505ecdb62f0ade2cc27cc86c2d9e8e2b6b'

# the whole table, stock and patched, asserted as a unit so a wrong file cannot be half-patched
STOCK_TABLE = bytes.fromhex(
    '03000001' 'c0000008' '0c000002' '30000004'
    '00010010' '00020020' '00040000' '00080000' '00000000')
PATCH_TABLE = bytes.fromhex(
    '03000001' 'c0000008' '30000004' '0c000002'
    '00010010' '00020020' '00040000' '00080000' '00000000')


def main():
    if len(sys.argv) != 2:
        sys.exit('usage: patch_dialA_ebx_ecx.py <copy-of>/BINB/WCC386.EXE')
    path = sys.argv[1]
    data = bytearray(open(path, 'rb').read())
    before_sha = hashlib.sha256(data).hexdigest()
    cur = bytes(data[TABLE:TABLE + len(STOCK_TABLE)])

    if cur == PATCH_TABLE:
        print(f'already patched (sha256 {before_sha}); nothing to do')
        return
    if cur != STOCK_TABLE:
        sys.exit(f'REFUSING: bytes at {TABLE:#x} are neither stock nor patched:\n'
                 f'  found  {cur.hex(" ", 4)}\n  stock  {STOCK_TABLE.hex(" ", 4)}')
    if before_sha != STOCK_SHA:
        print(f'note: whole-file sha256 {before_sha} != known stock {STOCK_SHA} '
              f'(table matched, continuing)')

    assert bytes(data[EBX_OFF:EBX_OFF + 4]) == EBX
    assert bytes(data[ECX_OFF:ECX_OFF + 4]) == ECX
    data[EBX_OFF:EBX_OFF + 4] = ECX
    data[ECX_OFF:ECX_OFF + 4] = EBX

    shutil.copy(path, path + '.stock')
    open(path, 'wb').write(data)
    after_sha = hashlib.sha256(data).hexdigest()
    print(f'patched {path}')
    print(f'  {EBX_OFF:#07x}  {EBX.hex(" ")} -> {ECX.hex(" ")}   (EBX -> ECX)')
    print(f'  {ECX_OFF:#07x}  {ECX.hex(" ")} -> {EBX.hex(" ")}   (ECX -> EBX)')
    print(f'  sha256 before {before_sha}')
    print(f'  sha256 after  {after_sha}')


if __name__ == '__main__':
    main()
