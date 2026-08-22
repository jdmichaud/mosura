#!/usr/bin/env python3
"""Decode a byte range of wcc386.exe as an array of hw_reg_set words and name each one."""
import sys

AH, AL = 0x0001, 0x0002
BH, BL = 0x0004, 0x0008
CH, CL = 0x0010, 0x0020
DH, DL = 0x0040, 0x0080
SI16, DI16, BP16, SP16 = 0x0100, 0x0200, 0x0400, 0x0800
DS, ES, CS, SS = 0x1000, 0x2000, 0x4000, 0x8000
EAXH, EBXH, ECXH, EDXH, ESIH, EDIH = 0x0100, 0x0200, 0x0400, 0x0800, 0x1000, 0x2000
FS, GS = 0x4000, 0x8000

def hw(lo, hi=0):
    return (lo | (hi << 16)) & 0xFFFFFFFF

# order matters: longest / composite first so EAX beats AX beats AL
ATOMS = [
    ('EAX', hw(AL | AH, EAXH)), ('EBX', hw(BL | BH, EBXH)),
    ('ECX', hw(CL | CH, ECXH)), ('EDX', hw(DL | DH, EDXH)),
    ('ESI', hw(SI16, ESIH)),    ('EDI', hw(DI16, EDIH)),
    ('AX', hw(AL | AH)), ('BX', hw(BL | BH)), ('CX', hw(CL | CH)), ('DX', hw(DL | DH)),
    ('AL', hw(AL)), ('AH', hw(AH)), ('BL', hw(BL)), ('BH', hw(BH)),
    ('CL', hw(CL)), ('CH', hw(CH)), ('DL', hw(DL)), ('DH', hw(DH)),
    ('SI', hw(SI16)), ('DI', hw(DI16)), ('BP', hw(BP16)), ('SP', hw(SP16)),
    ('DS', hw(DS)), ('ES', hw(ES)), ('CS', hw(CS)), ('SS', hw(SS)),
    ('FS', hw(0, FS)), ('GS', hw(0, GS)),
] + [(f'ST{i}', hw(0, 1 << i)) for i in range(8)]

def name(v):
    if v == 0:
        return 'EMPTY'
    if v == 0xFFFFFFFF:
        return 'FULL'
    parts, rest = [], v
    for n, m in ATOMS:
        if m and (rest & m) == m:
            parts.append(n)
            rest &= ~m
    if rest:
        parts.append(f'?{rest:#x}')
    return '+'.join(parts) if parts else f'?{v:#x}'

def main():
    path, start, end = sys.argv[1], int(sys.argv[2], 16), int(sys.argv[3], 16)
    d = open(path, 'rb').read()
    run = []
    for off in range(start, end, 4):
        v = int.from_bytes(d[off:off + 4], 'little')
        n = name(v)
        print(f'{off:#08x}  {v:08x}  {n}')

if __name__ == '__main__':
    main()
