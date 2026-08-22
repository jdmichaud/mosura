#!/usr/bin/env python3
"""Locate the 386rgtbl.c hw_reg_set tables inside a Watcom wcc386.exe image.

hw_reg_set on a 32-bit x86 host is a single `unsigned` (cghwreg.h: HW_NEED_64 and
HW_NEED_160 are undefined for Intel targets, so the struct has only member _0).
HW_DEFINE_SIMPLE( r, p0, p1, ... ) => r_0 = p0 + (p1 << 16), so each entry is one
little-endian 32-bit word.  Masks are derived from bld/cg/intel/h/cgi86reg.h.
"""
import sys

# low word (p_0)
AH, AL = 0x0001, 0x0002
BH, BL = 0x0004, 0x0008
CH, CL = 0x0010, 0x0020
DH, DL = 0x0040, 0x0080
SI16, DI16, BP16, SP16 = 0x0100, 0x0200, 0x0400, 0x0800
DS, ES, CS, SS = 0x1000, 0x2000, 0x4000, 0x8000
# high word (p_1), shifted << 16
ST = [0x0001 << (i) for i in range(8)]
EAXH, EBXH, ECXH, EDXH, ESIH, EDIH = 0x0100, 0x0200, 0x0400, 0x0800, 0x1000, 0x2000
FS, GS = 0x4000, 0x8000

def hw(lo, hi=0):
    return (lo | (hi << 16)) & 0xFFFFFFFF

AX = hw(AL | AH)
BX = hw(BL | BH)
CX = hw(CL | CH)
DX = hw(DL | DH)

R = {
    'HW_EAX': AX | hw(0, EAXH),
    'HW_EBX': BX | hw(0, EBXH),
    'HW_ECX': CX | hw(0, ECXH),
    'HW_EDX': DX | hw(0, EDXH),
    'HW_ESI': hw(SI16, ESIH),
    'HW_EDI': hw(DI16, EDIH),
    'HW_AX': AX, 'HW_BX': BX, 'HW_CX': CX, 'HW_DX': DX,
    'HW_AL': hw(AL), 'HW_AH': hw(AH), 'HW_BL': hw(BL), 'HW_BH': hw(BH),
    'HW_CL': hw(CL), 'HW_CH': hw(CH), 'HW_DL': hw(DL), 'HW_DH': hw(DH),
    'HW_SI': hw(SI16), 'HW_DI': hw(DI16),
    'HW_BP': hw(BP16), 'HW_SP': hw(SP16),
    'HW_DS': hw(DS), 'HW_ES': hw(ES), 'HW_CS': hw(CS), 'HW_SS': hw(SS),
    'HW_FS': hw(0, FS), 'HW_GS': hw(0, GS),
    'HW_EMPTY': 0,
    'HW_ST0': hw(0, ST[0]), 'HW_ST1': hw(0, ST[1]), 'HW_ST2': hw(0, ST[2]),
    'HW_ST3': hw(0, ST[3]), 'HW_ST4': hw(0, ST[4]), 'HW_ST5': hw(0, ST[5]),
    'HW_ST6': hw(0, ST[6]), 'HW_ST7': hw(0, ST[7]),
}

def le(v):
    return bytes([(v >> 0) & 0xFF, (v >> 8) & 0xFF, (v >> 16) & 0xFF, (v >> 24) & 0xFF])

def sig(names):
    out = b''
    for n in names:
        v = 0
        for part in n.split('+'):
            v |= R[part]
        out += le(v)
    return out

TABLES = {
    # name: entries exactly as in bld/cg/intel/386/c/386rgtbl.c (OW 1.0.0)
    'Reg64Order':   ['HW_EAX','HW_EBX','HW_ESI','HW_EDI','HW_EDX','HW_ECX','HW_BP','HW_SP','HW_EMPTY'],
    'ByteRegs':     ['HW_AL','HW_AH','HW_DL','HW_DH','HW_BL','HW_BH','HW_CL','HW_CH','HW_EMPTY'],
    'WordOrSegReg': ['HW_AX','HW_DX','HW_BX','HW_CX','HW_SI','HW_DI','HW_DS','HW_ES','HW_FS','HW_GS','HW_CS','HW_SS','HW_EMPTY'],
    'WordRegs':     ['HW_AX','HW_DX','HW_BX','HW_CX','HW_SI','HW_DI','HW_EMPTY'],
    'TwoByteRegs':  ['HW_AX','HW_DX','HW_BX','HW_CX','HW_EMPTY'],
    'SegRegs':      ['HW_DS','HW_ES','HW_FS','HW_GS','HW_CS','HW_SS','HW_EMPTY'],
    'ABCDRegs':     ['HW_EAX','HW_EDX','HW_EBX','HW_ECX','HW_EMPTY'],
    'DoubleRegs':   ['HW_EAX','HW_EDX','HW_ECX','HW_EBX','HW_ESI','HW_EDI','HW_BP','HW_SP','HW_EMPTY'],
    'DoubleParmRegs': ['HW_EAX','HW_EDX','HW_EBX','HW_ECX','HW_ESI','HW_EDI','HW_BP','HW_SP','HW_EMPTY'],
    'STIReg':       ['HW_ST1','HW_ST2','HW_ST3','HW_ST4','HW_ST5','HW_ST6','HW_ST7','HW_EMPTY'],
    'QuadReg':      ['HW_EDX+HW_EAX','HW_ECX+HW_EBX','HW_ECX+HW_EAX','HW_ECX+HW_ESI','HW_EDX+HW_EBX',
                     'HW_EDI+HW_EAX','HW_ECX+HW_EDI','HW_EDX+HW_ESI','HW_EDI+HW_EBX','HW_ESI+HW_EAX',
                     'HW_ECX+HW_EDX','HW_EDX+HW_EDI','HW_EDI+HW_ESI','HW_ESI+HW_EBX','HW_EBX+HW_EAX',
                     'HW_BP+HW_EAX','HW_BP+HW_EDX','HW_BP+HW_EBX','HW_BP+HW_ECX','HW_BP+HW_ESI',
                     'HW_BP+HW_EDI','HW_EMPTY'],
    'LongIndexRegs': ['HW_DS+HW_EAX','HW_DS+HW_EDX','HW_DS+HW_EBX','HW_DS+HW_ECX','HW_DS+HW_ESI',
                      'HW_DS+HW_EDI','HW_DS+HW_BP'],  # prefix only
}

def findall(hay, needle):
    out, i = [], hay.find(needle)
    while i >= 0:
        out.append(i)
        i = hay.find(needle, i + 1)
    return out

def main():
    path = sys.argv[1]
    data = open(path, 'rb').read()
    print(f'{path}: {len(data)} bytes')
    print()
    print('--- register masks ---')
    for n in ['HW_EAX','HW_EDX','HW_ECX','HW_EBX','HW_ESI','HW_EDI','HW_BP','HW_SP','HW_EMPTY']:
        print(f'  {n:10s} 0x{R[n]:08x}  bytes {le(R[n]).hex(" ")}')
    print()
    print('--- table searches ---')
    for name, entries in TABLES.items():
        s = sig(entries)
        hits = findall(data, s)
        print(f'  {name:16s} {len(entries):3d} entries, {len(s):4d} bytes: {len(hits)} hit(s) '
              f'{[hex(h) for h in hits]}')
        if not hits:
            # try progressively shorter prefixes to see where the match breaks
            for k in range(len(entries) - 1, 1, -1):
                hs = findall(data, sig(entries[:k]))
                if hs:
                    print(f'      longest matching prefix: {k}/{len(entries)} entries at '
                          f'{[hex(h) for h in hs][:6]}')
                    break

if __name__ == '__main__':
    main()
