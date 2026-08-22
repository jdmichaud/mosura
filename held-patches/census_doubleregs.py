#!/usr/bin/env python3
"""Find, in any wcc386 image, every run of consecutive hw_reg_set words drawn from the
32-bit general register set and terminated by HW_EMPTY -- i.e. the DoubleRegs-family
allocation-order tables -- and print the order.  Works on any Watcom revision whose host
is 32-bit (hw_reg_set == one LE u32; see bld/cg/h/cghwreg.h)."""
import sys, os

def hw(lo, hi=0):
    return (lo | (hi << 16)) & 0xFFFFFFFF

NAME = {
    hw(0x0003, 0x0100): 'EAX',
    hw(0x000C, 0x0200): 'EBX',
    hw(0x0030, 0x0400): 'ECX',
    hw(0x00C0, 0x0800): 'EDX',
    hw(0x0100, 0x1000): 'ESI',
    hw(0x0200, 0x2000): 'EDI',
    hw(0x0400, 0x0000): 'BP',
    hw(0x0800, 0x0000): 'SP',
}
EMPTY = 0
# 16-bit-word variants (AX/BX/CX/DX/SI/DI) for the 16-bit tables, reported separately
NAME16 = {
    hw(0x0003): 'AX', hw(0x000C): 'BX', hw(0x0030): 'CX', hw(0x00C0): 'DX',
    hw(0x0100): 'SI', hw(0x0200): 'DI', hw(0x0400): 'BP', hw(0x0800): 'SP',
}

def scan(data, names, minlen=4):
    """Yield (offset, [names...]) for maximal runs of `names` words ending in EMPTY."""
    n = len(data) // 4
    words = memoryview(data)
    i = 0
    out = []
    while i < n:
        v = int.from_bytes(data[4 * i:4 * i + 4], 'little')
        if v in names:
            j, seq = i, []
            while j < n:
                w = int.from_bytes(data[4 * j:4 * j + 4], 'little')
                if w in names:
                    seq.append(names[w]); j += 1
                else:
                    break
            term = j < n and int.from_bytes(data[4 * j:4 * j + 4], 'little') == EMPTY
            if len(seq) >= minlen and term:
                out.append((4 * i, seq))
            i = j + 1
        else:
            i += 1
    return out

def main():
    for path in sys.argv[1:]:
        try:
            data = open(path, 'rb').read()
        except Exception as e:
            print(f'{path}: {e}')
            continue
        print(f'=== {path}  ({len(data)} bytes) ===')
        runs = scan(data, NAME, minlen=4)
        if not runs:
            print('   (no 32-bit E-register order table found)')
        for off, seq in runs:
            print(f'   {off:#08x}  [{len(seq)}] ' + ','.join(seq))
        runs16 = scan(data, NAME16, minlen=5)
        for off, seq in runs16:
            print(f'   {off:#08x}  [{len(seq)}] (16b) ' + ','.join(seq))
        print()

if __name__ == '__main__':
    main()
