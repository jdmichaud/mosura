#!/usr/bin/env python3
"""Find little-endian u32 references to a set of addresses in wcc386.exe.
For this image, file offset == virtual address (see .claude/memory/wcc386-disassembly-notes.md),
so a pointer to a table is literally that offset stored as a dword."""
import sys

def main():
    path = sys.argv[1]
    targets = [int(x, 16) for x in sys.argv[2:]]
    d = open(path, 'rb').read()
    for t in targets:
        needle = t.to_bytes(4, 'little')
        hits, i = [], d.find(needle)
        while i >= 0:
            hits.append(i)
            i = d.find(needle, i + 1)
        print(f'{t:#08x}: {len(hits)} reference(s) {[hex(h) for h in hits]}')

if __name__ == '__main__':
    main()
