#!/usr/bin/env python3
"""Extract files from a Watcom `wpack` (PCK) archive -- LZSS + Shannon-Fano.

Ported from Open Watcom's bld/wpack/c/decode.c (Sybase Open Watcom Public License).
Multi-volume archives (PCKnnnnn.1, .2, ...) are plain concatenations.
"""
import os, struct, sys, zlib

STRBUF, LAHEAD, THRESHOLD = 4096, 60, 2
NUM_CHARS = 256 - THRESHOLD + LAHEAD
MAX_CODE_BITS = 16
MASK = [0, 1, 3, 7, 0xF, 0x1F, 0x3F, 0x7F, 0xFF]

D_CODE = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 8, 9, 9, 9, 9, 9, 9, 9, 9, 10, 10, 10, 10, 10, 10, 10, 10, 11, 11, 11, 11, 11, 11, 11, 11, 12, 12, 12, 12, 13, 13, 13, 13, 14, 14, 14, 14, 15, 15, 15, 15, 16, 16, 16, 16, 17, 17, 17, 17, 18, 18, 18, 18, 19, 19, 19, 19, 20, 20, 20, 20, 21, 21, 21, 21, 22, 22, 22, 22, 23, 23, 23, 23, 24, 24, 25, 25, 26, 26, 27, 27, 28, 28, 29, 29, 30, 30, 31, 31, 32, 32, 33, 33, 34, 34, 35, 35, 36, 36, 37, 37, 38, 38, 39, 39, 40, 40, 41, 41, 42, 42, 43, 43, 44, 44, 45, 45, 46, 46, 47, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63]
D_LEN = [3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8]

SORTPERM = os.path.join(os.path.dirname(os.path.abspath(__file__)), "sortperm")

def sort_lengths(idx, ln):
    """Sort symbol indices by code length using wpack's OWN qsort.

    Not any sort: `AssignCodes` numbers same-length symbols in whatever order the sort
    leaves them, and the encoder used this exact (unstable, Bentley-McIlroy) quicksort.
    A stable sort produces a different, wrong symbol assignment within each length class.
    """
    import subprocess
    inp = "%d\n" % len(idx) + "".join("%d %d\n" % (s, ln[s]) for s in idx)
    r = subprocess.run([SORTPERM], input=inp, capture_output=True, text=True)
    out = [int(x) for x in r.stdout.split()]
    assert len(out) == len(idx), "sortperm failed: %s" % r.stderr
    return out


class Dec:
    def __init__(self, data, pos):
        self.d, self.p = data, pos
        self.getbuf = 0; self.getlen = 0; self.secondbuf = 0
    def rb(self):
        if self.p < len(self.d):
            b = self.d[self.p]; self.p += 1; return b
        return 0
    def get_byte(self):
        i = self.getbuf >> 8
        if self.getlen >= 8:
            self.getbuf = (self.getbuf << 8) & 0xFFFF; self.getlen -= 8
        else:
            self.getbuf = self.secondbuf
            i |= self.getbuf >> self.getlen
            self.getbuf = (self.getbuf << (16 - self.getlen)) & 0xFFFF
            self.secondbuf = self.rb()
        return i & 0xFF
    def decode_position(self):
        i = self.get_byte(); c = D_CODE[i] << 6; j = D_LEN[i] - 2
        if j > self.getlen:
            self.getbuf |= (self.secondbuf << (8 - self.getlen)) & 0xFFFF
            self.getbuf &= 0xFFFF; self.getlen += 8; self.secondbuf = self.rb()
        i = ((i << j) | (self.getbuf >> (16 - j))) & 0xFFFF if j else i
        self.getbuf = (self.getbuf << j) & 0xFFFF; self.getlen -= j
        return c | (i & 0x3F)
    def shannon_trie(self):
        ln = [0]*NUM_CHARS; idx = []
        curr = 0; numcoded = self.rb() + 1
        while numcoded > 0:
            e = self.rb()
            if e & 0x80:
                curr += (e & 0x7F) + 1
            else:
                for _ in range((e >> 4) + 1):
                    idx.append(curr); ln[curr] = (e & 0xF) + 1; curr += 1
            numcoded -= 1
        idx = sort_lengths(idx, ln)
        self.MinVal = [0xFFFF]*(MAX_CODE_BITS+1)
        self.MapOffset = [0]*(MAX_CODE_BITS+1)
        self.CharMap = [0]*NUM_CHARS
        codeval = codeinc = lastlen = curroffset = 0
        self.MinCodeLen = ln[idx[0]]
        for i in range(len(idx)-1, -1, -1):
            codeval = (codeval + codeinc) & 0xFFFF
            if ln[idx[i]] != lastlen:
                lastlen = ln[idx[i]]; codeinc = 1 << (16 - lastlen)
                self.MinVal[lastlen] = codeval; self.MapOffset[lastlen] = curroffset
            self.CharMap[curroffset] = idx[i]; curroffset += 1
    def run(self, textsize):
        self.shannon_trie()
        self.getlen = 0; self.getbuf = 0; self.secondbuf = self.rb()
        tb = bytearray(b' ' * STRBUF); r = STRBUF - LAHEAD
        out = bytearray(); count = 0
        while count < textsize:
            if self.getlen < 8:
                self.getbuf = (self.getbuf | (self.secondbuf << (8 - self.getlen))) & 0xFFFF
                self.getlen += 8; self.secondbuf = self.rb()
            spare = self.getlen - 8; self.getlen = 16
            self.getbuf = (self.getbuf | (self.secondbuf >> spare)) & 0xFFFF
            codelen = self.MinCodeLen
            while codelen <= MAX_CODE_BITS and self.getbuf < self.MinVal[codelen]:
                codelen += 1
            if codelen > MAX_CODE_BITS: raise ValueError("bad code")
            c = self.CharMap[self.MapOffset[codelen] +
                             ((self.getbuf - self.MinVal[codelen]) >> (16 - codelen))]
            self.getbuf = (self.getbuf << codelen) & 0xFFFF; self.getlen -= codelen
            if spare > codelen:
                self.getlen -= 8 - spare
            else:
                self.getbuf = (self.getbuf | ((self.secondbuf & MASK[spare]) << (codelen - spare))) & 0xFFFF
                self.getlen += spare; self.secondbuf = self.rb()
            if c < 256:
                out.append(c); tb[r] = c; r = (r + 1) & (STRBUF - 1); count += 1
            else:
                i = (r - self.decode_position() - 1) & (STRBUF - 1)
                j = c - 255 + THRESHOLD
                for k in range(j):
                    ch = tb[(i + k) & (STRBUF - 1)]
                    tb[r] = ch; r = (r + 1) & (STRBUF - 1); out.append(ch)
                count += j
        return bytes(out)

def main():
    data = b"".join(open(p,'rb').read() for p in sys.argv[1:-1])
    outdir = sys.argv[-1]
    sig, maj, mnr, nf, ilen, ioff = struct.unpack_from("<HBBHHI", data, 0)
    if sig != 0x2403: sys.exit(f"not a wpack archive (sig={sig:#06x})")
    o = ioff
    for _ in range(nf):
        length, addr, stamp, crc, nl = struct.unpack_from("<IIIIB", data, o)
        shannon = not (nl & 0x80); nl &= 0x7F
        name = data[o+17:o+17+nl].decode('latin1'); o += 17 + nl
        if not shannon: sys.exit(f"{name}: stored (no-shannon) path not implemented")
        blob = Dec(data, addr).run(length)
        got = zlib.crc32(blob) & 0xFFFFFFFF
        open(f"{outdir}/{name}", 'wb').write(blob)
        print(f"{name}: {len(blob)} bytes (expected {length})  crc32={got:#010x} stored={crc:#010x}")

if __name__ == "__main__":
    main()
