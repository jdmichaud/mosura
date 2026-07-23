#!/usr/bin/env python3
"""Extract the raw code bytes from a Watcom OMF object (.obj) — the exact tool that produced
the committed `oracle/codegen-probes/watcom/<rev>.code` artefacts from `<rev>.obj`.

The codegen-fingerprint ground truth (docs/watcom-codegen-fingerprint.md) commits, per Watcom
revision, the machine code our probe (watcom_cg.c) compiled to. This script is the one link in
that chain that turns the compiler's OMF object into the committed flat code bytes:

    python3 scripts/extract-omf-code.py oracle/codegen-probes/watcom/10.0a.obj \
        > oracle/codegen-probes/watcom/10.0a.code

Method: walk the OMF record stream (each record: 1-byte type, 2-byte LE length, payload,
checksum byte included in the length) and concatenate the payloads of every LEDATA (0xA0) and
LEDATA32 (0xA1) record — the "logical enumerated data" records that carry the segment's raw
bytes — in file order. Per record the payload is: a segment index (1 byte, or 2 bytes when the
first byte has the 0x80 continuation bit), an enumerated offset (2 bytes for LEDATA, 4 for
LEDATA32), then the data; the trailing checksum byte is excluded.

Caveats, deliberate:
- Fixups are NOT applied (FIXUPP records are ignored), so relocated fields stay zero — e.g.
  every `call` disassembles as `e8 00 00 00 00`. The fingerprint signals (compare width,
  register choice, loop shape) are unaffected; only cross-reference targets are blank.
- A single code segment is assumed (true for the probe): all LEDATA payloads are concatenated
  in file order, offsets are not honoured. For multi-segment objects this would interleave —
  keep the probe single-file, no data globals with initializers.
"""

import sys


def extract_code(data: bytes) -> bytes:
    code = b""
    i = 0
    while i + 3 <= len(data):
        rec_type = data[i]
        rec_len = data[i + 1] | (data[i + 2] << 8)  # includes payload + checksum byte
        payload = data[i + 3 : i + 3 + rec_len - 1]  # strip the trailing checksum
        if rec_type in (0xA0, 0xA1):  # LEDATA / LEDATA32
            off = 2 if payload and payload[0] & 0x80 else 1  # segment index (1 or 2 bytes)
            off += 4 if rec_type == 0xA1 else 2  # enumerated data offset (32- or 16-bit)
            code += payload[off:]
        i += 3 + rec_len
    return code


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    with open(sys.argv[1], "rb") as f:
        data = f.read()
    sys.stdout.buffer.write(extract_code(data))
    return 0


if __name__ == "__main__":
    sys.exit(main())
