# Unpacking Watcom install media (`wpack` / `PCK` archives)

Some Watcom releases ship a compiler that exists **only** inside their installer archives. Watcom
10.5 is the case that forced this tool: its `BINW/WCC386.EXE` on the CD is a damaged 65,536-byte
stub (note the timestamp — it is a day newer than every other file on the disc), so the C compiler
could not be run at all, and `oracle/codegen-probes/watcom/10.5.*` did not exist. The real
567,558-byte binary is in `DISKIMGS/DISK02+03/PCK00017.{1,2}`.

## Use

```sh
./build.sh                                    # once: builds the sortperm helper
cat DISKIMGS/DISK02/PCK00017.1 \
    DISKIMGS/DISK03/PCK00017.2 > pck00017.bin # multi-volume: plain concatenation
python3 wunpack.py pck00017.bin <outdir>
```

Multiple volumes are passed as multiple inputs (the last argument is always the output directory);
concatenating them by hand as above works equally well.

To find which archive holds a file, parse the directories only — no decompression needed. Each
archive begins with a 12-byte header (`u16 sig=0x2403`, `u8 major`, `u8 minor`, `u16 num_files`,
`u16 info_len`, `u32 info_offset`) and the file list at `info_offset` holds
`u32 length, u32 disk_addr, u32 stamp, u32 crc, u8 namelen, char name[]`.

## The format

LZSS (4096-byte window, 60-byte lookahead) over a Shannon-Fano prefix code, ported from Open
Watcom's `bld/wpack/c/decode.c`. Two details cost real time and are worth stating plainly:

- **The code-length sort must be Watcom's own.** `AssignCodes` numbers same-length symbols in
  whatever order the sort leaves them, and the encoder used an *unstable* Bentley-McIlroy
  quicksort. A stable sort yields a valid-looking but wrong symbol assignment: decoding proceeds,
  consumes the right number of bits, and emits garbage. So `sortperm` links their real `wqsort.c`.

- **That sort must be built `-m32`.** Its portable byteswap fallback swaps 8-byte `long`s while
  advancing pointers by 4 (the comment says "this is for 32 bit machines"). On LP64 the
  overlapping writes corrupt the array — it returns a permutation with duplicates and omissions.

Both failures are silent, and neither is caught by the obvious check: the output is always exactly
`length` bytes, because `length` is the decode loop's termination condition. Verify content
(`file`, an `MZ` magic, an expected banner string), never size.

The stored CRC-32 is standard (poly `0xedb88320`) but **is not** `crc32(output)`: `CompareCRC`
folds the decoder's 1-3 read-ahead bytes into it before comparing, so a direct comparison
mismatches on correct output.

## Provenance

`wunpack.py` is a port of, and `sortperm.c` links directly against, Open Watcom source
(`bld/wpack/`), which is under the **Sybase Open Watcom Public License**. It lives under `oracle/`
with the other externally-licensed oracle tooling rather than in `crates/`, so nothing in the
mosura crates links it. It is a one-off acquisition tool: `cargo test` never invokes it, and it is
not needed to build or run mosura.
