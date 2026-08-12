# Analysis corpus

The binaries mosura's auto-analysis is captured against, built from `src/` by
`build.sh` (which needs the cross-toolchains, Watcom 10.0a under dosemu2, and sdcc).
`../../goldens/analysis/*.snapshot` are the Ghidra-derived goldens for them.

Most of these are our own sources compiled by open toolchains. Three items are not purely ours:

- `watcom_hello.exe` links the Watcom C/C++32 run-time (© WATCOM International Corp.);
- `mingw_hello.exe` / `mingw_hello32.exe` link the MinGW-w64 run-time and `libgcc`;
- `markers/` holds small slices of vendor-produced binaries (an MSVC 6 and an MSVC 8 Rich header,
  a Borland 4.5 banner) kept as compiler-identification fixtures.

See [`../../docs/third-party-test-binaries.md`](../../docs/third-party-test-binaries.md) for the
full inventory, provenance, and the gate each one serves.
