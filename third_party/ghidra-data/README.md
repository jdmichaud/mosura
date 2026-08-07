# Vendored Ghidra FID signature databases

Ghidra's shipped **Function ID** signature databases, embedded so mosura can identify
statically-linked Visual Studio runtime functions without a Ghidra checkout or a network fetch.

These are **external data files read at runtime** — not compiled into the binary, not a build
input. mosura opens them by path; absent, the FID analyzer is simply inert.

- **Provenance**: `github.com/NationalSecurityAgency/ghidra-data`, tag **`Ghidra_12.0.3`** — the
  same release the pinned `ghidra` checkout is at (`Ghidra_12.0.3_build`,
  `09f14c92d3da6e5d5f6b7dea115409719db3cce1`). Upstream URL pattern:
  `https://github.com/NationalSecurityAgency/ghidra-data/raw/Ghidra_${VERSION}/FunctionID/<name>.fidb`,
  as declared in `ghidra/gradle/support/fetchDependencies.gradle:117-175`.
- **Verbatim, verified**: all ten files are byte-identical to upstream. `FunctionID/SHA256SUMS`
  matches, file for file, the `sha256:` values gradle pins for each download. Re-verify any time
  with `cd FunctionID && sha256sum -c SHA256SUMS`.
- **Contents** (76 MB total): the **packed** `.fidb` form — the same form upstream publishes.

  | file | size | covers |
  | --- | --- | --- |
  | `vsOlder_x86.fidb` / `vsOlder_x64.fidb` | 17.1 / 11.2 MB | Visual Studio 1998 → 2010 |
  | `vs2012_x86.fidb` / `vs2012_x64.fidb` | 7.7 / 7.1 MB | Visual Studio 2012 |
  | `vs2015_x86.fidb` / `vs2015_x64.fidb` | 8.6 / 7.8 MB | Visual Studio 2015 |
  | `vs2017_x86.fidb` / `vs2017_x64.fidb` | 4.4 / 3.8 MB | Visual Studio 2017 |
  | `vs2019_x86.fidb` / `vs2019_x64.fidb` | 6.2 / 5.7 MB | Visual Studio 2019 |

  Each database holds a debug and a production library variant. **x86 / x64 MSVC only** —
  upstream ships nothing for gcc, Watcom, Borland, sdcc, or any non-x86 architecture (verified
  against both the `master` and `main` branches, 2026-08-07). Every other compiler×target column
  mosura supports gets its signatures from our own ingest — see `docs/fid-port-plan.md` §4.

- **Format** (two layers, both read-only ports — `docs/fid-port-plan.md` §5 Stage 2):
  1. the **packed** wrapper (`ItemSerializer.java:43`) — a Java `ObjectOutputStream` block-data
     header (`ac ed 00 05 77 44`, then magic `0x2e30212634e92c20`, format version, two UTF
     strings, file type, unpacked length) followed by a single DEFLATE'd ZIP entry;
  2. the **unpacked** payload — a raw `LocalBufferFile` (magic `0x2f30312c34292c2a`, 16 KiB
     buffers) carrying Ghidra's `db` B-tree, which holds the five FID tables.

  Ghidra's own build performs step 1 ahead of time into `.fidbf`; we do it at load. `flate2` is
  already a workspace dependency, so no new crate is needed.

- **License**: Apache-2.0 (`LICENSE` here) — `ghidra-data` is released under the same terms as
  Ghidra itself and declares no additional conditions; `Ghidra/Features/FunctionID/build/LICENSE.txt`
  lists that module's third-party files and the list is empty. Redistributed here **verbatim and
  unmodified**; any converted or derived database mosura emits must declare itself a modification
  per Apache-2.0 §4(b). A FID record contains two one-way 64-bit digests, a code-unit count, flags
  and a symbol name — no library code is recoverable from it.
