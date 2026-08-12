# FID identification probes

Programs built from `oracle/fid/src/*.c` by the historical compilers, kept as the input that proves
each FID column names real functions (`fid_watcom_identify`, `fid_borland_identify`, `fid_identify`,
`fid_detect`). Rebuild with `scripts/build-fid-probes.sh`.

Because they are linked, each one contains the vendor's C run-time. See
[`../../../docs/third-party-test-binaries.md`](../../../docs/third-party-test-binaries.md) for the
inventory, provenance and rationale.
