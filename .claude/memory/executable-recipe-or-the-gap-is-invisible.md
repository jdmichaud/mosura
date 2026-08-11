---
name: executable-recipe-or-the-gap-is-invisible
description: An audit that greps a staged directory can only confirm what was staged; only an executable recipe naming each input can report an absent one
metadata: 
  node_type: memory
  type: feedback
  originSessionId: 6a216fa6-e69f-4b20-b0bf-429f1307092c
  modified: 2026-08-08T23:51:59.139Z
---

**⭐ 2026-08-09.** The FID library-coverage audit declared the Watcom 16-bit column complete. It
was not: `LIB286/MATH*.LIB` sit one directory ABOVE the `LIB286/DOS/*` that had been extracted, so
a `find` over the staged tree returned nothing and the column looked finished while every 16-bit
float routine was missing (+250 records per memory model once fixed).

**Why:** the 85 database recipes existed only as ad-hoc shell loops in a session transcript.
Nothing could state what a database was SUPPOSED to be built from, so nothing could notice an
input that was not there.

**How to apply:** when a build recipe matters, write it as a script that names every input
explicitly and REPORTS an absent one rather than quietly building from what happens to be present
(`scripts/rebuild-fid-db.sh`, `-n` dry-run). Its first dry run found the gap. Corollary: prefer an
explicit path to `find | head -1` — see the OS/2-vs-DOS `CLIB3R.LIB` trap in
[[adaptations-inventory]]'s sibling docs.

Generalisation of [[could-it-have-come-out-otherwise]]: an audit whose method can only see what is
already staged has its answer fixed in advance.

Related: [[numbers-stale-unless-sha-stamped]], [[generated-artifact-drift]],
[[unlinked-zero-field-changes-the-decode]].
