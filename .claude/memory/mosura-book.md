---
name: mosura-book
description: "mosura-book = an O'Reilly-style Typst book on disassembly/decompilation documenting mosura; repo location, structure, toolchain quirks"
metadata: 
  node_type: memory
  type: project
  originSessionId: ba57400a-aa2c-42b8-86ff-0743f7dbd2c1
---

**mosura-book** is an O'Reilly-style book the user asked for, teaching
disassembly/decompilation theory (Part I) then documenting mosura as the worked
example (Part II, a manual). Separate repo from mosura: `/home/jd/projects/mosura-book`
(git-init'd, not committed — commit only when asked). Audience: software devs new
to RE jargon; didactic prose (NOT telegraphic), define every term, use diagrams.

**Authoring = Typst** (user's explicit choice, 0.15.0 installed). Diagrams via
CeTZ 0.3.4 (byte/bit layouts) + Fletcher (flow/graph). **GOTCHA: Fletcher 0.5.5
is BROKEN under Typst 0.15** (cetz 0.3.2 `..vertices` error) — use **fletcher
0.5.8**. Packages fetch from the Typst registry on first build (network needed
once, then cached) — nothing to install. Fonts (all bundled): Libertinus Serif
(body), DejaVu Sans (headings), DejaVu Sans Mono (code).

**Structure:** `book.typ` (master, includes everything) · `lib/template.typ` (design
system: `book()` show-fn, `part()`, `#note/tip/warning/caution`, `#sidebar`,
`#defn/#keyterm`, `#figc`, manual TOC built from a `toc-entries` state, roman
front-matter→arabic main via `mainmatter()`) · `lib/diagrams.typ` (pipeline/
bytes-row/bitfield helpers + re-exported diagram/node/edge/canvas; PINS pkg
versions) · `chapters/frontmatter.typ` + `chapters/part{1,2}/NN-slug.typ`.
`OUTLINE.md` = full 25-chapter annotated plan; `README.md`, `Makefile` (`make`,
`make watch`, `make png`), `.gitignore` (build/). Build → `build/from-bytes-to-source.pdf`.

**Typst gotchas learned:** (1) counter `.step()` then `.get()` in the SAME
`context` returns the PRE-step value — step in one context, read in a following
one. (2) `here().page()` = PHYSICAL page; for TOC/logical numbers use
`counter(page).get().first()` (front matter roman, main restarts at 1). (3)
`here()`/`counter().get()` must be captured to a `let` before going into a
`state.update(closure)`. (4) Fletcher `node(... inset:)` must be a LENGTH not an
`(x:,y:)` dict (else `to-absolute` error). (5) Running header driven by in-body
state: set `cur-chapter.update(...)` BEFORE the chapter's `pagebreak` or the
opening page shows the wrong header. Figures numbered per-chapter via figure-counter
reset in the chapter rule.

**HOUSE STYLE (user review, IMPORTANT — apply to ALL Part I):**
- **Part I = a standalone decompilation TEXTBOOK**, NOT cluttered with how mosura is
  built. Keep forward-refs to Part II chapters ("Part II / Chapter N shows this");
  strip mosura-implementation asides (measured op counts, "mosura ports X", algorithm
  attributions, `#note[mosura builds…]`).
- **Definitions are BLENDED INLINE**, never set-off blocks that break a sentence.
  Mechanism: `#term(name, [full def], display: [inline word])` emphasizes the word in
  prose + files the precise def in the Glossary/Index; the sentence itself explains
  it. Legacy block form = `#termbox(...)` (being phased out). `#defn` = local
  non-glossary block.
- **Running header shows the chapter title** (`cur-chapter` state; appendices show
  their own name).
- Ground examples in generic assembly/C, not mosura internals.

**PROGRESS (Part I front-to-back):** Ch **1–9 drafted AND fully migrated** to the
house style (blended inline defs, de-mosura'd, chapter-title header) + Ch **20**
(was 19) the Part II disassembler sample. Committed at `3d4607d` on master (initial
scaffold = `e9637d0`). Remaining Part I: 10 types, 11 variables/stack/calling, 12
structuring, 13 emit C, 14 idioms, 15 validation, **16 anti-obfuscation (NEW, added
per user)**. Adding ch16 shifted Part II to 17–26 (disassembler 19→20); cross-refs
renumbered. Running example across ch7–9 = the `while`-loop fn `f`. Migration
mechanics: `sed 's/#term(/#termbox(/'` first to keep chapters rendering, then blend
each termbox into prose as inline `#term`. Source facts about mosura itself: see
[[mosura-project]]; finished-tool framing: [[book-assume-tool-finished]].
