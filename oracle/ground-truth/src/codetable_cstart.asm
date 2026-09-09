; Ground-truth corpus program: the self-compiled repro of the second subject's INLINE CODE-POINTER
; TABLES (docs/tasklist-2026-09-08.md item 12) — routines reachable ONLY through a table of code
; pointers that sits INSIDE THE CODE SEGMENT, called through a scaled index, plus an UNGUARDED
; indexed jump through such a table. The whole fixture lives here because the shape cannot be
; written in C: a compiler puts its tables in data and guards its switch index; hand-written code
; does neither. src/codetable.c only supplies `main_`.
;
; Assembled with Open Watcom `wasm`, linked FIRST so _TEXT starts at the lowest text address and
; the labels stay in source order with no padding between them (`byte public` segment).
;
; PROPERTIES THIS PROGRAM DEPENDS ON — do not "simplify" any of them away:
;
;  1. NOTHING calls h0_..h3_ directly, and their addresses are stored NOWHERE in data. They appear
;     only as the entries of `tbl`, a run of four pointers INLINE IN _TEXT, and the only route to
;     them is the instruction that names the table: `call dword ptr cs:[tbl + ebx*4]` — the
;     second subject's exact form (segment override included; mode dispatch 0x1b15 -> table 0x1b85).
;  2. `tbl` is NOT 4-ALIGNED: it starts wherever `dispatch_`'s `ret` left the assembler (15 bytes
;     into a 16-aligned routine). Ghidra's blind address-table scan requires table alignment 4
;     (AddressTableAnalyzer.java:69, :167), so that scan can never see this table; only the path
;     that starts from the NAMING instruction can (OperandReferenceAnalyzer's "Switch Table
;     References", alignment 1 at :109). Aligning the table would let the blind scan find it and
;     the fixture would stop isolating the named-table path.
;  3. The run is TERMINATED BY CODE, not by data: four bytes `b0 02 f9 c3` (mov al,2; stc; ret)
;     follow the fourth pointer, exactly as the subject's tables carry short routines after their
;     pointer runs. Read as a dword (0xc3f902b0) it is not a mapped address, which is what ends
;     the pointer run at four. It is deliberately NOT a public symbol: no analysis may make a
;     function of it, and the truth must not demand one.
;  4. `deep_` is called ONLY from `h0_`, i.e. only from inside the table-reachable subgraph. It is
;     the CASCADE assertion (the subject's 229 "closure" routines): recovering the entries must
;     also recover what they call, by the ordinary direct-call route.
;  5. The index is OPAQUE: `ebx` is loaded from a data global nothing folds, so constant
;     propagation cannot resolve the call or the jump, and the table is the only evidence.
;  6. `jumper_` is the second shape: `jmp dword ptr cs:[jtbl + ebx*4]` with NO bound on `ebx`
;     (no `and ebx,3` before it — compiled switches always carry one). The decompiler-driven switch
;     recovery gives up on an unguarded index (`range size 536870912`); the named-table path bounds
;     the switch by the pointer run at `jtbl` and reaches the four arms, which lie AFTER the table,
;     outside anything a fall-through walk from the `jmp` can reach.
;  7. Every OTHER function (_cstart_, dispatch_, jumper_, main_) is genuinely call-reachable, so
;     the recall assertion in `ground_truth_parity` isolates the table-only routines.
;
; Gated by `ground_truth_parity.rs::ground_truth_parity` (under the option the truth declares) and
; `::switch_table_references` (both directions: absent under the default, present under the option).

        .386
        public  _cstart_
        public  dispatch_
        public  jumper_
        public  h0_
        public  h1_
        public  h2_
        public  h3_
        public  deep_
        extrn   main_ : near

_DATA   segment dword public use32 'DATA'
g_mode  dd      2               ; property 5: the call-table index, opaque to constant propagation
g_sel   dd      1               ; property 5: the jump-table index, likewise
_DATA   ends
DGROUP  group   _DATA

_TEXT   segment byte public use32 'CODE'
        assume  cs:_TEXT, ds:DGROUP

; The entry (property 7): every routine below that is meant to be call-reachable is called here.
_cstart_ proc
        call    dispatch_
        call    jumper_
        call    main_
        ret
_cstart_ endp

; --- THE CALL TABLE (properties 1, 2, 3, 5). 16 bytes of _cstart_ put dispatch_ 16-aligned;
;     6 + 8 + 1 bytes of dispatch_ put `tbl` at +15: 3 mod 4, never a blind-scan candidate.
dispatch_ proc
        mov     ebx, g_mode
        call    dword ptr cs:[tbl + ebx*4]
        ret
dispatch_ endp
tbl     label   dword
        dd      h0_
        dd      h1_
        dd      h2_
        dd      h3_
        db      0b0h, 002h, 0f9h, 0c3h      ; property 3: mov al,2 / stc / ret — code ends the run

; --- The entries: reachable only through `tbl` (property 1). Bare labels, not proc/endp, so no
;     symbol size claims bytes the table owns.
h0_     label   near
        call    deep_                       ; property 4: the cascade
        ret
h1_     label   near
        mov     eax, 1
        ret
h2_     label   near
        mov     eax, 2
        ret
h3_     label   near
        mov     eax, 3
        ret
deep_   label   near
        mov     eax, 11
        ret

; --- THE UNGUARDED JUMP TABLE (property 6). The arms follow the table; a fall-through walk from
;     the jmp reaches neither the table's bytes nor the arms.
jumper_ proc
        mov     ebx, g_sel
        jmp     dword ptr cs:[jtbl + ebx*4]
jtbl    label   dword
        dd      c0
        dd      c1
        dd      c2
        dd      c3
c0:     mov     eax, 10
        ret
c1:     mov     eax, 20
        ret
c2:     mov     eax, 30
        ret
c3:     mov     eax, 40
        ret
jumper_ endp

_TEXT   ends
        end     _cstart_
