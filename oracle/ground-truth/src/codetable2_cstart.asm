; Ground-truth corpus program: the FOLLOW-ON to item 12 (docs/tasklist-2026-09-08.md §12), the two
; closure gaps the operator measured once the "Switch Table References" port recovered the tables
; themselves (contrib 14 verification, 2026-09-09). `codetable` covers a table's own entries; this
; covers what those entries REACH, the two shapes that stayed missing:
;
;  W1 — A TABLE ENTRY WHOSE FIRST INSTRUCTION IS A CALL. `ent0_` begins `call deep2_`, then has more
;       body. The entry is reached only through the call table, and `deep2_` only through `ent0_`.
;       The port disassembled the entry but stopped at the call: the fall-through (`mov eax,5`) was
;       never decoded and `deep2_` never became a function. The entry seed must follow flow past the
;       call, not lay a single instruction.
;  W2 — A NESTED SWITCH INSIDE AN ARM. `jumper2_` switches through `jt1`; its arm `arm0_` is itself
;       `jmp cs:[jt2 + ebx*4]`, a second unguarded switch whose table and arms are reached only after
;       `arm0_` is decoded by the FIRST table's processing. The port decoded `arm0_` (the arm is in
;       the body) but never re-examined it, so `jt2` was never seen and `narm0_..narm2_` stayed
;       missing. The analyzer must revisit the code it decodes itself.
;
; The whole fixture is this file: hand-written unguarded indexed calls and jumps, which a C compiler
; does not emit. `codetable2.c` supplies only `main_`. Assembled with Open Watcom `wasm`, linked
; first. Verified under `switch-table-refs` (the truth declares it); gated by
; `ground_truth_parity.rs::switch_table_closure` in both directions.

        .386
        public  _cstart_
        public  dispatch2_
        public  jumper2_
        public  ent0_
        public  ent1_
        public  ent2_
        public  deep2_
        extrn   main_ : near

_DATA   segment dword public use32 'DATA'
g_mode2 dd      0               ; the call-table index (opaque to constant propagation)
g_sel1  dd      0               ; the outer jump index
g_sel2  dd      0               ; the inner (nested) jump index
_DATA   ends
DGROUP  group   _DATA

_TEXT   segment byte public use32 'CODE'
        assume  cs:_TEXT, ds:DGROUP

_cstart_ proc
        call    dispatch2_
        call    jumper2_
        call    main_
        ret
_cstart_ endp

; --- W1: the call table. ent0_ starts with a call; deep2_ is reached only through it. ---
dispatch2_ proc
        mov     ebx, g_mode2
        call    dword ptr cs:[ctbl + ebx*4]
        ret
dispatch2_ endp
ctbl    label   dword
        dd      ent0_
        dd      ent1_
        dd      ent2_
        db      0b0h, 002h, 0f9h, 0c3h      ; code ends the run, as on the subject

ent0_   label   near
        call    deep2_                      ; W1: the entry's FIRST instruction is a call
        mov     eax, 5                      ; the fall-through, which must be decoded
        ret
ent1_   label   near
        mov     eax, 1
        ret
ent2_   label   near
        mov     eax, 2
        ret
deep2_  label   near                        ; reached ONLY via ent0_'s call
        mov     eax, 7
        ret

; --- W2: the outer switch. arm0_ is itself a switch; jt2 and its arms are reached only after
;     arm0_ is decoded by jt1's processing. ---
jumper2_ proc
        mov     ebx, g_sel1
        jmp     dword ptr cs:[jt1 + ebx*4]
jt1     label   dword
        dd      arm0_
        dd      arm1_
        dd      arm2_
arm0_   label   near                        ; W2: an arm of jt1 that is itself a nested switch
        mov     ebx, g_sel2
        jmp     dword ptr cs:[jt2 + ebx*4]
jt2     label   dword
        dd      narm0_
        dd      narm1_
        dd      narm2_
narm0_  label   near                        ; reached ONLY through the nested jump in arm0_
        mov     eax, 40
        ret
narm1_  label   near
        mov     eax, 41
        ret
narm2_  label   near
        mov     eax, 42
        ret
arm1_   label   near
        mov     eax, 30
        ret
arm2_   label   near
        mov     eax, 31
        ret
jumper2_ endp

_TEXT   ends
        end     _cstart_
