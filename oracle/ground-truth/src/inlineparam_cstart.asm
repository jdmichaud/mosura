; Ground-truth corpus program (issues-become-source-tests (subject-profile note)): the self-compiled repro of
; <subject-profile>/notes/function-discovery-backlog.md §9 #5 — the INLINE CALL PARAMETER thunk family. See
; src/inlineparam.c for the full property list and the measured pre-fix behaviour; this file is
; where the whole fixture lives, because the idiom CANNOT BE WRITTEN IN C: it needs a callee that
; pops its own return address and reads the word the call is followed by.
;
; Assembled with Open Watcom `wasm`, linked FIRST so _TEXT starts at the lowest text address and
; these labels stay in source order with no padding between them (`byte public` segment) — the
; adjacency is load-bearing (property 3).
;
; THE SHAPE, byte for byte (the subject MZ 0x13a38..0x13a56 is the original):
;
;     thunk_a_:   e8 rel32          call dispatch_
;                 b8 11             <- 2-byte INLINE PARAMETER, read by dispatch_, NOT code
;     thunk_b_:   e8 rel32          call dispatch_
;                 b8 11
;     thunk_c_:   e8 rel32          call dispatch_
;                 b8 11
;     dispatch_:  5b                pop ebx        <- BX = the return address
;                 66 8b 0b          mov cx,[ebx]   <- read the word the call is FOLLOWED BY
;
; The `b8 11` parameter bytes are chosen, not arbitrary. A linear decode starting at the
; parameter reads `b8 11 <first 3 bytes of the next label>` as a 5-byte `mov eax,imm32`, which
; runs 3 bytes PAST the parameter and SWALLOWS THE NEXT LABEL'S ENTRY. That is exactly what
; mosura does to `00013a56 POP BX` on the subject MZ stub — a real instruction destroyed, not merely
; extra code — and it is what makes this a wrong-code gate rather than a tolerance question.
; Any other parameter bytes that decode short would leave the next entry intact and the fixture
; would measure nothing (property 2).

        .386
        public  _cstart_
        public  thunk_a_
        public  thunk_b_
        public  thunk_c_
        public  dispatch_
        extrn   main_ : near

_TEXT   segment byte public use32 'CODE'

; The entry. Calls each thunk once so all three are CALL-REACHABLE in the truth (property 4) —
; these call sites carry no inline parameter of their own; the parameter belongs to the call
; INSIDE each thunk, which is the one whose return address dispatch_ pops.
_cstart_ proc
        call    thunk_a_
        call    thunk_b_
        call    thunk_c_
        call    main_
        ret
_cstart_ endp

; --- The thunk family. Three call sites to the same target, which is what carries the evidence
;     past Ghidra's default non-return threshold of 3 (property 5). Bare labels, not proc/endp,
;     so no symbol size claims the parameter bytes as body (property 6).
thunk_a_ label near
        call    dispatch_
        db      0b8h, 011h

thunk_b_ label near
        call    dispatch_
        db      0b8h, 011h

thunk_c_ label near
        call    dispatch_
        db      0b8h, 011h

; --- The dispatcher. Pops its own return address, reads the inline parameter through it, steps
;     over it, and leaves by `push ebx; ret` — the classic "return to a computed address" idiom.
;     It therefore NEVER returns to any of its callers: control resumes two bytes past the call,
;     not at it. Deliberately NOT an indirect jump — `derive_truth_elf` classifies any x86
;     `jmp *` as a switch dispatch (build.sh:131), and an unrecoverable one would make
;     `ground_truth_parity` RED for a reason that has nothing to do with this fixture
;     (property 7).
dispatch_ label near
        pop     ebx
        mov     cx, [ebx]
        add     ebx, 2
        push    ebx
        ret

_TEXT   ends
        end     _cstart_
