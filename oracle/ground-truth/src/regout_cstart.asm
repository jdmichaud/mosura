; Minimal _cstart_ entry stub for the Open Watcom x86-32 ground-truth column (issues-become-source-tests (subject-profile note)), shared
; recipe with watprog_cstart.asm: this stub IS the entry (via `end _cstart_`), calls main, and
; returns — so the committed binary carries only our own functions (no Watcom C run-time recall
; surface). Assembled with Open Watcom `wasm`.
        .386
        public  _cstart_
        extrn   main_ : near
_TEXT   segment byte public use32 'CODE'
_cstart_ proc
        call    main_
        ret
_cstart_ endp

; The callee under test. Hand-written because wcc386 inlines a C definition in the same
; translation unit, leaving no call at all. Convention (declared to C via #pragma aux):
;   EBX = pointer in, EAX = count in, EBX = pointer out.
        public  bump_
bump_   proc
        add     ebx, eax
        ret
bump_   endp
_TEXT   ends
        end     _cstart_
