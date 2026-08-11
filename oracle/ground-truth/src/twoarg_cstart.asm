; Minimal _cstart_ entry stub, same recipe as regout_cstart.asm / regmodify_cstart.asm.
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
;   EAX = argument 1, EDX = argument 2, EAX = result. Reads BOTH argument registers, so a
;   caller that passes only one is provably wrong.
        public  add2_
add2_   proc
        add     eax, edx
        ret
add2_   endp

; The SAME contract, but with a BRANCH in the body. `callee_effects`' straight-line scan bails at
; the first branch and claims nothing, so this callee exercises the FALLBACK path where the call's
; parameter list comes from the convention rather than from the callee's own recovered reads. WAR2's
; real callees are branchy, so this is the shape that actually matters there.
        public  add2b_
add2b_  proc
        test    edx, edx
        jz      short skip
        add     eax, edx
skip:   ret
add2b_  endp
_TEXT   ends
        end     _cstart_
