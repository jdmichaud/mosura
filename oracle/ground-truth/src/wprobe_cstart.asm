; _cstart_ entry stub for `wprobe` (see src/wprobe.c) — §5 cell 1, built WITHOUT `-s`.
;
; Supplies three things the C file deliberately leaves undefined:
;   sink_   an opaque call, so the optimiser cannot see through it and must genuinely preserve
;           values across it — which is what forces the callee-saved push runs;
;   __CHK   Watcom's STACK-OVERFLOW PROBE. Without `-s`, wcc386 opens every framed function with
;           `push <framesize>; call __CHK`, so the freestanding link fails
;           `E2028: __CHK is an undefined reference` unless it is provided here. That failure is
;           itself the proof that the flag changes code generation, not just a check. The real
;           routine compares ESP against the stack limit and traps; a bare `ret` is all this
;           fixture needs, since the binary is analysed and never executed.
;   the call to probe_trail_fn_, which keeps the orphan off the end of the section
;           (src/wprobe.c property 3) — `main_` is already emitted by the time the include ends.
        .386
        public  _cstart_
        public  sink_
        public  __CHK
        extrn   main_ : near
        extrn   probe_trail_fn_ : near
_TEXT   segment byte public use32 'CODE'
_cstart_ proc
        call    main_
        mov     eax, 2
        call    probe_trail_fn_
        ret
_cstart_ endp
; opaque to the optimiser: returns its argument untouched, but wcc386 cannot inline it.
sink_   proc
        ret
sink_   endp
; Watcom's stack probe. Called from every prologue when `-s` is absent.
__CHK   proc
        ret
__CHK   endp
_TEXT   ends
        end     _cstart_
