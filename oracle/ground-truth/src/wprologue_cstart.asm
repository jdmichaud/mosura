; _cstart_ entry stub for `wprologue` (see src/wprologue.c). Also supplies the two externals the
; fixture deliberately leaves undefined in C — `sink_` (an opaque call, so the optimiser cannot
; see through it and must genuinely preserve values across it, which is what forces the
; callee-saved push runs the prologue-shape spec is built from) (`g` is defined in the C file).
        .386
        public  _cstart_
        public  sink_
        extrn   main_ : near
_TEXT   segment byte public use32 'CODE'
_cstart_ proc
        call    main_
        ret
_cstart_ endp
; opaque to the optimiser: returns its argument untouched, but wcc386 cannot inline it.
sink_   proc
        ret
sink_   endp
_TEXT   ends
        end     _cstart_
