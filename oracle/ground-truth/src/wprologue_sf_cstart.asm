; _cstart_ entry stub for `wprologue_sf` (see src/wprologue_sf.c). Also supplies the two externals
; the fixture deliberately leaves undefined in C — `sink_` (an opaque call, so the optimiser cannot
; see through it and must genuinely preserve values across it, which is what forces the
; callee-saved push runs the prologue-shape spec is built from) (`g` is defined in the C file).
;
; It calls `sf_trail_fn_` as well as `main_`, which src/wprologue_sf.c property 2/3 depends on: the
; orphan must be FOLLOWED by an ordinarily-called function, and `main_` is already emitted by the
; time the `#include "wprologue.c"` ends, so the trailer's only possible caller is here.
        .386
        public  _cstart_
        public  sink_
        extrn   main_ : near
        extrn   sf_trail_fn_ : near
_TEXT   segment byte public use32 'CODE'
_cstart_ proc
        call    main_
        mov     eax, 2
        call    sf_trail_fn_
        ret
_cstart_ endp
; opaque to the optimiser: returns its argument untouched, but wcc386 cannot inline it.
sink_   proc
        ret
sink_   endp
_TEXT   ends
        end     _cstart_
