; _cstart_ entry stub for `retorphan` (see src/retorphan.c). Nothing here references `orphan_fn_`
; — that is the whole point of the fixture (property 1). Assembled with Open Watcom `wasm` and
; linked FIRST, so it occupies the lowest text address and the C functions follow in source order,
; which is what puts `tab_h3_`'s `ret` immediately before the orphan (property 4).
        .386
        public  _cstart_
        extrn   main_ : near
_TEXT   segment byte public use32 'CODE'
_cstart_ proc
        call    main_
        ret
_cstart_ endp
_TEXT   ends
        end     _cstart_
