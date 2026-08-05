; _cstart_ entry stub for `fnpattern` (see src/fnpattern.c). Nothing here references `orphan_fn_`
; — that is the whole point of the fixture (property 2). Assembled with Open Watcom `wasm` and
; linked FIRST, so it occupies the lowest text address and the C functions follow in source order.
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
