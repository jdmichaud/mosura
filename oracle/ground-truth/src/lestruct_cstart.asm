; Minimal _cstart_ entry stub for `lestruct` (see src/datafnptr.c), the shared Open Watcom
; x86-32 recipe (watprog_cstart.asm / trimshape_cstart.asm): this stub IS the entry (via
; `end _cstart_`), calls main, and returns — so the committed binary carries only our own
; functions (no Watcom C run-time recall surface). Assembled with Open Watcom `wasm`.
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
