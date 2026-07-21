; Minimal _cstart_ entry stub for the Open Watcom x86-32 ground-truth column (task #3).
; wcc386 code expects the runtime entry symbol `_cstart_`; the full Watcom C run-time would drag
; in dozens of CRT functions (a fragile recall surface). This stub IS the entry (declared via the
; `end _cstart_` MODEND record so wlink sets the ELF entry point), calls main, and returns — so
; the committed binary carries only our own functions. Assembled with Open Watcom `wasm`.
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
