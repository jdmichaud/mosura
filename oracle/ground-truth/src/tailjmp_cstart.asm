; _cstart_ entry stub for `tailjmp` (see src/tailjmp.c) PLUS the FORWARD arm of the shared-return
; tail-call shape. wcc386 always lays a tail-call callee adjacent to (or before) its caller, so a
; jump FORWARD over another function's entry cannot be produced from C with this compiler — it is
; written here, where the emission order is exactly the written order. Assembled with Open Watcom
; `wasm`, and linked FIRST, so these three functions occupy the lowest text addresses.
;
;   fwd_jumper_  ends in `jmp fwd_landing_`, forward, over gap_fn_'s entry.
;   gap_fn_      an ordinary `call`-reachable function that the jump crosses.
;   fwd_landing_ reachable ONLY by that jump; preceded by gap_fn_'s `ret`, so nothing falls into
;                it, and its first instruction is not a terminator.
;
; This is Ghidra `SharedReturnAnalysisCmd.applyTo`'s forward arm (srcAddr < destAddr:
; `destAddr >= getFunctionAfter(srcAddr)` -> createFunction). the subject's 0x601f8 -> 0x60270 is the same
; shape. Do not reorder these three procs — the layout IS the test.
        .386
        public  _cstart_
        public  fwd_jumper_
        public  gap_fn_
        public  fwd_landing_
        extrn   main_ : near
_TEXT   segment byte public use32 'CODE'
_cstart_ proc
        call    main_
        ret
_cstart_ endp

fwd_jumper_ proc
        add     eax, 11
        jmp     fwd_landing_
fwd_jumper_ endp

gap_fn_ proc
        imul    eax, eax, 5
        ret
gap_fn_ endp

fwd_landing_ proc
        sub     eax, 3
        xor     eax, 2ch
        ret
fwd_landing_ endp
_TEXT   ends
        end     _cstart_
