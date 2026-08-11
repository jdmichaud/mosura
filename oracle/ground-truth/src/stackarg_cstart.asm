; Minimal _cstart_ entry stub for the Open Watcom x86-32 ground-truth column, same recipe as
; watprog_cstart.asm / regout_cstart.asm: this stub IS the entry (via `end _cstart_`), calls main,
; and returns — so the committed binary carries only our own functions.
;
; `keep` is NOT here: unlike regout's `bump_`, it is an ordinary C function in regmodify.c. It only
; has to survive as a real call, which the `#pragma aux` declaration plus two call sites achieve.
; What this program pins is the CALLER's code around that call, not the callee's body.
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
