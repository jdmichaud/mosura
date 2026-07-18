        .module crt0
        .globl  _main
        ; CP/M .COM entry: loaded at 0x100, execution starts here.
        .area   _CODE
        call    _main
        rst     0x00            ; warm boot back to CP/M
