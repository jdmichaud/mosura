        .module crt0
        .globl  _main
        .globl  _cpm_start
        ; CP/M .COM entry: loaded at the TPA (0x100), execution starts here. Labeled so the
        ; entry appears as a function in the linker map (the ground-truth function set).
        .area   _CODE
_cpm_start::
        call    _main
        rst     0x00            ; warm boot back to CP/M
