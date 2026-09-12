/* A value and a condition flag returned together (GNU assembler, i386/x86-64).
 *
 * advance takes EDI:uint4 and returns EDI:uint4 plus CF:bool. The explicit
 * assembly interface packs the value at byte 0 and the flag at byte 4; it is
 * not a compiler's ordinary C aggregate-return convention.
 * Keep both exits and both consumers. choose uses the returned value on each
 * flag-selected path. repeat feeds that value into the next call until CF is
 * set: using only the original input would fail to terminate for inputs 0..2.
 * ADD wraps at 32 bits, including when the incoming value is UINT32_MAX.
 * Strip symbols before analysis and derive function boundaries from the build.
 */
.text
.globl _start, advance, choose, repeat
.type _start,@function
_start:
    movl $0,%edi
    call repeat
    movl %eax,sink
    movl $17,%edi
    call choose
    movl %eax,sink+4
    ret
.size _start,.-_start

.type advance,@function
advance:
    cmpl $3,%edi
    jae .Ldone
    incl %edi
    clc
    ret
.Ldone:
    addl $7,%edi
    stc
    ret
.size advance,.-advance

.type choose,@function
choose:
    call advance
    movl %edi,%eax
    jc .Lmarked
    addl $100,%eax
    ret
.Lmarked:
    xorl $0x80000000,%eax
    ret
.size choose,.-choose

.type repeat,@function
repeat:
    call advance
    jnc repeat
    movl %edi,%eax
    ret
.size repeat,.-repeat

.data
sink: .long 0,0
.section .note.GNU-stack,"",@progbits
