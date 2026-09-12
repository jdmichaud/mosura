/* Named register convention and target declaration MVE (GNU assembler, i386).
 *
 * Keep all three distinct input registers live in combine: EAX/EDX/ECX select
 * the GCC cspec's named __regparm3 model. EAX/EDX in pair are a control whose
 * storage already matches Watcom's positional default. Both return in EAX.
 * The noncommutative operations make an input-register permutation observable.
 * _start references both bodies so discovery is independent of the convention.
 *
 * A Watcom translation unit must express the recovered register storage through
 * its aux pragma, without leaving a Ghidra model name as an unknown C keyword.
 * The faithful decompiler declaration must still retain that model name.
 * Build: gcc -m32 -nostdlib -static -no-pie -Wl,-e,_start model_declaration.S
 */
.text
.globl _start, combine, pair
.type _start,@function
_start:
    call combine
    call pair
    ret
.size _start,.-_start

.type combine,@function
combine:
    subl %edx,%eax
    xorl %ecx,%eax
    ret
.size combine,.-combine

.type pair,@function
pair:
    subl %edx,%eax
    ret
.size pair,.-pair
.section .note.GNU-stack,"",@progbits
