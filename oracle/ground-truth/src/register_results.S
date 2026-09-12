/* Multiple register results (GNU assembler, i386/x86-64).
 *
 * produce accepts EDI:uint4 and returns three independent uint4 values in
 * EAX, EBX and ECX. Their logical order is first, second, third; these registers
 * are neither adjacent nor ordered that way in the SLEIGH register address space.
 * Keep all three consumers: selecting just EAX, or treating an adjacent 12-byte
 * register range as the result, changes consume's source-defined value.
 * This is an explicitly supplied assembly interface, not a compiler ABI guess.
 * Strip symbols before analysis and derive the function population from the build.
 */
.text
.globl _start, produce, consume
.type _start,@function
_start:
    movl $17,%edi
    call consume
    movl %eax,sink
    ret
.size _start,.-_start

.type produce,@function
produce:
    leal 7(%edi),%eax
    leal (%edi,%edi,2),%ebx
    movl %edi,%ecx
    xorl $0x80000000,%ecx
    ret
.size produce,.-produce

.type consume,@function
consume:
    call produce
    addl %ebx,%eax
    xorl %ecx,%eax
    ret
.size consume,.-consume

.data
sink: .long 0
.section .note.GNU-stack,"",@progbits
