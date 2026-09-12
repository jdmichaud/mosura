/* Self-compiled indirect-call contract MVE (GNU assembler, x86-64 SysV).
 *
 * Keep these properties: the literal target reaches CALLIND through a register;
 * the read-only slot contains the same target; the writable slot has the same
 * initializer but can be replaced at run time. All callees are also directly
 * reachable, so function discovery is independent of indirect-call recovery.
 * The two branches share argument setup, making late prototype recovery restore
 * the original data flow rather than reuse any already-eliminated arguments.
 * custom_target/custom_literal add a declared 16-bit BX/BP protocol outside
 * SysV's argument slots; the test supplies those source-owned storage facts.
 * custom_load also writes an ordinary SysV argument register: a locked slot
 * declaration must not acquire that unrelated value as an extra argument.
 * No bytes in this program come from a survey binary.
 * Build: gcc -nostdlib -static -no-pie -Wl,-e,_start indirect_contract.S -o indirect_contract
 */
.text
.globl _start, target, alternate, literal, readonly_call, writable_call, replace_slot
.globl custom_target, custom_literal, custom_writable, custom_load
.type _start,@function
_start:
    call target
    call alternate
    call literal
    call readonly_call
    call writable_call
    call replace_slot
    call custom_target
    call custom_literal
    call custom_writable
    call custom_load
    ret
.size _start,.-_start

.type target,@function
target:
    leal (%rdi,%rsi),%eax
    ret
.size target,.-target

.type alternate,@function
alternate:
    movl %edi,%eax
    subl %esi,%eax
    ret
.size alternate,.-alternate

.type literal,@function
literal:
    leaq target(%rip),%rax
    movl $11,%edi
    movl $22,%esi
    testl %edx,%edx
    je 1f
    call *%rax
    addl $1,%eax
    ret
1:  call *%rax
    addl $2,%eax
    ret
.size literal,.-literal

.type readonly_call,@function
readonly_call:
    movl $11,%edi
    movl $22,%esi
    call *readonly_slot(%rip)
    ret
.size readonly_call,.-readonly_call

.type writable_call,@function
writable_call:
    movl $11,%edi
    movl $22,%esi
    call *writable_slot(%rip)
    ret
.size writable_call,.-writable_call

.type replace_slot,@function
replace_slot:
    leaq alternate(%rip),%rax
    movq %rax,writable_slot(%rip)
    ret
.size replace_slot,.-replace_slot

.type custom_target,@function
custom_target:
    movzwl %bx,%eax
    movzwl %bp,%ecx
    addl %ecx,%eax
    ret
.size custom_target,.-custom_target

.type custom_literal,@function
custom_literal:
    leaq custom_target(%rip),%rax
    movw $33,%bx
    movw $44,%bp
    call *%rax
    addl $1,%eax
    ret
.size custom_literal,.-custom_literal

.type custom_writable,@function
custom_writable:
    movw $33,%bx
    movw $44,%bp
    call *custom_slot(%rip)
    addl $1,%eax
    ret
.size custom_writable,.-custom_writable

.type custom_load,@function
custom_load:
    movq custom_slot(%rip),%r11
    movl $99,%edi
    movw $33,%bx
    movw $44,%bp
    call *%r11
    addl $1,%eax
    ret
.size custom_load,.-custom_load

.section .rodata
.globl readonly_slot
readonly_slot: .quad target
.data
.globl writable_slot
writable_slot: .quad target
.globl custom_slot
custom_slot: .quad custom_target
.section .note.GNU-stack,"",@progbits
