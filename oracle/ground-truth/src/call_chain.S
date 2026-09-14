/* A caller whose result comes from a callee, and an interrupt kept as an event.
 *
 *   outer            EAX = inner() + 1 through a real CALL/RET pair over the
 *                    stack the caller supplies: 41 + 1 = 42.
 *   inner            EAX = 41. It FOLLOWS outer in the text, so a byte window
 *                    that starts at outer and runs to the end holds both, and
 *                    a window cut at inner's entry has a call target with no
 *                    instruction in it.
 *   interrupt_event  INT 0x21 then RET. The handler is not in this image; an
 *                    interpreter that follows calls must still treat the
 *                    interrupt as an event and reach the RET.
 */
.text
.globl _start, outer, inner, interrupt_event
.type _start,@function
_start:
    call outer
    call interrupt_event
    ret
.size _start,.-_start

.type outer,@function
outer:
    call inner
    addl $1,%eax
    ret
.size outer,.-outer

.type inner,@function
inner:
    movl $41,%eax
    ret
.size inner,.-inner

.type interrupt_event,@function
interrupt_event:
    int $0x21
    ret
.size interrupt_event,.-interrupt_event
.section .note.GNU-stack,"",@progbits
