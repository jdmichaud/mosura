/* Port input and output.
 *
 *   wait_ready  polls the status port 0x3da until bit 3 is set, then returns with
 *               the status in AL. An IN nobody answers reads a fixed value, so an
 *               interpreter that cannot be told what the port holds spins until its
 *               step budget runs out; answered 0, 0, 8 it returns after three reads.
 *   write_pair  writes the register index in CL to port 0x388 and the value in CH to
 *               port 0x389, an OPL register write: the output is the order and the
 *               values of the writes, not any memory.
 */
.text
.globl _start, wait_ready, write_pair
.type _start,@function
_start:
    call wait_ready
    call write_pair
    ret
.size _start,.-_start

.type wait_ready,@function
wait_ready:
    movw $0x3da,%dx
1:
    inb %dx,%al
    testb $8,%al
    jz 1b
    ret
.size wait_ready,.-wait_ready

.type write_pair,@function
write_pair:
    movw $0x388,%dx
    movb %cl,%al
    outb %al,%dx
    incw %dx
    movb %ch,%al
    outb %al,%dx
    ret
.size write_pair,.-write_pair
.section .note.GNU-stack,"",@progbits
