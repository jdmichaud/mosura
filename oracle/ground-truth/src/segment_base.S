/* Reads through segment overrides.
 *
 * Ghidra's x86 lifts an FS or GS override as the FS_OFFSET or GS_OFFSET register plus
 * the displacement (ia.sinc segWide), in both widths; the other overrides are flat. A
 * run that never sets such a base computes the address from zero, and reads a thread
 * local, or a driver's own data, from the wrong place without any other sign.
 *   read_gs  EAX = the dword at the GS base + 0x10
 *   read_fs  EAX = the dword at the FS base + 0x10
 *   read_ds  EAX = the dword at DS:0x10, flat: the control that reads no base
 */
.text
.globl _start, read_gs, read_fs, read_ds
.type _start,@function
_start:
    call read_gs
    call read_fs
    call read_ds
    ret
.size _start,.-_start

.type read_gs,@function
read_gs:
    movl %gs:0x10,%eax
    ret
.size read_gs,.-read_gs

.type read_fs,@function
read_fs:
    movl %fs:0x10,%eax
    ret
.size read_fs,.-read_fs

.type read_ds,@function
read_ds:
    movl %ds:0x10,%eax
    ret
.size read_ds,.-read_ds
.section .note.GNU-stack,"",@progbits
