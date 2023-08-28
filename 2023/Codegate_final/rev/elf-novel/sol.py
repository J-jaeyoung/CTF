#!/usr/bin/env python2
from pwn import *
context.log_level = "fatal"
answer = [0x41] * 30

for i in range(29, -1, -1):
    for c in range(0x20, 0x7f):
        answer[i] = c
        test = ''.join(map(chr, answer))
        p = process("./vm")
        p.sendline(test)
        data = p.recvall()
        if data.count("OK") == (30 - i):
            print(test)
            break
        p.close()