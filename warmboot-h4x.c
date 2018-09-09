#include <assert.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "nvaes.h"

#define WARMBOOT_ADDR 0x40020000
#define LP0_VEC_STR "lp0_vec="

typedef struct warmboot_hdr {
    uint32_t len_insecure;
    uint32_t padding[3];
    uint8_t hash[16];
    uint8_t random_aes_block[16];
    uint32_t len_secure;
    uint32_t base_addr;
    uint32_t entry_point;
    uint32_t code_sz;
}
__attribute__((packed))
warmboot_hdr_t;

static struct {
    char in_path[PATH_MAX];
    char out_path[PATH_MAX];
    int use_sbk;
    int use_ssk;
    char key[AES_BLOCK_SIZE];
    int key_set;
    int debug;
    uint32_t base_addr;
    uint32_t entry_point;
    int decrypt;
    int encrypt;
    int inject;
} flags = {{0}};

static void parse_options(int argc, char **argv)
{
    struct option longopts[] = {
        { "in",  required_argument, 0, 'i' },
        { "out", required_argument, 0, 'o' },
        { "key", required_argument, 0, 'K' },
        { "sbk", required_argument, 0, 'b' },
        { "ssk", required_argument, 0, 's' },
        { "debug", required_argument, 0, 'D' },
        { "base-addr", required_argument, 0, 'B' },
        { "entry-point", required_argument, 0, 'E' },
        { "encrypt", required_argument, 0, 'e' },
        { "decrypt", required_argument, 0, 'd' },
        { "inject", required_argument, 0, 'I' },
        { 0, 0, 0, 0}
    };

    int index, c = 0, i;

    flags.base_addr = WARMBOOT_ADDR;
    flags.entry_point = WARMBOOT_ADDR;

    while(
        (c=getopt_long(argc,argv,"i:o:bsK:deDB:E:I",longopts,&index)) != -1
    ) switch(c) {
        case 'i':
            strncpy(flags.in_path, optarg, sizeof(flags.in_path));
        break;
        case 'o':
            strncpy(flags.out_path, optarg, sizeof(flags.out_path));
        break;
        case 'B':
            flags.base_addr = strtoul(optarg, NULL, 0);
        break;
        case 'E':
            flags.entry_point = strtoul(optarg, NULL, 0);
        break;
        case 'I':
            flags.inject = 1;
        break;
        case 'b':
            flags.use_sbk = 1;
        break;
        case 's':
            flags.use_ssk = 1;
        break;
        case 'K':
            if(strlen(optarg) == 32) {
                flags.key_set = 1;
                for(i = 0; i < sizeof(flags.key); i++) {
                    sscanf(&optarg[i * 2], "%2hhx", &flags.key[i]);
                }
            } else {
                fprintf(stderr, "invalid key length: %d\n", strlen(optarg));
                exit(3);
            }
        break;
        case 'D':
            flags.debug = 1;
        break;
        case 'd':
            flags.decrypt = 1;
            flags.encrypt = 0;
        break;
        case 'e':
            flags.encrypt = 1;
            flags.decrypt = 0;
        break;
    }
}

void print_hdr(const warmboot_hdr_t *hdr) {
    printf("\n");
    printf("len_insecure:       0x%08x\n", hdr->len_insecure);
    printf("padding[0]:         0x%08x\n", hdr->padding[0]);
    printf("padding[1]:         0x%08x\n", hdr->padding[1]);
    printf("padding[2]:         0x%08x\n", hdr->padding[2]);
    const uint8_t *h = hdr->hash;
    printf("hash:               "
            "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
            "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx\n",
            h[ 0], h[ 1], h[ 2], h[ 3], h[ 4], h[ 5], h[ 6], h[ 7],
            h[ 8], h[ 9], h[10], h[11], h[12], h[13], h[14], h[15]);
    const uint8_t *r = hdr->random_aes_block;
    printf("random_aes_block:   "
            "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
            "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx\n",
            r[ 0], r[ 1], r[ 2], r[ 3], r[ 4], r[ 5], r[ 6], r[ 7],
            r[ 8], r[ 9], r[10], r[11], r[12], r[13], r[14], r[15]);
    printf("len_secure:         0x%08x\n", hdr->len_secure);
    printf("base_addr:          0x%08x\n", hdr->base_addr);
    printf("entry_point:        0x%08x\n", hdr->entry_point);
    printf("code_sz:            0x%08x\n", hdr->code_sz);
    printf("\n");
}

int main(int argc, char **argv) {
    nvaes_ctx ctx;

    parse_options(argc, argv);
    nvaes_set_dbg(flags.debug);
    assert(flags.encrypt || flags.decrypt);

    size_t in_sz;
    uint8_t *in = mmap_file(flags.in_path, &in_sz);

    size_t out_sz;
    if (flags.encrypt) {
        out_sz = sizeof(warmboot_hdr_t) + in_sz;
    } else {
        out_sz = in_sz;
    }
    uint8_t *out = calloc(1, out_sz);
    assert(out);

    if((ctx = nvaes_open()) < 0) {
        perror("Error opening AES engine");
        exit(3);
    }

    if (flags.use_ssk) {
        printf("using ssk\n");
        if(nvaes_use_ssk(ctx, 1)) {
            fprintf(stderr, "Error setting the use of the SSK.\n");
            exit(3);
        }
    } else if (flags.use_sbk) {
        printf("using sbk\n");
        if(nvaes_use_sbk(ctx, 1)) {
            fprintf(stderr, "Error setting the use of the SBK.\n");
            exit(3);
        }
    } else if (flags.key_set) {
        char *k = flags.key;
        printf("Using key: "
            "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
            "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx\n",
            k[ 0], k[ 1], k[ 2], k[ 3], k[ 4], k[ 5], k[ 6], k[ 7],
            k[ 8], k[ 9], k[10], k[11], k[12], k[13], k[14], k[15]);
        nvaes_set_key(ctx, flags.key);
    }

    uint8_t iv[AES_BLOCK_SIZE] = {0};
    size_t clear_sz = offsetof(warmboot_hdr_t, random_aes_block);
    uint8_t calc_hash[AES_BLOCK_SIZE];

    if (flags.decrypt) {
        warmboot_hdr_t *hdr = (warmboot_hdr_t *)in;
        warmboot_hdr_t *hdr_out = (warmboot_hdr_t *)out;
        memcpy(out, in, sizeof(warmboot_hdr_t));
        print_hdr(hdr);
        uint8_t calc_hash[sizeof(hdr->hash)];
        size_t crypt_sz = hdr->len_insecure - clear_sz;
        uint8_t *h = hdr->hash;
        printf("input hash:          "
            "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
            "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx\n",
            h[ 0], h[ 1], h[ 2], h[ 3], h[ 4], h[ 5], h[ 6], h[ 7],
            h[ 8], h[ 9], h[10], h[11], h[12], h[13], h[14], h[15]);
        if(nvaes_sign(ctx, in + clear_sz, crypt_sz, calc_hash) == 0) {
            fprintf(stderr, "Failed to sign file.\n");
            exit(3);
        }
        h = calc_hash;
        printf("calc hash:           "
            "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
            "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx\n",
            h[ 0], h[ 1], h[ 2], h[ 3], h[ 4], h[ 5], h[ 6], h[ 7],
            h[ 8], h[ 9], h[10], h[11], h[12], h[13], h[14], h[15]);
        if (memcmp(hdr->hash, calc_hash, sizeof(calc_hash))) {
            printf("calculated hash mismatch\n");
        }
        if(nvaes_decrypt(ctx, in + clear_sz, crypt_sz, out + clear_sz, crypt_sz, iv) == 0) {
            fprintf(stderr, "Failed to decrypt file.\n");
            exit(3);
        }
        print_hdr(hdr_out);
        memcpy_to_file(flags.out_path, out + sizeof(warmboot_hdr_t), hdr_out->code_sz);
    } else {
        warmboot_hdr_t *hdr = (warmboot_hdr_t *)out;
        hdr->len_insecure = in_sz + sizeof(warmboot_hdr_t);
        hdr->len_secure = hdr->len_insecure;
        hdr->base_addr = flags.base_addr;
        hdr->entry_point = flags.entry_point;
        hdr->code_sz = in_sz;
        print_hdr(hdr);
        size_t crypt_sz = hdr->len_insecure - clear_sz;
        memcpy(out + sizeof(warmboot_hdr_t), in, in_sz);
        uint8_t *enc_buf = calloc(1, crypt_sz);
        if(nvaes_encrypt(ctx, out + clear_sz, crypt_sz, enc_buf, crypt_sz, iv) == 0) {
            fprintf(stderr, "Failed to encrypt file.\n");
            exit(3);
        }
        memcpy(out + clear_sz, enc_buf, crypt_sz);
        if(nvaes_sign(ctx, out + clear_sz, crypt_sz, calc_hash) == 0) {
            fprintf(stderr, "Failed to sign file.\n");
            exit(3);
        }
        uint8_t *h = calc_hash;
        printf("calc hash:           "
            "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx"
            "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx\n",
            h[ 0], h[ 1], h[ 2], h[ 3], h[ 4], h[ 5], h[ 6], h[ 7],
            h[ 8], h[ 9], h[10], h[11], h[12], h[13], h[14], h[15]);
        memcpy(out + offsetof(warmboot_hdr_t, hash), calc_hash, sizeof(calc_hash));
        print_hdr(hdr);
        memcpy_to_file(flags.out_path, out, hdr->len_insecure);

        if (flags.inject) {
            int fcmd;
            if((fcmd = open("/proc/cmdline", O_RDONLY)) < 0) {
                fprintf(stderr, "Error opening input file: %s\n", flags.in_path);
                perror("Error");
                exit(3);
            }
            int cmd_bytes;
            char cmd_buf[1024*8];
            cmd_bytes = read(fcmd, cmd_buf, sizeof(cmd_buf));
            assert(cmd_bytes > 0);
            char *lp0_arg = strstr(cmd_buf, LP0_VEC_STR);
            assert(lp0_arg);
            char *lp0_sz_str = lp0_arg + strlen(LP0_VEC_STR);
            uint32_t lp0_sz = strtoul(lp0_sz_str, NULL, 10);
            char *at_ptr = strstr(lp0_sz_str, "@");
            assert(at_ptr);
            char *lp0_addr_str = at_ptr + 1;
            uint32_t lp0_addr = strtoul(lp0_addr_str, NULL, 16);
            printf("lp0 addr: 0x%08x size: 0x%08x\n", lp0_addr, lp0_sz);

            long page_size = sysconf(_SC_PAGE_SIZE);
            assert(lp0_addr % page_size == 0);
            assert(lp0_sz % page_size == 0);
            assert(hdr->len_insecure <= lp0_sz);

            int devmem = open("/dev/mem", O_RDWR);
            uint8_t *mapping = mmap(NULL, lp0_sz, PROT_READ | PROT_WRITE,
                MAP_SHARED, devmem, lp0_addr);
            if (mapping == MAP_FAILED) {
                perror("Could not map memory");
                exit(3);
            }
            memcpy(mapping, out, hdr->len_insecure);
            __builtin___clear_cache(mapping, mapping + lp0_sz);
            close(devmem);
            sync();
        }
    }
    
    nvaes_close(ctx);

    return 0;
}
