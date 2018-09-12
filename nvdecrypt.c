#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>

#include "nvaes.h"

static struct {
    char in_path[PATH_MAX];
    char out_path[PATH_MAX];
    int use_sbk;
    int use_ssk;
    char key[AES_BLOCK_SIZE];
    int key_set;
    int debug;
} flags = {{0}};

static void parse_options(int argc, char * const *argv)
{
    struct option longopts[] = {
        { "in",  required_argument, 0, 'i' },
        { "out", required_argument, 0, 'o' },
        { "key", required_argument, 0, 'K' },
        { "sbk", required_argument, 0, 'b' },
        { "ssk", required_argument, 0, 's' },
        { "debug", required_argument, 0, 'd' },
        { 0, 0, 0, 0}
    };

    int index, c = 0, i;

    while(
        (c=getopt_long(argc,argv,"i:o:bsK:d",longopts,&index)) != -1
    ) switch(c) {
        case 'i':
            strncpy(flags.in_path, optarg, sizeof(flags.in_path));
        break;
        case 'o':
            strncpy(flags.out_path, optarg, sizeof(flags.out_path));
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
        case 'd':
            flags.debug = 1;
        break;
    }
}

int main(int argc, char **argv)
{
    char iv[AES_BLOCK_SIZE] = {0};
    char out[NVAES_PAGE_SIZE];
    char in[NVAES_PAGE_SIZE];
    int bytes, fi, fo;
    nvaes_ctx ctx;

    parse_options(argc, argv);

    nvaes_set_dbg(flags.debug);

    if((fi = open(flags.in_path, O_RDONLY)) <= 0) {
        fprintf(stderr, "Error opening input file: %s\n", flags.in_path);
        perror("Error");
        exit(3);
    }

    if((fo = open(flags.out_path, O_WRONLY | O_CREAT | O_TRUNC)) <= 0) {
        fprintf(stderr, "Error opening output file: %s\n", flags.out_path);
        perror("Error");
        exit(3);
    }

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

    if(nvaes_decrypt_fd(ctx, fi, fo) == 0) {
        fprintf(stderr, "Failed to decrypt file.\n");
        exit(3);
    }

    nvaes_close(ctx);
    close(fo);
    close(fi);
    return 0;
}
