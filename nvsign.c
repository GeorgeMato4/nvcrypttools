#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "nvaes.h"

int main(int argc, char **argv)
{
    unsigned char iv[AES_BLOCK_SIZE] = {0};
    unsigned char out[AES_BLOCK_SIZE] = {0};
    int fi, i;
    nvaes_ctx ctx;

    if(argc < 2) {
        printf("Usage: %s <file sign>\n", argv[0]);
        exit(3);
    }

    if((fi = open(argv[1], O_RDONLY)) <= 0) {
        fprintf(stderr, "Error opening input file: %s\n", argv[1]);
        perror("Error");
        exit(3);
    }

    if((ctx = nvaes_open()) < 0) {
        perror("Error opening AES engine");
        exit(3);
    }

    if(nvaes_use_sbk(ctx, 1) == 0) {
        fprintf(stderr, "Error requesting the use of the SSK.\n");
        exit(3);
    }

    if(nvaes_sign_fd(ctx, fi, out)) {
        printf("Signature: ");
        for(i = 0; i < sizeof(out); i++)
            printf("%02x ", out[i]);
        printf("\n");
    } else {
        fprintf(stderr, "Failed to sign file.\n");
        exit(3);
    }

    nvaes_close(ctx);
    close(fi);
    return 0;
}
