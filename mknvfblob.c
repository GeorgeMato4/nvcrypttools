#include <fcntl.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mknvfblob.h"
#include "nvrcm.h"

#include "miniloaders/tegra20-miniloader.h"
#include "miniloaders/tegra30-miniloader.h"

#define BLOB_VERSION "v1.5.00000"

/* Tegra2 default constants. */
#define TEGRA2_ODMDATA 0x300D8011
#define TEGRA2_BL_ENTRYPOINT 0x40008000

/* Tegra3 default constants. */
#define TEGRA3_ODMDATA 0x40080105
#define TEGRA3_BL_ENTRYPOINT 0x4000A000
#define TEGRA3_BCT_BL_COUNT_OFFSET 0xf50
#define TEGRA3_BCT_BL_RECORD_LEN (11 * 4)
#define TEGRA3_BCT_BL_HASH_OFFSET 0xf70

#define MAX_PATH_SIZE 128
static struct {
    char bctin[MAX_PATH_SIZE];
    char bctc[MAX_PATH_SIZE];
    char bctr[MAX_PATH_SIZE];
    char blin[MAX_PATH_SIZE];
    char blout[MAX_PATH_SIZE];
    char blob[MAX_PATH_SIZE];
    int chip_type;
    int wheelie_mode;
    int key_set;
    char key[AES_BLOCK_SIZE];
    uint32_t odmdata;
} flags = {0};

static struct chip_data {
    const char *name;
    enum {
        CHIP_TYPE_TEGRA2=0x20,
        CHIP_TYPE_TEGRA3=0x30,
        CHIP_TYPE_UNKNOWN=0xFFFFFFFF
    } type;
    const char *miniloader;
    uint32_t miniloader_len;
    uint32_t entrypoint;
    uint32_t odmdata;
} chip_types[] = {
    { "ventana", CHIP_TYPE_TEGRA2,
      miniloader_tegra20, sizeof(miniloader_tegra20),
      TEGRA20_MINILOADER_ENTRY, TEGRA2_ODMDATA
    },
    { "cardhu",  CHIP_TYPE_TEGRA3,
      miniloader_tegra30, sizeof(miniloader_tegra30),
      TEGRA30_MINILOADER_ENTRY, TEGRA3_ODMDATA
    }
};

static uint32_t get_chip_type()
{
    char buf[512] = {0};
    char *hardware = NULL;
    int i;
    FILE *fd;

    if(flags.chip_type > 0)
        return flags.chip_type;

    if(!(fd = fopen("/proc/cpuinfo", "r"))) {
        perror("failed to retrieve cpu info");
        return CHIP_TYPE_UNKNOWN;
    }

    while((fgets(buf, sizeof(buf), fd)) != NULL) {
        hardware = strtok(buf, ":");

        if(!strncmp(hardware, "Hardware", 8)) {
            hardware = strtok(NULL, ":");
            break;
        }
    }

    fclose(fd);

    if(!hardware)
        return CHIP_TYPE_UNKNOWN;

    while(*hardware == ' ')
        hardware++;

    for(i=0; i < sizeof(chip_types); i++) {
        if(!strncmp(hardware, chip_types[i].name, strlen(chip_types[i].name))) {
            return chip_types[i].type;
        }
    }

    return CHIP_TYPE_UNKNOWN;
}

static struct chip_data *get_chip_data(uint32_t chip_id)
{
    int i;
    for(i=0; i < sizeof(chip_types); i++) {
        if(chip_types[i].type == chip_id) {
            return &chip_types[i];
        }
    }

    return NULL;
}

static int create_blob(nvaes_ctx ctx, int blob, int bl)
{
    char iv[AES_BLOCK_SIZE] = {0};
    char *buf, *ptr;
    int i, bytes, entrypoint;
    struct chip_data *chip;

    BlobHeader header = {0};
    nvrcm_msg *rcm;

    for(i = TYPE_VERSION; i <= TYPE_BLHASH; i++) {
        header.type = i;
        memset(header.hash, 0, sizeof(header.hash));

        switch(header.type) {
            case TYPE_VERSION:
                header.length = strlen(BLOB_VERSION);
                ptr = BLOB_VERSION;
                buf = ptr;
            break;
            case TYPE_RCMVER:
                nvrcm_create(NVRCM_CODE_VERSION, 0, 0, NULL, &ptr,
                             &header.length);
                buf = malloc(header.length);
                memcpy(buf, ptr, NVRCM_CLEAR_LEN);
            break;
            case TYPE_RCMDLEXEC:
                if(!(chip = get_chip_data(get_chip_type()))) {
                    fprintf(stderr, "Could not get chip data.\n");
                    return 0;
                }

                nvrcm_create(NVRCM_CODE_DLEXEC, chip->entrypoint,
                             chip->miniloader_len, chip->miniloader, &ptr,
                             &header.length);

                buf = malloc(header.length);
                memcpy(buf, ptr, NVRCM_CLEAR_LEN);
            break;
            case TYPE_BLHASH:
                header.length = AES_BLOCK_SIZE;
                ptr = NULL;
                buf = NULL;
            break;
        }

        if(ptr != NULL) {
            if(buf != ptr) {
                rcm = (nvrcm_msg *)buf;
                buf += NVRCM_CLEAR_LEN;
                ptr += NVRCM_CLEAR_LEN;
                header.length -= NVRCM_CLEAR_LEN;

                bytes = nvaes_encrypt(ctx, ptr, header.length,
                                      buf, header.length, iv);

                if(bytes != header.length) {
                    fprintf(stderr, "Error during encryption: %d/%d\n",
                            bytes, header.length);
                    return 0;
                }

                memset(iv, 0, sizeof(iv));
                if(!nvaes_sign(ctx, buf, header.length, rcm->hash)) {
                    return 0;
                }

                buf -= NVRCM_CLEAR_LEN;
                ptr -= NVRCM_CLEAR_LEN;
                header.length += NVRCM_CLEAR_LEN;
            }
        } else {
            buf = malloc(AES_BLOCK_SIZE);
            ptr = NULL;
            lseek(bl, 0, SEEK_SET);
            nvaes_sign_fd(ctx, bl, buf);

            memset(iv, 0, sizeof(iv));
            nvaes_encrypt(ctx, buf, AES_BLOCK_SIZE, buf, AES_BLOCK_SIZE, iv);
        }

        if(write(blob, (char *)&header, sizeof(header)) != sizeof(header)) {
            perror("Failed to write header to blob file");
            return 0;
        }

        if(write(blob, buf, header.length) != header.length) {
            perror("Failed to write data to blob file");
            return 0;
        }

        if(buf != ptr) {
            nvrcm_free(ptr);
            free(buf);
        }
    }

    return 1;
}

static int process_bct(nvaes_ctx ctx, int bctin, int bctout, int bl, int create)
{
    int sz, rc = 0;
    char *bct = NULL, *bctenc = NULL, iv[AES_BLOCK_SIZE] = {0};

    sz = lseek(bctin, 0, SEEK_END);
    lseek(bctin, 0, SEEK_SET);

    if(!(bct = malloc(sz)) || !(bctenc = malloc(sz))) {
        perror("could not allocate memory for BCT");
        goto out;
    }

    if(read(bctin, bct, sz) != sz) {
        perror("failed to read BCT");
        goto out;
    }

    switch(get_chip_type()) {
        case CHIP_TYPE_TEGRA2:
            // No processing required for tegra2.
        break;
        case CHIP_TYPE_TEGRA3:
            lseek(bl, 0, SEEK_SET);
            nvaes_sign_fd(ctx, bl, bct + TEGRA3_BCT_BL_HASH_OFFSET);
            if(create) {
                memset(bct + TEGRA3_BCT_BL_COUNT_OFFSET, 0,
                       TEGRA3_BCT_BL_RECORD_LEN + 4);
            }
        break;
        default:
            fprintf(stderr, "unsupported chip type: 0x%02x\n", get_chip_type());
            goto out;
        break;
    }

    // Encrypt the BCT.
    if(!nvaes_encrypt(ctx, bct + AES_BLOCK_SIZE, sz - AES_BLOCK_SIZE,
                      bctenc + AES_BLOCK_SIZE, sz - AES_BLOCK_SIZE, iv)) {
        perror("failed to encrypt BCT");
        goto out;
    }

    // Sign the encrypted BCT
    if(!nvaes_sign(ctx, bctenc + AES_BLOCK_SIZE, sz - AES_BLOCK_SIZE, bctenc)) {
        perror("failed to sign BCT");
        goto out;
    }

    // Write out the BCT
    if(write(bctout, bctenc, sz) != sz) {
        perror("failed to write BCT");
        goto out;
    }

    rc = 1;
out:
    free(bct);
    free(bctenc);
    return rc;
}

static int add_wheelie_ext_fd(int type, int in, int out)
{
    char buf[1024];
    int bytes = 0, total = 0;
    BlobHeader hdr = {0};

    hdr.type = type;
    hdr.length = lseek(in, 0, SEEK_END);
    lseek(in, 0, SEEK_SET);

    if(write(out, (char *)&hdr, sizeof(hdr)) != sizeof(hdr)) {
        perror("failed to write header to blob");
        return 0;
    }

    while((bytes = read(in, buf, sizeof(buf))) > 0) {
        if(write(out, buf, bytes) != bytes) {
            perror("failed to write data to blob");
            return 0;
        }

        total += bytes;
    }

    if(total != hdr.length) {
        perror("incorrect size written to blob");
        return 0;
    }

    return 1;
}

static int add_wheelie_ext(int type, char *data, int len, int out)
{
    char buf[1024];
    int bytes = 0, total = 0;
    BlobHeader hdr = {0};

    hdr.type = type;
    hdr.length = len;

    if(write(out, (char *)&hdr, sizeof(hdr)) != sizeof(hdr)) {
        perror("failed to write header to blob");
        return 0;
    }

    if(write(out, data, len) != len) {
        perror("failed to write data to blob");
        return 0;
    }

    return 1;
}

static void parse_options(int argc, char * const *argv)
{
    struct option longopts[] = {
        { "bctin", required_argument, 0, 'B' },
        { "bctc", required_argument, 0, 'C' },
        { "bctr", required_argument, 0, 'R' },
        { "blin", required_argument, 0, 'i' },
        { "blout", required_argument, 0, 'o' },
        { "blob", required_argument, 0, 'b' },
        { "chip", required_argument, 0, 'c' },
        { "odmdata", required_argument, 0, 'd' },
        { 0, 0, 0, 0}
    };

    int index, c = 0, i;

    while(
        (c=getopt_long(argc,argv,"B:C:R:i:o:b:c:WK:d:",longopts,&index)) != -1
    ) switch(c) {
        case 'B':
            strncpy(flags.bctin, optarg, sizeof(flags.bctin));
        break;
        case 'C':
            strncpy(flags.bctc, optarg, sizeof(flags.bctc));
        break;
        case 'R':
            strncpy(flags.bctr, optarg, sizeof(flags.bctr));
        break;
        case 'i':
            strncpy(flags.blin, optarg, sizeof(flags.blin));
        break;
        case 'o':
            strncpy(flags.blout, optarg, sizeof(flags.blout));
        break;
        case 'b':
            strncpy(flags.blob, optarg, sizeof(flags.blob));
        break;
        case 'c':
            flags.chip_type = strtoul(optarg, NULL, 16);
        break;
        case 'W':
            flags.wheelie_mode = 1;
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
            flags.odmdata = strtoul(optarg, NULL, 16);
        break;
    }
}

int main(int argc, char * const *argv)
{
    FILE *fp, *fw;
    char *filename;
    int bctin = 0, bctc = 0, bctr = 0, blin = 0, blout = 0, blob = 0;
    uint32_t chip = 0, odmdata = 0;
    static struct chip_data *chipdata;
    nvaes_ctx ctx;

    printf("mknvfblob\n");
    printf("---------\n\n");

    parse_options(argc, argv);
    odmdata = flags.odmdata;

    if((chip = get_chip_type()) == CHIP_TYPE_UNKNOWN) {
        fprintf(stderr, "error: unknown chip type: 0x%02x\n", chip);
        exit(3);
    }

    if((ctx = nvaes_open()) == NULL) {
        perror("Error opening AES engine");
        exit(3);
    }

    if(flags.key_set == 0) {
        if(nvaes_use_ssk(ctx, 1) == 0) {
            fprintf(stderr, "Error requesting the use of the SSK.\n");
            exit(3);
        }
    } else {
        nvaes_set_key(ctx, flags.key);
    }

    if(strlen(flags.bctin)) {
        if((bctin = open(flags.bctin, O_RDONLY)) < 0) {
            perror("failed to open BCT source file");
            exit(3);
        }

        if(chip != CHIP_TYPE_TEGRA2) {
            if(strlen(flags.bctr)) {
                if((bctr = open(flags.bctr, O_CREAT | O_RDWR | O_EXCL)) < 0) {
                    perror("failed to open recovery BCT dest file");
                    exit(3);
                }
            }
        } else {
            bctr = bctin;
        }

        if(chip != CHIP_TYPE_TEGRA2 && strlen(flags.bctc)) {
            if((bctc = open(flags.bctc, O_CREAT | O_RDWR | O_EXCL)) < 0) {
                perror("failed to open create BCT dest file");
                exit(3);
            }
        }
    } else if(chip != CHIP_TYPE_TEGRA2 && strlen(flags.bctr)) {
        fprintf(stderr, "error: --bctr given without --bctin\n");
        exit(3);
    } else if(chip != CHIP_TYPE_TEGRA2 && strlen(flags.bctc)) {
        fprintf(stderr, "error: --bctc given without --bctin\n");
        exit(3);
    }

    if((blin = open(flags.blin, O_RDONLY)) < 0) {
        perror("failed to open bootloader source file");
        exit(3);
    }

    if(chip != CHIP_TYPE_TEGRA2) {
        if((blout = open(flags.blout, O_CREAT | O_RDWR | O_EXCL)) < 0) {
            perror("failed to open bootloader dest file");
            exit(3);
        }
    } else {
        blout = blin;
    }

    if((blob = open(flags.blob, O_CREAT | O_WRONLY | O_EXCL)) < 0) {
        perror("failed to open blob dest file");
        exit(3);
    }

    setbuf(stdout, NULL);

    if(chip != CHIP_TYPE_TEGRA2) {
        printf("Encrypting BL '%s' to '%s'...", flags.blin, flags.blout);
        if(!nvaes_encrypt_fd(ctx, blin, blout)) {
            printf("failed.\n");
            exit(3);
        }
        printf("done.\n");
    }

    if(chip != CHIP_TYPE_TEGRA2 && bctr) {
        printf("Generating encrypted recovery BCT from '%s' to '%s'...",
               flags.bctin, flags.bctr);
        if(!process_bct(ctx, bctin, bctr, blout, 0)) {
            exit(3);
        }
        printf("done.\n");
    }

    if(chip != CHIP_TYPE_TEGRA2 && bctc) {
        printf("Generating encrypted create BCT from '%s' to '%s'...",
               flags.bctin, flags.bctc);
        if(!process_bct(ctx, bctin, bctc, blout, 1)) {
            exit(3);
        }
        printf("done.\n");
    }

    printf("Generating blob file '%s'...", flags.blob);
    if(!create_blob(ctx, blob, blout)) {
        printf("failed.\n");
        exit(3);
    }
    printf("done.\n");

    if(flags.wheelie_mode) {
        if(bctc) {
            printf("Adding create BCT to blob file [wheelie]...");
            if(!add_wheelie_ext_fd(TYPE_EXT_WHEELIE_BCTC, bctc, blob)) {
                printf("failed.\n");
            }
            printf("done.\n");
        }

        if(bctr) {
            printf("Adding recovery BCT to blob file [wheelie]...");
            if(!add_wheelie_ext_fd(TYPE_EXT_WHEELIE_BCTR, bctr, blob)) {
                printf("failed.\n");
            }
            printf("done.\n");
        }

        printf("Adding bootloader to blob file [wheelie]...");
        if(!add_wheelie_ext_fd(TYPE_EXT_WHEELIE_BL, blout, blob)) {
            printf("failed.\n");
        }
        printf("done.\n");

        if(!(chipdata = get_chip_data(chip))) {
            fprintf(stderr, "warning: cannot add odmdata/chipid to blob.\n");
            exit(3);
        }

        if(odmdata == 0) {
            odmdata = chipdata->odmdata;
        }

        printf("Adding odmdata to blob file [wheelie]...");
        if(!add_wheelie_ext(TYPE_EXT_WHEELIE_ODMDATA,
                            (char *)&odmdata, sizeof(uint32_t), blob)) {
            printf("failed.\n");
        }
        printf("done.\n");

        printf("Adding chip id to blob file [wheelie]...");
        if(!add_wheelie_ext(TYPE_EXT_WHEELIE_CPU_ID,
                            (char *)&chip, sizeof(uint32_t), blob)) {
            printf("failed.\n");
        }
    }
    printf("done.\n");

    return 0;
}
