#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <limits.h>

#include "mknvfblob.h"
#include "nvaes.h"
#include "nvrcm.h"
#include "device_data.h"
#include "blob.h"
// Use paths without prefix so we can use -I to decide target
#include "device.h"


// Generic defines applicable to all devices.
// Device-specific defines are in device.h
#define DESTBLOB "blob.bin"
#define DESTEBT "bootloader.ebt"
#define DESTBCTR "recovery.bct"
#define DESTBCTC "create.bct"
#define DESTLOG "blob.log"
#define DESTSUBDIR "AndroidRoot"

#define TMP_MOUNT_PATH "/tmp"

#ifndef BLOB_VERSION
#define BLOB_VERSION "v1.5.00000"
#endif

#define CHECK_
//#define ENABLE_DEBUG


#ifdef ENABLE_DEBUG
#define DEBUG_LOG(...) append_log(__VA_ARGS__)
#else
#define DEBUG_LOG(...)
#endif


static FILE* logfile = NULL;

void append_log(char *format, ...)
{
    char buffer[1024];
    va_list args;
    va_start(args, format);
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end (args);
    if(logfile != NULL)
    {
        fprintf(logfile, "LOG: %s\n", buffer);
        fflush(logfile);
    }
}

void open_log()
{
    logfile = fopen("/tmp/AndroidRoot/blob.log", "w+");;
}

void close_log()
{
}

unsigned char* get_bootloader(char *filename, int *size)
{
  char magic_tag[SECURE_MAGIC_SIZE] = {0};

  FILE *blfile = NULL;
  int ret;
  header_type header;
  part_type partinfo;
  unsigned char *bldata;
  int blsize;

  *size = 0;
  memset(&header, 0, sizeof(header_type));
  memset(&partinfo, 0, sizeof(part_type));
  blfile = fopen(filename, "rb");

  if(blfile == NULL)
  {
    append_log("Unable to open file %s\n", filename);
    return NULL;
  }

  ret = fread (magic_tag, SECURE_MAGIC_SIZE, 1, blfile);
  if(!memcmp(magic_tag, SECURE_MAGIC, SECURE_MAGIC_SIZE))
  {
    fseek(blfile, SECURE_OFFSET, SEEK_SET);
  } else if(!memcmp(magic_tag, MAGIC, MAGIC_SIZE))
  {
    fseek(blfile, 0, SEEK_SET);
  } else
  {
    fclose(blfile);
    append_log("Invalid blob\n");
    return NULL;
  }

  fread(&header, sizeof(header_type), 1, blfile);
  if(header.num_parts != 1)
  {
    append_log("Invalid blob!?");
    return NULL;
  }
  ret = fread(&partinfo, sizeof(part_type), 1, blfile);
  if(strncmp(partinfo.name, "XBT", 3))
  {
    append_log("Invalid blob! Name: %.*s\n", partinfo.name, 3);
    return NULL;
  }
  blsize = partinfo.size + (16 - (partinfo.size % 16));
  append_log("Padded bootloader with %d bytes\n", (16 - (partinfo.size % 16)));
  bldata = malloc(blsize);
  memset(bldata, 0, blsize);

  if(bldata == NULL)
  {
    append_log("Unable to allocate memory for bootloader\n");
    return NULL;
  }
  ret = fread(bldata, 1, partinfo.size, blfile);
  if(ret != partinfo.size)
  {
    append_log("Error reading all of the bootloader\n");
    free(bldata);
    fclose(blfile);
    return NULL;
  }
  if(blsize > partinfo.size)
      bldata[partinfo.size] = 0x80;
  *size = blsize;
  return bldata;
}

static uint32_t get_chip_type()
{
    char buf[512] = {0};
    char *hardware = NULL;
    FILE *fd;

    if(!(fd = fopen("/proc/cpuinfo", "r"))) {
        append_log("failed to retrieve cpu info");
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

        if(!strncmp(hardware, device_data.name, strlen(device_data.name))) {
            return device_data.type;
    }

    return CHIP_TYPE_UNKNOWN;
}

static int create_blob(nvaes_ctx ctx, int blob, int bl)
{
    unsigned char iv[AES_BLOCK_SIZE] = {0};
    unsigned char *buf=NULL, *ptr=NULL;
    int i, bytes, entrypoint;

    BlobHeader header = {0};
    nvrcm_msg *rcm;

    for(i = TYPE_VERSION; i <= TYPE_BLHASH; i++) {
        header.type = i;
        memset(header.hash, 0, sizeof(header.hash));

        switch(header.type) {
            case TYPE_VERSION:
                header.length = strlen(BLOB_VERSION);
                ptr = (unsigned char*)strdup(BLOB_VERSION);
                buf = ptr;
            break;
            case TYPE_RCMVER:
                nvrcm_create(NVRCM_CODE_VERSION, 0, 0, NULL, &ptr,
                             (int32_t *)&header.length);
                buf = malloc(header.length);
                memcpy(buf, ptr, NVRCM_CLEAR_LEN);
            break;
            case TYPE_RCMDLEXEC:
                nvrcm_create(NVRCM_CODE_DLEXEC, device_data.entrypoint,
                             device_data.miniloader_len, device_data.miniloader, &ptr,
                             (int32_t*)&header.length);

                buf = malloc(header.length);
                memcpy(buf, ptr, NVRCM_CLEAR_LEN);
            break;
            case TYPE_BLHASH:
                header.length = AES_BLOCK_SIZE;
                ptr = NULL;
                buf = NULL;
            break;
            // We handle all possible cases, so quelch warnings
            default:
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
                   append_log("Error during encryption: %d/%d",
                            bytes, header.length);
                    return 0;
                }

                memset(iv, 0, sizeof(iv));
                if(!nvaes_sign(ctx, buf, header.length, (unsigned char*)rcm->hash)) {
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
            append_log("Failed to write header to blob file");
            return 0;
        }

        if(write(blob, buf, header.length) != header.length) {
            append_log("Failed to write data to blob file");
            return 0;
        }

        if(buf != ptr) {
            if(ptr != NULL)
              nvrcm_free(ptr);
            if(buf != NULL)
              free(buf);
        }
    }
    return 1;
}

static int process_bct(nvaes_ctx ctx, int bctout, int bl, int create)
{
    int rc = 0, sz = device_data.bct_len;
    unsigned char *bctbuf = NULL, *bctenc = NULL, iv[AES_BLOCK_SIZE] = {0};

    if(!(bctbuf = malloc(sz)) || !(bctenc = malloc(sz))) {
        append_log("could not allocate memory for BCT");
        goto out;
    }

    memcpy(bctbuf, device_data.bct, sz);

    switch(get_chip_type()) {
        case CHIP_TYPE_TEGRA3:
            lseek(bl, 0, SEEK_SET);
            nvaes_sign_fd(ctx, bl, bctbuf + BCT_BL_HASH_OFFSET);
            if(create) {
                memset(bctbuf + BCT_BL_COUNT_OFFSET, 0,
                       BCT_BL_RECORD_LEN + 4);
            }
        break;
        default:
            append_log("unsupported chip type: 0x%02x", get_chip_type());
            goto out;
        break;
    }

    // Encrypt the BCT.
    if(!nvaes_encrypt(ctx, bctbuf + AES_BLOCK_SIZE, sz - AES_BLOCK_SIZE,
                      bctenc + AES_BLOCK_SIZE, sz - AES_BLOCK_SIZE, iv)) {
        append_log("failed to encrypt BCT");
        goto out;
    }

    // Sign the encrypted BCT
    if(!nvaes_sign(ctx, bctenc + AES_BLOCK_SIZE, sz - AES_BLOCK_SIZE, bctenc)) {
        append_log("failed to sign BCT");
        goto out;
    }

    // Write out the BCT
    if(write(bctout, bctenc, sz) != sz) {
        append_log("failed to write BCT");
        goto out;
    }

    rc = 1;
out:
    free(bctbuf);
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
        append_log("failed to write header to blob");
        return 0;
    }

    while((bytes = read(in, buf, sizeof(buf))) > 0) {
        if(write(out, buf, bytes) != bytes) {
            append_log("failed to write data to blob");
            return 0;
        }

        total += bytes;
    }

    if(total != hdr.length) {
        append_log("incorrect size written to blob");
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
        append_log("failed to write header to blob");
        return 0;
    }

    if(write(out, data, len) != len) {
        append_log("failed to write data to blob");
        return 0;
    }

    return 1;
}

int nvblob_generate()
{
    unsigned char *buf, iv[AES_BLOCK_SIZE] = {0};
    int bctc = 0, bctr = 0, blout = 0, blob = 0, blsize;
    uint32_t chip = 0;
    static struct chip_data *chipdata;
    nvaes_ctx ctx;
    char cwd[PATH_MAX] = "/"; // Sane default
    unsigned char *bldata;
    int ret=0;

    if(getcwd(cwd, PATH_MAX) == NULL)
    {
        append_log("Error getting current dir: %s", strerror(errno));
    }

    if(chdir(TMP_MOUNT_PATH "/" DESTSUBDIR)) {
        append_log("failed to chdir to dest dir");
        ret = 1;
        goto fail;
    }
    if((chip = get_chip_type()) != CHIP_TYPE_TEGRA3) {
        append_log("error: unsupported chip type: 0x%02x", chip);
        ret = 2;
        goto fail;
    }

    if((ctx = nvaes_open()) == NULL) {
        append_log("Error opening AES engine: %s", strerror(errno));
        ret = 3;
        goto fail;
    }

    if(nvaes_use_sbk(ctx, 1) == 0) {
        append_log("Error requesting the use of the SSK.");
        ret = 4;
        goto fail;
    }

    if((bctr = open(DESTBCTR, O_CREAT | O_TRUNC | O_RDWR, 0664)) < 0) {
        append_log("failed to open recovery BCT dest file");
        ret = 5;
        goto fail;
    }

    if((bctc = open(DESTBCTC, O_CREAT | O_TRUNC | O_RDWR, 0664)) < 0) {
        append_log("failed to open create BCT dest file");
        ret = 6;
        goto fail;
    }

    if((blout = open(DESTEBT, O_CREAT | O_TRUNC | O_RDWR, 0664)) < 0) {
        ret = 7;
        append_log("failed to open bootloader dest file");
        goto fail;
    }

    if((blob = open(DESTBLOB, O_CREAT | O_TRUNC | O_WRONLY, 0664)) < 0) {
        append_log("failed to open blob dest file");
        ret = 8;
        goto fail;
    }

    append_log("Generating encrypted EBT file '%s'...", DESTEBT);

    bldata = get_bootloader("/etc/AndroidRoot/bootloader.blob", &blsize);
    if(bldata == NULL)
    {
        append_log("Error retrieving bootloader\n");
        ret = 9;
        goto fail;
    }

    if(!(buf = malloc(blsize))) {
        append_log("failed to allocate memory");
        ret = 9;
        goto fail;
    }

    memset(iv, 0, sizeof(iv));
    if(!nvaes_encrypt(ctx, bldata, blsize, buf, blsize, iv)) {
        append_log("failed.");
        ret = 10;
        goto fail;
    }

    if(write(blout, buf, blsize) != blsize) {
        append_log("failed.");
        ret = 11;
        goto fail;
    }
    free(bldata);
    bldata = NULL;
    append_log("done.");

    append_log("Generating encrypted recovery BCT file '%s'...", DESTBCTR);
    if(!process_bct(ctx, bctr, blout, 0)) {
        append_log("failed.");
        ret = 12;
        goto fail;
    }
    append_log("done.");

    append_log("Generating encrypted create BCT file '%s'...", DESTBCTC);
    if(!process_bct(ctx, bctc, blout, 1)) {
        append_log("failed.");
        ret = 13;
        goto fail;
    }
    append_log("done.");

    append_log("Generating blob file '%s'...", DESTBLOB);
    if(!create_blob(ctx, blob, blout)) {
        append_log("failed.");
        ret = 14;
        goto fail;
    }
    append_log("done.");

    append_log("Adding create BCT to blob file [wheelie]...");
    if(!add_wheelie_ext_fd(TYPE_EXT_WHEELIE_BCTC, bctc, blob)) {
        append_log("failed.");
        ret = 15;
        goto fail;
    }
    append_log("done.");

    append_log("Adding recovery BCT to blob file [wheelie]...");
    if(!add_wheelie_ext_fd(TYPE_EXT_WHEELIE_BCTR, bctr, blob)) {
        append_log("failed.");
        ret = 16;
        goto fail;
    }
    append_log("done.");

    append_log("Adding bootloader to blob file [wheelie]...");
    if(!add_wheelie_ext_fd(TYPE_EXT_WHEELIE_BL, blout, blob)) {
        append_log("failed.");
        ret = 17;
        goto fail;
    }
    append_log("done.");

    append_log("Adding odmdata to blob file [wheelie]...");
    if(!add_wheelie_ext(TYPE_EXT_WHEELIE_ODMDATA,
                        (char *)&device_data.odmdata, sizeof(uint32_t), blob)) {
        append_log("failed.");
        ret = 18;
        goto fail;
    }
    append_log("done.");

    append_log("Adding chip id to blob file [wheelie]...");
    if(!add_wheelie_ext(TYPE_EXT_WHEELIE_CPU_ID,
                        (char *)&device_data, sizeof(uint32_t), blob)) {
        append_log("failed.");
        ret = 19;
        goto fail;
    }
    append_log("done.");
    goto end;

fail:
    unlink(DESTBLOB);
    unlink(DESTBCTC);
    unlink(DESTBCTR);
    unlink(DESTEBT);
    ret = -1;
end:
    close(bctr);
    close(bctc);
    close(blob);
    close(blout);
    if(chdir(cwd))
    {
        append_log("Error restoring wd: %s\n", strerror(errno));
    }
    return ret;
}



int main(int argc, char * const *argv)
{
    char *buf, iv[AES_BLOCK_SIZE] = {0};
    int bctc = 0, bctr = 0, blout = 0, blob = 0, log = 0;
    uint32_t chip = 0;
    static struct chip_data *chipdata;
    nvaes_ctx ctx;
    int i,j,k,ret=0;

// TODO: Attempt this once files are ready on loopback fs
/*        if(mount(DATADEV, DATADIR, DATAFS, MS_SYNCHRONOUS, "")) {
            append_log("failed to mount data partition");
            goto fail;
        }*/
    append_log("BrickMeNot " DEVICE_NAME);
    append_log("Initialized...");

    open_log();

    // Generate files on loopback
    append_log("Starting blob generation");
    ret = nvblob_generate(device_data);
    if(!ret)
        append_log("Blob generation done");
    else
        append_log("Blog generation failed");
    // Copy files to internal storage for safe keeping
    //copy_blobs(TMP_MOUNT_PATH, DESTDIR);
    DEBUG_LOG("Closing logfile");
    close_log();

	return ret;
}
