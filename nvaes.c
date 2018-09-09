#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include "nvaes.h"

#ifndef MIN
#define MIN(x,y) ((x <= y) ? x : y)
#endif

#ifndef MAX
#define MAX(x,y) ((x <= y) ? y : x)
#endif

typedef struct {
    int handle;
    unsigned char key[AES_KEYSIZE_128];
    unsigned char iv[AES_BLOCK_SIZE];
    int use_ssk;
    int use_sbk;
} nvaes_ctx_priv;

int nvaes_dbg;

void *mmap_file(const char *path, size_t *sz)
{
    int fd;
    struct stat st;
    void *ptr;

    fd = open(path, O_RDONLY);
    if(fd == -1)
        perror("open");
    if(fstat(fd, &st) != 0)
        perror("fstat");

    ptr = mmap(0, st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if(ptr==NULL)
        perror("mmap");
    close(fd);

    *sz = st.st_size;

    return ptr;
}

void memcpy_to_file(const char *fname, uint8_t *ptr, size_t size)
{
    FILE *fp;

    fp = fopen(fname, "wb");
    fwrite(ptr, size, 1, fp);
    fclose(fp);
}

void nvaes_set_dbg(int dbg_on) {
    nvaes_dbg = dbg_on;
}

static void debug(const char *fmt, ...)
{
    #ifdef NVAES_DEBUG_ENABLE
    if (!nvaes_dbg) {
        return;
    }
    static int prefix = 0;
    va_list args;
    if(prefix == 0) {
        fprintf(stderr, "debug> ");
        prefix = 1;
    }

    va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);

    if(strstr(fmt, "\n")) {
        prefix = 0;
    }
    #endif
}

static void dump(const char *label, const unsigned char *data, int len)
{
    #ifdef NVAES_DEBUG_ENABLE
    int i;

    debug("%s dump (offset: 0x%08lx, size: %d):-\n",
          label, (unsigned long int)data, len);

    for(i = 0; i < len; i++) {
        debug("%02x ", (unsigned char)data[i]);
        if((i + 1) % 16 == 0)
            debug("\n", i);
    }

    debug("\n");
    #endif
}

static void leftshift(unsigned char *in, unsigned char *out, unsigned int size)
{
    unsigned int carry=0;
    int i;

    for(i=0;i<size; i++) {
        int j = size - 1 - i;
        out[j] = (in[j] << 1) | carry;
        carry = in[j] >> 7;
    }
}

static void generate_subkeys(nvaes_ctx ctx, unsigned char* K1, unsigned char *K2)
{
    unsigned char zeroval[AES_BLOCK_SIZE] = {0};
    unsigned char L[AES_BLOCK_SIZE] = {0};

    nvaes_encrypt(ctx, zeroval, sizeof(zeroval), L, sizeof(L), zeroval);
    dump("L", L, sizeof(L));
    leftshift(L, K1, AES_BLOCK_SIZE);
    dump("K1Pre", K1, AES_BLOCK_SIZE);

    if((L[0] >> 7) != 0) {
        K1[15] ^= 0x87;
    }

    leftshift(K1, K2, AES_BLOCK_SIZE);

    if((K1[0] >> 7) != 0) {
        K2[15] ^= 0x87;
    }
}

static void xor_128(unsigned char *X, unsigned char *Y, unsigned char *out)
{
    int i;

    for(i=0; i<AES_BLOCK_SIZE; i++) {
        out[i] = X[i] ^ Y[i];
    }
}

static int raw_crypt(nvaes_ctx ctx, unsigned char mode, unsigned char *src, int sz, unsigned char *dest, unsigned char *iv)
{
    nvaes_ctx_priv *priv = (nvaes_ctx_priv *)ctx;
    struct tegra_crypt_req req = {0};
    int ret;

    req.op = TEGRA_CRYPTO_CBC;
    req.encrypt = mode;
    req.plaintext = src;
    req.plaintext_sz = sz;
    req.result = dest;
    req.keylen = AES_KEYSIZE_128;
    req.ivlen = AES_BLOCK_SIZE;
    memcpy(req.iv, iv, AES_BLOCK_SIZE);

    if(!priv->use_ssk && !priv->use_sbk) {
        memset(req.key, 0, sizeof(req.key));
        memcpy(req.key, priv->key, MIN(sizeof(req.key), sizeof(priv->key)));
    }

    #ifdef NVAES_DEBUG_RAW_CRYPT
    debug("raw_crypt: processing %d bytes\n", sz);
    #ifdef NVAES_DEBUG_DATA
    dump("src", src, sz);
    dump("req", (unsigned char *)&req, sizeof(req));
    dump("req.op", (unsigned char *)&req.op, sizeof(req.op));
    dump("req.encrypt", &req.encrypt, sizeof(req.encrypt));
    dump("req.key", &req.key, sizeof(req.key));
    dump("req.keylen", (unsigned char *)&req.keylen, sizeof(req.keylen));
    dump("req.iv", &req.iv, sizeof(req.iv));
    dump("req.ivlen", (unsigned char *)&req.ivlen, sizeof(req.ivlen));
    dump("req.plaintext", &req.plaintext, sizeof(req.plaintext));
    dump("req.plaintext_sz",(unsigned char *)&req.plaintext_sz,sizeof(req.plaintext_sz));
    dump("req.result", &req.result, sizeof(req.result));
    #endif
    #endif

    do {
        ret = ioctl(priv->handle, TEGRA_CRYPTO_IOCTL_PROCESS_REQ, &req);
        // usleep(1000);

        if(ret != 0) {
            perror("error requesting crypt");
            return -1;
        }

        // FIXME: We should probably exit this loop at some point
        //        rather than looping ad infinitum.
        #ifdef NVAES_DEBUG_RAW_CRYPT
        #ifdef NVAES_DEBUG_DATA
        dump("result", dest, sz);
        #endif
        #endif
    } while(memcmp(req.result, req.plaintext, req.plaintext_sz) == 0);

    return 1;
}


int nvaes_use_ssk(nvaes_ctx ctx, int use_ssk)
{
    nvaes_ctx_priv *priv = (nvaes_ctx_priv *)ctx;

    if(ioctl(priv->handle, TEGRA_CRYPTO_IOCTL_NEED_SSK, use_ssk) < 0) {
        perror("error setting SSK usage");
        priv->use_ssk = 0;
        return -1;
    }

    priv->use_ssk = use_ssk;
    priv->use_sbk = 0;
    return 0;
}

int nvaes_use_sbk(nvaes_ctx ctx, int use_sbk)
{
    nvaes_ctx_priv *priv = (nvaes_ctx_priv *)ctx;

    if(ioctl(priv->handle, TEGRA_CRYPTO_IOCTL_NEED_SBK, use_sbk) < 0) {
        perror("error setting SBK usage");
        priv->use_sbk = 0;
        return -1;
    }

    priv->use_sbk = use_sbk;
    priv->use_ssk = 0;
    return 0;
}

void nvaes_set_key(nvaes_ctx ctx, char key[AES_BLOCK_SIZE])
{
    nvaes_ctx_priv *priv = (nvaes_ctx_priv *)ctx;
    memset(priv->key, 0, sizeof(priv->key));
    memcpy(priv->key, key, MIN(sizeof(priv->key), AES_BLOCK_SIZE));
    priv->use_sbk = 0;
    priv->use_ssk = 0;
}

nvaes_ctx nvaes_open()
{
    int handle;
    nvaes_ctx_priv *priv;

    if((handle = open(NVAES_TEGRA_DEVICE, 0)) < 0) {
        return NULL;
    }

    if(!(priv = malloc(sizeof(nvaes_ctx_priv)))) {
        close(handle);
        return NULL;
    }

    memset(priv, 0, sizeof(nvaes_ctx_priv));
    priv->handle = handle;
    return (nvaes_ctx)priv;
}

void nvaes_close(nvaes_ctx ctx)
{
    nvaes_ctx_priv *priv = (nvaes_ctx_priv *)ctx;
    close(priv->handle);
    free(priv);
}

unsigned char *nvaes_pad(unsigned char *buf, int *sz)
{
    unsigned char *new = buf;

    if(*sz % AES_BLOCK_SIZE != 0) {
        debug("Padding data: %d --> %d\n", *sz, NVAES_PADDED_SIZE(*sz));

        new = calloc(NVAES_PADDED_SIZE(*sz), sizeof(char));
        memcpy(new, buf, *sz);
        new[*sz] = '\x80';
        *sz = NVAES_PADDED_SIZE(*sz);
    }

    return new;
}

int nvaes_crypt(nvaes_ctx ctx,unsigned char mode,unsigned char *src,int sz,unsigned char *out,int len,unsigned char *iv)
{
    unsigned char T1[NVAES_PAGE_SIZE];
    unsigned char T2[NVAES_PAGE_SIZE];
    unsigned char T3[NVAES_PAGE_SIZE];
    unsigned char *buf = src;
    int curr = 0;

    if(mode != 0 && mode != 1) {
        fprintf(stderr, "Invalid mode: %d\n", mode);
        return -1;
    }

    if(sz % AES_BLOCK_SIZE == 0) {
        buf = src;
    } else if(mode == 0) {
        fprintf(stderr, "Invaild size for decrypt: %d\n", sz);
        return -1;
    } else {
        buf = nvaes_pad(src, &sz);

        if(sz > len) {
            fprintf(stderr, "Output buffer (%d bytes) insufficient for: %d\n",
                    len, sz);
            return -1;
        }
    }

    while(sz > 0) {
        int blocksize = MIN(sz, NVAES_PAGE_SIZE);
        int c = 0;

        #ifdef NVAES_DEBUG_CRYPT
        debug("nvaes_crypt: processing blocksize: %d\n", blocksize);
        #endif

        do {
            #ifdef NVAES_DEBUG_CRYPT
            debug("nvaes_crypt: inner process loop: %d\n", c);
            #endif
            usleep(c * 1000);
            raw_crypt(ctx, mode, &buf[curr], blocksize, T1, iv);
            #ifdef NVAES_DEBUG_CRYPT
            #ifdef NVAES_DEBUG_DATA
            dump("T1", T1, blocksize);
            #endif
            #endif
            raw_crypt(ctx, mode, &buf[curr], blocksize, T2, iv);
            #ifdef NVAES_DEBUG_CRYPT
            #ifdef NVAES_DEBUG_DATA
            dump("T2", T2, blocksize);
            #endif
            #endif
            raw_crypt(ctx, mode, &buf[curr], blocksize, T3, iv);
            #ifdef NVAES_DEBUG_CRYPT
            #ifdef NVAES_DEBUG_DATA
            dump("T3", T3, blocksize);
            #endif
            #endif
            c++; // ;-)
        } while(memcmp(T1, T2, blocksize) || memcmp(T2, T3, blocksize));

        #ifdef NVAES_DEBUG_CRYPT
        debug("nvaes_crypt: exit inner process loop...\n");
        #endif

        memcpy(&out[curr], T1, blocksize);

        if(mode == 1)
            memcpy(iv, &out[curr+blocksize-AES_BLOCK_SIZE], AES_BLOCK_SIZE);
        else
            memcpy(iv, &src[curr+blocksize-AES_BLOCK_SIZE], AES_BLOCK_SIZE);

        curr += blocksize;
        sz -= blocksize;
    }

    if(mode == 0) {
        // TODO: Trim padding (just subtract from curr)
    }

    if(buf != src) free(buf);
    return curr;
}

int nvaes_encrypt(nvaes_ctx ctx, unsigned char *src, int sz, unsigned char *dest, int len, unsigned char *iv)
{
    return nvaes_crypt(ctx, 1, src, sz, dest, len, iv);
}

int nvaes_decrypt(nvaes_ctx ctx, unsigned char *src, int sz, unsigned char *dest, int len, unsigned char *iv)
{
    return nvaes_crypt(ctx, 0, src, sz, dest, len, iv);
}

int nvaes_sign(nvaes_ctx ctx, unsigned char *src, int sz, unsigned char *out)
{
    unsigned char K1[AES_BLOCK_SIZE] = {0};
    unsigned char K2[AES_BLOCK_SIZE] = {0};
    unsigned char M_last[AES_BLOCK_SIZE] = {0};
    unsigned char iv[AES_BLOCK_SIZE] = {0};
    unsigned char *tmp, *data = src;
    unsigned int n;

    if(sz % AES_BLOCK_SIZE != 0) {
        fprintf(stderr, "Data to sign will be padded");
        data = nvaes_pad(src, &sz);
    }

    if(!(tmp = malloc(sz))) {
        fprintf(stderr, "Failed to allocate memory for temporary buffer.");
        return 0;
    }

    n = sz / AES_BLOCK_SIZE;

    debug("Signing blocks: %d\n", n);

    generate_subkeys(ctx, K1, K2);

    dump("K1", K1, sizeof(K1));
    dump("K2", K2, sizeof(K2));

    xor_128(&data[AES_BLOCK_SIZE*(n-1)], K1, M_last);
    dump("M_last", M_last, sizeof(M_last));
    dump("M_last IV", iv, AES_BLOCK_SIZE);

    debug("Encrypting %d blocks, size: %d for signing...\n",
          n, n * AES_BLOCK_SIZE);
    nvaes_encrypt(ctx, data, (n-1) * AES_BLOCK_SIZE, tmp, sz, iv);

    debug("Doing final encrypt for signing...\n");
    nvaes_encrypt(ctx, M_last, sizeof(M_last), out, AES_BLOCK_SIZE, iv);
    dump("CMAC", out, AES_BLOCK_SIZE);

    if(data != src) free(data);
    free(tmp);
    return 1;
}

int nvaes_sign_fd(nvaes_ctx ctx, int fd, unsigned char *out)
{
    unsigned char *buf;
    int pos = lseek(fd, 0, SEEK_CUR);
    int sz = lseek(fd, 0, SEEK_END) - pos;
    lseek(fd, pos, SEEK_SET);

    if(!(buf = malloc(sz))) {
        perror("failed to allocate memory to sign file");
        return 0;
    }

    if(read(fd, buf, sz) != sz) {
        perror("failed to read file to sign");
        return 0;
    }

    sz = nvaes_sign(ctx, buf, sz, out);
    free(buf);
    return sz;
}

int nvaes_encrypt_fd(nvaes_ctx ctx, int fdin, int fdout)
{
    unsigned char iv[AES_BLOCK_SIZE] = {0};
    unsigned char in[NVAES_PAGE_SIZE] = {0};
    unsigned char out[NVAES_PAGE_SIZE] = {0};
    int bytes;

    while((bytes = read(fdin, in, NVAES_PAGE_SIZE)) > 0) {
        bytes = nvaes_encrypt(ctx, in, bytes, out, sizeof(out), iv);

        if(bytes < 0) {
            fprintf(stderr, "Error whilst encrypting data\n");
            return 0;
        }

        if(write(fdout, out, bytes) != bytes) {
            perror("Error whilst writing to file");
            return 0;
        }
    }

    if(bytes < 0) {
        perror("Error whilst reading from file");
        return 0;
    }

    return 1;
}

int nvaes_decrypt_fd(nvaes_ctx ctx, int fdin, int fdout)
{
    unsigned char iv[AES_BLOCK_SIZE] = {0};
    unsigned char in[NVAES_PAGE_SIZE] = {0};
    unsigned char out[NVAES_PAGE_SIZE] = {0};
    int bytes;

    while((bytes = read(fdin, in, NVAES_PAGE_SIZE)) > 0) {
        bytes = nvaes_decrypt(ctx, in, bytes, out, sizeof(out), iv);

        if(bytes < 0) {
            fprintf(stderr, "Error whilst decrypting data\n");
            return 0;
        }

        if(write(fdout, out, bytes) != bytes) {
            perror("Error whilst writing to file");
            return 0;
        }
    }

    if(bytes < 0) {
        perror("Error whilst reading from file");
        return 0;
    }

    return 1;
}
