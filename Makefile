#!/usr/bin/make
CROSS_COMPILE ?= arm-linux-androideabi-

CC := $(CROSS_COMPILE)gcc
LD := $(CROSS_COMPILE)ld
OBJCOPY := $(CROSS_COMPILE)objcopy
MAKE ?= make

CFLAGS := -O0 -g -D__ANDROID_API__=17 -DNVAES_DEBUG_ENABLE -DNVAES_DEBUG_RAW_CRYPT -DNVAES_DEBUG_DATA -DENABLE_DEBUG -Wall -Wno-unused-variable -static -march=armv7-a -mthumb -I.
LDFLAGS := 
STRIP := $(CROSS_COMPILE)strip

SHARED_OBJS := nvaes.o nvrcm.o

#NVBLOB2GO_OBJS = gpiokeys.o scrollback.o

DEVICE_DIRS = $(shell gfind devices/ -mindepth 1 -maxdepth 1 -type d)
DEVICE_TARGETS = $(patsubst devices/%,%, $(DEVICE_DIRS))
DEVICE_RAMDISKS = $(patsubst %, %.cpio.gz, $(DEVICE_TARGETS))
DEVICE_BOOTIMGS = $(patsubst %, %.img, $(DEVICE_TARGETS))

all: nvsign nvencrypt nvdecrypt mknvfblob warmboot-tf101.bin warmboot-h4x $(DEVICE_TARGETS)

$(DEVICE_TARGETS): nvblob2go.c $(SHARED_OBJS) bins
	$(CC) $(CFLAGS) -Idevices/$@ -o $@ nvblob2go.c $(SHARED_OBJS) $(LDFLAGS) && \
		$(STRIP) $@

%.cpio.gz: %
	@echo "Creating ramdisk $@"
	@rm -rf $<_ramdisk
	@rm -f $@
	@mkdir $<_ramdisk
	@cp $< $<_ramdisk/init
	@cp vfat.img $<_ramdisk/
	@cd $<_ramdisk && find|cpio -o -H newc|gzip -c > ../$@
	@rm -rf $<_ramdisk
	@echo Done

%.img: % %.cpio.gz
	@echo "Creating $@"
	mkbootimg --kernel devices/$</kernel.gz --ramdisk $<.cpio.gz -o $@

mknvfblob: mknvfblob.c $(SHARED_OBJS)
	$(CC) $(CFLAGS) -o $@ $@.c $(SHARED_OBJS) && \
		$(STRIP) $@

nvsign: nvsign.c $(SHARED_OBJS)
	$(CC) $(CFLAGS) -o $@ $@.c $(SHARED_OBJS)

nvencrypt: nvencrypt.c $(SHARED_OBJS)
	$(CC) $(CFLAGS) -o $@ $@.c $(SHARED_OBJS)

nvdecrypt: nvdecrypt.c $(SHARED_OBJS)
	$(CC) $(CFLAGS) -o $@ $@.c $(SHARED_OBJS)

warmboot-h4x: warmboot-h4x.c $(SHARED_OBJS)
	$(CC) $(CFLAGS) -o $@ $@.c $(SHARED_OBJS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

warmboot-tf101.o: warmboot-tf101.S
	$(CC) -O0 -g -Wall -march=armv4t -mtune=arm7tdmi -marm -c -o $@ $<

warmboot-tf101.elf: warmboot-tf101.o warmboot-tf101.lds
	$(LD) -T warmboot-tf101.lds -marm -o $@ $<

warmboot-tf101.bin: warmboot-tf101.elf
	$(OBJCOPY) -v -O binary $< $@

bins:
	$(MAKE) -C devices


ramdisks: $(DEVICE_RAMDISKS)

bootimgs: $(DEVICE_BOOTIMGS)

clean: 
	@rm -f mknvfblob nvencrypt nvdecrypt nvsign $(SHARED_OBJS) \
		$(DEVICE_TARGETS) $(DEVICE_RAMDISKS) \
		warmboot-tf101.o warmboot-tf101.elf warmboot-tf101.bin \
		warmboot-h4x
	@make -C devices clean

.PHONY: all clean bins ramdisks
