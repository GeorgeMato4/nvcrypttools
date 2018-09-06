#!/usr/bin/make
CROSS_COMPILE ?= arm-linux-androideabi-

CC := $(CROSS_COMPILE)gcc
MAKE ?= make

CFLAGS := -O2 -static -march=armv7-a -mthumb -I.

STRIP := $(CROSS_COMPILE)strip

SHARED_OBJS := nvaes.o nvrcm.o

DEVICE_SOURCES = $(shell gfind -type f -name '*.bin')
DEVICE_TARGETS = $(patsubst %.bin, %.h, $(DEVICE_SOURCES))

all: $(DEVICE_TARGETS)

%.h: %.bin
	@echo "Making $@ from $<"
	cat $< | xxd -i > $@

clean:
	@rm -f $(DEVICE_TARGETS)

.PHONY: all clean 
