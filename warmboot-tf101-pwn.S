# ---------------------------------------------------------------------------
# File Name   : /Users/jevin/code/android/n7/nvcrypttools/warmboot-cut-dec-code.bin
# Format      : Binary file
# Base Address: 0000h Range: 40020000h - 40021FC0h Loaded length: 1FC0h
# ===========================================================================

# TF101 SBK v2: a2c3d7159fd2eeef14bbf33674efcab8
# ./warmboot-h4x -b -i warmboot-tf101-dump-sbk.bin -o foo.bin -B 0x40007800 -E 0x40007800 -e -I
# let device go to deep sleep (disconnect USB), wait ~15 seconds
# wake device by pressing power, SBK will be spammed to SRAM and device will reset + boot Android
# ./memdump 0x40000000 $((256*1024)) sram4.bin
# sram4.bin will contain SBK and DK spammed at end of dump

#define IRAM_START 0x40000000
#define IRAM_END (IRAM_START + 256 * 1024)
#define MINILOADER_ENTRY 0x40008000
#define FILL_START (MINILOADER_ENTRY + 1024)

#define IROM_START 0xfff00000
#define IROM_SIZE (48 * 1024)
#define IROM_COPY_ADDR 0x4002f000

#define PMC_BASE 0x7000E400
#define _REG(base, off) ((base) + (off))
#define PMC(off) _REG(PMC_BASE, off)
#define PMC_SCRATCH0 0x50
#define PMC_SCRATCH1 0x54
#define PMC_SCRATCH41 0x140

#define WARMBOOT_START 0x40020000

#define FUSE_PRIVATE_KEY0 0x7000F9A4

# Segment type: Regular
                # AREA RAM, DATA, ALIGN=0
                # ORG 0x40020000
                .section .text
                .p2align 4
                .globl Start
Start:                                   # DATA XREF: RAM:4002009C↓o
                                        # RAM:400200A0↓o ...
                BL fill_iram

                #if 0
                # IROM dumping
                LDR     R0, =IROM_COPY_ADDR
                LDR     R1, =IROM_START
                MOV     R2, #IROM_SIZE
                BL      copy
                #endif

                LDR     R0, =PMC(PMC_SCRATCH0)
                MOV     R1, #0x20000000
                STR     R1, [R0]

                LDR     R0, =PMC(0)
                MOV     R1, #(1 << 4)
                STR     R1, [R0]

spin:
                B       spin

                .globl fill_iram
fill_iram:
                ldr r0, =FILL_START
                ldr r1, =IRAM_END
                ldr r7, =FUSE_PRIVATE_KEY0
                ldr r2, [r7]
                ldr r3, [r7, #4]
                ldr r4, [r7, #8]
                ldr r5, [r7, #12]
                ldr r6, [r7, #16]
L_copy_sbk:
                str r2, [r0]
                str r3, [r0, #4]
                str r4, [r0, #8]
                str r5, [r0, #12]
                str r6, [r0, #16]
                add r0, r0, #20
                cmp r0, r1
                blt L_copy_sbk
                bx lr

//
// Simple block copy.
//   r0 = destination address
//   r1 = source address
//   r2 = length in bytes
// Destroys r0-r3.
//
                .globl copy
copy:
                // Copy the word...
                ldr r3, [r1], #4
                str r3, [r0], #4

                // And continue while we have words left to copy.
                subs r2, r2, #4
                bne copy

                // Once we're done, return.
                bx lr

litpool:
                .ltorg
                .size   litpool, .-litpool

                .rept 477
                .word 0x40007800
                .endr

                .p2align 4
                .globl End
End:
