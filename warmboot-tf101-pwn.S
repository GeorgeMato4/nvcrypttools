# ---------------------------------------------------------------------------
# File Name   : /Users/jevin/code/android/n7/nvcrypttools/warmboot-cut-dec-code.bin
# Format      : Binary file
# Base Address: 0000h Range: 40020000h - 40021FC0h Loaded length: 1FC0h
# ===========================================================================

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

# Segment type: Regular
                # AREA RAM, DATA, ALIGN=0
                # ORG 0x40020000
                .section .text
                .p2align 4
                .globl Start
Start:                                   # DATA XREF: RAM:4002009C↓o
                                        # RAM:400200A0↓o ...
                LDR     R0, =PMC(PMC_SCRATCH0)
                MOV     R1, #0x20000000
                STR     R1, [R0]

                LDR     R0, =PMC(0)
                MOV     R1, #(1 << 4)
                STR     R1, [R0]

spin:
                B       spin

litpool:
                .ltorg
                .size   litpool, .-litpool

                .rept 503
                .word 0x40007800
                .endr

                .p2align 4
                .globl End
End:
