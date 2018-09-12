// ---------------------------------------------------------------------------
// File Name   : /Users/jevin/code/android/n7/nvcrypttools/wb-dump-n7-dec.bin
// Format      : Binary file
// Base Address: 0000h Range: 40020000h - 400203C0h Loaded length: 03C0h

// Processor       : ARM
// ARM architecture: ARMv4T
// Target assembler: Generic assembler for ARM
// Byte sex        : Little endian

// ===========================================================================

#define PMC_BASE 0x7000E400
#define _REG(base, off) ((base) + (off))
#define PMC(off) _REG(PMC_BASE, off)
#define PMC_SCRATCH0 0x50

// Segment type: Regular
                // AREA RAM, DATA, ALIGN=0
                // ORG 0x40020000

                .section .text
                .p2align 4
                .globl Start

Start:                                   // DATA XREF: RAM:4002000C↓o
                                        // RAM:off_40020324↓o

                b indicate_pwn
back_to_start:

                MOV     R1, #0xC0
                STR     R1, [R0,#0x24]
                LDR     R0, =Start
                ADR     R1, SkipSettings

SkipSettings:                            // DATA XREF: RAM:40020010↑o
                SUB     R1, R1, #0x14
                MOV     R2, #0x60000000
                LDR     R3, [R2]
                LDR     R2, =0xAAAAAAAA
                CMP     R0, R1
                CMPEQ   R2, R3
                BNE     DoReset
                LDR     R4, =0x6000C000
                LDR     R5, =0x7000E400
                LDR     R6, =0x60007000
                LDR     R7, =0x60005010
                LDR     R8, =0x60006000
                LDR     R9, =0x6000F000
                LDR     R11, [R7]
                LDR     R0, [R8,#0x28]
                MOV     R2, #0x20000000
                STR     R2, [R8,#0x28]
                LDR     R2, =0xF075307
                STR     R2, [R8,#0xA4]
                LDR     R2, =0x6070607
                STR     R2, [R8,#0xA8]
                LDR     R1, [R5,#0x1A4]
                MOV     R2, R1,LSR#1
                AND     R2, R2, #0x3F
                LDR     R1, [R8,#0x50]
                LDR     R3, =0x3F1
                BIC     R1, R1, R3
                MOV     R3, R2,LSL#4
                MOV     R2, #1
                ORR     R3, R3, R2
                ORR     R3, R1, R3
                STR     R3, [R8,#0x50]
                LDR     R2, =0x40800
                STR     R2, [R8,#0xAC]
                LDR     R3, [R8,#0x50]
                MOV     R3, R3,LSR#28
                LDR     R2, =0x5001980D
                CMP     R3, #8
                LDREQ   R2, =0x5001980C
                CMP     R3, #1
                LDREQ   R2, =0x5001540E
                CMP     R3, #4
                LDREQ   R2, =0x50015410
                CMP     R3, #0xC
                LDREQ   R2, =0x5001981A
                CMP     R3, #5
                LDREQ   R2, =0x50015410
                CMP     R3, #9
                LDREQ   R2, =0x5001980C
                STR     R2, [R8,#0xA0]

IS_PLLP_LOCK:                            // CODE XREF: RAM:400200E4↓j
                LDR     R2, [R8,#0xA0]
                ANDS    R2, R2, #0x8000000
                BEQ     IS_PLLP_LOCK
                LDR     R3, =0x420000FA
                STR     R3, [R6,#4]
                STR     R0, [R8,#0x28]
                LDR     R1, [R8,#0x48]
                ORR     R1, R1, #1
                STR     R1, [R8,#0x48]
                LDR     R1, [R4,#0xE0]
                ORR     R1, R1, #4
                STR     R1, [R4,#0xE0]
                MOV     R1, #0x200
                STR     R1, [R8,#0x310]
                MOV     R1, #0x40000000
                STR     R1, [R6]
                STR     R1, [R6,#0x14]
                STR     R1, [R6,#0x1C]
                STR     R1, [R6,#0x24]
                LDR     R3, [R5,#0x60]
                ANDS    R3, R3, #0x80000000
                LDRNE   R3, [R6,#0x2C]
                ORRNE   R3, R3, #1
                STRNE   R3, [R6,#0x2C]
                LDR     R1, =0xF0FF
                STR     R1, [R8,#0x340]
                MOV     R1, #1
                STR     R1, [R8,#0x300]
                MOV     R1, #0x80000000
                STR     R1, [R8,#0x24]
                MOV     R1, #0xF00
                STR     R1, [R8,#0x348]
                ADD     R3, R11, #2

RstPoll:                                 // CODE XREF: RAM:40020168↓j
                LDR     R2, [R7]
                CMP     R2, R3
                BLE     RstPoll
                MOV     R1, #0x200
                STR     R1, [R8,#0x330]
                MOV     R1, #0x200
                STR     R1, [R8,#0x314]
                LDR     R3, [R8,#0x50]
                MOV     R3, R3,LSR#28
                CMP     R3, #0
                BEQ     PLLU_OSC_13M
                CMP     R3, #0xC
                BEQ     PLLU_OSC_26M
                CMP     R3, #1
                BEQ     PLLU_OSC_16_8M
                CMP     R3, #4
                BEQ     PLLU_OSC_19_2M
                CMP     R3, #5
                BEQ     PLLU_OSC_19_2M
                CMP     R3, #8
                BEQ     PLLU_OSC_12M
                CMP     R3, #9
                BEQ     PLLU_OSC_12M

PLLU_OSC_13M:                            // CODE XREF: RAM:40020188↑j
                LDR     R1, =0x8003C00D
                MOV     R2, #0xC10
                B       PROGRAM_PLLU
// ---------------------------------------------------------------------------

PLLU_OSC_26M:                            // CODE XREF: RAM:40020190↑j
                LDR     R1, =0x8003C01A
                MOV     R2, #0xC10
                B       PROGRAM_PLLU
// ---------------------------------------------------------------------------

PLLU_OSC_16_8M:                          // CODE XREF: RAM:40020198↑j
                LDR     R1, =0x80019007
                MOV     R2, #0x500
                B       PROGRAM_PLLU
// ---------------------------------------------------------------------------

PLLU_OSC_19_2M:                          // CODE XREF: RAM:400201A0↑j
                                        // RAM:400201A8↑j
                LDR     R1, =0x8000C804
                MOV     R2, #0x300
                B       PROGRAM_PLLU
// ---------------------------------------------------------------------------

PLLU_OSC_12M:                            // CODE XREF: RAM:400201B0↑j
                                        // RAM:400201B8↑j
                LDR     R1, =0x8003C00C
                MOV     R2, #0xC10

PROGRAM_PLLU:                            // CODE XREF: RAM:400201C4↑j
                                        // RAM:400201D0↑j ...
                STR     R1, [R8,#0xC0]
                STR     R2, [R8,#0xCC]
                BIC     R1, R1, #0x80000000
                ORR     R1, R1, #0x40000000
                STR     R1, [R8,#0xC0]
                ORR     R2, R2, #0x400000
                STR     R2, [R8,#0xCC]
                MOV     R0, #0x8000
                STR     R0, [R8,#0x320]
                MOV     R1, #0x8000
                LDR     R2, [R8,#4]
                STR     R1, [R8,#0x304]
                LDR     R4, =0x78000600
                LDR     R3, [R4,#0x100]
                ORR     R3, R3, #0x10
                STR     R3, [R4,#0x100]
                STR     R2, [R8,#4]
                STR     R0, [R8,#0x324]
                LDR     R11, =0x70012000
                LDR     R0, [R11]
                MOV     R1, #0xFFFFFFF7
                AND     R0, R0, R1
                STR     R0, [R11]
                ADR     R3, CPU_LP0_START
                STR     R3, [R9,#0x100]
                LDR     R3, =0x20004444
                STR     R3, [R8,#0x20]
                MOV     R3, #0x100
                STR     R3, [R8,#0x34C]
                MOV     R3, #1
                STR     R3, [R8,#0x320]
                MOV     R1, #0
                ORR     R1, R1, #6
                STR     R1, [R8,#0x3B4]
                MOV     R1, #8
                STR     R1, [R8,#0x440]
                MOV     R1, #8
                STR     R1, [R8,#0x434]
                LDR     R3, [R5,#0x60]
                ANDS    R3, R3, #0x80000000
                MOVNE   R0, #0x1000
                MOVNE   R1, #0x10C
                MOVNE   R2, #0x1000
                MOVEQ   R0, #1
                MOVEQ   R1, #0x100
                MOVEQ   R2, #1
                LDR     R3, [R5,#0x38]
                TST     R3, R0
                STREQ   R1, [R5,#0x30]

IsCpuOn:                                 // CODE XREF: RAM:400202C0↓j
                LDR     R3, [R5,#0x38]
                TST     R3, R0
                BEQ     IsCpuOn
                STR     R2, [R5,#0x34]

WaitStable:
                LDR     R3, =0x41000014
                STR     R3, [R6,#4]
                LDR     R1, =0x1011
                STR     R1, [R8,#0x344]
                MOV     R1, #1
                STR     R1, [R8,#0x304]
                MOV     R3, #0
                STR     R3, [R6]
                B       AvpResume
// ---------------------------------------------------------------------------
LP0_ENTRY:      
                .word 0xBFE00008          // DATA XREF: RAM:40020310↓r
LP0_BOOT_PARAM:
                .word 0x54464250          // DATA XREF: RAM:4002030C↓o
                .word 0x1015
                .word 0x80000100
                .word 0xBFF00000
                .word 0x100000
                .word 6
// ---------------------------------------------------------------------------

CPU_LP0_START:                           // DATA XREF: RAM:40020250↑o
                MOV     R0, #3
                ADR     R1, LP0_BOOT_PARAM
                LDR     R9, LP0_ENTRY
                CMP     R9, #0

spin1:                            // CODE XREF: RAM:loc_40020318↓j
                BEQ     spin1
                BX      R9
// ---------------------------------------------------------------------------

spin2:                            // CODE XREF: RAM:loc_40020320↓j
                B       spin2
// ---------------------------------------------------------------------------

                .ltorg

// ---------------------------------------------------------------------------

AvpResume:                               // CODE XREF: RAM:400202E8↑j
                BL      Obfuscate

AvpHalt:                                 // CODE XREF: RAM:400203A8↓j
                MOV     R3, #0x40000000
                ORR     R3, R3, #0x10000000
                STR     R3, [R6,#4]
                B       AvpHalt

// =============== S U B R O U T I N E =======================================


Obfuscate:                               // CODE XREF: RAM:AvpResume↑p
                                        // RAM:DoReset↓p
                BX      LR
// End of function Obfuscate

// ---------------------------------------------------------------------------

DoReset:                                 // CODE XREF: RAM:4002002C↑j
                BL      Obfuscate
                MOV     R0, #4
                STR     R0, [R8,#4]

spin3:                            // CODE XREF: RAM:loc_400203BC↓j
                B       spin3

indicate_pwn:

                LDR     R0, =PMC(PMC_SCRATCH0)
                LDR     R1, [R0]
                ORR     R1, #0x10000000
                STR     R1, [R0]

                LDR     R0, =PMC(0)
                MOV     R1, #(1 << 4)
                STR     R1, [R0]

                MOV     R0, #0x70000000
spin:
                B       spin

                .ltorg

                .p2align 4
                .globl End
End:

