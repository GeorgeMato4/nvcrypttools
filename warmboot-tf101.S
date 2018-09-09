# ---------------------------------------------------------------------------
# File Name   : /Users/jevin/code/android/n7/nvcrypttools/warmboot-cut-dec-code.bin
# Format      : Binary file
# Base Address: 0000h Range: 40020000h - 40021FC0h Loaded length: 1FC0h
# ===========================================================================

#define PMC_SCRATCH_0 0x7000E450

# Segment type: Regular
                # AREA RAM, DATA, ALIGN=0
                # ORG 0x40020000
                .section .text
                .p2align 4
                .globl Start
Start:                                   # DATA XREF: RAM:4002009C↓o
                                        # RAM:400200A0↓o ...
                LDR     R0, =PMC_SCRATCH_0
                LDR     R1, [R0]
                ORR     R1, #0x20000000
                STR     R1, [R0]
                LDR     R0, =0x6001A000
                LDR     R1, =0x1110
                ADD     R1, R0, R1
                LDR     R1, [R1]
                MOV     R2, #1
                MOV     R2, R2,LSL#1
                BIC     R1, R1, R2
                LDR     R3, =0x1110
                ADD     R0, R0, R3
                STR     R1, [R0]
                LDR     R0, [R0]
                AND     R0, R0, R2
                MOV     R2, #0
                CMP     R0, R2
                BNE     DoReset
                LDR     R0, =0x60011000
                MOV     R1, #0x110
                ADD     R1, R0, R1
                LDR     R1, [R1]
                MOV     R2, #1
                MOV     R2, R2,LSL#1
                BIC     R1, R1, R2
                MOV     R3, #0x110
                ADD     R0, R0, R3
                STR     R1, [R0]
                LDR     R0, [R0]
                AND     R0, R0, R2
                MOV     R2, #0
                CMP     R0, R2
                BNE     DoReset
                MOV     R0, #0x70000000
                MOV     R1, #0xC0
                STR     R1, [R0,#0x24]
                LDR     R5, =0x7000E400
                LDR     R6, =0x60007000
                LDR     R7, =0x60005010
                LDR     R8, =0x60006000
                LDR     R9, =0x6000F000
                LDR     R10, =0x70040000
                LDR     R0, =Start
                ADRL    R1, Start
                MOV     R2, #0x60000000
                LDR     R3, [R2]
                LDR     R2, =0xAAAAAAAA
                CMP     R0, R1
                CMPEQ   R2, R3
                BNE     DoReset
                LDR     R11, [R7]
                MOV     R1, #0x200
                STR     R1, [R8,#0x310]
                LDR     R1, [R8,#0x50]
                LDR     R3, =0x3F1
                BIC     R1, R1, R3
                MOV     R3, #0x41
                ORR     R3, R1, R3
                STR     R3, [R8,#0x50]
                LDR     R3, [R5,#0x38]
                TST     R3, #1
                MOVEQ   R2, #0x100
                STREQ   R2, [R5,#0x30]

IsCpuOn:                                 # CODE XREF: RAM:400200FC↓j
                LDR     R3, [R5,#0x38]
                TST     R3, #1
                BEQ     IsCpuOn
                MOV     R3, #1
                STR     R3, [R5,#0x34]
                LDR     R1, =0x803
                STR     R1, [R8,#0x94]
                MOV     R1, #1
                STR     R1, [R8,#0x30]
                LDR     R2, =0x10007777
                STR     R2, [R8,#0x28]
                LDR     R3, =0x42000003
                STR     R3, [R6,#4]
                LDR     R1, [R8,#0x50]
                MOV     R1, R1,LSR#30
                ADR     R2, pllp_base_table
                LDR     R2, [R2,R1,LSL#2]
                ADR     R3, pllp_misc_table
                LDR     R3, [R3,R1,LSL#2]
                STR     R3, [R8,#0xAC]
                STR     R2, [R8,#0xA0]
                ORR     R2, R2, #0x40000000
                STR     R2, [R8,#0xA0]
                LDR     R1, =0x7070D07
                STR     R1, [R8,#0xA4]
                LDR     R1, =0x2070407
                STR     R1, [R8,#0xA8]
                B       iodelay
# ---------------------------------------------------------------------------
pllp_base_table:                        # DATA XREF: RAM:40020130↑o
                .word 0x9011B00D
                .word 0x90105A04
                .word 0x9011B00C
                .word 0x9011B01A
pllp_misc_table:                        # DATA XREF: RAM:40020138↑o
                .word 0x800
                .word 0x100
                .word 0x800
                .word 0x800
# ---------------------------------------------------------------------------

iodelay:                                 # CODE XREF: RAM:40020160↑j
                LDR     R3, =0x41000014
                STR     R3, [R6,#4]
                BIC     R2, R2, #0x80000000
                STR     R2, [R8,#0xA0]
                MOV     R1, #1
                STR     R1, [R8,#0x300]
                LDR     R3, =0x3033
                STR     R3, [R8,#0x340]
                MOV     R3, #0x40000000
                STR     R3, [R6,#0x14]
                LDR     R3, [R5,#0x140]
                STR     R3, [R9,#0x100]
                LDR     R3, =0x20004444
                STR     R3, [R8,#0x20]
                LDR     R3, =0x203
                STR     R3, [R8,#0x4C]
                MOV     R3, #1
                STR     R3, [R8,#0x320]
                ADD     R3, R11, #2

RstPoll:                                 # CODE XREF: RAM:400201D8↓j
                LDR     R2, [R7]
                CMP     R2, R3
                BLE     RstPoll
                MOV     R1, #0x200
                STR     R1, [R8,#0x314]
                LDR     R1, =0xC5ACCE55
                LDR     R2, =0x10FB0
                LDR     R3, =0x12FB0
                STR     R1, [R10,R2]
                STR     R1, [R10,R3]
                LDR     R11, [R7]
                STR     R11, [R5,#0x54]
                LDR     R4, [R7,#4]
                AND     R4, R4, #0xFF
                ADD     R4, R4, #1
                CMP     R4, #0x1A
                MOVGT   R4, #0x13
                LDR     R0, [R5,#0x5C]
                AND     R2, R0, #0x1F
                CMP     R2, R4
                MOVEQ   R4, #0
                MOVNE   R4, #1
                MOV     R0, R0,ASR#5
                LDR     R3, =0x3FF
                AND     R1, R0, R3
                ORR     R2, R2, R1,LSL#8
                MOV     R4, R1,LSL R4
                MOV     R0, R0,ASR#10
                AND     R1, R0, #7
                ORR     R2, R2, R1,LSL#20
                MOV     R4, R4,ASR R1
                ORR     R2, R2, #0x80000000
                CMP     R4, #0x258
                MOVLT   R3, #0
                MOVGE   R3, #0x100000
                MOV     R0, R0,ASR#3
                AND     R1, R0, #0xF
                ORR     R3, R3, R1,LSL#4
                MOV     R0, R0,ASR#4
                AND     R1, R0, #0xF
                ORR     R3, R3, R1,LSL#8
                STR     R3, [R8,#0xE4]
                STR     R2, [R8,#0xE0]
                ORR     R2, R2, #0x40000000
                STR     R2, [R8,#0xE0]
                BIC     R2, R2, #0x80000000
                STR     R2, [R8,#0xE0]
                MOV     R3, #0
                STR     R3, [R6]
                LDR     R3, =0x1011
                STR     R3, [R8,#0x344]
                B       AvpResume  

# =============== S U B R O U T I N E =======================================

litpool:
                .ltorg
                .size   litpool, .-litpool

                .p2align 4

AvpResume:                              # CODE XREF: RAM:4002029C↑j
                                        # DATA XREF: obfuscate+14↓o
                BL      obfuscate

normal_resume:
                LDR     LR, [R5,#0x138]
                CMP     LR, #0
                MOV     R1, #1
                STR     R1, [R8,#0x304]
                BXNE    LR
# End of function AvpResume


# =============== S U B R O U T I N E =======================================

# Attributes: noreturn

AvpHalt:                                # CODE XREF: AvpHalt+C↓j
                # MOV     R3, #0x50000000
                MOV     R3, #0x40000000
                ORR     R3, #0x10000000
                STR     R3, [R6,#4]
                B       AvpHalt
# End of function AvpHalt


# =============== S U B R O U T I N E =======================================


obfuscate:                              # CODE XREF: AvpResume↑p
                                        # DoReset↓p
                MOV     R0, #0
                MOV     R1, #0
                MOV     R2, #0
                MOV     R3, #0
                ADR     R10, Start
                ADR     R11, AvpResume

BlastIt:                                # CODE XREF: obfuscate+20↓j
                # STMIA   R10!, {R0-R3}
                ADD     R10, #16        // just loop, don't really clear
                CMP     R10, R11
                BLT     BlastIt
                BX      LR
# End of function obfuscate


# =============== S U B R O U T I N E =======================================

# Attributes: noreturn

DoReset:                                 # CODE XREF: RAM:40020038↑j
                                        # RAM:40020074↑j ...
                BL      obfuscate
                MOV     R0, #4
                STR     R0, [R8,#4]

DoResetSpin:                         # CODE XREF: DoReset:loc_40020364↓j
                B       DoResetSpin
# End of function DoReset

                .p2align 4
                .globl End
End:
