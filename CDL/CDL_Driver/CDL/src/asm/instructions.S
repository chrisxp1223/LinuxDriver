.code64
.global invlpgb
.global tlbsync

#include <linux/linkage.h>

invlpgb:
    push %rax
    push %rcx
    mov %rdi, %rax
    mov %rsi, %rcx
    .byte   0x0F,0x01,0xFE  // Opcode for INVLPGB instruction
    pop %rcx
    pop %rax
    retq

tlbsync:
    .byte   0x0F,0x01,0xFF  // Opcode for TLBSYNC instruction
    retq
    
