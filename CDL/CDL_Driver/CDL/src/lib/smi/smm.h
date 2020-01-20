#ifndef SM_H
#define SM_H

#define SMM_CODE_SIZE         0x800 
#define SMM_DATA_SIZE         0x800
#define SMM_SIZE                (SMM_DATA_SIZE + SMM_CODE_SIZE)
#define SMM_CODE_START  0x8000
#define SMM_BASE 0xC0010111
#define SMMADDRH_L 0xC0010112
#define SMMMASKH_L 0xC0010113

#define HWRCR_SMM_LOCK_MASK 0x00000001
#define SMM_ISR_ENTRY_OFFSET 0x8000   
#define ENABLE_ASEG_SMRAM_RANGE_BIT  0x01
#define ENABLE_TSEG_SMRAM_RANGE_BIT  0x02


struct SmmSave {
 unsigned char code[SMM_CODE_SIZE];
 unsigned char data[SMM_DATA_SIZE];
} SmmSave;


struct IDTR {
   unsigned short reserved1;
   unsigned short reserved2;
   unsigned short limit;
   unsigned short reserved3;
   unsigned long base;
} IDTR;

struct GDTR {
   unsigned short reserved1;
   unsigned short reserved2;
   unsigned short limit;
   unsigned short reserved3;
   unsigned long base;
} GDTR;


struct SegmentReg {
  unsigned short selector;
  unsigned short attributes;
  unsigned limit;
  unsigned long base;

} SegmentReg;

struct SmmStateSave {

  struct SegmentReg es;
  struct SegmentReg cs;
  struct SegmentReg ss;
  struct SegmentReg ds;
  struct SegmentReg fs;
  struct SegmentReg gs;
  struct GDTR       gdtr;
  struct SegmentReg ldtr;
  struct IDTR       idtr;
  struct SegmentReg tr;
  unsigned char reserved1[32];
  unsigned int smmIoTrap;
  unsigned int localSmiStatus;
  unsigned char ioInstructionRestart;
  unsigned char autoHaltRestart;
  unsigned char reserved2[6];
  unsigned long efer;
  unsigned char reserved3[36];
  unsigned int smmRevisionId;
  unsigned int smmBase;
  unsigned char reserved4[68];
  unsigned long cr4;
  unsigned long cr3;
  unsigned long cr0;
  unsigned long dr7;
  unsigned long dr6;
  unsigned long rflags;
  unsigned long rip;
  unsigned long r15;
  unsigned long r14;
  unsigned long r13;
  unsigned long r12;
  unsigned long r11;
  unsigned long r10;
  unsigned long r9;
  unsigned long r8;
  unsigned long rdi;
  unsigned long rsi;
  unsigned long rbp;
  unsigned long rsp;
  unsigned long rbx;
  unsigned long rdx;
  unsigned long rcx;
  unsigned long rax;

} SmmStateSave;


#endif
