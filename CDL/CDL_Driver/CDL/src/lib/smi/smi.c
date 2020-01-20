#include <linux/acpi.h>
#include <linux/bootmem.h>
#include <linux/memblock.h>
#include <linux/dmi.h>
#include <linux/cpumask.h>
#include <linux/module.h>
#include <asm/segment.h>
#include <asm/desc.h>
#include <asm/pgtable.h>
#include <asm/io.h>
#include <asm/cacheflush.h>
#include <asm/realmode.h>
#include <asm/processor.h>
#include "../common/common.h"
#include "smi.h"
#include "smm.h"

//********************************************************************************************

// extern void disable_vga_hardscroll(void);
// extern void enable_vga_hardscroll(void);

//********************************************************************************************

static void* get_smm_code_lin_addr(void);
static void* get_smm_data_lin_addr(void);

static unsigned long get_smm_code_phys_addr(void);
static unsigned long get_smm_data_phys_addr(void);

static unsigned long open_smm( unsigned long* saved_MTRRfix16k_A000);
static int save_smm(void);
static int is_smm_locked(void);
static int broadcast_smi(void);

static void (*ksym_native_apic_icr_write)(u32, u32);
static unsigned char *ksym_vga_hardscroll_user_enable;
static unsigned char *ksym_vga_hardscroll_enabled;

//********************************************************************************************

const unsigned long uncacheable     = 0x1818181818181818ull;     
const unsigned long MTRRfix16k_A000 = 0x00000259;
const unsigned long SYS_CFG         = 0xC0010010;

//********************************************************************************************

static struct SmmSave save[NR_CPUS]; 

//********************************************************************************************

#define LOW       0
#define ID        1
#define SMI       2
#define EDGE      0
#define NONE      0
#define PHYSICAL  0
#define LOGICAL   1
#define BROADCAST 0xff

//********************************************************************************************

#define SET_APIC_TRIGGER_MODE(icrlow, trigger)	  (((icrlow) & ~0x00008000) | ((trigger)   << 15))
#define SET_APIC_DEST_SHORTHAND(icrlow,shorthand) (((icrlow) & ~0x000c0000) | ((shorthand) << 18))
#define SET_APIC_DEST_MODE(icrlow,mode)	          (((icrlow) & ~0x00000800) | ((mode)      << 11))
#define SET_APIC_DESTINATION(icrhi,dest)          (((icrhi)  & ~0xff000000) | ((dest)      << 24))



//********************************************************************************************
// FIXME: Calculate:
//               SMP :  Difference between the base addresses of core 0 and core 1
//               UP  :  0x8000



size_t smm_data_size(void)

{ static size_t size  = 0;

  if (size == 0) {
    size = 0x800;
  }
  return(size);

}

//********************************************************************************************
// FIXME: Calculate:
//               SMP :  Difference between the base addresses of core 0 and core 1
//               UP  :  0x8000

size_t smm_code_size(void)

{ static size_t size  = 0;

  if (size == 0) {
    size = 0x800;
  }
  return(size);

}

//********************************************************************************************

int amd_send_smi(unsigned long count)


{ unsigned long now;
  int error = 0;

  for (now = 0; now < count; now++) {
     broadcast_smi();
  }


   return(error);

}

void wait_icr_idle(void)

{ unsigned int icr;
 unsigned int  mask = (1 << 12);
 unsigned long wait;

 do {

   wait++;
   icr = apic_read(APIC_ICR);
 } while (icr & mask);
  

}

//********************************************************************************************


static int broadcast_smi(void)

 { unsigned long flags;
   unsigned int icr[2];
   int error = 0;

   local_irq_save(flags);

   icr[ID]  = apic_read(APIC_ICR2);
   icr[LOW] = apic_read(APIC_ICR);

   icr[LOW] &= ~APIC_VECTOR_MASK;

   icr[LOW] = SET_APIC_DELIVERY_MODE(icr[LOW],SMI);	
   icr[LOW] = SET_APIC_TRIGGER_MODE(icr[LOW],EDGE);	
   icr[LOW] = SET_APIC_DEST_SHORTHAND(icr[LOW],NONE);	
   icr[LOW] = SET_APIC_DEST_MODE(icr[LOW],PHYSICAL);	

   icr[ID]  = SET_APIC_DESTINATION(icr[ID],BROADCAST);	

   ksym_native_apic_icr_write = (void *) kallsyms_lookup_name("native_apic_icr_write");

   if(ksym_native_apic_icr_write)
      ksym_native_apic_icr_write(icr[LOW], icr[ID]);
   else
      printk("ERROR: can't find the symbol - native_spic_icr_write\n");

   local_irq_restore(flags);

   wait_icr_idle();
   icr[ID]  = apic_read(APIC_ICR2);
   icr[LOW] = apic_read(APIC_ICR);

   return(error);

}
                                     
//********************************************************************************************

void disable_mtrr_fix_dram_mod_en(void)

{  unsigned long state;   
   
   rdmsrl(SYS_CFG,state);

   state &= ~0x00080000ull;

   wrmsrl(SYS_CFG,state);

}

//********************************************************************************************

void enable_mtrr_fix_dram_mod_en(void)

{  unsigned long state;   
   
   rdmsrl(SYS_CFG,state);

   state |= 0x00080000ull;

   wrmsrl(SYS_CFG,state);

}

/*****************************************************************************
*
* Function    : open_smm
*
* Engineer    : Paul Hohle
*                                                       
* Parameters  : Pass by reference saved state 
*
* Returns     : Old MTRR state
*
* Description : Open SMM mode
*               Check if the ASeg SMRAM Range is currently valid.  If so, disable
*               the ASeg range and configure the MTRR for the A0000-BFFFF DRAM range.
*
* Notes       : We assume here that, in cases where TSeg is used for the SMM 
*               RAM region, it is apped in himem such that it is covered by 
*               the kernel's big variable MTRR
*               
******************************************************************************/

static unsigned long open_smm(unsigned long* saved_MTRRfix16k_A000 )

{ unsigned long old_smm_mask;
  unsigned long new_smm_mask;
  unsigned long saved;


  rdmsrl(SMMMASKH_L,old_smm_mask);  

  new_smm_mask = old_smm_mask;                

  *saved_MTRRfix16k_A000 = 0;

  // disable_vga_hardscroll();
  ksym_vga_hardscroll_user_enable = (unsigned char *) kallsyms_lookup_name("vga_hardscroll_user_enable");

  if(ksym_vga_hardscroll_user_enable)
    *ksym_vga_hardscroll_user_enable = 0;
  else
    printk("ERROR: can't find the symbol - vga_hardscroll_user_enable\n");

  ksym_vga_hardscroll_enabled = (unsigned char *) kallsyms_lookup_name("vga_hardscroll_enabled");

  if(ksym_vga_hardscroll_enabled)
    *ksym_vga_hardscroll_enabled = 0;
  else
    printk("ERROR: can't find the symbol - vga_hardscroll_enabled\n");

  if (old_smm_mask & ENABLE_ASEG_SMRAM_RANGE_BIT) {
     enable_mtrr_fix_dram_mod_en();
     new_smm_mask &= ~ENABLE_ASEG_SMRAM_RANGE_BIT;
     wrmsrl(SMMMASKH_L,new_smm_mask );

     rdmsrl(MTRRfix16k_A000,saved);
     *saved_MTRRfix16k_A000 = saved;
     wrmsrl(MTRRfix16k_A000,uncacheable);
  }

  if (old_smm_mask & ENABLE_TSEG_SMRAM_RANGE_BIT ) {
     new_smm_mask &= ~ENABLE_TSEG_SMRAM_RANGE_BIT;
     wrmsrl(SMMMASKH_L,new_smm_mask);
  }

        
  return(old_smm_mask);

}


//********************************************************************************************

static void close_smm(unsigned long fixed, unsigned long original_smm_mask)

{
        wbinvd();

        if (original_smm_mask & ENABLE_ASEG_SMRAM_RANGE_BIT) {
           wrmsrl(MTRRfix16k_A000,fixed);
        }
        
        wrmsrl(SMMMASKH_L,original_smm_mask); 
        disable_mtrr_fix_dram_mod_en();

        // enable_vga_hardscroll();
        ksym_vga_hardscroll_user_enable = (unsigned char *) kallsyms_lookup_name("vga_hardscroll_user_enable");

        if(ksym_vga_hardscroll_user_enable)
                *ksym_vga_hardscroll_user_enable = 1;
	else
                printk("ERROR: can't find the symbol - vga_hardscroll_user_enable\n");
        ksym_vga_hardscroll_enabled = (unsigned char *) kallsyms_lookup_name("vga_hardscroll_enabled");

        if(ksym_vga_hardscroll_enabled)
                *ksym_vga_hardscroll_enabled = 1;
        else
                printk("ERROR: can't find the symbol - vga_hardscroll_enabled\n");
}


//********************************************************************************************

int amd_smm_test(void)

{ // const int cpu            = smp_processor_id();
  const int locked         = is_smm_locked();
  // unsigned long data = get_smm_data_phys_addr();
  // unsigned long code = get_smm_code_phys_addr();
  // const void* lincode = get_smm_data_lin_addr();
  // const void* lindata = get_smm_code_lin_addr();


  return(locked ? -ENODEV : 0);
   
}


//********************************************************************************************

void* get_smm_code_lin_addr(void)

{ static void* linear[NR_CPUS]  = {[0 ... NR_CPUS-1] = NULL};
  const int cpu                 = smp_processor_id();

 if (!linear[cpu]) {
    linear[cpu]=ioremap(get_smm_code_phys_addr(),smm_code_size());
  }	
   

  return(linear[cpu]);

}

//********************************************************************************************

void*  get_smm_data_lin_addr(void)

{ static void* linear[NR_CPUS]  = {[0 ... NR_CPUS-1] = NULL};
  const int cpu                 = smp_processor_id();

 if (!linear[cpu]) {
    linear[cpu]=ioremap(get_smm_data_phys_addr(),smm_data_size());
 }	

  return(linear[cpu]);

}

//********************************************************************************************

static unsigned long  get_smm_code_phys_addr(void)

{ const unsigned long mask = 0xffffffffull;            
  unsigned long base;

  rdmsrl(SMM_BASE,base);

  return((base & mask) + SMM_ISR_ENTRY_OFFSET);

}

//********************************************************************************************

static unsigned long  get_smm_data_phys_addr(void)

{ const unsigned long mask = 0xffffffffull;            
  unsigned long base;

  rdmsrl(SMM_BASE,base);

  return((base & mask));

}


//********************************************************************************************

static int install_smi_handler(void* source, size_t bytes)

{ int error = 0;
  unsigned long fixed_16k;               // MTRR state for MTRRfix16k_A000
  // const int cpu = smp_processor_id();
  unsigned long flags;
  unsigned char* destination = (unsigned char*)get_smm_code_lin_addr(); 
  unsigned long smm_mask;

  local_irq_save(flags);

  smm_mask = open_smm(&fixed_16k);  

  memcpy_toio(destination, source, bytes);

  error = memcmp(destination,source,bytes) ? -EFAULT : 0;

  close_smm(fixed_16k, smm_mask);

  local_irq_restore(flags);



  return(error);

}

//********************************************************************************************

static int is_smm_locked(void)

{  unsigned long msr;

   rdmsrl(MSR_K7_HWCR,msr);

   return(msr & HWRCR_SMM_LOCK_MASK ? 1 : 0);

}

//********************************************************************************************

int amd_install_smi_handler(void* userCode, size_t bytes)

{ // const int cpu = smp_processor_id();
  int error = 0;



 if (is_smm_locked()) {
   error = -ENODEV;
 }
 else {
   error = save_smm();
   if (!error) {
      error = install_smi_handler(userCode,bytes);
   }
 }


  return(error);
}

//*********************************************************************************************

int amd_restore_smi_handler(void)

{  unsigned char* code = (unsigned char*)get_smm_code_lin_addr();
   unsigned char* data = (unsigned char*)get_smm_data_lin_addr();
   const int cpu             = smp_processor_id();
   struct SmmSave* buffer    = &save[cpu];
   int error = 0;
   int cmp[2];
   unsigned long flags;
   unsigned long fixed_16k; 
   unsigned long smm_mask;


   local_irq_save(flags);

   smm_mask = open_smm(&fixed_16k); 

   memcpy_toio(data,buffer->data,smm_data_size());
   memcpy_toio(code,buffer->code,smm_code_size());

   cmp[0] = memcmp(data,buffer->data,smm_data_size());
   cmp[1] = memcmp(code,buffer->code,smm_code_size());
   error  = cmp[0] || cmp[1] ? -EFAULT : 0;

   close_smm(fixed_16k, smm_mask);

   local_irq_restore(flags);


   return(error);

}

//*********************************************************************************************

static int amd_read_smm_data(void* destination, size_t bytes, unsigned long offset)

{ // const unsigned long base = get_smm_data_phys_addr();
  const unsigned char* source = (unsigned char*)(get_smm_data_lin_addr()+offset);
  int error = 0;
  unsigned long fixed_16k;         
  unsigned long flags;
  unsigned long smm_mask;

  local_irq_save(flags);

  smm_mask = open_smm(&fixed_16k);     


  memcpy_fromio(destination,source,bytes);

  close_smm(fixed_16k, smm_mask);

  local_irq_restore(flags);


  return(error);
}


//*********************************************************************************************

static int amd_write_smm_data(void* source, size_t bytes, unsigned long offset)

{ // const unsigned long base = get_smm_data_phys_addr();
  unsigned char* destination = (unsigned char*)(get_smm_data_lin_addr()+offset);
  int error = 0;
  unsigned long fixed_16k; 
  unsigned long smm_mask;
  unsigned long flags;

  local_irq_save(flags);

  smm_mask = open_smm(&fixed_16k); 
   
  memcpy_toio(destination,source,bytes);

  error = memcmp(destination,source,bytes) ? -EFAULT : 0;

  close_smm(fixed_16k, smm_mask);

  local_irq_restore(flags);



  return(error);
}

//*********************************************************************************************

int amd_read_smm_data_word(unsigned short* word, unsigned long offset)

{ const int error = amd_read_smm_data(word, sizeof(unsigned short) ,offset);

  return(error);
}

//*********************************************************************************************

int amd_write_smm_data_word(unsigned short word, unsigned long offset)

{ const int error = amd_write_smm_data(&word, sizeof(unsigned short) ,offset);

  return(error);
}


//*********************************************************************************************

int amd_read_smm_data_byte(unsigned char* byte, unsigned long offset)

{ const int error = amd_read_smm_data(byte, sizeof(unsigned char) ,offset);


  return(error);
}

//*********************************************************************************************

int amd_write_smm_data_byte(unsigned char byte, unsigned long offset)

{ const int error = amd_write_smm_data(&byte, sizeof(unsigned char) ,offset);

  return(error);
}

//*********************************************************************************************

static int save_smm(void)

{  const unsigned char* code = (unsigned char*)get_smm_code_lin_addr();
   const unsigned char* data = (unsigned char*)get_smm_data_lin_addr();
   const int cpu             = smp_processor_id();
   struct SmmSave* buffer    = &save[cpu];
   unsigned long flags;
   unsigned long fixed_16k; 
   unsigned long smm_mask;
   int error = 0;

   local_irq_save(flags);

   smm_mask = open_smm(&fixed_16k); 

   memcpy_fromio(buffer->data,data,smm_data_size());
   memcpy_fromio(buffer->code,code,smm_code_size());

   close_smm(fixed_16k, smm_mask);

   local_irq_restore(flags);


   return(error);

}
