#include <linux/acpi.h>
#include <linux/bootmem.h>
#include <linux/memblock.h>
#include <linux/dmi.h>
#include <linux/cpumask.h>
#include <linux/module.h>
#include <asm/segment.h>
#include <asm/desc.h>
#include <asm/pgtable.h>
#include <asm/cacheflush.h>
#include <asm/realmode.h>
#include <asm/processor.h>
#include <asm/tlbflush.h>
#include "common.h"

//*********************************************************************************************

static DEFINE_SPINLOCK(amd_smep_lock);

//*********************************************************************************************

int amd_disable_smep(void)
{ int smep = 0;

   if (cpu_has(&boot_cpu_data, X86_FEATURE_SMEP)) {
      spin_lock(&amd_smep_lock);
      smep = cr4_read_shadow() & X86_CR4_SMEP ? 1 : 0;
      cr4_clear_bits(X86_CR4_SMEP);
      spin_unlock(&amd_smep_lock);
   }

  return(smep);
}

//*********************************************************************************************

int amd_read_smep(void)
{ int smep = 0;

  if (cpu_has(&boot_cpu_data, X86_FEATURE_SMEP)) {
      spin_lock(&amd_smep_lock);
      smep = cr4_read_shadow() & X86_CR4_SMEP ? 1 : 0;
      spin_unlock(&amd_smep_lock);
   }
  
  return(smep);

}

//*********************************************************************************************

int amd_enable_smep(void)
{ int smep = 0;

  if (cpu_has(&boot_cpu_data, X86_FEATURE_SMEP)) {
      spin_lock(&amd_smep_lock);
      smep = cr4_read_shadow() & X86_CR4_SMEP ? 1 : 0;
      cr4_set_bits(X86_CR4_SMEP);
      spin_unlock(&amd_smep_lock);
   }
  
  return(smep);

}

//*********************************************************************************************

int amd_restore_smep(int smep)


{
   if (cpu_has(&boot_cpu_data, X86_FEATURE_SMEP))   {
        spin_lock(&amd_smep_lock);
        if (smep) { 
          cr4_set_bits(X86_CR4_SMEP);
        }
        else {
          cr4_clear_bits(X86_CR4_SMEP);
        }
        spin_unlock(&amd_smep_lock);
   }
   return(smep);
}

//*********************************************************************************************

void amd_clear_in_cr4(unsigned long mask)

{
   cr4_clear_bits(mask);
}

//*********************************************************************************************

void amd_set_in_cr4(unsigned long mask)

{
   cr4_set_bits(mask);
}
