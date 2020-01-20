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
#include "common.h"

//*********************************************************************************************

#define MSR_BIST_DATA 0xc0010060

//*********************************************************************************************

enum { BIST_OFF, BIST_WARN, BIST_FAIL };

static int  bist_mode=BIST_FAIL;
static unsigned long bist_disable_mask = 0;

static unsigned long bist[NR_CPUS]  = {[0 ... NR_CPUS-1] = 0};
static unsigned long bistFailed = 0;



//*********************************************************************************************

void amd_bist_check(void)

{ int cpu;
  cpumask_t mask;

    if (bist_mode != BIST_OFF && boot_cpu_data.x86 >= 0x10) {
           mask = current->cpus_allowed;
           for_each_online_cpu(cpu) {
                  set_cpus_allowed(current, cpumask_of_cpu(cpu));
		  printk("BIST Check : cpu=%d\n",smp_processor_id());
                  rdmsrl(MSR_BIST_DATA,bist[cpu]);
                  bistFailed |= ( bist[cpu] & ~bist_disable_mask);
                  if (bist[cpu]) {
                     printk(KERN_CRIT "BIST ERROR: CPU-%02d=0x%016lx\n",smp_processor_id(),bist[cpu]);
                  }
           }

           set_cpus_allowed(current, mask);

           if (bistFailed) {
              if (bist_mode == BIST_FAIL) {
                 printk("BIST Check : Failed!\n");
                 printk("           : Append bist=warn to GRUB boot options to boot despite BIST errors.\n");
                 printk("           : Abandon all hope ye who enter here.");
                 panic(" ");
              }
              else {
                 printk(KERN_CRIT "BIST Check: Booting with errors!\n");
              }
           }
}
else {
   printk(KERN_CRIT "BIST Check: Disabled!\n");
}


}

//*********************************************************************************************

static int __init amd_parse_bist(char *arg)
{
        if (!arg)
                return -EINVAL;

        if(!memcmp(arg, "off", 3)) {
           bist_mode = BIST_OFF;
        }

        else if(!memcmp(arg, "warn", 4)) {
           bist_mode = BIST_WARN;
           if (*(arg+4) == ',') {
             bist_disable_mask = simple_strtoul(arg+5, NULL, 0);
           }
        }

        else if(!memcmp(arg, "fail",4)) {
           bist_mode = BIST_FAIL;
           if (*(arg+4) == ',') {
             bist_disable_mask = simple_strtoul(arg+5, NULL, 0);
           }
        }

        return 0;
}

//*********************************************************************************************

early_param("bist", amd_parse_bist);

                                     
