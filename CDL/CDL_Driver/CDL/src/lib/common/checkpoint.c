//*****************************************************************************************************

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

unsigned short checkpoint=0;

void amd_checkpoint(unsigned int code, unsigned int subcode)

{ const unsigned int amdDiag = 0xdd;
  const unsigned int core   = smp_processor_id();
  const unsigned int value  = (amdDiag << 24)  | (core << 16 ) | (code << 8) | subcode;


   switch (checkpoint) {
     case 0x80 : outl(value,0x80);
                 break;
     case 0x84 : outl(value,0x84);
                 break;
     case 0x88 : outl(value,0x88);
                 break;
     default   : break;
   }

}

//*****************************************************************************************************

static int __init parse_checkpoint(char *arg)
{
	if (!arg)
		return -EINVAL;
        checkpoint = (unsigned short)simple_strtoul(arg, NULL, 0);
	return 0;
}

early_param("checkpoint", parse_checkpoint);
