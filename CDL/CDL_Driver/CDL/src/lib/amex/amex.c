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
#include "../common/common.h"


extern void amex_lowlevel(uint64_t target, uint64_t rsi, uint64_t rdx);
extern void amex_dummy(void);


// Do not send TLB flush IPI to cores running AMEX templates

DEFINE_SPINLOCK(amex_lock);
cpumask_t amex_ipi_disabled_mask = CPU_MASK_NONE;
int offline_amex_cores = 0;

int amex_enable_tlb_flush(int cpu)
{
	int rc = -EFAULT;

	if ((cpu >= 0) && (cpu < num_possible_cpus()))  {
		spin_lock(&amex_lock);

		rc = 0;

		if (cpumask_test_cpu(cpu, &amex_ipi_disabled_mask)) {
			// cpu_clear(cpu,amex_ipi_disabled_mask);
			cpumask_clear_cpu(cpu, &amex_ipi_disabled_mask);

			offline_amex_cores--;
		}

		spin_unlock(&amex_lock);
	}

	return rc; 
}

int amex_disable_tlb_flush(int cpu)
{
	int rc = -EFAULT;

	if ((cpu >= 0) && (cpu <  num_possible_cpus()))  {
		spin_lock(&amex_lock);

		rc = 0;

		if (!cpumask_test_cpu(cpu, &amex_ipi_disabled_mask)) {
			cpumask_set_cpu(cpu, &amex_ipi_disabled_mask);

			offline_amex_cores++;
		}

		spin_unlock(&amex_lock);
	}

	return rc; 
}

int amex(uint64_t target, uint64_t rsi, uint64_t rdx)
{
	unsigned long flags;
	int status = 0;
	int smep;

	local_irq_save(flags);
	smep = amd_disable_smep();

	amex_lowlevel(target, rsi, rdx);

	amd_restore_smep(smep);
	local_irq_restore(flags);

	return(status);
}

unsigned long get_amex_dummy(void)
{
	return((unsigned long) &amex_dummy);

}
