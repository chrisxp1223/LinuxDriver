#include <linux/acpi.h>
#include <linux/bootmem.h>
#include <linux/memblock.h>
#include <linux/dmi.h>
#include <linux/cpumask.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <asm/segment.h>
#include <asm/desc.h>
#include <asm/pgtable.h>
#include <asm/cacheflush.h>
#include <asm/realmode.h>
#include <asm/processor.h>
#include "common.h"

//***********************************************************************************************

extern unsigned long do_amd_user_code(uint64_t* rdi, uint64_t* rsi,uint64_t *rdx, uint64_t *rcx, uint64_t *r8, uint64_t *r9, void*  code);

//***********************************************************************************************

static DEFINE_SPINLOCK(amd_sched_lock);
static struct cpumask AMDDisableSched;

int call_amd_user_code(uint64_t *rdi,uint64_t* rsi, uint64_t *rdx, uint64_t *rcx, uint64_t *r8, uint64_t *r9, uint64_t* rax, void *code)
{
	int error = -EFAULT;
	int smep;
	unsigned long flags;
 
	if (code) {
		smep = amd_disable_smep();

		local_irq_save(flags);
		*rax = do_amd_user_code(rdi, rsi, rdx, rcx, r8, r9, code);
		local_irq_restore(flags);
		amd_restore_smep(smep);

		error = 0;
	}

	return(error);

}

int delete_amd_user_code(void* code)
{
	int error = -EFAULT;

	if (code) {
		error = 0;
		vfree(code);  
	}

	return(error);

}

int amd_disable_sched(void)
{
	spin_lock(&amd_sched_lock);

	cpumask_setall(&AMDDisableSched);
	cpumask_and(&AMDDisableSched, &AMDDisableSched, cpu_online_mask);

	spin_unlock(&amd_sched_lock);

	return(0);
}

int amd_enable_sched(void)
{
	cpumask_clear(&AMDDisableSched);

	return(0);
}

int amd_disable_current_sched(void)
{
	const int cpu   = smp_processor_id();
	const int state = cpumask_test_and_set_cpu(cpu, &AMDDisableSched);

	return(state);
}

int amd_enable_current_sched(void)
{
	const int cpu   = smp_processor_id();
	const int state = cpumask_test_and_clear_cpu(cpu, &AMDDisableSched);

	return(state);
}

int install_amd_user_code(void *user, size_t size, unsigned long *kernelCode)
{
	int  error = 0;
	char *kmem;

	*kernelCode = 0;

	kmem = __vmalloc(size, GFP_KERNEL, PAGE_KERNEL_EXEC);

	if (kmem)  {
		if (copy_from_user(kmem, user, size)) {
			error = -EFAULT;
			vfree(kmem);
		} else {
			*kernelCode = (unsigned long) kmem;
			error = 0;
		}
	} else
		error = -ENOMEM;

	return(error);
}
