//! Linux CDL driver - 2nd Generation.
/** \file
 *  \author Michael Floyd
 */

/** \if Copyright
 * Copyright 2013-2016 ADVANCED MICRO DEVICES, INC. All Rights Reserved.
 *
 * This software and any related documentation (the "Materials") are the
 * confidential proprietary information of AMD. Unless otherwise provided
 * in a software agreement specifically licensing the Materials, the Materials
 * are provided in confidence and may not be distributed, modified, or
 * reproduced in whole or in part by any means.
 *
 * LIMITATION OF LIABILITY: THE MATERIALS ARE PROVIDED "AS IS" WITHOUT ANY
 * EXPRESS OR IMPLIED WARRANTY OF ANY KIND, INCLUDING BUT NOT LIMITED TO
 * WARRANTIES OF MERCHANTABILITY, NONINFRINGEMENT, TITLE, FITNESS FOR ANY
 * PARTICULAR PURPOSE, OR WARRANTIES ARISING FORM CONDUCT, COURSE OF DEALING,
 * OR USAGE OF TRADE.  IN NO EVENT SHALL AMD OR ITS LICENSORS BE LIABLE FOR
 * ANY DAMAGES WHATSOEVER (INCLUDING, WITHOUT LIMITATION, DAMAGES FOR LOSS OF
 * PROFITS, BUSINESS INTERRUPTION, OR LOSS OF INFORMATION) ARISING OUT OF THE
 * USE OF OR INABILITY TO USE THE MATERIALS, EVEN IF AMD HAS BEEN ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGES.  BECAUSE SOME JURISDICTIONS PROHIBIT THE
 * EXCLUSION OR LIMITATION OF LIABILITY FOR CONSEQUENTIAL OR INCIDENTAL DAMAGES,
 * THE ABOVE LIMITATION MAY NOT APPLY TO YOU.
 *
 * AMD does not assume any responsibility for any errors which may appear in the
 * Materials nor any responsibility to support or update the Materials.  AMD
 * retains the right to modify the Materials at any time, without notice,
 * and is not obligated to provide such modified Materials to you.
 *
 * NO SUPPORT OBLIGATION: AMD is not obligated to furnish, support, or make any
 * further information, software, technical information, know-how, or show-how
 * available to you.
 *
 * U.S. GOVERNMENT RESTRICTED RIGHTS: The Materials are provided with
 * "RESTRICTED RIGHTS." Use, duplication, or disclosure by the Government
 * is subject to the restrictions as set forth in FAR 52.227-14 and DFAR
 * 252.227-7013, et seq., or its successor.  Use of the Materials by the
 * Government constitutes acknowledgement of AMD's proprietary rights in them.
 * \endif
 */
/** */


#include <asm/tlbflush.h>
#include <asm/uaccess.h>
#include <asm/current.h>
#include <asm/pat.h>
#include <asm/proto.h>
#include <asm/apic.h>
#include <asm/cacheflush.h>
#include <asm/realmode.h>
#include <asm/processor.h>
#include <asm/pgtable_types.h>
#include <asm/pgalloc.h>
#include <asm/pgtable.h>
#include <asm/hw_irq.h>
#include <asm/desc.h>
#include <asm/desc_defs.h>
#include <asm/delay.h>
#include <asm/msr.h>
#include <asm/irq_vectors.h>

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/device.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/kmod.h>
#include <linux/rwsem.h>
#include <linux/spinlock.h>
#include <linux/cpumask.h>
#include <linux/interrupt.h>
#include <linux/smp.h>
#include <linux/pci.h>
#include <linux/io.h>
#include <linux/delay.h>
#include <linux/version.h>
#include <linux/hugetlb.h>
#include <linux/irqflags.h>
#include <linux/sched.h>
#include <linux/moduleparam.h>
#include <linux/kallsyms.h>

#include "cdl_ioctl.h"
#include "cdl_driver.h"


MODULE_LICENSE("GPL");
MODULE_VERSION("1.00.00");
MODULE_DESCRIPTION("The device driver for AMD CPU Diagnostics Suite.\n");


extern int amd_install_smi_handler(void *, size_t);
extern int amd_restore_smi_handler(void);
extern int amd_write_smm_data_byte(unsigned char, unsigned long);
extern int amd_read_smm_data_byte(unsigned char *, unsigned long);
extern int amd_send_smi(unsigned long);
extern int amex(uint64_t, uint64_t, uint64_t);
extern int amd_disable_smep(void);
extern int amd_restore_smep(int);
extern unsigned long do_amd_user_code(uint64_t *, uint64_t *, uint64_t *, uint64_t *, uint64_t *, uint64_t *, void *);
extern int install_amd_user_code(void *, size_t, unsigned long *);
extern int call_amd_user_code(uint64_t *, uint64_t *, uint64_t *, uint64_t *, uint64_t *, uint64_t *, uint64_t *, void *);
extern int delete_amd_user_code(void *);
extern int amd_disable_sched(void);
extern int amd_enable_sched(void);
extern int amd_disable_current_sched(void);
extern int amd_enable_current_sched(void);
extern int amex_enable_tlb_flush(int);
extern int amex_disable_tlb_flush(int);


static struct class *amd_cpu_diag_class;
static int amd_cpu_diag_major;

static const int domain;
static uint64_t  global_mem_type;

static struct cdl_irq_desc cdlirqdesc[NR_VECTORS];
static struct desc_ptr idtr;
static struct irq_desc *desc_backup[MAX_NUM_CPUS];

/* DBG/TMP - content of pv_irq_ops.adjust_exception_frame, it's a function */
static unsigned long addr_adjust_exception_frame;
static unsigned long addr_error_entry = 0UL;
static unsigned long addr_error_exit = 0UL;
module_param(addr_adjust_exception_frame, ulong, S_IRUGO);
module_param(addr_error_entry, ulong, S_IRUGO);
module_param(addr_error_exit, ulong, S_IRUGO);

static DEFINE_SPINLOCK(irq_lock);
static DEFINE_SPINLOCK(msr_rmw_lock);
static DEFINE_SPINLOCK(pci_rmw_lock);


extern uint64_t amd_phys(uint64_t linear, uint64_t offset);
extern int invlpgb(uint64_t linearaddress, uint64_t count);
extern int tlbsync(void);


/*
 * section 1 - library functions
 */
static irqreturn_t dummy(int irq, void *dev_id)
{
	return(IRQ_HANDLED);
}

static unsigned long  private_msr_write(unsigned long msr, unsigned long datum, unsigned long edi, unsigned long esi)
{
	const uint64_t mask = 0x00000000ffffffffull;
	const uint32_t low  = (uint32_t) (datum  &  mask);
	const uint32_t high = (uint32_t) ((datum & ~mask) >> 32);

	asm volatile  (
		"  movl   %0,%%ecx   \n"
		"  movl   %1,%%edi   \n"
		"  movl   %2,%%esi   \n"
		"  movl   %3,%%eax   \n"
		"  movl   %4,%%edx   \n"
		"  wrmsr             \n"

		//*********** Output **************
		: // None

		//*********** Input ***************
		: "m"  (msr),      // %0
		  "m"  (edi),      // %1
		  "m"  (esi),      // %2
		  "m"  (low),      // %3
		  "m"  (high)      // %4
		//****** Clobbered Registers ******
		: "%eax",
		  "%ecx",
		  "%edx",
		  "%esi",
		  "%edi"
	);

	return(0);
}

unsigned long  private_msr_read(unsigned long msr, unsigned long edi, unsigned long esi)
{
	uint32_t low   = 0;
	uint32_t high  = 0;

	asm volatile  (
		"  movl   %2,%%ecx   \n"
		"  movl   %3,%%edi   \n"
		"  movl   %4,%%esi   \n"
		"  rdmsr             \n"
		"  movl  %%edx,%1    \n"
		"  movl  %%eax,%0    \n"

		//*********** Output **************
		: "=m" (low),    // %0
		  "=m" (high)    // %1

		//*********** Input ***************
		: "m"  (msr),   // %2
		  "m"  (edi),   // %3
		  "m"  (esi)    // %4

		//****** Clobbered Registers ******
		: "%eax",
		  "%ecx",
		  "%edx",
		  "%esi",
		  "%edi"
	);

	return ((((uint64_t) high << 32) | (uint64_t) low));
}

void __attribute__((weak))
unmap_devmem(uint64_t pfn, uint64_t len, pgprot_t prot)
{
	/* nothing. architectures can override. */
}

static int bad_address(void *p)
{
	uint64_t dummy;
	return __get_user(dummy, (uint64_t *)p);
}

static uint64_t local_set_pte(struct mm_struct *mm, uint64_t address, uint64_t clear, uint64_t set )
{
	pgd_t *pgd =  pgd_offset(mm, address);
	int64_t rc = -EFAULT;
 
	if (bad_address(pgd)) {
		/* nothing ? */
	} else if (!pgd_present(*pgd)) {
		/* nothing ? */
	} else {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
		pud_t *pud = pud_offset(pgd, address);
#else
		p4d_t *p4d = p4d_offset(pgd, address);
		pud_t *pud = pud_offset(p4d, address);
#endif

		if (!bad_address(pud)) {
			pmd_t *pmd = pmd_offset(pud, address);

			if (!bad_address(pmd)) {
				pte_t *pte = pte_offset_map(pmd, address);

				if (!pte_none(*pte)) {
					set_pte(pte,__pte((pte_val(*pte) & ~clear) | set));
					rc = 0;
				}
			}
		}
	}

	return(rc);
}

static int modify_page_flags(struct mm_struct *mm, uint64_t vaddr, size_t len, uint64_t set_bits, uint64_t clear_bits)
{
	struct vm_area_struct *vma;
	uint64_t end;
	int ret_val = 0;
	int i = 0;

	vma = find_vma(mm, vaddr);

	if(!vma)
		return -EFAULT;

	if(vma->vm_end < vaddr + len)
		return -EFAULT;
 
	if(!(vma->vm_flags & VM_LOCKED))
		vma->vm_flags |= VM_LOCKED;

	spin_lock(&mm->page_table_lock);

	for(end = vaddr + len; end > vaddr && ret_val == 0; vaddr += PAGE_SIZE)
		ret_val = local_set_pte(mm, vaddr, clear_bits, set_bits);
 
	for_each_online_cpu(i)
		__flush_tlb_all();

	spin_unlock(&mm->page_table_lock);

	return ret_val;
}

static void my_load_idt(void *info)
{
    struct desc_ptr *idtr = (struct desc_ptr *) info;

    load_idt(idtr);
}

void amd_default_vector_allocation_domain(int cpu, struct cpumask *retmask, const struct cpumask *mask)
{
       cpumask_copy(retmask, cpu_online_mask);
}

static int install_hwirq_handler(void *handler, size_t size, int vector)
{
	int        error = 0;
	unsigned   long flags;
	const int  iflags = IRQF_NOBALANCING;
	int        irq = 0;
	void      *destination;
	char      *name;
	cpumask_var_t tmp_mask;
  
	spin_lock_irqsave(&irq_lock, flags);

	if (cdlirqdesc[vector].handler == RESERVED && cdlirqdesc[vector].irq != NO_IRQ)
		destination = __vmalloc(size, GFP_KERNEL, PAGE_KERNEL_EXEC); 
	else {
		spin_unlock_irqrestore(&irq_lock, flags);
		return -EBUSY;
	}

	if (!copy_from_user(destination, handler, size)) {
		cdlirqdesc[vector].handler = destination;
		irq                        = cdlirqdesc[vector].irq;
		name                       = cdlirqdesc[vector].name;

		{
			int i = 0;
			vector_irq_t *ksym_vector_irq = NULL;

			ksym_vector_irq = (vector_irq_t *) kallsyms_lookup_name("vector_irq");

			if(ksym_vector_irq) {
				for_each_online_cpu(i) {
					if (i < MAX_NUM_CPUS)
						desc_backup[i] = per_cpu(*ksym_vector_irq, i)[vector];
					else {
						printk("ERROR: %s: number of CPUs bigger than max supported: %d vs %d\n",  __func__, i, MAX_NUM_CPUS);
						printk("ERROR: %s: please increase MAX_NUM_CPUS value\n",  __func__);
					}
				}
			} else
				printk("ERROR: can't find the symbol - vector_irq\n");
		}

		error = request_irq(irq, destination, iflags, name, NULL) ? -EBUSY : 0;

		{
			int i = 0;
			vector_irq_t *ksym_vector_irq = NULL;

			ksym_vector_irq = (vector_irq_t *) kallsyms_lookup_name("vector_irq");

			if(ksym_vector_irq) {
				for_each_online_cpu(i) {
					struct irq_desc *desc = irq_to_desc(irq);

					if (i < MAX_NUM_CPUS)
						per_cpu(*ksym_vector_irq, i)[vector] = desc;
					else {
						printk("ERROR: %s: number of CPUs bigger than max supported: %d vs %d\n",  __func__, i, MAX_NUM_CPUS);
						printk("ERROR: %s: please increase MAX_NUM_CPUS value\n",  __func__);
					}
				}
			} else
				printk("ERROR: can't find the symbol - vector_irq\n");
		}

		if (!alloc_cpumask_var(&tmp_mask, GFP_ATOMIC))
			error = -ENOMEM;

		cpumask_copy(tmp_mask, cpu_online_mask);

		free_cpumask_var(tmp_mask);
	} else {
		vfree(destination);

		cdlirqdesc[vector].handler = NULL;
		error                      = -EFAULT; 
	}

	spin_unlock_irqrestore(&irq_lock, flags);

	return(error);
}

static int remove_hwirq_handler(int vector)
{
	int      error = 0;
	unsigned long flags;

	spin_lock_irqsave(&irq_lock, flags);

	if (cdlirqdesc[vector].handler != NULL) { 
		vfree(cdlirqdesc[vector].handler);

		cdlirqdesc[vector].handler = NULL;

		free_irq(cdlirqdesc[vector].irq, NULL);

		{
			int i = 0;
			vector_irq_t *ksym_vector_irq = NULL;

			ksym_vector_irq = (vector_irq_t *) kallsyms_lookup_name("vector_irq");

			if(ksym_vector_irq) {
				for_each_online_cpu(i) {
					if (i < MAX_NUM_CPUS)
						per_cpu(*ksym_vector_irq, i)[vector] = desc_backup[i];
					else {
						printk("ERROR: %s: number of CPUs bigger than max supported: %d vs %d\n",  __func__, i, MAX_NUM_CPUS);
						printk("ERROR: %s: please increase MAX_NUM_CPUS value\n",  __func__);
					}
				}
			} else
				printk("ERROR: can't find the symbol - vector_irq\n");
		}

		cdlirqdesc[vector].irq = NO_IRQ;
	}

	spin_unlock_irqrestore(&irq_lock, flags);

	return(error);
}

static int install_exception_handler(void *handler, size_t size, int vector)
{
	int       error = 0;
	int       i = 0;
	void     *destination;
	unsigned  long flags;
	idt_desc *idtdesc;
	gate_desc gatedesc;
	uint64_t  start, end;
	struct mm_struct *mm = current->mm;

	spin_lock_irqsave(&irq_lock, flags);

	if (cdlirqdesc[vector].handler == NULL)
		destination = __vmalloc(size, GFP_KERNEL, PAGE_KERNEL_EXEC); 
	else {
		printk(KERN_ERR "ERR: vector %d handler is being used.\n", vector);

		error = -EBUSY;

		goto error0;
	}

	if (!destination) {
		printk(KERN_ERR "ERR: memory allocation failed for vector %d handler.\n", vector);

		error = -ENOMEM;

		goto error0;
	}
 
	if (!copy_from_user(destination, handler, size)) {
		store_idt(&idtr);

		start = (uint64_t) idtr.address;
		end   = (uint64_t) idtr.address + idtr.size;

		for(end = start + idtr.size; end > start; start += PAGE_SIZE)
			error = local_set_pte(mm, start, 0, PAGE_RW);

		for_each_online_cpu(i)
			__flush_tlb_all();

		idtdesc = (idt_desc *)(idtr.address);

		/* backup the original IDT entry */
		memcpy(&cdlirqdesc[vector].idtdesc, (void *) &idtdesc[vector], sizeof(idt_desc));

		/* replace the entry associate to the vector with new handler */
		pack_gate(&gatedesc, GATE_INTERRUPT,
		    (unsigned long) destination, 0, 0, __KERNEL_CS); 
		write_idt_entry(idtdesc, vector, &gatedesc);

		cdlirqdesc[vector].handler = destination;

		/* modify the IDTR with the new address */
		load_idt(&idtr);

		error = 0;
	} else {
		printk("ERROR: %s: copy from the user space has failed for vector %d handler.\n", __func__, vector);
		cdlirqdesc[vector].handler = NULL;

		error = -EFAULT; 

		goto error2;
	}

	spin_unlock_irqrestore(&irq_lock, flags);

	/* wait till all are finished */
	smp_call_function(my_load_idt, (void *) &idtr, 1);

	return(error);
error2:
	vfree(destination);
error0:
	spin_unlock_irqrestore(&irq_lock, flags);

	return(error);
}

static int remove_exception_handler(int vector)
{
	int       error = 0;
	unsigned  long flags;
	struct desc_ptr idtr;
	idt_desc *idtdesc;

	spin_lock_irqsave(&irq_lock, flags);

	if (cdlirqdesc[vector].handler != NULL) { 
		store_idt(&idtr);

		idtdesc = (idt_desc *)(idtr.address);

		/* restore the original IDT entry */
		memcpy(&idtdesc[vector], (void *) &cdlirqdesc[vector].idtdesc, sizeof(idt_desc));
		vfree(cdlirqdesc[vector].handler);

		cdlirqdesc[vector].handler = NULL;

		/* restor the IDT back to the original */
		load_idt(&idtr);

		error  = 0; 
	} else {
		cdlirqdesc[vector].handler = NULL;

		error = -EFAULT; 
	}

	spin_unlock_irqrestore(&irq_lock, flags);

	/* wait till all are finished */
	smp_call_function(my_load_idt, (void *) &idtr, 1);
	store_idt(&idtr);

	return(error);
}

static uint64_t get_linear_address(uint64_t physical)
{
	const uint64_t error  = ~0ull;
	const uint64_t end    = ~0ull;
	uint64_t linear       = ~0ull;
	const uint64_t mask[] = { 0xffff880000000000ull, 0x0ffffffff80000000ull, 0xffff810000000000ull, 0ull, ~0ull};
	uint64_t page_offset;
	int      valid=0;
	int      i;
	unsigned long flags;

	spin_lock_irqsave(&irq_lock, flags);

	page_offset = __PAGE_OFFSET;

	for (i = 0; mask[i] != end && !valid; i++) {
		linear = physical | mask[i];
		valid = amd_phys(linear, page_offset) == physical ? 1 : 0;
	}

	spin_unlock_irqrestore(&irq_lock, flags);

	return(!valid ? error :  linear );
}

static uint64_t follow_pte(struct mm_struct * mm, unsigned long address, pte_t * entry)
{
	uint64_t  phys=0xFFFFFFFF;
	pgd_t    *pgd = pgd_offset(mm, address);
	int       offset = address & (PAGE_SIZE -1);

	entry->pte = 0;

	if (!pgd_none(*pgd) && !pgd_bad(*pgd)) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
		pud_t *pud = pud_offset(pgd, address);
#else
		p4d_t *p4d = p4d_offset(pgd, address);
		pud_t *pud = pud_offset(p4d, address);
#endif
		struct vm_area_struct *vma = find_vma(mm, address);

		if (pud_none(*pud))
			return phys;

		if ( vma->vm_flags & VM_HUGETLB) {
			entry->pte = pud_val(*pud);
			return phys;
		}

		if (!pud_bad(*pud)) {
			pmd_t *pmd = pmd_offset(pud, address);

			if (pmd_none(*pmd))
				return phys;
 
			if (vma->vm_flags & VM_HUGETLB) {
				entry->pte = pmd_val(*pmd);

				return phys;
			}

			if (pmd_trans_huge(*pmd)) {
				entry->pte = pmd_val(*pmd);

				return phys;
			}

			if (!pmd_bad(*pmd)) {
				pte_t * pte = pte_offset_map(pmd, address);

				if (!pte_none(*pte)) {
					entry->pte = pte_val(*pte);
					phys = (resource_size_t) pte_pfn(*pte) << PAGE_SHIFT;	
					phys = phys + offset;	
				}

				pte_unmap(pte);

				return phys;
			}
		}
	}

	return phys;
}

static int swi_gen(int vector)
{
	int error = -EFAULT;

	switch (vector) {
	case 0xe1:
		asm volatile ("int $0xe1"); 
		error = 0;
		break;
	default:
		printk("ERROR: %s: invalid vector = %d\n", __func__, vector);
	}

	return(error);
}

static int amd_cpu_diag_device_create(int cpu)
{
	struct device *dev;

	dev = device_create(amd_cpu_diag_class, NULL, MKDEV(amd_cpu_diag_major, cpu), NULL, "amd_cpu_diag%d", cpu);

	return IS_ERR(dev) ? PTR_ERR(dev) : 0;
}

static void amd_cpu_diag_device_destroy(int cpu)
{
	device_destroy(amd_cpu_diag_class, MKDEV(amd_cpu_diag_major, cpu));
}

static char* amd_cpu_diag_nodename(struct device *dev, umode_t *mode)
{
	return kasprintf(GFP_KERNEL, "cpu/%u/amd_cpu_diag", MINOR(dev->devt));
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 20, 0)
extern int vector_to_irq(int vector);
    
int irq_to_vector(int irq)
{
	int vector;
	for (vector = FIRST_EXTERNAL_VECTOR; vector < VECTORS; vector++) {
		if (irq == vector_to_irq(vector))
			return vector;
	}
    
	printk("ERROR: %s: Failed to convert irq to vector (irq = %d)\n",
	    __func__, irq);

	return -EINVAL;
}

#else
#include <asm/hw_irq.h>
#include <linux/irqnr.h>
#include <linux/irq.h>
#include <linux/irqdesc.h>
#include <linux/interrupt.h>

int irq_to_vector(int irq)
{
	struct irq_desc *desc = irq_to_desc(irq);        // <= this function is in the symbol map
	struct irq_cfg *cfg = irqd_cfg(&desc->irq_data); // irqd_cfg is in kernel 4.X but not 3.X

	return cfg->vector;
}
#endif

int set_page_table_entry(struct mm_struct * mm, pte_t * entry, uint64_t addr,
                         uint64_t set, uint64_t clear, uint64_t size)
{
	uint64_t address,end;
	int error=-EINVAL;

	end = addr + size;

	entry->pte = 0;

	for(address = addr; address <  end ; address += PAGE_SIZE) {
		pgd_t *pgd = pgd_offset(mm, address);

		if (!pgd_none(*pgd) && !pgd_bad(*pgd)) {

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
			pud_t *pud = pud_offset(pgd, address);
#else
			p4d_t *p4d = p4d_offset(pgd, address);
			pud_t *pud = pud_offset(p4d, address);
#endif
			struct vm_area_struct *vma = find_vma(mm, address);

			if (pud_none(*pud)) {
				printk(KERN_ERR "Get pud failed, addr:%llu\n",
				    address);
				return -EINVAL;
			}

			if ( vma->vm_flags & VM_HUGETLB)
				entry->pte = pud_val(*pud);

			if (!pud_bad(*pud)) {
				pmd_t *pmd = pmd_offset(pud, address);

				if (pmd_none(*pmd)) {
					printk(KERN_ERR 
					    "Get pmd failed, addr:%llu\n",
					    address);
					return -EINVAL;
				}

				if (vma->vm_flags & VM_HUGETLB)
					entry->pte = pmd_val(*pmd);

				if (pmd_trans_huge(*pmd))
					entry->pte = pmd_val(*pmd);

				if (!pmd_bad(*pmd)) {
					pte_t *pte = pte_offset_map(pmd,
						       	address);

					if (!pte_none(*pte)) {
						entry->pte = pte_val(*pte);
						set_pte(pte, __pte((pte_val(*pte) & ~clear) | set));
						error = 0;
					} else {
						printk(KERN_ERR "Get pte failed, addr:%llu\n", address);
						return -EINVAL;
					}

					pte_unmap(pte);
				} else {
					printk(KERN_ERR "Get pmd failed, addr:%llu\n", address);

					return -EINVAL;
				}
			} else {
				printk(KERN_ERR "Get pud failed, addr:%llu\n", address);

				return -EINVAL;
			}
		} else {
			printk(KERN_ERR "Get pgd failed, addr:%llu\n", address);

			return -EINVAL;
		}
	}

	return error;
}

const char *print_ioctl_cmd(enum amd_ioctl_cmd cmd) 
{
	switch (cmd) {
		case EXECUTE_WBINVD_INSTRUCTION:
			return "EXECUTE_WBINVD_INSTRUCTION";
		case READ_PVT_MSR:
			return "READ_PVT_MSR";
		case WRITE_PVT_MSR:
			return "WRITE_PVT_MSR";
		case RMW_PVT_MSR:
			return "RMW_PVT_MSR";
		case PRE_SET_MEMORY_TYPE:
			return "PRE_SET_MEMORY_TYPE";
		case HLT:
			return "HLT";
		case HLT_IOPORT:
			return "HLT_IOPORT";
		case READ_PCI_IOPORT:
			return "READ_PCI_IOPORT";
		case WRITE_PCI_IOPORT:
			return "WRITE_PCI_IOPORT";
		case RMW_PCI_IOPORT:
			return "RMW_PCI_IOPORT";
		case DISABLE_TLBFLUSH_IPI:
			return "DISABLE_TLBFLUSH_IPI";
		case ENABLE_TLBFLUSH_IPI:
			return "ENABLE_TLBFLUSH_IPI";
		case CALL_AMEX_ENTRY:
			return "CALL_AMEX_ENTRY";
		case DISABLE_SCHEDULER:
			return "DISABLE_SCHEDULER";
		case ENABLE_SCHEDULER:
			return "ENABLE_SCHEDULER";
		case DISABLE_CURRENT_SCHEDULER:
			return "DISABLE_CURRENT_SCHEDULER";
		case ENABLE_CURRENT_SCHEDULER:
			return "ENABLE_CURRENT_SCHEDULER";
		case INSTALL_AMD_USER_CODE:
			return "INSTALL_AMD_USER_CODE";
		case CALL_AMD_USER_CODE:
			return "CALL_AMD_USER_CODE";
		case DELETE_AMD_USER_CODE:
			return "DELETE_AMD_USER_CODE";
		case READ_CR4:
			return "READ_CR4";
		case WRITE_CR4:
			return "WRITE_CR4";
		case SET_IN_CR4:
			return "SET_IN_CR4";
		case CLEAR_IN_CR4:
			return "CLEAR_IN_CR4";
		case IS_SMM_LOCKED:
			return "IS_SMM_LOCKED";
		case INSTALL_SMI_HANDLER:
			return "INSTALL_SMI_HANDLER";
		case RESTORE_SMI_HANDLER:
			return "RESTORE_SMI_HANDLER";
		case WRITE_SMM_BYTE:
			return "WRITE_SMM_BYTE";
		case READ_SMM_BYTE:
			return "READ_SMM_BYTE";
		case SEND_SMI:
			return "SEND_SMI";
		case INSTALL_INTERRUPT_HANDLER:
			return "INSTALL_INTERRUPT_HANDLER";
		case DISABLE_INTERRUPT_HANDLER:
			return "DISABLE_INTERRUPT_HANDLER";
		case ENABLE_INTERRUPT_HANDLER:
			return "ENABLE_INTERRUPT_HANDLER";
		case REMOVE_INTERRUPT_HANDLER:
			return "REMOVE_INTERRUPT_HANDLER";
		case READ_INTERRUPT_DATA:
			return "READ_INTERRUPT_DATA";
		case WRITE_INTERRUPT_DATA:
			return "WRITE_INTERRUPT_DATA";
		case INTERRUPT_TEST:
			return "INTERRUPT_TEST";
		case INVALIDATE_PAGE:
			return "INVALIDATE_PAGE";
		case INVALIDATE_TLB:
			return "INVALIDATE_TLB";
		case INVALIDATE_CACHES:
			return "INVALIDATE_CACHES";
		case FLUSH_CACHE_LINE:
			return "FLUSH_CACHE_LINE";
		case READ_GS_BASE:
			return "READ_GS_BASE";
		case READ_CR2:
			return "READ_CR2";
		case WRITE_CR2:
			return "WRITE_CR2";
		case READ_CR3:
			return "READ_CR3";
		case WRITE_CR3:
			return "WRITE_CR3";
		case STGI:
			return "STGI";
		case CLGI:
			return "CLGI";
		case READ_CR8:
			return "READ_CR8";
		case WRITE_CR8:
			return "WRITE_CR8";
		case GET_LINEAR_ADDRESS:
			return "GET_LINEAR_ADDRESS";
		case GET_PHYSICAL_ADDRESS:
			return "GET_PHYSICAL_ADDRESS";
		case RESERVE_VECTOR:
			return "RESERVE_VECTOR";
		case FREE_VECTOR:
			return "FREE_VECTOR";
		case GET_LAPIC_LINBASE:
			return "GET_LAPIC_LINBASE";
		case HARDLOCK:
			return "HARDLOCK";
		case READ_USER_DATA:
			return "READ_USER_DATA";
		case WRITE_USER_DATA:
			return "WRITE_USER_DATA";
		case SEND_INT_ALL:
			return "SEND_INT_ALL";
		case SEND_INT_ALL_BUT_SELF:
			return "SEND_INT_ALL_BUT_SELF";
		case SEND_INT_MASK:
			return "SEND_INT_MASK";
		default:
			return "unknown IOCTL cmd";
	}
}


/*
 * section 1 - functions for each IOCTL commands
 */
/* IOCTL command: IOCTL_READ_PCI_IOPORT */
static int  pci_read_ioport(uint64_t user)
{
	uint64_t input[IARGS5];
	uint8_t  type     = 0;
	uint16_t bus      = 0;
	uint16_t device   = 0;
	uint16_t function = 0;
	uint16_t offset   = 0;
	uint32_t dword    = 0;
	uint16_t word     = 0;
	uint8_t byte      = 0;
	uint64_t qword    = 0;
	int error = -EFAULT;
	struct pci_dev *pdev;
	int devfn;

	if (!copy_from_user(input, (uint64_t *) user, IARGS5 * ARGSIZE)) {

		type     = input[0];
		bus      = input[1];
		device   = input[2];
		function = input[3];
		offset   = input[4];
		devfn    = PCI_DEVFN(device, function);

		pdev = pci_get_domain_bus_and_slot(domain, bus, devfn);
     
		if (!pdev || pci_enable_device(pdev))
			return(-EFAULT);

		switch (type) {
		case PCI_IO_PORT_BYTE_ACCESS:
			error = pci_read_config_byte(pdev, offset, &byte);
			qword = (uint64_t) byte;
			break;
		case PCI_IO_PORT_WORD_ACCESS:
			error = pci_read_config_word(pdev, offset, &word);
			qword = (uint64_t) word;
			break;
		case PCI_IO_PORT_INT_ACCESS:
			error = pci_read_config_dword(pdev, offset, &dword);
			qword = (uint64_t) dword;
			break;
		default:
			error = -EINVAL;
			break;
		}

		error = copy_to_user((uint64_t *) user, &qword, 1 * ARGSIZE) ?
		    -EFAULT : 0;

	}

	return(error);
}

/* IOCTL command: IOCTL_WRITE_PCI_IOPORT */
static int pci_write_ioport(uint64_t user)
{
	uint64_t input[IARGS6];
	uint8_t  type       = 0;
	uint64_t qword      = 0;
	uint16_t bus        = 0;
	uint16_t device     = 0;
	uint16_t function   = 0;
	uint16_t offset     = 0;
	uint8_t byte        = 0;
	uint16_t word       = 0;
	uint32_t dword      = 0;
	int error = -EFAULT;
	struct pci_dev *pdev;
	int devfn;
    
	if (!copy_from_user(input, (uint64_t *) user, IARGS6 * ARGSIZE)) {
		type     = input[0];
		qword    = input[1];
		bus      = input[2];
		device   = input[3];
		function = input[4];
		offset   = input[5];
		devfn    = PCI_DEVFN(device, function);
 
		pdev = pci_get_domain_bus_and_slot(domain, bus, devfn);
     
		if (!pdev || pci_enable_device(pdev))
			return(-EFAULT);

		switch (type) {
		case PCI_IO_PORT_BYTE_ACCESS:
			byte  = (uint8_t) qword;
			error = pci_write_config_byte(pdev, offset, byte);
			break;

		case PCI_IO_PORT_WORD_ACCESS:
			word = (uint16_t) qword;
			error = pci_write_config_word(pdev, offset, word);
			break;
		case PCI_IO_PORT_INT_ACCESS:
			dword = (uint32_t) qword;
			error = pci_write_config_dword(pdev, offset, dword);
			break;
		default:
			error = -EINVAL;
			break;
		}
	}

	return (error);
}

/* IOCTL command: IOCTL_RMW_PCI_IOPORT */
static int  pci_rmw_ioport(uint64_t user)
{
	uint64_t input[IARGS7];
	uint32_t dword    = 0;
	uint16_t word     = 0;
	uint8_t  byte     = 0;
	uint8_t  type     = 0;
	uint16_t bus      = 0;
	uint16_t device   = 0;
	uint16_t function = 0;
	uint16_t offset   = 0;
	uint32_t set      = 0;
	uint32_t clear    = 0;
	unsigned long flags;
	int error = -EFAULT;
	struct pci_dev *pdev;
	int devfn;

	if (!copy_from_user(input, (uint64_t *) user, IARGS7 * ARGSIZE)) {
		type     = input[0];
		bus      = input[1];
		device   = input[2];
		function = input[3];
		offset   = input[4];
		set      = input[5];
		clear    = input[6];
		devfn    = PCI_DEVFN(device, function);

		pdev = pci_get_domain_bus_and_slot(domain, bus, devfn);
     
		if (!pdev || pci_enable_device(pdev))
			return(-EFAULT);

		spin_lock_irqsave(&pci_rmw_lock, flags);

		switch (type) {
		case PCI_IO_PORT_BYTE_ACCESS:
			error = pci_read_config_byte(pdev, offset, &byte);

			byte |= (uint8_t) set;
			byte &= ~(uint8_t) clear;

			error |= pci_write_config_byte(pdev, offset, byte);
			break;
		case PCI_IO_PORT_WORD_ACCESS:
			error = pci_read_config_word(pdev, offset, &word);

			word |= (uint16_t) set;
			word &= ~(uint16_t) clear;

			error |= pci_write_config_word(pdev, offset, word);
			break;
		case PCI_IO_PORT_INT_ACCESS:
			error = pci_read_config_dword(pdev, offset, &dword);

			dword |= set;
			dword &= ~clear;

			error |= pci_write_config_dword(pdev, offset, dword);
			break;
		default:
			error = -EINVAL;
			break;
		}

		spin_unlock_irqrestore(&pci_rmw_lock, flags);
	}

	return(error);
}

/* IOCTL command: IOCTL_FREE_VECTOR */
static int ioctl_free_vector(uint64_t user)
{
	int      error = -EFAULT;
	uint64_t input[IARGS1];
	int      vector;
	unsigned long flags;

	spin_lock_irqsave(&irq_lock, flags);

	if (!copy_from_user(input, (uint64_t *) user, IARGS1 * ARGSIZE))  {
		vector = input[0];

		if (is_hwirq_vector(vector)) {
			free_irq(cdlirqdesc[vector].irq, NULL);
			cdlirqdesc[vector].handler = NULL;
			cdlirqdesc[vector].irq     = NO_IRQ;

			error = 0;
		} else
			error = -EINVAL;
	}

	spin_unlock_irqrestore(&irq_lock, flags);

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_RESERVE_VECTOR */
static int ioctl_reserve_vector(uint64_t user)
{
	int      error = -EFAULT;
	uint64_t output[OARGS1];
	char*    name = "reserved-cdl";
	const int iflags = IRQF_NOBALANCING;
	int      vector;
	int      irq;
	int      allocated = -1;
	unsigned long flags;

	spin_lock_irqsave(&irq_lock, flags);

	for (irq = 10; irq <= 255; irq++) {
		allocated = request_irq(irq, dummy, iflags, name, NULL);

		if (!allocated)
			break;
	}

	if (!allocated)  {
		vector = irq_to_vector(irq);

		free_irq(irq, NULL);
		cdlirqdesc[vector].handler = RESERVED;
		cdlirqdesc[vector].irq     = irq;

		output[0] = vector;
	} else {
		printk("ERROR: can't find available IRQ.\n");

		output[0] = -1;
	}

	error = copy_to_user((uint64_t *) user + 0, output, OARGS1 * ARGSIZE);

	spin_unlock_irqrestore(&irq_lock, flags);

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_FREE_MSI_VECTOR */
static int ioctl_free_msi_vector(uint64_t user)
{
	int      error = -EFAULT;
	uint64_t input[IARGS2];
	int      num_vecs;
	int      i;
	int      vector;
	unsigned long flags;

	spin_lock_irqsave(&irq_lock, flags);

	if (!copy_from_user(input, (uint64_t *) user, IARGS2 * ARGSIZE))  {
		num_vecs = input[0];
		vector   = input[1];

		for (i = 0;i < num_vecs; i++) {
			if (is_hwirq_vector(vector + i)) {
				/*
				 * ??? - why do we need the following line
				 * when * free_irq() is called in the
				 * remove_hwirq_handler()
				 * we need to make sure suit(es) calls the
				 * remove_hwirq_handler() before removing
				 * the following line.
				 */
				free_irq(cdlirqdesc[vector + i].irq, NULL);
				cdlirqdesc[vector + i].handler = NULL;
				cdlirqdesc[vector + i].irq     = NO_IRQ;
	
				error = 0;
			} else
				error = -EINVAL;
		}
	}

	spin_unlock_irqrestore(&irq_lock, flags);

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_RESERVE_MSI_VECTOR */
static int ioctl_reserve_msi_vector_backup(uint64_t user)
{
	int      i;
	int      error = -EFAULT;
	uint64_t input[IARGS6];
	unsigned long flags;
	uint16_t bus;
	uint16_t device;
	uint16_t function;
	int      devfn;
	int      req_num_vec;
	int      alloc_num_vec;
	struct pci_dev *pdev = NULL;

	spin_lock_irqsave(&irq_lock, flags);

	if (!copy_from_user(input, (uint64_t *) user, IARGS4 * ARGSIZE))  {
		req_num_vec = input[0];
		bus         = input[1];
		device      = input[2];
		function    = input[3];

		devfn = PCI_DEVFN(device, function);

		pdev = pci_get_domain_bus_and_slot(domain, bus, devfn);

		if (pdev == NULL) {
			printk("ERROR: %s: can't find a PCI device with bus 0x%x device 0x%x function 0x%x\n", __func__, bus, device, function);
			goto error0;
		}

		if ((req_num_vec <= 0) || (req_num_vec > MAX_MSI_NUM_VECTORS)) {
			printk("ERROR: %s: invalid number (%d) of MSI vector(s) is requested\n", __func__, req_num_vec);
			goto error0;
		}

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 11, 0)
		// alloc_num_vec = pci_enable_msi_range(pdev, 1, req_num_vec);
		alloc_num_vec = pci_enable_msi_range(pdev, req_num_vec, req_num_vec);
#else
		if (req_num_vec == 1)
			if (pci_enable_msi(pdev)) {
				printk("ERROR: %s: failed to enable MSI\n", __func__);
				goto error1;
			} else
				alloc_num_vec = 1;
		else {
			printk("ERROR: %s: TBD - working in progress to support multiple MSI vector (%d in this case) allocation on the kernel 4.11.0 or higher\n", __func__, req_num_vec);
			goto error0;
		}
#endif
		if (alloc_num_vec <= 0) {
			printk("ERROR: %s: %d MSI vector allocation request has failed: request, status = %x\n", __func__, req_num_vec, alloc_num_vec);
			goto error1;
		}

		if (alloc_num_vec != req_num_vec) {
			if (alloc_num_vec > req_num_vec) {
				printk("ERROR: %s: allocated number of vector is not expected than what is requested: %d vs %d\n", __func__, alloc_num_vec, req_num_vec);
				goto error1;
			}

			/* TBD before returning error, try to allocate MSI vector one by one and see if they are consecutive */

			printk("WARNING: %s: allocated %d of vector(s) which is less than %d requested\n", __func__, alloc_num_vec, req_num_vec);
		}

		if ((pdev->irq < FIRST_EXTERNAL_VECTOR) || ((pdev->irq + alloc_num_vec - 1) > NR_VECTORS)) {
			printk("ERROR: %s: allocated %d is out of boundary the driver currently supports\n", __func__, pdev->irq + alloc_num_vec - 1);
			goto error1;
		}

		printk("NOTE/DEBUG: %s: total %d of vectors have been allocated for the device [B/D/F = %d/%d/%d] and starting vector is %d\n", __func__, alloc_num_vec, bus, device, function, pdev->irq);

		/*
		 * this means that:
		 * - the number of vectors are allocated as requested
		 * - they are consecutive starting from pdev->irq
		 * - this also means that pdev->irq == vector
		 */
		for (i = 0; i < alloc_num_vec; i++) {
			cdlirqdesc[pdev->irq + i].handler = RESERVED;
			cdlirqdesc[pdev->irq + i].irq     = pdev->irq + i;
		}

		input[4] = alloc_num_vec;
		/* for test suite, pdev->irq should be considered as starting vector */
		input[5] = pdev->irq;

		error = 0;

		error = copy_to_user((uint64_t *) user + 4, &input[4], OARGS2 * ARGSIZE);
error1:
		if (error)
			pci_disable_msi(pdev);
	}
error0:
	spin_unlock_irqrestore(&irq_lock, flags);

	return (error);
}

/* IOCTL command: IOCTL_RESERVE_MSI_VECTOR */
static int ioctl_reserve_msi_vector(uint64_t user)
{
	int      i = 0, j;
	int      error = -EFAULT;
	uint64_t input[IARGS6];
	unsigned long flags;
	uint16_t bus;
	uint16_t device;
	uint16_t function;
	int      devfn;
	int      req_num_vec;
	struct pci_dev *pdev = NULL;
	char*    name = "reserved-cdl";
	const int iflags = IRQF_NOBALANCING;
	int      vector;
	int      prev_vec = 0;
	int      irq;
	int      allocated = -1;

	spin_lock_irqsave(&irq_lock, flags);

	if (!copy_from_user(input, (uint64_t *) user, IARGS4 * ARGSIZE))  {
		req_num_vec = input[0];
		bus         = input[1];
		device      = input[2];
		function    = input[3];

		devfn = PCI_DEVFN(device, function);

		pdev = pci_get_domain_bus_and_slot(domain, bus, devfn);

		if (pdev == NULL) {
			printk("ERROR: %s: can't find a PCI device with bus 0x%x device 0x%x function 0x%x\n", __func__, bus, device, function);
			goto error0;
		}

		if ((req_num_vec <= 0) || (req_num_vec > MAX_MSI_NUM_VECTORS)) {
			printk("ERROR: %s: invalid number (%d) of MSI vector(s) is requested\n", __func__, req_num_vec);
			goto error0;
		}

		/* set the first IRQ for the external interrupt */
		j = 10;

		while (i < req_num_vec) {
			for (irq = j; irq <= 255; irq++) {
				allocated = request_irq(irq, dummy, iflags, name, NULL);

				if (!allocated)
					break;
			}

			if (!allocated)  {
				vector = irq_to_vector(irq);

				free_irq(irq, NULL);
				irq++;
				j = irq;

				if (vector != irq) {
					// printk("ERROR: %s: vector %d is differ from IRQ %d, which is unexpected for MSI\n", __func__, vector, irq);
					// goto error0;
					// printk("WARNING: %s: vector %d is differ from IRQ %d, which is unexpected for MSI\n", __func__, vector, irq);
				}

				if (i == 0) {
					if (vector % req_num_vec)
						continue;
					else {
						cdlirqdesc[vector].handler = RESERVED;
						cdlirqdesc[vector].irq     = irq;
						
						input[5] = vector;
						i++;
					}
				} else {
					if ((prev_vec + 1) == vector) {
						cdlirqdesc[vector].handler = RESERVED;
						cdlirqdesc[vector].irq     = irq;
						i++;
					} else {
						printk("ERROR: %s: [%d/%d]-th vector is incremental obs = %d exp = %d\n", __func__, i + 1, req_num_vec, vector, prev_vec + 1);
						goto error0;
					}
				}

				prev_vec = vector;
			} else {
				printk("ERROR: can't find available IRQ.\n");

				goto error0;
			}
		}

		input[4] = req_num_vec;

		error = 0;

		error = copy_to_user((uint64_t *) user + 4, &input[4], OARGS2 * ARGSIZE);
	}
error0:
	spin_unlock_irqrestore(&irq_lock, flags);

	return (error);
}

/* IOCTL command: IOCTL_READ_PVT_MSR */
static int ioctl_private_msr_read(uint64_t user)
{
	uint64_t input[IARGS3];
	uint64_t msr   = 0;
	uint64_t datum = 0;
	int      error = -EFAULT;
	struct msr_passwd password;

	if (!copy_from_user(input, (uint64_t *) user, IARGS3 * ARGSIZE))  {
		password.esi = input[0];
		password.edi = input[1];
		msr          = input[2];

		datum = private_msr_read(msr, password.edi, password.esi);
  
		error = copy_to_user((uint64_t *) user, &datum, 1 * ARGSIZE) ?
		    -EFAULT : 0;
	}

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return error;
}

/* IOCTL command: IOCTL_WRITE_PVT_MSR */
static int ioctl_private_msr_write(uint64_t user)
{
	uint64_t input[IARGS4];
	uint64_t msr;
	uint64_t datum;
	struct msr_passwd password;
	int error = -EFAULT;

	if (!copy_from_user(input, (uint64_t* ) user, IARGS4 * ARGSIZE)) {
		password.esi = input[0];
		password.edi = input[1];
		msr          = input[2];
		datum        = input[3];

		private_msr_write(msr, datum, password.edi, password.esi);

		error = 0;
	}

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return error;
}

/* IOCTL command: IOCTL_RMW_PVT_MSR */
static int ioctl_private_msr_rmw(uint64_t user)
{
	uint64_t input[IARGS5];
	uint64_t msr;
	uint64_t qword;
	struct msr_passwd password;
	uint64_t set;
	uint64_t clear;
	unsigned long flags;
	int error = -EFAULT;

	if (!copy_from_user(input, (uint64_t *) user, IARGS5 * ARGSIZE)) {
		password.esi = input[0];
		password.edi = input[1];
		msr          = input[2];
		set          = input[3];
		clear        = input[4];

		spin_lock_irqsave(&msr_rmw_lock, flags);

		qword  = private_msr_read(msr, password.edi, password.esi);

		qword |= set;
		qword &= ~clear;
 
		private_msr_write(msr, qword, password.edi, password.esi);

		spin_unlock_irqrestore(&msr_rmw_lock, flags);

		error = 0;
	}

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return error;
}

/* IOCTL command: IOCTL_RMW_PVT_MSR */
static int execute_halt(uint64_t user)
{
	uint64_t input[IARGS1];
	uint64_t trial;
	uint64_t trials;
	unsigned long flags;
	int      error = -EFAULT;
   
	if (!copy_from_user(input, (uint64_t *) user, IARGS1 * ARGSIZE)) {
		trials = input[0];
		local_irq_save(flags);
		sti();

		for (trial=0; trial < trials; trial++)
			halt();

		local_irq_restore(flags);
		error = 0;
	}

	return error;
}

/* IOCTL command: IOCTL_RMW_PVT_MSR */
static int execute_halt_ioport(uint64_t user)
{
	uint64_t input[IARGS2];
	unsigned long  flags;
	uint32_t trials = 0;
	uint32_t trial  = 0;
	uint16_t port   = 0;
	uint16_t dummy  = 0;
	int error       = -EFAULT;

	if (!copy_from_user(input, (uint64_t *) user, IARGS2 * ARGSIZE)) {
		port   = input[0];
		trials = input[1];

		local_irq_save(flags);
		sti();

		for ( trial=0; trial < trials; trial++)
			dummy = inw(port);

		local_irq_restore(flags);

		error  = 0;
	}

	return error;
}

/* IOCTL command: IOCTL_PRE_SET_MEMORY_TYPE */
static int pre_set_memtype(uint64_t user)
{
	uint64_t input[IARGS1];
	int  error = -EFAULT;

	if (!copy_from_user(input, (uint64_t *) user, IARGS1 * ARGSIZE)) {
		global_mem_type = input[0];

		if ((global_mem_type == SET_MT_WC) || (global_mem_type == SET_MT_WT) || (global_mem_type == SET_MT_WP))
			error = 0;
		else
			printk("ERROR: %s: invalid memory type setting = 0x%llx\n", __func__, global_mem_type);
	}

	return error;
}

/* IOCTL command: IOCTL_INSTALL_AMD_USER_CODE */
static int ioctl_install_amd_user_code(uint64_t user)
{
	uint64_t input[IARGS2];
	int      error = -EFAULT;
	void     *code;
	size_t   size;
	unsigned long kernelCode;

	if (!copy_from_user(input, (uint64_t*)user, IARGS2 * ARGSIZE)) {
		code  = (void *) input[0];
		size  = (size_t) input[1];

		error = install_amd_user_code(code, size, &kernelCode);

		if (copy_to_user((uint64_t *) user + 2, &kernelCode, 1 * ARGSIZE))
			error = -EFAULT;
	}

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_CALL_AMD_USER_CODE */
static int ioctl_call_amd_user_code(uint64_t user)
{
	uint64_t  input[IARGS8];
	uint64_t  output[OARGS8];
	void     *code;    // Pointer to code in kernel memory
                  // Obtained from install_amd_user_code
	uint64_t rdi;   // R/W data for user code
	uint64_t rsi;   // R/W data for user code
	uint64_t rdx;   // R/W data for user code
	uint64_t rcx;   // R/W data for user code
	uint64_t r8;    // R/W data for user code
	uint64_t r9;    // R/W data for user code
	uint64_t rax;   // R/W data for user code
	int error = -EFAULT;

	if (!copy_from_user(input, (uint64_t *) user, IARGS8 * ARGSIZE)) {
		code = (void *) input[0];
		rdi  = input[1];
		rsi  = input[2];
		rdx  = input[3];
		rcx  = input[4];
		r8   = input[5];
		r9   = input[6];
		rax  = input[7];

		error = call_amd_user_code(&rdi, &rsi, &rdx, &rcx, &r8, &r9, &rax, code);

		output[0] = input[0];
		output[1] = rdi;
		output[2] = rsi;
		output[3] = rdx;
		output[4] = rcx;
		output[5] = r8;
		output[6] = r9;
		output[7] = rax;

		if (!error) {
			if (copy_to_user((uint64_t *) user, output, OARGS8 * ARGSIZE))
				error = -EFAULT;
			else
				error = 0;
		}
	}

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_WRITE_USER_DATA */
static int ioctl_write_user_data(uint64_t user)
{
	uint64_t input[IARGS3];
	void    *source;       // Pointer to source buffer in user memory
	void    *destination;  // Pointer to destination in kernel memory
                     // Codebase obtained from install_amd_user_code ---> destination=codeBase+codeSize+dataOffset
	int      error = -EFAULT;
	size_t   bytes;

	if (!copy_from_user(input, (uint64_t *) user, IARGS3 * ARGSIZE)) {
		destination = (void *) input[0];
		source      = (void *) input[1];
		bytes       = (size_t)input[2];

		if (!copy_from_user(destination, source, bytes))
			error = -EFAULT;
		else
			error = 0;
	}

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_READ_USER_DATA */
static int ioctl_read_user_data(uint64_t user)
{
	uint64_t input[IARGS3];
	void    *destination;  // Pointer to destination buffer in user memory
	void    *source;       // Pointer to source data in kernel memory
                       // source=codeBase+codeSize+dataOffset
                       // Codebase is obtained from install_amd_user_code 
                       // Data is appended to code
	int      error = -EFAULT;
	size_t   bytes;

	if (!copy_from_user(input, (uint64_t *) user, IARGS3 * ARGSIZE)) {
		destination = (void *) input[0];
		source      = (void *) input[1];
		bytes       = (size_t) input[2];

		if (copy_to_user((void *) destination, source, bytes))
			error = -EFAULT;
		else
			error = 0;
	}

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_DELETE_AMD_USER_CODE */
static int ioctl_delete_amd_user_code(uint64_t user)
{
	uint64_t code;
	int      error = -EFAULT;

	if (!copy_from_user(&code, (uint64_t *) user, 1 * ARGSIZE)) {
		error = delete_amd_user_code((void *) code);
		error = 0;
	}

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_SET_IN_CR4 */
static int ioctl_set_in_cr4(uint64_t user)
{
	int      error = -EFAULT;
	uint64_t mask;

	if (!copy_from_user(&mask, (uint64_t *) user, 1 * ARGSIZE)) {
		cr4_set_bits(mask);

		error = 0;
	}

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_CLEAR_IN_CR4 */
static int ioctl_clear_in_cr4(uint64_t user)
{
	int      error = -EFAULT;
	uint64_t mask;

	if (!copy_from_user(&mask, (uint64_t *) user, 1 * ARGSIZE)) {
		cr4_clear_bits(mask);

		error = 0;
	}

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_WRITE_CR4 */
static int ioctl_write_cr4(uint64_t user)
{
	int      error = -EFAULT;
	uint64_t cr4;

	if (!copy_from_user(&cr4, (uint64_t *) user, 1 * sizeof(uint64_t))) {
		error = 0;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 20, 0)
		write_cr4(cr4);
#else
		__write_cr4(cr4);
#endif
	}

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_READ_CR4 */
static int ioctl_read_cr4(uint64_t user)
{
	int error;
#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 20, 0)
	const uint64_t cr4 = read_cr4();
#else
	const uint64_t cr4 = __read_cr4();
#endif

	error = copy_to_user((uint64_t *) user, &cr4, 1 * ARGSIZE) ?
	    -EFAULT : 0;

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_WRITE_CR2 */
static int ioctl_write_cr2(uint64_t user)
{
	int      error = -EFAULT;
	uint64_t cr2;

	if (!copy_from_user(&cr2, (uint64_t *) user, 1 * sizeof(uint64_t))) {
		error = 0;

		write_cr2(cr2);
	}

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_READ_CR2 */
static int ioctl_read_cr2(uint64_t user)
{
	int error;
	const uint64_t cr2 = read_cr2();

	error = copy_to_user((uint64_t *) user, &cr2, 1 * ARGSIZE) ?
	    -EFAULT : 0;

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_WRITE_CR3 */
static int ioctl_write_cr3(uint64_t user)
{
	int      error = -EFAULT;
	uint64_t cr3;

	if (!copy_from_user(&cr3, (uint64_t *) user, 1 * sizeof(uint64_t))) {
		error = 0;

		write_cr3(cr3);
	}

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_READ_CR3 */
static int ioctl_read_cr3(uint64_t user)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	const uint64_t cr3 = read_cr3();
#else
	const uint64_t cr3 = __read_cr3();
#endif
	const int error    = copy_to_user((uint64_t *) user, &cr3, 1 * ARGSIZE) ? -EFAULT : 0;

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_WRITE_CR3 */
static int ioctl_write_cr8(uint64_t user)
{
	int      error = -EFAULT;
	uint64_t cr8;

	if (!copy_from_user(&cr8, (uint64_t *)user, 1 * sizeof(uint64_t))) {
		error = 0;

		write_cr8(cr8);
	}

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_READ_CR8 */
static int ioctl_read_cr8(uint64_t user)
{
	int error;
	const uint64_t cr8 = read_cr8();

	error = copy_to_user((uint64_t *) user, &cr8, 1 * ARGSIZE) ?
	    -EFAULT : 0;

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_GET_LAPIC_LINBASE */
static int ioctl_get_lapic_linbase(uint64_t user)
{
        // const uint64_t base = fix_to_virt(0x804);
        // const uint64_t base = fix_to_virt(0x202);
        const uint64_t base = APIC_BASE;
        const int error     = copy_to_user((uint64_t *) user, &base, 1 * ARGSIZE) ? -EFAULT : 0;

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

        return(error);
}

/* IOCTL command: IOCTL_READ_GS_BASE */
static int ioctl_read_gs_base(uint64_t user)
{
	uint64_t output[OARGS1];
	unsigned long  base;
	int      error;

	rdmsrl(MSR_GS_BASE, base);
	output[0] = base;

	error = copy_to_user((uint64_t *) user, output, OARGS1 * ARGSIZE) ?
	    -EFAULT : 0;

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_IS_SMM_LOCKED */
static int ioctl_is_smm_locked(uint64_t user)
{
	uint64_t output[OARGS1];
	int      error;
	uint64_t msr;
	uint64_t locked;

	rdmsrl(MSR_K7_HWCR, msr);

	locked = (msr & HWRCR_SMM_LOCK_MASK) ? 1 : 0;

	output[0] = locked;

	error = copy_to_user((uint64_t *) user, output, OARGS1 * ARGSIZE) ?
	    -EFAULT : 0;

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_INSTALL_INTERRUPT_HANDLER */
static int ioctl_install_interrupt_handler(uint64_t user)
{
	uint64_t input[IARGS3];
	void    *handler;
	size_t   size;
	int      vector;
	int      error = -EFAULT;

	if (!copy_from_user(input, (uint64_t *) user, IARGS3 * ARGSIZE)) {
		handler = (void *) input[0];
		size    = (size_t) input[1];
		vector  = (int) input[2];

		if (is_exception_vector(vector))
			error = install_exception_handler(handler, size,
			    vector);
		else if (is_hwirq_vector(vector))
			error = install_hwirq_handler(handler, size, vector);
		else
			error = -EINVAL;
	}

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_REMOVE_INTERRUPT_HANDLER */
static int ioctl_remove_interrupt_handler(uint64_t user)
{
	uint64_t input[IARGS1];
	int      error = -EFAULT;
	int      vector;

	if (!copy_from_user(input, (uint64_t *) user, IARGS1 * ARGSIZE)) {
		vector = (int)input[0];

		if (is_exception_vector(vector))
			error = remove_exception_handler(vector);
		else if (is_hwirq_vector(vector))
			error = remove_hwirq_handler(vector);
		else
			error = -EINVAL;
	}

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);

}

/* IOCTL command: IOCTL_READ_INTERRUPT_DATA */
static int ioctl_read_interrupt_data(uint64_t user)
{
	uint64_t input[IARGS4];
	int      vector;
	size_t   offset;
	size_t   bytes;
	int      error = -EFAULT;
	void    *source;
	void    *destination;
	unsigned long flags;

	spin_lock_irqsave(&irq_lock, flags);

	if (!copy_from_user(input, (uint64_t *) user, IARGS4 * ARGSIZE)) {
		vector      = (int)input[0];
		offset      = (size_t)input[1];
		bytes       = (size_t)input[2];
		destination = (void *)input[3];

		if (vector >= 0 && vector < NR_VECTORS) {
			source = cdlirqdesc[vector].handler + offset;
			error  = copy_to_user(destination, source, bytes) ?
			    -EFAULT : 0;
		} else
			error = -EINVAL;
	}
   
	spin_unlock_irqrestore(&irq_lock, flags);

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_WRITE_INTERRUPT_DATA */
int ioctl_write_interrupt_data(uint64_t user)
{
	uint64_t input[IARGS4];
	int      vector;
	size_t   offset;
	size_t   bytes;
	int      error = -EFAULT;
	void    *source;
	void    *destination;
	unsigned long flags;

	spin_lock_irqsave(&irq_lock, flags);

	if (!copy_from_user(input, (uint64_t *) user, IARGS4 * ARGSIZE)) {
		vector = (int)input[0];
		offset = (size_t)input[1];
		bytes  = (size_t)input[2];
		source = (void *)input[3];

		if ((vector >= 0) && (vector < NR_VECTORS)) {
			destination = cdlirqdesc[vector].handler + offset;
			error       = copy_from_user(destination, source, bytes) ? -EFAULT : 0;
		} else
			error = -EINVAL;
	}

	spin_unlock_irqrestore(&irq_lock, flags);

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_GET_PHYSICAL_ADDRESS */
static int ioctl_get_physical_address(uint64_t user)
{
	uint64_t input[IARGS1];
	uint64_t physical;
	uint64_t linear;
	int      error = -EFAULT;
	struct mm_struct *mm;
	pte_t    entry;

	mm = current->mm;

	spin_lock(&mm->page_table_lock);

	if (!down_read_trylock(&mm->mmap_sem)) {
		printk (" cannot continue ioctl_get_physical_address \n" );
		return 0;	
	}

	if (!copy_from_user(input, (uint64_t *) user, IARGS1 * ARGSIZE)) {
		linear   = input[0];

		physical =  follow_pte(mm, linear, &entry);
		error    = copy_to_user((uint64_t *)user + 1,&physical,
		    OARGS1 * ARGSIZE) ? -EFAULT : 0;
	}
  
	up_read(&mm->mmap_sem);

	spin_unlock(&mm->page_table_lock);

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_GET_LINEAR_ADDRESS */
static int ioctl_get_linear_address(uint64_t user)
{
	uint64_t input[IARGS1];
	uint64_t physical;
	uint64_t linear;
	int      error = -EFAULT;

	if (!copy_from_user(input, (uint64_t *) user, IARGS1 * ARGSIZE)) {
		physical = input[0];

		linear = get_linear_address(physical);
		error  = copy_to_user((uint64_t*)user + 1, &linear, OARGS1 * ARGSIZE) ? -EFAULT : 0;
	}

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_INTERRUPT_TEST */
static int ioctl_interrupt_test(uint64_t user)
{
	uint64_t input[IARGS2];
	void     (*call)(void);
	int      vector;
	int      test;
	int      error = -EFAULT;
	unsigned long flags;

	spin_lock_irqsave(&irq_lock, flags);

	if (!copy_from_user(input, (uint64_t *) user, IARGS2 * ARGSIZE)) {
		vector = (int)input[0];
		test   = (int)input[1];

		if (vector < 0 || vector >= NR_VECTORS) {
			spin_unlock_irqrestore(&irq_lock, flags);
			return (-EINVAL); 
		}

		switch(test) {
		case IRQ_SIM:
			call = cdlirqdesc[vector].handler;
			call();
			error = 0; 
			break;
		case SWI_GEN:
			error = swi_gen(vector);
			break;
		default:
			error = -EFAULT; 
			break;
		}
	}
   
	spin_unlock_irqrestore(&irq_lock, flags);

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_FLUSH_CACHE_LINE */
static int ioctl_flush_cache_line(uint64_t user)
{
	unsigned long input[IARGS1];
	unsigned long address;
	int      error = -EFAULT;

	if (!copy_from_user(input, (uint64_t *) user, IARGS1 * ARGSIZE)) {
		address = input[0];
		error   = 0;

		asm volatile ("clflush (%0)" :: "r" (address) : "memory");
		asm volatile ("mfence");
	}

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_INVALIDATE_PAGE */
static int ioctl_invalidate_page(uint64_t user)
{
	unsigned long input[IARGS1];
	unsigned long address;
	int      error = -EFAULT;

	if (!copy_from_user(input, (uint64_t *) user, IARGS1 * ARGSIZE)) {
		address = input[0];
		error   = 0;

		asm volatile ("invlpg (%0)" ::"r" (address) : "memory");

	}

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_INVALIDATE_TLB */
int ioctl_invalidate_tlb(void)
{
	const int error = 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 12, 0)
	write_cr3(read_cr3());
#else
	write_cr3(__read_cr3());
#endif

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);

}

/* IOCTL command: IOCTL_SEND_INT_ALL */
int ioctl_send_int_all(unsigned long user)
{
	int      error = -EFAULT;
	unsigned long input[IARGS2];
	unsigned long count, now;
	int      vector;

	if (!copy_from_user(input, (uint64_t *) user, sizeof(input))) {
		vector = (int)input[0];
		count  = input[1];
		error  = 0;

		for (now = 0; now < count; now++)  {
			;//send_ipi_all(vector);
		}
	}

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_SEND_INT_ALL_BUT_SELF */
int ioctl_send_int_all_but_self(unsigned long user)
{
	int      error = -EFAULT;
	unsigned long input[IARGS2];
	int      vector;
	unsigned long count, now;

	if (!copy_from_user(input, (uint64_t *) user, sizeof(input))) {
		vector = input[0];
		count  = input[1];
		error  = 0;

		for (now = 0; now < count; now++)  {
			;//send_ipi_all_but_self(vector);
		}
	}

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_SEND_INT_MASK */
int ioctl_send_int_mask(unsigned long user)
{
	unsigned long input[IARGS3];
	int vector;
	unsigned long count, now;
	struct cpumask mask;
	int cpu;
	int error = -EFAULT;

	cpumask_clear(&mask);

	if (!copy_from_user(input, (uint64_t *) user, sizeof(input))) {
		vector = input[0];
		count  = input[1];

		for (cpu = 0; cpu < NR_CPUS; cpu++) {
			if ((1 << cpu) & input[2])
				cpumask_set_cpu(cpu,&mask);
		}

		error = 0;

		for (now = 0; now < count; now++) {
			;//send_ipi_mask(vector,&mask);
		}
	}

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

/* IOCTL command: IOCTL_EXECUTE_INVLPGB_INSTRUCTION */
int ioctl_invalidate_page_b(uint64_t user)
{
	unsigned long input[IARGS2];
	unsigned long address;
	unsigned long count;
	int error;

	if (!copy_from_user(input, (uint64_t*) user, IARGS2 * ARGSIZE)) {
		address = input[0];
		count   = (uint64_t) input[1];
		error   = 0;

		invlpgb(address, count);
	} else
		error = -EFAULT;

	return(error);
}

/* IOCTL command: IOCTL_EXECUTE_TLBSYNC_INSTRUCTION */
int ioctl_tlbsync(void)
{
	const int error = 0;

	tlbsync();

	return(error);
}

/* IOCTL command: IOCTL_SET_PTE */
int ioctl_set_page_table_entry(uint64_t user)
{
	uint64_t input[IARGS3];
	uint64_t linear;
	uint64_t pte_type;
	uint64_t size;
	uint64_t set_bits;
	uint64_t clear_bits;
	int error;
	struct mm_struct *mm = current->mm;
	pte_t entry;

	spin_lock(&mm->page_table_lock);
	if (!down_read_trylock(&mm->mmap_sem)) {
		printk(" cannot continue ioctl_set_page_table_entry \n" );
		return 0;
	}

	if (!copy_from_user(input, (uint64_t *) user, IARGS3 * ARGSIZE)) {
		linear   = input[0];
		pte_type = input[1];
		size     = input[2];

		if (pte_type == SET_PG_DIRTY ) {
			set_bits = PAGE_DIRTY;
			clear_bits = 0;
		}

		if (pte_type == SET_PG_ACCESSED ) {
			set_bits = PAGE_ACCESSED;
			clear_bits = 0;
		}

		if (pte_type == SET_PG_PRESENT ) {
			set_bits = PAGE_PRESENT;
			clear_bits = 0;
		}

		if (pte_type == CLEAR_PG_DIRTY ) {
			set_bits = 0;
			clear_bits = PAGE_DIRTY;
		}

		if (pte_type == CLEAR_PG_ACCESSED ) {
			set_bits = 0;
			clear_bits = PAGE_ACCESSED;
		}

		if (pte_type == CLEAR_PG_PRESENT ) {
			set_bits = 0;
			clear_bits = PAGE_PRESENT;
		}

		if (pte_type == CLEAR_PG_RW ) {
			set_bits = 0;
			clear_bits = PAGE_RW;
		}

		error =  set_page_table_entry(mm, &entry, linear, set_bits, clear_bits, size);

		__flush_tlb_all();
		wbinvd();
	} else
		error = -EFAULT;

	up_read(&mm->mmap_sem);
	spin_unlock(&mm->page_table_lock);

	return(error);
}

/* IOCTL command: IOCTL_INVALIDATE_CACHES */
static int ioctl_invalidate_caches(void)
{
	const int error = 0;

	asm volatile ( "invd" );

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

static int ioctl_install_smi_handler(uint64_t user) {
	uint64_t input[IARGS2];
	void    *code;
	size_t   size;
	int      error = -EFAULT;

	if (!copy_from_user(input, (uint64_t *) user, IARGS2 * ARGSIZE)) {
		code  = (void *) input[0];
		size  = (size_t) input[1];
		error = amd_install_smi_handler(code, size);
	}

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

int ioctl_write_smm_data_byte(uint64_t user)
{
	uint64_t input[IARGS2];
	unsigned char byte;
	size_t offset;
	int error = -EFAULT;

	if (!copy_from_user(input, (uint64_t *) user, IARGS2 * ARGSIZE)) {
		byte   = (unsigned char)input[0];
		offset = (size_t)input[1];
		error  = amd_write_smm_data_byte(byte, offset);
	}

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

int ioctl_read_smm_data_byte(uint64_t user)
{
	uint64_t input[IARGS2];
	uint64_t output[OARGS1];
	unsigned char byte;
	size_t offset;
	int error = -EFAULT;

	if (!copy_from_user(input, (uint64_t *) user, IARGS2 * ARGSIZE)) {
		byte   = (unsigned char) input[0];
		offset = (size_t) input[1];

		error = amd_read_smm_data_byte(&byte, offset);

		if (!error) {
			output[0] = (uint64_t) byte;

			error = copy_to_user((uint64_t *) user + 0, output, OARGS1 * ARGSIZE) ? -EFAULT : 0;
		}
	}

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

int ioctl_send_smi(uint64_t user)
{
	uint64_t input[IARGS1];
	uint64_t count;
	int error = -EFAULT;

	if (!copy_from_user(input, (uint64_t *) user, IARGS1 * ARGSIZE)) {
		count = input[0];

		error = amd_send_smi(count);
	}

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);
}

int ioctl_call_amex_entry(uint64_t user)
{
	uint64_t input[IARGS3];
	uint64_t target;  // AMEX entry point. Load into RDI before call
	uint64_t rsi;     // RSI value at time of call to AMEX entry
	uint64_t rdx;     // RDX value at time of call to AMEX entry
	int error = -EFAULT;;

	if (!copy_from_user(input, (uint64_t *) user, IARGS3 * ARGSIZE)) {
		target = input[0];
		rsi    = input[1];
		rdx    = input[2];

		error = amex(target, rsi, rdx);
	}

	if (error)
		printk("ERROR: %s: return status = 0x%x\n", __func__, error);

	return(error);


}


/*
 * section 1 - entry points of the driver
 */
static int amd_mmap(struct file * file, struct vm_area_struct * vma)
{
	const size_t size = vma->vm_end - vma->vm_start;

	switch(global_mem_type) {
	case SET_MT_WC:
		vma->vm_page_prot = __pgprot(pgprot_val(vma->vm_page_prot) | cachemode2protval(_PAGE_CACHE_MODE_WC));
		break;
	case SET_MT_WT:
		vma->vm_page_prot = __pgprot(pgprot_val(vma->vm_page_prot) | cachemode2protval(_PAGE_CACHE_MODE_WT));
		break;
	case SET_MT_WP:
		/* DIAG-2512: CDL Framework Support for different memory types not giving correct value */
		/* WP still can't be supported due to the limitation on the kernel support... from ./arch/x86/mm/pat.c */
		/**
		 * lookup_memtype - Looksup the memory type for a physical address
		 * @paddr: physical address of which memory type needs to be looked up
		 *
		 * Only to be called when PAT is enabled
		 *
		 * Returns _PAGE_CACHE_MODE_WB, _PAGE_CACHE_MODE_WC, _PAGE_CACHE_MODE_UC_MINUS
		 * or _PAGE_CACHE_MODE_WT.
		 */
		/**
		 * so, the kernel treats the setting _PAGE_CACHE_MODE_WP as UC-
		 * write-back @ 0x2000200000-0x2000300000
		 * write-combining @ 0x2000300000-0x2000400000
		 * write-through @ 0x2000400000-0x2000500000
		 * uncached-minus @ 0x2000500000-0x2000600000
		 * uncached-minus @ 0x2000600000-0x2000700000 <-- WP is requested
		 */
		/* NOTE - manually modifying PAT register with WP setting could lead the following error messaag from the kernel */
		/* Oct  5 09:36:40 Diesel10 kernel: [253081.857008] x86/PAT: MMIO_Access:30303 map pfn expected mapping type write-through for [mem 0x2000600000-0x20006fffff], got uncached-minus */
		/* This is because the confusion by the kernel triggered by the ambiguity in PAT/PCD/PWT combination in the PTE */

		vma->vm_page_prot = __pgprot(pgprot_val(vma->vm_page_prot) | cachemode2protval(_PAGE_CACHE_MODE_WP));
		break;
	default:
		printk("ERROR: %s: invalid global_mem_type = 0x%llx.\n", __func__, global_mem_type);
		return -EFAULT;
	}

	global_mem_type = 0;

	/* Remap-pfn-range will mark the range VM_IO and VM_RESERVED */
	if (remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff, size, vma->vm_page_prot)) {
		unmap_devmem(vma->vm_pgoff, size, vma->vm_page_prot);
		return -EAGAIN;
	}

	return 0;
}

static long cdl_ioctl(struct file *filp, unsigned int cmd, unsigned long user)
{
	const int cpu        = iminor(filp->f_path.dentry->d_inode);
	const cpumask_t mask = current->cpus_allowed; 
	int error = -EFAULT; 

	set_cpus_allowed_ptr(current, cpumask_of(cpu));

	switch(cmd) {
	case IOCTL_EXECUTE_WBINVD_INSTRUCTION:
		error = 0;
		wbinvd();
		break;
	case IOCTL_READ_PVT_MSR:
		error = ioctl_private_msr_read(user);
		break;
	case IOCTL_WRITE_PVT_MSR:
		error = ioctl_private_msr_write(user);
		break;
	case IOCTL_RMW_PVT_MSR:
		error = ioctl_private_msr_rmw(user);
		break;
	case IOCTL_PRE_SET_MEMORY_TYPE:
		error = pre_set_memtype(user);
		break;
	case IOCTL_HLT:
		error = execute_halt(user);
		break;
	case IOCTL_HLT_IOPORT:
		error = execute_halt_ioport(user);
		break;
	case IOCTL_READ_PCI_IOPORT:
		error = pci_read_ioport(user);
		break;
	case IOCTL_WRITE_PCI_IOPORT:
		error = pci_write_ioport(user);
		break;
	case IOCTL_RMW_PCI_IOPORT:
		error = pci_rmw_ioport(user);
		break;
	case IOCTL_CALL_AMEX_ENTRY:
		error = ioctl_call_amex_entry(user);
		break;
	case IOCTL_INSTALL_AMD_USER_CODE:
		error = ioctl_install_amd_user_code(user);
		break;
	case IOCTL_CALL_AMD_USER_CODE:
		error = ioctl_call_amd_user_code(user);
		break;
	case IOCTL_DELETE_AMD_USER_CODE:
		error = ioctl_delete_amd_user_code(user);
		break;
	case IOCTL_DISABLE_TLBFLUSH_IPI:
		error = amex_disable_tlb_flush(smp_processor_id());
		break;
	case IOCTL_ENABLE_TLBFLUSH_IPI:
		error = amex_enable_tlb_flush(smp_processor_id());
		break;
	case IOCTL_DISABLE_SCHEDULER:
		error = amd_disable_sched(); 
		break;
	case IOCTL_ENABLE_SCHEDULER:
		error = amd_enable_sched(); 
		break;
	case IOCTL_DISABLE_CURRENT_SCHEDULER:
		error = amd_disable_current_sched(); 
		break;
	case IOCTL_ENABLE_CURRENT_SCHEDULER:
		error = amd_enable_current_sched(); 
		break;
	case IOCTL_READ_CR2:
		error = ioctl_read_cr2(user);
		break;
	case IOCTL_WRITE_CR2:
		error = ioctl_write_cr2(user);
		break;
	case IOCTL_READ_CR3:
		error = ioctl_read_cr3(user);
		break;
	case IOCTL_WRITE_CR3:
		error = ioctl_write_cr3(user);
		break;
	case IOCTL_READ_CR4:
		error = ioctl_read_cr4(user);
		break;
	case IOCTL_WRITE_CR4:
		error = ioctl_write_cr4(user);
		break;
	case IOCTL_CLEAR_IN_CR4:
		error = ioctl_clear_in_cr4(user);
		break;
	case IOCTL_SET_IN_CR4:
		error = ioctl_set_in_cr4(user);
		break;
	case IOCTL_INSTALL_SMI_HANDLER:
		error = ioctl_install_smi_handler(user);
		break;
	case IOCTL_RESTORE_SMI_HANDLER:
		error = amd_restore_smi_handler();
		break;
	case IOCTL_WRITE_SMM_BYTE:
		error = ioctl_write_smm_data_byte(user);
		break;
	case IOCTL_READ_SMM_BYTE:
		error = ioctl_read_smm_data_byte(user);
		break;
	case IOCTL_SEND_SMI:
		error = ioctl_send_smi(user);
		break;
	case IOCTL_IS_SMM_LOCKED:
		error = ioctl_is_smm_locked(user);
		break;
	case IOCTL_INSTALL_INTERRUPT_HANDLER:
		error = ioctl_install_interrupt_handler(user);
		break;
	case IOCTL_REMOVE_INTERRUPT_HANDLER:
		error = ioctl_remove_interrupt_handler(user);
		break;
	case IOCTL_READ_INTERRUPT_DATA:
		error = ioctl_read_interrupt_data(user);
		break;
	case IOCTL_WRITE_INTERRUPT_DATA:
		error = ioctl_write_interrupt_data(user);
		break;
	case IOCTL_INTERRUPT_TEST:
		error = ioctl_interrupt_test(user);
		break;
	case IOCTL_INVALIDATE_PAGE:
		error = ioctl_invalidate_page(user);
		break;
	case IOCTL_INVALIDATE_TLB:
		error = ioctl_invalidate_tlb();
		break;
	case IOCTL_INVALIDATE_CACHES:
		error = ioctl_invalidate_caches();
		break;
	case IOCTL_FLUSH_CACHE_LINE:
		error = ioctl_flush_cache_line(user);
		break;
	case IOCTL_READ_GS_BASE:
		error = ioctl_read_gs_base(user);
		break;
	case IOCTL_STGI:
		error = 0;
		stgi();
		break;
	case IOCTL_CLGI:
		error = 0;
		clgi();
		break;
	case IOCTL_READ_CR8:
		error = ioctl_read_cr8(user);
		break;
	case IOCTL_WRITE_CR8:
		error = ioctl_write_cr8(user);
		break;
	case IOCTL_GET_LINEAR_ADDRESS:
		error = ioctl_get_linear_address(user);
		break;
	case IOCTL_GET_PHYSICAL_ADDRESS:
		error = ioctl_get_physical_address(user);
		break;
	case IOCTL_RESERVE_VECTOR:
		error = ioctl_reserve_vector(user);
		break;
	case IOCTL_FREE_VECTOR:
		error = ioctl_free_vector(user);
		break;
	case IOCTL_GET_LAPIC_LINBASE:
		error = ioctl_get_lapic_linbase(user);
		break;
	case IOCTL_READ_USER_DATA:
		error = ioctl_read_user_data(user);
		break;
	case IOCTL_WRITE_USER_DATA:
		error = ioctl_write_user_data(user);
		break;
	case IOCTL_SEND_INT_ALL:
		error = ioctl_send_int_all(user);
		break;
	case IOCTL_SEND_INT_ALL_BUT_SELF:
		error = ioctl_send_int_all_but_self(user);
		break;
	case IOCTL_SEND_INT_MASK:
		error = ioctl_send_int_mask(user);
		break;
	case IOCTL_EXECUTE_INVLPGB_INSTRUCTION:
		error = ioctl_invalidate_page_b(user);
		break;
	case IOCTL_EXECUTE_TLBSYNC_INSTRUCTION:
		error = ioctl_tlbsync();
		break;
	case IOCTL_SET_PTE:
		error = ioctl_set_page_table_entry(user);
		break;
	case IOCTL_RESERVE_MSI_VECTOR:
		error = ioctl_reserve_msi_vector(user);
		break;
	case IOCTL_FREE_MSI_VECTOR:
		error = ioctl_free_msi_vector(user);
		break;
	default:
		printk("ERROR: %s: invalid IOCTL command = 0x%x.\n", __func__,
		    cmd);
		break;
	}

	set_cpus_allowed_ptr(current, &mask);

	if (error)
		printk("ERROR: %s: error = %x.\n", __func__, error);

	return error;
}



/*
 * section 1 - module specifics for the driver
 */
static const struct file_operations cdl_fops =
{
	.owner   = THIS_MODULE,
	.unlocked_ioctl  = cdl_ioctl,
	.mmap       = amd_mmap
};

int init_module(void)
{
	void *ptr_err;
	int   ret;
	int   i = 0;
	int vector;

	for (vector = 0; vector < NR_VECTORS; vector++) {
		cdlirqdesc[vector].handler = NULL;
		cdlirqdesc[vector].irq     = NO_IRQ;

		sprintf(cdlirqdesc[vector].name,"cdl-0x%2x", vector);
	}

	ret = register_chrdev(0, "cpu/amd_cpu_diag", &cdl_fops);

	if ( ret < 0 ) {
		printk(KERN_ERR "Error in registering char device\n");
		return -1;
	} else {
		amd_cpu_diag_major = ret;
		printk(KERN_INFO "Success ! Major = %d \n", amd_cpu_diag_major);
	}

	amd_cpu_diag_class = class_create(THIS_MODULE, "amd_cpu_diag");

	if (IS_ERR(ptr_err = amd_cpu_diag_class))
		goto err2;
    
	amd_cpu_diag_class->devnode = amd_cpu_diag_nodename;

	for_each_online_cpu(i) {
		int err_val = amd_cpu_diag_device_create(i);

		if(err_val != 0)
			goto err;
	}

	return 0;
err:
	i = 0;

	for_each_online_cpu(i)
		amd_cpu_diag_device_destroy(i);

	class_destroy(amd_cpu_diag_class);
err2:
	unregister_chrdev(amd_cpu_diag_major, "cpu/amd_cpu_diag");
	return PTR_ERR(ptr_err);
}

void cleanup_module(void)
{
	int i = 0;

	for_each_online_cpu(i)
		amd_cpu_diag_device_destroy(i);
 
	class_destroy(amd_cpu_diag_class);
	printk(KERN_INFO "Unloaded module\n");
	unregister_chrdev(amd_cpu_diag_major, "cpu/amd_cpu_diag");
}
