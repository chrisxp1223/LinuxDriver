#include <linux/types.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/kernel.h>
//#include <linux/syscalls.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/cpu.h>
#include <linux/writeback.h>

//******************************************************************************************************************

#define BTHB_BASE    0xc0011007
#define BTHB_OFFSET  0xc0011008
#define BTHB_LIMIT   0xc0011009
#define BTHB_CTRL    0xc0011010
#define EXP_BP_CTRL  0xc0011018
#define HDT_CFG      0xc001100a

#define ALL_BITS ((unsigned int)~0)
#define NUM_BITS(high,low) ((high)-(low)+1)
#define INT_BITS (8*sizeof(unsigned int))
#define SHIFT(high,low) (INT_BITS-NUM_BITS(high,low))
#define GEN_BITS(high,low) (ALL_BITS >> SHIFT(high,low))

#define GEN_MASK(high,low)  ((GEN_BITS(high,low)) << (low))

#define BTHB_DRAM_BIT 6
#define BTHB_TEN_BIT  16
#define BTHB_TALL_BIT 17
#define BTHB_TBIT_BIT 18
#define BTHB_TFAR_BIT 19
#define BTHB_TSP_BIT  20
#define BTHB_TINT_BIT 21

#define BTHB_DRAM_MASK  GEN_MASK(6,6)
#define BTHB_TEN_MASK   GEN_MASK(10,10)
#define BTHB_TALL_MASK  GEN_MASK(17,17)
#define BTHB_TBIT_MASK  GEN_MASK(18,18)
#define BTHB_TFAR_MASK  GEN_MASK(19,19)
#define BTHB_TSP_MASK   GEN_MASK(20,20)
#define BTHB_TINT_MASK  GEN_MASK(21,21)
#define BTHB_TRNG_MASK  GEN_MASK(23,22)
#define BTHB_RING_MASK  GEN_MASK(25,24)
#define BTHB_TSMI_MASK  GEN_MASK(27,26)
#define BTHB_CTR_MASK   GEN_MASK(30,28)

//******************************************************************************************************************

unsigned long bthb_enable  = 0x00000;
unsigned long bthb_base    = 0xa0000;
unsigned long bthb_size    = 0x01000;
unsigned long bthb_offset  = 0x00000;
unsigned long bthb_control = 0x10340 | BTHB_TSP_MASK;

//******************************************************************************************************************


static int __init parse_bthb_enable(char *arg)
{
         if (!arg) {
            printk("%s : %lx\n",__FUNCTION__,bthb_enable);
            return -EINVAL;
          }

         bthb_enable = simple_strtoul(arg, NULL, 0);
         printk("%s : %lx\n",__FUNCTION__,bthb_enable);

         return 0;
}
early_param("bthb_enable", parse_bthb_enable);


//******************************************************************************************************************

static int __init parse_bthb_base(char *arg)
{

         if (!arg) {
            printk("%s : %lx\n",__FUNCTION__,bthb_base);
            return -EINVAL;
          }

         bthb_base = simple_strtoul(arg, NULL, 0);
         printk("%s : %lx\n",__FUNCTION__,bthb_base);

         return 0;
}
early_param("bthb_base", parse_bthb_base);

//******************************************************************************************************************
            
static int __init parse_bthb_size(char *arg)
{         
          
         if (!arg) { 
            printk("%s : %lx\n",__FUNCTION__,bthb_size);
            return -EINVAL;
          }
         
         bthb_size = simple_strtoul(arg, NULL, 0);
         printk("%s : %lx\n",__FUNCTION__,bthb_size);

         return 0;
}
early_param("bthb_size", parse_bthb_size);


//******************************************************************************************************************

static int __init parse_bthb_offset(char *arg)
{
         if (!arg) {
            printk("%s : %lx\n",__FUNCTION__,bthb_offset);
            return -EINVAL;
          }

         bthb_offset = simple_strtoul(arg, NULL, 0);
         printk("%s : %lx\n",__FUNCTION__,bthb_offset);

         return 0;
    
    
}
early_param("bthb_offset", parse_bthb_offset);

//******************************************************************************************************************

static int __init parse_bthb_ctrl(char *arg)
{
         if (!arg) {
            printk("%s : %lx\n",__FUNCTION__,bthb_control);
            return -EINVAL;
          }

         bthb_control = simple_strtoul(arg, NULL, 0);
         printk("%s : %lx\n",__FUNCTION__,bthb_control);

         return 0;
    
}
early_param("bthb_ctrl", parse_bthb_ctrl);

//******************************************************************************************************************
void amd_bthb_setup(void)

{  int cpu;
   unsigned long state,mask;


   if (bthb_enable) {
      for_each_online_cpu(cpu) {
          mask = 1 << cpu;
          if (mask & bthb_enable) {
             set_cpus_allowed(current, cpumask_of_cpu(cpu));
             printk("CPU-%d :: Configuring BTHB and INT3 redirect\n",smp_processor_id());
             wrmsrl(BTHB_BASE,bthb_base+cpu*bthb_size);
             wrmsrl(BTHB_LIMIT,bthb_base+cpu*bthb_size+bthb_size-5);
             wrmsrl(BTHB_OFFSET,bthb_offset);
             wrmsrl(BTHB_CTRL,bthb_control);
             rdmsrl(HDT_CFG,state);
             wrmsrl(HDT_CFG,state|1);
             rdmsrl(EXP_BP_CTRL,state);
             wrmsrl(EXP_BP_CTRL,state|0x103);
           }
      }
  }

}







