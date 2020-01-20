#include <linux/slab.h>
#include <asm/uaccess.h>
#include <asm/asm.h>

//******************************************************************************

#define RET 0xc3
#define NOP 0x00

//******************************************************************************

typedef void (*Call)(void);

//******************************************************************************

const static char heap[] = {RET,NOP,NOP};

//******************************************************************************

static noinline int execute(void *address)

{ Call call = (Call*) address;

  call();

  return 0;
}

//******************************************************************************

int testNXDisabled(void)
{
	int ret[] = {1,2,4};
	const char stack[] = {RET, 0x90, NOP };
        char *kmalloced;


	printk(KERN_INFO "NX Test: Enter\n");

	if (execute(&stack) == 0) {
	  printk(KERN_INFO "NX Test:  Stack was executable\n");
	  ret[0] = 0;
	}

	kmalloced = kmalloc(64, GFP_KERNEL);

	if (!kmalloced)  {
		return -ENOMEM;
        }

	kmalloced[0] = RET; 
	kmalloced[1] = NOP; 
	kmalloced[2] = NOP; 

	if (execute(kmalloced) == 0) {
	   printk(KERN_INFO "NX Test:  Kmalloc memory was executable\n");
	   ret[1] = 0;
	}

	kfree(kmalloced);

	if (execute(heap) == 0) {
	   printk(KERN_INFO "NX Test:  Heap was executable\n");
	   ret[2] = 0;
        }

        if ( ret[0]  || ret[1] || ret[2]) {
	   printk(KERN_INFO "NX Test: Failed\n");
        }
        else {
	   printk(KERN_INFO "NX Test: Passed\n");
        }

	return ret[0] | ret[1] | ret[2];
}

