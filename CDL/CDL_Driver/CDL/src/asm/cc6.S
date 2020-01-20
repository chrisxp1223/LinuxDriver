.code64
.global cc6

# MODULE_LICENSE("GPL");

#*****************************************************************************
#
#include <linux/linkage.h>
#
#*****************************************************************************
#
# int cc6(uint16_t port, uint64_t repeat);
#      port   --> %di
#      repeat --> %rsi
#
#*****************************************************************************

cc6:
	pushf
	push %rsi
	push %rdx

	sti                     // Enable interrupts so we can wake up
loop:
	in %dx,%ax              // Trigger CC6 halt
	dec %rsi
	test %rsi,%rsi
	jne loop

	pop %rdx
	pop %rsi
	popf

	xor %rax,%rax

	ret
