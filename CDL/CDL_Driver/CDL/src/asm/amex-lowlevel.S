.text


#***********************************************************************************************

#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/pgtable_types.h>
#include <asm/page_types.h>
#include <asm/msr.h>
#include <asm/asm-offsets.h>

#***********************************************************************************************

.code64
.globl amex_lowlevel
.globl amex_dummy

#***********************************************************************************************

amex_lowlevel:

# arg0 --> %rdi --> AMEX entry point
# arg1 --> %rsi --> Passed to AMEX.  Typically the IOAPIC linear base addess
# arg2 --> %rdx --> Passed to AMEX.  Typically the Local APIC linear base addess

	pushq	%rbp
	pushq	%rsi
	pushq	%rdi
	pushq	%rax
	pushq	%rbx
	pushq	%rcx
	pushq	%rdx
	pushq	%r8
	pushq	%r9
	pushq	%r10
	pushq	%r11
	pushq	%r12
	pushq	%r13
	pushq	%r14
	pushq	%r15
	pushfq

	call *%rdi  /* Call amex code */

	popfq
	popq	%r15
	popq	%r14
	popq	%r13
	popq	%r12
	popq	%r11
	popq	%r10
	popq	%r9
	popq	%r8
	popq	%rdx
	popq	%rcx
	popq	%rbx
	popq	%rax
	popq	%rdi
	popq	%rsi
	popq	%rbp

        ret

#***********************************************************************************************

amex_dummy:
# Clear out most of the GPRs to test Save/Restore
	xorq	%rsi, %rsi
	xorq	%rdi, %rdi
	xorq	%rbx, %rbx
	xorq	%rcx, %rcx
	xorq	%rdx, %rdx
	xorq	%r8, %r8
	xorq	%r9, %r9
	xorq	%r10, %r10
	xorq	%r11, %r11
	xorq	%r12, %r12
	xorq	%r13, %r13
	xorq	%r14, %r14
	xorq	%r15, %r15
	ret

#***********************************************************************************************



