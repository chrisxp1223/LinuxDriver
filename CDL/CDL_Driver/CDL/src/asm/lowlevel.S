.code64

#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/pgtable_types.h>
#include <asm/page_types.h>
#include <asm/msr.h>
#include <asm/asm-offsets.h>

#*****************************************************************************

.globl do_amd_user_code
do_amd_user_code:

# arg0 --> %rdi    -->
# arg1 --> %rsi    --> 
# arg2 --> %rdx    --> 
# arg3 --> %rcx    --> 
# arg4 --> %r8     --> 
# arg5 --> %r9     --> 

# ret  --> 0(%rsp) --> Caller return address
# arg6 --> 8(%rsp) --> Pointer to user code copied to kmalloc memory

	pushq %rbx
	movq 16(%rsp),%rbx    /* Get user code entry point */
	pushq %r10
	pushq %r11
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15
	pushq %rdi
	pushq %rsi
	pushq %rdx
	pushq %rcx
	pushq %r8
	pushq %r9
	
	movq (%rdi),%rdi     /* Dereference pointer */
	movq (%rsi),%rsi     /* Dereference pointer */
	movq (%rdx),%rdx     /* Dereference pointer */
	movq (%rcx),%rcx     /* Dereference pointer */
	movq (%r8),%r8       /* Dereference pointer */
	movq (%r9),%r9       /* Dereference pointer */

	call *%rbx         /* Call amd user code */

	popq %r15                
	movq %r9,(%r15)     

	popq %r15         
	movq %r8,(%r15)     

	popq %r15         
	movq %rcx,(%r15)     

	popq %r15         
	movq %rdx,(%r15)     

	popq %r15         
	movq %rsi,(%r15)     

	popq %r15         
	movq %rdi,(%r15)     

	popq %r15

	popq  %r14
	popq  %r13
	popq  %r12
	popq  %r11
	popq  %r10
	popq  %rbx

        ret

#*****************************************************************************

.globl amd_dummy
amd_dummy:
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
