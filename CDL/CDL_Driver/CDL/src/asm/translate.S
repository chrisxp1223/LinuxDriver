.code64

#include <asm/page.h>  /* For access to __PAGE_OFFSET */

#*****************************************************************************

.align 4
.global amd_phys
amd_phys:
        xor    %rax,%rax
	pushq	%rbx
	pushq	%rcx
	pushq	%rdx
	pushq	%r10
	pushq	%r9

	movq	%rdi, %rax			# parameter is linear addr
	movq	%rsi, %r9			# parameter is page offset
	movq	%cr3, %rcx			# phys addr of pml4 base
	movq	%rax, %rbx			# input addr to rbx
	movq	%r9, %r10	        # Physical to linear converson mask
	orq	%r10, %rcx	                # linear address of pml4 base

	movq	$0x0000ff8000000000, %rdx
	andq	%rdx, %rax			# calc offset into pml4
	shrq	$36, %rax
	addq	%rcx, %rax			# lin addr of entry in pml4
	movq	0(%rax), %rsi			# grab pml4 entry

	movq	%rsi, %rax
	movq	$0x0000000000000001, %rdx
	andq	%rdx, %rax			# present?
	jz	perr

	movq	%rsi, %rax
	movq	%rbx, %rsi
	movq	$0x000ffffffffff000, %rdx
	andq	%rdx, %rax			# base addr bits from pml4 entry
	movq	$0x0000007fc0000000, %rdx
	andq	%rdx, %rsi			# pdp offset from input addr
	shrq	$27, %rsi
	addq	%rsi, %rax			# physical addr of pdp in rax
	movq	%r9, %r10	                # Physical to linear converson mask
	orq	%r10, %rax	                # linear addr of pgdir in rax

	movq	0(%rax), %rsi			# pdp entry in rsi
	movq	%rsi, %rax
	movq	$0x0000000000000001, %rdx
	andq	%rdx, %rax			# present?
	jz	perr

	movq	%rsi, %rax
	movq	%rbx, %rsi
	movq	$0x000ffffffffff000, %rdx
	andq	%rdx, %rax			# base addr bits from pdp entry
	movq	$0x000000003fe00000, %rdx
	andq	%rdx, %rsi			# pgdir offset from input addr
	shrq	$18, %rsi
	addq	%rsi, %rax			# physical addr of pgdir in rax
	movq	%r9, %r10	                # Physical to linear converson mask
	orq	%r10, %rax	                # linear addr of pgdir in rax

	movq	0(%rax), %rsi			# pgdir entry in rsi
	movq	%rsi, %rax
	movq	$0x0000000000000001, %rdx
	andq	%rdx, %rax			# present?
	jz	perr

	movq	%rsi, %rax
	movq	$0x0000000000000080, %rdx
	andq	%rdx, %rsi			# 2MB page?
	jz	pg4k

	movq	$0x00000000001fffff, %rdx
	andq	%rdx, %rbx			# build addr from pgdir + offset
	movq	$0x000ffffffffff000, %rdx	
	andq	%rdx, %rax	
	addq	%rbx, %rax			# required phys addr in rax

pdone:	
        popq	%r9
        popq	%r10
        popq	%rdx
	popq	%rcx
	popq	%rbx
	ret

pg4k:
	movq	%rbx, %rsi
	movq	$0x000ffffffffff000, %rdx
	andq	%rdx, %rax			# base addr from pgdir entry
	movq	$0x00000000001ff000, %rdx
	andq	%rdx, %rsi			# page table offset from input
	shrq	$9, %rsi
	addq	%rsi, %rax			# physical addr of pte in eax
	movq	%r9, %r10	                # Physical to linear converson mask
	orq	%r10, %rax	                # linear addr of pgdir in rax

	movq	0(%rax), %rsi			# pte in rsi
	movq	%rsi, %rax
	movq	$0x0000000000000001, %rdx
	andq	%rdx, %rsi			# present?
	jz	perr

	movq	$0x0000000000000fff, %rdx
	andq	%rdx, %rbx			# add offset to page base addr
	movq	$0x000ffffffffff000, %rdx
	andq	%rdx, %rax
	addq	%rbx, %rax			# required phys addr in rax
	jmp	pdone

perr:	xorq	%rax, %rax
	decq	%rax
	jmp	pdone
