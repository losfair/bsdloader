/*
 * OpenBSD/amd64 kernel handoff trampoline.
 *
 * Adapted from OpenBSD sys/arch/amd64/stand/efiboot/run_i386.S
 *   Copyright (c) 2015 YASUOKA Masahiko <yasuoka@yasuoka.net>
 *   ISC-style license (see source file header).
 *
 * This stub is copied into a low (<4GB) page that is *not* part of the kernel
 * destination range, then jumped to after ExitBootServices().  It:
 *
 *   1. stages the eight 32-bit kernel arguments into a local area,
 *   2. memmove()s the loaded kernel image from the EFI staging region down to
 *      its final low physical address (params->dst),
 *   3. installs a flat 32-bit GDT, far-jumps to a 32-bit code segment,
 *      disables paging and PAE (dropping out of long mode), and
 *   4. calls the kernel entry point with the i386-style stack arguments:
 *          start(howto, bootdev, apiver, end, extmem, cnvmem, ac, av)
 *
 * Single argument (SysV ABI, %rdi): pointer to `struct TrampParams`:
 *     0x00 u64 src       (kernel image start in EFI staging region)
 *     0x08 u64 dst       (final low physical destination)
 *     0x10 u64 len       (bytes to move)
 *     0x18 u64 entry     (32-bit physical kernel entry point)
 *     0x20 u32 howto
 *     0x24 u32 bootdev
 *     0x28 u32 apiver
 *     0x2c u32 markend
 *     0x30 u32 extmem
 *     0x34 u32 cnvmem
 *     0x38 u32 ac
 *     0x3c u32 av
 */


	.text
	.globl	obsd_tramp
	.globl	obsd_tramp_end
	.p2align 4
.code64
obsd_tramp:
	cli

	/* Stage the eight i386 arguments (32 bytes at params+0x20). */
	lea	iarg_area(%rip), %rax
	movq	0x20(%rdi), %rcx
	movq	%rcx, 0x00(%rax)
	movq	0x28(%rdi), %rcx
	movq	%rcx, 0x08(%rax)
	movq	0x30(%rdi), %rcx
	movq	%rcx, 0x10(%rax)
	movq	0x38(%rdi), %rcx
	movq	%rcx, 0x18(%rax)

	/* Keep the entry point in a register that survives the move. */
	movq	0x18(%rdi), %r15

	/* memmove(dst, src, len) via rep movsb (dst < src, forward-safe). */
	movq	0x00(%rdi), %rsi	/* src */
	movq	0x10(%rdi), %rcx	/* len */
	movq	0x08(%rdi), %rdx	/* dst */
	movq	%rdx, %rdi		/* %rdi = dst (params pointer now dead) */
	cld
	rep	movsb

	/* Recompute our own load base for 32-bit (%edi-relative) addressing. */
	lea	obsd_tramp(%rip), %rdi
	movq	%r15, %rsi		/* %esi = kernel entry for the 32-bit call */

	/* Patch the indirect far-jump target with &start32a. */
	lea	start32a(%rip), %rax
	movl	%eax, start32r(%rip)

	/* Load the flat 32-bit GDT. */
	lea	gdt(%rip), %rax
	movq	%rax, gdtrr(%rip)
	lgdt	gdtr(%rip)

	/* Far jump to reload %cs with the 32-bit code segment. */
	ljmp	*start32r(%rip)

	.p2align 4
start32a:
	.code32
	movl	$0x18, %eax		/* DATA_SEGMENT */
	movl	%eax, %ds
	movl	%eax, %es
	movl	%eax, %fs
	movl	%eax, %gs
	movl	%eax, %ss

	/* %esp = &iarg_area (top of the i386 argument block). */
	leal	(iarg_area - obsd_tramp)(%edi), %eax
	movl	%eax, %esp

	/* Disable paging (drops us out of long mode: LMA = LME & PG). */
	movl	%cr0, %eax
	andl	$0x7fffffff, %eax	/* ~CR0_PG */
	movl	%eax, %cr0

	/* Disable PAE. */
	movl	%cr4, %eax
	andl	$0xffffffdf, %eax	/* ~CR4_PAE */
	movl	%eax, %cr4

	jmp	start32b
start32b:
	.code32
	call	*%esi

	/* not reached */
1:	hlt
	jmp	1b

	.p2align 4
start32r:
	.long	0			/* offset (patched to &start32a) */
	.long	0x10			/* CODE_SEGMENT selector */

	.p2align 4
gdt:
	.long	0, 0
	.long	0, 0
	.byte	0xff, 0xff, 0x00, 0x00, 0x00, 0x9f, 0xcf, 0x00
	.byte	0xff, 0xff, 0x00, 0x00, 0x00, 0x93, 0xcf, 0x00
gdtr:
	.word	gdtr - gdt		/* limit */
gdtrr:
	.quad	0			/* base (patched to &gdt) */

	.p2align 4
	.space	8192			/* i386 call stack (grows down into here) */
iarg_area:
	.space	32			/* eight 32-bit kernel arguments */
obsd_tramp_end:

