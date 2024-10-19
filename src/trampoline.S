/*
 * void amd64_tramp(uint64_t stack, void *copy_finish, uint64_t kernend,
 *		    uint64_t modulep, uint64_t pagetable, uint64_t entry)
 */
amd64_tramp:
	cli			/* Make sure we don't get interrupted. */
	mov	rsp, rcx	/* Switch to our temporary stack. */
    pop r14
    mov cr3, r14
	ret			/* "Return" to kernel entry. */

.p2align 4, 0x90

amd64_tramp_end: