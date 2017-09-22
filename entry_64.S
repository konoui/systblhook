/*
 *  linux/arch/x86_64/entry.S
 *
 *  Copyright (C) 1991, 1992  Linus Torvalds
 *  Copyright (C) 2000, 2001, 2002  Andi Kleen SuSE Labs
 *  Copyright (C) 2000  Pavel Machek <pavel@suse.cz>
 *
 * entry.S contains the system-call and fault low-level handling routines.
 *
 * Some of this is documented in Documentation/x86/entry_64.txt
 *
 * A note on terminology:
 * - iret frame:	Architecture defined interrupt frame from SS to RIP
 *			at the top of the kernel process stack.
 *
 * Some macro usage:
 * - ENTRY/END:		Define functions in the symbol table.
 * - TRACE_IRQ_*:	Trace hardirq state for lock debugging.
 * - idtentry:		Define exception entry points.
 */
#include <linux/linkage.h>
#include <asm/segment.h>
#include <asm/cache.h>
#include <asm/errno.h>
#include "calling.h"
#include <asm/asm-offsets.h>
#include <asm/msr.h>
#include <asm/unistd.h>
#include <asm/thread_info.h>
#include <asm/hw_irq.h>
#include <asm/page_types.h>
#include <asm/irqflags.h>
#include <asm/paravirt.h>
#include <asm/percpu.h>
#include <asm/asm.h>
#include <asm/smap.h>
#include <asm/pgtable_types.h>
#include <linux/err.h>

// NOTE [ouikon] add
//#include <asm/ptrace.h>

/* Avoid __ASSEMBLER__'ifying <linux/audit.h> just for this.  */
#include <linux/elf-em.h>
#define AUDIT_ARCH_X86_64			(EM_X86_64|__AUDIT_ARCH_64BIT|__AUDIT_ARCH_LE)
#define __AUDIT_ARCH_64BIT			0x80000000
#define __AUDIT_ARCH_LE				0x40000000


.macro TRACE_IRQS_IRETQ
.endm

ENTRY(entry_SYSCALL_64)
	/*
	 * Interrupts are off on entry.
	 * We do not frame this tiny irq-off block with TRACE_IRQS_OFF/ON,
	 * it is too small to ever cause noticeable irq latency.
	 */
	SWAPGS_UNSAFE_STACK
	/*
	 * A hypervisor implementation might want to use a label
	 * after the swapgs, so that it can do the swapgs
	 * for the guest and jump here on syscall.
	 */
GLOBAL(entry_SYSCALL_64_after_swapgs)

	movq	%rsp, PER_CPU_VAR(rsp_scratch)
	movq	PER_CPU_VAR(cpu_current_top_of_stack), %rsp

	/* Construct struct pt_regs on stack */
	pushq	$__USER_DS			/* pt_regs->ss */
	pushq	PER_CPU_VAR(rsp_scratch)	/* pt_regs->sp */
	/*
	 * Re-enable interrupts.
	 * We use 'rsp_scratch' as a scratch space, hence irq-off block above
	 * must execute atomically in the face of possible interrupt-driven
	 * task preemption. We must enable interrupts only after we're done
	 * with using rsp_scratch:
	 */
	ENABLE_INTERRUPTS(CLBR_NONE)
	pushq	%r11				/* pt_regs->flags */
	pushq	$__USER_CS			/* pt_regs->cs */
	pushq	%rcx				/* pt_regs->ip */
	pushq	%rax				/* pt_regs->orig_ax */
	pushq	%rdi				/* pt_regs->di */
	pushq	%rsi				/* pt_regs->si */
	pushq	%rdx				/* pt_regs->dx */
	pushq	%rcx				/* pt_regs->cx */
	pushq	$-ENOSYS			/* pt_regs->ax */
	pushq	%r8				/* pt_regs->r8 */
	pushq	%r9				/* pt_regs->r9 */
	pushq	%r10				/* pt_regs->r10 */
	pushq	%r11				/* pt_regs->r11 */
	sub	$(6*8), %rsp			/* pt_regs->bp, bx, r12-15 not saved */

	testl	$_TIF_WORK_SYSCALL_ENTRY, ASM_THREAD_INFO(TI_flags, %rsp, SIZEOF_PTREGS)
	jnz	tracesys
entry_SYSCALL_64_fastpath:
#if __SYSCALL_MASK == ~0
	cmpq	$__NR_syscall_max, %rax
#else
	andl	$__SYSCALL_MASK, %eax
	cmpl	$__NR_syscall_max, %eax
#endif
	ja	1f				/* return -ENOSYS (already in pt_regs->ax) */
	movq	%r10, %rcx
//	call	*sys_call_table(, %rax, 8)
	call	*sys_call_table_v2(, %rax, 8)
	movq	%rax, RAX(%rsp)
1:
/*
 * Syscall return path ending with SYSRET (fast path).
 * Has incompletely filled pt_regs.
 */
	LOCKDEP_SYS_EXIT
	/*
	 * We do not frame this tiny irq-off block with TRACE_IRQS_OFF/ON,
	 * it is too small to ever cause noticeable irq latency.
	 */
	DISABLE_INTERRUPTS(CLBR_NONE)

	/*
	 * We must check ti flags with interrupts (or at least preemption)
	 * off because we must *never* return to userspace without
	 * processing exit work that is enqueued if we're preempted here.
	 * In particular, returning to userspace with any of the one-shot
	 * flags (TIF_NOTIFY_RESUME, TIF_USER_RETURN_NOTIFY, etc) set is
	 * very bad.
	 */
	testl	$_TIF_ALLWORK_MASK, ASM_THREAD_INFO(TI_flags, %rsp, SIZEOF_PTREGS)
	jnz	int_ret_from_sys_call_irqs_off	/* Go to the slow path */

	RESTORE_C_REGS_EXCEPT_RCX_R11
	movq	RIP(%rsp), %rcx
	movq	EFLAGS(%rsp), %r11
	movq	RSP(%rsp), %rsp
	/*
	 * 64-bit SYSRET restores rip from rcx,
	 * rflags from r11 (but RF and VM bits are forced to 0),
	 * cs and ss are loaded from MSRs.
	 * Restoration of rflags re-enables interrupts.
	 *
	 * NB: On AMD CPUs with the X86_BUG_SYSRET_SS_ATTRS bug, the ss
	 * descriptor is not reinitialized.  This means that we should
	 * avoid SYSRET with SS == NULL, which could happen if we schedule,
	 * exit the kernel, and re-enter using an interrupt vector.  (All
	 * interrupt entries on x86_64 set SS to NULL.)  We prevent that
	 * from happening by reloading SS in __switch_to.  (Actually
	 * detecting the failure in 64-bit userspace is tricky but can be
	 * done.)
	 */
	USERGS_SYSRET64


GLOBAL(int_ret_from_sys_call_irqs_off)
	TRACE_IRQS_ON
	ENABLE_INTERRUPTS(CLBR_NONE)
	jmp int_ret_from_sys_call

	/* Do syscall entry tracing */
tracesys:
	movq	%rsp, %rdi
	movl	$AUDIT_ARCH_X86_64, %esi
//	call	syscall_trace_enter_phase1
	nop //ouikon
	test	%rax, %rax

//	jnz	tracesys_phase2			/* if needed, run the slow path */
	nop // ouikon

	RESTORE_C_REGS_EXCEPT_RAX		/* else restore clobbered regs */
	movq	ORIG_RAX(%rsp), %rax
	jmp	entry_SYSCALL_64_fastpath	/* and return to the fast path */

tracesys_phase2:
	SAVE_EXTRA_REGS
	movq	%rsp, %rdi
	movl	$AUDIT_ARCH_X86_64, %esi
	movq	%rax, %rdx

//	call	syscall_trace_enter_phase2
	nop //ouikon

	/*
	 * Reload registers from stack in case ptrace changed them.
	 * We don't reload %rax because syscall_trace_entry_phase2() returned
	 * the value it wants us to use in the table lookup.
	 */
	RESTORE_C_REGS_EXCEPT_RAX
	RESTORE_EXTRA_REGS
#if __SYSCALL_MASK == ~0
	cmpq	$__NR_syscall_max, %rax
#else
	andl	$__SYSCALL_MASK, %eax
	cmpl	$__NR_syscall_max, %eax
#endif
	ja	1f				/* return -ENOSYS (already in pt_regs->ax) */
	movq	%r10, %rcx			/* fixup for C */
//	call	*sys_call_table(, %rax, 8)
	call	*sys_call_table_v2(, %rax, 8)
	movq	%rax, RAX(%rsp)
1:
	/* Use IRET because user could have changed pt_regs->foo */

/*
 * Syscall return path ending with IRET.
 * Has correct iret frame.
 */
GLOBAL(int_ret_from_sys_call)
GLOBAL(int_ret_from_sys_call)
        SAVE_EXTRA_REGS
        movq    %rsp, %rdi
        call    syscall_return_slowpath /* returns with IRQs disabled */
        RESTORE_EXTRA_REGS
        TRACE_IRQS_IRETQ                /* we're about to change IF */

        /*
         * Try to use SYSRET instead of IRET if we're returning to
         * a completely clean 64-bit userspace context.
         */
        movq    RCX(%rsp), %rcx
        movq    RIP(%rsp), %r11
        cmpq    %rcx, %r11                      /* RCX == RIP */
        jne     opportunistic_sysret_failed

        /*
         * On Intel CPUs, SYSRET with non-canonical RCX/RIP will #GP
         * in kernel space.  This essentially lets the user take over
         * the kernel, since userspace controls RSP.
         *
         * If width of "canonical tail" ever becomes variable, this will need
         * to be updated to remain correct on both old and new CPUs.
         */
        .ifne __VIRTUAL_MASK_SHIFT - 47
        .error "virtual address width changed -- SYSRET checks need update"
        .endif

        /* Change top 16 bits to be the sign-extension of 47th bit */
        shl     $(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx
        sar     $(64 - (__VIRTUAL_MASK_SHIFT+1)), %rcx

        /* If this changed %rcx, it was not canonical */
        cmpq    %rcx, %r11
        jne     opportunistic_sysret_failed

        cmpq    $__USER_CS, CS(%rsp)            /* CS must match SYSRET */
        jne     opportunistic_sysret_failed

        movq    R11(%rsp), %r11
        cmpq    %r11, EFLAGS(%rsp)              /* R11 == RFLAGS */
        jne     opportunistic_sysret_failed

        /*
         * SYSRET can't restore RF.  SYSRET can restore TF, but unlike IRET,
         * restoring TF results in a trap from userspace immediately after
         * SYSRET.  This would cause an infinite loop whenever #DB happens
         * with register state that satisfies the opportunistic SYSRET
         * conditions.  For example, single-stepping this user code:
         *
         *           movq       $stuck_here, %rcx
         *           pushfq
         *           popq %r11
         *   stuck_here:
         *
         * would never get past 'stuck_here'.
         */
        testq   $(X86_EFLAGS_RF|X86_EFLAGS_TF), %r11
        jnz     opportunistic_sysret_failed

        /* nothing to check for RSP */

        cmpq    $__USER_DS, SS(%rsp)            /* SS must match SYSRET */
        jne     opportunistic_sysret_failed

        /*
         * We win! This label is here just for ease of understanding
         * perf profiles. Nothing jumps here.
         */
syscall_return_via_sysret:
        /* rcx and r11 are already restored (see code above) */
        RESTORE_C_REGS_EXCEPT_RCX_R11
        movq    RSP(%rsp), %rsp
        USERGS_SYSRET64

opportunistic_sysret_failed:
        SWAPGS
        jmp     restore_c_regs_and_iret
END(entry_SYSCALL_64)


GLOBAL(restore_regs_and_iret)
	RESTORE_EXTRA_REGS
	restore_c_regs_and_iret:
	RESTORE_C_REGS
	REMOVE_PT_GPREGS_FROM_STACK 8
	INTERRUPT_RETURN
