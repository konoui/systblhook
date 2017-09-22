#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/smp.h>
#include <linux/syscalls.h>
#include <asm/syscall.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <asm/pgtable.h>

#include <asm/syscall.h>

extern int entry_SYSCALL_64(void);
DEFINE_PER_CPU(uint64_t, rsp_scratch);
sys_call_ptr_t *sys_call_table_v2 = (sys_call_ptr_t *)SYSCALL_TBL;
// XXX
void syscall_return_slowpath(struct pt_regs *regs)
{
	return;
}

static inline void hook_syscall(void)
{
	wrmsrl(MSR_LSTAR, (uint64_t)entry_SYSCALL_64);
}

static inline uint64_t get_entry_syscall_from_msr(void)
{
	uint64_t address;
	rdmsrl(MSR_LSTAR, address);

	pr_info("msr lstar: 0x%lx\n", address);

	return address;
}

void *fake_entry = NULL;
uint64_t orig_entry_page;
pte_t orig_entry_pte_v;

static inline pte_t alloc_fake_entry_pte(void *entry_page)
{
	pte_t *fake_entry_pte;
	unsigned int l;

	fake_entry = kmalloc(4096*2, GFP_KERNEL);
	memcpy(fake_entry, entry_page, 4096);
	fake_entry_pte = lookup_address((uint64_t)fake_entry, &l);
	
	*fake_entry_pte = pte_mkwrite(*fake_entry_pte);
	*fake_entry_pte = pte_mkexec(*fake_entry_pte);

	pr_info("exec flag %d write flag %d\n", pte_exec(*fake_entry_pte), pte_write(*fake_entry_pte));
	pr_info("fake entry pte: %p, *pte 0x%llx\n", fake_entry_pte, *fake_entry_pte);

	return *fake_entry_pte;
}

static inline void hook_entry_syscall(void)
{
	uint64_t orig_entry;
	unsigned int l;
	pte_t *orig_entry_pte;
	pte_t fake_entry_pte_v;

	orig_entry = get_entry_syscall_from_msr();
	orig_entry_page = orig_entry & PAGE_MASK;
	pr_info("orig entry 0x%llx entry page 0x%llx\n", orig_entry, orig_entry_page);

	orig_entry_pte = lookup_address(orig_entry_page, &l);
	pr_info("orig entry pte: %p *pte 0x%llx\n", orig_entry_pte, *orig_entry_pte);

	fake_entry_pte_v = alloc_fake_entry_pte((void*)orig_entry_page);

	orig_entry_pte_v = *orig_entry_pte;
	*orig_entry_pte  = fake_entry_pte_v;
	/* XXX */
	/* TLB FLUSH */
}

int __init main_init(void)
{
//	hook_entry_syscall();
	hook_entry_syscall();
	pr_info("%p\n", entry_SYSCALL_64);
	return 0;
}

void __exit main_cleanup(void)
{
	unsigned int l;
	pte_t *entry_pte;
	entry_pte = lookup_address(orig_entry_page, &l);
	pr_info("entry pte: %p *pte 0x%llx\n", entry_pte, *entry_pte);
	pr_info("orig_entry_pte: 0x%llx\n", orig_entry_pte_v);

	*entry_pte = orig_entry_pte_v;
	kfree(fake_entry);
	return;
}

module_init(main_init);
module_exit(main_cleanup);
MODULE_LICENSE("GPL");
