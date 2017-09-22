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

static inline uint64_t get_entry_syscall_from_msr(void)
{
	uint64_t address;
	rdmsrl(MSR_LSTAR, address);

	pr_info("msr lstar: 0x%lx\n", address);

	return address;
}

void *g_fake_entry = NULL;
uint64_t g_orig_entry_page;
pte_t g_orig_entry_pte_v;

static inline void *alloc_fake_entry(void *entry_page)
{
	void* l_fake_entry;
	l_fake_entry = kmalloc(4096*2, GFP_KERNEL);
	memcpy(l_fake_entry, entry_page, 4096);

	return l_fake_entry;
}

static inline pte_t alloc_fake_entry_pte(void *entry_page)
{
	pte_t *fake_entry_pte;
	unsigned int l;

	g_fake_entry = alloc_fake_entry(entry_page);
	fake_entry_pte = lookup_address((uint64_t)g_fake_entry, &l);
	
	*fake_entry_pte = pte_mkwrite(*fake_entry_pte);
	*fake_entry_pte = pte_mkexec(*fake_entry_pte);

	pr_info("exec flag %d write flag %d\n", pte_exec(*fake_entry_pte), pte_write(*fake_entry_pte));
	pr_info("fake entry pte: %p, *pte 0x%llx\n", fake_entry_pte, *fake_entry_pte);

	return *fake_entry_pte;
}

static inline void hook_syscall(void)
{
	uint64_t orig_entry;
	void *l_fake_entry;
	orig_entry   = get_entry_syscall_from_msr();
	l_fake_entry = alloc_fake_entry((void *)orig_entry);
	wrmsrl(MSR_LSTAR, (uint64_t)l_fake_entry);
//	wrmsrl(MSR_LSTAR, (uint64_t)entry_SYSCALL_64);
}

static inline void hook_entry_syscall(void)
{
	uint64_t orig_entry;
	unsigned int l;
	pte_t *orig_entry_pte;
	pte_t fake_entry_pte_v;

	orig_entry = get_entry_syscall_from_msr();
	g_orig_entry_page = orig_entry & PAGE_MASK;
	orig_entry_pte = lookup_address(g_orig_entry_page, &l);

	pr_info("orig entry 0x%llx entry page 0x%llx\n", orig_entry, g_orig_entry_page);
	pr_info("orig entry pte: %p *pte 0x%llx\n", orig_entry_pte, *orig_entry_pte);

	fake_entry_pte_v = alloc_fake_entry_pte((void*)g_orig_entry_page);

	g_orig_entry_pte_v = *orig_entry_pte;
	*orig_entry_pte  = fake_entry_pte_v;

	/* XXX */
	/* TLB FLUSH */
}

int __init main_init(void)
{
	hook_syscall();
//	hook_entry_syscall();
	pr_info("entry_SYSCALL_64 %p\n", entry_SYSCALL_64);
	pr_info("current lstar %p\n", get_entry_syscall_from_msr());
	return 0;
}

void __exit main_cleanup(void)
{
	unsigned int l;
	pte_t *entry_pte;
	entry_pte = lookup_address(g_orig_entry_page, &l);
	pr_info("entry pte: %p *pte 0x%llx\n", entry_pte, *entry_pte);
	pr_info("orig_entry_pte: 0x%llx\n", g_orig_entry_pte_v);

	*entry_pte = g_orig_entry_pte_v;
	kfree(g_fake_entry);
	return;
}

module_init(main_init);
module_exit(main_cleanup);
MODULE_LICENSE("GPL");
