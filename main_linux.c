#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/smp.h>
#include <linux/syscalls.h>
#include <asm/syscall.h>
#include <linux/vmalloc.h>
#include <linux/slab.h>
#include <asm/pgtable.h>

//#define MSR_LSTAR	0xC0000082
sys_call_ptr_t *syscall_table = (sys_call_ptr_t *)SYSCALL_TBL;
void *k_page = NULL;
uint64_t orig_dispatcher;

static inline uint64_t get_dispatcher_from_msr(void)
{
	uint32_t low = 0, high = 0;
	uint64_t address;

	rdmsr(MSR_LSTAR,low, high);
	address = 0;
	address |= high;
	address = address << 32;
	address |= low;

	pr_info("hook msr: 0x%lx\n", address);

	return address;
}

int __init main_init(void)
{
	uint64_t orig_dispatcher_page;
	unsigned int l, k;
	pte_t *orig_pte;
	pte_t *k_page_pte;

	orig_dispatcher = get_dispatcher_from_msr();
	orig_dispatcher_page = orig_dispatcher & PAGE_MASK;
	pr_info("orig dsptchr 0x%llx dsptchr page 0x%llx\n", orig_dispatcher, orig_dispatcher_page);

	orig_pte = lookup_address(orig_dispatcher_page, &l);
	pr_info("orig_dispatcher pte: %p *pte 0x%llx\n", orig_pte, *orig_pte);

	k_page = kmalloc(4096*2, GFP_KERNEL);
	memcpy(k_page, (void *)orig_dispatcher_page, 4096);
	k_page_pte = lookup_address((uint64_t)k_page, &k);
	
	*k_page_pte = pte_mkwrite(*k_page_pte);
	*k_page_pte = pte_mkexec(*k_page_pte);

	pr_info("exec flag %d write flag %d\n", pte_exec(*k_page_pte), pte_write(*k_page_pte));
	pr_info("present %d\n", pte_present(*k_page_pte));
	pr_info("k_page pte: %p, *pte 0x%llx\n", k_page_pte, *k_page_pte);

	*orig_pte = *k_page_pte;

	return 0;
}
 
void __exit main_cleanup(void)
{
	unsigned int l, k;
	pte_t *orig_pte;
	pte_t *k_page_pte;
	
	return;
}

module_init(main_init);
module_exit(main_cleanup);
MODULE_LICENSE("GPL");
