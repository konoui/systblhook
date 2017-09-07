#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/percpu.h>
#include <linux/smp.h>
#include <linux/syscalls.h>
#include <asm/syscall.h>


sys_call_ptr_t *syscall_table = (sys_call_ptr_t *)SYSCALL_TBL;

typedef long (*_do_fork_hack) (unsigned long, unsigned long, 
		unsigned long, 
		int __user *, int __user *, 
		unsigned long);
_do_fork_hack my_do_fork = (_do_fork_hack) DO_FORK;

extern void fake_stub_clone(void);
void *original_stub_clone;
void *original_sys_clone = (void *) SYS_CLONE;
void *original_sys_fork;
void *original_sys_vfork;


asmlinkage long fake_sys_clone(unsigned long clone_flags, unsigned long newsp, 
		int __user *parent_tidptr, 
		int __user *child_tidptr, 
		unsigned long tls) {

	printk("fake clone\n");

	return my_do_fork(clone_flags, newsp, 0, parent_tidptr, child_tidptr, tls);
}

asmlinkage static long fake_sys_fork(void) {
	printk("fake fork\n");
	return my_do_fork(SIGCHLD, 0, 0, NULL, NULL, 0);
}

asmlinkage static long fake_sys_vfork(void) {
	printk("fake vfork\n");
	return my_do_fork(CLONE_VFORK | CLONE_VM | SIGCHLD, 0, 0, NULL, NULL, 0);
}

//----------------------- exit ----------------------
typedef void (*do_exit_hack) (long);
typedef void (*do_group_exit_hack) (int);

void *original_sys_exit;
void *original_sys_exit_group;

do_exit_hack my_do_exit = (do_exit_hack) DO_EXIT;
do_group_exit_hack my_do_group_exit = (do_group_exit_hack) DO_GROUP_EXIT;

asmlinkage static int fake_sys_exit(int error_code) {
	printk("fake exit\n");
	my_do_exit((error_code & 0xff) << 8);
}

asmlinkage static int fake_sys_exit_group(int error_code) {
	printk("fake exit group\n");

	struct task_struct *task, *leader;

	rcu_read_lock();
	leader = current;
	task = current;
	int i = 0;
	do {
		printk("test %d %s: pid(%d) tgid(%d) \n", i, task->comm, task->pid, task->tgid);
		i++;
	} while_each_thread(leader, task);
	rcu_read_unlock();

	my_do_group_exit((error_code & 0xff) << 8);
	return 0;
}
//----------------------- exit ----------------------

int __init main_init(void)
{

	unsigned int l;
	pte_t *pte;

	pte = lookup_address((long unsigned int)syscall_table, &l);
	pte->pte |= _PAGE_RW;

	original_stub_clone =   syscall_table[__NR_clone];
	syscall_table[__NR_clone] = (void *) &fake_stub_clone;

	original_sys_fork =  syscall_table[__NR_fork];
	syscall_table[__NR_fork] = (void *) &fake_sys_fork;

	original_sys_vfork =   syscall_table[__NR_vfork];
	syscall_table[__NR_vfork] = (void *) &fake_sys_vfork;

	original_sys_exit = syscall_table[__NR_exit];
	syscall_table[__NR_exit] = (void *) &fake_sys_exit;

	original_sys_exit_group = syscall_table[__NR_exit_group];
	syscall_table[__NR_exit_group] = (void *) &fake_sys_exit_group;

	pte->pte &= ~_PAGE_RW;
	return 0;
}
 
void __exit main_cleanup(void)
{
	unsigned int l;
	pte_t *pte;

	pte = lookup_address((long unsigned int)syscall_table, &l);
	pte->pte |= _PAGE_RW;

	syscall_table[__NR_clone] = original_stub_clone;
	syscall_table[__NR_fork] = original_sys_fork;
	syscall_table[__NR_vfork] = original_sys_vfork;

	syscall_table[__NR_exit] = original_sys_exit;
	syscall_table[__NR_exit_group] = original_sys_exit_group;

	pte->pte &= ~_PAGE_RW;
	return;
}

module_init(main_init);
module_exit(main_cleanup);
MODULE_LICENSE("GPL");
