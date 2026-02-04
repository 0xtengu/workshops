 _     _                    ____             _   _    _ _ 
| |   (_)_ __  _   ___  __ |  _ \ ___   ___ | |_| | _(_) |_ ___ 
| |   | | '_ \| | | \ \/ / | |_) / _ \ / _ \| __| |/ / | __/ __|
| |___| | | | | |_| |>  <  |  _ < (_) | (_) | |_|   <| | |_\__ \
|_____|_|_| |_|\__,_/_/\_\ |_| \_\___/ \___/ \__|_|\_\_|\__|___/
                                                                  
                                W O R K S H O P 

================================================================================
                            PART I: FOUNDATIONS
================================================================================


----[ Introduction - Linux Rootkits Landscape ]------------------------------

A rootkit is malware whose main objective and purpose is to:

    Maintain persistence within a system
    Remain completely hidden from detection
    Hide processes, files, directories, and network connections
    Avoid detection by security tools
    Change the system's default behavior

This makes detection complex, and mitigation even more challenging, since 
one of the primary objectives of a rootkit is to remain hidden.

# We already have initial access

In this workshop, we cover two major categories:

    USERLAND ROOTKITS - Operating in user space using techniques like LD_PRELOAD

#### Mostly though
    KERNEL ROOTKITS - Operating in kernel space as Loadable Kernel Modules (LKMs)

# WHY LKM's HERE - WE WILL COME BACK TO THIS TOO
    
Why Attackers Choose Kernel Rootkits:

    Kernel-level privileges with complete access to system resources
    Deep system integration with ability to hook critical functions
    Difficult detection at the lowest system layer
    Powerful capabilities to manipulate any aspect of the OS


----[ Userland vs Kernel Space ]----------------------------------------------

The kernel is the core of the operating system, responsible for managing system
resources, facilitating hardware/software communication, and operating at the
lowest layer. Userspace is where user programs execute (browsers, shells, etc).

Linux uses a monolithic kernel design where all core functionality lives in
kernel space with unrestricted access between components.

                +----------------------------------+
                |        USER SPACE (Ring 3)       |
                |                                  |
                |  [Browser] [Shell] [Text Editor] |
                |                                  |
                +----------------------------------+
                        |  System Calls  |
                        v                v
                +----------------------------------+
                |       KERNEL SPACE (Ring 0)      |
                |                                  |
                |  [Kernel] [Drivers] [Modules]    |
                |                                  |
                +----------------------------------+
                        |                |
                        v                v
                +----------------------------------+
                |           HARDWARE               |
                +----------------------------------+

# MEMORY

ACCESS RULES:

    Kernel space:
        Access to all memory (kernel + userspace)
        Must use copy_from_user/copy_to_user for safety
        Can modify page tables
        
    User space:
        Only own process memory
        Cannot access other processes
        Cannot access kernel memory
        Violations cause segfault

WHY THIS MATTERS FOR ROOTKITS:

    Userland rootkits:
        Restricted by memory isolation
        Cannot access kernel memory
        Limited to library interception*
        
    Kernel rootkits:
        Run in Ring 0
        Access all memory++
        Modify kernel code/data
        Intercept syscalls before userspace
        Hide from all userspace tools

# MMU

The CPU's MMU and page tables enforce isolation. Each process sees its own
virtual address space:

    Process A:                   Process B:                   Kernel:
    0x0000 - 0x7FFF             0x0000 - 0x7FFF             Sees all memory
    [Process A memory]          [Process B memory] 
    
    0x8000 - 0xFFFF             0x8000 - 0xFFFF             0x8000 - 0xFFFF
    [Kernel - blocked]          [Kernel - blocked]          [Kernel memory]

Same virtual address maps to different physical RAM per process.

# PAGE TABLES

Each page table entry contains permission bits:

    U/S bit - User/Supervisor (can userspace access?)
    R/W bit - Read/Write permission
    NX bit  - No Execute

Example entries:

    Userspace page: U=1, R/W=1 (user accessible)
    Kernel page:    U=0, R/W=1 (kernel only)

VIOLATION HANDLING:

When userspace tries to access kernel memory:

    1. MMU checks page table entry
    2. Sees U/S bit = 0 (supervisor only)
    3. Current ring = 3 (user mode)
    4. MMU triggers Page Fault
    5. Kernel sends SIGSEGV
    6. Process crashes: "Segmentation fault"

# COMMS
        
    Device Files (/dev):
        Special files representing devices or kernel interfaces
        Read/write operations trigger kernel code
        
        Character devices (stream):
            /dev/null       Discards writes, returns EOF
            /dev/zero       Returns infinite zeros
            /dev/urandom    Pseudo-random bytes
            /dev/random     Crypto-secure random
            
        Block devices (fixed blocks):
            /dev/sda        SATA/SCSI disk
            /dev/nvme0n1    NVMe drive
            
        Pseudo devices (kernel interfaces):
            /dev/shm        Shared memory
            /dev/pts/*      Pseudo-terminals

----[ System Calls - The Interface Between Worlds ]---------------------------

System calls (syscalls) are fundamental interfaces that allow running processes
to request services from the kernel.

        CPU switches Ring 3 → Ring 0
        Kernel validates and executes
        Returns to Ring 3

Services provided by syscalls include:

    File management
    Inter-process communication
    Process creation and management
    Memory management
    Network operations

FILE DESCRIPTORS:

    0 = stdin (standard input)
    1 = stdout (standard output)
    2 = stderr (standard error)

EXAMPLE FLOW:

When a userspace program calls printf(), the following happens:

    1. Program calls printf() in libc
    2. libc translates to write() syscall
    3. CPU switches from Ring 3 (user) to Ring 0 (kernel)
    4. Kernel validates parameters and permissions
    5. Kernel performs the actual write operation
    6. CPU switches back to Ring 3
    7. Control returns to userspace program

                USERSPACE              KERNEL
                ---------              ------
                
                printf()
                   |
                   v
                libc: write()
                   |
              [syscall trap] ---------> sys_write()
                   |                        |
                   |                        v
                   |                   validate args
                   |                        |
                   |                        v
                   |                   do actual write
                   |                        |
                   <--------- [return] -----+
                   |
                   v
                continue program

Each syscall has a unique number. The kernel maintains a syscall table that
maps these numbers to kernel functions. For example:

    sys_read    = 0
    sys_write   = 1
    sys_open    = 2
    sys_close   = 3

You can view the complete syscall table at:

    https://filippo.io/linux-syscall-table/
    https://www.ime.usp.br/~kon/MAC211/syscalls.html

Understanding syscalls is critical because rootkits work by INTERCEPTING these
calls and modifying their behavior before the kernel processes them.


----[ Types of Rootkits ]-----------------------------------------------------

# USERLAND ROOTKITS

LD_PRELOAD Method:

    Uses a shared object (.so) file
    Added to /etc/ld.so.preload
    Intercepts library calls before they reach libc
    Relatively simple to detect and remove

Advantages:

    Simpler to execute
    Generally cannot crash kernel (lower risk)
    No kernel headers required
    Works without kernel module support (LKM)

Disadvantages:

    Easier to detect (check /etc/ld.so.preload)
    Can be bypassed with static binaries
    Limited to process-level hiding
    Cannot hide from kernel-level inspection
    Ineffective against forensic tools

# LINUX KERNEL MODULES (LKM)

[ ! ]

----[ Anatomy of a Loadable Kernel Module ]-----------------------------------

A Loadable Kernel Module (LKM) is a kernel object (.ko file) that can be
dynamically loaded into the kernel at runtime without requiring a reboot.

CORE CONCEPTS:

Module Lifecycle:

    insmod loads the module into kernel memory
           |
           v
    module_init() function is called automatically
           |
           v
    Module registers hooks, allocates resources
           |
           v
    Module operates as part of the kernel
           |
           v
    rmmod signals module to unload
           |
           v
    module_exit() function is called automatically
           |
           v
    Module cleans up hooks and frees resources
           |
           v
    Module is removed from kernel memory

Required Headers:

    linux/init.h        Module initialization macros
    linux/module.h      Core module support
    linux/kernel.h      Kernel types and functions

Module Metadata:

    MODULE_LICENSE()        License type (GPL usually required)
    MODULE_AUTHOR()         Author information
    MODULE_DESCRIPTION()    Brief description of functionality
    MODULE_VERSION()        Version string

Entry and Exit Points:

    module_init(function)   Macro registering initialization function
    module_exit(function)   Macro registering cleanup function
    __init                  Marks code freed after initialization
    __exit                  Marks code only used during unload

Kernel Logging:

    printk() is the kernel equivalent of printf()
    Writes to kernel ring buffer (read with dmesg) 
    Uses log levels: KERN_INFO, KERN_ERR, KERN_DEBUG, etc.

KERNEL BUILD SYSTEM:

The kernel uses a build system (Kbuild) to ensure modules are compiled
with the same flags, configuration, and ABI as the running kernel.

Key Requirements:

    Must use kernel headers from /lib/modules/$(uname -r)/build
    Must compile with same GCC version as kernel
    Must match kernel configuration options
    Must respect kernel symbol versions

Why This Matters:

    Kernel checks module compatibility at load time
    Mismatched modules cause "Invalid module format" errors
    Wrong configuration causes "Unknown symbol" errors
    ABI mismatches can cause kernel panics


 _____ _   ___     _____ ____   ___  _   _ __  __ _____ _   _ _____ 
| ____| \ | \ \   / /_ _|  _ \ / _ \| \ | |  \/  | ____| \ | |_   _|
|  _| |  \| |\ \ / / | || |_) | | | |  \| | |\/| |  _| |  \| | | |  
| |___| |\  | \ V /  | ||  _ <| |_| | |\  | |  | | |___| |\  | | |  
|_____|_| \_|  \_/  |___|_| \_\\___/|_| \_|_|  |_|_____|_| \_| |_|  


----[ Development Environment Setup ]-----------------------------------------

REQUIRED PACKAGES:

For Debian/Ubuntu/Kali:

----[ terminal ]---
sudo apt update
sudo apt install build-essential linux-headers-$(uname -r)
-------------------

VERIFY INSTALLATION:

Check that kernel headers are installed:

----[ terminal ]---
ls -la /lib/modules/$(uname -r)/build
-------------------

You should see directories like: arch, drivers, include, scripts, etc.

Verify your kernel version matches available headers:

----[ terminal ]---
uname -r
6.1.0-kali9-amd64

ls /lib/modules/
6.1.0-kali9-amd64
-------------------

# TROUBLESHOOTING:

If headers are missing for your exact kernel:

----[ terminal ]---
# Debian/Ubuntu/Kali
sudo apt install linux-headers-amd64    # Install latest
apt search linux-headers                # Find available versions

# Check what's installed
dpkg -l | grep linux-headers
-------------------

If you get "Required key not available" when loading modules:

    Secure Boot is enabled
    Either disable Secure Boot in BIOS or sign your modules (have fun :D)
    For workshop purposes, disabling is easier

WORKSHOP DIRECTORY STRUCTURE:

Create organized workspace:

----[ terminal ]---
mkdir -p ~/rootkit_workshop/{userland,ftrace,kprobes,ebpf,helpers}
cd ~/rootkit_workshop
tree
-------------------

This gives you:

    rootkit_workshop/
    ├── userland/
    ├── ftrace/
    ├── kprobes/
    ├── ebpf/
    └── persistence/


----[ Building and Testing Kernel Modules ]-----------------------------------

COMPILATION PROCESS:

The kernel build system generates multiple files during compilation. Here's
what happens and what each file does:

Source Files (you create):

    module.c            Your source code
    Makefile            Build instructions [ optional ]

Generated Object Files:

    module.o            Compiled object from module.c
    module.mod.c        Auto-generated module metadata
    module.mod.o        Compiled metadata
    module.ko           Final kernel object [ WE LOAD THIS ]

Build Metadata:

    Module.symvers      Symbol version information
    modules.order       Build order for multiple modules
    .module.*.cmd       Hidden files with compilation commands
    .tmp_versions/      Temporary directory with version info

                    SOURCE CODE
                        |
                        v
                [Compilation Phase]
                        |
                        v
                    module.o
                        |
                        v
            [Metadata Generation]
                        |
                        v
                module.mod.c/o
                        |
                        v
                [Final Linking]
                        |
                        v
                    module.ko  <-- LOAD THIS
                        |
                        v
                [insmod module.ko]
                        |
                        v
                  KERNEL MEMORY

WHY SO MANY FILES?:

The kernel tracks symbol versions, dependencies, and compilation parameters
to ensure module compatibility. All files are necessary during build, but only
the .ko file is needed after compilation succeeds.

CAN WE AVOID THEM?:

No - the kernel build system requires these for compatibility checking. However,
after successful compilation you only need the .ko file. All others can be
deleted with a clean command.


COMPILATION METHODS:

# Method 1: Direct command [ single line ]

----[ terminal ]---
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
-------------------

# If you want to be fancy with your pinky up
# Method 2: Build script (reusable, accepts module name) 

----[ build.sh ]---

#!/bin/bash

MODULE="${1:-mymodule}"

echo "[*] Building ${MODULE}.ko"
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules

if [ -f "${MODULE}.ko" ]
then
    echo "[+] Success: ${MODULE}.ko"
    ls -lh "${MODULE}.ko"
else
    echo "[-] Build failed"
    exit 1
fi
-------------------

Usage:

----[ terminal ]---
chmod +x build.sh
./build.sh              # Builds mymodule.ko
./build.sh hello_kernel # Builds hello_kernel.ko
-------------------

MANUAL WORKFLOW

For manual control at each step (recommended for learning):

----[ terminal ]---
# Build
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules

# Load
sudo insmod mymodule.ko

# Verify loaded
lsmod | grep mymodule

# Check logs
sudo dmesg | tail -10

# Test functionality
# (depends on what your module does)

# Unload
sudo rmmod mymodule

# Check exit logs
sudo dmesg | tail -5

# Clean build artifacts
make -C /lib/modules/$(uname -r)/build M=$(pwd) clean
-------------------

  ____  ___  ____  _____   _______  __    _    __  __ ____  _     _____ ____ 
 / ___|/ _ \|  _ \| ____| | ____\ \/ /   / \  |  \/  |  _ \| |   | ____/ ___| 
| |   | | | | | | |  _|   |  _|  \  /   / _ \ | |\/| | |_) | |   |  _| \___ \ 
| |___| |_| | |_| | |___  | |___ /  \  / ___ \| |  | |  __/| |___| |___ ___) |
 \____|\___/|____/|_____| |_____/_/\_\/_/   \_\_|  |_|_|   |_____|_____|____/ 


----[ Example 1: Minimal Kernel Module ]--------------------------------------

This is the absolute minimum code needed for a working kernel module.

WHY THIS IS MINIMAL:

Every LKM requires exactly these components and nothing more:

    Three headers:
        linux/init.h     - For __init and __exit macros
        linux/module.h   - For module_init/module_exit
        linux/kernel.h   - For printk and KERN_* levels
        
    MODULE_LICENSE():
        Required by kernel
        GPL allows access to most kernel symbols
        Proprietary code gets limited access :D
        
    Two functions:
        Init function - Called when module loads
        Exit function - Called when module unloads
        Both can be empty but must exist
        
    Two macros:
        module_init() - Registers init function
        module_exit() - Registers exit function

Without any of these components, the module will fail to compile or load.
This is the bare minimum to have a functional LKM.

```C
----[ minimal.c ]---
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");

static int __init minimal_init(void)
{
    printk(KERN_INFO "Module loaded\n");
    return 0;
}

static void __exit minimal_exit(void)
{
    printk(KERN_INFO "Module unloaded\n");
}

module_init(minimal_init);
module_exit(minimal_exit);
```
-------------------

Compile and test:

----[ terminal ]---
# Build
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules

# Load
sudo insmod minimal.ko

# Verify
lsmod | grep minimal

# Check logs
sudo dmesg | tail -2

# Unload
sudo rmmod minimal

# Clean
make -C /lib/modules/$(uname -r)/build M=$(pwd) clean
-------------------


----[ Example 2: Module with Parameters ]-------------------------------------

This demonstrates passing parameters to control module behavior at load time.

WHY MODULE PARAMETERS WORK:

Module parameters are a kernel feature that allows passing configuration to
modules without recompiling. Here's how they work:

    Declaration:
        module_param(name, type, permissions)
        Creates a variable that can be set at load time
        
    The Mechanism:
        When you load with: insmod module.ko param=value 
        Kernel parses the command line arguments
        Before calling module_init(), kernel sets your variables
        Your init function sees the user-provided values
        
    Supported Types:
        int, uint, long, ulong   - Integer types
        bool                     - Boolean (0/1, true/false)
        charp                    - Character pointer (string)
        
    Permissions (octal):
        0000 - Not visible in sysfs [{ take note }]
        0444 - Read-only in /sys/module/name/parameters/
        0644 - Read-write in /sys/module/name/parameters/
        
    Runtime Access:
        After loading, parameters visible in:
        /sys/module/module_name/parameters/
        Can be changed at runtime if permissions allow

This is how rootkits can be configured without recompiling, making them more
flexible and reusable across different targets.

```C
----[ sysinfo_params.c ]---
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/utsname.h>
#include <linux/sched.h>
#include <linux/mm.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Workshop Attendee");
MODULE_DESCRIPTION("System info with configurable parameters");
MODULE_VERSION("1.0");

// Module parameters to control what info to display
static bool show_hostname = true;
static bool show_kernel = true;
static bool show_memory = true;
static bool show_process = true;
static bool show_uptime = true;
static bool verbose = false;

module_param(show_hostname, bool, 0644);
MODULE_PARM_DESC(show_hostname, "Display hostname");

module_param(show_kernel, bool, 0644);
MODULE_PARM_DESC(show_kernel, "Display kernel version");

module_param(show_memory, bool, 0644);
MODULE_PARM_DESC(show_memory, "Display memory information");

module_param(show_process, bool, 0644);
MODULE_PARM_DESC(show_process, "Display process information");

module_param(show_uptime, bool, 0644);
MODULE_PARM_DESC(show_uptime, "Display system uptime");

module_param(verbose, bool, 0644);
MODULE_PARM_DESC(verbose, "Enable verbose output");

static int __init sysinfo_init(void)
{
    struct new_utsname *uts;
    struct sysinfo si;
    
    printk(KERN_INFO "=====================================\n");
    printk(KERN_INFO "[sysinfo] System Information Module\n");
    printk(KERN_INFO "=====================================\n");
    
    if (verbose)
    {
        printk(KERN_INFO "[sysinfo] Verbose mode enabled\n");
        printk(KERN_INFO "[sysinfo] Parameters:\n");
        printk(KERN_INFO "[sysinfo]   show_hostname = %s\n", 
               show_hostname ? "true" : "false");
        printk(KERN_INFO "[sysinfo]   show_kernel = %s\n",
               show_kernel ? "true" : "false");
        printk(KERN_INFO "[sysinfo]   show_memory = %s\n",
               show_memory ? "true" : "false");
        printk(KERN_INFO "[sysinfo]   show_process = %s\n",
               show_process ? "true" : "false");
        printk(KERN_INFO "[sysinfo]   show_uptime = %s\n",
               show_uptime ? "true" : "false");
        printk(KERN_INFO "-------------------------------------\n");
    }
    
    // Get system name info
    uts = utsname();
    
    if (show_hostname)
    {
        printk(KERN_INFO "[sysinfo] Hostname: %s\n", uts->nodename);
        if (verbose)
        {
            printk(KERN_INFO "[sysinfo]   Domain: %s\n", uts->domainname);
        }
    }
    
    if (show_kernel)
    {
        printk(KERN_INFO "[sysinfo] Kernel: %s %s\n", 
               uts->sysname, uts->release);
        printk(KERN_INFO "[sysinfo] Architecture: %s\n", uts->machine);
        if (verbose)
        {
            printk(KERN_INFO "[sysinfo]   Version: %s\n", uts->version);
        }
    }
    
    if (show_process)
    {
        printk(KERN_INFO "[sysinfo] Loaded by: %s (PID: %d, UID: %d)\n",
               current->comm, current->pid, 
               from_kuid(&init_user_ns, current_uid()));
        
        if (verbose)
        {
            printk(KERN_INFO "[sysinfo]   Parent PID: %d\n", 
                   current->parent->pid);
            printk(KERN_INFO "[sysinfo]   GID: %d\n",
                   from_kgid(&init_user_ns, current_gid()));
        }
    }
    
    if (show_memory)
    {
        si_meminfo(&si);
        printk(KERN_INFO "[sysinfo] Total RAM: %lu MB\n", 
               (si.totalram * si.mem_unit) / (1024 * 1024));
        printk(KERN_INFO "[sysinfo] Free RAM: %lu MB\n",
               (si.freeram * si.mem_unit) / (1024 * 1024));
        
        if (verbose)
        {
            printk(KERN_INFO "[sysinfo]   Shared RAM: %lu MB\n",
                   (si.sharedram * si.mem_unit) / (1024 * 1024));
            printk(KERN_INFO "[sysinfo]   Buffer RAM: %lu MB\n",
                   (si.bufferram * si.mem_unit) / (1024 * 1024));
            printk(KERN_INFO "[sysinfo]   Total Swap: %lu MB\n",
                   (si.totalswap * si.mem_unit) / (1024 * 1024));
        }
    }
    
    if (show_uptime)
    {
        si_meminfo(&si);
        printk(KERN_INFO "[sysinfo] Uptime: %lu seconds (%lu days)\n",
               si.uptime, si.uptime / 86400);
    }
    
    printk(KERN_INFO "=====================================\n");
    printk(KERN_INFO "[sysinfo] Module loaded successfully\n");
    printk(KERN_INFO "=====================================\n");
    
    return 0;
}

static void __exit sysinfo_exit(void)
{
    printk(KERN_INFO "[sysinfo] Module unloaded\n");
}

module_init(sysinfo_init);
module_exit(sysinfo_exit);
```
-------------------

Build and test with different parameter combinations:

----[ terminal ]---
# Build
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules

# Load with defaults (all info shown)
sudo insmod sysinfo_params.ko
sudo dmesg | tail -15
sudo rmmod sysinfo_params

# Load with only hostname and kernel info
sudo insmod sysinfo_params.ko show_memory=0 show_process=0 show_uptime=0
sudo dmesg | tail -10
sudo rmmod sysinfo_params

# Load with verbose mode
sudo insmod sysinfo_params.ko verbose=1
sudo dmesg | tail -20
sudo rmmod sysinfo_params

# Load showing only memory info
sudo insmod sysinfo_params.ko show_hostname=0 show_kernel=0 show_process=0 show_uptime=0
sudo dmesg | tail -8

# Check parameter values in sysfs
cat /sys/module/sysinfo_params/parameters/show_memory
cat /sys/module/sysinfo_params/parameters/verbose

# Change parameter at runtime (if permissions allow)
echo 1 > /sys/module/sysinfo_params/parameters/verbose

# Unload
sudo rmmod sysinfo_params
-------------------

Expected output with all parameters enabled:

----[ dmesg ]---
[sysinfo] System Information Module
[sysinfo] Verbose mode enabled
[sysinfo] Parameters:
[sysinfo]   show_hostname = true
[sysinfo]   show_kernel = true
[sysinfo]   show_memory = true
[sysinfo]   show_process = true
[sysinfo]   show_uptime = true
[sysinfo] Hostname: workshop-vm
[sysinfo]   Domain: localdomain
[sysinfo] Kernel: Linux 6.1.0-kali9-amd64
[sysinfo] Architecture: x86_64
[sysinfo]   Version: #1 SMP PREEMPT_DYNAMIC Debian 6.1.27-1kali1
[sysinfo] Loaded by: insmod (PID: 1234, UID: 0)
[sysinfo]   Parent PID: 1200
[sysinfo]   GID: 0
[sysinfo] Total RAM: 4096 MB
[sysinfo] Free RAM: 2048 MB
[sysinfo]   Shared RAM: 256 MB
[sysinfo]   Buffer RAM: 128 MB
[sysinfo]   Total Swap: 2048 MB
[sysinfo] Uptime: 3600 seconds (0 days)
[sysinfo] Module loaded successfully
-------------------


----[ Example 3: Interactive /proc Interface ]--------------------------------

This module creates a /proc file that userspace can read from and write to,
demonstrating kernel-userspace communication.

WHY THIS WORKS:

The proc filesystem is a virtual filesystem that provides an interface between
kernel and userspace. When we create a /proc entry:

    1. We register file operations (read/write handlers)
    2. Userspace opens /proc/our_file like a normal file
    3. Read/write calls trigger our kernel functions
    4. We can pass data back and forth
    5. No real file exists - all in memory

This is how many kernel modules communicate with userspace tools, and how
rootkits can be controlled without loading new modules.

----[ proc_interface.c ]---
```C
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Workshop Attendee");
MODULE_DESCRIPTION("Interactive /proc interface");

#define PROC_NAME "rootkit_control"
#define BUFFER_SIZE 1024

static struct proc_dir_entry *proc_entry;
static char *kernel_buffer;
static size_t buffer_len = 0;

// Called when userspace reads from /proc/rootkit_control
static ssize_t proc_read(struct file *file, char __user *user_buffer,
                        size_t count, loff_t *offset)
{
    size_t len = buffer_len;
    
    // Check if we've already sent data
    if (*offset > 0 || count < len)
    {
        return 0;
    }
    
    // Copy data to userspace
    if (copy_to_user(user_buffer, kernel_buffer, len))
    {
        return -EFAULT;
    }
    
    *offset = len;
    
    printk(KERN_INFO "[proc_interface] Read %zu bytes from /proc/%s\n", 
           len, PROC_NAME);
    
    return len;
}

// Called when userspace writes to /proc/rootkit_control
static ssize_t proc_write(struct file *file, const char __user *user_buffer,
                         size_t count, loff_t *offset)
{
    size_t len = count;
    
    if (len > BUFFER_SIZE - 1)
    {
        len = BUFFER_SIZE - 1;
    }
    
    // Clear buffer
    memset(kernel_buffer, 0, BUFFER_SIZE);
    
    // Copy data from userspace
    if (copy_from_user(kernel_buffer, user_buffer, len))
    {
        return -EFAULT;
    }
    
    kernel_buffer[len] = '\0';
    buffer_len = len;
    
    printk(KERN_INFO "[proc_interface] Received command: %s\n", kernel_buffer);
    
    // Parse commands
    if (strncmp(kernel_buffer, "status", 6) == 0)
    {
        printk(KERN_INFO "[proc_interface] Status: Active\n");
        snprintf(kernel_buffer, BUFFER_SIZE, "Rootkit Status: Active\n");
        buffer_len = strlen(kernel_buffer);
    }
    else if (strncmp(kernel_buffer, "hide", 4) == 0)
    {
        printk(KERN_INFO "[proc_interface] Hide command received\n");
        snprintf(kernel_buffer, BUFFER_SIZE, "Hiding activated\n");
        buffer_len = strlen(kernel_buffer);
    }
    else if (strncmp(kernel_buffer, "show", 4) == 0)
    {
        printk(KERN_INFO "[proc_interface] Show command received\n");
        snprintf(kernel_buffer, BUFFER_SIZE, "Showing activated\n");
        buffer_len = strlen(kernel_buffer);
    }
    else
    {
        snprintf(kernel_buffer, BUFFER_SIZE, 
                "Unknown command. Try: status, hide, show\n");
        buffer_len = strlen(kernel_buffer);
    }
    
    return len;
}

// File operations structure
static const struct proc_ops proc_fops =
{
    .proc_read = proc_read,
    .proc_write = proc_write,
};

static int __init proc_interface_init(void)
{
    printk(KERN_INFO "[proc_interface] Creating /proc/%s\n", PROC_NAME);
    
    // Allocate buffer
    kernel_buffer = kmalloc(BUFFER_SIZE, GFP_KERNEL);
    if (!kernel_buffer)
    {
        printk(KERN_ERR "[proc_interface] Failed to allocate buffer\n");
        return -ENOMEM;
    }
    
    // Initialize buffer with default message
    snprintf(kernel_buffer, BUFFER_SIZE, 
            "Rootkit control interface\nCommands: status, hide, show\n");
    buffer_len = strlen(kernel_buffer);
    
    // Create /proc entry
    proc_entry = proc_create(PROC_NAME, 0666, NULL, &proc_fops);
    if (!proc_entry)
    {
        printk(KERN_ERR "[proc_interface] Failed to create /proc entry\n");
        kfree(kernel_buffer);
        return -ENOMEM;
    }
    
    printk(KERN_INFO "[proc_interface] Module loaded\n");
    printk(KERN_INFO "[proc_interface] Read: cat /proc/%s\n", PROC_NAME);
    printk(KERN_INFO "[proc_interface] Write: echo 'command' > /proc/%s\n", 
           PROC_NAME);
    
    return 0;
}

static void __exit proc_interface_exit(void)
{
    // Remove /proc entry
    proc_remove(proc_entry);
    
    // Free buffer
    kfree(kernel_buffer);
    
    printk(KERN_INFO "[proc_interface] Module unloaded\n");
}

module_init(proc_interface_init);
module_exit(proc_interface_exit);
```
-------------------

Build and test:

----[ terminal ]---
# Build
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules

# Load module
sudo insmod proc_interface.ko

# Check that /proc entry was created
ls -la /proc/rootkit_control

# Read default message
cat /proc/rootkit_control

# Send commands
echo "status" > /proc/rootkit_control
cat /proc/rootkit_control

echo "hide" > /proc/rootkit_control
cat /proc/rootkit_control

echo "show" > /proc/rootkit_control
cat /proc/rootkit_control

# Try invalid command
echo "invalid" > /proc/rootkit_control
cat /proc/rootkit_control

# Check kernel logs
sudo dmesg | grep proc_interface | tail -10

# Unload module
sudo rmmod proc_interface

# Verify /proc entry removed
ls -la /proc/rootkit_control  # Should not exist
-------------------

Expected interaction:

----[ terminal ]---
$ cat /proc/rootkit_control
Rootkit control interface
Commands: status, hide, show

$ echo "status" > /proc/rootkit_control
$ cat /proc/rootkit_control
Rootkit Status: Active

$ echo "hide" > /proc/rootkit_control
$ cat /proc/rootkit_control
Hiding activated
-------------------

HOW IT WORKS:

The proc filesystem provides a bridge between kernel and userspace:

    Registration:
        proc_create() creates virtual file in /proc
        Assigns our read/write handlers
        Sets permissions (0666 = world readable/writable)
        
    Read Operation:
        User runs: cat /proc/rootkit_control
        Kernel calls our proc_read() function
        We copy data from kernel buffer to userspace
        User sees the output
        
    Write Operation:
        User runs: echo "command" > /proc/rootkit_control
        Kernel calls our proc_write() function
        We copy data from userspace to kernel buffer
        We parse command and take action
        We prepare response for next read
        
    Memory Management:
        kmalloc() allocates kernel memory
        copy_to_user() / copy_from_user() for safe copying
        kfree() releases memory on unload
        
    Cleanup:
        proc_remove() removes /proc entry
        All resources freed
        File disappears from /proc

This technique is commonly used by rootkits to:
    - Accept commands without loading new modules
    - Toggle hiding on/off
    - Change configuration at runtime
    - Report status to attacker tools
    - Receive target PIDs or filenames to hide



 ____  _   _ __  __ __  __    _    ______   __
/ ___|| | | |  \/  |  \/  |  / \  |  _ \ \ / /
\___ \| | | | |\/| | |\/| | / _ \ | |_) \ V / 
 ___) | |_| | |  | | |  | |/ ___ \|  _ < | |  
|____/ \___/|_|  |_|_|  |_/_/   \_\_| \_\|_|  


----[ Foundations Summary ]----------------------------------------------------

CONCEPTS COVERED:

    The Linux rootkit landscape (userland vs kernel)
    Memory isolation between user space and kernel space 
    System calls as the interface between worlds 
    Types of rootkits and their tradeoffs
    Structure and lifecycle of Loadable Kernel Modules
    The kernel build system and why it's complex

PRACTICAL SKILLS:

    Setting up a kernel development environment
    Compiling kernel modules with the build system
    Loading and unloading modules with insmod/rmmod
    Viewing kernel logs with dmesg
    Understanding build artifacts and cleanup
    Using scripts to streamline the workflow

BUILD ARTIFACTS RECAP:

After compilation you'll have many files, but only .ko is needed to load.
The others are build metadata that ensure kernel compatibility. Clean them
up with a cleanup script or the kernel's clean target.

YOU ARE NOW READY:

    [✓] Your environment is configured
    [✓] You understand the kernel module lifecycle
    [✓] You can build, load, test, and unload modules
    [✓] You know how to debug with printk and dmesg

Next we'll explore how rootkits use these fundamentals to intercept system
calls and modify kernel behavior in userland and kernel space.

            ▐             
            ▜▀ ▞▀▖▛▀▖▞▀▌▌ ▌
            ▐ ▖▛▀ ▌ ▌▚▄▌▌ ▌
             ▀ ▝▀▘▘ ▘▗▄▘▝▀▘
                      
                   ONWARDS TO
                 PART II: USERLAND
                    ROOTKITS

.EOF



# Notes for edit
    Compiler for kernel objects from C code
    printk's required?
