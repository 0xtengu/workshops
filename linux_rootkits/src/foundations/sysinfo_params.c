#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/utsname.h>
#include <linux/sched.h>
#include <linux/mm.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0xtengu");
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
