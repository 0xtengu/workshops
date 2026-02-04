#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Demo");
MODULE_DESCRIPTION("Persistence Test Payload");

static int __init chaos_init(void) {
    // KERN_ALERT ensures it prints to the console even if logging level is low
    printk(KERN_ALERT "========================================\n");
    printk(KERN_ALERT "[+] PERSISTENCE SUCCESSFUL: Chaos Loaded\n");
    printk(KERN_ALERT "========================================\n");
    return 0;
}

static void __exit chaos_exit(void) {
    printk(KERN_INFO "[-] Chaos Unloaded\n");
}

module_init(chaos_init);
module_exit(chaos_exit);