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