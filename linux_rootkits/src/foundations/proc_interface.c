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
