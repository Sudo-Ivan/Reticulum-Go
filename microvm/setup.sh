#!/bin/sh
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MICROVM_DIR="$SCRIPT_DIR"
BINARY_NAME="reticulum-go"
FIRECRACKER_VERSION="v1.8.0"
FIRECRACKER_REPO="firecracker-microvm/firecracker"
VMLINUX_URL="https://s3.amazonaws.com/spec.ccfc.min/img/hello/kernel/hello-vmlinux.bin"

check_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Error: $1 is not installed" >&2
        exit 1
    fi
}

check_firecracker() {
    if ! command -v firecracker >/dev/null 2>&1; then
        echo "Error: firecracker binary is not installed" >&2
        echo "Install from: https://github.com/firecracker-microvm/firecracker/releases" >&2
        exit 1
    fi
    echo "Firecracker found: $(firecracker --version 2>&1 || echo 'version check failed')"
}

download_vmlinux() {
    VMLINUX_PATH="$MICROVM_DIR/vmlinux.bin"
    if [ -f "$VMLINUX_PATH" ]; then
        echo "vmlinux.bin already exists, skipping download"
        return
    fi
    
    echo "Downloading vmlinux.bin from AWS S3..."
    if ! command -v curl >/dev/null 2>&1; then
        echo "Error: curl required to download vmlinux.bin" >&2
        exit 1
    fi
    
    curl -fsSL -o "$VMLINUX_PATH" "$VMLINUX_URL"
    chmod +x "$VMLINUX_PATH"
    echo "Downloaded: $VMLINUX_PATH"
}

build_binary() {
    echo "Building binary..."
    cd "$PROJECT_ROOT"
    GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o "$MICROVM_DIR/$BINARY_NAME" ./cmd/reticulum-go
    echo "Binary built: $MICROVM_DIR/$BINARY_NAME"
}

create_rootfs() {
    ROOTFS_PATH="$MICROVM_DIR/rootfs.ext4"
    if [ -f "$ROOTFS_PATH" ]; then
        echo "rootfs.ext4 already exists, skipping creation"
        return
    fi
    
    echo "Creating rootfs..."
    TMP_DIR=$(mktemp -d)
    trap "rm -rf $TMP_DIR" EXIT
    
    mkdir -p "$TMP_DIR/bin" "$TMP_DIR/etc" "$TMP_DIR/dev" "$TMP_DIR/proc" "$TMP_DIR/sys" "$TMP_DIR/tmp"
    
    cp "$MICROVM_DIR/$BINARY_NAME" "$TMP_DIR/bin/"
    chmod +x "$TMP_DIR/bin/$BINARY_NAME"
    
    cat > "$TMP_DIR/etc/inittab" <<EOF
::sysinit:/bin/sh /etc/rc
::respawn:/bin/sh
ttyS0::respawn:/bin/sh
EOF
    
    cat > "$TMP_DIR/etc/rc" <<EOF
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
/bin/$BINARY_NAME
EOF
    chmod +x "$TMP_DIR/etc/rc"
    
    ROOTFS_SIZE_MB=100
    dd if=/dev/zero of="$ROOTFS_PATH" bs=1M count="$ROOTFS_SIZE_MB" 2>/dev/null
    mkfs.ext4 -F "$ROOTFS_PATH" >/dev/null 2>&1
    
    TMP_MOUNT=$(mktemp -d)
    mount -o loop "$ROOTFS_PATH" "$TMP_MOUNT" 2>/dev/null || {
        echo "Error: Failed to mount rootfs. You may need root privileges or use a different method." >&2
        rm -rf "$TMP_DIR" "$TMP_MOUNT"
        exit 1
    }
    trap "umount $TMP_MOUNT 2>/dev/null; rm -rf $TMP_DIR $TMP_MOUNT" EXIT
    
    cp -r "$TMP_DIR"/* "$TMP_MOUNT/"
    umount "$TMP_MOUNT"
    rm -rf "$TMP_DIR" "$TMP_MOUNT"
    echo "Rootfs created: $ROOTFS_PATH"
}

create_config() {
    CONFIG_PATH="$MICROVM_DIR/firecracker-config.json"
    API_SOCK="${API_SOCK:-/tmp/firecracker.sock}"
    VSOCK_SOCK="${VSOCK_SOCK:-$MICROVM_DIR/vsock.sock}"
    
    cat > "$CONFIG_PATH" <<EOF
{
  "boot-source": {
    "kernel_image_path": "$MICROVM_DIR/vmlinux.bin",
    "boot_args": "console=ttyS0 reboot=k panic=1 pci=off root=/dev/vda rw"
  },
  "drives": [
    {
      "drive_id": "rootfs",
      "path_on_host": "$MICROVM_DIR/rootfs.ext4",
      "is_root_device": true,
      "is_read_only": false
    }
  ],
  "machine-config": {
    "vcpu_count": 1,
    "mem_size_mib": 128,
    "smt": false
  },
  "network-interfaces": [
    {
      "iface_id": "eth0",
      "guest_mac": "AA:FC:00:00:00:01",
      "host_dev_name": "tap0"
    }
  ],
  "vsock": {
    "guest_cid": 3,
    "uds_path": "$VSOCK_SOCK"
  }
}
EOF
    echo "Config created: $CONFIG_PATH"
    echo "API socket: $API_SOCK"
    echo "VSock socket: $VSOCK_SOCK"
}

check_firecracker() {
    if ! command -v firecracker >/dev/null 2>&1; then
        echo "Error: firecracker binary is not installed" >&2
        echo "Install from: https://github.com/firecracker-microvm/firecracker/releases" >&2
        exit 1
    fi
    echo "Firecracker found: $(firecracker --version 2>&1 || echo 'version check failed')"
}

check_kvm() {
    if [ ! -c /dev/kvm ]; then
        echo "Warning: /dev/kvm not found. KVM may not be available." >&2
        return
    fi
    
    if [ ! -r /dev/kvm ] || [ ! -w /dev/kvm ]; then
        echo "Warning: /dev/kvm exists but you may not have read/write access." >&2
        echo "Add yourself to the kvm group: sudo usermod -aG kvm $USER" >&2
        echo "Or set ACL: sudo setfacl -m u:$USER:rw /dev/kvm" >&2
    else
        echo "KVM access OK"
    fi
}

cleanup_sockets() {
    echo "Cleaning up old socket files..."
    rm -f /tmp/firecracker.sock "$MICROVM_DIR/vsock.sock"
    echo "Cleanup complete"
}

main() {
    echo "Setting up microVM..."
    
    cleanup_sockets
    
    check_command go
    check_firecracker
    check_kvm
    
    download_vmlinux
    build_binary
    create_rootfs
    create_config
    
    echo ""
    echo "Setup complete!"
    echo "Files created in: $MICROVM_DIR"
    echo ""
    echo "To run the microVM:"
    echo "  1. Ensure KVM access: sudo usermod -aG kvm $USER (then logout/login)"
    echo "  2. Create tap interface: sudo ip tuntap add tap0 mode tap"
    echo "  3. Start firecracker: firecracker --api-sock /tmp/firecracker.sock --config-file $CONFIG_PATH"
}

main "$@"

