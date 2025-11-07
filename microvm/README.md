# Reticulum-Go MicroVM

Minimal Firecracker microVM setup for running Reticulum-Go.

## Prerequisites

- Firecracker binary installed
- Go compiler
- Root privileges (for network setup and KVM access)
- Linux host system with KVM support
- Access to `/dev/kvm`

## Important: Nested Virtualization

**If running inside a QEMU/KVM VM**, nested virtualization must be enabled:

1. **Host QEMU configuration**: Start your QEMU VM with nested KVM:
   ```bash
   qemu-system-x86_64 -cpu host -enable-kvm -machine q35,accel=kvm ...
   ```

2. **Enable nested KVM on host** (if not already):
   ```bash
   # Check if nested is enabled
   cat /sys/module/kvm_intel/parameters/nested  # Intel
   cat /sys/module/kvm_amd/parameters/nested    # AMD
   
   # Enable nested (Intel)
   echo "options kvm_intel nested=1" | sudo tee /etc/modprobe.d/kvm.conf
   
   # Enable nested (AMD)
   echo "options kvm_amd nested=1" | sudo tee /etc/modprobe.d/kvm.conf
   
   # Reboot host
   ```

3. **Inside the VM**, check if `/dev/kvm` exists:
   ```bash
   ls -l /dev/kvm
   ```

**Alternative**: If nested virtualization isn't available, consider:
- Running Firecracker directly on the host machine
- Using QEMU directly instead of Firecracker
- Using Docker/LXC containers instead

## KVM Setup

Ensure your user has access to `/dev/kvm`:

```bash
# Check if /dev/kvm exists
ls -l /dev/kvm

# Add your user to the kvm group (recommended)
sudo usermod -aG kvm $USER

# Or set ACL (alternative)
sudo setfacl -m u:$USER:rw /dev/kvm

# Log out and back in for group changes to take effect
```

## Setup

Run the setup script:

```bash
./setup.sh
```

This will:
- Check for Firecracker installation
- Download vmlinux.bin kernel
- Build Reticulum-Go binary
- Create rootfs.ext4 disk image
- Generate firecracker-config.json

## Running

1. Create tap interface:
```bash
sudo ip tuntap add tap0 mode tap
sudo ip addr add 172.16.0.1/24 dev tap0
sudo ip link set tap0 up
```

2. Enable IP forwarding:
```bash
sudo sysctl -w net.ipv4.ip_forward=1
```

3. Start Firecracker:
```bash
# Clean up any old socket files first
rm -f /tmp/firecracker.sock microvm/vsock.sock

firecracker --api-sock /tmp/firecracker.sock --config-file firecracker-config.json
```

4. Connect to console (in another terminal):
```bash
firecracker --api-sock /tmp/firecracker.sock
```

## Configuration

- **CPU**: 1 vCPU
- **Memory**: 128 MiB
- **Network**: tap0 interface
- **Disk**: rootfs.ext4 (100MB)

Modify `firecracker-config.json` to adjust resources.

## Files

- `vmlinux.bin` - Linux kernel
- `rootfs.ext4` - Root filesystem with binary
- `firecracker-config.json` - Firecracker configuration
- `reticulum-go` - Compiled binary

