#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---
# !! IMPORTANT: Verify TARGET_DISK is correct for your server !!
TARGET_DISK="/dev/sda"

# Partition Sizes (MB)
BOOT_SIZE_MB=1024
SWAP_SIZE_MB=8192
VAR_SIZE_MB=40960 # 40 GiB

# User Configuration
USERNAME="DAN"
# Check if password argument is provided
if [ -z "$1" ]; then
  echo "Usage: $0 <password>"
  echo "Error: Password argument missing."
  exit 1
fi
USER_PASSWORD="$1" # Password is taken from the first command-line argument
ROOT_PASSWORD="$1" # Use the same password for root

# Network Configuration (Static IP)
# !! IMPORTANT: Adjust these network settings for your environment !!
STATIC_IP="192.168.1.68"
GATEWAY="192.168.1.254"
DNS="8.8.8.8,8.8.4.4" # You can add more DNS servers separated by commas, e.g., "8.8.8.8,1.1.1.1"
HOSTNAME="nymph.idragonfly.net"

# Mount point for the target system
TARGET_MOUNT_POINT="/mnt/target"
# --- End Configuration ---

echo "Starting Rocky Linux Installation Script"
echo "======================================="
echo "Target Disk:       ${TARGET_DISK}"
echo "Username:          ${USERNAME}"
echo "Static IP:         ${STATIC_IP}"
echo "Hostname:          ${HOSTNAME}"
echo "Partition Scheme:  MBR (Legacy BIOS)"
echo ""
echo "WARNING: ALL DATA ON ${TARGET_DISK} WILL BE ERASED!"
read -p "Press Enter to continue, or Ctrl+C to abort..."

# === Disk Preparation ===

echo "Preparing target disk: ${TARGET_DISK}"

# Verify the disk size (Example: Check if between 200GiB and 240GiB)
echo "Verifying disk size..."
DISK_BYTES=$(sudo lsblk -b -n -d -o SIZE "${TARGET_DISK}")
MIN_BYTES=$((60 * 1024**3)) # 60 GiB
MAX_BYTES=$((2000 * 1024**3)) # 2 TB

if [ -z "${DISK_BYTES}" ]; then
    echo "Error: Could not determine size of ${TARGET_DISK}. Aborting."
    exit 1
fi

if [ "${DISK_BYTES}" -lt "${MIN_BYTES}" ] || [ "${DISK_BYTES}" -gt "${MAX_BYTES}" ]; then
    # Convert bytes to GiB for a friendlier message
    DISK_GIB=$(awk -v bytes="${DISK_BYTES}" 'BEGIN {printf "%.2f", bytes / (1024**3)}')
    MIN_GIB=$(awk -v bytes="${MIN_BYTES}" 'BEGIN {printf "%.0f", bytes / (1024**3)}')
    MAX_GIB=$(awk -v bytes="${MAX_BYTES}" 'BEGIN {printf "%.0f", bytes / (1024**3)}')
    echo "Error: Disk size (${DISK_GIB} GiB) is outside the expected range (${MIN_GIB}GiB-${MAX_GIB}GiB). Aborting."
    exit 1
fi
echo "Disk size verification passed."

# Wipe existing signatures (optional but recommended for clean slate)
echo "Wiping existing filesystem signatures from ${TARGET_DISK}..."
sudo wipefs -a "${TARGET_DISK}"

# Partitioning for MBR (Legacy BIOS)
# NOTE: For UEFI/GPT, you would use 'mklabel gpt' and create an EFI System Partition (ESP).
echo "Partitioning ${TARGET_DISK} with MBR layout..."
sudo parted -s "${TARGET_DISK}" mklabel msdos

# Create partitions using parted (adjust sizes as needed)
echo "Creating partitions..."
BOOT_END_MB=$((BOOT_SIZE_MB))
SWAP_END_MB=$((BOOT_END_MB + SWAP_SIZE_MB))
VAR_END_MB=$((SWAP_END_MB + VAR_SIZE_MB))

# /boot partition
sudo parted -s "${TARGET_DISK}" mkpart primary ext4 1MiB ${BOOT_END_MB}MiB # Start at 1MiB for alignment
sudo parted -s "${TARGET_DISK}" set 1 boot on
# Swap partition
sudo parted -s "${TARGET_DISK}" mkpart primary linux-swap ${BOOT_END_MB}MiB ${SWAP_END_MB}MiB
# /var partition
sudo parted -s "${TARGET_DISK}" mkpart primary ext4 ${SWAP_END_MB}MiB ${VAR_END_MB}MiB
# / (root) partition (using remaining space)
sudo parted -s "${TARGET_DISK}" mkpart primary ext4 ${VAR_END_MB}MiB 100%

# Ensure kernel recognizes new partitions
echo "Waiting for kernel to recognize new partitions..."
sudo partprobe "${TARGET_DISK}"
sleep 2 # Brief pause for safety

# Define partition device names (predictable after partprobe for /dev/sdX)
BOOT_PARTITION="${TARGET_DISK}1"
SWAP_PARTITION="${TARGET_DISK}2"
VAR_PARTITION="${TARGET_DISK}3"
ROOT_PARTITION="${TARGET_DISK}4"

echo "Formatting partitions..."
sudo mkfs.ext4 -F -L boot "${BOOT_PARTITION}"
sudo mkswap -L swap "${SWAP_PARTITION}"
sudo mkfs.ext4 -F -L var "${VAR_PARTITION}"
sudo mkfs.ext4 -F -L root "${ROOT_PARTITION}"

# === Mount Filesystems ===

echo "Mounting filesystems..."
sudo mkdir -p "${TARGET_MOUNT_POINT}"
sudo mount "${ROOT_PARTITION}" "${TARGET_MOUNT_POINT}"

sudo mkdir -p "${TARGET_MOUNT_POINT}/boot"
sudo mount "${BOOT_PARTITION}" "${TARGET_MOUNT_POINT}/boot"

sudo mkdir -p "${TARGET_MOUNT_POINT}/var"
sudo mount "${VAR_PARTITION}" "${TARGET_MOUNT_POINT}/var"

# NOTE: For UEFI/GPT, you would create and mount the ESP here:
# sudo mkdir -p "${TARGET_MOUNT_POINT}/boot/efi"
# sudo mount /dev/sdXN "${TARGET_MOUNT_POINT}/boot/efi" # Replace /dev/sdXN with your ESP partition

sudo swapon "${SWAP_PARTITION}"

# Mount necessary virtual filesystems for chroot
echo "Mounting virtual filesystems..."
sudo mkdir -p "${TARGET_MOUNT_POINT}/dev"
sudo mkdir -p "${TARGET_MOUNT_POINT}/proc"
sudo mkdir -p "${TARGET_MOUNT_POINT}/sys"

sudo mount --bind /dev "${TARGET_MOUNT_POINT}/dev"
sudo mount --bind /proc "${TARGET_MOUNT_POINT}/proc"
sudo mount --bind /sys "${TARGET_MOUNT_POINT}/sys"

# === Network Configuration (Live Env -> Target Env) ===

echo "Detecting active network interface..."
# Attempt to find the interface associated with the default route
LIVE_INTERFACE=$(ip route get 1.1.1.1 | grep -oP 'dev \K\S+' || true) # || true prevents script exit if no default route

if [ -z "${LIVE_INTERFACE}" ]; then
    # Fallback: Try getting the first active connection device from NetworkManager
    echo "Default route method failed, trying NetworkManager..."
    LIVE_INTERFACE=$(nmcli -g DEVICE connection show --active | head -n 1 || true)
fi

if [ -z "${LIVE_INTERFACE}" ]; then
    echo "--------------------------------------------------------------------"
    echo "ERROR: Could not automatically determine the active network interface."
    echo "Please identify your primary network interface manually (e.g., eth0, enp3s0)."
    ip link show
    read -p "Enter the name of the network interface to configure: " INTERFACE_NAME
    if [ -z "${INTERFACE_NAME}" ]; then
        echo "No interface provided. Aborting."
        # Consider unmounting filesystems here before exiting
        exit 1
    fi
else
    echo "Detected active interface: ${LIVE_INTERFACE}"
    INTERFACE_NAME="${LIVE_INTERFACE}"
fi
echo "Using interface '${INTERFACE_NAME}' for configuration."

# === Chroot and System Installation ===

echo "Chrooting into ${TARGET_MOUNT_POINT} and installing system..."

# Export variables needed inside chroot
export USERNAME USER_PASSWORD ROOT_PASSWORD STATIC_IP GATEWAY DNS HOSTNAME INTERFACE_NAME TARGET_DISK

sudo chroot "${TARGET_MOUNT_POINT}" /bin/bash -c '
    set -e

    echo "--- Inside Chroot ---"

    # Enable standard Rocky Linux repositories
    echo "Enabling standard repositories..."
    dnf config-manager --set-enabled baseos appstream

    # Enable CRB and EPEL repositories
    echo "Enabling CRB and EPEL repositories..."
    dnf config-manager --set-enabled crb
    dnf -y install epel-release # Installs EPEL repo config

    # Ensure necessary dirs exist before install (some packages might expect them)
    mkdir -p /etc/sysconfig/network-scripts # Though less used with NM, some tools might expect it
    mkdir -p /etc/NetworkManager/system-connections
    mkdir -p /boot/grub2 # For MBR grub config

    # Install base system, kernel, server tools, utilities
    echo "Installing core packages, tools, and services..."
    dnf -y install \
        kernel \
        grub2 \
        os-prober \
        dnf-utils \
        NetworkManager \
        NetworkManager-tui \
        nm-connection-editor \
        firewalld \
        sudo \
        selinux-policy \
        selinux-policy-targeted \
        policycoreutils \
        chrony \
        podman \
        container-selinux \
        skopeo \
        buildah \
        runc \
        qemu-kvm \
        libvirt \
        libvirt-daemon-kvm \
        virt-install \
        virt-manager \
        cockpit \
        tmux \
        nano \
        net-tools \
        bash-completion \
        rsync \
        wget \
        curl

    # NOTE: For UEFI/GPT, install grub2-efi-x64 and shim-x64 instead of/in addition to grub2
    dnf -y install grub2-efi-x64 shim-x64

    # Configure timezone
    echo "Setting timezone to America/Chicago..."
    timedatectl set-timezone America/Chicago

    # Configure locale
    echo "Setting locale to en_US.UTF-8..."
    localectl set-locale LANG=en_US.UTF-8

    # Configure NetworkManager for static IP
    echo "Configuring static network for interface ${INTERFACE_NAME}..."
    cat > /etc/NetworkManager/system-connections/static-${INTERFACE_NAME}.nmconnection <<EOL
[connection]
id=static-${INTERFACE_NAME}
uuid=$(uuidgen) # Generate a unique UUID
type=ethernet
interface-name=${INTERFACE_NAME}
autoconnect=true

[ethernet]

[ipv4]
method=manual
addresses=${STATIC_IP}/24 # Assuming /24 subnet mask, adjust if needed
gateway=${GATEWAY}
dns=${DNS}

[ipv6]
method=auto # Or disabled, ignore, manual as needed
EOL
    chmod 600 /etc/NetworkManager/system-connections/static-${INTERFACE_NAME}.nmconnection
    echo "Network configuration created for ${INTERFACE_NAME}."

    # Set hostname
    echo "Setting hostname to ${HOSTNAME}..."
    echo "${HOSTNAME}" > /etc/hostname
    # hostnamectl set-hostname "${HOSTNAME}" # Alternative command

    # Add user
    echo "Adding user: ${USERNAME}"
    useradd -m -s /bin/bash "${USERNAME}"

    # Set user password (using chpasswd for scripting)
    echo "Setting password for user: ${USERNAME}"
    echo "${USERNAME}:${USER_PASSWORD}" | chpasswd

    # Set root password
    echo "Setting root password..."
    echo "root:${ROOT_PASSWORD}" | chpasswd

    # Grant administrator privileges (add to wheel group for sudo)
    echo "Adding user ${USERNAME} to wheel group for sudo access"
    usermod -aG wheel "${USERNAME}"

    # Enable core services
    echo "Enabling essential services..."
    systemctl enable NetworkManager.service
    systemctl enable firewalld.service
    systemctl enable chronyd.service # Time synchronization
    systemctl enable cockpit.socket # Web console
    systemctl enable libvirtd.service # Virtualization daemon
    systemctl enable podman.socket # For rootless podman API (optional)

    # Configure Firewall (Open SSH, Cockpit)
    echo "Configuring firewall..."
    # Note: firewalld should already be started if installed and enabled correctly
    # but running firewall-cmd ensures rules are applied if it is running.
    firewall-cmd --permanent --add-service=ssh
    firewall-cmd --permanent --add-service=cockpit
    # Add other ports/services as needed
    firewall-cmd --permanent --add-port=80/tcp
    firewall-cmd --permanent --add-port=443/tcp
    firewall-cmd --reload # Apply permanent rules

    # Install GRUB Bootloader for MBR/BIOS
    # NOTE: TARGET_DISK is inherited from the exported environment variable
    echo "Installing GRUB bootloader for MBR on ${TARGET_DISK}..."
    grub2-install "${TARGET_DISK}" # Installs to the MBR of the specified disk

    # Generate GRUB configuration file
    echo "Generating GRUB configuration..."
    grub2-mkconfig -o /boot/grub2/grub.cfg

    # NOTE: For UEFI/GPT, the process is different:
    # 1. Ensure ESP is mounted at /boot/efi
    # 2. Ensure grub2-efi-x64 and shim-x64 are installed
    # 3. Run: grub2-mkconfig -o /boot/efi/EFI/rocky/grub.cfg (path specific to Rocky)

    echo "--- Exiting Chroot ---"
' # End of chroot commands

# === Cleanup ===

echo "Unmounting filesystems..."
# Unmount in reverse order of mounting (virtual filesystems first)
sudo umount "${TARGET_MOUNT_POINT}/sys" || echo "Warning: Failed to unmount /sys"
sudo umount "${TARGET_MOUNT_POINT}/proc" || echo "Warning: Failed to unmount /proc"
sudo umount "${TARGET_MOUNT_POINT}/dev" || echo "Warning: Failed to unmount /dev"

# Unmount regular filesystems
sudo umount "${TARGET_MOUNT_POINT}/var" || echo "Warning: Failed to unmount /var"
sudo umount "${TARGET_MOUNT_POINT}/boot" || echo "Warning: Failed to unmount /boot"
# Note: For UEFI, you would unmount /boot/efi here as well
# sudo umount "${TARGET_MOUNT_POINT}/boot/efi" || echo "Warning: Failed to unmount /boot/efi"
sudo umount "${TARGET_MOUNT_POINT}" || echo "Warning: Failed to unmount /mnt/target"

# Deactivate swap
sudo swapoff "${SWAP_PARTITION}" || echo "Warning: Failed to swapoff ${SWAP_PARTITION}"

echo "=========================================================="
echo "Installation Script Completed."
echo "Target Disk:      ${TARGET_DISK}"
echo "Hostname:         ${HOSTNAME}"
echo "IP Address:       ${STATIC_IP}"
echo "User:             ${USERNAME}"
echo ""
echo "You can now attempt to reboot the server."
echo "IMPORTANT: Ensure your server's BIOS/UEFI is set to boot from ${TARGET_DISK}."
echo "For this MBR setup, ensure BIOS is in Legacy Boot mode (not UEFI)."
echo "=========================================================="

exit 0
