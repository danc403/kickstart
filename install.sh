#!/bin/bash

set -e

TARGET_DISK="/dev/sda" # Adjust this to your target server's disk (e.g., /dev/sdb)
BOOT_SIZE_MB=1024
SWAP_SIZE_MB=4096
VAR_SIZE_MB=20480
USERNAME="DAN" # Replace with your desired username
USER_PASSWORD="$1" # Replace with your desired password (will be hashed)
ROOT_PASSWORD="$1" # Replace with your desired root password (will be hashed)

STATIC_IP="192.168.1.69" # Adjust to your desired static IP
GATEWAY="192.168.1.254"
DNS="8.8.8.8"
HOSTNAME="idragonfly.net"

TARGET_MOUNT_POINT="/mnt/target"

echo "Preparing target disk: ${TARGET_DISK}"

# Partitioning (WARNING: THIS WILL ERASE DATA ON ${TARGET_DISK})
echo "Partitioning ${TARGET_DISK} (MBR layout)..."
sudo parted -s ${TARGET_DISK} mklabel msdos # Create MBR label

# Create partitions using parted
echo "Creating partitions with parted..."
BOOT_END=$((BOOT_SIZE_MB))
SWAP_END=$((BOOT_END + SWAP_SIZE_MB))
VAR_END=$((SWAP_END + VAR_SIZE_MB))

sudo parted -s ${TARGET_DISK} mkpart primary ext4 0% ${BOOT_END}MiB
sudo parted -s ${TARGET_DISK} set 1 boot on
sudo parted -s ${TARGET_DISK} mkpart primary linux-swap ${BOOT_END}MiB ${SWAP_END}MiB
sudo parted -s ${TARGET_DISK} mkpart primary ext4 ${SWAP_END}MiB ${VAR_END}MiB
sudo parted -s ${TARGET_DISK} mkpart primary ext4 ${VAR_END}MiB 100%

# Get the actual device names created by parted
BOOT_PARTITION=$(sudo lsblk -no PATH ${TARGET_DISK}1)
SWAP_PARTITION=$(sudo lsblk -no PATH ${TARGET_DISK}2)
VAR_PARTITION=$(sudo lsblk -no PATH ${TARGET_DISK}3)
ROOT_PARTITION=$(sudo lsblk -no PATH ${TARGET_DISK}4)

echo "Formatting partitions..."
sudo mkfs.ext4 -F "${BOOT_PARTITION}"
sudo mkswap -F "${SWAP_PARTITION}"
sudo mkfs.ext4 -F "${VAR_PARTITION}"
sudo mkfs.ext4 -F "${ROOT_PARTITION}"

# Mount partitions
sudo mkdir -p "${TARGET_MOUNT_POINT}"
sudo mount "${ROOT_PARTITION}" "${TARGET_MOUNT_POINT}"
sudo mkdir -p "${TARGET_MOUNT_POINT}/boot"
sudo mount "${BOOT_PARTITION}" "${TARGET_MOUNT_POINT}/boot"
sudo mkdir -p "${TARGET_MOUNT_POINT}/var"
sudo mount "${VAR_PARTITION}" "${TARGET_MOUNT_POINT}/var"
sudo swapon "${SWAP_PARTITION}"

# Create necessary directories
sudo mkdir -p "${TARGET_MOUNT_POINT}/dev"
sudo mkdir -p "${TARGET_MOUNT_POINT}/sys"
sudo mkdir -p "${TARGET_MOUNT_POINT}/proc"
sudo mkdir -p "${TARGET_MOUNT_POINT}/etc"
sudo mkdir -p "${TARGET_MOUNT_POINT}/boot/grub" # MBR uses grub, not grub2 directly
sudo mkdir -p "${TARGET_MOUNT_POINT}/etc/yum.repos.d"
sudo mkdir -p "${TARGET_MOUNT_POINT}/etc/sysconfig"
sudo mkdir -p "${TARGET_MOUNT_POINT}/etc/NetworkManager/system-connections"

# Mount virtual filesystems
sudo mount --bind /dev "${TARGET_MOUNT_POINT}/dev"
sudo mount --bind /sys "${TARGET_MOUNT_POINT}/sys"
sudo mount --bind /proc "${TARGET_MOUNT_POINT}/proc"

echo "Identifying the primary network interface with a DHCP address (Rocky 9 specific)..."
LIVE_INTERFACE=$(nmcli c show --active | grep "IP4.ADDRESS" | awk '{print $4}' | sed 's/\..*//')

if [ -z "${LIVE_INTERFACE}" ]; then
    echo "Error: Could not automatically determine the active network interface with a DHCP address. Please check your network configuration in the live environment."
    exit 1
fi

echo "Detected live environment interface with DHCP: ${LIVE_INTERFACE}"
INTERFACE_NAME="${LIVE_INTERFACE}" # Use the detected interface for configuration

echo "Chrooting into ${TARGET_MOUNT_POINT}"
sudo chroot "${TARGET_MOUNT_POINT}" /bin/bash -c "
    set -e

    # Enable standard Rocky Linux repositories (explicitly, though often default)
    echo 'Enabling standard Rocky Linux repositories...'
    dnf config-manager --set-enabled baseos
    dnf config-manager --set-enabled appstream

    # Enable CRB and EPEL repositories
    echo 'Enabling CRB and EPEL repositories...'
    dnf config-manager --set-enabled crb
    dnf install -y epel-release

    # Configure Repositories (assuming default Rocky repos are OK in the live env for initial install)
    echo 'Configuring repositories (if needed)...'
    # You might add more specific repository configurations here if required

    # Install base system, kernel, server tools, utilities, and dkms
    echo 'Installing base system, kernel, server tools, utilities, and dkms...'
    dnf -y install @base kernel cockpit podman qemu-kvm libvirt libvirt-daemon-kvm sudo net-tools nano yum-utils tmux dkms

    # Configure timezone
    echo 'Setting timezone to America/Chicago...'
    ln -sf /usr/share/zoneinfo/America/Chicago /etc/localtime
    echo 'America/Chicago' > /etc/timezone
    timedatectl set-timezone America/Chicago # More modern way

    # Configure locale
    echo 'Setting locale to en_US.UTF-8...'
    localectl set-locale LANG=en_US.UTF-8

    # Install and enable firewall
    echo 'Installing and enabling firewall...'
    dnf -y install firewalld
    systemctl enable firewalld
    systemctl start firewalld

    # Open SSH port in the firewall
    echo 'Opening SSH port in the firewall...'
    firewall-cmd --permanent --add-service=ssh
    firewall-cmd --reload

    # Add user
    echo 'Adding user: ${USERNAME}'
    useradd -m -s /bin/bash ${USERNAME}

    # Set user password
    echo 'Setting password for user: ${USERNAME}'
    echo '${USERNAME}:${USER_PASSWORD}' | chpasswd

    # Set root password
    echo 'Setting root password...'
    echo 'root:${ROOT_PASSWORD}' | chpasswd

    # Grant administrator privileges (add to wheel group)
    echo 'Adding user to wheel group for sudo access'
    usermod -aG wheel ${USERNAME}

    # Configure NetworkManager for static IP
    echo 'Configuring static network...'
    cat > /etc/NetworkManager/system-connections/static-${INTERFACE_NAME}.nmconnection <<EOL
[connection]
id=static-${INTERFACE_NAME}
type=ethernet
interface-name=${INTERFACE_NAME}
connection.autoconnect=true

[ipv4]
method=manual
address=${STATIC_IP}/24
gateway=${GATEWAY}
dns=${DNS}

[ipv6]
method=auto
EOL
    chmod 600 /etc/NetworkManager/system-connections/static-${INTERFACE_NAME}.nmconnection

    # Set hostname
    echo '${HOSTNAME}' > /etc/hostname
    hostname '${HOSTNAME}'

    # Enable and start services
    echo 'Enabling and starting services...'
    systemctl enable NetworkManager.service
    systemctl enable cockpit.socket
    systemctl enable libvirtd.service
    systemctl enable podman.socket
    systemctl enable firewalld.service # Ensure firewall service is enabled
    systemctl start NetworkManager.service
    systemctl start cockpit.socket
    systemctl start libvirtd.service
    systemctl start podman.socket
    systemctl start firewalld.service # Ensure firewall service is started

    # Install GRUB for MBR
    echo 'Installing GRUB for MBR...'
    grub2-install --boot-directory=/boot /dev/sda # Ensure this matches your target disk
    grub2-mkconfig -o /boot/grub/grub.cfg # MBR uses /boot/grub

    echo 'Installation inside chroot complete.'
"

echo "Unmounting virtual filesystems and target partitions..."
sudo umount "${TARGET_MOUNT_POINT}/sys"
sudo umount "${TARGET_MOUNT_POINT}/proc"
sudo umount "${TARGET_MOUNT_POINT}/dev"
sudo umount "${TARGET_MOUNT_POINT}/var"
sudo umount "${TARGET_MOUNT_POINT}/boot"
sudo umount "${TARGET_MOUNT_POINT}"
sudo swapoff "${SWAP_PARTITION}"

echo "Installation preparation complete. You can now try rebooting the server."
echo "Remember to set your server's BIOS to boot from the hard drive."
