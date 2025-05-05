#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

# --- Configuration ---

# Partition Sizes (MB) - These remain configurable
BOOT_SIZE_MB=1024
SWAP_SIZE_MB=8192
VAR_SIZE_MB=40960 # 40 GiB

# User Configuration
USERNAME="DAN"
# Password will be prompted for below

# Network Configuration (Static IP)
# !! IMPORTANT: Adjust these network settings for your environment !!
STATIC_IP="192.168.1.69"
NETMASK="24" # Subnet mask in CIDR notation (e.g., 24 for 255.255.255.0)
GATEWAY="192.168.1.254"
DNS="8.8.8.8,8.8.4.4" # Comma-separated DNS servers
HOSTNAME="idragonfly.net"

# Mount point for the target system
TARGET_MOUNT_POINT="/mnt/target"
# --- End Configuration ---

echo "Starting Rocky Linux 9 Installation Script"
echo "======================================="

# --- Password Prompt ---
echo "Please set the password for user '${USERNAME}' and the root account."
while true; do
    read -sp "Enter desired password: " CHOSEN_PASSWORD
    echo # Add a newline after the prompt
    read -sp "Confirm password: " CHOSEN_PASSWORD_CONFIRM
    echo # Add a newline after the prompt
    if [ "$CHOSEN_PASSWORD" == "$CHOSEN_PASSWORD_CONFIRM" ]; then
        if [ -z "$CHOSEN_PASSWORD" ]; then
            echo "Password cannot be empty. Please try again."
        else
            echo "Password confirmed."
            break # Exit loop if passwords match and are not empty
        fi
    else
        echo "Passwords do not match. Please try again."
    fi
done
USER_PASSWORD="${CHOSEN_PASSWORD}"
ROOT_PASSWORD="${CHOSEN_PASSWORD}"
# Clear intermediate variable for security (optional)
unset CHOSEN_PASSWORD CHOSEN_PASSWORD_CONFIRM
# --- End Password Prompt ---


# --- Disk Selection ---
echo "Detecting available disks..."
# Use lsblk to find block devices (-d), no header (-n), output specific columns
# Filter out loop devices, ROMs (like cd/dvd), and partitions (which have '/' in NAME like sda1)
mapfile -t DISK_LINES < <(lsblk -dno NAME,SIZE,VENDOR,MODEL | grep -vE '^loop|^sr[0-9]+|/')

# Check if any disks were found
if [ ${#DISK_LINES[@]} -eq 0 ]; then
    echo "Error: No suitable disks found. Please check your hardware."
    lsblk -d # Show devices for debugging
    exit 1
fi

declare -a DISKS_ARRAY=()
declare -a DISK_PATHS=()
echo "Available disks for installation:"
INDEX=0
while IFS= read -r line; do
    # Extract details using awk (handles variable spacing better)
    DEV_NAME=$(echo "$line" | awk '{print $1}')
    DEV_SIZE=$(echo "$line" | awk '{print $2}')
    DEV_VENDOR=$(echo "$line" | awk '{print $3}')
    DEV_MODEL=$(echo "$line" | awk '{print $4}') # Model might be empty

    DISK_DESC="${DEV_NAME} (${DEV_SIZE})"
    BRAND_INFO=""
    if [ -n "${DEV_VENDOR}" ]; then
        BRAND_INFO+="${DEV_VENDOR}"
    fi
    if [ -n "${DEV_MODEL}" ]; then
        # Add a space only if vendor was also present
        [ -n "${BRAND_INFO}" ] && BRAND_INFO+=" "
        BRAND_INFO+="${DEV_MODEL}"
    fi
    if [ -n "${BRAND_INFO}" ]; then
        DISK_DESC+=" [${BRAND_INFO}]"
    fi

    # Store full path and description
    DISK_PATHS+=("/dev/${DEV_NAME}")
    DISKS_ARRAY+=("${DISK_DESC}")

    # Print numbered option for the user
    echo "  $((INDEX + 1)). ${DISK_DESC}"
    INDEX=$((INDEX + 1))
done <<< "$(printf "%s\n" "${DISK_LINES[@]}")" # Process the mapfile content

# Prompt user for selection
while true; do
    read -p "Select the number of the disk to install to: " DISK_CHOICE
    # Validate if input is a number and within range
    if [[ "${DISK_CHOICE}" =~ ^[0-9]+$ ]] && \
       [ "${DISK_CHOICE}" -ge 1 ] && \
       [ "${DISK_CHOICE}" -le "${#DISKS_ARRAY[@]}" ]; then
        SELECTED_INDEX=$((DISK_CHOICE - 1))
        TARGET_DISK="${DISK_PATHS[SELECTED_INDEX]}"
        echo "You have selected: ${DISKS_ARRAY[SELECTED_INDEX]}"
        echo "Installation target set to: ${TARGET_DISK}"
        break # Valid choice, exit loop
    else
        echo "Invalid selection. Please enter a number between 1 and ${#DISKS_ARRAY[@]}."
    fi
done
# --- End Disk Selection ---

# Display final configuration before warning
echo ""
echo "--- Final Configuration ---"
echo "Target Disk:       ${TARGET_DISK} (${DISKS_ARRAY[SELECTED_INDEX]})"
echo "Username:          ${USERNAME}"
echo "Static IP:         ${STATIC_IP}/${NETMASK}"
echo "Gateway:           ${GATEWAY}"
echo "DNS Servers:       ${DNS}"
echo "Hostname:          ${HOSTNAME}"
echo "Partition Scheme:  MBR (Legacy BIOS)"
echo "---------------------------"
echo ""
echo "WARNING: ALL DATA ON ${TARGET_DISK} WILL BE ERASED!"
read -p "Press Enter to continue, or Ctrl+C to abort..."

# === Disk Preparation ===

echo "Preparing target disk: ${TARGET_DISK}"

# Verify the disk size (using the selected TARGET_DISK)
echo "Verifying selected disk size..."
DISK_BYTES=$(sudo lsblk -b -n -d -o SIZE "${TARGET_DISK}" || echo "") # Handle potential lsblk error

if [ -z "${DISK_BYTES}" ]; then
    echo "Error: Could not determine size of ${TARGET_DISK}. Aborting."
    exit 1
fi

# Keep size checks as they were, or adjust if needed
MIN_BYTES=$((60 * 1024**3)) # 60 GiB Minimum
MAX_BYTES=$((2000 * 1024**3)) # 2 TB Maximum

if [ "${DISK_BYTES}" -lt "${MIN_BYTES}" ] || [ "${DISK_BYTES}" -gt "${MAX_BYTES}" ]; then
    DISK_GIB=$(awk -v bytes="${DISK_BYTES}" 'BEGIN {printf "%.2f", bytes / (1024**3)}')
    MIN_GIB=$(awk -v bytes="${MIN_BYTES}" 'BEGIN {printf "%.0f", bytes / (1024**3)}')
    MAX_GIB=$(awk -v bytes="${MAX_BYTES}" 'BEGIN {printf "%.0f", bytes / (1024**3)}')
    #echo "Error: Selected disk size (${DISK_GIB} GiB) is outside the expected range (${MIN_GIB}GiB-${MAX_GIB}GiB). Aborting."
    # Optional: Allow override? For now, we abort.
    read -p "Disk size is outside expected range. Continue anyway? (y/N): " OVERRIDE
    if [[ ! "$OVERRIDE" =~ ^[Yy]$ ]]; then exit 1; fi
    #exit 1
fi
echo "Selected disk size verification passed."

# Wipe existing signatures
echo "Wiping existing filesystem signatures from ${TARGET_DISK}..."
sudo wipefs -a "${TARGET_DISK}"

# Partitioning for MBR (Legacy BIOS) - Using the selected TARGET_DISK
echo "Partitioning ${TARGET_DISK} with MBR layout..."
sudo parted -s "${TARGET_DISK}" mklabel msdos

# Create partitions - Using the selected TARGET_DISK
echo "Creating partitions on ${TARGET_DISK}..."
BOOT_END_MB=$((BOOT_SIZE_MB))
SWAP_END_MB=$((BOOT_END_MB + SWAP_SIZE_MB))
VAR_END_MB=$((SWAP_END_MB + VAR_SIZE_MB))

# /boot partition (primary, ext4, bootable)
sudo parted -s "${TARGET_DISK}" mkpart primary ext4 1MiB ${BOOT_END_MB}MiB
sudo parted -s "${TARGET_DISK}" set 1 boot on
# Swap partition (primary, linux-swap)
sudo parted -s "${TARGET_DISK}" mkpart primary linux-swap ${BOOT_END_MB}MiB ${SWAP_END_MB}MiB
# /var partition (primary, ext4)
sudo parted -s "${TARGET_DISK}" mkpart primary ext4 ${SWAP_END_MB}MiB ${VAR_END_MB}MiB
# / (root) partition (primary, ext4, remaining space)
sudo parted -s "${TARGET_DISK}" mkpart primary ext4 ${VAR_END_MB}MiB 100%

# Ensure kernel recognizes new partitions on the selected TARGET_DISK
echo "Waiting for kernel to recognize new partitions on ${TARGET_DISK}..."
sudo partprobe "${TARGET_DISK}"
sleep 2 # Brief pause for safety

# Define partition device names based on the selected TARGET_DISK
# !! IMPORTANT: Assumes predictable naming (e.g., /dev/sda -> /dev/sda1, /dev/nvme0n1 -> /dev/nvme0n1p1)
# Adjust if using non-standard disk types where numbering might differ
# For common SATA/SCSI/IDE (/dev/sdX)
if [[ "${TARGET_DISK}" == /dev/sd* ]]; then
    BOOT_PARTITION="${TARGET_DISK}1"
    SWAP_PARTITION="${TARGET_DISK}2"
    VAR_PARTITION="${TARGET_DISK}3"
    ROOT_PARTITION="${TARGET_DISK}4"
# For NVMe (/dev/nvmeXnY)
elif [[ "${TARGET_DISK}" == /dev/nvme* ]]; then
    BOOT_PARTITION="${TARGET_DISK}p1"
    SWAP_PARTITION="${TARGET_DISK}p2"
    VAR_PARTITION="${TARGET_DISK}p3"
    ROOT_PARTITION="${TARGET_DISK}p4"
# Add other device types if needed (e.g., /dev/vdX for virtio)
elif [[ "${TARGET_DISK}" == /dev/vd* ]]; then
    BOOT_PARTITION="${TARGET_DISK}1"
    SWAP_PARTITION="${TARGET_DISK}2"
    VAR_PARTITION="${TARGET_DISK}3"
    ROOT_PARTITION="${TARGET_DISK}4"
else
    echo "Error: Unrecognized disk type '${TARGET_DISK}'. Cannot reliably determine partition names."
    echo "Script needs adjustment for this disk type."
    exit 1
fi
echo "Partitions identified as:"
echo "  Boot: ${BOOT_PARTITION}"
echo "  Swap: ${SWAP_PARTITION}"
echo "  Var:  ${VAR_PARTITION}"
echo "  Root: ${ROOT_PARTITION}"


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

# Activate swap
echo "Activating swap on ${SWAP_PARTITION}..."
sudo swapon "${SWAP_PARTITION}"

# Mount necessary virtual filesystems for chroot
echo "Mounting virtual filesystems..."
# Create mount points within the target root
sudo mkdir -p "${TARGET_MOUNT_POINT}/dev"
sudo mkdir -p "${TARGET_MOUNT_POINT}/proc"
sudo mkdir -p "${TARGET_MOUNT_POINT}/sys"
# /run is often needed for systemd/dbus interactions inside chroot
sudo mkdir -p "${TARGET_MOUNT_POINT}/run"

# Bind mount from host to target
sudo mount --bind /dev "${TARGET_MOUNT_POINT}/dev"
sudo mount --bind /proc "${TARGET_MOUNT_POINT}/proc"
sudo mount --bind /sys "${TARGET_MOUNT_POINT}/sys"
# Mount /run as tmpfs OR bind mount if appropriate for the live env
# Mounting as tmpfs is often safer if host /run contains sensitive live env info
sudo mount -t tmpfs tmpfs "${TARGET_MOUNT_POINT}/run"
# Alternatively, if host /run is simple: sudo mount --bind /run "${TARGET_MOUNT_POINT}/run"

# === Network Detection (Host) ===

echo "Detecting active network interface on host..."
# Attempt to find the interface associated with the default route
LIVE_INTERFACE=$(ip route get 1.1.1.1 | grep -oP 'dev \K\S+' || true) # || true prevents script exit

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
        # Consider unmounting filesystems here before exiting cleanly
        # (Add cleanup logic here if desired before aborting)
        exit 1
    fi
else
    echo "Detected active interface: ${LIVE_INTERFACE}"
    INTERFACE_NAME="${LIVE_INTERFACE}"
fi
echo "Using interface '${INTERFACE_NAME}' for configuration inside target system."


# === Install Base System for Chroot ===

echo "Preparing target for package installation..."
# Ensure /etc exists in the target first
sudo mkdir -p "${TARGET_MOUNT_POINT}/etc"

# Copy host DNS settings to allow package downloads in the next step
# Check if /etc/resolv.conf exists and is readable before copying
if [ -r /etc/resolv.conf ]; then
    sudo cp /etc/resolv.conf "${TARGET_MOUNT_POINT}/etc/"
    echo "Copied host DNS configuration for initial package install."
else
    echo "Warning: Host /etc/resolv.conf not found or not readable. DNS may fail during base install."
    echo "Consider configuring DNS manually if the next step fails."
fi

echo "Installing base system packages into ${TARGET_MOUNT_POINT}..."
# Install the bare minimum needed to chroot and run dnf inside
# Requires the live environment (DVD) to have access to Rocky 9 repositories
# Use --releasever=9 to be explicit, especially if live env is different
sudo dnf --installroot="${TARGET_MOUNT_POINT}" -y install \
    bash \
    coreutils \
    dnf \
    dnf-data \
    rocky-repos \
    rocky-gpg-keys \
    glibc-minimal-langpack \
    filesystem \
    --releasever=9
    # Add --nogpgcheck if GPG key import fails in the live environment

echo "Base packages installed."

# === Chroot and System Installation/Configuration ===

echo "Chrooting into ${TARGET_MOUNT_POINT} and completing installation..."

# Export variables needed inside chroot environment
# Ensure TARGET_DISK (the selected disk) is exported for GRUB installation
export USERNAME USER_PASSWORD ROOT_PASSWORD STATIC_IP NETMASK GATEWAY DNS HOSTNAME INTERFACE_NAME TARGET_DISK

# Execute the main installation and configuration steps inside the chroot
sudo chroot "${TARGET_MOUNT_POINT}" /bin/bash -c '
    # Exit on error inside the chroot script
    set -e

    echo "--- Inside Chroot ---"

    # Optional: Mount API filesystems if needed by specific tools inside chroot.
    # The bind mounts from the host might suffice, but mounting explicitly inside
    # ensures the standard paths are populated from the chroot perspective.
    # mountpoint -q /proc || mount -t proc proc /proc
    # mountpoint -q /sys || mount -t sysfs sys /sys
    # mountpoint -q /dev || mount -t devtmpfs dev /dev # Needed if /dev wasn't bind mounted properly
    # mountpoint -q /run || mount -t tmpfs tmpfs /run # If /run wasn''t mounted before chroot

    # Source os-release to confirm environment (optional check)
    if [ -f /etc/os-release ]; then
        source /etc/os-release
        echo "Running inside chroot: ${PRETTY_NAME:-Unknown OS}"
    fi

    # Ensure DNS resolution works inside the chroot *before* installing packages.
    # The copied resolv.conf should handle this initially.
    echo "Testing DNS inside chroot..."
    if ! ping -c 1 pool.ntp.org &> /dev/null; then # Be less verbose on success
        echo "Warning: DNS resolution might not be working inside chroot."
        echo "Verify /etc/resolv.conf or network setup."
        # Consider pausing or exiting if DNS is critical for the next steps
    fi

    # Verify/Enable standard Rocky Linux repositories (should be okay via rocky-repos)
    # echo "Ensuring base repositories are enabled..."
    # dnf config-manager --set-enabled baseos appstream # Usually default

    # Enable CRB (CodeReady Builder) repository
    echo "Enabling CRB repository..."
    dnf config-manager --set-enabled crb

    # Install and enable EPEL (Extra Packages for Enterprise Linux) repository
    echo "Installing EPEL repository..."
    dnf -y install epel-release
    # Refresh metadata cache after adding/enabling repositories
    echo "Refreshing DNF metadata..."
    dnf makecache

    # Ensure necessary directories exist (though packages should create them)
    mkdir -p /etc/sysconfig/network-scripts # Legacy
    mkdir -p /etc/NetworkManager/system-connections
    mkdir -p /boot/grub2

    # Install the full set of desired packages
    echo "Installing core system, kernel, tools, and services..."
    # Using @core group provides a good base server environment
    dnf -y install \
        @core \
        kernel \
        grub2 \
        grub2-tools \
        os-prober \
        dnf-utils \
        NetworkManager \
        NetworkManager-tui \
        nm-connection-editor \
        firewalld \
        sudo \
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
        # Note: grub2-efi-* packages are intentionally omitted for MBR boot

    # Configure System Timezone
    echo "Setting timezone to America/Chicago..."
    timedatectl set-timezone America/Chicago

    # Configure System Locale
    echo "Setting locale to en_US.UTF-8..."
    localectl set-locale LANG=en_US.UTF-8

    # Configure NetworkManager for Static IP using inherited variables
    echo "Configuring static network for interface ${INTERFACE_NAME}..."
    # Create the NetworkManager connection profile file
    cat > /etc/NetworkManager/system-connections/static-${INTERFACE_NAME}.nmconnection <<EOL
[connection]
id=static-${INTERFACE_NAME}
uuid=$(uuidgen) # Generate a unique connection UUID
type=ethernet
interface-name=${INTERFACE_NAME} # Bind profile to the specific hardware interface
autoconnect=true # Connect automatically on boot/interface up

[ethernet]
# Add specific ethernet options here if needed (e.g., MTU, cloned MAC)

[ipv4]
method=manual
addresses=${STATIC_IP}/${NETMASK} # IP address and subnet mask length
gateway=${GATEWAY} # Default gateway
dns=${DNS} # Comma-separated DNS server(s)

[ipv6]
method=auto # Disable IPv6 if not used, common for internal servers
# Use method=auto for SLAAC/DHCPv6, or method=manual for static IPv6

[proxy]
# Add proxy settings here if required
EOL
    # Set secure permissions for the connection file (contains no secrets here, but good practice)
    chmod 600 /etc/NetworkManager/system-connections/static-${INTERFACE_NAME}.nmconnection
    echo "Network configuration created: /etc/NetworkManager/system-connections/static-${INTERFACE_NAME}.nmconnection"

    # Set System Hostname
    echo "Setting hostname to ${HOSTNAME}..."
    hostnamectl set-hostname "${HOSTNAME}"

    # Add Regular User Account
    echo "Adding user: ${USERNAME}"
    # Creates user, group, home directory (/home/USERNAME), sets shell
    useradd -m -s /bin/bash "${USERNAME}"

    # Set Password for Regular User using the chosen password
    echo "Setting password for user: ${USERNAME}"
    echo "${USERNAME}:${USER_PASSWORD}" | chpasswd

    # Set Password for Root User using the chosen password
    echo "Setting root password..."
    echo "root:${ROOT_PASSWORD}" | chpasswd

    # Grant Sudo Privileges to Regular User
    echo "Adding user ${USERNAME} to 'wheel' group for sudo access"
    usermod -aG wheel "${USERNAME}" # Members of wheel can use sudo by default on RHEL/Rocky

    # Enable Essential System Services to Start on Boot
    echo "Enabling essential services..."
    systemctl enable NetworkManager.service # Manages network connections
    systemctl enable firewalld.service     # Manages the firewall
    systemctl enable chronyd.service       # Manages system time synchronization (NTP)
    systemctl enable cockpit.socket       # Enables the Cockpit web console (socket activation)
    systemctl enable libvirtd.service     # Enables the KVM/QEMU virtualization daemon
    systemctl enable podman.socket      # Optional: Enable socket for rootless Podman API access

    # Configure Firewall Rules
    echo "Configuring firewall..."
    # Add permanent rules for common services. These are loaded when firewalld starts.
    firewall-cmd --permanent --add-service=ssh      # Allow SSH access
    firewall-cmd --permanent --add-service=cockpit  # Allow Cockpit web console access
    firewall-cmd --permanent --add-port=80/tcp      # Allow standard HTTP
    firewall-cmd --permanent --add-port=443/tcp     # Allow standard HTTPS
    # Add other rules as needed: firewall-cmd --permanent --add-service=... or --add-port=...
    # No reload needed here; rules apply when service starts on first boot.
    echo "Firewall rules configured (will apply on system boot)."

    # Install GRUB Bootloader for MBR/Legacy BIOS Boot
    # Uses the TARGET_DISK variable exported from the main script
    echo "Installing GRUB bootloader for MBR on ${TARGET_DISK}..."
    # This command installs the GRUB boot code to the Master Boot Record of the target disk.
    grub2-install "${TARGET_DISK}"

    # Generate GRUB Configuration File
    echo "Generating GRUB configuration file..."
    # This command scans for kernels and generates /boot/grub2/grub.cfg
    # It relies on /boot being mounted correctly within the chroot.
    grub2-mkconfig -o /boot/grub2/grub.cfg

    # Optional: Trigger SELinux relabel on next boot.
    # This ensures file contexts are correct after potentially moving/creating files.
    # Usually handled automatically if SELinux is enforcing.
    # touch /.autorelabel

    echo "--- Exiting Chroot ---"
' # End of chroot commands block

# Check the exit status of the chroot command block
if [ $? -ne 0 ]; then
  echo "ERROR: Chroot operations failed. Please check the output above."
  echo "Filesystems will remain mounted at ${TARGET_MOUNT_POINT} for inspection."
  exit 1
fi

# === Cleanup ===

echo "Unmounting filesystems..."
# Unmount in reverse order of mounting. Add warnings on failure.
# Use lazy unmount (-l) as a fallback if busy, though clean unmount is preferred.
# Unmounting virtual filesystems first
sudo umount "${TARGET_MOUNT_POINT}/sys" || sudo umount -l "${TARGET_MOUNT_POINT}/sys" || echo "Warning: Failed to unmount ${TARGET_MOUNT_POINT}/sys"
sudo umount "${TARGET_MOUNT_POINT}/proc" || sudo umount -l "${TARGET_MOUNT_POINT}/proc" || echo "Warning: Failed to unmount ${TARGET_MOUNT_POINT}/proc"
sudo umount "${TARGET_MOUNT_POINT}/run" || sudo umount -l "${TARGET_MOUNT_POINT}/run" || echo "Warning: Failed to unmount ${TARGET_MOUNT_POINT}/run" # If mounted as tmpfs or bind
sudo umount "${TARGET_MOUNT_POINT}/dev" || sudo umount -l "${TARGET_MOUNT_POINT}/dev" || echo "Warning: Failed to unmount ${TARGET_MOUNT_POINT}/dev"

# Unmounting target partitions
sudo umount "${TARGET_MOUNT_POINT}/var" || sudo umount -l "${TARGET_MOUNT_POINT}/var" || echo "Warning: Failed to unmount ${TARGET_MOUNT_POINT}/var"
sudo umount "${TARGET_MOUNT_POINT}/boot" || sudo umount -l "${TARGET_MOUNT_POINT}/boot" || echo "Warning: Failed to unmount ${TARGET_MOUNT_POINT}/boot"
sudo umount "${TARGET_MOUNT_POINT}" || sudo umount -l "${TARGET_MOUNT_POINT}" || echo "Warning: Failed to unmount ${TARGET_MOUNT_POINT}"

# Deactivate swap partition
echo "Deactivating swap on ${SWAP_PARTITION}..."
sudo swapoff "${SWAP_PARTITION}" || echo "Warning: Failed to swapoff ${SWAP_PARTITION}"

echo "=========================================================="
echo "Installation Script Completed Successfully."
echo "Target Disk:       ${TARGET_DISK}"
echo "Hostname:          ${HOSTNAME}"
echo "IP Address:        ${STATIC_IP}/${NETMASK}"
echo "User:              ${USERNAME} (sudo access via 'wheel' group)"
echo ""
echo "You can now attempt to reboot the server."
echo "IMPORTANT: Ensure your server's BIOS is set to boot from ${TARGET_DISK}"
echo "           in Legacy Boot mode (not UEFI mode)."
echo "=========================================================="

exit 0

