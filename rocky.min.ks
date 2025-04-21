# Kickstart file for Rocky Linux 9 - Headless Installation

# System language
lang en_US.UTF-8

# Keyboard layout
keyboard --vckeymap=us --xlayouts='us'

# System timezone
timezone America/Chicago --isUtc

# Partition clearing information
clearpart --all --drives=sda --initlabel

# Disk partitioning information
part /boot --fstype=ext4 --size=1024
part /var --fstype=ext4 --size=20480
part swap --size=4096
part / --fstype=ext4 --grow

# System bootloader configuration
bootloader --append="rhgb quiet" --location=mbr

# Network configuration (DHCP is default, static IP configured in %pre)
network --bootproto=dhcp --device=link

# Firewall configuration
firewall --enabled --service=ssh --service=http --service=https --service=nfs

# SELinux configuration
selinux --permissive

# Do not install the X Window System or any graphical environments
skipx

# Repositories
repo --name="Rocky-9-BaseOS" --baseurl=http://dl.rockylinux.org/pub/rocky/9/BaseOS/x86_64/os/
repo --name="Rocky-9-AppStream" --baseurl=http://dl.rockylinux.org/pub/rocky/9/AppStream/x86_64/os/
repo --name="Rocky-9-CRB" --baseurl=http://dl.rockylinux.org/pub/rocky/9/crb/x86_64/os/
repo --name="epel" --baseurl=https://download.fedoraproject.org/pub/epel/9/Everything/x86_64/

# Package selection
%packages
@^minimal-environment
@base-x
@console-internet
@development-tools
@network-file-system-client
@network-tools
@server-product
@virtualization-host
rocky-release
epel-release
python3-pip
cronie
fail2ban
certbot
nfs-utils
rpcbind
httpd
mariadb-server
php
php-cli
php-mysqli
php-pdo
php-fpm
mod_ssl
vim
nano
wget
python3
rsync
git
curl
gcc
cmake
make
autoconf
automake
createrepo
genisoimage
isomd5sum
nss-tools
python-utils
syslinux
podman
cockpit
cockpit-podman
%end

# Pre-installation script to dynamically set network interface
%pre
# Function to find the first wired network interface
find_first_wired_interface() {
    for interface in $(nmcli -t -f DEVICE,TYPE d | grep ethernet | cut -d: -f1); do
        echo "$interface"
        return
    done
}

# Find the first wired network interface
INTERFACE=$(find_first_wired_interface)

# If an interface is found, create a NetworkManager connection file
if [ -n "$INTERFACE" ]; then
    cat > /tmp/ifcfg-$INTERFACE <<EOM
TYPE=Ethernet
BOOTPROTO=none
DEFROUTE=yes
IPADDR=192.168.1.69
NETMASK=255.255.255.0
GATEWAY=192.168.1.255
DNS1=8.8.8.8
DNS2=8.8.4.4
IPV6INIT=yes
IPV6_AUTOCONF=yes
IPV6_DEFROUTE=yes
IPV6_PEERDNS=yes
IPV6_PEERROUTES=yes
IPV6_PRIVACY=no
NAME=$INTERFACE
DEVICE=$INTERFACE
ONBOOT=yes
EOM
    # Activate the connection
    nmcli connection up ifcfg-$INTERFACE
else
    echo "No wired network interface found."
fi
%end

# Post-installation script
%post
# Define the UUIDs (replace with your actual UUIDs)
MODELS_UUID="9a58889a-f8ba-4cc9-80e2-b7ecd5dc1e2c"
DATA_UUID="6c330ffb-09cf-4ee8-96b1-f44fb8eaf38d"

# Create mount points (make sure they don't already exist)
mkdir -p /models /repo /data /venv
chmod 777 /data /repo /models /venv

# Add to /etc/fstab
echo "UUID=$MODELS_UUID /models ext4 defaults 0 2" >> /etc/fstab
echo "UUID=$DATA_UUID /data ext4 defaults 0 2" >> /etc/fstab

# Mount the partitions
mount -a

# Update the system
dnf update -y

# Create the autostart directory in /etc/skel (no GUI, so this won't be used for autostart)
mkdir -p /etc/skel/.config/autostart

# Create a custom .bashrc file
cat <<EOF > /etc/skel/.bashrc
# ~/.bashrc: executed by bash(1) for non-login shells.

# If not running interactively, don't do anything
case \$- in
    *i*) ;;
    *) return;;
esac

# Set the default editor to nano
export EDITOR=nano

# Define some aliases
alias ll='ls -la'
alias grep='grep --color=auto'

# Prompt customization
PS1='\u@\h:\w\$ '

# Source global definitions
if [ -f /etc/bashrc ]; then
    . /etc/bashrc
fi
EOF

# Set the correct permissions for the .bashrc file
chmod 644 /etc/skel/.bashrc

# Create a custom .bash_profile file
cat <<EOF > /etc/skel/.bash_profile
# ~/.bash_profile

# Get the aliases and functions
if [ -f ~/.bashrc ]; then
    . ~/.bashrc
fi

# User specific environment and startup programs
PATH=\$PATH:\$HOME/bin

export PATH
EOF

# Set the correct permissions for the .bash_profile file
chmod 644 /etc/skel/.bash_profile

# Create a custom .profile file
cat <<EOF > /etc/skel/.profile
# ~/.profile

# Get the aliases and functions
if [ -f ~/.bashrc ]; then
    . ~/.bashrc
fi

# Set the default editor
export EDITOR=nano
EOF

# Set the correct permissions for the .profile file
chmod 644 /etc/skel/.profile

# Enable and start services
systemctl enable cockpit.socket
systemctl start cockpit.socket

# Create NFS export configuration entries. Replace with your actual NFS server and export paths.
echo "/models 192.168.1.0/24(rw,no_root_squash)" >> /etc/exports
echo "/repo 192.168.1.0/24(rw,no_root_squash)" >> /etc/exports
echo "/data 192.168.1.0/24(rw,no_root_squash)" >> /etc/exports

# Enable and start services
systemctl enable httpd mariadb firewalld NetworkManager cockpit.socket nfs-server rpcbind
systemctl start httpd mariadb firewalld NetworkManager cockpit.socket nfs-server rpcbind

firewall-cmd --permanent --add-service=ssh
firewall-cmd --permanent --add-service=https
firewall-cmd --permanent --add-service=nfs-server
firewall-cmd --permanent --add-service=nfs
firewall-cmd --reload

# Create user 'dan' with sudo privileges
useradd -m -G wheel dan
echo "dan:dc32asd#" | chpasswd

# Allow root login with password
echo "root:dc32asd#" | chpasswd
sed -i 's/^#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
systemctl restart sshd

echo "Kickstart installation complete."
%end
