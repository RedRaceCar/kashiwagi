#!/bin/bash

# How to use this script:

# 1. Read the README and do the Forensics first, to ensure you don't miss anything
# 2. Configure the allowed users file in users.txt
#    a) 
# 3. Configure the list of allowed services
# 4. Run sudo -i to open up a terminal as root (do not use sudo to run the script)
# 5. Navigate to the directory with the script, then just run 'bash asn_script.sh'

# TODO: Change main user password to something simple, so you don't get locked out
# TODO: Check for Users as per README (using a config file). Make sure that any added users are included in the desired config
# TODO: Change passwords to match README
# TODO: Manually check for insecure passwords (you can script to make sure there are no empty passwords too!)
# TODO: Make password files immutable after fixing
# TODO: Manually do forensics
# TODO: Manually search for rootkit finders
# TODO: Ensure that the distributions for packages work (the sources)
# TODO: Check for malicious sources
# TODO: Manually check Ubuntu Software Center for any bad software
# TODO: Manually set firefox security settings (this should be able to be scripted, i just don't know how)
# TODO: Manually set up BUM stuff
# TODO: Create a config file for removing cron
# TODO: Manually check for any hidden users
# TODO: Manually add dangerous common auth?
# TODO: Fill out all the Apache and Samba stuff
# TODO? Disable service autostarts
# TODO: PSAD?
# TODO: Examine INIT files for discrepancies
# TODO: Manually look over added Kernel Modules (lsmod)
# TODO: Run a Lynis Audit
# TODO? Replace all bash shells with rbash (from nats checklist)
# TODO: Run sysctl -p to update all changes


#Ensure everything is OK before we begin

gnome-terminal -- sh -c 'sudo -i' & #backup terminal

# Set the path to the configuration file
USER_CONFIG_FILE="./users.txt"
SERVICE_CONFIG_FILE="./services.txt"

# Set the colors for displaying alerts
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo "Starting Script"

run_in_terminal() {
  local cmd="$1"
  gnome-terminal -- bash -c "$cmd; exec bash" &
}

echo "Running apt update"

apt update 

echo "Finished running apt update"

# Check if the user is root
if [[ $(id -u) -ne 0 ]]; then
  echo "This script must be run as root."
  exit 1
fi


# Check if the config file exists
if [ ! -f "$USER_CONFIG_FILE" ]; then
    echo -e "${RED}Configuration file '$USER_CONFIG_FILE' does not exist.${NC}"
    exit 1
fi

# Check if the config file exists
if [ ! -f "$SERVICE_CONFIG_FILE" ]; then
    echo -e "${RED}Configuration file '$SERVICE_CONFIG_FILE' does not exist.${NC}"
    exit 1
fi

# Configuration options to append
options_to_append='DPkg::options { "--force-confdef"; "--force-confnew"; }'

# Check if the configuration file already exists
if [ -e "/etc/apt/apt.conf.d" ]; then
  # Check if the configuration options are already present
  if grep -q "$options_to_append" "/etc/apt/apt.conf.d"; then
    echo "Configuration options already present in /etc/apt/apt.conf.d"
  else
    # Append the configuration options to the existing file
    echo "$options_to_append" | sudo tee -a "/etc/apt/apt.conf.d" > /dev/null
    echo "Configuration options appended to /etc/apt/apt.conf.d"
  fi
else
  # Create a new configuration file and append the options
  echo "$options_to_append" | sudo tee "/etc/apt/apt.conf.d" > /dev/null
  echo "Configuration file created at /etc/apt/apt.conf.d with appended options."
fi

# Read the service requirements from services.txt
while IFS= read -r line; do
    service=$(echo "$line" | awk '{print $1}')
    required=$(echo "$line" | awk '{print $2}')

    # Set variables based on service requirements
    case "$service" in
        ssh)
            if [[ "$required" -eq 1 ]]; then
                SSH_REQ=true
            else
                SSH_REQ=false
            fi
            ;;
        ftp)
            if [[ "$required" -eq 1 ]]; then
                FTP_REQ=true
            else
                FTP_REQ=false
            fi
            ;;
        http)
            if [[ "$required" -eq 1 ]]; then
                HTTP_REQ=true
            else
                HTTP_REQ=false
            fi
            ;;
        smb)
            if [[ "$required" -eq 1 ]]; then
                SMB_REQ=true
            else
                SMB_REQ=false
            fi
            ;;
        mysql)
            if [[ "$required" -eq 1 ]]; then
                MYSQL_REQ=true
            else
                MYSQL_REQ=false
            fi
            ;;
        apache)
            if [[ "$required" -eq 1 ]]; then
                APACHE_REQ=true
            else
                APACHE_REQ=false
            fi
            ;;
        *)
            echo "Unknown service: $service"
            ;;
    esac

done < $SERVICE_CONFIG_FILE

yes | dpkg --configure -a

sudo debconf-set-selections <<< "postfix postfix/mailname string yourdomain.com"
sudo debconf-set-selections <<< "postfix postfix/main_mailer_type string 'Internet Site'"

#Prerequisites

if [ "$SSH_REQ" == true ]; then
    # Update SSH services
     DEBIAN_FRONTEND=noninteractive sudo apt-get install -y openssh-server 
fi

if [ "$FTP_REQ" = true ]; then
    # update all ftp services
    apt-get install -y vsftpd proftpd 
fi

if [ "$HTTP_REQ" = true ]; then
	# Install Nginx
   DEBIAN_FRONTEND=noninteractive apt-get install -y nginx 
fi

if [ "MYSQL_REQ" = true ]; then
	# Set the MySQL configuration options
	sudo apt-get install -y mysql-server 
fi

echo "Critical Services Updated"

echo "Installing Dependencies"
DEBIAN_FRONTEND=noninteractive sudo apt-get install -y ufw libpam-cracklib iptables auditd unattended-upgrades 
echo "Installed Dependencies"

sudo apt-get --purge remove finger xinetd nis yp-tools tftpd atftpd tftpd-hpa telnetd rsh-server rsh-redone-server > /dev/null
echo "Removed miscellaneous insecure services."

#REAL SCRIPT STARTS HERE

echo "Checking Users section..."
while read -r line
do
    # Break out of the loop if the Admins section is found
    if [[ "$line" == "Admins:" ]]; then
        break
    fi

    # Skip the Users section header
    if [[ "$line" == "Users:" ]]; then
        continue
    fi

    # Extract the username and primary group (if present)
    username=$(echo "$line" | cut -d ':' -f 1)
    group=$(echo "$line" | cut -d ':' -f 2 | tr -d ' ')
    group+=" $username"

    # Check if the user exists
    if ! id "$username" &> /dev/null; then
        echo -e "${YELLOW}User '$username' does not exist.${NC}"
	  echo -e "Mitigated"
        echo -e "${YELLOW}User '$username' has no password set. ${NC}"
        echo -e "${RED}Needs manual action${NC}"
	  sudo useradd "$username"
    fi
    # Check if the user belongs to any of the specified groups
        if [[ -n "$group" ]]; then
            user_groups=$(id -Gn "$username")
            for g in $group; do
                if ! echo "$user_groups" | grep -qw "$g"; then
                    echo -e "${YELLOW}User '$username' does not belong to group '$g'.${NC}"
                    # You can add your action here to add the user to the group, e.g.:
			  sudo usermod -aG "$g" "$username"
			  echo "Mitigated"
                fi
            done
        fi

        # Check if the user is in any other group (excluding sudo)
        other_groups=$(id -Gn "$username" | grep -vw "sudo")
        # Convert to arrays
	  group_arr=($group)
	  other_groups_arr=($other_groups)

	  # Loop through and remove element
	  for item in "${group_arr[@]}"; do
  	    other_groups_arr=("${other_groups_arr[@]/$item}")
	  done

	  # Convert back to a string
        # Create a temporary array to store non-empty items
        non_empty_arr=()

        # Loop through each item in other_groups_arr
	  for item in "${other_groups_arr[@]}"; do
        # Check if item is not empty
    	 	if [[ -n "$item" ]]; then
             # Add non-empty item to non_empty_arr
             non_empty_arr+=("$item")
    	  	fi
	  done

	  # Replace other_groups with non_empty_arr
	  other_groups_arr=("${non_empty_arr[@]}")
        other_groups="${other_groups_arr[*]}"
	  if [[ "${#other_groups_arr[@]}" -gt 0 ]]; then
            echo -e "${YELLOW}User '$username' is in additional groups: $other_groups${NC}"
		echo -e "${RED}Needs manual action${NC}"
        fi
done < "$USER_CONFIG_FILE"

# Get the list of members in the sudo group
sudo_group_members=$(getent group sudo | cut -d ':' -f 4)

# Convert the list of members into an array
sudo_group_arr=()
IFS=',' read -ra members <<< "$sudo_group_members"
for member in "${members[@]}"; do
  sudo_group_arr+=("$member")
done

# Check the Admins section
echo "Checking Admins section..."
admins_section=false
while read -r line
do
    # Look for the Admins section header
    if [[ "$line" == "Admins:" ]]; then
        admins_section=true
        continue
    fi

    # Only check if we've reached the Admins section
    if [[ "$admins_section" == true ]]; then
        # Check if the admin user exists
        if ! id "$line" &> /dev/null; then
            echo -e "${YELLOW}Admin user '$line' does not exist.${NC}"
        else
            # Check if the admin user is not in the sudo group
            if ! id -nG "$line" | grep -qw "sudo"; then
                echo -e "${YELLOW}Admin user '$line' is not in the sudo group.${NC}"
            else
                # Remove admin user from sudo_group variable
                sudo_group_arr=("${sudo_group_arr[@]/$line}")
            fi
        fi
    fi
done < "$USER_CONFIG_FILE"

arr2=()
for val in "${sudo_group_arr[@]}"; do
    [[ $val ]] && arr2+=( "$val" )
done

sudo_group_arr=("${arr2[@]}")

# Remove all users in sudo_group_arr from the system that are not part of the config
for member in "${sudo_group_arr[@]}"; do
  echo -e "${YELLOW}Unauthorized admin user $member detected.${NC}" # Print member in red
  sudo deluser "$member" sudo > /dev/null # Remove member from sudo group
  echo "Mitigated."
done


echo "Checking for other users on the system..."
while IFS=: read -r username _ uid _; do
    # Ignore the root user and users with uid less than 1000
    if [[ "$username" == "root" ]] || [[ "$username" == "nobody" ]] || [[ "$uid" -lt 1000 ]]; then
        continue
    fi

    # Check if the user is in the config file
    if ! grep -q "^$username" "$USER_CONFIG_FILE"; then
        echo -e "${RED}User '$username' exists on the system but is not part of the configuration.${NC}"
    fi
done < /etc/passwd

PASSWORD_CONFIG="
password	requisite	pam_cracklib.so retry=3 minlen=14 maxrepeat=3 dcredit=-1 ucredit=-1 ocredit=-1 lcredit=-1 difok=4
password    [success=1 default=ignore]    pam_unix.so obscure use_authtok try_first_pass sha512 remember=10 minlen=14 rounds=65536
password requisite pam_pwhistory.so use_authtok remember=24 enforce_for_root
password        requisite                       pam_deny.so
password        required                        pam_permit.so
"

# Replace contents of /etc/pam.d/common-password with the new config
echo "$PASSWORD_CONFIG" > /etc/pam.d/common-password

# Print a success message
echo "Configured /etc/pam.d/common-password"

AUTH_CONFIG="
# here are the per-package modules (the \"Primary\" block)
auth required pam_tally2.so audit silent deny=5 onerr=fail unlock_time=900
auth    [success=1 default=ignore]    pam_unix.so 
# here's the fallback if no module succeeds
auth    requisite            pam_deny.so
# prime the stack with a positive return value if there isn't one already;
# this avoids us returning an error just because nothing sets a success code
# since the modules above will each just jump around
auth    required            pam_permit.so
# and here are more per-package modules (the \"Additional\" block)
auth    optional            pam_cap.so
# end of pam-auth-update config
session required pam_lastlog.so showfailed
"

# Replace contents of /etc/pam.d/common-auth with the new config
echo "$AUTH_CONFIG" > /etc/pam.d/common-auth

# Print a success message
echo "Configured /etc/pam.d/common-auth"

# Seems legit
echo "Removing vulnerable PAM configuration files"
find /etc/pam.d -type f -print0 | xargs -0 sed -i /pam_exec/d


# Check for empty passwords in /etc/shadow
while IFS=: read -r username password _; do
    if [ -z "$password" ]; then
        echo -e "${RED}User '$username' has an empty password!${NC}"
    fi
done < /etc/shadow

# Print a success message
echo "Empty password check completed."

# Verify password and shadow files with pwck
if ! pwck >/dev/null; then
    echo -e "${RED}There was an error with the password or shadow files.${NC}" 
    #There is probably a hidden user
fi

if ! grpck >/dev/null; then
    echo -e "${RED}There was an error with the group files.${NC}"
fi

echo "Verified integrity of password files"

find / -user "toor" 2>/dev/null

ROOT_UID=0

if [ $(id -u root) -ne $ROOT_UID ]; then
    echo "Root user does not have UID 0. Removing user with UID 0..."
    userdel -r $(getent passwd $ROOT_UID | cut -d: -f1)

    echo "Setting root user to have UID 0..."
    usermod -u $ROOT_UID root
fi

echo "Root user has UID 0."

# Get a list of users in the root group
users=$(getent group root | cut -d: -f4)

# Loop through each user in the root group and remove them
for user in $users; do
  echo "Removing user $user from the root group"
  sudo gpasswd -d $user root
done

echo "All users removed from the root group."

echo "Unlocking all locked user accounts..."

# Loop through all lines in /etc/passwd and filter out accounts with /sbin/nologin or /usr/sbin/nologin as the shell
# Also exclude root user and users with UID less than 1000

echo -e "${YELLOW}"

while IFS=: read -r user _ uid _ shell; do
    if [[ $shell == "/sbin/nologin" || $shell == "/usr/sbin/nologin" ]]; then
        continue
    fi

    if [[ $user != "root" && $uid -ge 1000 ]]; then
        sudo passwd -u $user > /dev/null
    fi
done < /etc/passwd

echo -e "${NC}"

echo "All locked user accounts have been unlocked."

# Define the new sudoers configuration
NEW_SUDOERS=$(cat <<EOF
Defaults env_reset
Defaults mail_badpass
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
root ALL=(ALL:ALL) ALL
%admin ALL=(ALL) ALL
%sudo ALL=(ALL:ALL) ALL
EOF
)

# Backup the current sudoers file
cp /etc/sudoers /etc/sudoers.bak

# Write the new sudoers configuration to a temporary file
echo "$NEW_SUDOERS" > /tmp/new_sudoers

# Check the syntax of the new sudoers file
if ! visudo -c -f /tmp/new_sudoers; then
  echo "Error: The new sudoers configuration has syntax errors."
  exit 1
fi

# Replace the sudoers file with the new configuration
mv /tmp/new_sudoers /etc/sudoers

echo "The sudoers configuration has been updated."

# Define the new sysctl configuration
NEW_SYSCTL=$(cat <<EOF
kernel.printk = 3 4 1 3
fs.file-max = 65535
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
kernel.ctrl-alt-del = 0
kernel.kptr_restrict = 2
kernel.msgmax = 65535
kernel.msgmnb = 65535
kernel.pid_max = 65535
kernel.randomize_va_space = 2
kernel.shmall = 268435456
kernel.shmmax = 268435456
kernel.sysrq = 0
net.core.default_qdisc = fq
net.core.dev_weight = 64
net.core.netdev_max_backlog = 16384
net.core.optmem_max = 65535
net.core.rmem_default = 262144
net.core.rmem_max = 16777216
net.core.somaxconn = 32768
net.core.wmem_default = 262144
net.core.wmem_max = 16777216
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.bootp_relay = 0
net.ipv4.conf.all.forwarding = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.all.proxy_arp = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.default.forwarding = 0
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.lo.accept_redirects = 0
net.ipv4.conf.lo.accept_source_route = 0
net.ipv4.conf.lo.rp_filter = 1
net.ipv4.icmp_echo_ignore_all = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.ip_forward = 0
net.ipv4.ip_local_port_range = 2000 65000
net.ipv4.ipfrag_low_thresh = 196608
net.ipv4.neigh.default.gc_interval = 30
net.ipv4.neigh.default.gc_thresh1 = 32
net.ipv4.neigh.default.gc_thresh2 = 1024
net.ipv4.neigh.default.gc_thresh3 = 2048
net.ipv4.neigh.default.proxy_qlen = 96
net.ipv4.neigh.default.unres_qlen = 6
net.ipv4.route.flush = 1
net.ipv4.tcp_congestion_control = htcp
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_keepalive_time = 1800
net.ipv4.tcp_max_orphans = 16384
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_orphan_retries = 0
net.ipv4.tcp_reordering = 3
net.ipv4.tcp_retries1 = 3
net.ipv4.tcp_retries2 = 15
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_rmem = 8192 87380 16777216
net.ipv4.tcp_sack = 0
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_syn_retries = 5
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_timestamps = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_window_scaling = 0
net.ipv4.tcp_wmem = 8192 65536 16777216
net.ipv4.udp_rmem_min = 16384
net.ipv4.udp_wmem_min = 16384
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.all.autoconf = 0
net.ipv6.conf.all.forwarding = 0
net.ipv6.conf.default.accept_ra_defrtr = 0
net.ipv6.conf.default.accept_ra_pinfo = 0
net.ipv6.conf.default.accept_ra_rtr_pref = 0
net.ipv6.conf.default.accept_ra=0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.default.log_martians  = 1
net.ipv6.conf.default.autoconf = 0
net.ipv6.conf.default.dad_transmits = 0
net.ipv6.conf.default.forwarding = 0
net.ipv6.conf.default.max_addresses = 1
net.ipv6.conf.default.router_solicitations = 0
net.ipv6.ip6frag_low_thresh = 196608
net.ipv6.route.flush = 1
net.unix.max_dgram_qlen = 50
vm.dirty_background_ratio = 5
vm.dirty_ratio = 30
vm.min_free_kbytes = 65535
vm.mmap_min_addr = 4096
vm.overcommit_memory = 0
vm.overcommit_ratio = 50
vm.swappiness = 30
net.ipv4.ip_forward = 0
net.ipv4.conf.all.log_martians  = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1
kernel.randomize_va_space = 2
EOF
)

# Backup the current sysctl configuration file
cp /etc/sysctl.conf /etc/sysctl.conf.bak

# Write the new sysctl configuration to a temporary file
echo "$NEW_SYSCTL" > /tmp/new_sysctl

# Replace the sysctl configuration file with the new configuration
mv /tmp/new_sysctl /etc/sysctl.conf

# Load the new sysctl configuration
sysctl -p > /dev/null

echo "The sysctl configuration has been updated."

# Check if SSH_REQ is true
if [ "$SSH_REQ" == true ]; then

    # Create a backup of sshd_config
    sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

    # Write new sshd_config
    cat <<EOF > /etc/ssh/sshd_config
Port 300
Protocol 2
PermitRootLogin no
PermitEmptyPasswords no
PermitUserEnvironment no
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
LogLevel VERBOSE
RekeyLimit 1G 1H
KexAlgorithms curve25519-sha256@libssh.org,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256
Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com
MaxAuthTries 2
MaxStartups 2
MaxSessions 5
ClientAliveInterval 300
ClientAliveCountMax 0
LoginGraceTime 60
TCPKeepAlive no
UsePAM no
PasswordAuthentication no #undo if ssh shows as down
ChallengeResponseAuthentication no
HostbasedAuthentication no
PubkeyAuthentication no
AllowAgentForwarding no
AllowTcpForwarding no
X11Forwarding no
PrintMotd no
PrintLastLog no
Compression no
UseDNS yes
StrictModes yes
IgnoreRhosts yes
AuthorizedKeysFile      .ssh/authorized_keys
EOF

    # Restart SSH service
    sudo service ssh restart
    echo "SSH Configured"
fi

if [ "$FTP_REQ" = true ]; then
  

    # backup the original configuration file
    cp /etc/vsftpd.conf /etc/vsftpd.conf.bak

    # update the FTP configuration
    echo "anonymous_enable=NO
local_enable=YES
local_root=/var/www/sub-domains
write_enable=YES
chroot_local_user=YES
allow_writeable_chroot=YES
hide_ids=YES
# Virtual User Settings
user_config_dir=/etc/vsftpd/vsftpd_user_conf
guest_enable=YES
virtual_use_local_privs=YES
pam_service_name=vsftpd
nopriv_user=vsftpd
guest_username=vsftpd
rsa_cert_file=/etc/vsftpd/vsftpd.pem
rsa_private_key_file=/etc/vsftpd/vsftpd.key
ssl_enable=YES
allow_anon_ssl=NO
force_local_data_ssl=YES
force_local_logins_ssl=YES
ssl_tlsv1=YES
ssl_sslv2=NO
ssl_sslv3=NO

pasv_min_port=7000
pasv_max_port=7500
#proftp
AllowOverwrite off" > /etc/vsftpd.conf

    echo "FTP configuration updated successfully!"
fi

if [ "$HTTP_REQ" = true ]; then
	# backup the original configuration file
    cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
	
	# Specify the path to the nginx.conf file
nginx_conf="/etc/nginx/nginx.conf"

# Use a Here Document to write the new configuration to a temporary file
cat > /tmp/nginx.conf.tmp << EOF
#This config is made for user with the basic "nginx-extras" package available on Debian Buster

#Uncomment these two lines for Crowdsec support (tested on Debian 11 - NGINX Extras)
#load_module modules/ndk_http_module.so;
#load_module modules/ngx_http_lua_module.so;


user www-data;
worker_processes auto;
worker_cpu_affinity auto;
pid /run/nginx.pid;

load_module modules/ngx_http_headers_more_filter_module.so;

events {
        worker_connections 16384;
        multi_accept on;
        use epoll;
}

# worker_rlimit_nofile = (worker_connections * 1) + 500
# worker_rlimit_nofile = (worker_connections * 2) + 500 if you use nginx as reverse proxy

worker_rlimit_nofile 16884;


http {
        ##
        # Basic Settings
        ##

        server_names_hash_bucket_size 64;
        # server_name_in_redirect off;

        include /etc/nginx/mime.types;
        default_type application/octet-stream;

        ##VirtualHosts and configs includes
        include /etc/nginx/conf.d/*.conf;
        include /etc/nginx/sites-enabled/*;

        ##
        # TLS
        ##

        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_ecdh_curve X25519:sect571r1:secp521r1:secp384r1;
        ssl_session_timeout 1d;
        ssl_session_cache shared:SSL:50m;
        ssl_session_tickets off;
        ssl_ciphers 'EECDH+AESGCM:EDH+AESGCM:!AES128';
        ssl_prefer_server_ciphers off;


        ##
        # Headers
        #
        ##Less Verbose for Nginx headers
        server_tokens off;

        ##Common headers for security
        ## You need to adapt the configuration to your website need, It may break some shitty content management system or poorly build websites.
        more_set_headers "Content-Security-Policy : default-src https: data: 'unsafe-inline' 'unsafe-eval' always";
        more_set_headers "Permissions-Policy: geolocation=();midi=();notifications=();push=();sync-xhr=();microphone=();camera=();magnetometer=();gyroscope=();speaker self;vibrate=();fullscreen self;payment=();;"
        more_set_headers "Strict-Transport-Security : max-age=15768000; includeSubDomains; preload";
        more_set_headers "X-Frame-Options : SAMEORIGIN";
        more_set_headers "X-Xss-Protection : 1; mode=block";
        more_set_headers "X-Content-Type-Options : nosniff";
        more_set_headers "Referrer-Policy : strict-origin-when-cross-origin";
        more_set_headers "Server : Follow the white rabbit.";
        more_set_headers "Cross-Origin-Opener-Policy : same-origin"
        more_set_headers "Cross-Origin-Embedder-Policy : unsafe-none"
        more_set_headers "Origin-Agent-Cluster : ?1"
        more_set_headers "Permissions-Policy : accelerometer=(), ambient-light-sensor=(), autoplay=(), battery=(), camera=(), clipboard-read=(), clipboard-write=(), display-capture=(), document-domain=(), encrypted-media=(), fullscreen=(), gamepad=(), geolocation=(), gyroscope=(), hid=(), idle-detection=(),  magnetometer=(), microphone=(), midi=(), payment=(), picture-in-picture=(), publickey-credentials-get=(), screen-wake-lock=(), serial=(), speaker-selection=(), sync-xhr=(), usb=(), xr-spatial-tracking=()";

        ##OCSP settings
        ssl_stapling on;
        ssl_stapling_verify on;
        #ssl_trusted_certificate /etc/ssl/private/ocsp-certs.pem; # <- Add signing certs here
        resolver 1.0.0.1 8.8.4.4 valid=300s;
        resolver_timeout 5s;

        ##
        # Logging
        ##

        #access_log /var/log/nginx/access.log; #Disabled for performance

        access_log off;
        error_log /var/log/nginx/error.log;

        ##
        # Gzip
        ##

        gzip on;
        gzip_disable "msie6";
        gzip_vary on;
        gzip_proxied any;
        gzip_comp_level 6;
        gzip_buffers 16 8k;
        gzip_http_version 1.1;
        gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;


        ##
        # GeoIP
        ##

        #GeoIP (optional)
        #geoip_country  /usr/local/share/GeoIP/GeoIP.dat;
        #geoip_city     /usr/local/share/GeoIP/GeoLiteCity.dat;


        ##
        # Performance and Cache
        ##

        #See - https://www.nginx.com/blog/thread-pools-boost-performance-9x/
        aio threads;

        #Enable 0-RTT support for TLS 1.3
        ssl_early_data on;
        proxy_set_header Early-Data $ssl_early_data;

        #Simple DOS mitigation
        ##Max c/s by ip
        limit_conn_zone $binary_remote_addr zone=limit_per_ip:10m;
        limit_conn limit_per_ip 40;

        ##Max rq/s by ip
        limit_req_zone $binary_remote_addr zone=allips:10m rate=400r/s;
        limit_req zone=allips burst=400 nodelay;

        #PHP
        fastcgi_buffers 256 32k;
        fastcgi_buffer_size 256k;
        fastcgi_connect_timeout 4s;
        fastcgi_send_timeout 120s;
        fastcgi_read_timeout 120s;
        fastcgi_busy_buffers_size 512k;
        fastcgi_temp_file_write_size 512K;
        reset_timedout_connection on;

        #Others
        open_file_cache max=2000 inactive=20s;
        open_file_cache_valid 60s;
        open_file_cache_min_uses 5;
        open_file_cache_errors off;

        client_max_body_size 50M;
        client_body_buffer_size 1m;
        client_body_timeout 15;
        client_header_timeout 15;
        keepalive_timeout 65;
        send_timeout 15;
        sendfile on;
        tcp_nopush on;
        tcp_nodelay on;
}
EOF

# Replace the contents of the nginx.conf file with the new configuration
cp /tmp/nginx.conf.tmp $nginx_conf

# Restart Nginx to apply the changes
echo -e "${RED}"
service nginx restart
echo -e "${NC}"

# Remove the temporary file
rm /tmp/nginx.conf.tmp

fi

if [ "MYSQL_REQ" = true ]; then

# Set the MySQL configuration options

mysql_config="/etc/mysql/mysql.conf.d/mysqld.cnf"

cp $mysql_config $mysql_config.bak

echo "bind-address = 127.0.0.1" >> $mysql_config
echo "local-infile = 0" >> $mysql_config
echo "log = /var/log/mysql-logfile" >> $mysql_config

# Create the log file and set its permissions
touch /var/log/mysql-logfile
chown mysql:adm /var/log/mysql-logfile
chmod 640 /var/log/mysql-logfile

# Restart the MySQL service to apply the changes
service mysql restart

fi

# Define the new login.defs configuration
NEW_LOGIN_DEFS=$(cat <<EOF
PASS_MAX_DAYS 30
PASS_MIN_DAYS 5
PASS_MIN_LEN 14
PASS_WARN_AGE 7
PASS_CHANGE_TRIES 3
PASS_ALWAYS_WARN yes
MAIL_DIR /var/spool/mail
EOF
)

# Backup the current login.defs file
cp /etc/login.defs /etc/login.defs.bak

# Write the new login.defs configuration to a temporary file
echo "$NEW_LOGIN_DEFS" > /tmp/new_login_defs

# Replace the login.defs file with the new configuration
mv /tmp/new_login_defs /etc/login.defs

echo "The login.defs configuration has been updated."

# Lock the root user account
passwd -l root

echo "The root user account has been locked."

# Set incoming traffic to Deny
ufw default deny incoming > /dev/null

# Set outgoing traffic to Allow
ufw default allow outgoing > /dev/null

# Enable firewall logging in ufw
ufw logging on
ufw logging high

# Enable ufw
ufw enable

echo "ufw has been configured."

# Set up firewall rules
# iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
# iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
# iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

# Enable firewall logging
iptables -N LOGGING
iptables -A INPUT -j LOGGING
iptables -A LOGGING -m limit --limit 2/min -j LOG --log-prefix "iptables: " --log-level 4
iptables -A LOGGING -j DROP

echo "iptables has been configured."

# Array of packages to check for
PACKAGES=(
  "zenmap"
  "lighttpd"
  "wireshark"
  "tcpdump"
  "rsh-server"
  "deluge"
  "rarcrack"
  "fcrackzip"
  "lcrack"
  "pdfcrack"
  "pyrit"
  "sipcrack"
  "irpas"
  "john-data"
  "openarena"
  "freeciv"
  "minetest"
  "apache2"
  "nginx"
  "mysql"
  "postgresql"
  "mariadb"
  "ssh"
  "vsftpd"
  "smb"
  "hydra"
  "hydra-gtk"
  "netcat"
  "netcat-openbsd"
  "netcat-traditional"
  "john"
  "johnny"
  "aircrack-ng"
  "nikto"
  "cups"
  "apache"
  "nmap"
  "medusa"
  "tightvnc"
  "prelink"
  "ophcrack"
  "ircd-irc2"
  "ftp"
  "nis"
  "rsh-client"
  "talk"
  "telnet"
  "ldap-utils"
  "rsync"
  "dsniff"
  "knocker"
  "ncrack"
  "oclgausscrack"
  "reaver"
  "rebind"
  "bind9"
  "yersinia"
  "remmina"
)

# Loop through each package and check if it exists
for PACKAGE in "${PACKAGES[@]}"
do
  # Use grep to search for the package in the output of dpkg -l
  dpkg -l | grep "$PACKAGE" > /dev/null

  # If the package exists, print a warning message in RED
  if [ $? -eq 0 ]; then
    echo -e "\e[31mWARNING: $PACKAGE is installed\e[0m"
  fi
done

RED='\033[0;31m' # Red color code
NC='\033[0m' # No color code

echo "Searching for prohibited files..."

# List of file extensions to search for
EXTENSIONS=("mp3" "sh" "wav" "wma" "aac" "m4a" "ogg" "avi" "mp4" "flv" "wmv" "mov" "webm" "mpg" "mpeg" "gif" "png" "jpg" "jpeg" "pdf" "docx" "txt" "zip" "tgz" "deb" "tar" "tar.*" "exe")

# Search for prohibited files in /home
for ext in "${EXTENSIONS[@]}"; do
    find /home -name "*.$ext" -type f -print0 | while read -d $'\0' file; do
        echo -e "${RED}Prohibited file found:${NC} $file"
        # You can delete the prohibited file by uncommenting the following line
        # rm -f "$file"
    done
done

echo "Prohibited file search completed."

echo "Ensuring rc.local is closed"
cp /etc/rc.local /etc/rc.local.bak
echo "exit 0" > /etc/rc.local
sudo systemctl enable rc-local &> /dev/null
#I suppressed this error since it wasn't too relevant

echo "Securing crontab"
# Set the path to the crontab file
CRONTAB_FILE="/etc/crontab"

# Create a backup of crontab
cp $CRONTAB_FILE $CRONTAB_FILE.bak

# Remove all startup tasks from crontab
sed -i '/@reboot/d' $CRONTAB_FILE

SERVICES=(
    # Database
    "mysqld"
    "postgres"

    # E-mail
    "dovecot"
    "exim4"
    "postfix"

    # File Sharing
    "nfs"
    "nmbd"
    "rpc.mountd"
    "rpc.nfsd"
    "smbd"
    "vsftpd"
    "samba"

    # Music
    "mpd"

    # Networking
    "avahi-daemon"
    "bind"
    "bind9"
    "dnsmasq"
    "xinetd"
    "inetd"
    "sshd"
    "telnet"

    # Printing, Scanning
    "cupsd"
    "saned"

    # Time
    "ntpd"
    "cron"

    # Web/Application Server
    "apache2"
    "httpd"
    "jetty"
    "nginx"
    "tomcat"
)

echo "Checking for unwanted services..."

for service in "${SERVICES[@]}"
do
    if systemctl list-unit-files | grep -q "^$service.*"; then
        echo -e "${RED}Service '$service' detected.${NC}"
    fi
done

# Get a list of all listening services
listening_services=$(sudo netstat -tulpn | grep LISTEN | awk '{print $NF}' | sort | uniq)

# Print the list of listening services and their executable locations
echo "Listening services and their executable locations:"
while read -r service; do
    # Extract the PID of the service
    pid=$(sudo netstat -tulpn | grep ":$service " | awk '{print $7}' | cut -d'/' -f1)
    # Get the location of the executable using the PID
    location=$(sudo readlink -f /proc/$pid/exe)
    # Print the service name and its executable location
    echo -e "${RED}[LISTENING]${NC} - $service: $location"
done <<< "$listening_services"

# Get a list of all open ports
open_ports=$(sudo ss -ln | awk '/LISTEN/ {print $4}' | cut -d':' -f2 | sort -n | uniq)

# If there are no open ports, exit the script
if [[ -z "$open_ports" ]]; then
  echo "No open ports found"
  exit 0
fi

# Print the list of open ports in RED
echo -e "Open ports:${RED}\n$open_ports${NC}"

echo "Enabling automatic updates"

# Configure automatic updates
sudo dpkg-reconfigure -pmedium unattended-upgrades

# Enable automatic updates for security patches
sudo sed -i 's#//\s*\(.*security.*\)#\1#' /etc/apt/sources.list
echo 'APT::Periodic::Update-Package-Lists "1";' | sudo tee /etc/apt/apt.conf.d/20auto-upgrades
echo 'APT::Periodic::Unattended-Upgrade "1";' | sudo tee -a /etc/apt/apt.conf.d/20auto-upgrades
echo 'APT::Periodic::AutocleanInterval "7";' | sudo tee -a /etc/apt/apt.conf.d/20auto-upgrades
sudo sed -i 's#//\s*\(.*APT::Periodic::Update-Package-Lists.*\)#\1#' /etc/apt/apt.conf.d/10periodic
sudo sed -i 's#//\s*\(.*APT::Periodic::Download-Upgradeable-Packages.*\)#\1#' /etc/apt/apt.conf.d/10periodic
sudo sed -i 's#//\s*\(.*APT::Periodic::AutocleanInterval.*\)#\1#' /etc/apt/apt.conf.d/10periodic
sudo sed -i 's#//\s*\(.*APT::Periodic::Unattended-Upgrade.*\)#\1#' /etc/apt/apt.conf.d/10periodic

echo "Setting Firefox as the default browser"

# Set Firefox as the default browser
sudo update-alternatives --set x-www-browser /usr/bin/firefox

echo "Configuring Firefox Settings"

# Download user.js from GitHub
wget -q -O - https://raw.githubusercontent.com/pyllyukko/user.js/master/user.js > user.js

# Parse user.js and write syspref.js
while read line
do
  # Ignore comments and empty lines
  if [[ $line == \#* ]] || [[ -z $line ]]; then
    continue
  fi

  # Replace 'user_pref(' with 'pref(' and write to syspref.js
  echo "${line/user_pref(/pref(}" >> /etc/firefox/syspref.js
done < user.js

# Remove temporary user.js file
rm user.js

# Restart Firefox
killall firefox > /dev/null

echo "Firefox Configured"

echo "Configuring auditd"

# Enable auditd
sudo systemctl enable auditd.service > /dev/null

# Set auditd rules
sudo tee /etc/audit/rules.d/audit.rules > /dev/null <<EOF
# Delete all existing rules
-D

# Set the audit control flag to keep the audit data even if the audit daemon stops
-f 2

# Set the audit rate to 100 events per second
-b 100

# Monitor file system modifications
-w /etc/group -p wa -k group_modification
-w /etc/passwd -p wa -k passwd_modification
-w /etc/shadow -p wa -k shadow_modification
-w /etc/sudoers -p wa -k sudoers_modification

# Monitor system calls
-a exit,always -F arch=b64 -S adjtimex -S settimeofday -k time_change
-a exit,always -F arch=b32 -S adjtimex -S settimeofday -S stime -k time_change
-a exit,always -F arch=b64 -S clock_settime -k time_change
-a exit,always -F arch=b32 -S clock_settime -k time_change
-a exit,always -F arch=b64 -S time -k time_change
-a exit,always -F arch=b32 -S time -k time_change
EOF

sudo auditctl -e 1 > /dev/null

echo "Configuring /etc/hosts"

# Create a backup of the current /etc/hosts file
sudo cp /etc/hosts /etc/hosts.bak

# Set the contents of /etc/hosts to only include localhost and ubuntu
sudo cat > /etc/hosts << EOF
127.0.0.1   localhost
127.0.1.1   ubuntu
EOF

# Restart networking service to apply changes
systemctl restart networking.service &> /dev/null
systemctl restart systemd-networkd
systemctl restart NetworkManager

echo "Setting up file permissions"

sudo chmod 0644 /etc/passwd /etc/passwd- /etc/group /etc/group- /etc/fstab  > /dev/null
sudo chmod 0640 /etc/shadow /etc/shadow- /etc/gshadow /etc/gshadow-  > /dev/null
sudo chown root:root /etc/fstab /etc/passwd /etc/shadow /etc/group /var/spool/cron  > /dev/null
sudo chown root:root /home > /dev/null
sudo chmod 755 /home > /dev/null
sudo chown root:root /root > /dev/null
sudo chown 700 /root > /dev/null
sudo chmod -R 444 /var/log > /dev/null
sudo chmod -R 444 /etc/ssh > /dev/null
sudo chmod 000 /media/ > /dev/null
sudo chmod 0700 /etc/rc* > /dev/null
sudo chmod 0700 /etc/init.d* > /dev/null
sudo chmod 0700 /etc/sysctl.conf > /dev/null
sudo chmod 0700 /etc/inittab &> /dev/null
sudo chown root:root /etc/anacrontab > /dev/null
sudo chmod og-rwx /etc/anacrontab > /dev/null
sudo chown root:root /etc/crontab > /dev/null
sudo chmod og-rwx /etc/crontab > /dev/null
sudo chown root:root /etc/cron.hourly > /dev/null
sudo chmod og-rwx /etc/cron.hourly > /dev/null
sudo chown root:root /etc/cron.daily > /dev/null
sudo chmod og-rwx /etc/cron.daily > /dev/null
sudo chown root:root /etc/cron.weekly > /dev/null
sudo chmod og-rwx /etc/cron.weekly > /dev/null
sudo chown root:root /etc/cron.monthly > /dev/null
sudo chmod og-rwx /etc/cron.monthly > /dev/null
sudo chown root:root /etc/cron.d > /dev/null
sudo chmod og-rwx /etc/cron.d > /dev/null
sudo chmod 0700 /etc/profile	 > /dev/null
sudo chmod 0700 /etc/hosts.allow	 > /dev/null
sudo chmod 0700 /etc/mtab &> /dev/null
sudo chmod 0700 /etc/utmp &> /dev/null
sudo chmod 0700 /var/adm/wtmp &> /dev/null
sudo chmod 0700 /var/log/wtmp > /dev/null
sudo chmod 0700 /etc/syslog.pid &> /dev/null
sudo chmod 0700 /var/run/syslog.pid &> /dev/null
sudo chmod 02750 /bin/ping > /dev/null
sudo chmod 02750 /sbin/ifconfig > /dev/null
sudo chmod 02750 /usr/bin/w > /dev/null
sudo chmod 02750 /usr/bin/who > /dev/null
sudo chmod 02750 /usr/bin/locate &> /dev/null
sudo chmod 02750 /usr/bin/whereis > /dev/null 
sudo rm /etc/cron.deny &> /dev/null
sudo rm /etc/at.deny &> /dev/null
sudo echo “root” &> cron.allow
sudo echo “root” &> at.allow
sudo chmod og-rwx /etc/cron.allow &> /dev/null
sudo chmod og-rwx /etc/at.allow &> /dev/null
sudo chown root:root /etc/cron.allow &> /dev/null
sudo chown root:root /etc/at.allow &> /dev/null

# Shutdown and disable the insecure services
sudo systemctl stop rlogin.socket &> /dev/null
sudo systemctl disable rlogin.socket &> /dev/null

sudo systemctl stop rsh.socket &> /dev/null
sudo systemctl disable rsh.socket &> /dev/null

sudo systemctl stop rexec.socket &> /dev/null
sudo systemctl disable rexec.socket &> /dev/null

sudo systemctl stop rbootd.socket &> /dev/null
sudo systemctl disable rbootd.socket &> /dev/null

sudo systemctl stop rquota.socket &> /dev/null
sudo systemctl disable rquota.socket  &> /dev/null

sudo systemctl stop rstat.socket  &> /dev/null
sudo systemctl disable rstat.socket  &> /dev/null

sudo systemctl stop rusers.socket  &> /dev/null
sudo systemctl disable rusers.socket  &> /dev/null
 
sudo systemctl stop rwalld.socket  &> /dev/null
sudo systemctl disable rwalld.socket  &> /dev/null

sudo systemctl stop rexd.socket  &> /dev/null
sudo systemctl disable rexd.socket  &> /dev/null

# Remove/disable tftpd
sudo systemctl disable tftpd-hpa &> /dev/null

# Disable SNMP daemon
sudo systemctl disable snmpd &> /dev/null

echo "Disabled insecure services"

sudo echo 'install usb-storage /bin/true' >> /etc/modprobe.d/disable-usb-storage.conf
sudo echo "blacklist firewire-core" >> /etc/modprobe.d/firewire.conf
sudo echo "blacklist thunderbolt" >> /etc/modprobe.d/thunderbolt.conf

echo "Disabled USBs"

# Split PATH into an array
IFS=':' read -ra dirs <<< "$PATH"

# Loop through each directory in PATH
for i in "${!dirs[@]}"
do
    dir="${dirs[$i]}"
    
    # Check if the directory is empty or current directory
    if [ "$dir" = "" ] || [ "$dir" = "." ]; then
        unset dirs[$i] # Remove directory from the array
    fi
done

echo "Removed empty directories and current directories from PATH"

# Join the remaining directories back into PATH
new_path=$(IFS=:; echo "${dirs[*]}")
export PATH="$new_path"
echo "PATH updated: $PATH"

# Set the directory where kernel modules are stored
MODULE_DIR="/lib/modules/$(uname -r)/kernel"

# Loop through all files in the module directory
for file in $(find "$MODULE_DIR" -type f)
do
    # Check if the file is a kernel module
    if [[ "$file" == *.ko ]]; then
        
        # Ensure the file is owned by root
        chown root:root "$file"
        
        # Ensure the file has secure permissions (read and write for root only)
        chmod 600 "$file"
    fi
done

echo "Kernel modules ownership and permissions updated."

# Run rkhunter scan in a separate terminal window
echo "Starting malware scans in a new terminal window..."

# Command to run in a separate terminal window
cmd="echo 'Checking for suspicious files in /tmp and /var/tmp...'; find /tmp /var/tmp -type f -mtime -1 -exec ls -lah {} \; echo 'Checking for suspicious processes...'; ps aux | awk '{print \$11}' | grep -v '^COMMAND\$' | sort | uniq -c | sort -n; echo 'Running chkrootkit...'; chkrootkit -q; echo 'Configuring rkhunter...'; sudo rkhunter --propupd; rkhunter -c --sk --enable all --disable none"

# Run the command in a separate terminal window
run_in_terminal "$cmd"

echo "Successfully conscripted chkrootkit, rkhunter, and other antimalware programs"

echo "Searching for Unwanted SUID and SGID Binaries"

# Find SUID and SGID files and make the output red
find / \( -perm -4000 -o -perm -2000 \) -print 2>&1 | sed "s@.*@\x1b[31m&\x1b[0m@"

# Find files with SETUID, SETGID and Sticky bit set and make the output red
find / -path -prune -o -type f -perm +6000 -ls 2>&1 | sed "s@.*@\x1b[31m&\x1b[0m@"

echo "Searching for World-Writable and Noowner Files"

# Find world-writable directories and make the output red
find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print 2>&1 | sed "s@.*@\x1b[31m&\x1b[0m@"

# Find files and directories without an associated user or group ID and make the output red
find / -xdev \( -nouser -o -nogroup \) -print 2>&1 | sed "s@.*@\x1b[31m&\x1b[0m@"

echo "Making the password files immutable"
chattr +i /etc/passwd
chattr +i /etc/shadow

echo "Configuring logcheck"

# Configure logcheck
sudo dpkg-reconfigure logcheck

# Modify logcheck configuration files
sudo sed -i 's/REPORTLEVEL=server/REPORTLEVEL=workstation/' /etc/logcheck/logcheck.conf

# Restart logcheck service
sudo service logcheck restart

echo "Configuring fail2ban"

# Copy the default configuration file
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Modify the configuration file
sudo sed -i 's/bantime  = 10m/bantime  = 1h/' /etc/fail2ban/jail.local
sudo sed -i 's/maxretry = 5/maxretry = 3/' /etc/fail2ban/jail.local

# Restart fail2ban service
sudo service fail2ban restart

echo "Remounting /boot as read-only"

# Backup the current /boot/fstab file
sudo cp /boot/fstab /boot/fstab.bak

# Add a new entry to /boot/fstab to mount /boot as read-only
echo "/dev/mapper/boot_crypt /boot ext2 ro,defaults 0 2" | sudo tee -a /boot/fstab > /dev/null

# Remount the /boot partition with read-only permissions
sudo mount -o remount,ro /boot

echo "Configuring Debsums"

# Verify package integrity
sudo debsums_init 

# Generate checksums for all installed packages
sudo debsums -g > /var/lib/dpkg/info/PACKAGE.md5sums

# Check the integrity of all installed packages' binaries
sudo debsums -c > /dev/null

# Check the integrity of all installed packages' binaries and configuration files
sudo debsums -a > /dev/null

# Configure daily verification
#sudo sh -c 'echo "DPkg::Post-Invoke {\"if [ -x /usr/bin/debsums ]; then /usr/bin/debsums --silent --changed; fi\";};" >> /etc/apt/apt.conf.d/99debsums'

# Enable email notifications
sudo sh -c 'echo "debsums -s 2>&1 | mail -s \"debsums report\" root" >> /etc/cron.daily/debsums'

echo "Script Finished"
