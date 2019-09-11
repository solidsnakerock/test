#!/bin/sh

# Create secure audit rules
cat <<EOF > /etc/audit/rules.d/audit.rules
# DISA STIG Audit Rules
## Add keys to the audit rules below using the -k option to allow for more
## organized and quicker searches with the ausearch tool.  See auditctl(8)
## and ausearch(8) for more information.
# Remove any existing rules
-D
# Increase kernel buffer size
-b 16384
# Failure of auditd causes a kernel panic
-f 2
###########################
## DISA STIG Audit Rules ##
###########################
# Watch syslog configuration
-w /etc/rsyslog.conf
-w /etc/rsyslog.d/
# Watch PAM and authentication configuration
-w /etc/pam.d/ -p wxa -k pam
-w /etc/nsswitch.conf
# Watch system log files
-w /var/log/messages
-w /var/log/audit/ -p wxa -k audittampering
# Watch audit configuration files
-w /etc/audit/auditd.conf -p wa
-w /etc/audit/audit.rules -p wa
# Watch login configuration
-w /etc/login.defs
-w /etc/securetty
-w /etc/resolv.conf
# Watch cron and at
-w /etc/at.allow
-w /etc/at.deny
-w /var/spool/at/
-w /etc/crontab
-w /etc/anacrontab
-w /etc/cron.allow
-w /etc/cron.deny
-w /etc/cron.d/
-w /etc/cron.hourly/
-w /etc/cron.weekly/
-w /etc/cron.monthly/
# Watch shell configuration
-w /etc/profile.d/
-w /etc/profile
-w /etc/shells
-w /etc/bashrc
-w /etc/csh.cshrc
-w /etc/csh.login
# Watch kernel configuration
-w /etc/sysctl.conf
-w /etc/modprobe.conf
# Watch linked libraries
-w /etc/ld.so.conf -p wa
-w /etc/ld.so.conf.d/ -p wa
# Watch init configuration
-w /etc/rc.d/init.d/
-w /etc/sysconfig/
-w /etc/inittab -p wa
-w /etc/rc.local
-w /usr/lib/systemd/
-w /etc/systemd/
# Watch filesystem and NFS exports
-w /etc/fstab
-w /etc/exports
# Watch xinetd configuration
-w /etc/xinetd.conf
-w /etc/xinetd.d/
# Watch Grub2 configuration
-w /etc/grub2.cfg
-w /etc/grub.d/
# Watch TCP_WRAPPERS configuration
-w /etc/hosts.allow
-w /etc/hosts.deny
# Watch sshd configuration
-w /etc/ssh/sshd_config
# Watch auditing in Docker files and directories
-w /usr/bin/docker -p wa
-w /var/lib/docker -p wa
-w /etc/docker -p wa
-w /lib/systemd/system/docker.service -p wa
-w /lib/systemd/system/docker.socket -p wa
-w /etc/default/docker -p wa
-w /etc/docker/daemon.json -p wa
-w /usr/bin/docker-containerd -p wa
-w /usr/bin/docker-runc -p wa
# Audit system events
-a always,exit -F arch=b32 -S acct -S reboot -S sched_setparam -S sched_setscheduler -S setrlimit -S swapon
-a always,exit -F arch=b64 -S acct -S reboot -S sched_setparam -S sched_setscheduler -S setrlimit -S swapon
# Audit any link creation
-a always,exit -F arch=b32 -S link -S symlink
-a always,exit -F arch=b64 -S link -S symlink
##############################
## NIST 800-53 Requirements ##
##############################
#2.6.2.4.1 Records Events that Modify Date and Time Information
-a always,exit -F arch=b32 -S adjtimex -S stime -S settimeofday -S clock_settime -k time-change
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
#2.6.2.4.2 Record Events that Modify User/Group Information
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
#2.6.2.4.3 Record Events that Modify the Systems Network Environment
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k audit_network_modifications
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k audit_network_modifications
-w /etc/issue -p wa -k audit_network_modifications
-w /etc/issue.net -p wa -k audit_network_modifications
-w /etc/hosts -p wa -k audit_network_modifications
-w /etc/sysconfig/network -p wa -k audit_network_modifications
#2.6.2.4.4 Record Events that Modify the System Mandatory Access Controls
-w /etc/selinux/ -p wa -k MAC-policy
#2.6.2.4.5 Ensure auditd Collects Logon and Logout Events
-w /var/log/tallylog -p wa -k logins
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
#2.6.2.4.6 Ensure auditd Collects Process and Session Initiation Information
-w /var/run/utmp -p wa -k session
-w /var/log/btmp -p wa -k session
-w /var/log/wtmp -p wa -k session
#2.6.2.4.12 Ensure auditd Collects System Administrator Actions
-w /etc/sudoers -p wa -k actions
#2.6.2.4.13 Make the auditd Configuration Immutable
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b32 -S init_module -S delete_module -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
# Ignore all the anonymous events. Often tagged on every rule, but ignoring
# up front should improve processing time
-a exit,never -F auid=4294967295
# Ignore system services
-a exit,never -F auid<1000
#2.6.2.4.7 Ensure auditd Collects Discretionary Access Control Permission Modification Events
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -k perm_mod
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -k perm_mod
#2.6.2.4.8 Ensure auditd Collects Unauthorized Access Attempts to Files (unsuccessful)
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -k access
#2.6.2.4.9 Ensure auditd Collects Information on the Use of Privileged Commands
-a always,exit -F path=/usr/sbin/semanage -F perm=x -F key=privileged-priv_change
-a always,exit -F path=/usr/sbin/setsebool -F perm=x -F key=privileged-priv_change
-a always,exit -F path=/usr/bin/chcon -F perm=x -F key=privileged-priv_change
-a always,exit -F path=/usr/sbin/restorecon -F perm=x -F key=privileged-priv_change
-a always,exit -F path=/usr/bin/userhelper -F perm=x -F key=privileged
-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F key=privileged
-a always,exit -F path=/usr/libexec/pt_chown -F perm=x -F key=privileged
#Loading / Unloading of LKM's
-w /bin/kmod -p x -k kernelmodules
EOF

#### Networking hardening
# Ignore ICMP broadcast requests
echo "net.ipv4.icmp_echo_ignore_broadcasts = 1" >> /etc/sysctl.d/10-network-security.conf
echo "net.ipv4.conf.default.rp_filter=1" >> /etc/sysctl.d/10-network-security.conf
echo "net.ipv4.conf.all.rp_filter=1" >> /etc/sysctl.d/10-network-security.conf

# Disable source packet routing
echo "net.ipv4.conf.all.accept_source_route = 0" >> /etc/sysctl.d/10-network-security.conf
echo "net.ipv6.conf.all.accept_source_route = 0" >> /etc/sysctl.d/10-network-security.conf
echo "net.ipv4.conf.default.accept_source_route = 0" >> /etc/sysctl.d/10-network-security.conf
echo "net.ipv6.conf.default.accept_source_route = 0" >> /etc/sysctl.d/10-network-security.conf

# Ignore send redirects
echo "net.ipv4.conf.all.send_redirects = 0" >> /etc/sysctl.d/10-network-security.conf
echo "net.ipv4.conf.default.send_redirects = 0" >> /etc/sysctl.d/10-network-security.conf
echo "net.ipv4.tcp_syncookies=1" >> /etc/sysctl.d/10-network-security.conf

# Block SYN attacks
echo "net.ipv4.tcp_max_syn_backlog = 2048" >> /etc/sysctl.d/10-network-security.conf
echo "net.ipv4.tcp_synack_retries = 2" >> /etc/sysctl.d/10-network-security.conf
echo "net.ipv4.tcp_syn_retries = 5" >> /etc/sysctl.d/10-network-security.conf

# Log Martians
echo "net.ipv4.conf.all.log_martians = 1" >> /etc/sysctl.d/10-network-security.conf
echo "net.ipv4.icmp_ignore_bogus_error_responses = 1" >> /etc/sysctl.d/10-network-security.conf

# Ignore ICMP redirects
echo "net.ipv4.conf.all.accept_redirects = 0" >> /etc/sysctl.d/10-network-security.conf
echo "net.ipv6.conf.all.accept_redirects = 0" >> /etc/sysctl.d/10-network-security.conf
echo "net.ipv4.conf.default.accept_redirects = 0" >> /etc/sysctl.d/10-network-security.conf
echo "net.ipv6.conf.default.accept_redirects = 0" >> /etc/sysctl.d/10-network-security.conf

# Zeroconf Disable [https://access.redhat.com/solutions/8627]
echo "NOZEROCONF=yes" >> /etc/sysconfig/network

# Files Permissions
chmod 640 /etc/rsyslog.conf

# Disabling RDS protects the system [https://www.stigviewer.com/stig/red_hat_enterprise_linux_6/2013-02-05/finding/RHEL-06-000126]
# Disabling uncommon protocols 
echo "install rds /bin/false" > /etc/modprobe.d/rds.conf
echo "install dccp /bin/false" > /etc/modprobe.d/dccp.conf
echo "install sctp /bin/false" > /etc/modprobe.d/sctp.conf
echo "install tipc /bin/false" > /etc/modprobe.d/tipc.conf

# The portmap service should be disabled
systemctl disable rpcbind; systemctl disable rpcbind.socket
systemctl stop rpcbind; systemctl stop rpcbind.socket

# Kernel Hardening
echo "kernel.exec-shield = 1" >> /etc/sysctl.conf
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf
# Restrict dmesg
echo "kernel.dmesg_restrict = 1" > /etc/sysctl.d/10-kernel-security.conf

# Compliance Scan and remediate
oscap xccdf eval --profile xccdf_org.ssgproject.content_profile_pci-dss --fetch-remote-resources --remediate /usr/share/xml/scap/ssg/content/ssg-centos7-ds.xml || true

rm -rf ~/.ssh/*
rm -rf /root/*
rm -f ~/.bash_history
