###################################
## Disable Redundant Filesystems ##
###################################
touch /etc/modprobe.d/CIS.con
cat >/etc/modprobe.d/CIS.conf <<-EOF
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
EOF

#######################
## Enforce GPG Check ##
#######################
sed -i 's/gpgcheck=0/gpgcheck=1/g' /etc/yum.conf

#######################
## Update the Server ##
#######################
yum update -y

#########################
## Enable Auto Updates ##
#########################
yum install yum-cron -y
sed -i 's/apply_updates = no/apply_updates = yes/g' /etc/yum/yum-cron.conf
systemctl start yum-cron
systemctl enable yum-cron

#############################################################
## Install Advanced Intrusion Detection Environment (AIDE) ##
#############################################################
yum install aide -y
/usr/sbin/aide --init -B 'database_out=file:/var/lib/aide/aide.db.gz'

# Schedule daily file integrity checks
echo "0 5 * * * root /usr/sbin/aide --check" >> /etc/crontab

###########################
## Remove SETroubleshoot ##
###########################
yum erase setroubleshoot -y

####################################
## Remove MCS Translation Service ##
####################################
yum erase mcstrans -y

################################
## Set Root Ownership on GRUB ##
################################
chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg

########################
## Disable Core Dumps ##
########################
echo "* hard core 0" >> /etc/security/limits.conf
echo "fs.suid_dumpable = 0" >> /etc/sysctl.conf

#######################################################
## Enable Randomised Virtual Memory Region Placement ##
#######################################################
echo "kernel.randomize_va_space = 2" >> /etc/sysctl.conf

####################################
## Remove/Disable Legacy Services ##
####################################
chkconfig chargen-dgram off
chkconfig chargen-stream off
chkconfig daytime-dgram off
chkconfig daytime-stream off
chkconfig echo-dgram off
chkconfig echo-stream off
chkconfig tcpmux-server off

######################
## Set Daemon Umask ##
######################
echo "umask 027" >> /etc/sysconfig/init

############################
## Remove X Window System ##
############################
cd /etc/lib/systemd/system/
unlink default.target
ln -s /usr/lib/systemd/system/multi-user.target default.target
yum remove xorg-x11-server-common -y

#############################
## Remove/Disable Services ##
#############################
systemctl disable avahi-daemon cups nfslock rpcgssd rpcbind rpcidmapd rpcsvcgssd

yum erase dhcp openldap-servers openldap-clients bind vsftpd httpd dovecot samba squid net-snmp telnet-server telnet rsh-server rsh ypbind ypserv tftp tftp-server talk talk-server xinetd -y

#############
## Fix NTP ##
#############
yum install ntp -y
cat > /etc/ntp.conf <<-EOF
driftfile /var/lib/ntp/drift
restrict default kod nomodify notrap nopeer noquery
restrict -6 default kod nomodify notrap nopeer noquery
restrict 127.0.0.1
restrict ::1
server 0.centos.pool.ntp.org iburst
server 1.centos.pool.ntp.org iburst
server 2.centos.pool.ntp.org iburst
server 3.centos.pool.ntp.org iburst
includefile /etc/ntp/crypto/pw
keys /etc/ntp/keys
disable monitor
EOF

echo "OPTIONS=\"-u ntp:ntp\"" >> /etc/sysconfig/ntpd

systemctl start ntpd
systemctl enable ntpd

####################################
## Set Postfix to Local-Only Mode ##
####################################
sed -i 's/^inet_interfaces .*$/inet_interfaces = localhost/g' /etc/postfix/main.cf
systemctl restart postfix

###########################
## Network Configuration ##
###########################
echo "net.ipv4.ip_forward=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0" >> /etc/sysctl.conf

/sbin/sysctl -w net.ipv4.ip_forward=0
/sbin/sysctl -w net.ipv4.conf.all.send_redirects=0
/sbin/sysctl -w net.ipv4.conf.default.send_redirects=0
/sbin/sysctl -w net.ipv4.conf.all.accept_source_route=0
/sbin/sysctl -w net.ipv4.conf.default.accept_source_route=0
/sbin/sysctl -w net.ipv4.conf.all.accept_redirects=0
/sbin/sysctl -w net.ipv4.conf.default.accept_redirects=0
/sbin/sysctl -w net.ipv4.conf.all.secure_redirects=0
/sbin/sysctl -w net.ipv4.conf.default.secure_redirects=0
/sbin/sysctl -w net.ipv4.conf.all.log_martians=1
/sbin/sysctl -w net.ipv4.conf.default.log_martians=1
/sbin/sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
/sbin/sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
/sbin/sysctl -w net.ipv4.conf.all.rp_filter=1
/sbin/sysctl -w net.ipv4.conf.default.rp_filter=1
/sbin/sysctl -w net.ipv4.tcp_syncookies=1
/sbin/sysctl -w net.ipv4.route.flush=1
/sbin/sysctl -w net.ipv6.conf.all.accept_ra=0
/sbin/sysctl -w net.ipv6.conf.default.accept_ra=0
/sbin/sysctl -w net.ipv6.conf.all.accept_redirects=0
/sbin/sysctl -w net.ipv6.conf.default.accept_redirects=0
/sbin/sysctl -w net.ipv6.route.flush=1

yum install tcp_wrappers -y

#############################
## Create /etc/hosts.allow ##
#############################
echo "ALL: 10.1.1.0/255.255.255.0" >> /etc/hosts.allow
chmod 644 /etc/hosts.allow

############################
## Create /etc/hosts.deny ##
############################
echo "ALL: ALL" >> /etc/hosts.deny
chmod 644 /etc/hosts.deny

########################################
## Disable Uncommon Network Protocols ##
########################################
echo "install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true" >> /etc/modprobe.d/CIS.conf

######################
## Enable Firewalld ##
######################
yum install firewalld -y
systemctl enable firewalld
systemctl start firewalld

####################
## Install Syslog ##
####################
yum install rsyslog -y
systemctl enable rsyslog
systemctl start rsyslog

######################
## Configure Syslog ##
######################
cat >/etc/rsyslog.conf <<-EOF
\$ModLoad imuxsock
\$ModLoad imjournal
\$WorkDirectory /var/lib/rsyslog
\$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat
\$IncludeConfig /etc/rsyslog.d/*.conf
\$OmitLocalLogging on
\$IMJournalStateFile imjournal.state
*.info;authpriv.none;cron.none /var/log/messages
auth,user.* /var/log/messages
kern.* /var/log/kern.log
daemon.* /var/log/daemon.log
syslog.* /var/log/syslog
lpr,news,uucp,local0,local1,local2,local3,local4,local5,local6.* /var/log/unused.log
authpriv.* /var/log/secure
mail.* /var/log/maillog
cron.* /var/log/cron
*.emerg :omusrmsg:*
uucp,news.crit /var/log/spooler
local7.* /var/log/boot.log
*.* @@10.1.1.122:514
EOF

touch /var/log/kern.log
chown root:root /var/log/kern.log
chmod og-rwx /var/log/kern.log

systemctl restart rsyslog

########################
## Configure Auditing ##
########################
systemctl start auditd
systemctl enable auditd

cat > /etc/audit/auditd.conf <<-EOF
log_file = /var/log/audit/audit.log
log_format = RAW
log_group = root
priority_boost = 4
flush = INCREMENTAL
freq = 20
num_logs = 5
disp_qos = lossy
dispatcher = /sbin/audispd
name_format = NONE
##name = mydomain
max_log_file = 100
max_log_file_action = keep_logs
space_left = 75
space_left_action = email
action_mail_acct = root
admin_space_left = 50
admin_space_left_action = halt
disk_full_action = SUSPEND
disk_error_action = SUSPEND
##tcp_listen_port =
tcp_listen_queue = 5
tcp_max_per_addr = 1
##tcp_client_ports = 1024-65535
tcp_client_max_idle = 0
enable_krb5 = no
krb5_principal = auditd
##krb5_key_file = /etc/audit/audit.key
EOF


##############################################################
## Enable Auditing for Processes that Start Prior to auditd ##
##############################################################
echo 'GRUB_CMDLINE_LINUX="audit=1"' >> /etc/default/grub
grub2-mkconfig -o /boot/grub2/grub.cfg

#########################################################
## Record Events that Modify Date and Time Information ##
#########################################################
echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change 
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change 
-a always,exit -F arch=b32 -S clock_settime -k time-change 
-w /etc/localtime -p wa -k time-change" >> /etc/audit/rules.d/audit.rules

######################################################
## Record Events that Modify User/Group Information ##
######################################################
echo "-w /etc/group -p wa -k identity 
-w /etc/passwd -p wa -k identity 
-w /etc/gshadow -p wa -k identity 
-w /etc/shadow -p wa -k identity 
-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/rules.d/audit.rules

############################################################
## Record Events that Modify System's Network Environment ##
############################################################
echo "-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale 
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale 
-w /etc/issue -p wa -k system-locale 
-w /etc/issue.net -p wa -k system-locale 
-w /etc/hosts -p wa -k system-locale 
-w /etc/sysconfig/network -p wa -k system-locale" >> /etc/audit/rules.d/audit.rules

#########################################################
## Record Events that Modify Mandatory Access Controls ##
#########################################################
echo "-w /etc/selinux/ -p wa -k MAC-policy" >> /etc/audit/rules.d/audit.rules

#####################################
## Collect Login and Logout Events ##
#####################################
echo "-w /var/log/faillog -p wa -k logins 
-w /var/log/lastlog -p wa -k logins 
-w /var/log/tallylog -p wa -k logins" >> /etc/audit/rules.d/audit.rules

############################################
## Collect Session Initiation Information ##
############################################
echo "-w /var/run/utmp -p wa -k session 
-w /var/log/wtmp -p wa -k session 
-w /var/log/btmp -p wa -k session" >> /etc/audit/rules.d/audit.rules

#########################################################################
## Collect Discretionary Access Control Permission Modification Events ##
#########################################################################
echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod 
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod" >> /etc/audit/rules.d/audit.rules

###############################################################
## Collect Unsuccessful Unauthorised Access Attemps to Files ##
###############################################################
echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access 
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access 
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access 
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access" >> /etc/audit/rules.d/audit.rules

########################################
## Collect Use of Privileged Commands ##
########################################

###########################################
## Collect Successful File System Mounts ##
###########################################
echo "-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts 
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts" >> /etc/audit/rules.d/audit.rules

##########################################
## Collect File Deletion Events by User ##
##########################################
echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete 
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete" >> /etc/audit/rules.d/audit.rules

####################################################
## Collect Changes to System Administration Scope ##
####################################################
echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/rules.d/audit.rules

##########################################
## Collect System Administrator Actions ##
##########################################
echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/rules.d/audit.rules

#################################################
## Collect Kernel Module Loading and Unloading ##
#################################################
echo "-w /sbin/insmod -p x -k modules 
-w /sbin/rmmod -p x -k modules 
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/rules.d/audit.rules

############################################
## Make the Audit Configuration Immutable ##
############################################
echo "-e 2" >> /etc/audit/rules.d/audit.rules

pkill -HUP -P 1 auditd

#########################
## Configure Logrotate ##
#########################

####################
## Enable Anacron ##
####################
yum install cronie-anacron -y

##################
## Enable Crond ##
##################
systemctl enable crond

###########################################
## Set User/Group Permissions on Anacron ##
###########################################
chown root:root /etc/anacrontab
chmod og-rwx /etc/anacrontab

########################################
## Set User/Group Permissions on Cron ##
########################################
chown root:root /etc/crontab
chmod og-rwx /etc/crontab
chown root:root /etc/cron.hourly
chmod og-rwx /etc/cron.hourly
chown root:root /etc/cron.daily
chmod og-rwx /etc/cron.daily
chown root:root /etc/cron.weekly
chmod og-rwx /etc/cron.weekly
chown root:root /etc/cron.monthly
chmod og-rwx /etc/cron.monthly
chown root:root /etc/cron.d
chmod og-rwx /etc/cron.d

########################
## Restrict At Daemon ##
########################
rm -f /etc/at.deny
rm -f /etc/cron.deny
touch /etc/at.allow
touch /etc/cron.allow
chown root:root /etc/at.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chmod og-rwx /etc/cron.allow

#######################
## SSH Configuration ##
#######################
sed -i 's/^Protocol .*$/Protocol 2/g' /etc/ssh/sshd_config
sed -i 's/^LogLevel .*$/LogLevel INFO/g' /etc/ssh/sshd_config
sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config
sed -i 's/^MaxAuthTries .*$/MaxAuthTries 4/g' /etc/ssh/sshd_config
sed -i 's/IgnoreRhosts no/IgnoreRhosts yes/g' /etc/ssh/sshd_config
sed -i 's/HostbasedAuthentication yes/HostbasedAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
sed -i 's/PermitEmptyPasswords yes/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
sed -i 's/PermitUserEnvironment yes/PermitUserEnvironment no/g' /etc/ssh/sshd_config
sed -i 's/^Ciphers .*$/Ciphers aes128-ctr,aes192-ctr,aes256-ctr/g' /etc/ssh/sshd_config
sed -i 's/^ClientAliveInterval .*$/ClientAliveInterval 300/g' /etc/ssh/sshd_config
sed -i 's/^ClientAliveCountMax .*$/ClientAliveCountMax 0/g' /etc/ssh/sshd_config

chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config

###################
## Configure PAM ##
###################
authconfig --passalgo=sha512 --update
