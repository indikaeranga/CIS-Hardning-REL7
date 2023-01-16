#!/bin/bash
### CIS Hardening Script for Redhat7 / CentOS7 Servers.

AUDITDIR="/tmp/$(hostname -s)_audit"
TIME="$(date +%F_%T)"

mkdir -p $AUDITDIR


# Initial Setup

part1(){
echo "Disable unused filesystems"
cp /etc/modprobe.d/CIS.conf $AUDITDIR/modp_CIS_$TIME.bak 
cat > /etc/modprobe.d/CIS.conf << "EOF"
install cramfs /bin/true
install freevxfs /bin/true
install jffs2 /bin/true
install hfs /bin/true
install hfsplus /bin/true
install squashfs /bin/true
install udf /bin/true
install vfat /bin/true
install dccp /bin/true
install sctp /bin/true
install rds /bin/true
install tipc /bin/true
EOF

echo "Setting Sticky Bit on All World-Writable Directories..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 2>/dev/null | xargs chmod a+t

echo "Configuring Bootloader permision"

chown root:root /boot/grub2/grub.cfg
chmod og-rwx /boot/grub2/grub.cfg


echo "Setting core dump security limits..."
cp /etc/security/limits.conf $AUDITDIR/limits_config_$TIME.bak
#echo '* hard core 0' >> /etc/security/limits.conf

echo "Creating Banner..."
cp -p /etc/issue.net $AUDITDIR/issue.net_$TIME.bak
cat > /etc/issue.net << 'EOF'
#############################################################################
##This is Production Server                                                 #
##Authorized uses only. All activity will be monitored and reported.        #
#############################################################################
EOF

cp -p /etc/motd $AUDITDIR/motd_$TIME.bak
echo -e "\e[41m##################################################################################\e[0m" > /etc/motd
echo -e "\e[41m## THIS SYSTEM IS FOR THE USE OF AUTHORIZED USERS ONLY                           #\e[0m" >> /etc/motd
echo -e "\e[41m##                                                                               #\e[0m" >> /etc/motd
echo -e "\e[41m## Individuals using this system without authority or in                         #\e[0m" >> /etc/motd
echo -e "\e[41m## excess of their authority are subject to having all their                     #\e[0m" >> /etc/motd
echo -e "\e[41m## activities on this system monitored and recorded or examined                  #\e[0m" >> /etc/motd
echo -e "\e[41m## by any authorized person, including law enforcement, as                       #\e[0m" >> /etc/motd
echo -e "\e[41m## system personnel deem appropriate.                                            #\e[0m" >> /etc/motd
echo -e "\e[41m##                                                                               #\e[0m" >> /etc/motd
echo -e "\e[41m## In the course of monitoring individuals improperly using the                  #\e[0m" >> /etc/motd
echo -e "\e[41m## system or in the course of system maintenance, the activities                 #\e[0m" >>/etc/motd
echo -e "\e[41m## of authorized users may also be monitored and recorded. Any                   #\e[0m" >> /etc/motd
echo -e "\e[41m## material so recorded may be disclosed as appropriate. Anyone                  #\e[0m" >> /etc/motd
echo -e "\e[41m## using this system consents to these terms.                                    #\e[0m" >> /etc/motd
echo -e "\e[41m##################################################################################\e[0m" >> /etc/motd

cp -p /etc/issue $AUDITDIR/issue_$TIME.bak
cat > /etc/issue << 'EOF'
#######################################################################
##"This is Production Server"                                         #
##"Authorized uses only. All activity may be monitered and reported." #
#######################################################################
EOF

echo "Configuring Banner permision..."

chown root:root /etc/motd
chmod 644 /etc/motd
chown root:root /etc/issue
chmod 644 /etc/issue
chown root:root /etc/issue.net
chmod 644 /etc/issue.net
}

#Services

part2(){

for a in chargen daytime discard echo time rhnsd
do
chkconfig $a-dgram off
chkconfig $a-stream off
done

echo "Removing legacy services..."
yum -y remove ypbind rsh talk xorg-x11* >> $AUDITDIR/service_remove_$TIME.log

echo "Removing prelink..."
yum -y remove prelink >> $AUDITDIR/service_remove_$TIME.log

echo "Disabling LDAP..."
yum -y remove openldap-clients >> $AUDITDIR/service_remove_$TIME.log

echo "Removing telnet..."
yum -y remove telnet >> $AUDITDIR/service_remove_$TIME.log

echo "Disabling Unnecessary Services-1..."
servicelist=(dhcpd avahi-daemon cups slapd nfs nfs-server rpcbind rsh.socket rlogin.socket rexec.socket ntalk tftp.socket rsyncd xinetd)
for i in ${servicelist[@]}; do
  [ $(systemctl disable $i 2> /dev/null) ] || echo "$i is Disabled"
done

echo "Disabling Unnecessary Services-2..."
service=(named vsftpd dovecot smb httpd squid snmpd ypserv autofs)
for i in ${service[@]}; do
  [ $(systemctl disable $i 2> /dev/null) ] || echo "$i is Disabled"
done
}

#Network Configuration

part3(){

echo "Configure /etc/sysctl.conf..."
cp /etc/sysctl.conf $AUDITDIR/sysctl_config_$TIME.bak
cat > /etc/sysctl.conf << 'EOF'
# System default settings live in /usr/lib/sysctl.d/00-system.conf.
# To override those settings, enter new settings here, or in an /etc/sysctl.d/<name>.conf file
#
# For more information, see sysctl.conf(5) and sysctl.d(5).
net.ipv4.tcp_fin_timeout = 5
#net.ipv4.tcp_fin_timeout = 60
#fs.suid_dumpable = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
kernel.exec-shield=1
kernel.randomize_va_space=1
net.core.somaxconn=4096
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.ip_local_port_range=1024 65535
net.ipv4.tcp_tw_recycle=1
net.ipv4.tcp_max_syn_backlog=8192
net.core.netdev_max_backlog=16384
net.core.rmem_max=16777216
net.core.wmem_max=16777216
net.ipv4.tcp_rmem=4096 87380 16777216
net.ipv4.tcp_wmem=4096 16384 16777216
net.core.netdev_max_backlog=300000
net.ipv4.tcp_timestamps = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv4.ip_forward = 0
EOF

#sysctl -w fs.suid_dumpable=0
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv4.conf.all.log_martians=1
sysctl -w net.ipv4.conf.default.log_martians=1
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1

echo "Configuring host file permission..."
chown root:root /etc/hosts.allow
chmod 644 /etc/hosts.allow
chown root:root /etc/hosts.deny
chmod 644 /etc/hosts.deny
}

#Logging and Auditing

part4(){

echo "Setting audit rules..."
cp /etc/audit/rules.d/audit.rules $AUDITDIR/auditrules_conf_$TIME.bak
cat > /etc/audit/rules.d/audit.rules << "EOF"
# This file contains the auditctl rules that are loaded
# whenever the audit daemon is started via the initscripts.
# The rules are simply the parameters that would be passed
# to auditctl.

# First rule - delete all
-D

# Increase the buffers to survive stress events.
# Make this bigger for busy systems
-b 320

# Feel free to add below this line. See auditctl man page

-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-w /etc/sysconfig/network-scripts/ -p wa -k system-locale
-w /etc/selinux/ -p wa -k MAC-policy
-w /usr/share/selinux/ -p wa -k MAC-policy
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295
-k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295
-k perm_mod
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=1000 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /var/log/sudo.log -p wa -k actions
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-e 2
EOF

echo "Enabling rsyslog service..."
systemctl enable rsyslog
cp /etc/rsyslog.conf $AUDITDIR/rsyslog_conf_$TIME.bak
rsys='/etc/rsyslog.conf'
grep -q "FileCreateMode" "${rsys}"
if [[ "$?" -eq 0 ]]; then
echo "FileCreateMode configured in ${rsys}"
else
echo "\$FileCreateMode 0640" >> "${rsys}"
fi

echo "Configure log file permissions..."
find /var/log -type f -exec chmod g-wx,o-rwx {} +


echo "Enabling auditd service..."
systemctl enable auditd

echo "Configuring audit.conf... "
cp /etc/audit/auditd.conf $AUDITDIR/auditd_conf_$TIME.bak
sed -i 's/^space_left_action.*$/space_left_action = SYSLOG/' /etc/audit/auditd.conf
sed -i 's/^action_mail_acct.*$/action_mail_acct = root/' /etc/audit/auditd.conf
sed -i 's/^admin_space_left_action.*$/admin_space_left_action = SUSPEND/' /etc/audit/auditd.conf
}

#Access, Authentication and Authorization

part5(){

echo "Configuring SSH..."
cp /etc/ssh/sshd_config $AUDITDIR/sshd_config_$TIME.bak
sed -i 's/#LogLevel INFO/LogLevel INFO/g' /etc/ssh/sshd_config
#sed -i 's/#MaxAuthTries 6/MaxAuthTries 6/g' /etc/ssh/sshd_config
sed -i 's/#IgnoreRhosts yes/IgnoreRhosts yes/g' /etc/ssh/sshd_config
#sed -i 's/#HostbasedAuthentication no/HostbasedAuthentication no/g' /etc/ssh/sshd_config
sed -i 's/X11Forwarding yes/X11Forwarding no/g' /etc/ssh/sshd_config
sed -i 's/#PermitRootLogin yes/PermitRootLogin no/g' /etc/ssh/sshd_config
sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords no/g' /etc/ssh/sshd_config
sed -i 's/#PermitUserEnvironment no/PermitUserEnvironment no/g' /etc/ssh/sshd_config
sed -i 's/#ClientAliveInterval 0/ClientAliveInterval 300/g' /etc/ssh/sshd_config
sed -i 's/#ClientAliveCountMax 3/ClientAliveCountMax 0/g' /etc/ssh/sshd_config
#sed -i 's/#LoginGraceTime 2m/LoginGraceTime 60/g' /etc/ssh/sshd_config
sed -i "s/\#Banner none/Banner \/etc\/issue\.net/" /etc/ssh/sshd_config
chown root:root /etc/ssh/sshd_config
chmod 600 /etc/ssh/sshd_config
ssh='/etc/ssh/sshd_config'
grep -q "^Protocol[[:space:]]2" "${ssh}"
if [[ "$?" -eq 0 ]]; then
echo "Protocol configured in ${ssh}"
else
echo "Protocol 2" >> "${ssh}"
fi

#grep -q "^MACs" "${ssh}"
#if [[ "$?" -eq 0 ]]; then
#echo "MACs configured in ${ssh} "
#else
#echo "MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com" >> "${ssh}"
#fi

systemctl restart sshd >> $AUDITDIR/service_restart_$TIME.log

echo "Configuring Cron..."
systemctl enable crond
chown root:root /etc/crontab
chmod 0600 /etc/crontab
chown root:root /etc/cron.hourly
chmod 0700 /etc/cron.hourly
chown root:root /etc/cron.daily
chmod 0700 /etc/cron.daily
chown root:root /etc/cron.weekly
chmod 0700 /etc/cron.weekly
chown root:root /etc/cron.monthly
chmod 0700 /etc/cron.monthly
chown root:root /etc/cron.d
chmod 0700 /etc/cron.d
/bin/rm -f /etc/cron.deny
touch /etc/cron.allow
chmod 600 /etc/cron.allow
chown root:root /etc/cron.allow

echo "Configuring PAM..."
cp /etc/login.defs $AUDITDIR/login_defs_$TIME.bak
sed -i 's/PASS_MAX_DAYS   99999/PASS_MAX_DAYS   45/g' /etc/login.defs
chage -M 45 indika

echo "Configuring Systems accounts..."
for user in `awk -F: '($3 < 1000) {print $1 }' /etc/passwd` ; do
if [ $user != "root" ]; then
usermod -L $user
if [ $user != "sync" ] && [ $user != "shutdown" ] && [ $user != "halt" ];
then
usermod -s /sbin/nologin $user
fi
fi
done

echo "Setting default umask for users..."
cp /etc/bashrc $AUDITDIR/bashrc_config_$TIME.bak
cp /etc/profile $AUDITDIR/profile_config_$TIME.bak
line_num=$(grep -n "^[[:space:]]*umask" /etc/bashrc | head -1 | cut -d: -f1)
sed -i ${line_num}s/002/027/ /etc/bashrc
line_num=$(grep -n "^[[:space:]]*umask" /etc/profile | head -1 | cut -d: -f1)
sed -i ${line_num}s/002/027/ /etc/profile

echo "Setting TMOUT..."
bash='/etc/bashrc'
prof='/etc/profile'
croA='/etc/cron.allow'
grep -q "^TMOUT=" "${bash}" 
if [[ "$?" -eq 0 ]]; then
echo "TMOUT configured in ${bash}"
else
echo "TMOUT=600" >> /etc/bashrc
fi
grep -q "^TMOUT=" "${prof}" 
if [[ "$?" -eq 0 ]]; then  
echo "TMOUT configured in ${prof}"
else
echo "TMOUT=600" >> /etc/profile
fi

grep -qa ^indika /etc/cron.allow
if [[ "$?" -eq 0 ]]; then
echo "indika user configured in ${croA}"
else
echo "indika" >> /etc/cron.allow
fi
}

#System Maintenance

part6(){

echo "Verifying System File Permissions..."
chmod 644 /etc/passwd
chmod 644 /etc/passwd-
chmod 000 /etc/shadow
chmod 000 /etc/shadow-
chmod 000 /etc/gshadow
chmod 000 /etc/gshadow-
chmod 644 /etc/group
chmod 644 /etc/group-
chown root:root /etc/passwd
chown root:root /etc/passwd-
chown root:root /etc/shadow
chown root:root /etc/shadow-
chown root:root /etc/gshadow
chown root:root /etc/gshadow-
chown root:root /etc/group
chown root:root /etc/group-


echo "Searching for world writable files..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 >> $AUDITDIR/world_writable_files_$TIME.log


echo "Searching for Un-owned files and directories..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser -ls >> $AUDITDIR/unowned_files_$TIME.log

echo "Searching for Un-grouped files and directories..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup -ls >> $AUDITDIR/ungrouped_files_$TIME.log

echo "Searching for SUID System Executables..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -4000 -print >> $AUDITDIR/suid_exec_$TIME.log

echo "Searching for SGID System Executables..."
df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -2000 -print >> $AUDITDIR/sgid_exec_$TIME.log

echo "Searching for empty password fields..."
/bin/cat /etc/shadow | /bin/awk -F: '($2 == "" ) { print $1 " does not have a password "}' >> $AUDITDIR/empty_passwd_$TIME.log

echo "Reviewing User and Group Settings..."
echo "Reviewing User and Group Settings..." >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/grep '^+:' /etc/passwd >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/grep '^+:' /etc/shadow >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/grep '^+:' /etc/group >> $AUDITDIR/reviewusrgrp_$TIME.log
/bin/cat /etc/passwd | /bin/awk -F: '($3 == 0) { print $1 }' >> $AUDITDIR/reviewusrgrp_$TIME.log




echo "Checking root PATH integrity..."

if [ "`echo $PATH | /bin/grep :: `" != "" ]; then
    echo "Empty Directory in PATH (::)" >> $AUDITDIR/root_path_$TIME.log
fi

if [ "`echo $PATH | /bin/grep :$`"  != "" ]; then
    echo "Trailing : in PATH" >> $AUDITDIR/root_path_$TIME.log
fi

p=`echo $PATH | /bin/sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
set -- $p
while [ "$1" != "" ]; do
    if [ "$1" = "." ]; then
        echo "PATH contains ." >> $AUDITDIR/root_path_$TIME.log
        shift
        continue
    fi
    if [ -d $1 ]; then
        dirperm=`/bin/ls -ldH $1 | /bin/cut -f1 -d" "`
        if [ `echo $dirperm | /bin/cut -c6 ` != "-" ]; then
            echo "Group Write permission set on directory $1" >> $AUDITDIR/root_path_$TIME.log
        fi
        if [ `echo $dirperm | /bin/cut -c9 ` != "-" ]; then
            echo "Other Write permission set on directory $1" >> $AUDITDIR/root_path_$TIME.log
        fi
            dirown=`ls -ldH $1 | awk '{print $3}'`
           if [ "$dirown" != "root" ] ; then
             echo "$1 is not owned by root" >> $AUDITDIR/root_path_$TIME.log
              fi
    else
            echo "$1 is not a directory" >> $AUDITDIR/root_path_$TIME.log
      fi
    shift
done


echo "Checking Permissions on User Home Directories..."

for dir in `/bin/cat /etc/passwd  | /bin/egrep -v '(root|halt|sync|shutdown)' |\
    /bin/awk -F: '($8 == "PS" && $7 != "/sbin/nologin") { print $6 }'`; do
        dirperm=`/bin/ls -ld $dir | /bin/cut -f1 -d" "`
        if [ `echo $dirperm | /bin/cut -c6 ` != "-" ]; then
            echo "Group Write permission set on directory $dir" >> $AUDITDIR/home_permission_$TIME.log
        fi
        if [ `echo $dirperm | /bin/cut -c8 ` != "-" ]; then
            echo "Other Read permission set on directory $dir" >> $AUDITDIR/home_permission_$TIME.log

        fi

        if [ `echo $dirperm | /bin/cut -c9 ` != "-" ]; then
            echo "Other Write permission set on directory $dir" >> $AUDITDIR/home_permission_$TIME.log
        fi
        if [ `echo $dirperm | /bin/cut -c10 ` != "-" ]; then
            echo "Other Execute permission set on directory $dir" >> $AUDITDIR/home_permission_$TIME.log
        fi
done


echo "Checking User Dot File Permissions..."
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' |
/bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for file in $dir/.[A-Za-z0-9]*; do

        if [ ! -h "$file" -a -f "$file" ]; then
            fileperm=`/bin/ls -ld $file | /bin/cut -f1 -d" "`

            if [ `echo $fileperm | /bin/cut -c6 ` != "-" ]; then
                echo "Group Write permission set on file $file" >> $AUDITDIR/dotfile_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c9 ` != "-" ]; then
                echo "Other Write permission set on file $file" >> $AUDITDIR/dotfile_permission_$TIME.log
            fi
        fi

    done

done

echo "Checking Permissions on User .netrc Files..."
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|sync|halt|shutdown)' |\
    /bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for file in $dir/.netrc; do
        if [ ! -h "$file" -a -f "$file" ]; then
            fileperm=`/bin/ls -ld $file | /bin/cut -f1 -d" "`
            if [ `echo $fileperm | /bin/cut -c5 ` != "-" ]
            then
                echo "Group Read set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c6 ` != "-" ]
            then
                echo "Group Write set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c7 ` != "-" ]
            then
                echo "Group Execute set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c8 ` != "-" ]
            then
                echo "Other Read  set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c9 ` != "-" ]
            then
                echo "Other Write set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
            if [ `echo $fileperm | /bin/cut -c10 ` != "-" ]
            then
                echo "Other Execute set on $file" >> $AUDITDIR/netrd_permission_$TIME.log
            fi
        fi
    done
done


echo "Checking for Presence of User .rhosts Files..."
for dir in `/bin/cat /etc/passwd | /bin/egrep -v '(root|halt|sync|shutdown)' |\
    /bin/awk -F: '($7 != "/sbin/nologin") { print $6 }'`; do
    for file in $dir/.rhosts; do
        if [ ! -h "$file" -a -f "$file" ]; then
            echo ".rhosts file in $dir" >> $AUDITDIR/rhosts_$TIME.log
        fi    done
done

echo "Checking Groups in /etc/passwd..."

for i in $(cut -s -d: -f4 /etc/passwd | sort -u ); do
  grep -q -P "^.*?:x:$i:" /etc/group
  if [ $? -ne 0 ]; then
    echo "Group $i is referenced by /etc/passwd but does not exist in /etc/group" >> $AUDITDIR/audit_$TIME.log
  fi
done

echo "Checking That Users Are Assigned Home Directories..."

cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
  if [ $uid -ge 500 -a ! -d "$dir" -a $user != "nfsnobody" ]; then
 echo "The home directory ($dir) of user $user does not exist." >> $AUDITDIR/Assignedhomedir_$TIME.log
 fi
done

echo "Checking That Defined Home Directories Exist..."

cat /etc/passwd | awk -F: '{ print $1 " " $3 " " $6 }' | while read user uid dir; do
 if [ $uid -ge 500 -a -d "$dir" -a $user != "nfsnobody" ]; then
 owner=$(stat -L -c "%U" "$dir")
 if [ "$owner" != "$user" ]; then
 echo "The home directory ($dir) of user $user is owned by $owner." >> $AUDITDIR/Definedhomedir_$TIME.log
 fi
 fi
done

echo "Checking for Duplicate UIDs..."

/bin/cat /etc/passwd | /bin/cut -f3 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        users=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2 \
            /etc/passwd | /usr/bin/xargs`
        echo "Duplicate UID ($2): ${users}" >> $AUDITDIR/DupilicateUIDs_$TIME.log
    fi
done

echo "Checking for Duplicate GIDs..."

/bin/cat /etc/group | /bin/cut -f3 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        grps=`/bin/gawk -F: '($3 == n) { print $1 }' n=$2 \
            /etc/group | xargs`
        echo "Duplicate GID ($2): ${grps}" >> $AUDITDIR/DupilicateGIDs_$TIME.log
    fi
done

#echo "Checking That Reserved UIDs Are Assigned to System Accounts..."

#defUsers="root bin daemon adm lp sync shutdown halt mail news uucp operator games
#gopher ftp nobody nscd vcsa rpc mailnull smmsp pcap ntp dbus avahi sshd rpcuser
#nfsnobody haldaemon avahi-autoipd distcache apache oprofile webalizer dovecot squid
#named xfs gdm sabayon usbmuxd rtkit abrt saslauth pulse postfix tcpdump"
#/bin/cat /etc/passwd | /bin/awk -F: '($3 < 500) { print $1" "$3 }' |\
#    while read user uid; do
#        found=0
#        for tUser in ${defUsers}
#        do
#            if [ ${user} = ${tUser} ]; then
#               found=1
#            fi
#        done
#        if [ $found -eq 0 ]; then
#            echo "User $user has a reserved UID ($uid)."  >> $AUDITDIR/audit_$TIME.log
#        fi
#    done

echo "Checking for Duplicate User Names..."

cat /etc/passwd | cut -f1 -d":" | sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        uids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 \
            /etc/passwd | xargs`
        echo "Duplicate User Name ($2): ${uids}"  >> $AUDITDIR/Dupilicateusername_$TIME.log
    fi
done

echo "Checking for Duplicate Group Names..."

cat /etc/group | cut -f1 -d":" | /bin/sort -n | /usr/bin/uniq -c |\
    while read x ; do
    [ -z "${x}" ] && break
    set - $x
    if [ $1 -gt 1 ]; then
        gids=`/bin/gawk -F: '($1 == n) { print $3 }' n=$2 \
            /etc/group | xargs`
        echo "Duplicate Group Name ($2): ${gids}"  >> $AUDITDIR/Dupilicategroupname_$TIME.log
    fi
done

echo "Checking for Presence of User .netrc Files..."

for dir in `/bin/cat /etc/passwd |\
    /bin/awk -F: '{ print $6 }'`; do
    if [ ! -h "$dir/.netrc" -a -f "$dir/.netrc" ]; then
        echo ".netrc file $dir/.netrc exists"  >> $AUDITDIR/netrcfile_$TIME.log
    fi
done

echo "Checking for Presence of User .forward Files..."

for dir in `/bin/cat /etc/passwd |\
    /bin/awk -F: '{ print $6 }'`; do
    if [ ! -h "$dir/.forward" -a -f "$dir/.forward" ]; then
        echo ".forward file $dir/.forward exists"  >> $AUDITDIR/forwardfile_$TIME.log
    fi
done
}

case "$1" in
      part1)
            part1
            ;;

      part2)
            part2
            ;;
      part3)
            part3
            ;;
      part4)
            part4
            ;;
      part5)
            part5
            ;;
      part6)
            part6
            ;;
        all)
            part1
            part2
            part3
            part4
            part5
            part6
            echo " All Parts Successfully Completed"
            echo " Please check $AUDITDIR"
            ;;
      *)
            echo $"Usage: $0 {all|part1|part2|part3|part4|part5|part6}"
            exit 1
esac



