#!/bin/bash

set +e

# V-260471 | medium | Ubuntu 22.04 LTS must initiate session audits at system startup.
echo '=== V-260471 | medium ==='
# 'Running: sudo grep "^\s*linux" /boot/grub/grub.cfg '
sudo grep "^\s*linux" /boot/grub/grub.cfg 

# V-260473 | medium | Ubuntu 22.04 LTS must disable kernel core dumps so that it can fail to a secure state if system initialization fails, shutdown fails or aborts fail.
echo '=== V-260473 | medium ==='
# 'Running: systemctl status kdump-tools.service'
systemctl status kdump-tools.service

# V-260474 | medium | Ubuntu 22.04 LTS must implement address space layout randomization to protect its memory from unauthorized code execution.
echo '=== V-260474 | medium ==='
# 'Running: sysctl kernel.randomize_va_space '
sysctl kernel.randomize_va_space 
# 'Running: cat /proc/sys/kernel/randomize_va_space '
cat /proc/sys/kernel/randomize_va_space 
# 'Running: sudo grep -ER "^kernel.randomize_va_space=[^2]" /etc/sysctl.conf /etc/sysctl.d '
sudo grep -ER "^kernel.randomize_va_space=[^2]" /etc/sysctl.conf /etc/sysctl.d 

# V-260475 | medium | Ubuntu 22.04 LTS must implement nonexecutable data to protect its memory from unauthorized code execution.
echo '=== V-260475 | medium ==='
# 'Running: sudo dmesg | grep -i "execute disable" '
sudo dmesg | grep -i "execute disable" 
# 'Running: grep flags /proc/cpuinfo | grep -o nx | sort -u '
grep flags /proc/cpuinfo | grep -o nx | sort -u 

# V-260477 | medium | Ubuntu 22.04 LTS must be configured so that the Advance Package Tool (APT) removes all software components after updated versions have been installed.
echo '=== V-260477 | medium ==='
# 'Running: grep -i remove-unused /etc/apt/apt.conf.d/50unattended-upgrades '
grep -i remove-unused /etc/apt/apt.conf.d/50unattended-upgrades 

# V-260478 | medium | Ubuntu 22.04 LTS must have the "libpam-pwquality" package installed.
echo '=== V-260478 | medium ==='
# 'Running: dpkg -l | grep libpam-pwquality '
dpkg -l | grep libpam-pwquality 

# V-260484 | medium | Ubuntu 22.04 LTS must implement cryptographic mechanisms to prevent unauthorized disclosure and modification of all information that requires protection at rest.
echo '=== V-260484 | medium ==='
# 'Running: sudo fdisk -l '
sudo fdisk -l 

# V-260485 | medium | Ubuntu 22.04 LTS must have directories that contain system commands set to a mode of "755" or less permissive.
echo '=== V-260485 | medium ==='
# 'Running: find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c "%n %a" '{}' \;  '
find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type d -exec stat -c "%n %a" '{}' \;  

# V-260486 | medium | Ubuntu 22.04 LTS must have system commands set to a mode of "755" or less permissive.
echo '=== V-260486 | medium ==='
# 'Running: sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c "%n %a" '{}' \; '
sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -perm /022 -type f -exec stat -c "%n %a" '{}' \; 

# V-260487 | medium | Ubuntu 22.04 LTS library files must have mode "755" or less permissive.
echo '=== V-260487 | medium ==='
# 'Running: sudo find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' -perm /022 -exec stat -c "%n %a" {} +'
sudo find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' -perm /022 -exec stat -c "%n %a" {} +

# V-260488 | medium | Ubuntu 22.04 LTS must configure the "/var/log" directory to have mode "755" or less permissive.
echo '=== V-260488 | medium ==='
# 'Running: stat -c "%n %a" /var/log '
stat -c "%n %a" /var/log 

# V-260489 | medium | Ubuntu 22.04 LTS must generate error messages that provide information necessary for corrective actions without revealing information that could be exploited by adversaries.
echo '=== V-260489 | medium ==='
# 'Running: sudo find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec stat -c "%n %a" {} \; '
sudo find /var/log -perm /137 ! -name '*[bw]tmp' ! -name '*lastlog' -type f -exec stat -c "%n %a" {} \; 

# V-260490 | medium | Ubuntu 22.04 LTS must generate system journal entries without revealing information that could be exploited by adversaries.
echo '=== V-260490 | medium ==='
# 'Running: sudo find /run/log/journal /var/log/journal -type d -exec stat -c "%n %a" {} \;'
sudo find /run/log/journal /var/log/journal -type d -exec stat -c "%n %a" {} \;
# 'Running: sudo find /run/log/journal /var/log/journal  -type f -exec stat -c "%n %a" {} \; '
sudo find /run/log/journal /var/log/journal  -type f -exec stat -c "%n %a" {} \; 

# V-260491 | medium | Ubuntu 22.04 LTS must configure "/var/log/syslog" file with mode "640" or less permissive.
echo '=== V-260491 | medium ==='
# 'Running: stat -c "%n %a" /var/log/syslog  '
stat -c "%n %a" /var/log/syslog  

# V-260492 | medium | Ubuntu 22.04 LTS must configure audit tools with a mode of "755" or less permissive.
echo '=== V-260492 | medium ==='
# 'Running: stat -c "%n %a" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules '
stat -c "%n %a" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audispd* /sbin/augenrules 

# V-260493 | medium | Ubuntu 22.04 LTS must have directories that contain system commands owned by "root".
echo '=== V-260493 | medium ==='
# 'Running: sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c "%n %U" '{}' \; '
sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type d -exec stat -c "%n %U" '{}' \; 

# V-260494 | medium | Ubuntu 22.04 LTS must have directories that contain system commands group-owned by "root".
echo '=== V-260494 | medium ==='
# 'Running: sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c "%n %G" '{}' \; '
sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type d -exec stat -c "%n %G" '{}' \; 

# V-260495 | medium | Ubuntu 22.04 LTS must have system commands owned by "root" or a system account.
echo '=== V-260495 | medium ==='
# 'Running: sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c "%n %U" '{}' \; '
sudo find /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -user root -type f -exec stat -c "%n %U" '{}' \; 

# V-260496 | medium | Ubuntu 22.04 LTS must have system commands group-owned by "root" or a system account.
echo '=== V-260496 | medium ==='
# 'Running: sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type f ! -perm /2000 -exec stat -c "%n %G" '{}' \; '
sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin ! -group root -type f ! -perm /2000 -exec stat -c "%n %G" '{}' \; 

# V-260497 | medium | Ubuntu 22.04 LTS library directories must be owned by "root".
echo '=== V-260497 | medium ==='
# 'Running: sudo find /lib /usr/lib /lib64 ! -user root -type d -exec stat -c "%n %U" '{}' \; '
sudo find /lib /usr/lib /lib64 ! -user root -type d -exec stat -c "%n %U" '{}' \; 

# V-260498 | medium | Ubuntu 22.04 LTS library directories must be group-owned by "root".
echo '=== V-260498 | medium ==='
# 'Running: sudo find /lib /usr/lib /lib64 ! -group root -type d -exec stat -c "%n %G" '{}' \; '
sudo find /lib /usr/lib /lib64 ! -group root -type d -exec stat -c "%n %G" '{}' \; 

# V-260499 | medium | Ubuntu 22.04 LTS library files must be owned by "root".
echo '=== V-260499 | medium ==='
# 'Running: sudo find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' ! -user root -exec stat -c "%n %U" {} +'
sudo find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' ! -user root -exec stat -c "%n %U" {} +

# V-260500 | medium | Ubuntu 22.04 LTS library files must be group-owned by "root".
echo '=== V-260500 | medium ==='
# 'Running: sudo find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' ! -group root -exec stat -c "%n %G" {} +'
sudo find /lib /lib64 /usr/lib /usr/lib64 -type f -name '*.so*' ! -group root -exec stat -c "%n %G" {} +

# V-260501 | medium | Ubuntu 22.04 LTS must configure the directories used by the system journal to be owned by "root".
echo '=== V-260501 | medium ==='
# 'Running: sudo find /run/log/journal /var/log/journal  -type d -exec stat -c "%n %U" {} \; '
sudo find /run/log/journal /var/log/journal  -type d -exec stat -c "%n %U" {} \; 

# V-260502 | medium | Ubuntu 22.04 LTS must configure the directories used by the system journal to be group-owned by "systemd-journal".
echo '=== V-260502 | medium ==='
# 'Running: sudo find /run/log/journal /var/log/journal  -type d -exec stat -c "%n %G" {} \; '
sudo find /run/log/journal /var/log/journal  -type d -exec stat -c "%n %G" {} \; 

# V-260503 | medium | Ubuntu 22.04 LTS must configure the files used by the system journal to be owned by "root".
echo '=== V-260503 | medium ==='
# 'Running: sudo find /run/log/journal /var/log/journal  -type f -exec stat -c "%n %U" {} \; '
sudo find /run/log/journal /var/log/journal  -type f -exec stat -c "%n %U" {} \; 

# V-260504 | medium | Ubuntu 22.04 LTS must configure the files used by the system journal to be group-owned by "systemd-journal".
echo '=== V-260504 | medium ==='
# 'Running: sudo find /run/log/journal /var/log/journal  -type f -exec stat -c "%n %G" {} \; '
sudo find /run/log/journal /var/log/journal  -type f -exec stat -c "%n %G" {} \; 

# V-260505 | medium | Ubuntu 22.04 LTS must be configured so that the "journalctl" command is owned by "root".
echo '=== V-260505 | medium ==='
# 'Running: sudo find /usr/bin/journalctl -exec stat -c "%n %U" {} \; '
sudo find /usr/bin/journalctl -exec stat -c "%n %U" {} \; 

# V-260506 | medium | Ubuntu 22.04 LTS must be configured so that the "journalctl" command is group-owned by "root".
echo '=== V-260506 | medium ==='
# 'Running: sudo find /usr/bin/journalctl -exec stat -c "%n %G" {} \; '
sudo find /usr/bin/journalctl -exec stat -c "%n %G" {} \; 

# V-260507 | medium | Ubuntu 22.04 LTS must configure audit tools to be owned by "root".
echo '=== V-260507 | medium ==='
# 'Running: stat -c "%n %U" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audisp* /sbin/augenrules '
stat -c "%n %U" /sbin/auditctl /sbin/aureport /sbin/ausearch /sbin/autrace /sbin/auditd /sbin/audisp* /sbin/augenrules 

# V-260508 | medium | Ubuntu 22.04 LTS must configure the "/var/log" directory to be owned by "root".
echo '=== V-260508 | medium ==='
# 'Running: stat -c "%n %U" /var/log '
stat -c "%n %U" /var/log 

# V-260509 | medium | Ubuntu 22.04 LTS must configure the "/var/log" directory to be group-owned by "syslog".
echo '=== V-260509 | medium ==='
# 'Running: stat -c "%n %G" /var/log '
stat -c "%n %G" /var/log 

# V-260510 | medium | Ubuntu 22.04 LTS must configure "/var/log/syslog" file to be owned by "syslog".
echo '=== V-260510 | medium ==='
# 'Running: stat -c "%n %U" /var/log/syslog '
stat -c "%n %U" /var/log/syslog 

# V-260511 | medium | Ubuntu 22.04 LTS must configure the "/var/log/syslog" file to be group-owned by "adm".
echo '=== V-260511 | medium ==='
# 'Running: stat -c "%n %G" /var/log/syslog '
stat -c "%n %G" /var/log/syslog 

# V-260512 | medium | Ubuntu 22.04 LTS must be configured so that the "journalctl" command is not accessible by unauthorized users.
echo '=== V-260512 | medium ==='
# 'Running: sudo find /usr/bin/journalctl -exec stat -c "%n %a" {} \; '
sudo find /usr/bin/journalctl -exec stat -c "%n %a" {} \; 

# V-260513 | medium | Ubuntu 22.04 LTS must set a sticky bit on all public directories to prevent unauthorized and unintended information transferred via shared system resources.
echo '=== V-260513 | medium ==='
# 'Running: sudo find / -type d -perm -002 ! -perm -1000 '
sudo find / -type d -perm -002 ! -perm -1000 

# V-260514 | medium | Ubuntu 22.04 LTS must have an application firewall installed in order to control remote access methods.
echo '=== V-260514 | medium ==='
# 'Running: dpkg -l | grep ufw '
dpkg -l | grep ufw 

# V-260515 | medium | Ubuntu 22.04 LTS must enable and run the Uncomplicated Firewall (ufw).
echo '=== V-260515 | medium ==='
# 'Running: sudo ufw status '
sudo ufw status 

# V-260516 | medium | Ubuntu 22.04 LTS must have an application firewall enabled.
echo '=== V-260516 | medium ==='
# 'Running: systemctl status ufw.service | grep -i "active:" '
systemctl status ufw.service | grep -i "active:" 

# V-260517 | medium | Ubuntu 22.04 LTS must configure the Uncomplicated Firewall (ufw) to rate-limit impacted network interfaces.
echo '=== V-260517 | medium ==='
# 'Running: ss -l46ut '
ss -l46ut 
# 'Running: sudo ufw status  '
sudo ufw status  

# V-260518 | medium | Ubuntu 22.04 LTS must be configured to prohibit or restrict the use of functions, ports, protocols, and/or services, as defined in the PPSM CAL and vulnerability assessments.
echo '=== V-260518 | medium ==='
# 'Running: sudo ufw show raw '
sudo ufw show raw 

# V-260522 | medium | Ubuntu 22.04 LTS must be configured to use TCP syncookies.
echo '=== V-260522 | medium ==='
# 'Running: sysctl net.ipv4.tcp_syncookies '
sysctl net.ipv4.tcp_syncookies 
# 'Running: sudo grep -ir net.ipv4.tcp_syncookies /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2> /dev/null '
sudo grep -ir net.ipv4.tcp_syncookies /etc/sysctl.d/*.conf /run/sysctl.d/*.conf /usr/local/lib/sysctl.d/*.conf /usr/lib/sysctl.d/*.conf /lib/sysctl.d/*.conf /etc/sysctl.conf 2> /dev/null 

# V-260525 | medium | Ubuntu 22.04 LTS must display the Standard Mandatory DOD Notice and Consent Banner before granting any local or remote connection to the system.
echo '=== V-260525 | medium ==='
# 'Running: sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'banner' '
sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'banner' 
# 'Running: cat /etc/issue.net  '
cat /etc/issue.net  

# V-260527 | medium | Ubuntu 22.04 LTS must be configured so that all network connections associated with SSH traffic terminate after becoming unresponsive.
echo '=== V-260527 | medium ==='
# 'Running: sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'clientalivecountmax' '
sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'clientalivecountmax' 

# V-260528 | medium | Ubuntu 22.04 LTS must be configured so that all network connections associated with SSH traffic are terminated after 10 minutes of becoming unresponsive.
echo '=== V-260528 | medium ==='
# 'Running: sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'clientaliveinterval' '
sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'clientaliveinterval' 

# V-260530 | medium | Ubuntu 22.04 LTS SSH daemon must prevent remote hosts from connecting to the proxy display.
echo '=== V-260530 | medium ==='
# 'Running: sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'x11uselocalhost' '
sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'x11uselocalhost' 

# V-260531 | medium | Ubuntu 22.04 LTS must configure the SSH daemon to use FIPS 140-3-approved ciphers to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.
echo '=== V-260531 | medium ==='
# 'Running: sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'ciphers' '
sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'ciphers' 

# V-260532 | medium | Ubuntu 22.04 LTS must configure the SSH daemon to use Message Authentication Codes (MACs) employing FIPS 140-3-approved cryptographic hashes to prevent the unauthorized disclosure of information and/or detect changes to information during transmission.
echo '=== V-260532 | medium ==='
# 'Running: sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'macs' '
sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'macs' 

# V-260533 | medium | Ubuntu 22.04 LTS SSH server must be configured to use only FIPS-validated key exchange algorithms.
echo '=== V-260533 | medium ==='
# 'Running: sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'kexalgorithms' '
sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'kexalgorithms' 

# V-260534 | medium | Ubuntu 22.04 LTS must use strong authenticators in establishing nonlocal maintenance and diagnostic sessions.
echo '=== V-260534 | medium ==='
# 'Running: sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'usepam' '
sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'usepam' 

# V-260535 | medium | Ubuntu 22.04 LTS must enable the graphical user logon banner to display the Standard Mandatory DOD Notice and Consent Banner before granting local access to the system via a graphical user logon.
echo '=== V-260535 | medium ==='
# 'Running: grep -i banner-message-enable /etc/gdm3/greeter.dconf-defaults '
grep -i banner-message-enable /etc/gdm3/greeter.dconf-defaults 

# V-260536 | medium | Ubuntu 22.04 LTS must display the Standard Mandatory DOD Notice and Consent Banner before granting local access to the system via a graphical user logon.
echo '=== V-260536 | medium ==='
# 'Running: grep -i banner-message-text /etc/gdm3/greeter.dconf-defaults '
grep -i banner-message-text /etc/gdm3/greeter.dconf-defaults 

# V-260537 | medium | Ubuntu 22.04 LTS must retain a user's session lock until that user reestablishes access using established identification and authentication procedures.
echo '=== V-260537 | medium ==='
# 'Running: sudo gsettings get org.gnome.desktop.screensaver lock-enabled '
sudo gsettings get org.gnome.desktop.screensaver lock-enabled 

# V-260538 | medium | Ubuntu 22.04 LTS must initiate a graphical session lock after 15 minutes of inactivity.
echo '=== V-260538 | medium ==='
# 'Running: gsettings get org.gnome.desktop.screensaver lock-enabled '
gsettings get org.gnome.desktop.screensaver lock-enabled 
# 'Running: gsettings get org.gnome.desktop.screensaver lock-delay '
gsettings get org.gnome.desktop.screensaver lock-delay 
# 'Running: gsettings get org.gnome.desktop.session idle-delay '
gsettings get org.gnome.desktop.session idle-delay 

# V-260540 | medium | Ubuntu 22.04 LTS must disable automatic mounting of Universal Serial Bus (USB) mass storage driver.
echo '=== V-260540 | medium ==='
# 'Running: grep usb-storage /etc/modprobe.d/* | grep "/bin/false" '
grep usb-storage /etc/modprobe.d/* | grep "/bin/false" 
# 'Running: grep usb-storage /etc/modprobe.d/* | grep -i "blacklist" '
grep usb-storage /etc/modprobe.d/* | grep -i "blacklist" 

# V-260541 | medium | Ubuntu 22.04 LTS must disable all wireless network adapters.
echo '=== V-260541 | medium ==='
# 'Running: cat /proc/net/wireless '
cat /proc/net/wireless 

# V-260542 | medium | Ubuntu 22.04 LTS must prevent direct login into the root account.
echo '=== V-260542 | medium ==='
# 'Running: sudo passwd -S root  '
sudo passwd -S root  

# V-260543 | medium | Ubuntu 22.04 LTS must uniquely identify interactive users.
echo '=== V-260543 | medium ==='
# 'Running: awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd '
awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd 

# V-260545 | medium | Ubuntu 22.04 LTS must enforce 24 hours/one day as the minimum password lifetime. Passwords for new users must have a 24 hours/one day minimum password lifetime restriction.
echo '=== V-260545 | medium ==='
# 'Running: grep -i pass_min_days /etc/login.defs '
grep -i pass_min_days /etc/login.defs 

# V-260546 | medium | Ubuntu 22.04 LTS must enforce a 60-day maximum password lifetime restriction. Passwords for new users must have a 60-day maximum password lifetime restriction.
echo '=== V-260546 | medium ==='
# 'Running: grep -i pass_max_days /etc/login.defs '
grep -i pass_max_days /etc/login.defs 

# V-260547 | medium | Ubuntu 22.04 LTS must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.
echo '=== V-260547 | medium ==='
# 'Running: grep INACTIVE /etc/default/useradd  '
grep INACTIVE /etc/default/useradd  

# V-260553 | medium | Ubuntu 22.04 LTS must allow users to directly initiate a session lock for all connection types.
echo '=== V-260553 | medium ==='
# 'Running: dpkg -l | grep vlock '
dpkg -l | grep vlock 

# V-260554 | medium | Ubuntu 22.04 LTS must automatically exit interactive command shell user sessions after 15 minutes of inactivity.
echo '=== V-260554 | medium ==='
# 'Running: sudo grep -E "\bTMOUT=[0-9]+" /etc/bash.bashrc /etc/profile.d/* '
sudo grep -E "\bTMOUT=[0-9]+" /etc/bash.bashrc /etc/profile.d/* 

# V-260555 | medium | Ubuntu 22.04 LTS default filesystem permissions must be defined in such a way that all authenticated users can read and modify only their own files.
echo '=== V-260555 | medium ==='
# 'Running: grep -i '^\s*umask' /etc/login.defs  '
grep -i '^\s*umask' /etc/login.defs  

# V-260556 | medium | Ubuntu 22.04 LTS must have the "apparmor" package installed.
echo '=== V-260556 | medium ==='
# 'Running: dpkg -l | grep apparmor  '
dpkg -l | grep apparmor  

# V-260557 | medium | Ubuntu 22.04 LTS must be configured to use AppArmor.
echo '=== V-260557 | medium ==='
# 'Running: systemctl is-enabled apparmor.service '
systemctl is-enabled apparmor.service 
# 'Running: systemctl is-active apparmor.service '
systemctl is-active apparmor.service 
# 'Running: sudo apparmor_status | grep -i profile '
sudo apparmor_status | grep -i profile 

# V-260558 | medium | Ubuntu 22.04 LTS must require users to reauthenticate for privilege escalation or when changing roles.
echo '=== V-260558 | medium ==='
# 'Running: sudo egrep -iR '!authenticate' /etc/sudoers /etc/sudoers.d/'
sudo egrep -iR '!authenticate' /etc/sudoers /etc/sudoers.d/

# V-260560 | medium | Ubuntu 22.04 LTS must enforce password complexity by requiring at least one uppercase character be used.
echo '=== V-260560 | medium ==='
# 'Running: grep -i ucredit /etc/security/pwquality.conf '
grep -i ucredit /etc/security/pwquality.conf 

# V-260561 | medium | Ubuntu 22.04 LTS must enforce password complexity by requiring at least one lowercase character be used.
echo '=== V-260561 | medium ==='
# 'Running: grep -i lcredit /etc/security/pwquality.conf '
grep -i lcredit /etc/security/pwquality.conf 

# V-260562 | medium | Ubuntu 22.04 LTS must enforce password complexity by requiring that at least one numeric character be used.
echo '=== V-260562 | medium ==='
# 'Running: grep -i dcredit /etc/security/pwquality.conf '
grep -i dcredit /etc/security/pwquality.conf 

# V-260563 | medium | Ubuntu 22.04 LTS must enforce password complexity by requiring that at least one special character be used.
echo '=== V-260563 | medium ==='
# 'Running: grep -i ocredit /etc/security/pwquality.conf '
grep -i ocredit /etc/security/pwquality.conf 

# V-260564 | medium | Ubuntu 22.04 LTS must prevent the use of dictionary words for passwords.
echo '=== V-260564 | medium ==='
# 'Running: grep -i dictcheck /etc/security/pwquality.conf '
grep -i dictcheck /etc/security/pwquality.conf 

# V-260565 | medium | Ubuntu 22.04 LTS must enforce a minimum 15-character password length.
echo '=== V-260565 | medium ==='
# 'Running: grep -i minlen /etc/security/pwquality.conf '
grep -i minlen /etc/security/pwquality.conf 

# V-260566 | medium | Ubuntu 22.04 LTS must require the change of at least eight characters when passwords are changed.
echo '=== V-260566 | medium ==='
# 'Running: grep -i difok /etc/security/pwquality.conf '
grep -i difok /etc/security/pwquality.conf 

# V-260567 | medium | Ubuntu 22.04 LTS must be configured so that when passwords are changed or new passwords are established, pwquality must be used.
echo '=== V-260567 | medium ==='
# 'Running: grep -i enforcing /etc/security/pwquality.conf  '
grep -i enforcing /etc/security/pwquality.conf  
# 'Running: cat /etc/pam.d/common-password | grep requisite | grep pam_pwquality '
cat /etc/pam.d/common-password | grep requisite | grep pam_pwquality 

# V-260569 | medium | Ubuntu 22.04 LTS must store only encrypted representations of passwords.
echo '=== V-260569 | medium ==='
# 'Running: grep pam_unix.so /etc/pam.d/common-password '
grep pam_unix.so /etc/pam.d/common-password 

# V-260572 | medium | Ubuntu 22.04 LTS must encrypt all stored passwords with a FIPS 140-3-approved cryptographic hashing algorithm.
echo '=== V-260572 | medium ==='
# 'Running: grep -i '^\s*encrypt_method' /etc/login.defs '
grep -i '^\s*encrypt_method' /etc/login.defs 

# V-260573 | medium | Ubuntu 22.04 LTS must implement multifactor authentication for remote access to privileged accounts in such a way that one of the factors is provided by a device separate from the system gaining access.
echo '=== V-260573 | medium ==='
# 'Running: dpkg -l | grep libpam-pkcs11 '
dpkg -l | grep libpam-pkcs11 

# V-260574 | medium | Ubuntu 22.04 LTS must accept personal identity verification (PIV) credentials.
echo '=== V-260574 | medium ==='
# 'Running: dpkg -l | grep opensc-pkcs11 '
dpkg -l | grep opensc-pkcs11 

# V-260575 | medium | Ubuntu 22.04 LTS must implement smart card logins for multifactor authentication for local and network access to privileged and nonprivileged accounts.
echo '=== V-260575 | medium ==='
# 'Running: grep -i pam_pkcs11.so /etc/pam.d/common-auth '
grep -i pam_pkcs11.so /etc/pam.d/common-auth 
# 'Running: sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'pubkeyauthentication' '
sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'pubkeyauthentication' 

# V-260576 | medium | Ubuntu 22.04 LTS must electronically verify personal identity verification (PIV) credentials.
echo '=== V-260576 | medium ==='
# 'Running: sudo grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | sudo awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ocsp_on '
sudo grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | sudo awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ocsp_on 

# V-260577 | medium | Ubuntu 22.04 LTS, for PKI-based authentication, must validate certificates by constructing a certification path (which includes status information) to an accepted trust anchor.
echo '=== V-260577 | medium ==='
# 'Running: sudo grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | sudo awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ca   '
sudo grep use_pkcs11_module /etc/pam_pkcs11/pam_pkcs11.conf | sudo awk '/pkcs11_module opensc {/,/}/' /etc/pam_pkcs11/pam_pkcs11.conf | grep cert_policy | grep ca   

# V-260578 | medium | Ubuntu 22.04 LTS for PKI-based authentication, must implement a local cache of revocation data in case of the inability to access revocation information via the network.
echo '=== V-260578 | medium ==='
# 'Running: grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf | grep  -E -- 'crl_auto|crl_offline' '
grep cert_policy /etc/pam_pkcs11/pam_pkcs11.conf | grep  -E -- 'crl_auto|crl_offline' 

# V-260580 | medium | Ubuntu 22.04 LTS must use DOD PKI-established certificate authorities for verification of the establishment of protected sessions.
echo '=== V-260580 | medium ==='
# 'Running: ls /etc/ssl/certs | grep -i DOD '
ls /etc/ssl/certs | grep -i DOD 
# 'Running: ls /etc/ssl/certs '
ls /etc/ssl/certs 

# V-260582 | medium | Ubuntu 22.04 LTS must use a file integrity tool to verify correct operation of all security functions.
echo '=== V-260582 | medium ==='
# 'Running: dpkg -l | grep aide '
dpkg -l | grep aide 

# V-260583 | medium | Ubuntu 22.04 LTS must configure AIDE to perform file integrity checking on the file system.
echo '=== V-260583 | medium ==='
# 'Running: sudo aide -c /etc/aide/aide.conf --check '
sudo aide -c /etc/aide/aide.conf --check 

# V-260584 | medium | Ubuntu 22.04 LTS must notify designated personnel if baseline configurations are changed in an unauthorized manner. The file integrity tool must notify the system administrator when changes to the baseline configuration or anomalies in the operation of any security functions are discovered.
echo '=== V-260584 | medium ==='
# 'Running: grep -i '^\s*silentreports' /etc/default/aide  '
grep -i '^\s*silentreports' /etc/default/aide  

# V-260585 | medium | Ubuntu 22.04 LTS must be configured so that the script that runs each 30 days or less to check file integrity is the default.
echo '=== V-260585 | medium ==='
# 'Running: cd /tmp; apt download aide-common '
cd /tmp; apt download aide-common 
# 'Running: dpkg-deb --fsys-tarfile /tmp/aide-common_*.deb | tar -xO ./usr/share/aide/config/cron.daily/aide | sha1sum '
dpkg-deb --fsys-tarfile /tmp/aide-common_*.deb | tar -xO ./usr/share/aide/config/cron.daily/aide | sha1sum 
# 'Running: sha1sum /etc/cron.{daily,monthly}/aide 2>/dev/null '
sha1sum /etc/cron.{daily,monthly}/aide 2>/dev/null 

# V-260586 | medium | Ubuntu 22.04 LTS must use cryptographic mechanisms to protect the integrity of audit tools.
echo '=== V-260586 | medium ==='
# 'Running: grep -E '(\/sbin\/(audit|au))' /etc/aide/aide.conf '
grep -E '(\/sbin\/(audit|au))' /etc/aide/aide.conf 

# V-260588 | medium | Ubuntu 22.04 LTS must be configured to preserve log records from failure events.
echo '=== V-260588 | medium ==='
# 'Running: dpkg -l | grep rsyslog '
dpkg -l | grep rsyslog 
# 'Running: systemctl is-enabled rsyslog.service '
systemctl is-enabled rsyslog.service 
# 'Running: systemctl is-active rsyslog.service '
systemctl is-active rsyslog.service 

# V-260589 | medium | Ubuntu 22.04 LTS must monitor remote access methods.
echo '=== V-260589 | medium ==='
# 'Running:  grep -Er '^(auth\.\*,authpriv\.\*|daemon\.\*)' /etc/rsyslog.* '
 grep -Er '^(auth\.\*,authpriv\.\*|daemon\.\*)' /etc/rsyslog.* 

# V-260590 | medium | Ubuntu 22.04 LTS must have the "auditd" package installed.
echo '=== V-260590 | medium ==='
# 'Running: dpkg -l | grep auditd '
dpkg -l | grep auditd 

# V-260591 | medium | Ubuntu 22.04 LTS must produce audit records and reports containing information to establish when, where, what type, the source, and the outcome for all DOD-defined auditable events and actions in near real time.
echo '=== V-260591 | medium ==='
# 'Running: systemctl is-enabled auditd.service '
systemctl is-enabled auditd.service 
# 'Running: systemctl is-active auditd.service '
systemctl is-active auditd.service 

# V-260594 | medium | Ubuntu 22.04 LTS must shut down by default upon audit failure.
echo '=== V-260594 | medium ==='
# 'Running: sudo grep -i disk_full_action /etc/audit/auditd.conf '
sudo grep -i disk_full_action /etc/audit/auditd.conf 

# V-260597 | medium | Ubuntu 22.04 LTS must be configured so that audit log files are not read- or write-accessible by unauthorized users.
echo '=== V-260597 | medium ==='
# 'Running: sudo grep -iw log_file /etc/audit/auditd.conf '
sudo grep -iw log_file /etc/audit/auditd.conf 
# 'Running: sudo stat -c "%n %a" /var/log/audit/* '
sudo stat -c "%n %a" /var/log/audit/* 

# V-260598 | medium | Ubuntu 22.04 LTS must be configured to permit only authorized users ownership of the audit log files.
echo '=== V-260598 | medium ==='
# 'Running: sudo grep -iw log_file /etc/audit/auditd.conf '
sudo grep -iw log_file /etc/audit/auditd.conf 
# 'Running: sudo stat -c "%n %U" /var/log/audit/* '
sudo stat -c "%n %U" /var/log/audit/* 

# V-260599 | medium | Ubuntu 22.04 LTS must permit only authorized groups ownership of the audit log files.
echo '=== V-260599 | medium ==='
# 'Running: sudo grep -iw log_group /etc/audit/auditd.conf '
sudo grep -iw log_group /etc/audit/auditd.conf 

# V-260600 | medium | Ubuntu 22.04 LTS must be configured so that the audit log directory is not write-accessible by unauthorized users.
echo '=== V-260600 | medium ==='
# 'Running: sudo grep -iw log_file /etc/audit/auditd.conf '
sudo grep -iw log_file /etc/audit/auditd.conf 
# 'Running: sudo stat -c "%n %a" /var/log/audit '
sudo stat -c "%n %a" /var/log/audit 

# V-260601 | medium | Ubuntu 22.04 LTS must be configured so that audit configuration files are not write-accessible by unauthorized users.
echo '=== V-260601 | medium ==='
# 'Running: sudo ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print $1, $9}' '
sudo ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print $1, $9}' 

# V-260602 | medium | Ubuntu 22.04 LTS must permit only authorized accounts to own the audit configuration files.
echo '=== V-260602 | medium ==='
# 'Running: sudo ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print $3, $9}' '
sudo ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print $3, $9}' 

# V-260603 | medium | Ubuntu 22.04 LTS must permit only authorized groups to own the audit configuration files.
echo '=== V-260603 | medium ==='
# 'Running: sudo ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print $4, $9}'  '
sudo ls -al /etc/audit/audit.rules /etc/audit/auditd.conf /etc/audit/rules.d/* | awk '{print $4, $9}'  

# V-260604 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the apparmor_parser command.
echo '=== V-260604 | medium ==='
# 'Running: sudo auditctl -l | grep apparmor_parser '
sudo auditctl -l | grep apparmor_parser 

# V-260605 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chacl command.
echo '=== V-260605 | medium ==='
# 'Running: sudo auditctl -l | grep chacl '
sudo auditctl -l | grep chacl 

# V-260606 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chage command.
echo '=== V-260606 | medium ==='
# 'Running: sudo auditctl -l | grep -w chage '
sudo auditctl -l | grep -w chage 

# V-260607 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chcon command.
echo '=== V-260607 | medium ==='
# 'Running: sudo auditctl -l | grep chcon '
sudo auditctl -l | grep chcon 

# V-260608 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chfn command.
echo '=== V-260608 | medium ==='
# 'Running: sudo auditctl -l | grep /usr/bin/chfn '
sudo auditctl -l | grep /usr/bin/chfn 

# V-260609 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chsh command.
echo '=== V-260609 | medium ==='
# 'Running: sudo auditctl -l | grep chsh '
sudo auditctl -l | grep chsh 

# V-260610 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the crontab command.
echo '=== V-260610 | medium ==='
# 'Running: sudo auditctl -l | grep -w crontab '
sudo auditctl -l | grep -w crontab 

# V-260611 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful attempts to use the fdisk command.
echo '=== V-260611 | medium ==='
# 'Running: sudo auditctl -l | grep fdisk '
sudo auditctl -l | grep fdisk 

# V-260612 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the gpasswd command.
echo '=== V-260612 | medium ==='
# 'Running: sudo auditctl -l | grep -w gpasswd '
sudo auditctl -l | grep -w gpasswd 

# V-260613 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful attempts to use the kmod command.
echo '=== V-260613 | medium ==='
# 'Running: sudo auditctl -l | grep kmod  '
sudo auditctl -l | grep kmod  

# V-260614 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful attempts to use modprobe command.
echo '=== V-260614 | medium ==='
# 'Running: sudo auditctl -l | grep /sbin/modprobe '
sudo auditctl -l | grep /sbin/modprobe 

# V-260615 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the mount command.
echo '=== V-260615 | medium ==='
# 'Running: sudo auditctl -l | grep /usr/bin/mount '
sudo auditctl -l | grep /usr/bin/mount 

# V-260616 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the newgrp command.
echo '=== V-260616 | medium ==='
# 'Running: sudo auditctl -l | grep newgrp '
sudo auditctl -l | grep newgrp 

# V-260617 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the pam_timestamp_check command.
echo '=== V-260617 | medium ==='
# 'Running: sudo auditctl -l | grep -w pam_timestamp_check '
sudo auditctl -l | grep -w pam_timestamp_check 

# V-260618 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the passwd command.
echo '=== V-260618 | medium ==='
# 'Running: sudo auditctl -l | grep -w passwd '
sudo auditctl -l | grep -w passwd 

# V-260619 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the setfacl command.
echo '=== V-260619 | medium ==='
# 'Running: sudo auditctl -l | grep setfacl '
sudo auditctl -l | grep setfacl 

# V-260620 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the ssh-agent command.
echo '=== V-260620 | medium ==='
# 'Running: sudo auditctl -l | grep /usr/bin/ssh-agent '
sudo auditctl -l | grep /usr/bin/ssh-agent 

# V-260621 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the ssh-keysign command.
echo '=== V-260621 | medium ==='
# 'Running: sudo auditctl -l | grep ssh-keysign '
sudo auditctl -l | grep ssh-keysign 

# V-260622 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the su command.
echo '=== V-260622 | medium ==='
# 'Running: sudo auditctl -l | grep /bin/su '
sudo auditctl -l | grep /bin/su 

# V-260623 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the sudo command.
echo '=== V-260623 | medium ==='
# 'Running: sudo auditctl -l | grep /usr/bin/sudo  '
sudo auditctl -l | grep /usr/bin/sudo  

# V-260624 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the sudoedit command.
echo '=== V-260624 | medium ==='
# 'Running: sudo auditctl -l | grep /usr/bin/sudoedit '
sudo auditctl -l | grep /usr/bin/sudoedit 

# V-260625 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the umount command.
echo '=== V-260625 | medium ==='
# 'Running: sudo auditctl -l | grep /usr/bin/umount '
sudo auditctl -l | grep /usr/bin/umount 

# V-260626 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the unix_update command.
echo '=== V-260626 | medium ==='
# 'Running: sudo auditctl -l | grep -w unix_update '
sudo auditctl -l | grep -w unix_update 

# V-260627 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the usermod command.
echo '=== V-260627 | medium ==='
# 'Running: sudo auditctl -l | grep -w usermod '
sudo auditctl -l | grep -w usermod 

# V-260628 | medium | Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group.
echo '=== V-260628 | medium ==='
# 'Running: sudo auditctl -l | grep group '
sudo auditctl -l | grep group 

# V-260629 | medium | Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/gshadow.
echo '=== V-260629 | medium ==='
# 'Running: sudo auditctl -l | grep gshadow '
sudo auditctl -l | grep gshadow 

# V-260630 | medium | Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/opasswd.
echo '=== V-260630 | medium ==='
# 'Running: sudo auditctl -l | grep opasswd '
sudo auditctl -l | grep opasswd 

# V-260631 | medium | Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/passwd.
echo '=== V-260631 | medium ==='
# 'Running: sudo auditctl -l | grep passwd '
sudo auditctl -l | grep passwd 

# V-260632 | medium | Ubuntu 22.04 LTS must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/shadow.
echo '=== V-260632 | medium ==='
# 'Running: sudo auditctl -l | grep shadow '
sudo auditctl -l | grep shadow 

# V-260633 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chmod, fchmod, and fchmodat system calls.
echo '=== V-260633 | medium ==='
# 'Running: sudo auditctl -l | grep chmod '
sudo auditctl -l | grep chmod 

# V-260634 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the chown, fchown, fchownat, and lchown system calls.
echo '=== V-260634 | medium ==='
# 'Running: sudo auditctl -l | grep chown  '
sudo auditctl -l | grep chown  

# V-260635 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the creat, open, openat, open_by_handle_at, truncate, and ftruncate system calls.
echo '=== V-260635 | medium ==='
# 'Running: sudo auditctl -l | grep 'open\|truncate\|creat'  '
sudo auditctl -l | grep 'open\|truncate\|creat'  

# V-260636 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the delete_module system call.
echo '=== V-260636 | medium ==='
# 'Running: sudo auditctl -l | grep -w delete_module  '
sudo auditctl -l | grep -w delete_module  

# V-260637 | medium | Ubuntu 22.04 LTS must generate audit records for successful/unsuccessful uses of the init_module and finit_module system calls.
echo '=== V-260637 | medium ==='
# 'Running: sudo auditctl -l | grep init_module  '
sudo auditctl -l | grep init_module  

# V-260638 | medium | Ubuntu 22.04 LTS must generate audit records for any use of the setxattr, fsetxattr, lsetxattr, removexattr, fremovexattr, and lremovexattr system calls.
echo '=== V-260638 | medium ==='
# 'Running: sudo auditctl -l | grep xattr  '
sudo auditctl -l | grep xattr  

# V-260639 | medium | Ubuntu 22.04 LTS must generate audit records for any successful/unsuccessful use of unlink, unlinkat, rename, renameat, and rmdir system calls.
echo '=== V-260639 | medium ==='
# 'Running: sudo auditctl -l | grep 'unlink\|rename\|rmdir'  '
sudo auditctl -l | grep 'unlink\|rename\|rmdir'  

# V-260640 | medium | Ubuntu 22.04 LTS must generate audit records for all events that affect the systemd journal files.
echo '=== V-260640 | medium ==='
# 'Running: sudo auditctl -l | grep journal  '
sudo auditctl -l | grep journal  

# V-260641 | medium | Ubuntu 22.04 LTS must generate audit records for the /var/log/btmp file.
echo '=== V-260641 | medium ==='
# 'Running: sudo auditctl -l | grep '/var/log/btmp'  '
sudo auditctl -l | grep '/var/log/btmp'  

# V-260642 | medium | Ubuntu 22.04 LTS must generate audit records for the /var/log/wtmp file.
echo '=== V-260642 | medium ==='
# 'Running: sudo auditctl -l | grep '/var/log/wtmp'  '
sudo auditctl -l | grep '/var/log/wtmp'  

# V-260643 | medium | Ubuntu 22.04 LTS must generate audit records for the /var/run/utmp file.
echo '=== V-260643 | medium ==='
# 'Running: sudo auditctl -l | grep '/var/run/utmp'  '
sudo auditctl -l | grep '/var/run/utmp'  

# V-260644 | medium | Ubuntu 22.04 LTS must generate audit records for the use and modification of faillog file.
echo '=== V-260644 | medium ==='
# 'Running: sudo auditctl -l | grep faillog  '
sudo auditctl -l | grep faillog  

# V-260645 | medium | Ubuntu 22.04 LTS must generate audit records for the use and modification of the lastlog file.
echo '=== V-260645 | medium ==='
# 'Running: sudo auditctl -l | grep lastlog  '
sudo auditctl -l | grep lastlog  

# V-260646 | medium | Ubuntu 22.04 LTS must generate audit records when successful/unsuccessful attempts to modify the /etc/sudoers file occur.
echo '=== V-260646 | medium ==='
# 'Running: sudo auditctl -l | grep sudoers  '
sudo auditctl -l | grep sudoers  

# V-260647 | medium | Ubuntu 22.04 LTS must generate audit records when successful/unsuccessful attempts to modify the /etc/sudoers.d directory occur.
echo '=== V-260647 | medium ==='
# 'Running: sudo auditctl -l | grep sudoers.d  '
sudo auditctl -l | grep sudoers.d  

# V-260648 | medium | Ubuntu 22.04 LTS must prevent all software from executing at higher privilege levels than users executing the software and the audit system must be configured to audit the execution of privileged functions.
echo '=== V-260648 | medium ==='
# 'Running: sudo auditctl -l | grep execve '
sudo auditctl -l | grep execve 

# V-260649 | medium | Ubuntu 22.04 LTS must generate audit records for privileged activities, nonlocal maintenance, diagnostic sessions and other system-level access.
echo '=== V-260649 | medium ==='
# 'Running: sudo auditctl -l | grep sudo.log  '
sudo auditctl -l | grep sudo.log  

# V-274860 | medium | The operating system must require users to provide a password for privilege escalation.
echo '=== V-274860 | medium ==='
# 'Running: sudo egrep -iR 'NOPASSWD' /etc/sudoers /etc/sudoers.d/'
sudo egrep -iR 'NOPASSWD' /etc/sudoers /etc/sudoers.d/

# V-274861 | medium | The operating system must restrict privilege elevation to authorized personnel.
echo '=== V-274861 | medium ==='
# 'Running: sudo grep -iwR 'ALL' /etc/sudoers /etc/sudoers.d/ | grep -v '#''
sudo grep -iwR 'ALL' /etc/sudoers /etc/sudoers.d/ | grep -v '#'

# V-274862 | medium | Ubuntu 22.04 LTS must audit any script or executable called by cron as root or by any privileged user.
echo '=== V-274862 | medium ==='
# 'Running: sudo auditctl -l | grep /etc/cron.d'
sudo auditctl -l | grep /etc/cron.d
# 'Running: sudo auditctl -l | grep /var/spool/cron'
sudo auditctl -l | grep /var/spool/cron

# V-274864 | medium | Ubuntu 22.04 LTS must have the "SSSD" package installed.
echo '=== V-274864 | medium ==='
# 'Running: dpkg -l | grep sssd'
dpkg -l | grep sssd
# 'Running: dpkg -l | grep libpam-sss'
dpkg -l | grep libpam-sss
# 'Running: dpkg -l | grep libnss-sss'
dpkg -l | grep libnss-sss

# V-274865 | medium | Ubuntu 22.04 LTS must map the authenticated identity to the user or group account for PKI-based authentication.
echo '=== V-274865 | medium ==='
# 'Running: grep -i ldap_user_certificate /etc/sssd/sssd.conf'
grep -i ldap_user_certificate /etc/sssd/sssd.conf

# V-274866 | medium | Ubuntu 22.04 LTS must use the "SSSD" package for multifactor authentication services.
echo '=== V-274866 | medium ==='
# 'Running: sudo systemctl is-enabled sssd'
sudo systemctl is-enabled sssd
# 'Running: sudo systemctl is-active sssd'
sudo systemctl is-active sssd

# V-274867 | medium | Ubuntu 22.04 LTS must ensure SSSD performs certificate path validation, including revocation checking, against a trusted anchor for PKI-based authentication.
echo '=== V-274867 | medium ==='
# 'Running: sudo grep -A 1 '^\[sssd\]' /etc/sssd/sssd.conf'
sudo grep -A 1 '^\[sssd\]' /etc/sssd/sssd.conf
# 'Running: sudo grep -A 1 '^\[pam]' /etc/sssd/sssd.conf'
sudo grep -A 1 '^\[pam]' /etc/sssd/sssd.conf
# 'Running: sudo grep certificate_verification /etc/sssd/sssd.conf'
sudo grep certificate_verification /etc/sssd/sssd.conf

