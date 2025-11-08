#!/bin/bash

set +e

# V-260469 | high | Ubuntu 22.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence.
echo '=== V-260469 | high ==='
# 'Running: systemctl status ctrl-alt-del.target '
systemctl status ctrl-alt-del.target 

# V-260470 | high | Ubuntu 22.04 LTS, when booted, must require authentication upon booting into single-user and maintenance modes.
echo '=== V-260470 | high ==='
# 'Running: sudo grep -i password /boot/grub/grub.cfg  '
sudo grep -i password /boot/grub/grub.cfg  

# V-260482 | high | Ubuntu 22.04 LTS must not have the "rsh-server" package installed.
echo '=== V-260482 | high ==='
# 'Running: dpkg -l | grep rsh-server '
dpkg -l | grep rsh-server 

# V-260483 | high | Ubuntu 22.04 LTS must not have the "telnet" package installed.
echo '=== V-260483 | high ==='
# 'Running: dpkg -l | grep telnetd '
dpkg -l | grep telnetd 

# V-260523 | high | Ubuntu 22.04 LTS must have SSH installed.
echo '=== V-260523 | high ==='
# 'Running: sudo dpkg -l | grep openssh '
sudo dpkg -l | grep openssh 

# V-260524 | high | Ubuntu 22.04 LTS must use SSH to protect the confidentiality and integrity of transmitted information.
echo '=== V-260524 | high ==='
# 'Running: sudo systemctl is-enabled ssh '
sudo systemctl is-enabled ssh 
# 'Running: sudo systemctl is-active ssh '
sudo systemctl is-active ssh 

# V-260526 | high | Ubuntu 22.04 LTS must not allow unattended or automatic login via SSH.
echo '=== V-260526 | high ==='
# 'Running: sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iEH '(permit(.*?)(passwords|environment))' '
sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iEH '(permit(.*?)(passwords|environment))' 

# V-260529 | high | Ubuntu 22.04 LTS must be configured so that remote X connections are disabled, unless to fulfill documented and validated mission requirements.
echo '=== V-260529 | high ==='
# 'Running: sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'x11forwarding' '
sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH 'x11forwarding' 

# V-260539 | high | Ubuntu 22.04 LTS must disable the x86 Ctrl-Alt-Delete key sequence if a graphical user interface is installed.
echo '=== V-260539 | high ==='
# 'Running: gsettings get org.gnome.settings-daemon.plugins.media-keys logout '
gsettings get org.gnome.settings-daemon.plugins.media-keys logout 

# V-260559 | high | Ubuntu 22.04 LTS must ensure only users who need access to security functions are part of sudo group.
echo '=== V-260559 | high ==='
# 'Running: grep sudo /etc/group  '
grep sudo /etc/group  

# V-260570 | high | Ubuntu 22.04 LTS must not allow accounts configured with blank or null passwords.
echo '=== V-260570 | high ==='
# 'Running: grep nullok /etc/pam.d/common-auth /etc/pam.d/common-password'
grep nullok /etc/pam.d/common-auth /etc/pam.d/common-password

# V-260571 | high | Ubuntu 22.04 LTS must not have accounts configured with blank or null passwords.
echo '=== V-260571 | high ==='
# 'Running: sudo awk -F: '!$2 {print $1}' /etc/shadow '
sudo awk -F: '!$2 {print $1}' /etc/shadow 

# V-260579 | high | Ubuntu 22.04 LTS must map the authenticated identity to the user or group account for PKI-based authentication.
echo '=== V-260579 | high ==='
# 'Running: grep -i use_mappers /etc/pam_pkcs11/pam_pkcs11.conf '
grep -i use_mappers /etc/pam_pkcs11/pam_pkcs11.conf 

# V-260650 | high | Ubuntu 22.04 LTS must implement NIST FIPS-validated cryptography to protect classified information and for the following: To provision digital signatures, to generate cryptographic hashes, and to protect unclassified information requiring confidentiality and cryptographic protection in accordance with applicable federal laws, Executive Orders, directives, policies, regulations, and standards.
echo '=== V-260650 | high ==='
# 'Running: grep -i 1 /proc/sys/crypto/fips_enabled '
grep -i 1 /proc/sys/crypto/fips_enabled 

