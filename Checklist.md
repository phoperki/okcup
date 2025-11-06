## Updates
apt-get update && apt-get upgrade

## Enable Firewall
sudo ufw enable

## SSH Settings
PermitRootLogin no
ChallengeResponseAuthentication no
PasswordAuthentication no
UsePAM no
PermitEmptyPasswords no
ClientAliveInterval 300
ClientAliveCountMax 0

Check sudo users group:
grep sudo /etc/group