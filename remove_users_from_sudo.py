import os

# grep sudo /etc/group
sudo_users = []

for user in sudo_users:
    os.system(f"sudo gpasswd -d {user} sudo")