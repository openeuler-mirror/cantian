#!/bin/bash

user=$1
core_dir=$2
commitID=$3

if [[ "${user}" == "root" ]]; then
    echo "Root has already created"
    exit 0
fi

useradd -m ${user} -u 5000
chown -R ${user}:${user} ${core_dir}
rm -f /etc/maven/settings.xml
cp /home/regress/CantianKernel/CI/maven/settings.xml /etc/maven/settings.xml
sed -i '/source \/etc\/profile/d' /root/.bashrc
echo "export MYSQL_COMMIT_ID=$commitID" >> /etc/profile
echo "source /etc/profile" >> /root/.bashrc
echo "alias ll='ls -alrt'" >> /etc/profile
echo "source /home/regress/mysql-server/docker/mysql8_exports" >> /etc/profile
echo "${user} ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers


