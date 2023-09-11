#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
deploy_user=$(python3 "${CURRENT_PATH}"/get_config_info.py "deploy_user")

su - "${deploy_user}" -s /bin/bash -c "chmod 750 /mnt/dbdata/local/cantian/tmp/data/dbstor"
su - "${deploy_user}" -s /bin/bash -c "chmod 750 /mnt/dbdata/local/cantian/tmp/data/dbstor/data"
su - "${deploy_user}" -s /bin/bash -c "chmod 750 /mnt/dbdata/local/cantian/tmp/data/dbstor/data/logs"
su - "${deploy_user}" -s /bin/bash -c "chmod 750 /mnt/dbdata/local/cantian/tmp/data/dbstor/data/logs/run"
su - "${deploy_user}" -s /bin/bash -c "chmod 640 /mnt/dbdata/local/cantian/tmp/data/dbstor/data/logs/run/*"

su - "${deploy_user}" -s /bin/bash -c "chmod 640 /mnt/dbdata/local/cantian/tmp/data/log/cantianstatus.log"
su - "${deploy_user}" -s /bin/bash -c "chmod 640 /opt/cantian/cms/log/run/*"