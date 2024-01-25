#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
source "${CURRENT_PATH}"/env.sh
deploy_user=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_user")


su - "${cantian_user}" -s /bin/bash -c "chown -hR ${cantian_user}:${cantian_common_group} /mnt/dbdata/local/cantian"
su - "${cantian_user}" -s /bin/bash -c "chmod 750 /mnt/dbdata/local/cantian/tmp/data/dbstor"
su - "${cantian_user}" -s /bin/bash -c "chmod 750 /mnt/dbdata/local/cantian/tmp/data/dbstor/data"
su - "${cantian_user}" -s /bin/bash -c "chmod 750 /mnt/dbdata/local/cantian/tmp/data/dbstor/data/logs"
su - "${cantian_user}" -s /bin/bash -c "chmod 750 /mnt/dbdata/local/cantian/tmp/data/dbstor/data/logs/run"
su - "${cantian_user}" -s /bin/bash -c "chmod 640 /mnt/dbdata/local/cantian/tmp/data/dbstor/data/logs/run/*"
su - "${cantian_user}" -s /bin/bash -c "chmod 640 /mnt/dbdata/local/cantian/tmp/data/log/cantianstatus.log"
su - "${cantian_user}" -s /bin/bash -c "chmod 640 /opt/cantian/cms/log/run/*"

su - "${deploy_user}" -s /bin/bash -c "chgrp ${cantian_common_group} /mnt/dbdata/remote/metadata_*/*/mysql/*.log" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "chown -hR ${cantian_user}:${cantian_common_group} /opt/cantian/ct_om/logs"
su - "${cantian_user}" -s /bin/bash -c "chown ${cantian_user}:${cantian_common_group} /opt/cantian/dbstor/"
su - "${cantian_user}" -s /bin/bash -c "chown -hR ${cantian_user}:${cantian_common_group} /opt/cantian/dbstor/log"
su - "${cantian_user}" -s /bin/bash -c "chown ${cantian_user}:${cantian_common_group} /opt/cantian/cantian/"
su - "${cantian_user}" -s /bin/bash -c "chown -hR ${cantian_user}:${cantian_common_group} /opt/cantian/cantian/log"
su - "${cantian_user}" -s /bin/bash -c "chown ${cantian_user}:${cantian_common_group} /opt/cantian/cms/"
su - "${cantian_user}" -s /bin/bash -c "chown -hR ${cantian_user}:${cantian_common_group} /opt/cantian/cms/log"