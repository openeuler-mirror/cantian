#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
source "${CURRENT_PATH}"/env.sh
deploy_user=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_user")

su - "${cantian_user}" -s /bin/bash -c "chown -hR :${cantian_common_group} /mnt/dbdata/local/cantian" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "find /mnt/dbdata/local/cantian/tmp/data/dbstor -type d -print0 | xargs -0 chmod 750" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "chmod 640 /mnt/dbdata/local/cantian/tmp/data/dbstor/data/logs/run/*" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "chmod 640 /mnt/dbdata/local/cantian/tmp/data/log/cantianstatus.log" > /dev/null 2>&1

su - "${cantian_user}" -s /bin/bash -c "chown -hR :${cantian_common_group} /opt/cantian/cms/dbstor" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "find /opt/cantian/ -type d -print0 | xargs -0 chmod 750" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "chmod 640 /opt/cantian/cms/dbstor/data/logs/run/*" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "chmod 640 /opt/cantian/cms/log/run/*"

su - "${deploy_user}" -s /bin/bash -c "chgrp ${cantian_common_group} /mnt/dbdata/remote/metadata_*/*/mysql/*.log" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "chown -hR :${cantian_common_group} /opt/cantian/ct_om/log" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "chown $:${cantian_common_group} /opt/cantian/dbstor/" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "chown -hR :${cantian_common_group} /opt/cantian/dbstor/log" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "chown :${cantian_common_group} /opt/cantian/cantian/" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "chown -hR :${cantian_common_group} /opt/cantian/cantian/log" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "chown :${cantian_common_group} /opt/cantian/cms/" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "chown -hR :${cantian_common_group} /opt/cantian/cms/log" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "chown :${cantian_common_group} /opt/cantian/mysql" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "chown -hR :${cantian_common_group} /opt/cantian/mysql/log" > /dev/null 2>&1
