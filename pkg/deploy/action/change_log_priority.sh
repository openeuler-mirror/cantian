#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
source "${CURRENT_PATH}"/env.sh
deploy_user=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_user")

su - "${cantian_user}" -s /bin/bash -c "chown -hR :${cantian_common_group} /mnt/dbdata/local/cantian" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "find /mnt/dbdata/local/cantian/tmp/data/dbstor -type d -print0 | xargs -0 chmod 770" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "chmod 660 /mnt/dbdata/local/cantian/tmp/data/dbstor/data/logs/run/*" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "chmod 660 /mnt/dbdata/local/cantian/tmp/data/log/cantianstatus.log" > /dev/null 2>&1

su - "${cantian_user}" -s /bin/bash -c "chown -hR :${cantian_common_group} /opt/cantian/cms/dbstor" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "find /opt/cantian/ -type d -print0 | xargs -0 chmod 770" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "find /opt/cantian/log -type d -print0 | xargs -0 chmod -R 770" > /dev/null 2>&1

su - "${cantian_user}" -s /bin/bash -c "chmod 640 /opt/cantian/cms/dbstor/data/logs/run/*" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "find /opt/cantian/log/cantian -type f -print0 | xargs -0 chmod 660" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "find /opt/cantian/log/cms -type f -print0 | xargs -0 chmod 660" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "find /opt/cantian/log/ct_om -type f -print0 | xargs -0 chmod 660" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "find /opt/cantian/log/deploy -type f -print0 | xargs -0 chmod 660" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "find /opt/cantian/log/logicrep -type f -print0 | xargs -0 chmod 660" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "find /opt/cantian/log/cantian_exporter -type f -print0 | xargs -0 chmod 660" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "find /opt/cantian/log/mysql -type f -print0 | xargs -0 chmod 660" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "find /opt/cantian/log/dbstor -type f -print0 | xargs -0 chmod 660" > /dev/null 2>&1

su - "${cantian_user}" -s /bin/bash -c "chgrp -R ${cantian_common_group} /mnt/dbdata/local/cantian/tmp/data/log/cantianstatus.log" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "chgrp -R ${cantian_common_group} /opt/cantian/log" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "chown -R :${cantian_common_group} /opt/cantian/log" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "chown -R :${cantian_common_group} /opt/cantian/dbstor/" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "chown -R :${cantian_common_group} /opt/cantian/cantian/" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "chown -R :${cantian_common_group} /opt/cantian/cms/" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "chown -R :${cantian_common_group} /opt/cantian/logicrep" > /dev/null 2>&1
su - "${cantian_user}" -s /bin/bash -c "chown -R :${cantian_common_group} /opt/cantian/mysql" > /dev/null 2>&1


