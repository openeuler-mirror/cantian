#!/bin/bash
CURRENT_PATH=$(dirname $(readlink -f $0))
READINESS_FILE="/opt/cantian/readiness"
cantian_user=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_user"`
deploy_user=`python3 ${CURRENT_PATH}/../get_config_info.py "deploy_user"`
deploy_group=`python3 ${CURRENT_PATH}/../get_config_info.py "deploy_group"`
node_id=`python3 ${CURRENT_PATH}/get_config_info.py "node_id"`

cantiand_pid=$(ps -ef | grep -v grep | grep cantiand | awk 'NR==1 {print $2}')
mysql_pid=$(ps -ef | grep -v grep | grep mysqld | awk 'NR==1 {print $2}')
cms_pid=$(ps -ef | grep cms | grep server | grep start | grep -v grep | awk 'NR==1 {print $2}')

# 启动项检查
if [[ "$1" == "startup-check" ]]; then
    if [[ -f "${READINESS_FILE}" ]]; then
        exit 0
    else
        exit 1
    fi
fi

if [[ ! -f "${READINESS_FILE}" ]]; then
    exit 1
fi

if [[ -z "${cantiand_pid}" ]] || [[ -z "${cms_pid}" ]]; then
    exit 1
fi

work_stat=$(su -s /bin/bash - ${cantian_user} -c 'cms stat' | awk -v nid=$((${node_id}+1)) 'NR==nid+1 {print $6}')
if [[ "${work_stat}" != "1" ]]; then
    exit 1
fi

if [[ -z "${mysql_pid}" ]]; then
    su -s /bin/bash - ${deploy_user} -c "python3 -B \
        /opt/cantian/image/cantian_connector/CantianKernel/Cantian-DATABASE-CENTOS-64bit/install.py \
        -U ${deploy_user}:${deploy_group} -l /home/${deploy_user}/logs/install.log \
        -M mysqld -m /opt/cantian/image/cantian_connector/cantian-connector-mysql/scripts/my.cnf -g withoutroot"
    mysql_pid=$(ps -ef | grep -v grep | grep mysqld | awk 'NR==1 {print $2}')
    if [[ -z "${mysql_pid}" ]]; then
        exit 1
    fi
fi

exit 0