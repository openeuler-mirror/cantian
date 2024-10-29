#!/bin/bash

CURRENT_PATH=$(dirname $(readlink -f $0))
READINESS_FILE="/opt/cantian/readiness"
SINGLE_FLAG="/opt/cantian/cantian/cfg/single_flag"
CMS_ENABLE="/opt/cantian/cms/cfg/cms_enable"

source ${CURRENT_PATH}/docker_common/docker_log.sh

cantian_user=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_user"`
deploy_user=`python3 ${CURRENT_PATH}/../get_config_info.py "deploy_user"`
install_step=`python3 ${CURRENT_PATH}/../cms/get_config_info.py "install_step"`
deploy_group=`python3 ${CURRENT_PATH}/../get_config_info.py "deploy_group"`
run_mode=`python3 ${CURRENT_PATH}/get_config_info.py "M_RUNING_MODE"`
node_id=`python3 ${CURRENT_PATH}/get_config_info.py "node_id"`

cantiand_pid=$(ps -ef | grep cantiand | grep -v grep | awk 'NR==1 {print $2}')
mysql_pid=$(ps -ef | grep /opt/cantian/mysql/install/mysql/bin/mysqld | grep -v grep | awk 'NR==1 {print $2}')
cms_pid=$(ps -ef | grep cms | grep server | grep start | grep -v grep | awk 'NR==1 {print $2}')
cantian_daemon_pid=$(pgrep -f cantian_daemon)


# 手动停止cantian场景不触发飘逸和检查/cms未安装完成也不检查
if [[ -f /opt/cantian/stop.enable ]] || [[ x"${install_step}" != x"3" ]];then
    exit 1
fi
if [[ -f /opt/cantian/cms/res_disable ]];then
    logInfo "DB is manually stopped."
    exit 1
fi

# 启动项检查
if [[ "$1" == "startup-check" ]]; then
    if [[ -f "${READINESS_FILE}" ]]; then
        exit 0
    else
        exit 1
    fi
fi

function handle_failure() {
    if [[ -n "${cms_pid}" ]]; then
        manual_stop_count=$(su -s /bin/bash - ${cantian_user} -c "source ~/.bashrc && cms stat" | grep 'db' | awk '{if($5=="OFFLINE" && $1=='"${node_id}"'){print $5}}' | wc -l)
        if [[ -f "${CMS_ENABLE}" ]] && [[ ${manual_stop_count} -eq 1 ]]; then
            logInfo "CMS is manually stopped. Exiting."
            exit 1
        fi
    fi

    if [[ -f "${READINESS_FILE}" ]]; then
        python3 ${CURRENT_PATH}/delete_unready_pod.py
    fi
    exit 1
}

if [[ ! -f "${READINESS_FILE}" ]]; then
    exit 1
fi

if [[ -z "${cantiand_pid}" ]] && [[ "${run_mode}" == "cantiand_in_cluster" ]]; then
    logWarn "Cantiand process not running in cluster mode."
    handle_failure
fi

if [[ -z "${cms_pid}" ]]; then
    logWarn "CMS process not found."
    handle_failure
fi

work_stat=$(su -s /bin/bash - ${cantian_user} -c 'cms stat' | awk -v nid=$((${node_id}+1)) 'NR==nid+1 {print $6}')
if [[ "${work_stat}" != "1" ]]; then
    logWarn "Work status is not 1."
    handle_failure
fi

if [[ -z "${mysql_pid}" ]] && [[ "${run_mode}" == "cantiand_in_cluster" ]]; then
    logInfo "MySQL process not found. Attempting to start."
    su -s /bin/bash - ${deploy_user} -c "python3 -B \
        /opt/cantian/image/cantian_connector/CantianKernel/Cantian-DATABASE-CENTOS-64bit/install.py \
        -U ${deploy_user}:${deploy_group} -l /home/${deploy_user}/logs/install.log \
        -M mysqld -m /opt/cantian/image/cantian_connector/cantian-connector-mysql/scripts/my.cnf -g withoutroot"
    mysql_pid=$(ps -ef | grep /opt/cantian/mysql/install/mysql/bin/mysqld | grep -v grep | awk 'NR==1 {print $2}')
    if [[ -z "${mysql_pid}" ]]; then
        logError "Failed to start MySQL."
        handle_failure
    else
        logInfo "MySQL started successfully."
    fi
fi

if [[ -z "${cantian_daemon_pid}" ]]; then
    logInfo "Cantian daemon not found. Attempting to start."
    if [[ -f /opt/cantian/stop.enable ]];then
        logInfo "Cantian daemon not found. because to stop."
        exit 1
    fi
    /bin/bash /opt/cantian/common/script/cantian_service.sh start
    cantian_daemon_pid=$(pgrep -f cantian_daemon)
    if [[ -z "${cantian_daemon_pid}" ]]; then
        logError "Failed to start Cantian daemon."
        handle_failure
    else
        logInfo "Cantian daemon started successfully."
    fi
fi

exit 0