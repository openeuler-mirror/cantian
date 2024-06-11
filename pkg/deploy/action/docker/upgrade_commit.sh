#!/bin/bash
set +x

CURRENT_PATH=$(dirname $(readlink -f $0))
PKG_PATH=${CURRENT_PATH}/../..
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
CLUSTER_COMMIT_STATUS=("prepared" "commit")
storage_metadata_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_metadata_fs"`
node_id=`python3 ${CURRENT_PATH}/get_config_info.py "node_id"`
cantian_user=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_user"`
METADATA_FS_PATH="/mnt/dbdata/remote/metadata_${storage_metadata_fs}"
VERSION_FILE="versions.yml"
WAIT_TIME=10

source "${CURRENT_PATH}"/../log4sh.sh
source "${CURRENT_PATH}"/../env.sh

function init_cluster_status_flag() {
    logAndEchoInfo "begin to init cluster status flag"

    upgrade_path="${METADATA_FS_PATH}/upgrade"
    cluster_and_node_status_path="${upgrade_path}/cluster_and_node_status"
    cluster_status_flag="${cluster_and_node_status_path}/cluster_status.txt"
    modify_sys_table_success_flag="${storage_metadata_fs_path}/updatesys.success"
    source_version=`cat ${METADATA_FS_PATH}/${VERSION_FILE} | grep 'Version:' | awk -F ":" '{print $2}' | sed -r 's/[a-z]*[A-Z]*0*([0-9])/\1/' | sed 's/ //g'`
    cluster_commit_flag="${upgrade_path}/cantian_upgrade_commit_${source_version}.success"

    logAndEchoInfo "init cluster status flag success"
}

function check_upgrade_commit_flag() {
    # 解决网络波动导致的标记文件延后感知问题
    try_times=3
    while [ ${try_times} -gt 0 ]
    do
        try_times=$(expr "${try_times}" - 1)
        if [ -f "${cluster_commit_flag}" ]; then
            logAndEchoInfo "flag file '${cluster_commit_flag}' has been detected"
            return 0
        else
            logAndEchoInfo "flag file '${cluster_commit_flag}' is not detected, remaining attempts: ${try_times}"
            sleep "${WAIT_TIME}"
        fi
    done

    return 1
}

function cluster_status_check() {
    logAndEchoInfo "begin to check cluster status"

    if [ -z "${cluster_status_flag}" ] || [ ! -e "${cluster_status_flag}" ]; then
        logAndEchoError "cluster status file '${cluster_and_node_status_path}' does not exist."
        exit 1
    fi

    cluster_status=$(cat ${cluster_status_flag})
    if [ -z "${cluster_status}" ]; then
        logAndEchoError "no cluster status information in '${cluster_and_node_status_path}'"
        exit 1
    elif [[ " ${CLUSTER_COMMIT_STATUS[*]} " != *" ${cluster_status} "* ]]; then
        logAndEchoError "the cluster status must be one of  '${CLUSTER_COMMIT_STATUS[@]}', instead of ${cluster_status}"
        exit 1
    fi

    logAndEchoInfo "check cluster status success, current cluster status: ${cluster_status}"
}

function modify_cluster_status() {
    # 串入参数依次是：状态文件绝对路径、新的状态、集群或节点标志
    local cluster_or_node_status_file_path=$1
    local new_status=$2

    if [ -n "${cluster_or_node_status_file_path}" ] && [ ! -e "${cluster_or_node_status_file_path}" ]; then
        logAndEchoInfo "rollup upgrade status of '${cluster_or_node}' does not exist."
        exit 1
    fi

    old_status=$(cat ${cluster_or_node_status_file_path})
    if [ "${old_status}" == "${new_status}" ]; then
        logAndEchoInfo "the old status of current cluster is consistent with the new status, both are ${new_status}"
        return 0
    fi

    echo "${new_status}" > ${cluster_or_node_status_file_path}
    if [ $? -eq 0 ]; then
        logAndEchoInfo "change upgrade status of current cluster from '${old_status}' to '${new_status}' success."
        return 0
    else
        logAndEchoInfo "change upgrade status of current cluster from '${old_status}' to '${new_status}' failed."
        exit 1
    fi
}

function raise_version_num() {
    logAndEchoInfo "begin to call cms tool to raise the version num"
    target_numbers=$(cat ${PKG_PATH}/${VERSION_FILE} | grep -E "Version:" | awk '{print $2}' | \sed 's/\([0-9]*\.[0-9]*\)\(\.[0-9]*\)\?\.[A-Z].*/\1\2/')
    format_target="${target_numbers[@]//./ } 0"

    for ((i=1;i<11;i++))
    do
        su -s /bin/bash - "${cantian_user}" -c "cms upgrade -version ${format_target}"
        if [ $? -ne 0 ]; then
            logAndEchoError "calling cms tool to raise the version num failed, current attempt:${i}/10".
            sleep 10
            continue
        else
            break
        fi
    done
    if [ $i -eq 11 ];then
        exit 1
    fi
    logAndEchoInfo "calling cms tool to raise the version num success"
    return 0
}

function upgrade_commit() {
    if [[ x"${node_id}" != x"0" ]];then
        logAndEchoError "Upgrade commit only allows operations at node 0. Please check."
        exit 1
    fi
    cluster_status_check
    modify_cluster_status "${cluster_status_flag}" "commit"
    raise_version_num
    modify_cluster_status "${cluster_status_flag}" "normal"
    touch "${cluster_commit_flag}" && chmod 400 "${cluster_commit_flag}"
    # 等待创建的标记文件生效
    sleep "${WAIT_TIME}"
    check_upgrade_commit_flag
    if [ $? -ne 0 ]; then
        logAndEchoError "Touch rollup upgrade commit tag file failed."
        exit 1
    fi
}

function clear_upgrade_residual_data() {
    logAndEchoInfo "begin to clear residual data"
    target_version=`cat ${PKG_PATH}/${VERSION_FILE} | grep 'Version:' | awk -F ":" '{print $2}' | sed -r 's/[a-z]*[A-Z]*0*([0-9])/\1/' | sed 's/ //g'`
    modify_sys_table_success_flag="${upgrade_path}/updatesys.success"
    modify_sys_tables_failed="${upgrade_path}/updatesys.failed"
    # 删除状态文件
    if [ -d ${cluster_and_node_status_path} ]; then
        rm -rf ${cluster_and_node_status_path}
    fi
    # 删除修改系统表成功的标记文件
    if [ -f "${modify_sys_table_success_flag}" ]; then
        rm -f"${modify_sys_table_success_flag}"
    fi
    if [ -f "${modify_sys_tables_failed}" ]; then
        rm -f"${modify_sys_tables_failed}"
    fi
    if [[ -n $(ls "${upgrade_path}"/upgrade_node*."${target_version}") ]];then
        rm -f "${upgrade_path}"/upgrade_node*."${target_version}"
    fi
    logAndEchoInfo "clear residual data success"
}

function set_version_file() {
    if [ ! -f ${PKG_PATH}/${VERSION_FILE} ]; then
        logAndEchoError "${VERSION_FILE} is not exist!"
        exit 1
    fi

    cp -rf ${PKG_PATH}/${VERSION_FILE} ${METADATA_FS_PATH}/${VERSION_FILE}

    init_sql="/opt/cantian/cantian/server/admin/scripts/initdb.sql"
    cp -rf ${init_sql} "${METADATA_FS_PATH}/initdb.sql"
}

function main() {
    logAndEchoInfo "begin to perform the upgrade commit operation"
    init_cluster_status_flag
    check_upgrade_commit_flag
    if [ $? -eq 0 ]; then
        logAndEchoInfo "perform the upgrade commit operation has been successful"
        return
    fi
    upgrade_commit
    logAndEchoInfo "perform the upgrade commit operation success"
    clear_upgrade_residual_data
    set_version_file
}

main