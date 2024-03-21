#!/bin/bash
set +x

CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
UPGRADE_MODE=$1
PRE_UPGRADE_SUCCESS_FLAG=/opt/cantian/pre_upgrade.success
BACKUP_NOTE=/opt/backup_note
CLUSTER_COMMIT_STATUS=("prepared" "commit")
UPGRADE_MODE_LIS=("offline" "rollup")
WAIT_TIME=10
storage_metadata_fs_path=""
cluster_and_node_status_path=""
cluster_status_flag=""
business_code_backup_path=""
cluster_commit_flag=""
modify_sys_table_success_flag=""


source "${CURRENT_PATH}"/log4sh.sh
source "${CURRENT_PATH}"/env.sh

# 输入参数检查
function input_params_check() {
    if [[ " ${UPGRADE_MODE_LIS[*]} " == *" ${UPGRADE_MODE} "* ]]; then
        logAndEchoInfo "pass upgrade mode check, current upgrade mode: ${UPGRADE_MODE}"
    else
        logAndEchoError "input upgrade module must be one of '${UPGRADE_MODE_LIS[@]}', instead of '${UPGRADE_MODE}'" && exit 1
    fi
}

# 初始化集群状态flag
function init_cluster_status_flag() {
    logAndEchoInfo "begin to init cluster status flag"
    source_version=$(cat "${BACKUP_NOTE}" | awk 'END {print}' | tr ':' ' ' | awk '{print $1}')
    if [ -z "${source_version}" ]; then
        logAndEchoError "failed to obtain source version"
        exit 1
    fi

    storage_metadata_fs=$(python3 ${CURRENT_PATH}/get_config_info.py "storage_metadata_fs")
    node_id=$(python3 ${CURRENT_PATH}/get_config_info.py "node_id")
    if [[ ${storage_metadata_fs} == 'None' ]]; then
        logAndEchoError "obtain current node  storage_metadata_fs error, please check file: config/deploy_param.json"
        exit 1
    fi
    business_code_backup_path="/opt/cantian/upgrade_backup/cantian_upgrade_bak_${source_version}"

    if [ "${UPGRADE_MODE}" == "rollup" ]; then
        storage_metadata_fs_path="/mnt/dbdata/remote/metadata_${storage_metadata_fs}/upgrade/rollup_bak_${source_version}"
        cluster_and_node_status_path="${storage_metadata_fs_path}/cluster_and_node_status"
        cluster_status_flag="${cluster_and_node_status_path}/cluster_status.txt"
        modify_sys_table_success_flag="${storage_metadata_fs_path}/updatesys.success"
    fi

    cluster_commit_flag="/mnt/dbdata/remote/metadata_${storage_metadata_fs}/upgrade/cantian_${UPGRADE_MODE}_upgrade_commit_${source_version}.success"
    PRE_UPGRADE_SUCCESS_FLAG="/opt/cantian/pre_upgrade_${UPGRADE_MODE}.success"

    logAndEchoInfo "init cluster status flag success"
}

# 集群状态检查
function cluster_status_check() {
    logAndEchoInfo "begin to check cluster status"

    if [ -z "${cluster_status_flag}" ] || [ ! -e "${cluster_status_flag}" ]; then
        logAndEchoError "cluster status file '${cluster_and_node_status_path}' does not exist." && exit 1
    fi

    cluster_status=$(cat ${cluster_status_flag})
    if [ -z "${cluster_status}" ]; then
        logAndEchoError "no cluster status information in '${cluster_and_node_status_path}'" && exit 1
    elif [[ " ${CLUSTER_COMMIT_STATUS[*]} " != *" ${cluster_status} "* ]]; then
        logAndEchoError "the cluster status must be one of  '${CLUSTER_COMMIT_STATUS[@]}', instead of ${cluster_status}" && exit 1
    fi

    logAndEchoInfo "check cluster status success, current cluster status: ${cluster_status}"
}

# 更改集群升级状态
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

# 调用cms工具抬升版本号
function raise_version_num() {
    logAndEchoInfo "begin to call cms tool to raise the version num"
    target_numbers=$(cat "${CURRENT_PATH}"/../versions.yml |sed 's/ //g' | grep 'Version:' | awk -F ':' '{print $2}' | sed -n 's/\([0-9]\+\.[0-9]\+\.[0-9]\+\).*/\1/p')
    format_target="${target_numbers[@]//./ }"

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

# 检查升级提交操作标记文件是否存在
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

# 升级确认后清理标记文件
function clear_upgrade_residual_data() {
    logAndEchoInfo "begin to clear residual data"
    target_version=$(python3 ${CURRENT_PATH}/implement/get_source_version.py)
    upgrade_path="/mnt/dbdata/remote/metadata_${storage_metadata_fs}/upgrade"
    storage_metadata_fs_path="${upgrade_path}/rollup_bak_${source_version}"
    cluster_and_node_status_path="${storage_metadata_fs_path}/cluster_and_node_status"
    modify_sys_table_success_flag="${storage_metadata_fs_path}/updatesys.success"
    modify_sys_tables_failed="${storage_metadata_fs_path}/updatesys.failed"
    # 清除升级前预检查标记文件
    if [ -e ${PRE_UPGRADE_SUCCESS_FLAG} ]; then
        rm -f ${PRE_UPGRADE_SUCCESS_FLAG}
    fi
    # 删除状态文件
    if [ -d ${cluster_and_node_status_path} ]; then
        rm -rf ${cluster_and_node_status_path}
    fi
    # 删除调用ctback工具执行成功的标记文件
    if [ -f "${storage_metadata_fs_path}/call_ctback_tool.success" ]; then
        rm -f "${storage_metadata_fs_path}/call_ctback_tool.success"
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

function rollup_upgrade_commit() {
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

# 版本号抬升适配离线升级
function offline_upgrade_commit() {
    dorado_ip=""
    dorado_user=""
    dorado_pwd=""
    do_snapshot_choice=""
    if [[ x"${node_id}" != x"0" ]];then
        logAndEchoError "Upgrade offline commit only allows operations at node 0. Please check."
        exit 1
    fi
    raise_version_num
    deploy_mode=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_mode")
    if [[ x"${deploy_mode}" != x"nas" ]];then
        read -p "Please input dorado_ip:" dorado_ip
        echo "dorado_ip is: ${dorado_ip}"
        ping -c 1 "${dorado_ip}" > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            logAndEchoError "try to ping storage array ip '${dorado_ip}', but failed"
            echo "Please check whether input is correct. If the network is disconnected, manually delete snapshot according to the upgrade guide."
            read -p "Continue upgrade commit please input yes, otherwise exit:" do_snapshot_choice
            echo ""
            if [[ x"${do_snapshot_choice}" != x"yes" ]];then
                exit 1
            fi
        fi
        if [[ x"${do_snapshot_choice}" != x"yes" ]];then
            read -p "please enter dorado_user: " dorado_user
            echo "dbstor_user is: ${dorado_user}"
            read -s -p "please enter dorado_pwd: " dorado_pwd
            echo ''
            echo -e "${dorado_user}\n${dorado_pwd}" | python3 ${CURRENT_PATH}/storage_operate/do_snapshot.py delete "${dorado_ip}" "${business_code_backup_path}"
            if [ $? -ne 0 ]; then
                logAndEchoError "delete snapshot failed"
                exit 1
            fi
            logAndEchoInfo "delete snapshot success."
        fi
    fi
    touch "${cluster_commit_flag}" && chmod 400 "${cluster_commit_flag}"
    # 等待创建的标记文件生效
    sleep "${WAIT_TIME}"
    check_upgrade_commit_flag
    if [ $? -ne 0 ]; then
        logAndEchoError "Touch rollup upgrade commit tag file failed."
        exit 1
    fi
}

function main() {
    logAndEchoInfo "begin to perform the upgrade commit operation, current upgrade mode: ${UPGRADE_MODE}"
    input_params_check
    init_cluster_status_flag
    check_upgrade_commit_flag
    if [ $? -eq 0 ]; then
        logAndEchoInfo "perform the upgrade commit operation has been successful"
        return
    fi
    if [ "${UPGRADE_MODE}" == "rollup" ]; then
        rollup_upgrade_commit
    elif [ "${UPGRADE_MODE}" == "offline" ]; then
        offline_upgrade_commit
    fi
    logAndEchoInfo "perform the upgrade commit operation success"
    clear_upgrade_residual_data
}

main

