#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
PKG_PATH=${CURRENT_PATH}/../..
VERSION_FILE="versions.yml"
SCRIPT_NAME="container_upgrade.sh"

storage_metadata_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_metadata_fs"`
node_id=`python3 ${CURRENT_PATH}/get_config_info.py "node_id"`
cms_ip=`python3 ${CURRENT_PATH}/get_config_info.py "cms_ip"`
cantian_user=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_user"`
cantian_group=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_group"`
upgrade_mode=`python3 ${CURRENT_PATH}/get_config_info.py "upgrade_mode"`
METADATA_FS_PATH="/mnt/dbdata/remote/metadata_${storage_metadata_fs}"
upgrade_path="${METADATA_FS_PATH}/upgrade"
upgrade_lock="${METADATA_FS_PATH}/upgrade.lock"
cluster_and_node_status_path="${upgrade_path}/cluster_and_node_status"
DORADO_CONF_PATH="${CURRENT_PATH}/../../config/container_conf/dorado_conf"
SYS_PASS="sysPass"
START_STATUS_NAME="start_status.json"
CLUSTER_COMMIT_STATUS=("prepared" "commit")
CLUSTER_PREPARED=3

source ${CURRENT_PATH}/../log4sh.sh

function check_if_need_upgrade() {
    if [ ! -f ${METADATA_FS_PATH}/${VERSION_FILE} ]; then
        logAndEchoInfo "this is first to start node, no need to upgrade. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        exit 0
    fi
    logAndEchoInfo "check if the container needs to upgrade. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    local_version=`cat ${PKG_PATH}/${VERSION_FILE} | grep 'Version:' | awk -F ":" '{print $2}' | sed -r 's/[a-z]*[A-Z]*0*([0-9])/\1/' | sed 's/ //g'`
    remote_version=`cat ${METADATA_FS_PATH}/${VERSION_FILE} | grep 'Version:' | awk -F ":" '{print $2}' | sed -r 's/[a-z]*[A-Z]*0*([0-9])/\1/' | sed 's/ //g'`
    if [[ ${local_version} < ${remote_version} ]]; then
        logAndEchoError "The version is outdated. cluster version:${remote_version}, but this version:${local_version}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        exit 1
    fi
    if [[ ${local_version} > ${remote_version} ]]; then
        return 0
    fi
    return 1
}

function rollback_check_cluster_status() {
    if [ ! -d ${cluster_and_node_status_path} ]; then
        logAndEchoInfo "the cluster status dir is not exist, no need to rollback."
        return 1
    fi

    cluster_status_flag="${cluster_and_node_status_path}/cluster_status.txt"
    if [ ! -e ${cluster_status_flag} ]; then
        logAndEchoInfo "the cluster status file is not exist, no need to rollback."
        return 1
    fi

    cluster_status=$(cat ${cluster_status_flag})
    if [ "${cluster_status}" == "commit" ]; then
        logAndEchoInfo "the cluster status is commit, failed to rollback."
        exit 1
    fi

    if  [ "${cluster_status}" == "normal" ]; then
        logAndEchoInfo "the cluster status is normal, no need to rollback."
        return 1
    fi

    modify_cluster_or_node_status "${cluster_status_flag}" "rollback" "cluster"
}

function rollback_check_local_node_status() {
    logAndEchoInfo "begin to check if the current node needs to rollback."
    local_node_status_flag="${cluster_and_node_status_path}/node${node_id}_status.txt"
    if [ ! -e ${local_node_status_flag} ]; then
        logAndEchoInfo "the current node has not been upgraded, no need to rollback."
        return 1
    fi

    modify_cluster_or_node_status "${local_node_status_flag}" "rollback" "node${node_id}"
    logAndEchoInfo "pass check if the current node needs roll back."
}

function rollback_check() {
    logAndEchoInfo "begin to check if the container needs to rollback."
    rollback_check_cluster_status
    if [ $? -ne 0 ]; then
        logAndEchoInfo "the cluster status is not prepared, no need to rollback."
        return 1
    fi
    rollback_check_local_node_status
    if [ $? -ne 0 ]; then
        logAndEchoInfo "the current node status is not prepared, no need to rollback."
        return 1
    fi
}

function cluster_rollback_status_check() {
    logAndEchoInfo "begin to check cluster rollback status"

    # 统计当前节点数目
    node_count=$(expr "$(echo "${cms_ip}" | grep -o ";" | wc -l)" + 1)

    # 读取各节点升级状态文件
    node_status_files=($(find "${cluster_and_node_status_path}" -type f | grep -v grep | grep -E "^${cluster_and_node_status_path}/node[0-9]+_status.txt$"))
    status_array=()
    for status in "${node_status_files[@]}";
    do
        status_array+=($(cat "${status}"))
    done

    # 对升级状态数组去重
    unique_status=($(printf "%s\n" "${status_array[@]}" | uniq))
    # 去重后长度若不为1则直接退出
    if [ ${#unique_status[@]} -ne 1 ]; then
        logAndEchoInfo "existing nodes have not been rollback successfully, details: ${status_array[@]}"
        return 0
    fi

    if [ "${unique_status[0]}" != "rollback_success" ]; then
        logAndEchoError "none of the ${node_count} nodes were rollback successfully."
        exit 1
    fi

    modify_cluster_or_node_status "${cluster_status_flag}" "normal" "cluster"
    rm -rf ${cluster_and_node_status_path}
    logAndEchoInfo "all nodes have been rollback successfully."
}

function clear_flag_after_rollback () {
    upgrade_path="${METADATA_FS_PATH}/upgrade"
    rm -f ${upgrade_path}/upgrade_node${node_id}.*
}

function do_rollback() {
    logAndEchoInfo "begin to rollback."
    local_node_status=$(cat "${local_node_status_flag}")
    if [ "${local_node_status}" != "rollback_success" ]; then
        start_cantiand_by_cms
        modify_cluster_or_node_status "${local_node_status_flag}" "rollback_success" "node${node_id}"
    fi
    cluster_rollback_status_check
    clear_flag_after_rollback
}

function check_white_list() {
    if [ "${upgrade_mode}" != "rollup" ] && [ "${upgrade_mode}" != "offline" ]; then
        err_info="Invalid upgrade_mode '${upgrade_mode}'. It should be either 'rollup' or 'offline'."
        return 1
    fi

    check_list_res=`python3 ${CURRENT_PATH}/upgrade_version_check.py`
    upgrade_stat=`echo ${check_list_res} | awk '{print $1}'`
    # 白名单检查通过，允许升级
    if [ "${upgrade_stat}" == "True" ]; then
        upgrade_support_mode=`echo ${check_list_res} | awk '{print $3}'`
        if [ "${upgrade_support_mode}" == "offline" ] && [ "${upgrade_mode}" == "rollup" ]; then
            err_info="current version does not support 'rollup' mode"
            return 1
        fi

        if [ "${upgrade_mode}" == "offline" ]; then
            # 如果首个节点离线升级，需要判断是否有其他节点在线
            if [ ! -d ${cluster_and_node_status_path} ]; then
                cms_ret=`su -s /bin/bash - ${cantian_user} -c "cms stat" | awk '{print $3}' | grep "ONLINE" | wc -l`
                if [ ${cms_ret} -ne 0 ]; then
                    err_info="current upgrade mode is offline, but ONLINE count is ${cms_ret}"
                    return 1
                fi
            fi
        fi
        modify_systable=`echo ${check_list_res} | awk '{print $2}'`
        return 0
    else
        err_info=`echo ${check_list_res} | awk '{print $2}'`
        return 1
    fi
}

function container_upgrade_check() {
    check_if_need_upgrade

    # 不需要升级，检查是否需要回滚
    if [ $? -ne 0 ]; then
        rollback_check
        if [ $? -ne 0 ]; then
            logAndEchoInfo "now is the latest version, no need to upgrade. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            exit 0
        fi
        upgrade_lock
        do_rollback
        exit 0
    fi

    check_white_list
    if [ $? -ne 0 ]; then
        logAndEchoError "failed to white list check. err_info:${err_info} [Line:${LINENO}, File:${SCRIPT_NAME}]"
        exit 1
    fi

    logAndEchoInfo "upgrade check succeded. [Line:${LINENO}, File:${SCRIPT_NAME}]"
}

function check_upgrade_flag() {
    if [ ! -d "${upgrade_path}" ]; then
        return 0
    fi

    upgrade_file=$(ls "${upgrade_path}" | grep -E "^upgrade.*" | grep -v "${local_version}" | grep -v upgrade.lock)
    if [[ -n ${upgrade_file} ]];then
        logAndEchoError "The cluster is being upgraded to another version: ${upgrade_file}, current target version: ${local_version}"
        exit 1
    fi
}

function create_upgrade_flag() {
    if [ ! -d "${upgrade_path}" ]; then
        mkdir -m 755 -p "${upgrade_path}"
    fi
    
    if [ ! -f "${upgrade_flag}" ]; then
        touch ${upgrade_flag}
        chmod 400 ${upgrade_flag}
    fi
    
    if [ ! -f "${upgrade_lock}" ]; then
        touch ${upgrade_lock}
        chmod 400 ${upgrade_lock}
    fi

    if [ "${modify_systable}" == "true" ]; then
        if [ -f "${updatesys_flag}" ] || [ -f "${upgrade_path}/updatesys.success" ]; then
            logAndEchoInfo "detected that the system tables file flag already exists."
            return 0
        fi
        touch ${updatesys_flag} && chmod 400 ${updatesys_flag}
        logAndEchoInfo "detect need to update system tables, success to create updatesys_flag: '${updatesys_flag}'"
    fi
}

function upgrade_init_flag() {
    upgrade_flag="${upgrade_path}/upgrade_node${node_id}.${local_version}"
    updatesys_flag="${upgrade_path}/updatesys.true"

    check_upgrade_flag
    create_upgrade_flag
}

function upgrade_lock() {
    exec 506>"${upgrade_lock}"
    flock -x --wait 600 506 
    if [ $? -ne 0 ]; then
        logAndEchoError "Other node is upgrading or rollback, please check again later."
        exit 1
    fi
}

function init_cluster_or_node_status_flag() {
    if [ ! -d "${cluster_and_node_status_path}" ]; then
        mkdir -m 755 -p "${cluster_and_node_status_path}"
    fi

    cluster_status_flag="${cluster_and_node_status_path}/cluster_status.txt"
    local_node_status_flag="${cluster_and_node_status_path}/node${node_id}_status.txt"

    logAndEchoInfo "init current cluster status and node status flag success."

    if [ -f ${cluster_status_flag} ]; then
        cluster_status=$(cat ${cluster_status_flag})
        if [[ "${CLUSTER_COMMIT_STATUS[*]}" == *"${cluster_status}"* ]]; then
            logAndEchoInfo "the current cluster status is already ${cluster_status}, no need to execute the upgrade."
            exit 0
        fi
    fi

    commit_success_file="${upgrade_path}/cantian_upgrade_commit_${remote_version}"
    if [ -f "${commit_success_file}" ]; then
        rm -rf "${commit_success_file}"
    fi
}

function check_if_any_node_in_upgrade_status() {
    logAndEchoInfo "begin to check if any nodes in upgrading state"
    node_status_files=($(find "${cluster_and_node_status_path}" -type f | grep -v grep | grep -E "^${cluster_and_node_status_path}/node[0-9]+_status\.txt$" | grep -v "node${node_id}"))
    if [ ${#node_status_files[@]} -eq 0 ]; then
        return 0
    fi

    status_array=()
    for status in "${node_status_files[@]}";
    do
        status_array+=("$(cat ${status})")
    done

    unique_status=($(printf "%s \n" "${status_array[@]}" | uniq))
    if [ ${#unique_status[@]} -ne 1 ]; then
        logAndEchoError "currently existing nodes are in upgrading state, details: ${status_array[@]}"
        exit 1
    fi

    if [ "${unique_status[0]}" != "${upgrade_mode}_success" ]; then
        logAndEchoError "there are currently other nodes in upgrading or other upgrade mode. current mode: ${upgrade_mode}, details: ${unique_status[0]}"
        exit 1
    fi
    logAndEchoInfo "check pass, currently no nodes are in upgrading state."
}

function modify_cluster_or_node_status() {
    local cluster_or_node_status_file_path=$1
    local new_status=$2
    local cluster_or_node=$3
    local old_status=""

    if [ -n "${cluster_or_node_status_file_path}" ] && [ ! -f "${cluster_or_node_status_file_path}" ]; then
        logAndEchoInfo "${upgrade_mode} upgrade status of '${cluster_or_node}' does not exist."
    fi

    if [ -f "${cluster_or_node_status_file_path}" ]; then
        old_status=$(cat ${cluster_or_node_status_file_path})
        if [ "${old_status}" == "${new_status}" ]; then
            logAndEchoInfo "the old status of ${cluster_or_node} is consistent with the new status, both are ${new_status}"
            return 0
        fi
    fi

    echo "${new_status}" > ${cluster_or_node_status_file_path}
    if [ $? -eq 0 ]; then
        logAndEchoInfo "change upgrade status of ${cluster_or_node} from '${old_status}' to '${new_status}' success."
        return 0
    else
        logAndEchoError "change upgrade status of ${cluster_or_node} from '${old_status}' to '${new_status}' failed."
        exit 1
    fi
}

function local_node_upgrade_status_check() {
    logAndEchoInfo "begin to check local node upgrade status"
    if [ -f "${local_node_status_flag}" ]; then
        cur_upgrade_status=$(cat ${local_node_status_flag})
        if [ "${cur_upgrade_status}" == "${upgrade_mode}_success" ]; then
            local_node_status="${upgrade_mode}_success"
            logAndEchoInfo "node${node_id} has been upgraded successfully"
            return 0
        elif [ "${cur_upgrade_status}" == "${upgrade_mode}" ]; then
            logAndEchoInfo "node_${node_id} is in ${upgrade_mode} state"
            return 0
        fi
    fi

    modify_cluster_or_node_status "${local_node_status_flag}" "${upgrade_mode}" "node${node_id}"
    logAndEchoInfo "pass check local node upgrade status"
}

function cluster_upgrade_status_check() {
    logAndEchoInfo "begin to check cluster upgrade status"

    # 统计当前节点数目
    node_count=$(expr "$(echo "${cms_ip}" | grep -o ";" | wc -l)" + 1)

    # 读取各节点升级状态文件
    node_status_files=($(find "${cluster_and_node_status_path}" -type f | grep -v grep | grep -E "^${cluster_and_node_status_path}/node[0-9]+_status\.txt$"))
    status_array=()
    for status in "${node_status_files[@]}";
    do
        status_array+=("$(cat ${status})")
    done

    # 执行了升级操作的节点数少于计算节点数，直接退出
    if [ "${#status_array[@]}" != "${node_count}" ]; then
        logAndEchoInfo "currently only ${#status_array[@]} nodes have performed the ${upgrade_mode} upgrade operation, totals:${node_count}."
        return 0
    fi

    # 对升级状态数组去重
    unique_status=($(printf "%s\n" "${status_array[@]}" | uniq))
    # 去重后长度若不为1则直接退出
    if [ ${#unique_status[@]} -ne 1 ]; then
        logAndEchoInfo "existing nodes have not been upgraded successfully, details: ${status_array[@]}"
        return 0
    fi
    # 去重后元素不是${upgrade_mode}_success
    if [ "${unique_status[0]}" != "${upgrade_mode}_success" ]; then
        logAndEchoError "none of the ${node_count} nodes were upgraded successfully"
        exit 1
    fi

    logAndEchoInfo "all ${node_count} nodes were upgraded successfully, pass check cluster upgrade status"
    return 3
}

function start_cantiand_by_cms() {
    logAndEchoInfo "begin to start cms"
    sh "${CURRENT_PATH}"/../cms/appctl.sh start
    if [ $? -ne 0 ]; then
        logAndEchoError "start cms when upgrade failed"
        exit 1
    fi
    logAndEchoInfo "begin to start cantiand"
    for ((i=1; i<=10; i++));do
        su -s /bin/bash - "${cantian_user}" -c "cms res -start db -node ${node_id}"
        if [ $? -ne 0 ]; then
            logAndEchoError "start cantiand by cms failed, remaining Attempts: ${i}/10"
            sleep 20
            continue
        else
            # 修改cantian配置文件，后续start不会执行
            su -s /bin/bash - "${cantian_user}" -c "sed -i 's/\"start_status\": \"default\"/\"start_status\": \"started\"/' /opt/cantian/cantian/cfg/${START_STATUS_NAME}"
            logAndEchoInfo "start cantiand by cms success"
            return
        fi
    done
    logAndEchoError "start cantiand by cms failed" && exit 1
}

function modify_sys_tables() {
    modify_sys_table_flag="${upgrade_path}/updatesys.true"
    modify_sys_tables_success="${upgrade_path}/updatesys.success"
    modify_sys_tables_failed="${upgrade_path}/updatesys.failed"
    systable_home="/opt/cantian/cantian/server/admin/scripts/rollUpgrade"
    old_initdb_sql="${METADATA_FS_PATH}/initdb.sql"
    new_initdb_sql="${systable_home}/../initdb.sql"
    # 无需修改系统表或者已经修改过系统表
    if [ ! -f "${modify_sys_table_flag}" ] || [ -f "${modify_sys_tables_success}" ]; then
        logAndEchoInfo "detected that the system tables have been modified or does not need to be modified"
        return 0
    fi
    # 判断sql文件是否相同，如果不相同需要进行系统表升级，相同场景无需修改（避免B版本升级问题）
    diff "${old_initdb_sql}" "${new_initdb_sql}" > /dev/null
    if [[ $? != 0 ]];then
        logAndEchoInfo "modify sys tables start"
        sys_password=`cat ${DORADO_CONF_PATH}/${SYS_PASS}`
        chown "${cantian_user}":"${cantian_group}" "${old_initdb_sql}"
        echo -e "${sys_password}" | su -s /bin/bash - "${cantian_user}" -c "sh ${CURRENT_PATH}/upgrade_systable.sh "127.0.0.1" ${systable_home}/../../../bin ${old_initdb_sql} ${new_initdb_sql} ${systable_home}"
        if [ $? -ne 0 ];then
            logAndEchoError "modify sys tables failed"
            touch "${modify_sys_tables_failed}" && chmod 400 "${modify_sys_tables_failed}"
            exit 1
        fi
        rm "${modify_sys_table_flag}"
        touch "${modify_sys_tables_success}" && chmod 400 "${modify_sys_tables_success}"
        logAndEchoInfo "modify sys tables success"
    else
        logAndEchoInfo "two init.sql files are the same, no need to modify sys tables."
    fi
}

function container_upgrade() {
    logAndEchoInfo "Begin to upgrade. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    # 升级状态标记
    upgrade_init_flag
    upgrade_lock
    init_cluster_or_node_status_flag
    check_if_any_node_in_upgrade_status
    modify_cluster_or_node_status "${cluster_status_flag}" "${upgrade_mode}" "cluster"
    local_node_upgrade_status_check
    # 升级已完成，跳过
    if [ "${local_node_status}" != "${upgrade_mode}_success" ]; then
        start_cantiand_by_cms
        modify_sys_tables
        modify_cluster_or_node_status "${local_node_status_flag}" "${upgrade_mode}_success" "node${node_id}"
    fi

    cluster_upgrade_status_check
    ret=$?
    if [[ "${ret}" == "${CLUSTER_PREPARED}" ]]; then
        modify_cluster_or_node_status "${cluster_status_flag}" "prepared" "cluster"
    fi

    logAndEchoInfo "container upgrade success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
}

function main() {
    container_upgrade_check
    container_upgrade
}

main