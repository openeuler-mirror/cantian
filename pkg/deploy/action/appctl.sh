#!/bin/bash
################################################################################
# 【功能说明】
# 1.appctl.sh由管控面调用
# 2.完成如下流程
#     服务初次安装顺序:pre_install->install->start->check_status
#     服务带配置安装顺序:pre_install->install->restore->start->check_status
#     服务卸载顺序:stop->uninstall
#     服务带配置卸载顺序:backup->stop->uninstall
#     服务重启顺序:stop->start->check_status

#     服务A升级到B版本:pre_upgrade(B)->stop(A)->update(B)->start(B)->check_status(B)
#                      update(B)=备份A数据，调用A脚本卸载，调用B脚本安装，恢复A数据(升级数据)
#     服务B回滚到A版本:stop(B)->rollback(B)->start(A)->check_status(A)->online(A)
#                      rollback(B)=根据升级失败标志调用A或是B的卸载脚本，调用A脚本安装，数据回滚特殊处理
# 3.典型流程路线：install(A)-upgrade(B)-upgrade(C)-rollback(B)-upgrade(C)-uninstall(C)
# 【返回】
# 0：成功
# 1：失败
#
# 【注意事项】
# 1.所有的操作需要支持失败可重入
################################################################################
set +x
#当前路径
CURRENT_PATH=$(dirname $(readlink -f $0))
SUCCESS_FLAG_PATH=/opt/cantian/
UPDATESYS_FLAG=/opt/cantian/updatesys.true
CHECK_POINT_FLAG=/opt/cantian/check_point.success

#脚本名称
PARENT_DIR_NAME=$(pwd | awk -F "/" '{print $NF}')
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)

#依赖文件
source ${CURRENT_PATH}/log4sh.sh

#组件名称
COMPONENT_NAME=cantian-common

INSTALL_NAME="install.sh"
UNINSTALL_NAME="uninstall.sh"
START_NAME="start.sh"
STOP_NAME="stop.sh"
PRE_INSTALL_NAME="pre_install.sh"
BACKUP_NAME="backup.sh"
RESTORE_NAME="restore.sh"
STATUS_NAME="check_status.sh"
UPGRADE_NAME="upgrade.sh"
UPGRADE_COMMIT_NAME="upgrade_commit.sh"
ROLLBACK_NAME="rollback.sh"
PRE_UPGRADE="pre_upgrade.sh"
CHECK_POINT="check_point.sh"
lock_file=""

function clear_history_flag() {
    if [[ "$(find ${SUCCESS_FLAG_PATH} -type f -name 'pre_upgrade_*.success')" ]]; then
        rm -rf ${SUCCESS_FLAG_PATH}/pre_upgrade_*.success
    fi

    if [ -f ${FAIL_FLAG} ]; then
        rm -rf ${FAIL_FLAG}
    fi

    if [ -f ${UPDATESYS_FLAG} ]; then
        rm -rf ${UPDATESYS_FLAG}
    fi
    if [ -f "${CHECK_POINT_FLAG}" ]; then
        rm -rf ${CHECK_POINT_FLAG}
    fi
}

function gen_pre_check_flag() {
    local pre_upgrade_mode=$1
    # 适配离线升级
    if [ -z "${pre_upgrade_mode}" ] || [ -f "${pre_upgrade_mode}" ]; then
        offline_flag="${SUCCESS_FLAG_PATH}/pre_upgrade_offline.success"
        touch ${offline_flag} && chmod 400 ${offline_flag}
        return 0
    fi

    mode_flag="${SUCCESS_FLAG_PATH}/pre_upgrade_${pre_upgrade_mode}.success"
    touch ${mode_flag} && chmod 400 ${mode_flag}
}

function usage()
{
    logAndEchoInfo "Usage: ${0##*/} {
    start|stop|install|uninstall|pre_install|pre_upgrade|
    check_status|upgrade|backup|restore|upgrade_commit|check_point|
    rollback|clear_upgrade_backup|certificate|update_pwd|dr_operate}.
    [Line:${LINENO}, File:${SCRIPT_NAME}]"
    exit 1
}

function do_deploy()
{
    flock -n 505
    if [ $? -ne 0 ]; then
        logAndEchoError "${lock_file} is executing, please check again later"
        return 1
    fi

    local script_name_param=$1
    local install_type=$2
    local force_uninstall_or_dorado_ip_port=$3
    local rollback_version=$4

    if [ ! -f  ${CURRENT_PATH}/${script_name_param} ]; then
        logAndEchoError "${COMPONENT_NAME} ${script_name_param} is not exist. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        flock -u 505
        return 1
    fi
    sh ${CURRENT_PATH}/${script_name_param} ${install_type} ${force_uninstall_or_dorado_ip_port} ${rollback_version}

    ret=$?
    if [ $ret -ne 0 ]; then
        logAndEchoError "Execute ${COMPONENT_NAME} ${script_name_param} return failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        flock -u 505
        return 1
    else
        logAndEchoInfo "Execute ${COMPONENT_NAME} ${script_name_param} return success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    fi

    flock -u 505
    return 0
} 505<>${CURRENT_PATH}/${lock_file}

function clean_dir() {
    if [ "${INSTALL_TYPE}" == "override" ];then
        rm -rf /opt/cantian
    fi
}

function upgrade_init_flag() {
    storage_metadata_fs=$(python3 ${CURRENT_PATH}/get_config_info.py "storage_metadata_fs")
    node_id=$(python3 ${CURRENT_PATH}/get_config_info.py "node_id")
    upgrade_path="/mnt/dbdata/remote/metadata_${storage_metadata_fs}/upgrade"
    upgrade_lock="/mnt/dbdata/remote/metadata_${storage_metadata_fs}/upgrade.lock"
    target_version=$(cat "${CURRENT_PATH}"/../versions.yml | grep -E "Version:" | awk '{print $2}')
    upgrade_flag=upgrade_node${node_id}.${target_version}
}

##############################################################################################
# 生成升级标记文件，解决以下问题：
# 1、当前处于某个版本（如2.0.0）升级状态（升级中、升级失败、升级成功未提交），避免执行其他版本升级（如3.0.0）；
# 2、确保不同节点使用的升级目标版本一致。
##############################################################################################
function check_upgrade_flag() {
    upgrade_init_flag
    if [ ! -d "${upgrade_path}" ];then
        return 0
    fi
    upgrade_file=$(ls "${upgrade_path}" | grep -E "^upgrade.*" | grep -v "${target_version}" | grep -v upgrade.lock)
    if [[ -n ${upgrade_file} ]];then
        logAndEchoError "The cluster is being upgraded to another version: ${upgrade_file}, current target version: ${target_version}"
        return 1
    fi
}

function create_upgrade_flag() {
    upgrade_init_flag
    if [ ! -d "${upgrade_path}" ];then
        mkdir -m 755 -p "${upgrade_path}"
    fi
    touch "${upgrade_path}"/"${upgrade_flag}" && chmod 400 "${upgrade_path}"/"${upgrade_flag}"
    if [[ ! -f "${upgrade_lock}" ]];then
        touch "${upgrade_lock}"
        chmod 400 "${upgrade_lock}"
    fi
}

# 回滚结束清理标记文件
function clear_flag_after_rollback() {
    upgrade_init_flag
    if [ -f "${upgrade_path}"/"${upgrade_flag}" ];then
        rm -f "${upgrade_path}"/"${upgrade_flag}"
    fi
}

# 升级场景增加文件锁，避免多节点同时进行
function upgrade_lock() {
    exec 506>"${upgrade_lock}"
    flock -n 506
    if [ $? -ne 0 ]; then
        logAndEchoError "Other node is upgrading/rollback, please check again later."
        exit 1
    fi
}

function warning_tips() {
    declare -A warning_opt
    declare -A warning_msg
    local invalid_input_msg="Invalid input. Please enter 'yes' or 'no': "
    local conform_msg="Do you want to continue? (yes/no): "
    local second_conform_msg="To confirm operation, enter yes. Otherwise, exit:"
    local cancel_msg="Operation cancelled."
    warning_opt=([switch_over]=1 [recover]=1 [fail_over]=1)
    warning_msg=([switch_over]="\tSwitchover operation will be performed.
    \tThe current operation will cause the active-standby switch,
    \tplease make sure the standby data is consistent with the main data,
    \tif the data is not consistent, the execution of the switch operation may cause data loss." \
    [recover]="\tRecover operation will downgrade current station to standby,
    \tsynchronize data from remote to local, and cover local data.
    \tEnsure remote data consistency to avoid data loss." \
    [fail_over]="\tFailover operation will start the standby cluster.
    \tPlease confirm that the active device or cantian has failed,
    \tAfter this operation,
    \tplease ensure that the original active cluster is not accessed for write operations,
    \totherwise it will cause data inconsistency.")
    if [[ "${warning_opt[$dr_action]}" -eq 1 ]]; then
        echo -e "\033[5;31mWarning:\033[0m"
        echo -e "\033[31m${warning_msg[${dr_action}]}\033[0m"
        read -p "${conform_msg}" warning_confirm
        if [[ ${warning_confirm} != "yes" ]] && [[ ${warning_confirm} != "no" ]];then
            read -p "${invalid_input_msg}"  warning_confirm
        fi
        if [[ ${warning_confirm} == "no" ]];then
            echo "${cancel_msg}"
            exit 1
        fi
        read -p "${second_conform_msg}" second_warning_confirm
        if [[ ${second_warning_confirm} != "yes" ]];then
            echo "${cancel_msg}"
            exit 1
        fi
    fi
}

function dr_deploy() {
    dr_action=$2
    dr_site=$3
    if [ $# -ge 3 ];then
        shift 3
    elif [ $# -ge 2 ];then
        shift 2
    fi
    export PYTHONPATH="${CURRENT_PATH}"
    dm_pwd=""
    dbstor_user=""
    dbstor_pwd_first=""
    unix_sys_pwd_first=""
    unix_sys_pwd_second=""
    comfirm=""
    declare -A action_opt
    action_opt=([deploy]=1 [pre_check]=1 [undeploy]=1 [full_sync]=1 [progress_query]=1 \
    [switch_over]=1 [recover]=1 [fail_over]=1 [update_conf]=1)
    if [[ ! "${action_opt[$dr_action]}" ]];then
        dr_action="help"
    fi
    warning_tips
    if [[ x"${dr_action}" == x"undeploy" ]];then
        dbstor_user="yes"
        dbstor_pwd_first="no"
        if [[ x"${dr_site}" == x"standby" ]];then
            echo "Select an uninstallation mode.
    if you want to remove the DR, select 1.
    if you want to remove the DR and uninstall the cantian, select 2.
    Other inputs exit directly.
      1、Only Uninstall DR.
      2、Uninstall DR and Cantian Engine."
            read -p "What's your choice, please input [1|2]:" choice
            if [[ x"${choice}" != x"1" ]] && [[ x"${choice}" != x"2" ]];then
                exit 0
            fi
            if [[ x"${choice}" == x"1" ]];then
                dbstor_user="yes"
                dbstor_pwd_first="no"
            fi
            if [[ x"${choice}" == x"2" ]];then
                dbstor_user="yes"
                dbstor_pwd_first="yes"
            fi
        fi
        read -p "To confirm the operation, enter yes. Otherwise, exit:" comfirm
        if [[ x"${comfirm}" != x"yes" ]];then
            exit 0
        fi
    fi
    if [[ x"${dr_action}" != x"help" ]] && [[ x"${dr_action}" != x"progress_query" ]];then
        read -s -p "Please input device manager login passwd:" dm_pwd
        echo ""
    fi
    if [[ x"${dr_action}" == x"deploy" && x"${dr_site}" == x"standby" ]];then
        read -p "please enter dbstor_user: " dbstor_user
        echo "Enter dbstor_user is ${dbstor_user}"
        read -s -p "please enter dbstor_pwd: " dbstor_pwd_first
        echo ""
        read -s -p "please enter cantian_sys_pwd: " unix_sys_pwd_first
        echo ""
        read -s -p "please enter cantian_sys_pwd again: " unix_sys_pwd_second
        echo ""
    fi
    if [[ x"${dr_site}" == x"active" ]] && [[ x"${dr_action}" == x"deploy" || "${dr_action}" == "full_sync" ]];then
        read -s -p "Please input mysql login passwd:" dbstor_user
    fi
    if [[ "${dr_action}" == "deploy" ]] || [[ "${dr_action}" == "full_sync" ]];then
        _pid=$(ps -ef | grep "storage_operate/dr_operate_interface.py ${dr_action}" | grep -v grep | awk '{print $2}')
        if [[ -z $_pid ]];then
            echo -e "${dm_pwd}\n${dbstor_user}\n" | python3 -B "${CURRENT_PATH}/storage_operate/dr_operate_interface.py" param_check --action="${dr_action}" --site="${dr_site}" "$@"
            if [ $? -ne 0 ];then
                logAndEchoError "Passwd check failed."
                exit 1
            fi
            echo -e "${dm_pwd}\n${dbstor_user}\n${dbstor_pwd_first}\n${unix_sys_pwd_first}\n${unix_sys_pwd_second}" | \
            nohup python3 -B "${CURRENT_PATH}/storage_operate/dr_operate_interface.py" "${dr_action}" --site="${dr_site}" "$@" \
            >> /opt/cantian/deploy/deploy.log 2>&1 &
        else
            logAndEchoInfo "dr ${dr_action} is started."
        fi
        sleep 2
        _pid=$(ps -ef | grep "storage_operate/dr_operate_interface.py ${dr_action}" | grep -v grep | awk '{print $2}')
        if [[ -z $_pid ]];then
            logAndEchoError "dr ${dr_action} execute failed."
            exit 1
        fi
        logAndEchoInfo "dr ${dr_action} execute success, process id[${_pid}].\n        please use command[sh appctl.sh dr_operate progress_query --action=deploy/full_sync --display=table\json] to query progress."
    elif [[ "${dr_action}" == "progress_query" ]]; then
        if [[ -z ${dr_site} ]];then
            dr_site="--action=deploy"
        fi
        echo -e "${dm_pwd}" | python3 -B "${CURRENT_PATH}/storage_operate/dr_operate_interface.py" "${dr_action}" "${dr_site}" "$@"
    else
        echo -e "${dm_pwd}\n${dbstor_user}\n${dbstor_pwd_first}\n${unix_sys_pwd_first}\n${unix_sys_pwd_second}" | \
        python3 -B "${CURRENT_PATH}/storage_operate/dr_operate_interface.py" "${dr_action}" --site="${dr_site}" "$@"
    fi
}

##################################### main #####################################
ACTION=$1
INSTALL_TYPE=$2
case "$ACTION" in
    start)
        lock_file=${START_NAME}
        if [[ x"${INSTALL_TYPE}" != x"" ]] && [[ x"${INSTALL_TYPE}" != x"standby" ]];then
            logAndEchoError "Input errors, please check."
            exit 1
        fi
        do_deploy ${START_NAME} ${INSTALL_TYPE}
        exit $?
        ;;
    stop)
        lock_file=${STOP_NAME}
        do_deploy ${STOP_NAME}
        exit $?
        ;;
    pre_install)
        lock_file=${PRE_INSTALL_NAME}
        do_deploy ${PRE_INSTALL_NAME} ${INSTALL_TYPE}
        exit $?
        ;;
    install)
        CONFIG_FILE=$3
        lock_file=${INSTALL_NAME}
        do_deploy ${INSTALL_NAME} ${INSTALL_TYPE} ${CONFIG_FILE}
        exit $?
        ;;
    uninstall)
        FORCE_TYPE=$3
        lock_file=${UNINSTALL_NAME}

        if [ "x${FORCE_TYPE}" != "xforce" ]; then  # 非强制卸载前先检查所有进程是否引进停止
            source ${CURRENT_PATH}/running_status_check.sh
            if [ ${#online_list[*]} -ne 0 ]; then
                logAndEchoError "process ${online_list[@]} is still online, please execute stop first"
                exit 1
            fi
        fi

        do_deploy ${UNINSTALL_NAME} ${INSTALL_TYPE} ${FORCE_TYPE}
        ret=$?
        if [ $ret -ne 0 ];then
            exit 1
        fi
        clean_dir
        exit $?
        ;;
    check_status)
        lock_file=${STATUS_NAME}
        do_deploy ${STATUS_NAME}
        exit $?
        ;;
    backup)
        lock_file=${BACKUP_NAME}
        do_deploy ${BACKUP_NAME}
        exit $?
        ;;
    restore)
        lock_file=${RESTORE_NAME}
        do_deploy ${RESTORE_NAME}
        exit $?
        ;;
    pre_upgrade)
        CONFIG_PATH=$3
        lock_file=${PRE_UPGRADE}
        FAIL_FLAG=/opt/cantian/pre_upgrade_${INSTALL_TYPE}.fail
        clear_history_flag
        do_deploy ${PRE_UPGRADE} ${INSTALL_TYPE} ${CONFIG_PATH}
        if [ $? -ne 0 ]; then
            touch ${FAIL_FLAG} && chmod 400 ${FAIL_FLAG}
            exit 1
        fi
        check_upgrade_flag
        if [ $? -ne 0 ]; then
            touch ${FAIL_FLAG} && chmod 400 ${FAIL_FLAG}
            exit 1
        fi
        gen_pre_check_flag "${INSTALL_TYPE}"
        exit 0
        ;;
    upgrade)
        if [[ "$(find ${SUCCESS_FLAG_PATH} -type f -name pre_upgrade_"${INSTALL_TYPE}".success)" ]]; then
            UPGRADE_IP_PORT=$3
            lock_file=${UPGRADE_NAME}
            create_upgrade_flag
            upgrade_lock
            do_deploy ${UPGRADE_NAME} ${INSTALL_TYPE} ${UPGRADE_IP_PORT}
            ret=$?
            flock -u 506
            exit ${ret}
        elif [[ -f ${FAIL_FLAG} ]]; then
            logAndEchoError "pre_upgrade failed, upgrade is not allowed"
            exit 1
        else
            logAndEchoError "please do pre_upgrade first"
            exit 1
        fi
        ;;
    upgrade_commit)
        upgrade_init_flag
        upgrade_lock
        lock_file=${UPGRADE_COMMIT_NAME}
        do_deploy ${UPGRADE_COMMIT_NAME} ${INSTALL_TYPE}
        exit $?
        ;;
    check_point)
        lock_file=${CHECK_POINT}
        do_deploy ${CHECK_POINT}
        exit $?
        ;;
    rollback)
        UPGRADE_IP_PORT=$3
        ROLLBACK_VERSION=$4
        lock_file=${ROLLBACK_NAME}
        upgrade_init_flag
        upgrade_lock
        do_deploy ${ROLLBACK_NAME} ${INSTALL_TYPE} ${UPGRADE_IP_PORT} ${ROLLBACK_VERSION}
        ret=$?
        flock -u 506
        if [[ ${ret} -ne 0 ]];then
            exit 1
        fi
        clear_flag_after_rollback
        exit $?
        ;;
    clear_upgrade_backup)
        logAndEchoInfo "begin to clear upgrade backups"
        python3 ${CURRENT_PATH}/clear_upgrade_backup.py
        if [ $? -ne 0 ]; then
            logAndEchoError "clear upgrade backups failed"
            exit 1
        fi

        logAndEchoInfo "clear upgrade backups success"
        exit 0
        ;;
    certificate)
        logAndEchoInfo "begin to Certificate Operations"
        shift
        python3 -B "${CURRENT_PATH}/implement/certificate_update_and_revocation.py" $@
        exit $?
        ;;
    update_pwd)
        logAndEchoInfo "begin to update ctsql sys user login passwd."
        su -s /bin/bash - cantian -c "export LD_LIBRARY_PATH=/opt/cantian/dbstor/lib/:$LD_LIBRARY_PATH;python3 -B ${CURRENT_PATH}/update_config.py --component=ctsql_pwd --action=add --key=cantian --value=cantian"
        ret=$?
        if [ "${ret}" != 0 ]; then
            logAndEchoInfo "update ctsql sys user login passwd failed!"
            exit 1
        fi
        logAndEchoInfo "update ctsql sys user login passwd success."
        ;;
    dr_operate)
        dr_deploy "$@"
        exit $?
        ;;
    config_opt)
        shift
        python3 -B "${CURRENT_PATH}/implement/config_opt.py" $@
        ;;
    *)
        usage
        ;;
esac
