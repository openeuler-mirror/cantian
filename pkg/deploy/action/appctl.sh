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
SUCCESS_FLAG=/opt/cantian/pre_upgrade.success
FAIL_FLAG=/opt/cantian/pre_upgrade.fail

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
ROLLBACK_NAME="rollback.sh"
PRE_UPGRADE="pre_upgrade.sh"
CHECK_POINT="check_point.sh"
lock_file=""

function clear_history_flag() {
    if [ -f ${SUCCESS_FLAG} ]; then
        rm -rf ${SUCCESS_FLAG}
    fi

    if [ -f ${FAIL_FLAG} ]; then
        rm -rf ${FAIL_FLAG}
    fi
}

function usage()
{
    logAndEchoInfo "Usage: ${0##*/} {start|stop|install|uninstall|pre_install|pre_upgrade|check_status|upgrade}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
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


##################################### main #####################################
ACTION=$1
INSTALL_TYPE=$2
case "$ACTION" in
    start)
        lock_file=${START_NAME}
        do_deploy ${START_NAME}
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
        CONFIG_PATH=$2
        lock_file=${PRE_UPGRADE}
        clear_history_flag
        do_deploy ${PRE_UPGRADE} ${CONFIG_PATH}
        if [ $? -ne 0 ]; then
            touch ${FAIL_FLAG}
            chmod 400 ${FAIL_FLAG}
            exit 1
        else
            touch ${SUCCESS_FLAG}
            chmod 400 ${SUCCESS_FLAG}
            exit 0
        fi
        ;;
    upgrade)
        if [ -f ${SUCCESS_FLAG} ]; then
            UPGRADE_IP_PORT=$3
            lock_file=${UPGRADE_NAME}
            do_deploy ${UPGRADE_NAME} ${INSTALL_TYPE} ${UPGRADE_IP_PORT}
            exit $?
        elif [ -f ${FAIL_FLAG} ]; then
            logAndEchoError "pre_upgrade failed, upgrade is not allowed"
            exit 1
        else
            logAndEchoError "please do pre_upgrade first"
            exit 1
        fi
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
        do_deploy ${ROLLBACK_NAME} ${INSTALL_TYPE} ${UPGRADE_IP_PORT} ${ROLLBACK_VERSION}
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
    *)
        usage
        ;;
esac
