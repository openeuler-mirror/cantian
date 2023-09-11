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

#脚本名称
PARENT_DIR_NAME=$(pwd | awk -F "/" '{print $NF}')
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)

#依赖文件
source ${CURRENT_PATH}/../log4sh.sh

#组件名称
COMPONENT_NAME=ct_exporter

CT_ECPORTER_CGROUP=/sys/fs/cgroup/memory/cantian_exporter
CT_ECPORTER_MEM="2G"
CT_EXPORTER_DATA_SAVE_PATH=/opt/cantian/ct_om/service/cantian_exporter/exporter_data

START_NAME="start.sh"
STOP_NAME="stop.sh"
PRE_INSTALL_NAME="pre_install.sh"
STATUS_NAME="check_status.sh"
UPGRADE_NAME="upgrade.sh"
ROLLBACK_NAME="rollback.sh"
POST_UPGRADE_NAME="post_upgrade.sh"

user=`python3 ${CURRENT_PATH}/../get_config_info.py "deploy_user"`

function usage()
{
    logAndEchoInfo "Usage: ${0##*/} {start|stop|install|uninstall|pre_install|pre_upgrade|check_status|upgrade}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    exit 1
}

function do_deploy()
{
    local script_name_param=$1
    local install_type=$2

    if [ ! -f  ${CURRENT_PATH}/${script_name_param} ]; then
        logAndEchoError "${COMPONENT_NAME} ${script_name_param} is not exist. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi
    su -s /bin/bash ${user} -c "sh ${CURRENT_PATH}/${script_name_param}"
    ret=$?

    if [ $ret -ne 0 ]; then
        logAndEchoError "Execute ${COMPONENT_NAME} ${script_name_param} return failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    logAndEchoInfo "Execute ${COMPONENT_NAME} ${script_name_param} return success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    return 0
}

function create_cgroup() {
    cgroup_name=$1
    logAndEchoInfo "begin to create cgroup: ${cgroup_name}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        if [[ -d ${cgroup_name} ]]; then
            rmdir ${cgroup_name}
        fi
        mkdir -p ${cgroup_name}
        if [ $? -ne 0 ]; then
            logAndEchoError "create cgroup: ${cgroup_name} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            exit 1
        else
            logAndEchoInfo "create cgroup: ${cgroup_name} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        fi
}

function add_pid_to_cgroup() {
    process_pid=$1
    cgroup_name=$2

    sh -c "echo ${process_pid} > ${cgroup_name}/tasks"
    if [ $? -ne 0 ]; then
        logAndEchoError "add pid to cgroup: ${cgroup_name} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        exit 1
    else
        logAndEchoInfo "add pid to cgroup: ${cgroup_name} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    fi
}

function limite_cgroup_mem() {
    mem_limited=$1
    cgroup_name=$2

    sh -c "echo ${mem_limited} > ${cgroup_name}/memory.limit_in_bytes"
    if [ $? -ne 0 ]; then
        logAndEchoError "cgroup: ${cgroup_name} memory limited failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        exit 1
    else
        logAndEchoInfo "cgroup: ${cgroup_name} memory limited success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    fi
}

function mod_prepare() {
    # 修改cantian_exporter相关文件归属和权限
    sh ${CURRENT_PATH}/pre_install.sh ${ACTION}
    if [ $? -eq 0 ]; then
        logAndEchoInfo "cantian_exporter change mod and owner success"
    else
        logAndEchoInfo "cantian_exporter change mod and owner failed"
        exit 1
    fi
}

##################################### main #####################################
ACTION=$1
INSTALL_TYPE=$2
case "$ACTION" in
    start)
        # 上报数据目录权限兼容
        if [[ -d "${CT_EXPORTER_DATA_SAVE_PATH}" ]]; then
            group=`python3 ${CURRENT_PATH}/../get_config_info.py "deploy_group"`
            chown -hR "${user}":"${group}" ${CT_EXPORTER_DATA_SAVE_PATH}
        fi
        do_deploy ${START_NAME}
        exit $?
        ;;
    stop)
        do_deploy ${STOP_NAME}
        exit $?
        ;;
    pre_install)
        exit 0
        ;;
    install)
        mod_prepare
        exit 0
        ;;
    uninstall)
        exit 0
        ;;
    check_status)
        do_deploy ${STATUS_NAME}
        exit $?
        ;;
    backup)
        exit 0
        ;;
    restore)
        exit 0
        ;;
    pre_upgrade)
        exit 0
        ;;
    upgrade_backup)
        exit 0
        ;;
    upgrade)
        mod_prepare
        exit $?
        ;;
    post_upgrade)
        exit 0
        ;;
    rollback)
        mod_prepare
        exit $?
        ;;
    *)
        usage
        ;;
esac
