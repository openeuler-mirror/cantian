#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
CONFIG_FILE_PATH=$1
CONFIG_PATH=${CURRENT_PATH}/../config
CMS_CHECK_FILE=/opt/cantian/action/fetch_cls_stat.py
CANTIAN_PATH=/opt/cantian
MEM_REQUIRED=5  # 单位G
SIZE_UPPER=1024

source ${CURRENT_PATH}/log4sh.sh
source ${CURRENT_PATH}/env.sh

function prepare_env() {
    logAndEchoInfo "prepare upgrade env."
    if [ -f ${CONFIG_FILE_PATH} ] && [ -n "${CONFIG_FILE_PATH}" ]; then
        python3 ${CURRENT_PATH}/pre_upgrade.py ${CONFIG_FILE_PATH}
        if [ $? -ne 0 ]; then
            logAndEchoError "config check failed, please check /opt/cantian/deploy/om_deploy/om_deploy.log for detail"
            exit 1
        else
            mv -f ${CURRENT_PATH}/deploy_param.json ${CONFIG_PATH}
        fi
    else
        python3 ${CURRENT_PATH}/pre_upgrade.py
        if [ $? -ne 0 ]; then
            logAndEchoError "new config_params.json different with source config_params.json"
            exit 1
        else
            cp -rf /opt/cantian/config/deploy_param.json ${CURRENT_PATH}/../config
            if [ $? -ne 0 ]; then
                logAndEchoError "prepare upgrade env failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
                exit 1
            fi
        fi
    fi
}

# 检查集群状态
function check_cms_stat() {
    logAndEchoInfo "begin to check cms stat"
    cms_result=$(python3 ${CMS_CHECK_FILE})
    cms_stat=${cms_result: 0-2: 1}
    if [[ ${cms_stat} != '0' ]]; then
        logAndEchoError "failed cms stat check. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        exit 1
    fi

    logAndEchoInfo "pass cms stat check"
}

# 检查磁盘空间
function check_mem_avail() {
    logAndEchoInfo "begin to check memory available"
    let mem_limited=MEM_REQUIRED*${SIZE_UPPER}*${SIZE_UPPER}
    mem_info=($(df ${CANTIAN_PATH}))
    mem_avail=${mem_info[10]}
    if [ $((mem_avail)) -lt ${mem_limited} ]; then
        logAndEchoError "failed memory check. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        exit 1
    fi

    logAndEchoInfo "pass memory check"
}

# 检查升级白名单
function check_upgrade_version() {
    logAndEchoInfo "begin to check upgrade version"
    white_list_check_res=$(python3 ${CURRENT_PATH}/upgrade_version_check.py ${CURRENT_PATH}/white_list.txt)
    logAndEchoInfo "source_version, upgrade_mode, change_system are: ${white_list_check_res}"
    if [ -z "${white_list_check_res}" ]; then
        logAndEchoError "failed to white list check"
        exit 1
    fi

    logAndEchoInfo "pass white list check"
}

# 调用各模块升级前检查脚本
function call_each_pre_upgrade() {
    for module_name in "${PRE_UPGRADE_ORDER[@]}";
    do
        logAndEchoInfo "begin to execute ${module_name} pre_upgrade"
        sh ${CURRENT_PATH}/${module_name}/appctl.sh pre_upgrade
        if [ $? -ne 0 ]; then
            logAndEchoError "call ${module_name} pre_upgrade failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            logAndEchoError "For details, see the /opt/cantian/${module_name}/log. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            exit 1
        fi
        logAndEchoInfo "${module_name} pre_upgrade success"
    done
}

function main() {
    logAndEchoInfo "begin to pre_upgrade"
    prepare_env
    check_cms_stat
    check_mem_avail
    check_upgrade_version
    call_each_pre_upgrade
}

main