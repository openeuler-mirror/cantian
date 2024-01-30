#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${CURRENT_PATH}/$(basename $0)
STOP_SCRIPT_PATH="/opt/cantian/ct_om/service/cantian_exporter/scripts"
FORCE_TYPE=$2

source ${CURRENT_PATH}/ct_om_log.sh

function check_rpm_exist()
{
    rpm -qa | grep "ct_om"
    return $?
}

function uninstall_ctom_rpm()
{
    rpm -ev ct_om
    return $?
}

function main()
{
    if [ "x${FORCE_TYPE}" == "xforce" ]; then  # 强制卸载避免ctmgr进程残留
        local ctmgr_pid=$(ps -ef | grep "/opt/cantian/ct_om/service/ctmgr/uds_server.py" | grep -v grep | awk '{print $2}')
        if [ -n ${ctmgr_pid} ]; then
            kill -9 ${ctmgr_pid}
        fi
    fi

    # 检查ctmgr是否已经停止
    local active_service=$(ps -ef | grep /opt/cantian/ct_om/service/ctmgr/uds_server.py | grep python)
    if [[ ${active_service} != "" ]]; then
        logAndEchoError "please stop ctmgr first"
        exit 1
    fi

    # 检查cantian_exporter是否已经停止
    local py_pid=$(ps -ef | grep "/opt/cantian/ct_om/service/cantian_exporter/exporter/execute.py" | grep -v grep | awk '{print $2}')
    if [ -n "${py_pid}" ];then
        logAndEchoError "please stop cantian_exporter first"
        exit 1
    fi

    check_rpm_exist > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        logAndEchoInfo "Start to uninstall rpm bag. [Line:${LINENO}, File:${SCRIPT_NAME}]"

        uninstall_ctom_rpm > /dev/null 2>&1
        if [ $? -eq 0 ]; then
            logAndEchoInfo "Success to uninstall. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            return 0
        else
            logAndEchoError "Fail to uninstall. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            return 1
        fi

    else
        logAndEchoInfo "rpm bag does not exist, no need to uninstall. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 0
    fi
}

main

