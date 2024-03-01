#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${CURRENT_PATH}/$(basename $0)
SERVICE_SCRIPT_PATH=/opt/cantian/ct_om/service/cantian_exporter/scripts
cantian_exporter_log=/opt/cantian/cantian_exporter/cantian_exporter.log
WAIT_TIME=3

source ${CURRENT_PATH}/cantian_exporter_log.sh

function start_exporter()
{
    sh ${SERVICE_SCRIPT_PATH}/start_cantian_exporter.sh >> ${cantian_exporter_log}
    return $?
}

function main()
{
    logAndEchoInfo "Begin to start ct_exporter. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    start_exporter > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        logAndEchoError "The ct_exporter start error. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    # 根据进程是否在位确定cantian_exporter拉起成功
    sleep ${WAIT_TIME}
    sh ${CURRENT_PATH}/check_status.sh
    if [ $? -ne 0 ]; then
        logAndEchoError "Failed to start ct_exporter. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    logAndEchoInfo "Success to start ct_exporter. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    return 0
}

main
