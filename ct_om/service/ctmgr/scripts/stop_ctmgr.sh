#!/bin/bash

CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${CURRENT_PATH}/$(basename $0)
source ${CURRENT_PATH}/log4sh.sh

function check_status() {
    active_service=$(ps -ef | grep /opt/cantian/ct_om/service/ctmgr/uds_server.py | grep python)
    if [[ ${active_service} != "" ]]; then
        return 0
    else
        return 1
    fi
}

check_status
if [ $? -eq 0 ]; then
    ctmgr_pid=$(ps -ef | grep "/opt/cantian/ct_om/service/ctmgr/uds_server.py" | grep -v grep | awk '{print $2}')
    kill -9 ${ctmgr_pid}
    if [ $? -eq 0 ]; then
        rm -rf /opt/cantian/ct_om/service/ct_om.sock
        logAndEchoInfo "success stop ctmgr"
        exit 0
    else
        logAndEchoError "fail to stop ctmgr"
        exit 1
    fi
else
    logAndEchoInfo "ctmgr already stopped"
    exit 0
fi
