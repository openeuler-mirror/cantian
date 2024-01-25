#!/bin/bash

WAIT_TIME=2
CURRENT_PATH=$(dirname $(readlink -f $0))

export PYTHONPATH=/opt/cantian/ct_om/service/ctmgr/
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
    logAndEchoInfo "ctmgr already in service"
else
    python3 /opt/cantian/ct_om/service/ctmgr/uds_server.py &
    sleep ${WAIT_TIME}
    check_status
    if [ $? -ne 0 ]; then
        logAndEchoError "start ctmgr fail please check /opt/cantian/ct_om/service/ctmgr/ctmgr_log/deploy.log"
        exit 1
    else
        logAndEchoInfo "start ctmgr success"
        exit 0
    fi
fi