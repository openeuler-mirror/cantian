#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${CURRENT_PATH}/$(basename $0)
SERVICE_SCRIPT_PATH_CTMGR=/opt/cantian/ct_om/service/ctmgr/scripts
WAIT_TIME=3

function start_ctmgr() {
    sh ${SERVICE_SCRIPT_PATH_CTMGR}/start_ctmgr.sh
}

function main()
{
    start_ctmgr
    if [ $? -ne 0 ]; then
        return 1
    fi

    sleep ${WAIT_TIME}
    return 0
}

main
