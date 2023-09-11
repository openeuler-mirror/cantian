#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${CURRENT_PATH}/$(basename $0)
SERVICE_SCRIPT_PATH=/opt/cantian/ct_om/service/

sh ${CURRENT_PATH}/check_status.sh
if [ $? -ne 0 ]; then
    echo "ctmgr has been offline already"
    exit 0
fi


function stop_ctmgr()
{
    sh ${SERVICE_SCRIPT_PATH}/ctmgr/scripts/stop_ctmgr.sh
    return $?
}

function main()
{
    stop_ctmgr
    return $?
}

main
