#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${CURRENT_PATH}/$(basename $0)

function check_ctmgr_status() {
    active_service=$(ps -ef | grep /opt/cantian/ct_om/service/ctmgr/uds_server.py | grep python)
    if [[ ${active_service} != "" ]]; then
        return 0
    else
        return 1
    fi
}

function main()
{

    check_ctmgr_status
    return $?
}

main
