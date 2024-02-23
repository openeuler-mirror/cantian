#!/bin/bash
set +x

function check_logicrep_status() {
    active_service=$(ps -ef | grep ZlogCatcherMain | grep )
    if [[ ${active_service} != "" ]]; then
        return 0
    else
        return 1
    fi
}

function main()
{
    check_logicrep_status
    return $?
}

main
