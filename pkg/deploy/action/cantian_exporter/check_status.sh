#!/bin/bash
set +x

function check_python_script_status()
{
    py_pid=$(ps -ef | grep "python3 /opt/cantian/ct_om/service/cantian_exporter/exporter/execute.py" | grep -v grep | awk '{print $2}')
    if [ -z "${py_pid}" ];then
        return 1
    fi
    return 0
}


function main()
{
    check_python_script_status
    return $?

}

main
