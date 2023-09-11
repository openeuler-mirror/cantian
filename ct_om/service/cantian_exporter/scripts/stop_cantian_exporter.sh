#!/bin/bash
set +x

function check_python_script_status() {
    py_pid=$(ps -ef | grep "python3 /opt/cantian/ct_om/service/cantian_exporter/exporter/execute.py" | grep -v grep | awk '{print $2}')
    if [ -z "${py_pid}" ];then
        return 1
    fi
    return 0
}

# 杀死父进程派生的子孙进程
function kill_descendants() {
    local parent_pid=$1

    # 获取所有子孙进程的PID
    descendants=$(pgrep -P "$parent_pid")

    # 杀掉子孙进程
    for pid in ${descendants[@]}; do
        kill_descendants "${pid}"  # 递归杀掉子孙进程
    done

    kill -9 "${parent_pid}"
}

function kill_python_script_process() {
    check_python_script_status
    if [ $? -eq 0 ];then
        ct_exporter_pid=$(ps -ef | grep "python3 /opt/cantian/ct_om/service/cantian_exporter/exporter/execute.py" | grep -v grep | awk '{print $2}')
        kill_descendants "${ct_exporter_pid}"
        if [ $? -eq 0 ];then
            echo "Success to kill [execute.py] process"
        else
            echo "Fail to kill [execute.py] process"
            exit 1
        fi
    else
        echo "Python scripts process [execute.py] does not exist, no need to kill"
    fi
}

echo "Start to kill cantian_exporter daemon and python scripts process"

kill_python_script_process

echo "Success to execute current shell script"
