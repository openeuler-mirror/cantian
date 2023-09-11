#!/bin/bash
set +x
UPPER_LEVEL_PATH=$(dirname $(dirname $(readlink -f $0)))
PYTHON_HOME_DIR="service/cantian_exporter"
PYTHON_SCRIPT_PATH="exporter/execute.py"
CE_TESK_ID=""
WAIT_TIME=2
# 查询cantian_exporter进程id
# 1、第一次通过ps或pidof获取到pid后，保存对应的PID。
# 2、后续再访问时，通过/proc/${pid}/cmdline文件来检查进程是否存在？
#    2.1 如果PID还存在，则继续使用该PID处理。
#    2.2 如果PID不存在，则执行步骤1。

export PYTHONPATH=${UPPER_LEVEL_PATH}
# 导入kmc加解密需要用到的动态库
export LD_LIBRARY_PATH=/opt/cantian/dbstor/lib:${LD_LIBRARY_PATH}

function query_cetask_pid()
{
    CE_TESK_ID=$(ps -ef | grep "python3 /opt/cantian/ct_om/service/cantian_exporter/exporter/execute.py" | grep -v grep | awk '{print $2}')
}

function check_cetask_status()
{
    query_cetask_pid
    # ct_exporter进程不在
    if [ -z "${CE_TESK_ID}" ];then
        return 1
    fi
    return 0
}

function start_cetask()
{
    check_cetask_status
    if [ $? -eq 0 ]; then
        echo "ct_exporter already in service"
        exit 0
    fi
    python3 ${UPPER_LEVEL_PATH}/${PYTHON_SCRIPT_PATH}&
    sleep ${WAIT_TIME}
    check_cetask_status
    if [ $? -eq 0 ]; then
      echo "success to start ct_exporter"
      exit 0
    else
      echo "Fail to start ct_exporter"
      exit 1
    fi
}

start_cetask