#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
DBSTOOL_PATH='/opt/cantian/dbstor'
LOG_NAME='cgwshowdev.log'
DEL_DATABASE_SH='del_databasealldata.sh'

# 停止 cstool 进程
function kill_process()
{
    local processName=${1}
    local testId=$(ps -elf | grep ${processName} | grep -v grep | head -n 1 | awk '{print $4}')
    if [[ -n ${testId} ]]; then
        kill -9 ${testId}
    fi
}

# 拉起 cstool 进程，查询client server版本兼容性
function use_cstool_query_compatibility()
{
    local cstoolCmd="./cstool"
    local setType=""
    export LD_LIBRARY_PATH=/opt/cantian/dbstor/add-ons

    # 默认使用 --set-debug 类型的命令。如果打包时指定了 CSTOOL_TYPE=release 变量，则添加 --set-cli 参数，使用 release 的命令
    if [ ${CSTOOL_TYPE} == release ] || [ ${CSTOOL_TYPE} == asan ]; then
        setType="--set-cli"
    fi

    # 先清理 cstool 进程
    kill_process ${cstoolCmd}
    sleep 2s

    #挂起进程
    cd ${DBSTOOL_PATH}/tools
    chmod +x cstool
    nohup ${cstoolCmd} &> /dev/null &

    #等待 cstool 有足够的时间后台拉起
    sleep 5s

    local ret
    ret=$(./diagsh ${setType} --attach="cs_tool_2048" --cmd="client_test -func checkversion" | grep -i "Fail" | wc -l)

    sleep 1s
    #查询后台挂起的进程并退出
    kill_process ${cstoolCmd}
    unset LD_LIBRARY_PATH
    exit ${ret}
}

function main()
{
    use_cstool_query_compatibility
}

main $@
