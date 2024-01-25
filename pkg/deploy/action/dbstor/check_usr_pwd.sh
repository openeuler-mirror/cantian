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
    kill -9 `pidof ${processName}`

}

# 拉起 cstool 进程，查询CGW建链情况
function use_cstool_query_connection()
{
    local cstoolCmd="cstool"
    local setType=""
    export LD_LIBRARY_PATH=/opt/cantian/cantian/server/add-ons
    
    # 默认使用 --set-debug 类型的命令。如果打包时指定了 CSTOOL_TYPE=release 变量，则添加 --set-cli 参数，使用 release 的命令
    if [ ${CSTOOL_TYPE} == release ] || [ ${CSTOOL_TYPE} == asan ]; then
        setType="--set-cli"
    fi

    # 先清理 cstool 进程
    kill_process ${cstoolCmd}
    sleep 5s

    #挂起进程
    nohup ./${cstoolCmd} &> /dev/null &
     
    #等待 cstool 有足够的时间后台拉起
    sleep 5s
    
    #查看建链情况
    for i in {1..30}
    do 
        ./diagsh ${setType} --attach="cs_tool_2048" --cmd="cgw showdev" 2>&1 | tee >${DBSTOOL_PATH}/${LOG_NAME}
        chmod 640 ${DBSTOOL_PATH}/${LOG_NAME}
        link_cnt=$(cat ${DBSTOOL_PATH}/${LOG_NAME} | sed -n '/LinkCnt/,$ p' |grep '0x' | wc -l)

        if [ ${link_cnt} -eq 0 ]; then
            sleep 1s
        else
            #查询后台挂起的进程并退出
            kill_process ${cstoolCmd}
            unset LD_LIBRARY_PATH
            exit 0
        fi
    done

    #查询后台挂起的进程并退出
    kill_process ${cstoolCmd}
    unset LD_LIBRARY_PATH
    exit 1
}

function main()
{
    rm -rf ${DBSTOOL_PATH}/conf/
    cp -r /mnt/dbdata/local/cantian/tmp/data/dbstor/conf/ ${DBSTOOL_PATH}/
    cp -r ${DBSTOOL_PATH}/tools/dbstor_config.ini ${DBSTOOL_PATH}/conf/dbs/dbstor_config.ini
    chmod 640 ${DBSTOOL_PATH}/conf/infra/config/*
    chmod 640 ${DBSTOOL_PATH}/conf/dbs/*
    cd  ${DBSTOOL_PATH}/tools
    use_cstool_query_connection
}

main $@
