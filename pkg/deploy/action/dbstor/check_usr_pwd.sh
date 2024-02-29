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

# 拉起 cstool 进程，查询CGW建链情况
function use_cstool_query_connection()
{
    local cstoolCmd="cstool"
    local setType=""
    export LD_LIBRARY_PATH=/opt/cantian/dbstor/add-ons
    
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
    link_type=$(python3 ${CURRENT_PATH}/../cantian/get_config_info.py "link_type")
    rm -rf ${DBSTOOL_PATH}/conf/
    mkdir -p ${DBSTOOL_PATH}/conf/{dbs,infra/config}
    if [ ${link_type} == 1 ];then
        cp -arf /opt/cantian/image/Cantian-RUN-CENTOS-64bit/cfg/node_config_rdma.xml ${DBSTOOL_PATH}/conf/infra/config/node_config.xml
        cp -arf /opt/cantian/dbstor/add-ons/mlnx/* /opt/cantian/dbstor/add-ons/
    else
        cp -arf /opt/cantian/image/Cantian-RUN-CENTOS-64bit/cfg/node_config_tcp.xml ${DBSTOOL_PATH}/conf/infra/config/node_config.xml
        cp -arf /opt/cantian/dbstor/add-ons/nomlnx/* /opt/cantian/dbstor/add-ons/
    fi
    cp -arf /opt/cantian/image/Cantian-RUN-CENTOS-64bit/cfg/osd.cfg ${DBSTOOL_PATH}/conf/infra/config/
    cp -r ${DBSTOOL_PATH}/tools/dbstor_config.ini ${DBSTOOL_PATH}/conf/dbs/dbstor_config.ini
    chmod 640 ${DBSTOOL_PATH}/conf/infra/config/*
    chmod 640 ${DBSTOOL_PATH}/conf/dbs/*
    cd  ${DBSTOOL_PATH}/tools
    use_cstool_query_connection
}

main $@
