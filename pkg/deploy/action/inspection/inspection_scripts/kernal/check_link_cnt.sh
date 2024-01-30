#!/bin/bash
DBSTOOL_PATH='/opt/cantian/dbstor'
 
 
function use_cstool_query_connection()
{
    local setType=""
    LOG_NAME='cgwshowdev.log'
 
    # 默认使用 --set-debug 类型的命令。如果打包时指定了 CSTOOL_TYPE=release 变量，则添加 --set-cli 参数，使用 release 的命令
    if [ ${CSTOOL_TYPE} == release ] || [ ${CSTOOL_TYPE} == asan ]; then
        setType="--set-cli"
    fi
     
    #查看建链情况
    for i in {1..5}
    do 
        ./diagsh ${setType} --attach="dbstore_client_350" --cmd="cgw showdev" 2>&1 | tee >${DBSTOOL_PATH}/${LOG_NAME}
        link_cnt=$(cat ${DBSTOOL_PATH}/${LOG_NAME} | sed -n '/LinkCnt/,$ p' |grep '0x' | wc -l)
 
        if [ ${link_cnt} -lt 2 ]; then
            sleep 1s
        else
            #链路数量不小于2
            echo "0"
            exit 0
        fi
    done
 
    #链路数量小于2
    echo "1"
    exit 1
}
 
function main()
{
    cd  ${DBSTOOL_PATH}/tools
    use_cstool_query_connection
}
 
main $@