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

function main()
{
    link_type=$(python3 ${CURRENT_PATH}/../cantian/get_config_info.py "link_type")
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
    mkdir -p /opt/cantian/dbstor/data/logs/run
    export LD_LIBRARY_PATH=/opt/cantian/image/Cantian-RUN-CENTOS-64bit/lib:/opt/cantian/dbstor/add-ons
    /opt/cantian/image/Cantian-RUN-CENTOS-64bit/bin/dbstor --dbs-link-check >> /opt/cantian/dbstor/log/install.log
    if [[ $? -ne 0 ]];then
        cat /opt/cantian/dbstor/data/logs/run/dsware_* | grep "CGW link failed, locIp" | tail -n 5
        if [[ $? -eq 0 ]];then
            echo "Notice:
        CGW_LINK_STATE_CONNECT_OK   = 0
        CGW_LINK_STATE_CONNECTING   = 1
        CGW_LINK_STATE_CONNECT_FAIL = 2
        CGW_LINK_STATE_AUTH_FAIL    = 3
        CGW_LINK_STATE_REJECT_AUTH  = 4
        CGW_LINK_STATE_OVER_SIZE    = 5
        CGW_LINK_STATE_LSID_EXIT    = 6"
        fi
        exit 1
    fi
}

main $@
