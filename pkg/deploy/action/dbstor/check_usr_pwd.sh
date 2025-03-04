#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
DBSTOOL_PATH='/opt/cantian/dbstor'
LOG_NAME='cgwshowdev.log'
DEL_DATABASE_SH='del_databasealldata.sh'
dr_setup=`python3 ${CURRENT_PATH}/../docker/get_config_info.py "dr_deploy.dr_setup"`
role=`python3 ${CURRENT_PATH}/../docker/get_config_info.py "dr_deploy.role"`
cantian_in_container=`python3 ${CURRENT_PATH}/../docker/get_config_info.py "cantian_in_container"`
NUMA_CONF_DIR="/opt/cantian/dbstor/conf/dbs"

# 停止 cstool 进程
function kill_process()
{
    local processName=${1}
    local testId=$(ps -elf | grep ${processName} | grep -v grep | head -n 1 | awk '{print $4}')
    if [[ -n ${testId} ]]; then
        kill -9 ${testId}
    fi
}

function check_dr_status_in_container()
{
  if [[ x"${cantian_in_container}" == x"0" ]];then
    # 物理默认返回0，要检查
    return 0
  fi
  share_fs=$(python3 ${CURRENT_PATH}/../cantian/get_config_info.py "storage_share_fs")
  out=$(/opt/cantian/image/Cantian-RUN-CENTOS-64bit/bin/dbstor --query-file --fs-name="${share_fs}" )
  if [[ $? -ne 0 ]];then
    echo "Failed to query share filesystem."
    return 0
  fi
  num=$(echo ${out} | grep 'dr_deploy_param.json' | wc -l)
  if [[ ${num} -gt 0 ]];then
    # 容器已经搭好容灾，不检查
    return 1
  fi
  if [[ x"${dr_setup}" == x"True" ]] && [[ x"${role}" == x"standby" ]];then
    # 容器第一次搭容灾，备端不检查
    return 1
  fi
  return 0
}

function execute_dbstor_query_file()
{
  local fs=$(python3 ${CURRENT_PATH}/../cantian/get_config_info.py "$1")
  if [ $1 == "storage_dbstor_fs" ];then
    local dbstor_fs_vstore_id=$(python3 ${CURRENT_PATH}/../cantian/get_config_info.py "dbstor_fs_vstore_id")
    out=$(/opt/cantian/image/Cantian-RUN-CENTOS-64bit/bin/dbstor --query-fs-info --fs-name="${fs}" --vstore_id="${dbstor_fs_vstore_id}" )
    result=$?
  else
    out=$(/opt/cantian/image/Cantian-RUN-CENTOS-64bit/bin/dbstor --query-fs-info --fs-name="${fs}" --vstore_id=0 )
    result=$?
  fi
  echo ${out} >> /opt/cantian/log/dbstor/install.log
  if [[ ${result} -ne 0 ]];then
    notsupporte=$(echo ${out} | grep -c "DBstor version not supported")
    if [[ ${notsupporte} -gt 0 ]];then
      echo "DBstor version not supported cmd dbstor --query-file"
      exit 0
    fi
    echo "Fail to query file system [$1], please check if vstore id matches file system [$1]"
    exit 1
  else
    fs_mode=$(echo ${out} | grep -c "fs_mode = 1")
    if [[ ${fs_mode} -gt 0 ]];then
      if [ $1 == "storage_dbstor_fs" ];then
        out=$(/opt/cantian/image/Cantian-RUN-CENTOS-64bit/bin/dbstor --query-file --fs-name="${fs}" --vstore_id="${dbstor_fs_vstore_id}" )
        return_code=$?
        echo ${out} >> /opt/cantian/log/dbstor/install.log
        if [[ ${return_code} -ne 0 ]];then
          echo "Fail to query file system [$1], because filesystem type is metro, but hyper metro filesystem pair does not exist."
          exit 1
        fi
      fi
    fi
  fi
}

function check_file_system()
{
  echo "Begin to check file system" >> /opt/cantian/log/dbstor/install.log
  deploy_mode=$(python3 ${CURRENT_PATH}/../cantian/get_config_info.py "deploy_mode")
  if [[ ${deploy_mode} == "dbstor" ]];then
    execute_dbstor_query_file "storage_share_fs"
    execute_dbstor_query_file "storage_archive_fs"
  fi
  check_dr_status_in_container
  dr_stat=$?
  if [[ ! -f "${CURRENT_PATH}/../../config/dr_deploy_param.json" ]] && [[ ${dr_stat} -ne 1 ]];then
    execute_dbstor_query_file "storage_dbstor_fs"
    execute_dbstor_query_file "storage_dbstor_page_fs"
  fi
  echo "File system check pass" >> /opt/cantian/log/dbstor/install.log
}

function generate_numa_config() {
    local node_numa_file="${NUMA_CONF_DIR}/node_numa.ini"
    local numa_info_file="${NUMA_CONF_DIR}/numa_info.ini"

    local success=true

    if [[ -f "$node_numa_file" && -f "$numa_info_file" ]]; then
        echo "NUMA configuration files already exist. Skipping update."
        return 0
    fi

    mkdir -p "$NUMA_CONF_DIR" || { echo "Failed to create directory: $NUMA_CONF_DIR"; success=false; }

    cpu_num=$(grep -c ^processor /proc/cpuinfo) || { echo "Failed to get CPU number from /proc/cpuinfo"; success=false; }

    # 创建 numa_info.ini 文件
    if [ ! -f "$numa_info_file" ]; then
        numa_nodes=$(lscpu | grep -oP "NUMA node\(s\):\s+\K\d+") || { echo "Failed to get NUMA nodes from lscpu"; success=false; }

        numa_cpu_ranges=$(lscpu | grep -oP "NUMA node\d+ CPU\(s\):\s+\K[0-9,-]+")

        echo "[NUMA_PARTITION]" > "$numa_info_file" || { echo "Failed to write to $numa_info_file"; success=false; }
        echo "cpu_num=$cpu_num" >> "$numa_info_file" || { echo "Failed to write cpu_num to $numa_info_file"; success=false; }
        echo "numa_num=$numa_nodes" >> "$numa_info_file" || { echo "Failed to write numa_num to $numa_info_file"; success=false; }

        for i in $(seq 0 $((numa_nodes - 1))); do
            numa_range=$(echo "$numa_cpu_ranges" | sed -n "$((i + 1))p") || { echo "Failed to parse NUMA range for node $i"; success=false; }
            echo "numa_${i}=$numa_range" >> "$numa_info_file" || { echo "Failed to write numa_${i} to $numa_info_file"; success=false; }
        done
    fi

    if [ ! -f "$node_numa_file" ]; then
        # 获取 NUMA 是否启用
        numa_enabled=false
        if lscpu | grep -q "NUMA node"; then
            numa_enabled=true
        fi

        echo "[PROC_PARTITION]" > "$node_numa_file" || { echo "Failed to write to $node_numa_file"; success=false; }
        echo "numa_enable=$numa_enabled" >> "$node_numa_file" || { echo "Failed to write numa_enable to $node_numa_file"; success=false; }
        echo "numa_virtual_enable=false" >> "$node_numa_file" || { echo "Failed to write numa_virtual_enable to $node_numa_file"; success=false; }
    fi

    if [ "$success" = true ]; then
        echo "NUMA configuration files created successfully."
    else
        echo "Failed to create NUMA configuration file."
    fi
}

function main()
{
    if [[ "$1" == "update_numa_config" ]]; then
        generate_numa_config
        exit 0
    fi

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
    if [[ -f /opt/cantian/youmai_demo ]];then
        return
    fi

    generate_numa_config

    /opt/cantian/image/Cantian-RUN-CENTOS-64bit/bin/dbstor --dbs-link-check >> /opt/cantian/log/dbstor/install.log
    if [[ $? -ne 0 ]];then
        cat /opt/cantian/log/dbstor/run/dsware_* | grep "CGW link failed, locIp" | tail -n 5
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
        echo "
        check dbstor passwd failed, possible reasons:
                1 username or password of dbstor storage service is incorrect.
                2 cgw create link failed.
                3 ip address of dbstor storage service is incorrect.
                please contact the engineer to solve."
        exit 1
    fi
    check_file_system
}

main $@
