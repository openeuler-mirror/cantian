#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
CONFIG_PATH=${CURRENT_PATH}/../../config
NFS_TIMEO=50

mount_nfs_check='true'
node_id=`python3 ${CURRENT_PATH}/get_config_info.py "node_id"`
deploy_mode=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_mode"`
cantian_user=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_user"`
cantian_group=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_group"`
deploy_user=`python3 ${CURRENT_PATH}/../get_config_info.py "deploy_user"`
storage_share_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_share_fs"`
storage_archive_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_archive_fs"`
storage_metadata_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_metadata_fs"`

source ${CURRENT_PATH}/../log4sh.sh
source ${CURRENT_PATH}/../env.sh

# 检查NFS是否挂载成功
function checkMountNFS() {
    check_item=$1
    if [[ ${check_item} -ne 0 ]]; then
        mount_nfs_check='false'
        logAndEchoError "NFS mount failed with exit code ${check_item}"
    fi
}

function check_port() {
  # nfs4.0协议挂载固定监听端口，不指定端口该监听会随机指定端口不符合安全要求。指定前检查若该端口被非nfs进程占用则报错
  # 端口范围36729~36738: 起始端口36729， 通过循环每次递增1，检查端口是否被暂用，如果10个端口都被暂用，报错退出；
  #                     检测到有未被占用端口，退出循环，使用当前未被占用端口进行文件系统挂载
  for ((i=0; i<10; i++))
  do
    local port=$(("${NFS_PORT}" + "${i}"))
    listen_port=$(netstat -tunpl 2>/dev/null | grep "${port}" | awk '{print $4}' | awk -F':' '{print $NF}')
    occupied_proc_name=$(netstat -tunpl 2>/dev/null | grep "${port}" | awk '{print $7}' | awk 'NR==1 { print }')
    if [[ -n "${listen_port}" && ${occupied_proc_name} != "-" ]];then
      logAndEchoError "Port ${port} has been temporarily used by a non-nfs process"
      continue
    else
      logAndEchoInfo "Port[${port}] is available"
      NFS_PORT=${port}
      return
    fi
  done
  logAndEchoError "Port 36729~36738 has been temporarily used by a non-nfs process, please modify env.sh file in the current path, Change the value of NFS_PORT to an unused port"
  exit 1
}

function copy_deploy_param() {
    if [[ x"${node_id}" == x"0" ]];then
        cp -rf "${CONFIG_PATH}"/deploy_param.json /mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/
        chmod 600 /mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/deploy_param.json
        chown "${cantian_user}":"${cantian_group}" /mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/deploy_param.json
    fi
}

function mount_fs() {
    # 该脚本只有两种模式：file和combined
    mkdir -m 750 -p /mnt/dbdata/remote/share_${storage_share_fs}
    chown ${cantian_user}:${cantian_group} /mnt/dbdata/remote/share_${storage_share_fs}

    if [[ ${storage_archive_fs} != '' ]]; then
        mkdir -m 750 -p /mnt/dbdata/remote/archive_${storage_archive_fs}
        chown ${cantian_user}:${cantian_group} /mnt/dbdata/remote/archive_${storage_archive_fs}
    fi

    mkdir -m 755 -p /mnt/dbdata/remote/metadata_${storage_metadata_fs}
    

    # 获取nfs挂载的ip
    metadata_logic_ip=`python3 ${CURRENT_PATH}/get_config_info.py "metadata_logic_ip"`

    if [[ x"${deploy_mode}" != x"file" ]]; then
        kerberos_type=`python3 ${CURRENT_PATH}/get_config_info.py "kerberos_key"`
        mount -t nfs -o sec="${kerberos_type}",timeo=${NFS_TIMEO},nosuid,nodev ${metadata_logic_ip}:/${storage_metadata_fs} /mnt/dbdata/remote/metadata_${storage_metadata_fs}
    else
        mount -t nfs -o timeo=${NFS_TIMEO},nosuid,nodev ${metadata_logic_ip}:/${storage_metadata_fs} /mnt/dbdata/remote/metadata_${storage_metadata_fs}
    fi

    metadata_result=$?
    if [ ${metadata_result} -ne 0 ]; then
        logAndEchoError "mount metadata nfs failed"
    fi
    # 检查36729~36728是否有可用端口
    check_port
    sysctl fs.nfs.nfs_callback_tcpport="${NFS_PORT}" > /dev/null 2>&1
    # 挂载share nfs
    if [[ ${storage_archive_fs} != '' ]]; then
        archive_logic_ip=`python3 ${CURRENT_PATH}/get_config_info.py "archive_logic_ip"`
        if [[ ${archive_logic_ip} = '' ]]; then
            logAndEchoInfo "please check archive_logic_ip"
        fi

        if [[ x"${deploy_mode}" != x"file" ]]; then
            mount -t nfs -o sec="${kerberos_type}",timeo=${NFS_TIMEO},nosuid,nodev ${archive_logic_ip}:/${storage_archive_fs} /mnt/dbdata/remote/archive_${storage_archive_fs}
        else
            mount -t nfs -o timeo=${NFS_TIMEO},nosuid,nodev ${archive_logic_ip}:/${storage_archive_fs} /mnt/dbdata/remote/archive_${storage_archive_fs}
        fi
        archive_result=$?
        if [ ${archive_result} -ne 0 ]; then
            logAndEchoError "mount archive nfs failed"
        fi
        checkMountNFS ${archive_result}

        chmod 750 /mnt/dbdata/remote/archive_${storage_archive_fs}
        chown -hR "${cantian_user}":"${deploy_group}" /mnt/dbdata/remote/archive_${storage_archive_fs} > /dev/null 2>&1
        # 修改备份nfs路径属主属组
    fi
    checkMountNFS ${metadata_result}

    if [[ x"${deploy_mode}" == x"file" ]]; then
        share_logic_ip=`python3 ${CURRENT_PATH}/get_config_info.py "share_logic_ip"`
        storage_dbstore_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_dbstore_fs"`
        storage_logic_ip=`python3 ${CURRENT_PATH}/get_config_info.py "storage_logic_ip"`
        # nas模式才挂载share nfs
        mount -t nfs -o vers=4.0,timeo=${NFS_TIMEO},nosuid,nodev ${share_logic_ip}:/${storage_share_fs} /mnt/dbdata/remote/share_${storage_share_fs}
        share_result=$?
        if [ ${share_result} -ne 0 ]; then
            logAndEchoError "mount share nfs failed"
        fi
        chown -hR "${cantian_user}":"${cantian_group}" /mnt/dbdata/remote/share_${storage_share_fs} > /dev/null 2>&1
        checkMountNFS ${share_result}

        mkdir -m 750 -p /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"
        mount -t nfs -o vers=4.0,timeo=${NFS_TIMEO},nosuid,nodev "${storage_logic_ip}":/"${storage_dbstore_fs}" /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"
        dbstore_result=$?
        if [ ${dbstore_result} -ne 0 ]; then
            logAndEchoError "mount dbstore nfs failed"
        fi
        chown "${cantian_user}":"${cantian_user}" /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"
        checkMountNFS ${dbstore_result}

        mkdir -m 750 -p /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"/data
        mkdir -m 750 -p /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"/share_data
        rm -rf /mnt/dbdata/local/cantian/tmp/data/data
        ln -s /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"/data/ /mnt/dbdata/local/cantian/tmp/data/data
        chown -h ${cantian_user}:${cantian_user} /mnt/dbdata/local/cantian/tmp/data/data
        chown -h ${cantian_user}:${cantian_user} /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"/data
        chown -h ${cantian_user}:${cantian_user} /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"/share_data
    fi

    # 检查nfs是否都挂载成功
    if [[ ${mount_nfs_check} != 'true' ]]; then
        logAndEchoInfo "mount nfs failed"
        exit 1
    fi
    remoteInfo=`ls -l /mnt/dbdata/remote`
    logAndEchoInfo "/mnt/dbdata/remote detail is: ${remoteInfo}"
    # 目录权限最小化
    chmod 750 /mnt/dbdata/remote/share_${storage_share_fs}

    chmod 755 /mnt/dbdata/remote/metadata_${storage_metadata_fs}
    node_id=$(python3 ${CURRENT_PATH}/get_config_info.py "node_id")
    copy_deploy_param
    if [ ! -f /mnt/dbdata/remote/metadata_${storage_metadata_fs}/versions.yml ] && [ "${node_id}" == "0" ]; then
        if [ -d /mnt/dbdata/remote/metadata_${storage_metadata_fs}/node0 ]; then
            rm -rf /mnt/dbdata/remote/metadata_${storage_metadata_fs}/node${node_id}
        fi
        if [ -d /mnt/dbdata/remote/metadata_${storage_metadata_fs}/node1 ]; then
            rm -rf /mnt/dbdata/remote/metadata_${storage_metadata_fs}/node${node_id}
        fi
        mkdir -m 770 -p /mnt/dbdata/remote/metadata_${storage_metadata_fs}/node0
        chown ${deploy_user}:${cantian_common_group} /mnt/dbdata/remote/metadata_${storage_metadata_fs}/node0
        mkdir -m 770 -p /mnt/dbdata/remote/metadata_${storage_metadata_fs}/node1
        chown ${deploy_user}:${cantian_common_group} /mnt/dbdata/remote/metadata_${storage_metadata_fs}/node1
        if [ -f "/mnt/dbdata/remote/share_${storage_share_fs}/gcc_home/gcc_file" ]; then
            logAndEchoError "gcc file already exists, please check if any cluster is running."
            exit 1
        fi
    fi
}

mount_fs