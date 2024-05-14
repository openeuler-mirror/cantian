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
    if [[ ${check_item} != '0' ]]; then
        mount_nfs_check='fales'
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

function wait_for_node0_install() {
    logAndEchoInfo "if block here, this node is wait for node 0 to install. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    random_seed=$(python3 ${CURRENT_PATH}/../get_config_info.py "share_random_seed")
    try_times=180
    while [ ${try_times} -gt 0 ]
    do
        try_times=$(expr "${try_times}" - 1)
        if [[ "${random_seed}" != "" ]] && [[ "${random_seed}" != "None" ]]; then
            return 0
        else
            sleep 1s
            random_seed=$(python3 ${CURRENT_PATH}/../get_config_info.py "share_random_seed")
        fi
    done
    logAndEchoError "deploy config file is not detected, please check node 0 weather is installed"
    exit 1
}

function update_random_seed() {
    if [[ x"${node_id}" == x"0" ]];then
        random_seed=$(python3 -c 'import secrets; secrets_generator = secrets.SystemRandom(); print(secrets_generator.randint(0, 255))')
    else
        wait_for_node0_install
        random_seed=$(python3 ${CURRENT_PATH}/../get_config_info.py "share_random_seed")
    fi
    python3 ${CURRENT_PATH}/../write_config.py "random_seed" "${random_seed}"
}

function check_deploy_param() {
    if [[ x"${node_id}" == x"0" ]];then
        cp -rf "${CONFIG_PATH}"/deploy_param.json /mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/
        chmod 600 /mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/deploy_param.json
        chown "${cantian_user}":"${cantian_group}" /mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/deploy_param.json
    fi
}

function mount_fs() {
    if [[ x"${deploy_mode}" != x"dbstore_unify" ]]; then
        mkdir -m 750 -p /mnt/dbdata/remote/share_${storage_share_fs}
        chown ${cantian_user}:${cantian_group} /mnt/dbdata/remote/share_${storage_share_fs}
    fi

    if [[ ${storage_archive_fs} != '' ]]; then
        mkdir -m 750 -p /mnt/dbdata/remote/archive_${storage_archive_fs}
        chown ${cantian_user}:${cantian_group} /mnt/dbdata/remote/archive_${storage_archive_fs}
    fi

    mkdir -m 755 -p /mnt/dbdata/remote/metadata_${storage_metadata_fs}
    chmod 755 /mnt/dbdata/remote


    # 获取nfs挂载的ip
    share_logic_ip=`python3 ${CURRENT_PATH}/get_config_info.py "share_logic_ip"`
    if [[ ${storage_archive_fs} != '' ]]; then
        archive_logic_ip=`python3 ${CURRENT_PATH}/get_config_info.py "archive_logic_ip"`
        if [[ ${archive_logic_ip} = '' ]]; then
            logAndEchoInfo "please check archive_logic_ip"
        fi
    fi
    metadata_logic_ip=`python3 ${CURRENT_PATH}/get_config_info.py "metadata_logic_ip"`

    if [[ x"${deploy_mode}" != x"nas" ]]; then
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
    if [[ x"${deploy_mode}" != x"dbstore_unify" ]]; then
        if [[ x"${deploy_mode}" == x"dbstore" ]]; then
            mount -t nfs -o sec="${kerberos_type}",vers=4.0,timeo=${NFS_TIMEO},nosuid,nodev ${share_logic_ip}:/${storage_share_fs} /mnt/dbdata/remote/share_${storage_share_fs}
        else
            mount -t nfs -o vers=4.0,timeo=${NFS_TIMEO},nosuid,nodev ${share_logic_ip}:/${storage_share_fs} /mnt/dbdata/remote/share_${storage_share_fs}
        fi
        share_result=$?
        if [ ${share_result} -ne 0 ]; then
            logAndEchoError "mount share nfs failed"
        fi
        chown -hR "${cantian_user}":"${cantian_group}" /mnt/dbdata/remote/share_${storage_share_fs} > /dev/null 2>&1
        checkMountNFS ${share_result}
    fi
    if [[ ${storage_archive_fs} != '' ]]; then
        if [[ x"${deploy_mode}" != x"nas" ]]; then
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

    if [[ x"${deploy_mode}" == x"nas" ]]; then
        storage_dbstore_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_dbstore_fs"`
        storage_logic_ip=`python3 ${CURRENT_PATH}/get_config_info.py "storage_logic_ip"`
        mkdir -m 750 -p /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"
        chown "${cantian_user}":"${cantian_user}" /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"
        mount -t nfs -o vers=4.0,timeo=${NFS_TIMEO},nosuid,nodev "${storage_logic_ip}":/"${storage_dbstore_fs}" /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"
        checkMountNFS $?
        chown "${cantian_user}":"${cantian_user}" /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"
        mkdir -m 750 -p /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"/data
        mkdir -m 750 -p /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"/share_data
        chown ${cantian_user}:${cantian_user} /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"/data
        chown ${cantian_user}:${cantian_user} /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"/share_data
    fi

    # 检查nfs是否都挂载成功
    if [[ ${mount_nfs_check} != 'true' ]]; then
        logAndEchoInfo "mount nfs failed"
        exit 1
    fi
    remoteInfo=`ls -l /mnt/dbdata/remote`
    logAndEchoInfo "/mnt/dbdata/remote detail is: ${remoteInfo}"
    # 目录权限最小化
    if [[ x"${deploy_mode}" != x"dbstore_unify" ]]; then
        chmod 750 /mnt/dbdata/remote/share_${storage_share_fs}
    fi
    chmod 755 /mnt/dbdata/remote/metadata_${storage_metadata_fs}
    node_id=$(python3 ${CURRENT_PATH}/get_config_info.py "node_id")
    if [ ! -f /mnt/dbdata/remote/metadata_${storage_metadata_fs}/versions.yml ]; then
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

        update_random_seed
        # 挂载后，0节点拷贝配置文件至文件系统下，1节点检查对应配置文件参数
        check_deploy_param
    fi
}

mount_fs