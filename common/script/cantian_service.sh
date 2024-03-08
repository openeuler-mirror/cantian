#!/bin/bash

# 检查参天的守护进程是否在位

set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
source ${CURRENT_PATH}/../../action/env.sh
source ${CURRENT_PATH}/log4sh.sh
NFS_TIMEO=50

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

function mountNfs()
{
    # 获取要创建路径的路径名 /opt/cantian/common/script
    storage_share_fs=`python3 ${CURRENT_PATH}/../../action/get_config_info.py "storage_share_fs"`
    storage_archive_fs=`python3 ${CURRENT_PATH}/../../action/get_config_info.py "storage_archive_fs"`
    storage_metadata_fs=`python3 ${CURRENT_PATH}/../../action/get_config_info.py "storage_metadata_fs"`
    kerberos_type=`python3 ${CURRENT_PATH}/../../action/get_config_info.py  "kerberos_key"`
    deploy_mode=`python3 ${CURRENT_PATH}/../../action/get_config_info.py  "deploy_mode"`

    if [[ ${storage_archive_fs} != '' ]]; then
        mountpoint /mnt/dbdata/remote/archive_${storage_archive_fs} > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            logAndEchoInfo "/mnt/dbdata/remote/share_${storage_archive_fs} is not not a mountpoint, begin to mount. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            archive_logic_ip=`python3 ${CURRENT_PATH}/../../action/get_config_info.py "archive_logic_ip"`
            if [[ x"${deploy_mode}" != x"nas" ]]; then
                mount -t nfs -o sec="${kerberos_type}",timeo=${NFS_TIMEO},nosuid,nodev ${archive_logic_ip}:/${storage_archive_fs} /mnt/dbdata/remote/archive_${storage_archive_fs}
            else
                mount -t nfs -o timeo=${NFS_TIMEO},nosuid,nodev ${archive_logic_ip}:/${storage_archive_fs} /mnt/dbdata/remote/archive_${storage_archive_fs}
            fi

            if [ $? -ne 0 ]; then
                logAndEchoError "mount /mnt/dbdata/remote/share_${storage_archive_fs} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
                exit 1
            else
                logAndEchoInfo "mount /mnt/dbdata/remote/share_${storage_archive_fs} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            fi
        fi
    fi

    mountpoint /mnt/dbdata/remote/metadata_${storage_metadata_fs} > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        logAndEchoInfo "/mnt/dbdata/remote/metadata_${storage_metadata_fs} is not not a mountpoint, begin to mount. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        metadata_logic_ip=`python3 ${CURRENT_PATH}/../../action/get_config_info.py "metadata_logic_ip"`
        if [[ x"${deploy_mode}" != x"nas" ]]; then
            mount -t nfs -o sec="${kerberos_type}",timeo=${NFS_TIMEO},nosuid,nodev ${metadata_logic_ip}:/${storage_metadata_fs} /mnt/dbdata/remote/metadata_${storage_metadata_fs}
        else
            mount -t nfs -o timeo=${NFS_TIMEO},nosuid,nodev ${metadata_logic_ip}:/${storage_metadata_fs} /mnt/dbdata/remote/metadata_${storage_metadata_fs}
        fi

        if [ $? -ne 0 ]; then
            logAndEchoError "mount /mnt/dbdata/remote/metadata_${storage_metadata_fs} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            exit 1
        else
            logAndEchoInfo "mount /mnt/dbdata/remote/metadata_${storage_metadata_fs} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        fi
    fi
    # 防止日志输出到/var/log/messages中

    if [[ x"${deploy_mode}" != x"dbstore_unify" ]]; then
        mountpoint /mnt/dbdata/remote/share_${storage_share_fs} > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            logAndEchoInfo "/mnt/dbdata/remote/share_${storage_share_fs} is not not a mountpoint, begin to mount. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            share_logic_ip=`python3 ${CURRENT_PATH}/../../action/get_config_info.py "share_logic_ip"`
            check_port
            sysctl fs.nfs.nfs_callback_tcpport="${NFS_PORT}" > /dev/null 2>&1
            if [ $? -ne 0 ];then
                logAndEchoError "Sysctl service is not ready.[Line:${LINENO}, File:${SCRIPT_NAME}]"
                exit 1
            fi
            if [[ x"${deploy_mode}" != x"nas" ]]; then
                mount -t nfs -o vers=4.0,sec="${kerberos_type}",timeo=${NFS_TIMEO},nosuid,nodev ${share_logic_ip}:/${storage_share_fs} /mnt/dbdata/remote/share_${storage_share_fs}
            else
                mount -t nfs -o vers=4.0,timeo=${NFS_TIMEO},nosuid,nodev ${share_logic_ip}:/${storage_share_fs} /mnt/dbdata/remote/share_${storage_share_fs}
            fi

            if [ $? -ne 0 ]; then
                logAndEchoError "mount /mnt/dbdata/remote/share_${storage_share_fs} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
                exit 1
            else
                logAndEchoInfo "mount /mnt/dbdata/remote/share_${storage_share_fs} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            fi
        fi
    fi

    if [[ x"${deploy_mode}" == x"nas" ]]; then
        storage_dbstore_fs=`python3 ${CURRENT_PATH}/../../action/get_config_info.py "storage_dbstore_fs"`
        storage_logic_ip=`python3 ${CURRENT_PATH}/../../action/get_config_info.py "storage_logic_ip"`
        mountpoint /mnt/dbdata/remote/storage_"${storage_dbstore_fs}" > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            mount -t nfs -o timeo=${NFS_TIMEO},nosuid,nodev "${storage_logic_ip}":/"${storage_dbstore_fs}" /mnt/dbdata/remote/storage_"${storage_dbstore_fs}"
        fi

        if [ $? -ne 0 ]; then
            logAndEchoError "mount /mnt/dbdata/remote/storage_"${storage_dbstore_fs} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            exit 1
        else
            logAndEchoInfo "mount /mnt/dbdata/remote/storage_"${storage_dbstore_fs} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        fi
    fi
}

function getDaemonPid()
{
    local daemonPid=`ps -ef | grep -v grep | grep "sh /opt/cantian/common/script/cantian_daemon.sh" | awk '{print $2}'`
    echo ${daemonPid}
}


LOOP_TIME=5  # 循环间隔 5s
MAL_LOOP_COUNT=3

function startDaemon()
{
    mountNfs
    local cantianPid=$(getDaemonPid)
    if [ -z "${cantianPid}" ];then
        logAndEchoInfo "[cantian service] cantian_daemon is not found, begin to start cantian_daemon. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        nohup sh /opt/cantian/common/script/cantian_daemon.sh > /dev/null 2>&1 &
        logAndEchoInfo "[cantian service] start cantian_daemon result: $?. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        sleep ${LOOP_TIME}
        cantianPid=$(getDaemonPid)
        logAndEchoInfo "[cantian service] cantian_daemon pid is : ${cantianPid}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        if [ -n "${cantianPid}" ]; then
            logAndEchoInfo "[cantian service] start cantian_daemon success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        else
            logAndEchoError "[cantian service] start cantian_daemon failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            return 1
        fi
    fi

    return 0
}

function killDeamon() {
    local cantianPid=$(getDaemonPid)
    if [ -n "${cantianPid}" ];then
        logAndEchoInfo "[cantian service] cantian_daemon pid ${cantianPid}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        kill -9 ${cantianPid}
        logAndEchoInfo "[cantian service] stop cantian_daemon result: $?. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    fi
}

function stopDaemon()
{
    for (( i = 0; i < 10; i++ )); do
        killDeamon
        sleep ${LOOP_TIME}
        local cantianPid=$(getDaemonPid)
        if [ -z "${cantianPid}" ];then
            break
        fi
    done

    cantianPid=$(getDaemonPid)
    logAndEchoInfo "[cantian service] cantian_daemon pid is : ${cantianPid}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    if [ -z "${cantianPid}" ]; then
        logAndEchoInfo "[cantian service] stop cantian_daemon success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    else
        logAndEchoInfo "[cantian service] stop cantian_daemon failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    return 0
}

ACTION=$1
case "$ACTION" in
    start)
        startDaemon
        startResult=$?
        if [ ${startResult} -ne 0 ]; then
            logAndEchoError "start failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        else
            logAndEchoInfo "start success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        fi
        exit ${startResult}
        ;;
    stop)
        stopDaemon
        stopResult=$?
        if [ ${stopResult} -ne 0 ]; then
            logAndEchoError "stop failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        else
            logAndEchoInfo "stop success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        fi
        exit ${stopResult}
        ;;
esac
