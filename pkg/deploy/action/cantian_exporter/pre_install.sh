#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
CANTIAN_EXPORTER_PATH=/opt/cantian/action/cantian_exporter
CANTIAN_EXPORTER_LOG_PATH=/opt/cantian/cantian_exporter/log
CANTIAN_EXPORTER_LOG_FILE=/opt/cantian/cantian_exporter/log/cantian_exporter.log
ACTION_TYPE=$1

source ${CURRENT_PATH}/../log4sh.sh
source ${CURRENT_PATH}/../env.sh

LOG_MOD=740
CANTIAN_EXPORTER_DIR_MOD=755
CANTIAN_EXPORTER_FILE_MOD=400
CANTIANDBA_FILE_LIST=('cantian_exporter_log.sh' 'check_status.sh' 'start.sh' 'stop.sh')


# 原子操作，仅将应为低权限属主的脚本改为低权限
for cantiandba_file in "${CANTIANDBA_FILE_LIST[@]}"; do
    chown -h "${cantian_user}":"${cantian_group}" "${CURRENT_PATH}/${cantiandba_file}"
    if [ $? -eq 0 ]; then
        logAndEchoInfo "change owner of ${cantiandba_file} to cantian success"
    else
        logAndEchoError "change owner of ${cantiandba_file} to cantian failed"
        exit 1
    fi
done

chmod ${CANTIAN_EXPORTER_DIR_MOD} ${CURRENT_PATH}
chmod ${CANTIAN_EXPORTER_FILE_MOD} ${CURRENT_PATH}/*

# 仅安装部署和离线升级场景需要执行下方的拷贝操作
if [[ ${ACTION_TYPE} != "rollback" ]];then
    # 把cantian_exporter代码拷贝到opt/cantian/action路径下
    cp -rpf ${CURRENT_PATH} /opt/cantian/action
    if [ $? -eq 0 ]; then
        logAndEchoInfo "copy cantian_exporter path to /opt/cantian/action success"
    else
        logAndEchoError "copy cantian_exporter path to /opt/cantian/action failed"
        exit 1
    fi
fi

# 修改/opt/cantian/ct_om目录属组
if [ -d /opt/cantian/ct_om ];then
    chown -h "${cantian_user}":"${cantian_common_group}" /opt/cantian/ct_om
fi
if [ -d /opt/cantian/ct_om/service ];then
    chown -h "${cantian_user}":"${cantian_common_group}" /opt/cantian/ct_om/service
fi
if [ -d /opt/cantian/ct_om/service/cantian_exporter ];then
    chown -hR "${cantian_user}":"${cantian_common_group}" /opt/cantian/ct_om/service/cantian_exporter
fi

if [ ! -d ${CANTIAN_EXPORTER_LOG_PATH} ]; then
    mkdir -m 750 -p ${CANTIAN_EXPORTER_LOG_PATH}
    touch ${CANTIAN_EXPORTER_LOG_FILE}
fi

if [ -d /opt/cantian/deploy/logs ];then
    chmod 755 /opt/cantian/deploy/logs
fi

if [ -d /opt/cantian/cantian_exporter/log ]; then
    # 修改/opt/cantian/cantian_exporter/log日志文件属性
    chmod -Rf ${LOG_MOD} /opt/cantian/cantian_exporter/log
    if [ $? -eq 0 ]; then
        logAndEchoInfo "change mod of /opt/cantian/cantian_exporter/log success"
    else
        logAndEchoError "change mod of /opt/cantian/cantian_exporter/log failed"
        exit 1
    fi
    # 修改/opt/cantian/cantian_exporter/log/cantian_exporter.log日志文件权限
    chmod 640 /opt/cantian/cantian_exporter/log/cantian_exporter.log
    if [ $? -eq 0 ]; then
        logAndEchoInfo "change mod of /opt/cantian/cantian_exporter/log/cantian_exporter.log success"
    else
        logAndEchoError "change mod of /opt/cantian/cantian_exporter/log/cantian_exporter.log failed"
        exit 1
    fi
    # 修改/opt/cantian/cantian_exporter 文件归属
    chown -hR "${cantian_user}":"${cantian_group}" /opt/cantian/cantian_exporter
    if [ $? -eq 0 ]; then
        logAndEchoInfo "change owner of /opt/cantian/cantian_exporter success"
    else
        logAndEchoError "change owner of /opt/cantian/cantian_exporter failed"
        exit 1
    fi
fi

if [ -d /opt/cantian/ct_om/log ]; then
    chmod -Rf 640 /opt/cantian/ct_om/log
    if [ $? -eq 0 ]; then
        logAndEchoInfo "recursively change mod of /opt/cantian/ct_om/log"
    else
        logAndEchoError "recursively change mod of /opt/cantian/ct_om/log"
        exit 1
    fi

    chmod -f 750 /opt/cantian/ct_om/log
    if [ $? -eq 0 ]; then
        logAndEchoInfo "change mod of /opt/cantian/ct_om/log"
    else
        logAndEchoError "change mod of /opt/cantian/ct_om/log"
        exit 1
    fi
    chown -hR "${cantian_user}":"${cantian_group}" /opt/cantian/ct_om/log
    if [ $? -eq 0 ]; then
        logAndEchoInfo "change owner of /opt/cantian/ct_om/log"
    else
        logAndEchoError "change owner of /opt/cantian/ct_om/log"
        exit 1
    fi
fi
