#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
CT_OM_PATH=/opt/cantian/action/ct_om
CT_OM_LOG_PATH=/opt/cantian/ct_om/log
CT_OM_CTMGR=/opt/cantian/ct_om/service/ctmgr
ACTION_TYPE=$1

source ${CURRENT_PATH}/ct_om_log.sh

LOG_MOD=740
CT_OM_DIR_MOD=700
CT_OM_FILE_MOD=400
CTMGR_USER_FILE_LIST=('check_status.sh' 'start.sh' 'stop.sh')

# 修改/opt/cantian/ct_om/log/日志文件属性
if [ -d ${CT_OM_LOG_PATH} ]; then
    chmod -Rf ${LOG_MOD} ${CT_OM_LOG_PATH}
    if [ $? -eq 0 ]; then
        logAndEchoInfo "change mod of ${CT_OM_LOG_PATH} success"
    else
        logAndEchoError "change mod of ${CT_OM_LOG_PATH} failed"
        exit 1
    fi
fi

# 修改/opt/cantian/ct_om/log/日志文件归属
if [ -d ${CT_OM_LOG_PATH} ]; then
    chmod 640 ${CT_OM_LOG_PATH}/om_deploy.log
    if [ $? -eq 0 ]; then
        logAndEchoInfo "change mod of ${CT_OM_LOG_PATH}/om_deploy.log success"
    else
        logAndEchoError "change mod of ${CT_OM_LOG_PATH}/om_deploy.log failed"
        exit 1
    fi

    chown -hR ctmgruser:ctmgruser ${CT_OM_LOG_PATH}
    if [ $? -eq 0 ]; then
        logAndEchoInfo "change owner of ${CT_OM_LOG_PATH} success"
    else
        logAndEchoError "change owner of ${CT_OM_LOG_PATH} failed"
        exit 1
    fi
fi

# 原子操作，仅将应为低权限属主的脚本改为低权限
for ctmgr_file in "${CTMGR_USER_FILE_LIST[@]}"; do
    chown -h ctmgruser:ctmgruser "${CURRENT_PATH}/${ctmgr_file}"
    if [ $? -eq 0 ]; then
        logAndEchoInfo "change owner of ${ctmgr_file} to ctmgruser success"
    else
        logAndEchoError "change owner of ${ctmgr_file} to ctmgruser failed"
        exit 1
    fi
done

# 仅安装部署和离线升级场景需要执行下方的拷贝操作
if [[ ${ACTION_TYPE} != "rollback" ]];then
    # 把ct_om代码拷贝到opt/cantian/action路径下
    cp -rpf ${CURRENT_PATH} /opt/cantian/action
    if [ $? -eq 0 ]; then
        logAndEchoInfo "copy ct_om path to /opt/cantian/action success"
    else
        logAndEchoError "copy ct_om path to /opt/cantian/action failed"
        exit 1
    fi
fi
