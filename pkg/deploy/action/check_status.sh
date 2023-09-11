#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
source ${CURRENT_PATH}/env.sh
source ${CURRENT_PATH}/log4sh.sh


allOnlineFlag=0
allOfflineFlag=0

logAndEchoInfo "-------Begin to check process and systemd------- [Line:${LINENO}, File:${SCRIPT_NAME}]"
for lib_name in "${START_ORDER[@]}"
do
    sh ${CURRENT_PATH}/${lib_name}/appctl.sh check_status >> ${OM_DEPLOY_LOG_FILE} 2>&1
    if [ $? -eq 0 ]; then
        logAndEchoInfo "${lib_name} is online. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        allOfflineFlag=1
    else
        logAndEchoInfo "${lib_name} is offline. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        allOnlineFlag=1
    fi
done

# 检查守护进程
logAndEchoInfo "-------Begin to check cantian_daemon------- [Line:${LINENO}, File:${SCRIPT_NAME}]"
daemonPid=`ps -ef | grep -v grep | grep "sh /opt/cantian/common/script/cantian_daemon.sh" | awk '{print $2}'`
if [ -n "${daemonPid}" ];then
    logAndEchoInfo "cantian_daemon is online, pid is ${daemonPid}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    allOfflineFlag=1
else
    logAndEchoInfo "cantian_daemon is offline, pid is ${daemonPid}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    allOnlineFlag=1
fi

logAndEchoInfo "-------Begin to check cantian.timer------- [Line:${LINENO}, File:${SCRIPT_NAME}]"
systemctl daemon-reload >> ${OM_DEPLOY_LOG_FILE} 2>&1
systemctl status cantian.timer >> ${OM_DEPLOY_LOG_FILE} 2>&1

systemctl is-active cantian.timer >> ${OM_DEPLOY_LOG_FILE} 2>&1
if [ $? -eq 0 ];then
    logAndEchoInfo "cantian.timer is active. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    allOfflineFlag=1
else
    logAndEchoInfo "cantian.timer is inactive. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    allOnlineFlag=1
fi

systemctl is-enabled cantian.timer >> ${OM_DEPLOY_LOG_FILE} 2>&1
if [ $? -eq 0 ];then
    logAndEchoInfo "cantian.timer is enabled. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    allOfflineFlag=1
else
    logAndEchoInfo "cantian.timer is disabled. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    allOnlineFlag=1
fi

logAndEchoInfo "-------Begin to check cantian_logs_handler.timer------- [Line:${LINENO}, File:${SCRIPT_NAME}]"
systemctl status cantian_logs_handler.timer >> ${OM_DEPLOY_LOG_FILE} 2>&1

systemctl is-active cantian_logs_handler.timer >> ${OM_DEPLOY_LOG_FILE} 2>&1
if [ $? -eq 0 ];then
    logAndEchoInfo "cantian_logs_handler.timer is active. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    allOfflineFlag=1
else
    logAndEchoInfo "cantian_logs_handler.timer is inactive. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    allOnlineFlag=1
fi

systemctl is-enabled cantian_logs_handler.timer >> ${OM_DEPLOY_LOG_FILE} 2>&1
if [ $? -eq 0 ];then
    logAndEchoInfo "cantian_logs_handler.timer is enabled. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    allOfflineFlag=1
else
    logAndEchoInfo "cantian_logs_handler.timer is disabled. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    allOnlineFlag=1
fi

logAndEchoInfo "-------allOnlineFlag is ${allOnlineFlag}, allOfflineFlag is ${allOfflineFlag}------- [Line:${LINENO}, File:${SCRIPT_NAME}]"

if [ ${allOnlineFlag} -eq 0 ]; then
    logAndEchoInfo "process and systemd is all online. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    exit 0
fi

if [ ${allOfflineFlag} -eq 0 ]; then
    logAndEchoInfo "process and systemd is all offline. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    exit 1
fi

logAndEchoInfo "process and systemd is partial online. [Line:${LINENO}, File:${SCRIPT_NAME}]"

exit 2