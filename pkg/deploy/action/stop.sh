#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)

function stop_systemd_timer() {
    local timer_name=$1
    systemctl stop ${timer_name} >> ${OM_DEPLOY_LOG_FILE} 2>&1
    if [ $? -eq 0 ]; then
        logAndEchoInfo "stop ${timer_name} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    else
        logAndEchoError "stop ${timer_name} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    systemctl status ${timer_name} >> ${OM_DEPLOY_LOG_FILE} 2>&1
    systemctl disable ${timer_name} >> ${OM_DEPLOY_LOG_FILE} 2>&1
    if [ $? -eq 0 ]; then
        logAndEchoInfo "disable ${timer_name} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    else
        logAndEchoError "disable ${timer_name} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi
    systemctl is-enabled ${timer_name} >> ${OM_DEPLOY_LOG_FILE} 2>&1

    return 0
}

if [ ! -d /opt/cantian/image ]; then
    echo "Cantian id not install, stop success."
    exit 0
fi
source ${CURRENT_PATH}/env.sh
source ${CURRENT_PATH}/log4sh.sh

# step1 停systemd
logAndEchoInfo "Begin to stop cantian.timer. [Line:${LINENO}, File:${SCRIPT_NAME}]"
systemctl daemon-reload >> ${OM_DEPLOY_LOG_FILE} 2>&1

sys_service_batch=(cantian.timer cantian_logs_handler.timer)
for service in "${sys_service_batch[@]}"
do
    stop_systemd_timer ${service}
    if [ $? -ne 0 ];then
        exit 1
    fi
done

sleep 10

logAndEchoInfo "begin to stop cantian_service.sh. [Line:${LINENO}, File:${SCRIPT_NAME}]"
startPid=`ps -ef | grep -v grep | grep "sh /opt/cantian/common/script/cantian_service.sh start" | awk '{print $2}'`
logAndEchoInfo "cantian_service.sh pid is ${startPid}. [Line:${LINENO}, File:${SCRIPT_NAME}]"

if [ -n "${startPid}" ]; then
    logAndEchoInfo "cantian_service.sh ${startPid} is online, begin to kill ${startPid}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    kill -9 ${startPid}
    if [ $? -eq 0 ];then
        logAndEchoInfo "stop cantian_service success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    else
        logAndEchoError "stop cantian_service failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        exit 1
    fi
fi

# step2 停止守护进程
logAndEchoInfo "begin to stop cantian_daemon. [Line:${LINENO}, File:${SCRIPT_NAME}]"
if [ -f /opt/cantian/common/script/cantian_service.sh ]; then
    sh /opt/cantian/common/script/cantian_service.sh stop
    if [ $? -eq 0 ]; then
        logAndEchoInfo "stop cantian_daemon success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    else
        logAndEchoError "stop cantian_daemon failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        exit 1
    fi
fi

# step3 检查守护进程拉起的cms_start2.sh -check进程是否存在，存在就删除。
proc_pid_list=$(ps -ef | grep 'cms_start2.sh -start' | grep -v grep | awk '{print $2}')
if [ x"$proc_pid_list" != x"" ];then
    logAndEchoInfo "cms_start2.sh -start process need stop"
    echo "$proc_pid_list" | xargs kill -9
fi

# step4 停止各个模块进程
logAndEchoInfo "Begin to stop. [Line:${LINENO}, File:${SCRIPT_NAME}]"
for lib_name in "${STOP_ORDER[@]}"
do
    logAndEchoInfo "stop ${lib_name} . [Line:${LINENO}, File:${SCRIPT_NAME}]"
    sh ${CURRENT_PATH}/${lib_name}/appctl.sh stop >> ${OM_DEPLOY_LOG_FILE} 2>&1
    if [ $? -ne 0 ]; then
        logAndEchoError "stop ${lib_name} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        logAndEchoError "For details, see the /opt/cantian/${lib_name}/log. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        exit 1
    fi
    logAndEchoInfo "stop ${lib_name} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
done

# 10s 后检查，避免进程kill未生效
sleep 10s

# step5 停止各个模块进程是否停止
logAndEchoInfo "check cantian status. [Line:${LINENO}, File:${SCRIPT_NAME}]"
source ${CURRENT_PATH}/running_status_check.sh
if [ ${#online_list[*]} -ne 0 ]; then
    logAndEchoError "process ${online_list[@]} is still online, please execute stop first"
    exit 1
fi
