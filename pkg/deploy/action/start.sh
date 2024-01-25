#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
LIMITS_CONFIG_PATH="/etc/security/limits.conf"
open_file_num=102400
node_count=$(python3 ${CURRENT_PATH}/get_config_info.py "cluster_scale")
source ${CURRENT_PATH}/env.sh
source ${CURRENT_PATH}/log4sh.sh

function initLimitsConfig() {
    nr_open=`cat /proc/sys/fs/nr_open`
    if [ ${open_file_num} -gt ${nr_open} ]; then
        logAndEchoError "the num of openfile can not greater than nr_open, please check and reset it."
        exit 1
    fi
    sed -i '/hard nofile/d' ${LIMITS_CONFIG_PATH}
    sed -i '/soft nofile/d' ${LIMITS_CONFIG_PATH}
    if [ -s ${LIMITS_CONFIG_PATH} ]; then
        sed -i '$a\'${cantian_user}' hard nofile '${open_file_num}'' ${LIMITS_CONFIG_PATH}
    else
        echo "${cantian_user} hard nofile ${open_file_num}" >> ${LIMITS_CONFIG_PATH}
    fi
    sed -i '$a\'${cantian_user}' soft nofile '${open_file_num}'' ${LIMITS_CONFIG_PATH}
}

function checkOpenFiles() {
    exit_hard_nofile=`cat ${LIMITS_CONFIG_PATH} | grep "hard nofile ${open_file_num}"`
    exit_soft_nofile=`cat ${LIMITS_CONFIG_PATH} | grep "soft nofile ${open_file_num}"`
    if [[ ${exit_hard_nofile} = '' ]] || [[ ${exit_soft_nofile} = '' ]]; then
        logAndEchoError "failed to set openfile, please check file ${LIMITS_CONFIG_PATH}"
        exit 1
    fi
}

function systemd_timer_setter() {
    local timer_name=$1
    systemctl start ${timer_name} >> ${OM_DEPLOY_LOG_FILE} 2>&1
    if [ $? -eq 0 ];then
        logAndEchoInfo "start ${timer_name} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        systemctl status ${timer_name} >> ${OM_DEPLOY_LOG_FILE} 2>&1
    else
        logAndEchoError "start ${timer_name} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        logAndEchoError "For details, see the ${OM_DEPLOY_LOG_FILE}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    systemctl enable ${timer_name} >> ${OM_DEPLOY_LOG_FILE} 2>&1
    if [ $? -eq 0 ];then
        logAndEchoInfo "enable ${timer_name} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        systemctl is-enabled ${timer_name} >> ${OM_DEPLOY_LOG_FILE} 2>&1
    else
        logAndEchoError "enable ${timer_name} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        logAndEchoError "For details, see the ${OM_DEPLOY_LOG_FILE}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    return 0
}

# 自动配置openfile
deploy_user=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_user")
deploy_group=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_group")


if [ ! -f  ${LIMITS_CONFIG_PATH} ]; then
    logAndEchoInfo "the file ${LIMITS_CONFIG_PATH} not exist, creating it now."
    touch ${LIMITS_CONFIG_PATH}
fi
initLimitsConfig
checkOpenFiles

logAndEchoInfo "Begin to start. [Line:${LINENO}, File:${SCRIPT_NAME}]"
for lib_name in "${START_ORDER[@]}"
do
    logAndEchoInfo "start ${lib_name} . [Line:${LINENO}, File:${SCRIPT_NAME}]"
    sh ${CURRENT_PATH}/${lib_name}/appctl.sh start >> ${OM_DEPLOY_LOG_FILE} 2>&1
    if [ $? -ne 0 ]; then
        logAndEchoError "start ${lib_name} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        logAndEchoError "For details, see the /opt/cantian/${lib_name}/log. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        exit 1
    fi
    logAndEchoInfo "start ${lib_name} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
done

logicrep_pid=$(ps -ef | grep "/opt/software/tools/logicrep/watchdog_logicrep.sh -n logicrep -N" | grep -v grep | awk '{print $2}')
if [[ -f /opt/software/tools/logicrep/start.success ]] && [[ -z ${logicrep_pid} ]];then
    su -s /bin/bash - "${cantian_user}" -c "nohup sh /opt/software/tools/logicrep/watchdog_logicrep.sh -n logicrep -N ${node_count} &" >> /opt/cantian/deploy/deploy.log 2>&1
fi

# 全部启动成功后，拉起守护进程 自动拉起cms和ct_om
su -s /bin/bash "${cantian_user}" -c "sh /opt/cantian/action/cms/cms_reg.sh enable"
sh /opt/cantian/common/script/cantian_service.sh start
if [ $? -eq 0 ];then
    logAndEchoInfo "start cantian_service success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
else
    logAndEchoError "startcantian_service failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    logAndEchoError "For details, see the ${OM_DEPLOY_LOG_FILE}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    exit 1
fi
# 守护进程拉起后启动system服务 开机启动后拉起守护进程
systemctl daemon-reload >> ${OM_DEPLOY_LOG_FILE} 2>&1

sys_service_batch=(cantian.timer cantian_logs_handler.timer)
for service in "${sys_service_batch[@]}"
do
    systemd_timer_setter ${service}
    if [ $? -ne 0 ];then
        exit 1
    fi
done

chmod 660 /dev/shm/cantian*
chown -hR "${cantian_user}":"${deploy_group}" /dev/shm/cantian*

exit 0