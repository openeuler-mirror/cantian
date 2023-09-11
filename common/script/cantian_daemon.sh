#!/bin/bash

# 检查cms进程和cantian_exportor进程是否在位

set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
CMS_ENABLE_FLAG=/opt/cantian/cms/cfg/cms_enable
DEPLOY_USER=`python3 ${CURRENT_PATH}/../../action/get_config_info.py "deploy_user"`
MYSQL_IN_CONTAINER=`python3 ${CURRENT_PATH}/../../action/get_config_info.py "mysql_in_container"`
CMS_CGROUP=/sys/fs/cgroup/memory/cms
CANTIAND_CGROUP=/sys/fs/cgroup/memory/cantiand
CTMGR_CGROUP=/sys/fs/cgroup/memory/ctmgr
CANTIAN_EXPORTER_CGROUP=/sys/fs/cgroup/memory/cantian_exporter
CANTIAND_CGROUP_CALCULATE=${CURRENT_PATH}/../../action/cantian/cantiand_cgroup_calculate.sh
KUBE_CGROUP=/sys/fs/cgroup/cpu/kubepods.slice

source ${CURRENT_PATH}/log4sh.sh
source ${CANTIAND_CGROUP_CALCULATE}

cantiand_cgroup_config
declare -A CGROUP_SIZE_MAP=(['cms']=10 ['cantian_exporter']=2 ['ctmgr']=2 ['cantiand']=${DEFAULT_MEM_SIZE})

function create_cgroup() {
    local cgroup_path=$1

    if [ -d "${cgroup_path}" ]; then
        rmdir "${cgroup_path}"
    fi
    mkdir -p "${cgroup_path}"
    local cgroup_model_path_lis=($(echo ${cgroup_path} | tr '/' ' '))
    local cgroup_memory=${CGROUP_SIZE_MAP[${cgroup_model_path_lis[-1]}]}
    sh -c "echo ${cgroup_memory}G > ${cgroup_path}/memory.limit_in_bytes"
    if [ $? -eq 0 ]; then
        logAndEchoInfo "limited ${cgroup_model_path_lis[-1]} memory ${cgroup_memory} to ${cgroup_path}/memory.limit_in_bytes success"
    else
        logAndEchoError "limited ${cgroup_model_path_lis[-1]} memory ${cgroup_memory} to ${cgroup_path}/memory.limit_in_bytes failed"
    fi
}

function cgroup_add_pid() {
    procs_pid=$1
    cgroup=$2

    if [[ -n ${procs_pid} && -n ${cgroup} ]]; then
        cat ${cgroup}/tasks | grep ${procs_pid} > /dev/null 2>&1
        if [ $? -ne 0 ]; then  # 如果cgroup不存在或者cgroup中tasks中没有进程 进入判断
            create_cgroup ${cgroup}
            sh -c "echo ${procs_pid} > ${cgroup}/tasks"
            if [ $? -ne 0 ]; then
                logAndEchoError "add pid[${procs_pid}] to cgroup: ${cgroup} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            else
                logAndEchoInfo "add pid[${procs_pid}] to cgroup: ${cgroup} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            fi
        fi
    fi
}

function add_cpu_cgroup() {
    procs_pid=$1
    cgroup=$2
     if [[ -n ${procs_pid} && -n ${cgroup} ]]; then
        cat ${cgroup}/cgroup.procs | grep ${procs_pid} > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            sh -c "echo ${procs_pid} > ${cgroup}/cgroup.procs"
            if [ $? -ne 0 ]; then
                logAndEchoError "add pid to cgroup: ${cgroup} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            else
                logAndEchoInfo "add pid to cgroup: ${cgroup} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            fi
        fi
    fi

}

# 定时任务内存实时监控
function memory_monitoring() {
    procs_pid=$1
    mem_limit=$2
    if [[ -n ${procs_pid} && -n ${mem_limit} ]]; then
        mem_usage=$(cat /proc/${procs_pid}/status | awk '/VmRSS/{print $2}')
        procs_name=$(cat /proc/${procs_pid}/status | awk '/Name/{print $2}')
        mem_limit_k=$(expr "${mem_limit}" \* 1024 \* 1024)
        if [[ ${mem_usage} -gt ${mem_limit_k} ]];then
            kill -9 ${procs_pid}
            logAndEchoError "Process ${procs_name}[${procs_pid}] oom, current use ${mem_usage}K, memory limit ${mem_limit_k}K"
        fi
    fi
}

# 循环间隔 1s
LOOP_TIME=1
# cms后台重拉计数，最大10次，避免cms start卡死后，后台进程过多导致节点资源耗尽
CMS_COUNT=0
while :
do

    cantiand_pid=`pidof cantiand`
    memory_monitoring "${cantiand_pid}" "${CGROUP_SIZE_MAP['cantiand']}"
    cgroup_add_pid ${cantiand_pid} ${CANTIAND_CGROUP}
    cms_start_pid=`ps -ef | grep "sh /opt/cantian/action/cms/cms_start2.sh -start"| grep -v grep | awk 'NR==1 {print $2}'`
    cms_pid=`ps -ef | grep cms | grep server | grep start | grep -v grep | awk 'NR==1 {print $2}'`
    memory_monitoring "${cms_pid}" "${CGROUP_SIZE_MAP['cms']}"
    # cms 拉起过程中不加入cgroup
    if [[ -z ${cms_start_pid} && -n ${cms_pid} && -n ${cantiand_pid} ]];then
        cgroup_add_pid ${cms_pid} ${CMS_CGROUP}
    fi
    su -s /bin/bash ctmgruser -c "sh /opt/cantian/action/ct_om/check_status.sh"
    if [ $? -ne 0 ];then
        logAndEchoInfo "[cantian daemon] ct_om is check_status return 1, begin to start ct_om. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        sh /opt/cantian/action/ct_om/appctl.sh start
        logAndEchoInfo "[cantian daemon] start ct_om result: $?. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        sleep ${LOOP_TIME}
    fi
    # 创建ctmgr cgroup
    ctmgr_pid=$(ps -ef | grep "python3 /opt/cantian/ct_om/service/ctmgr/uds_server.py" | grep -v grep | awk '{print $2}')
    memory_monitoring "${ctmgr_pid}" "${CGROUP_SIZE_MAP['ctmgr']}"
    cgroup_add_pid ${ctmgr_pid} ${CTMGR_CGROUP}

    su -s /bin/bash ${DEPLOY_USER} -c "sh /opt/cantian/action/cantian_exporter/check_status.sh"
    if [ $? -ne 0 ];then
        logAndEchoInfo "[cantian daemon] cantian_exporter is check_status return 1, begin to start ct_om. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        sh /opt/cantian/action/cantian_exporter/appctl.sh start
        logAndEchoInfo "[cantian daemon] start cantian_exporter result: $?. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        sleep ${LOOP_TIME}
    fi
    # 创建cantian_exporter cgroup
    cantian_exporter_pid=$(ps -ef | grep "python3 /opt/cantian/ct_om/service/cantian_exporter/exporter/execute.py" | grep -v grep | awk '{print $2}')
    memory_monitoring "${cantian_exporter_pid}" "${CGROUP_SIZE_MAP['cantian_exporter']}"
    cgroup_add_pid ${cantian_exporter_pid} ${CANTIAN_EXPORTER_CGROUP}

    if [ ! -f ${CMS_ENABLE_FLAG} ]; then
        sleep ${LOOP_TIME}
        continue
    fi

    cms_process_info=$(ps -fu ${DEPLOY_USER} | grep "cms server -start" | grep -vE '(grep|defunct)')
    if [ -z ${cms_process_info} ]; then
      cms_process_count=0
    else
      cms_process_count=$(echo "${cms_process_info}" | wc -l)
    fi
    if [ ${cms_process_count} -ne 1 ]; then
        if [ ${CMS_COUNT} -le 9 ]; then
            logAndEchoInfo "[cantian daemon] the process count of cms is ${cms_process_count}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            if [[ -n ${cms_process_info} ]]; then
                logAndEchoInfo "[cantian daemon] cms process info: ${cms_process_info} [Line:${LINENO}, File:${SCRIPT_NAME}]"
            fi

            logAndEchoInfo "[cantian daemon] cms status is abnormal. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            CMS_COUNT=$(expr "${CMS_COUNT}" + 1)
            if [ ${cms_process_count} -eq 0 ]; then
                logAndEchoInfo "[cantian daemon] begin to close iptables. [Line:${LINENO}, File:${SCRIPT_NAME}]"
                iptables -D INPUT -p udp --sport 14587 -j ACCEPT
                iptables -D FORWARD -p udp --sport 14587 -j ACCEPT
                iptables -D OUTPUT -p udp --sport 14587 -j ACCEPT
                iptables -I INPUT -p udp --sport 14587 -j ACCEPT
                iptables -I FORWARD -p udp --sport 14587 -j ACCEPT
                iptables -I OUTPUT -p udp --sport 14587 -j ACCEPT
                logAndEchoInfo "[cantian daemon] begin to start cms use ${DEPLOY_USER}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
                su - ${DEPLOY_USER} -c "sh /opt/cantian/action/cms/cms_start2.sh -start" >> /opt/cantian/cms/log/CmsStatus.log 2>&1 &
                logAndEchoInfo "[cantian daemon] starting cms in backstage ${CMS_COUNT} times. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            fi

        fi
        sleep ${LOOP_TIME}
    else
        CMS_COUNT=0
    fi
    
    if [[ "${MYSQL_IN_CONTAINER}" == "1" && -d ${KUBE_CGROUP} ]]; then
        add_cpu_cgroup ${cantiand_pid} ${KUBE_CGROUP}
    fi
    
    sleep ${LOOP_TIME}
done

