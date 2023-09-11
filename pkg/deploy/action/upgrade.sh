#!/bin/bash
set +x

CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
UPGRADE_MODLE=$1
DORADO_IP=$2
FILE_MOD_FILE=${CURRENT_PATH}/file_mod.sh
CMS_CHECK_FILE=${CURRENT_PATH}/fetch_cls_stat.py
SOURCE_ACTION_PATH=/opt/cantian/action
VERSION_FILE=/opt/cantian/versions.yml
CONFIG_PATH=/opt/cantian/config
UPGRADE_SUCCESS_FLAG=/opt/cantian/pre_upgrade.success
UPGRADE_MODLE_LIS=("offline")
dorado_user=""
dorado_pwd=""
node_id=""
upgrade_module_correct=false

source ${CURRENT_PATH}/env.sh
source ${CURRENT_PATH}/log4sh.sh
source ${FILE_MOD_FILE}

# 检查UPGRADE_MODLE
for upgrade_select in "${UPGRADE_MODLE_LIS[@]}"; do
    if [[ ${UPGRADE_MODLE} == ${upgrade_select} ]]; then
        upgrade_module_correct=true
    fi
done

if [[ ${upgrade_module_correct} == false ]]; then
    echo "[error] input upgrade module is wrong"
    exit 1
fi

# 检查ip
if [ -z "${DORADO_IP}" ]; then
    echo "[error] ip is required"
    exit 1
fi

ping -c 1 ${DORADO_IP} > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "[error] try to ping ${DORADO_IP} failed"
fi

deploy_user=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_user")
deploy_group=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_group")
deploy_mode=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_mode")

if [[ x"${deploy_mode}" == x"--nas" ]];then
    python3 "${CURRENT_PATH}"/modify_env.py
    if [  $? -ne 0 ];then
        echo "Current deploy mode is ${deploy_mode}, modify env.sh failed."
    fi
fi

# 获取用户输入的阵列侧用户名ip等
function get_user_input() {
    read -p "please enter dorado_user: " dorado_user
    echo "dbstor_user is: ${dbstor_user}"

    read -s -p "please enter dorado_pwd: " dorado_pwd
    echo ''
}

# 获取当前节点
function get_current_node() {
    node_id=$(python3 ${CURRENT_PATH}/get_config_info.py "node_id")
    if [[ ${node} == 'None' ]]; then
        echo "obtain current node id error, please check file: config/deploy_param.json"
        exit 1
    fi
}

#  停止参天, 离线升级不使用，滚动升级预留
function stop_cantian() {
    logAndEchoInfo "begin to stop cantian"
    sh "${SOURCE_ACTION_PATH}/stop.sh"
    if [ $? -ne 0 ]; then
        logAndEchoError "stop cantian failed"
        exit 1
    fi

    logAndEchoInfo "stop cantian success"
}

#  检查参天是否停止
function cantian_status_check() {
    logAndEchoInfo "begin to check cantian status"
    # 检查ct_om状态
    su - ctmgruser -s /bin/bash -c "sh /opt/cantian/action/ct_om/check_status.sh"
    if [ $? -eq 0 ]; then
        logAndEchoError "ct_om is online, cantian status check failed"
        exit 1
    fi
    logAndEchoInfo "ct_om pass the check"

    # 检查cantian_exporter状态
    su - ${deploy_user} -s /bin/bash -c "sh /opt/cantian/action/cantian_exporter/check_status.sh"
    if [ $? -eq 0 ]; then
        logAndEchoError "cantian_exporter is online, cantian status check failed"
        exit 1
    fi
    logAndEchoInfo "cantian_exporter pass the check"

    # 检查cantiand状态
    cantiand_pid=$(pidof cantiand)
    if [ -n "${cantiand_pid}" ]; then
        logAndEchoError "cantiand is online, cantian status check failed"
        exit 1
    fi
    logAndEchoInfo "cantiand pass the check"

    # 检查cms状态
    cms_pid=$(ps -ef | grep cms | grep server | grep start | grep -v grep | awk 'NR==1 {print $2}')
    if [ -n "${cms_pid}" ]; then
        logAndEchoError "cms is online, cantian status check failed"
        exit 1
    fi
    logAndEchoInfo "cms pass the check"

    # 检查守护进程状态
    daemon_pid=$(ps -ef | grep -v grep | grep 'sh /opt/cantian/common/script/cantian_daemon.sh' | awk '{print $2}')
    if [ -n "${daemon_pid}" ]; then
        logAndEchoError "cantian_deamon is online, cantian status check failed"
        exit 1
    fi
    logAndEchoInfo "cantian_deamon pass the check"

    logAndEchoInfo "pass to check cantian status"
}

#  打快照
function creat_snapshot() {
    logAndEchoInfo "begin to create snapshot"
    get_user_input
    echo -e "${dorado_user}\n${dorado_pwd}" | python3 ${CURRENT_PATH}/do_snapshot.py create ${DORADO_IP} ${dircetory_path}
    if [ $? -ne 0 ]; then
        logAndEchoError "create snapshot failed"
        exit 1
    fi

    logAndEchoInfo "create snapshot success"
}

#  备份老版本程序和配置
function do_backup() {
    logAndEchoInfo "begin to backup resource"
    source "${CURRENT_PATH}/upgrade_backup.sh"
    if [ $? -ne 0 ]; then
        return 0  # upgrade_backup 已经执行成功，跳过下面步骤
    fi

    for upgrade_module in "${UPGRADE_ORDER[@]}";
    do
        logAndEchoInfo "begin to backup ${upgrade_module}"
        sh "${CURRENT_PATH}/${upgrade_module}/appctl.sh" upgrade_backup ${dircetory_path}
        if [ $? -ne 0 ]; then
            logAndEchoError "${upgrade_module} upgrade_backup failed"
            logAndEchoError "For details, see the /opt/cantian/${upgrade_module}/log. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            exit 1
        fi

        logAndEchoInfo "${upgrade_module} upgrade_backup success"
    done

    touch ${dircetory_path}/backup_success && chmod 400 ${dircetory_path}/backup_success
    if [ $? -ne 0 ]; then
        logAndEchoError "backup resource failed"
        exit 1
    fi
    logAndEchoInfo "backup resource success"
}

#  升级
function do_upgrade() {
    logAndEchoInfo "begin to upgrade"
    # 升级前删除掉遗留系统文件
    rm -rf /etc/systemd/system/cantian*.service
    rm -rf /etc/systemd/system/cantian*.timer
    # 更新系统定时任务文件
    cp -f ${CURRENT_PATH}/../config/*.service /etc/systemd/system/
    cp -f ${CURRENT_PATH}/../config/*.timer /etc/systemd/system/

    cp -fp ${CURRENT_PATH}/* /opt/cantian/action > /dev/null 2>&1
    cp -rfp ${CURRENT_PATH}/inspection /opt/cantian/action
    cp -rfp ${CURRENT_PATH}/../config /opt/cantian/
    cp -rfp ${CURRENT_PATH}/../common /opt/cantian/
    cp -rf ${CURRENT_PATH}/../repo /opt/cantian/
    logAndEchoInfo "om upgrade finished"

    for upgrade_module in "${UPGRADE_ORDER[@]}";
    do
        logAndEchoInfo "begin to upgrade ${upgrade_module}"
        sh "${CURRENT_PATH}/${upgrade_module}/appctl.sh" upgrade ${UPGRADE_MODLE} ${dircetory_path}
        if [ $? -ne 0 ]; then
            logAndEchoError "${upgrade_module} upgrade failed"
            logAndEchoError "For details, see the /opt/cantian/${upgrade_module}/log. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            exit 1
        fi
        logAndEchoInfo "${upgrade_module} upgrade success"
    done
}

#  修改公共文件mod
function correct_files_mod() {
    logAndEchoInfo "begin to correct files mod"
    for file_path in ${!FILE_R_MODE_MAP[@]}; do
        if [ ! -f ${file_path} ]; then
            continue
        fi

        chmod -R ${FILE_R_MODE_MAP[$file_path]} $file_path
        if [ $? -ne 0 ]; then
            logAndEchoError "chmod -R ${FILE_R_MODE_MAP[$file_path]} ${file_path} failed"
            exit 1
        fi
    done

    for file_path in ${!FILE_MODE_MAP[@]}; do
        if [ ! -f ${file_path} ]; then
            continue
        fi

        chmod ${FILE_MODE_MAP[$file_path]} $file_path
        if [ $? -ne 0 ]; then
            logAndEchoError "chmod ${FILE_MODE_MAP[$file_path]} ${file_path} failed"
            exit 1
        fi
    done
    # 其他模块使用升级后需要修改权限
    chown -hR "${deploy_user}":"${deploy_group}" "${CURRENT_PATH}"/obtains_lsid.py
    chown -hR "${deploy_user}":"${deploy_group}" "${CURRENT_PATH}"/inspection
    logAndEchoInfo "correct file mod success"
}

#  启动参天
function start_cantian() {
    logAndEchoInfo "begin to start cantian"
    sh "${SOURCE_ACTION_PATH}/start.sh"
    if [ $? -ne 0 ]; then
        logAndEchoError "start cantian after upgrade failed"
        stop_cantian
        exit 1
    fi

    logAndEchoInfo "start cantian after upgrade success"
}

#  升级后检查
function check_local_nodes() {
    logAndEchoInfo "begin to post upgrade check on local node"
    logAndEchoInfo "begin to check cms stat on local node"
    cms_result=$(python3 ${CMS_CHECK_FILE})
    cms_stat=${cms_result: 0-2: 1}
    if [[ ${cms_stat} != '0' ]]; then
        logAndEchoError "local node failed cms stat check"
        exit 1
    fi

    logAndEchoInfo "local node pass cms stat check"

    # 调用各模块post_upgrade
    for check_module in ${POST_UPGRADE_ORDER[@]};
    do
        logAndEchoInfo "begin post upgrade check for ${check_module}"
        sh "${CURRENT_PATH}/${check_module}/appctl.sh" post_upgrade
        if [ $? -ne 0 ]; then
            logAndEchoError "${check_module} post upgrade check failed"
            logAndEchoError "For details, see the /opt/cantian/${check_module}/log. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            exit 1
        fi

        logAndEchoInfo "${check_module} post upgrade check success"
    done
    logAndEchoInfo "local node post upgrade check finished"
}

# 预留，如果用户需要保留数据需要修改系统表
function modify_sys_tables() {
    logAndEchoInfo "modify sys tables start"
    return 0
}

function main() {
    get_current_node
    cantian_status_check
    do_backup
    if [[ ${node_id} == '0' ]]; then
        creat_snapshot
    fi
    correct_files_mod
    do_upgrade
    if [[ ${node_id} == '0' ]]; then
        modify_sys_tables
    fi
    # 升级后需要把配置文件放到/opt/cantian/config下
    cp -fp ${dircetory_path}/config/deploy_param.json ${CONFIG_PATH}
    cp -fp ${dircetory_path}/action/config_params.json ${SOURCE_ACTION_PATH}
    start_cantian
    check_local_nodes
    # 升级成功后更新版本信息
    cp -fp ${CURRENT_PATH}/../versions.yml /opt/cantian
    # 升级成功后删除升级检查成功标志文件
    if [ -f ${UPGRADE_SUCCESS_FLAG} ]; then
        rm -f ${UPGRADE_SUCCESS_FLAG}
    fi

}

main