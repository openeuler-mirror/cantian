#!/bin/bash
set +x

CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
ROLLBACK_MODLE=$1
DORADO_IP=$2
ROLLBACK_VERSION=$3
DEPLOY_PARAM_PATH='/opt/cantian/config/deploy_params.json'
CMS_CHECK_FILE=${CURRENT_PATH}/fetch_cls_stat.py
CHECK_POINT_FILE=${CURRENT_PATH}/cantian/upgrade_checkpoint.sh
CHECK_POINT_FLAG=/opt/cantian/check_point.success
CLEAR_MEM_FILE=/opt/cantian/dbstor/tools/cs_clear_mem.sh
BACKUP_NOTE=/opt/backup_note
BACKUP_TARGET_PATH=/opt/cantian
TAG_FILES=(${CHECK_POINT_FLAG})
dorado_user=""
dorado_pwd=""
back_version=""
zsql_pwd=""
node_id=""

source ${CURRENT_PATH}/log4sh.sh
source ${CURRENT_PATH}/env.sh


deploy_user=$(python3 "${CURRENT_PATH}"/get_config_info.py "deploy_user")
deploy_mode=$(python3 "${CURRENT_PATH}"/get_config_info.py "deploy_mode")

# 获取用户输入的阵列侧用户名ip等
function get_user_input() {
    read -p "please enter dorado_user: " dorado_user
    echo "dorado_user is: ${dorado_user}"

    read -s -p "please enter dorado_pwd: " dorado_pwd
    echo ''
}

# 检查参天是否停止
function stopping_check() {
    source ${CURRENT_PATH}/running_status_check.sh
    if [ ${#online_list[*]} -ne 0 ]; then
        logAndEchoError "process ${online_list[@]} is still online, please execute stop first"
        exit 1
    fi
}

# 获取当前节点
function get_current_node() {
    node_id=$(python3 ${CURRENT_PATH}/get_config_info.py "node_id")
    if [[ ${node} == 'None' ]]; then
        echo "obtain current node id error, please check file: config/deploy_param.json"
        exit 1
    fi
}

# 获取回滚版本
function get_rollback_version() {
  if [[ ${ROLLBACK_VERSION} != '' ]]; then
      back_version=${ROLLBACK_VERSION}
  else
      back_version_detail=$(cat ${BACKUP_NOTE} | awk 'END {print}')
      fullback_version=($(echo ${back_version_detail} | tr ':' ' '))
      back_version=${fullback_version[0]}
  fi
  if [[ ${back_version} == '' ]]; then
      logAndEchoError "obtain rollback version failed, please check file: ${BACKUP_NOTE} or name a rollback version"
      exit 1
  fi
  logAndEchoInfo "rollback version is ${back_version}"
}

# 检查是否存在版本备份
function rollback_check() {
    local backup_path="/opt/cantian/upgrade_backup/cantian_upgrade_bak_${back_version}"
    if [ ! -f "${backup_path}/backup_success" ]; then
        logAndEchoError "version: ${back_version} backup file note complete, rollback failed;"
        exit 1
    fi
}

# 停止参天，离线升级不停止，滚动升级预留
function stop_cantian() {
    logAndEchoInfo "begin to stop cantian"
    sh ${CURRENT_PATH}/stop.sh
    if [ $? -ne 0 ]; then
        logAndEchoError "stop cantian failed"
        exit 1
    fi

    logAndEchoInfo "stop cantian success"
}

# 升级回退
function do_rollback() {
    logAndEchoInfo "begin to rollback on local node"
    local backup_path="/opt/cantian/upgrade_backup/cantian_upgrade_bak_${back_version}"

    for rollback_module in "${ROLLBACK_ORDER[@]}";
    do
        logAndEchoInfo "begin to rollback ${rollback_module}"
        sh "${CURRENT_PATH}/${rollback_module}/appctl.sh" rollback ${ROLLBACK_MODLE} ${backup_path}
        if [ $? -ne 0 ]; then
            logAndEchoError "rollback ${rollback_module} failed"
            logAndEchoError "For details, see the /opt/cantian/${rollback_module}/log. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            exit 1
        fi
        logAndEchoInfo "rollback ${rollback_module} success"
    done

    # 回滚完快照再执行拷贝操作，避免回滚快照使用的是旧脚本
    if [[ ${node_id} == '0' && ! -f ${CHECK_POINT_FLAG} ]]; then
        clear_mem
        rollback_snapshot
    fi

    cp -rfp "${backup_path}/action" ${BACKUP_TARGET_PATH}
    cp -rfp "${backup_path}/common" ${BACKUP_TARGET_PATH}
    cp -rfp "${backup_path}/config" ${BACKUP_TARGET_PATH}
    cp -rfp "${backup_path}/repo" ${BACKUP_TARGET_PATH}
    cp -fp "${backup_path}/versions.yml" ${BACKUP_TARGET_PATH}
    # 回滚前删除掉遗留系统定时任务
    rm -rf /etc/systemd/system/cantian*.service
    rm -rf /etc/systemd/system/cantian*.timer
    # 拷贝备份目录下的系统定时任务
    cp -f ${backup_path}/config/cantian*.service /etc/systemd/system/
    cp -f ${backup_path}/config/cantian*.timer /etc/systemd/system/
    logAndEchoInfo "om rollback finished"
}

# 快照回退
function rollback_snapshot() {
    local backup_path="/opt/cantian/upgrade_backup/cantian_upgrade_bak_${back_version}"
    logAndEchoInfo "begin to rollback snapshot"
    get_user_input
    echo -e "${dorado_user}\n${dorado_pwd}" | python3 ${CURRENT_PATH}/do_snapshot.py rollback ${DORADO_IP} ${backup_path}
    if [ $? -ne 0 ]; then
        logAndEchoError "rollback snapshot failed"
        exit 1
    fi

    logAndEchoInfo "rollback snapshot success"
}

# 调用dbstor的脚本在回滚快照前，清除内存占用
function clear_mem() {
    if [[ x"${deploy_mode}" == x"--nas" ]];then
        return
    fi
    if [[ ! -f ${CLEAR_MEM_FILE} ]];then
        logAndEchoError "file ${CLEAR_MEM_FILE} missing"
        exit 1
    fi

    try_times=3

    while [ ${try_times} -gt 0 ]
    do
        try_times=$(expr "${try_times}" - 1)
        su -s /bin/bash - ${deploy_user} -c "sh ${CLEAR_MEM_FILE}"
        if [ $? -eq 0 ]; then
            logAndEchoInfo "clear mem before rolling back snapshots success"
            return 0
        else
            logAndEchoError "calling ${CLEAR_MEM_FILE} to clear mem failed, remaining attempts: ${try_times}"
        fi
    done

    if [ ${try_times} -eq 0 ]; then
        exit 1
    fi
}

# 启动参天
function start_cantian() {
    logAndEchoInfo "begin to start cantian"
    sh "${CURRENT_PATH}/start.sh"
    if [ $? -ne 0 ]; then
        logAndEchoError "start cantian after upgrade failed"
        stop_cantian
        exit 1
    fi

    logAndEchoInfo "start cantian after upgrade success"
}

# 启动参天后触发一次全量ckpt
function upgrade_checkpoint() {
    su -s /bin/bash -c "${user}" "echo ${zsql_pwd} | sh ${CHECK_POINT_FILE} ${node_ip}"
    if [ $? -ne 0 ];then
        logAndEchoError "Execute cantian check point failed."
        exit 1
    fi
}

function clear_tag_file() {
    for _file in "${TAG_FILES[@]}";
    do
        if [ -f "${_file}" ];then
            rm -rf "${_file}"
        fi
    done
    logAndEchoInfo "clear tag file success"
}

# 回退后检查
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
    for check_module in "${POST_UPGRADE_ORDER[@]}";
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

# 预留，如果用户需要保留数据需要回退修改系统表
function rollback_sys_tables() {
    logAndEchoInfo "rollback modify sys tables start"
    return 0
}

function modify_env() {
    if [[ x"${deploy_mode}" == x"--nas" ]];then
        python3 "${CURRENT_PATH}"/modify_env.py
        if [ $? -ne 0 ];then
            echo "Current deploy mode is ${deploy_mode}, modify env.sh failed."
        fi
    fi
}

function main() {
    get_current_node
    stopping_check
    modify_env
    if [[ ${node_id} == '0' && -f ${CHECK_POINT_FLAG} ]]; then
        rollback_sys_tables
    fi
    get_rollback_version
    rollback_check
    do_rollback
    start_cantian
    check_local_nodes
    clear_tag_file
}

main