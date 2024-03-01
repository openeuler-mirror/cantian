#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
UPGRADE_MODE=$1
CONFIG_FILE_PATH=$2
CONFIG_PATH=${CURRENT_PATH}/../config
CMS_CHECK_FILE=/opt/cantian/action/fetch_cls_stat.py
DBSTORE_CHECK_FILE=/opt/cantian/dbstor/tools/cs_check_version.sh
CANTIAN_PATH=/opt/cantian
MEM_REQUIRED=5  # 单位G
SIZE_UPPER=1024
UPGRADE_MODE_LIS=("offline" "rollup")
UPDATESYS_FLAG=/opt/cantian/updatesys.true
upgrade_module_correct=false


source ${CURRENT_PATH}/log4sh.sh
source ${CURRENT_PATH}/env.sh

# 输入参数预处理，适配离线升级
function input_params_check() {
    # 不传入任何参数，默认使用离线升级
    if [ -z "${UPGRADE_MODE}" ] && [ -z "${CONFIG_FILE_PATH}" ]; then
        CONFIG_FILE_PATH=""
        UPGRADE_MODE="offline"
    fi

    # 传入的第一个参数是config.json的路径，适配离线升级输入
    if [ -n "${UPGRADE_MODE}" ] && [ -f "${UPGRADE_MODE}" ]; then
        CONFIG_FILE_PATH="${UPGRADE_MODE}"
        UPGRADE_MODE="offline"
    fi

    # 检查升级模式
    if [[ " ${UPGRADE_MODE_LIS[*]} " == *" ${UPGRADE_MODE} "* ]]; then
        logAndEchoInfo "pass upgrade mode check, current upgrade mode: ${UPGRADE_MODE}"
    else
        logAndEchoError "input upgrade module must be one of '${UPGRADE_MODE_LIS[@]}', instead of '${UPGRADE_MODE}'"
        exit 1
    fi

}

# 修改用户用户组
function initUserAndGroup()
{
    useradd ${cantian_user} -s /sbin/nologin -G cantiangroup -u 6000 > /dev/null 2>&1
    usermod -a -G cantiangroup ctmgruser
    usermod -a -G ${deploy_group} ${cantian_user}
}

function update_share_config() {
    if [[ -f /mnt/dbdata/remote/share_"${storage_share_fs}"/deploy_param.json ]] && [[ ! -f /mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/deploy_param.json ]]; then
        cp -arf /mnt/dbdata/remote/share_"${storage_share_fs}"/deploy_param.json /mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/
    elif [[ ! -f /mnt/dbdata/remote/share_"${storage_share_fs}"/deploy_param.json ]] && [[ ! -f /mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/deploy_param.json ]]; then
      cp -arf ${CONFIG_PATH}/deploy_param.json /mnt/dbdata/remote/metadata_"${storage_metadata_fs}"
      chown ${cantian_user}:${cantian_group} /mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/deploy_param.json
    fi
}

function prepare_env() {
    logAndEchoInfo "prepare upgrade env."
    if [ -f ${CONFIG_FILE_PATH} ] && [ -n "${CONFIG_FILE_PATH}" ]; then
        python3 ${CURRENT_PATH}/pre_upgrade.py ${CONFIG_FILE_PATH}
        if [ $? -ne 0 ]; then
            logAndEchoError "config check failed, please check /opt/cantian/ct_om/log/om_deploy.log for detail"
            exit 1
        else
            mv -f ${CURRENT_PATH}/deploy_param.json ${CONFIG_PATH}
        fi
    else
        python3 ${CURRENT_PATH}/pre_upgrade.py
        if [ $? -ne 0 ]; then
            logAndEchoError "new config_params.json different with source config_params.json"
            exit 1
        else
            cp -rf /opt/cantian/config/deploy_param.json ${CONFIG_PATH}
            if [ $? -ne 0 ]; then
                logAndEchoError "prepare upgrade env failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
                exit 1
            fi
        fi
    fi
    deploy_user=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_user"`
    deploy_group=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_group"`
    storage_share_fs=$(python3 ${CURRENT_PATH}/get_config_info.py "storage_share_fs")
    storage_metadata_fs=$(python3 ${CURRENT_PATH}/get_config_info.py "storage_metadata_fs")
    node_id=$(python3 ${CURRENT_PATH}/get_config_info.py "node_id")
    random_seed=$(python3 ${CURRENT_PATH}/get_config_info.py "share_random_seed")
    if [[ x"${random_seed}" == x"None" ]] || [[ x"${random_seed}" == x"" ]]; then
        random_seed=$(python3 -c 'import secrets; secrets_generator = secrets.SystemRandom(); print(secrets_generator.randint(0, 255))')
    fi
    python3 ${CURRENT_PATH}/write_config.py "random_seed" "${random_seed}"
    if [[ ${node_id} == '0' ]]; then
        update_share_config
    fi
}

# 检查集群状态
function check_cms_stat() {
    logAndEchoInfo "begin to check cms stat"
    cms_result=$(python3 ${CMS_CHECK_FILE})
    cms_stat=${cms_result: 0-2: 1}
    if [[ ${cms_stat} != '0' ]]; then
        logAndEchoError "failed cms stat check. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        exit 1
    fi

    logAndEchoInfo "pass cms stat check"
}

# 检查磁盘空间
function check_mem_avail() {
    logAndEchoInfo "begin to check memory available"
    let mem_limited=MEM_REQUIRED*${SIZE_UPPER}*${SIZE_UPPER}
    mem_info=($(df ${CANTIAN_PATH}))
    mem_avail=${mem_info[10]}
    if [ $((mem_avail)) -lt ${mem_limited} ]; then
        logAndEchoError "failed memory check. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        exit 1
    fi

    logAndEchoInfo "pass memory check"
}

# 检查升级白名单
function check_upgrade_version() {
    logAndEchoInfo "begin to check upgrade version"
    white_list_check_res=$(python3 ${CURRENT_PATH}/implement/upgrade_version_check.py ${CURRENT_PATH}/white_list.txt ${UPGRADE_MODE})
    logAndEchoInfo "source_version, upgrade_mode, change_system are: ${white_list_check_res}"
    if [ -z "${white_list_check_res}" ]; then
        logAndEchoError "failed to white list check, please check upgrade white list."
        exit 1
    fi

    logAndEchoInfo "pass white list check"
}

# 调用各模块升级前检查脚本
function call_each_pre_upgrade() {
    for module_name in "${PRE_UPGRADE_ORDER[@]}";
    do
        logAndEchoInfo "begin to execute ${module_name} pre_upgrade"
        sh ${CURRENT_PATH}/${module_name}/appctl.sh pre_upgrade
        if [ $? -ne 0 ]; then
            logAndEchoError "call ${module_name} pre_upgrade failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            logAndEchoError "For details, see the /opt/cantian/${module_name}/log. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            exit 1
        fi
        logAndEchoInfo "${module_name} pre_upgrade success"
    done
}

# 软件包内层校验
function package_check() {
    logAndEchoInfo "begin to package internal verification"
    logAndEchoInfo "pass package internal verification"
    return 0
}

# 当前节点健康度检查
function local_node_health_check() {
    logAndEchoInfo "begin to check current node health status"
    # 操作系统检查
    if [ -z $(echo $(uname -s) | grep -v grep | grep -E "(Linux|Unix)") ]; then
        logAndEchoError "operating system check failed, current operating system is not linux/unix"
        exit 1
    fi
    logAndEchoInfo "pass operating system check"

    # 磁盘负载检查 （预留此接口）
    logAndEchoInfo "pass disk-io check"

    # 目录空闲空间大小检查
    check_mem_avail

    logAndEchoInfo "pass current node health status check"
    return 0
}

# 数据库状态检查
function cantian_database_health_status_check() {
    logAndEchoInfo "begin to check cantian database health status"
    # 检查集群在线情况
    check_cms_stat

    # 检查集群是否处于扩/缩容状态，间隔检查三次
    try_times=3
    while [ ${try_times} -gt 0 ]
    do
        try_times=$(expr "${try_times}" - 1)
        # 获取扩缩容状态
        cmd_res=$(su -s /bin/bash - "${cantian_user}" -c "cms stat")
        work_stat_array=()
        readarray -t work_stat_array <<< "$(echo "${cmd_res}" | awk '{print $6}' | tail -n +$'2')"
        # work_stat_array数组去重
        unique_elements=($(printf "%s\n" "${work_stat_array[@]}" | uniq))
        if [ ${#unique_elements[@]} -eq 1 ] && [ "${unique_elements[0]}" == "1" ]; then
            logAndEchoInfo "current cluster does not belong to the expansion and contraction state, check pass, remaining attempts: ${try_times}"
            sleep 10
        else
            logAndEchoError "current cluster may belong to the expansion and contraction state, work_stat of cluster: ${work_stat_array[@]}"
            exit 1
        fi
    done

    logAndEchoInfo "pass cantian database health status check"
    return 0
}

# 参天各组件最低版本检查，当前预留此接口
function component_version_dependency_check() {
    logAndEchoInfo "begin to check component version dependency"
    logAndEchoInfo "pass component version dependency check"
    return 0
}

# 输出升级计划
function gen_upgrade_plan() {
    logAndEchoInfo "begin to generate an upgrade plan"
    # 白名单校验
    white_list_check_res=$(python3 ${CURRENT_PATH}/implement/upgrade_version_check.py ${CURRENT_PATH}/white_list.txt ${UPGRADE_MODE})
    if [ -z "${white_list_check_res}" ]; then
        logAndEchoInfo "source_version, upgrade_mode, change_system should be specific info, instead of '${white_list_check_res}'"
        logAndEchoError "failed to white list check"
        exit 1
    fi

    # 升级计划输出
    logAndEchoInfo "recommended upgrade mode is $(echo ${white_list_check_res} | awk '{print $2}')"

    # 生成更新系统表标志文件
    weather_change_system=$(echo ${white_list_check_res} | awk '{print $3}')
    if [ "${weather_change_system}" == "true" ]; then
        source_version=$(python3 ${CURRENT_PATH}/implement/get_source_version.py)
        storage_metadata_fs_path="/mnt/dbdata/remote/metadata_${storage_metadata_fs}/upgrade/${UPGRADE_MODE}_bak_${source_version}"
        # 提前创建避免报错
        if [ ! -d "${storage_metadata_fs_path}" ]; then
            mkdir -p -m 755 "${storage_metadata_fs_path}"
        fi
        UPDATESYS_FLAG="${storage_metadata_fs_path}/updatesys.true"
        # 避免多次创建更新系统表标记文件
        if [ -f "${UPDATESYS_FLAG}" ] || [ -f "${storage_metadata_fs_path}/updatesys.success" ]; then
            logAndEchoInfo "detected that the system tables file flag already exists"
            return 0
        fi
        touch ${UPDATESYS_FLAG} && chmod 400 ${UPDATESYS_FLAG}
        logAndEchoInfo "detected need to update system tables, success to create updatesys_flag: '${UPDATESYS_FLAG}'"
    fi
    return 0
}

function check_dbstore_client_compatibility() {
    deploy_mode=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_mode")
    if [[ x"${deploy_mode}" == x"nas" || "${source_version}" == "2.0.0"* ]]; then
        return 0
    fi
    logAndEchoInfo "begin to check dbstore client compatibility."
    if [ ! -f "${DBSTORE_CHECK_FILE}" ];then
        logAndEchoError "${DBSTORE_CHECK_FILE} file is not exists."
        exit 1
    fi
    su -s /bin/bash - "${cantian_user}" -c "sh ${DBSTORE_CHECK_FILE}"
    if [[ $? -ne 0 ]];then
        logAndEchoError "dbstore client compatibility check failed."
        exit 1
    fi
    logAndEchoInfo "dbstore client compatibility check success."
}

function check_file_system_exist() {
    source_version=$(python3 "${CURRENT_PATH}"/implement/get_source_version.py)
    if [[ "$source_version" == "2.0.0"* && x"${node_id}" == x"0" ]];then
      read -p "please input DM login ip:" dm_login_ip
      if [[ x"${dm_login_ip}" == x"" ]];then
          logAndEchoError "Enter a correct IP address, not None"
          exit 1
      fi
      echo "DM login ip is:${dm_login_ip}"
      read -p "please enter dorado_user: " dm_login_user
      if [[ x"${dm_login_user}" == x"" ]];then
          logAndEchoError "Enter a correct user, not None"
          exit 1
      fi
      echo "dbstor_user is: ${dm_login_user}"
      read -s -p "please input DM login passwd:" dm_login_pwd
      if [[ x"${dm_login_pwd}" == x"" ]];then
          logAndEchoError "Enter a correct passwd, not None."
          exit 1
      fi
      echo ""
      echo -e "${dm_login_ip}\n${dm_login_user}\n${dm_login_pwd}\n" | python3 "${CURRENT_PATH}"/storage_operate/split_dbstore_fs.py "pre_upgrade" "${CURRENT_PATH}"/../config/deploy_param.json
      if [ $? -ne 0 ];then
          logAndEchoError "Check dbstore page file system failed, /opt/cantian/deploy/om_deploy"
          exit 1
      fi
      echo -e "${dm_login_ip}\n${dm_login_user}\n${dm_login_pwd}\n" | python3 "${CURRENT_PATH}"/storage_operate/migrate_file_system.py "pre_upgrade" "${CURRENT_PATH}"/../config/deploy_param.json "/opt/cantian/config/deploy_param.json"
      if [ $? -ne 0 ];then
          logAndEchoError "Check share file system failed, details see /opt/cantian/deploy/om_deploy/"
          exit 1
      fi
    fi
}

function offline_upgrade() {
    initUserAndGroup
    check_file_system_exist
    check_cms_stat
    check_mem_avail
    check_upgrade_version
    check_dbstore_client_compatibility
    call_each_pre_upgrade
    gen_upgrade_plan
}

function rollup_upgrade() {
    package_check
    check_upgrade_version
    local_node_health_check
    cantian_database_health_status_check
    component_version_dependency_check
    check_dbstore_client_compatibility
    call_each_pre_upgrade
    gen_upgrade_plan
}

function version_check() {
    local target_version=$(cat ${CURRENT_PATH}/../versions.yml | grep -oP 'Version: \K\S+')
    local old_version=$(cat /opt/cantian/versions.yml | grep -oP 'Version: \K\S+')
    if [[ x"${target_version}" == x"${old_version}" ]];then
        logAndEchoError "The target version is the same as the current version. No upgrade is required."
        exit 1
    fi
}

function main() {
    logAndEchoInfo "begin to pre_upgrade"
    version_check
    input_params_check
    prepare_env
    if [ ${UPGRADE_MODE} == "offline" ]; then
        offline_upgrade
    elif [ ${UPGRADE_MODE} == "rollup" ]; then
        rollup_upgrade
    fi

    return 0
}

main