#!/bin/bash
set +x

CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
ROLLBACK_MODE=$1
DORADO_IP=$2
ROLLBACK_VERSION=$3
DEPLOY_PARAM_PATH='/opt/cantian/config/deploy_params.json'
CMS_CHECK_FILE='/opt/cantian/action/fetch_cls_stat.py'
CHECK_POINT_FILE=${CURRENT_PATH}/cantian/upgrade_checkpoint.sh
CHECK_POINT_FLAG=/opt/cantian/check_point.success
CLEAR_MEM_FILE=/opt/cantian/dbstor/tools/cs_clear_mem.sh
MYSQL_MOUNT_PATH=/opt/cantian/image/cantian_connector/for_mysql_official/mf_connector_mount_dir
UPGRADE_SUCCESS_FLAG=/opt/cantian/pre_upgrade_${ROLLBACK_MODE}.success
BACKUP_NOTE=/opt/backup_note
BACKUP_TARGET_PATH=/opt/cantian
CANTIAN_STATUS=/opt/cantian/cantian/cfg/start_status.json
ROLLBACK_MODE_LIS=("offline" "rollup")
dorado_user=""
dorado_pwd=""
back_version=""
ctsql_pwd=""
node_id=""
cluster_status=""
choose=""
do_snapshot_choice=""
NFS_TIMEO=50
deploy_user=$(python3 "${CURRENT_PATH}"/get_config_info.py "deploy_user")
deploy_group=$(python3 "${CURRENT_PATH}"/get_config_info.py "deploy_group")
# 滚动回滚
CLUSTER_COMMIT_STATUS=("commit" "normal")
NODE_NOT_ROLLBACK_STATUS=("rollup" "rolldown")
storage_metadata_fs_path=""
cluster_and_node_status_path=""
cluster_status_flag=""
local_node_status_flag=""
local_node_status=""
storage_metadata_fs=$(python3 "${CURRENT_PATH}"/get_config_info.py "storage_metadata_fs")

source ${CURRENT_PATH}/log4sh.sh

deploy_user=$(python3 "${CURRENT_PATH}"/get_config_info.py "deploy_user")
deploy_mode=$(python3 "${CURRENT_PATH}"/get_config_info.py "deploy_mode")

# 获取共享目录名称
function get_mnt_dir_name() {
    storage_share_fs=$(python3 "${CURRENT_PATH}"/get_config_info.py "storage_share_fs")
    storage_archive_fs=$(python3 "${CURRENT_PATH}"/get_config_info.py "storage_archive_fs")
    storage_metadata_fs=$(python3 "${CURRENT_PATH}"/get_config_info.py "storage_metadata_fs")
}

# 输入参数校验
function input_params_check() {
    logAndEchoInfo ">>>>> begin to check input params <<<<<"
    # 升级模式校验
    if [[ " ${ROLLBACK_MODE_LIS[*]} " != *" ${ROLLBACK_MODE} "* ]]; then
        logAndEchoError "input rollback module must be one of '${ROLLBACK_MODE_LIS[@]}', instead of '${ROLLBACK_MODE}'"
        exit 1
    fi
    # 离线升级需要检查阵列侧ip
    if [ "${ROLLBACK_MODE}" == "offline" ]; then
        if [ -z "${DORADO_IP}" ]; then
            logAndEchoError "storage array ip must be provided"
            exit 1
        fi

        ping -c 1 ${DORADO_IP} > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            logAndEchoError "try to ping storage array ip '${DORADO_IP}', but failed"
            echo "Please check whether input is correct. If the network is disconnected, manually rollback snapshot according to the upgrade guide."
            read -p "Continue rollback please input yes, otherwise exit:" do_snapshot_choice
            echo ""
            if [[ x"${do_snapshot_choice}" != x"yes" ]];then
                exit 1
            fi
        fi
    fi
    logAndEchoInfo ">>>>> pass check input params <<<<<"
}

# 获取用户输入的阵列侧用户名ip等
function get_user_input() {
    read -p "please enter dorado_user: " dorado_user
    echo "dorado_user is: ${dorado_user}"

    read -s -p "please enter dorado_pwd: " dorado_pwd
    echo ''
}

# 防呆功能，在滚动升级或回滚时执行离线回滚会再次询问:滚动升级提交、提交成功，滚动升级修改系统表成功或者失败场景只支持离线回退
function mode_check(){
    local storage_metadata_fs_path="/mnt/dbdata/remote/metadata_${storage_metadata_fs}/upgrade/rollup_bak_${back_version}"
    local modify_sys_tables_success="${storage_metadata_fs_path}/updatesys.success"
    local modify_sys_tables_failed="${storage_metadata_fs_path}/updatesys.failed"
    local upgrade_path="/mnt/dbdata/remote/metadata_${storage_metadata_fs}/upgrade"
    local node_flag_path="/mnt/dbdata/remote/metadata_${storage_metadata_fs}/upgrade/rollup_bak_${back_version}/cluster_and_node_status"
    if ls "${node_flag_path}"/node*_status.txt >/dev/null 2>&1; then
        cluster_status=$(cat "${node_flag_path}"/cluster_status.txt)
        if [[ x"${cluster_status}" != x"commit" && ! -f ${modify_sys_tables_success} && ! -f ${modify_sys_tables_failed} ]];then
            logAndEchoError "Rolling upgrade is currently in progress, Offline rollback cannot be performed."
            exit 1
        fi
    fi
    local commit_flag_path="${upgrade_path}/cantian_rollup_upgrade_commit_${back_version}.success"
    if [[ -f "${commit_flag_path}" || x"${cluster_status}" == x"commit" || -f ${modify_sys_tables_success} || -f ${modify_sys_tables_failed} ]]; then
        logAndEchoInfo "A rolling upgrade is being performed or has been performed."
        logAndEchoInfo "Are you sure you want to perform the offline rollback?yes/no"
        read -p "please enter yes if you want to continue:" choose
        if [[ ${choose} != "yes" ]];then
            logAndEchoInfo "exit offline rollback"
            exit 1
        fi
    fi
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
  if [ ! -f ${BACKUP_NOTE} ];then
      logAndEchoError "The upgrade flag file ${BACKUP_NOTE} does not exist. Please Check whether an upgrade has been performed."
      exit 1
  fi
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
    sh /opt/cantian/action/stop.sh
    if [ $? -ne 0 ]; then
        logAndEchoError "stop cantian failed"
        exit 1
    fi

    logAndEchoInfo "stop cantian success"
}

# 切换成老版本的权限
function change_old_owner(){
    logAndEchoInfo "begin to correct files owner"
    chown -hR "${deploy_user}":"${deploy_group}" /opt/cantian/common/config
    chown -hR "${deploy_user}":"${deploy_group}" /opt/cantian/common/data
    chown -hR "${deploy_user}":"${deploy_group}" /mnt/dbdata/local/cantian
    chown -hR "${deploy_user}":"${deploy_group}" /opt/cantian/cantian/ /opt/cantian/cms/ /opt/cantian/ct_om/ /opt/cantian/dbstor/
    chown -hR "${deploy_user}":"${deploy_group}" /opt/cantian/deploy/logs/cantian_exporter/

    chown -hR ctmgruser:ctmgruser /opt/cantian/ct_om/log /opt/cantian/ct_om/service/
    chown -h "${deploy_user}":"${deploy_group}" /opt/cantian/ct_om/service/
    chown -hR "${deploy_user}":"${deploy_group}" /opt/cantian/ct_om/service/cantian_exporter

    chown -hR "${deploy_user}":"${deploy_group}" /mnt/dbdata/remote/share_${storage_share_fs} > /dev/null 2>&1
    chown -hR "${deploy_user}":"${deploy_group}" /mnt/dbdata/remote/archive_${storage_archive_fs} > /dev/null 2>&1
    chown "${deploy_user}":"${deploy_group}" /mnt/dbdata/remote/metadata_${storage_metadata_fs}
    node_id=$(python3 ${CURRENT_PATH}/get_config_info.py "node_id")
    chown ${deploy_user}:${deploy_group} /mnt/dbdata/remote/metadata_${storage_metadata_fs}/node${node_id}
    chown "${deploy_user}":"${deploy_group}" /opt/cantian/action/obtains_lsid.py
    chown "${deploy_user}":"${deploy_group}" "${CURRENT_PATH}"/implement/update_cantian_passwd.py > /dev/null 2>&1
    chown "${deploy_user}":"${deploy_group}" "${CURRENT_PATH}"/update_config.py > /dev/null 2>&1
}

# 配置环境变量
function export_user_env(){
    logAndEchoInfo "begin to export environment variable"
    cantian_profile="/home/${cantian_user}/.bashrc"
    deploy_user_profile="/home/${deploy_user}/.bashrc"
    grep "CMS_HOME" ${deploy_user_profile} > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        logAndEchoInfo "export environment variable success"
        return 0
    fi
    rm -f ${deploy_user_profile}
    cp -fP ${cantian_profile} ${deploy_user_profile}
    chown ${deploy_user}:${deploy_group} ${deploy_user_profile}
    if [ $? -ne 0 ]; then
        logAndEchoError "export environment variable failed"
        exit 1
    fi
    logAndEchoInfo "export environment variable success"

}

function change_user_group() {
    less /etc/group | grep "^cantiangroup:" > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        groupadd cantiangroup -g 1100
        if [ $? -ne 0 ]; then
            logAndEchoError "add group failed"
        fi
    fi

    less /etc/group | grep "^cantianmgrgroup:" > /dev/null 2>&1
    if [ $? -ne 0 ]; then
        groupadd cantianmgrgroup -g 1101
        if [ $? -ne 0 ]; then
            logAndEchoError "add group failed"
        fi
    fi

    usermod ctmgruser -G cantiangroup,cantianmgrgroup,${deploy_group}
}

# 如果存在信号量则删除，防止信号量权限异常
function check_sem_id() {
    ret=`lsipc -s -c | grep 0x20161227`
    if [ -n "$ret" ]; then
        arr=($ret)
        sem_id=${arr[1]}
        ipcrm -s $sem_id
    fi
}

function install_dbstore(){
    local arrch=$(uname -p)
    local dbstor_path="${CURRENT_PATH}"/../repo
    local dbstor_package_file=$(ls "${dbstor_path}"/DBStor_Client*_"${arrch}"*.tgz)
    if [ ! -f "${dbstor_package_file}" ];then
        logAndEchoError "${dbstor_package_file} is not exist."
        return 1
    fi

    dbstor_file_path=${CURRENT_PATH}/dbstor_file_path
    if [ -d "${dbstor_file_path}" ];then
        rm -rf "${dbstor_file_path}"
    fi
    mkdir -p "${dbstor_file_path}"
    tar -zxf "${dbstor_package_file}" -C "${dbstor_file_path}"

    local dbstor_test_file=$(ls "${dbstor_file_path}"/Dbstor_Client_Test*-"${arrch}"*-dbstor*.tgz)
    local dbstor_client_file=$(ls "${dbstor_file_path}"/dbstor_client*-"${arrch}"*-dbstor*.tgz)
    if [ ! -f "${dbstor_test_file}" ];then
        logAndEchoError "${dbstor_test_file} is not exist."
        return 1
    fi
    if [ ! -f "${dbstor_client_file}" ];then
        logAndEchoError "${dbstor_client_file} is not exist."
        return 1
    fi

    mkdir -p "${dbstor_file_path}"/client
    mkdir -p "${dbstor_file_path}"/client_test
    tar -zxf "${dbstor_test_file}" -C "${dbstor_file_path}"/client_test
    tar -zxf "${dbstor_client_file}" -C "${dbstor_file_path}"/client
    cp -arf "${dbstor_file_path}"/client/lib/* "${RPM_PACK_ORG_PATH}"/Cantian-RUN-CENTOS-64bit/add-ons/
    cp -arf "${dbstor_file_path}"/client_test "${RPM_PACK_ORG_PATH}"/Cantian-RUN-CENTOS-64bit
    rm -rf "${dbstor_file_path}"
    return 0
}

function install_rpm()
{
    RPM_PATH="${backup_path}/repo/cantian-*.rpm"
    RPM_UNPACK_PATH_FILE="/opt/cantian/image/cantian_connector/CantianKernel/Cantian-DATABASE-CENTOS-64bit"
    RPM_PACK_ORG_PATH="/opt/cantian/image"

    echo "RPM_PATH is : ${RPM_PATH}"
    if [ ! -f  "${backup_path}"/repo/cantian-*.rpm ]; then
        echo "cantian.rpm is not exist."
        exit 1
    fi

    rpm -ivh --replacepkgs ${RPM_PATH} --nodeps --force

    tar -zxf ${RPM_UNPACK_PATH_FILE}/Cantian-RUN-CENTOS-64bit.tar.gz -C ${RPM_PACK_ORG_PATH}
    if [ x"${deploy_mode}" != x"nas" ];then
        echo "start rollback rpm package"
        install_dbstore
        if [ $? -ne 0 ];then
            sh ${CURRENT_PATH}/uninstall.sh ${config_install_type}
            exit 1
        fi
    fi
    chmod -R 750 ${RPM_PACK_ORG_PATH}/Cantian-RUN-CENTOS-64bit
    chown ${deploy_user}:${deploy_group} -hR ${RPM_PACK_ORG_PATH}/Cantian-RUN-CENTOS-64bit
    chown root:root ${RPM_PACK_ORG_PATH}
}

function uninstall_rpm()
{
    RPM_PACK_ORG_PATH="/opt/cantian/image/Cantian-RUN-CENTOS-64bit"
    result=`rpm -qa cantian | wc -l`
    if [ ${result} -ne 0 ]; then
        rpm -ev cantian --nodeps
    fi

    if [ -d ${RPM_PACK_ORG_PATH} ]; then
        rm -rf ${RPM_PACK_ORG_PATH}
    fi
}

# 升级回退
function do_rollback() {
    logAndEchoInfo "begin to rollback on local node"
    backup_path="/opt/cantian/upgrade_backup/cantian_upgrade_bak_${back_version}"
    back_config_path="${backup_path}"/config/deploy_param.json
    deploy_mode_back=$(cat "${back_config_path}" | grep 'deploy_mode' | awk -F'"' '{print $4}')
    if [[ ${node_id} == '1' && ! -f ${CHECK_POINT_FLAG} && ${ROLLBACK_MODE} == "offline" && ${back_version} == "2.0.0"* ]]; then
        logAndEchoInfo "Mount share file system."
        kerberos_type=$(python3 "${CURRENT_PATH}"/get_config_info.py "kerberos_key")
        share_logic_ip=$(cat "${back_config_path}" | grep 'share_logic_ip' | awk -F'"' '{print $4}')
        storage_share_fs=$(python3 "${CURRENT_PATH}"/get_config_info.py "storage_share_fs")
        umount /mnt/dbdata/remote/share_"${storage_share_fs}"
        sleep 2
        mount -t nfs -o sec="${kerberos_type}",vers=4.0,timeo="${NFS_TIMEO}",nosuid,nodev "${share_logic_ip}":/"${storage_share_fs}" /mnt/dbdata/remote/share_"${storage_share_fs}"
    elif [[ x"${deploy_mode_back}" == x"dbstore" ]]; then
        kerberos_type=$(cat "${back_config_path}" | grep 'kerberos_key' | awk -F'"' '{print $4}')
        share_logic_ip=$(cat "${back_config_path}" | grep 'share_logic_ip' | awk -F'"' '{print $4}')
        storage_share_fs=$(cat "${back_config_path}" | grep 'storage_share_fs' | awk -F'"' '{print $4}')
        if [[ ! -d "/mnt/dbdata/remote/share_${storage_share_fs}" ]]; then
            mkdir -m 750 -p /mnt/dbdata/remote/share_${storage_share_fs}
            chown -hR "${cantian_user}":"${cantian_group}" /mnt/dbdata/remote/share_${storage_share_fs} > /dev/null 2>&1
        fi
        mount -t nfs -o sec="${kerberos_type}",vers=4.0,timeo="${NFS_TIMEO}",nosuid,nodev "${share_logic_ip}":/"${storage_share_fs}" /mnt/dbdata/remote/share_"${storage_share_fs}"
    fi

    uninstall_rpm
    install_rpm

    for rollback_module in "${ROLLBACK_ORDER[@]}";
    do
        logAndEchoInfo "begin to rollback ${rollback_module}"
        sh "${CURRENT_PATH}/${rollback_module}/appctl.sh" rollback ${ROLLBACK_MODE} ${backup_path}
        if [ $? -ne 0 ]; then
            logAndEchoError "rollback ${rollback_module} failed"
            logAndEchoError "For details, see the /opt/cantian/${rollback_module}/log. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            exit 1
        fi
        logAndEchoInfo "rollback ${rollback_module} success"
    done

    if [[ ${version_first_number} -eq 2 ]];then
        change_old_owner
        export_user_env
        change_user_group
        check_sem_id
    fi
    cp -rfp "${backup_path}/action" ${BACKUP_TARGET_PATH}
    cp -rfp "${backup_path}/common" ${BACKUP_TARGET_PATH}
    cp -rfp "${backup_path}/config" ${BACKUP_TARGET_PATH}
    rm -rf ${BACKUP_TARGET_PATH}/repo/*
    cp -rfp "${backup_path}/repo" ${BACKUP_TARGET_PATH}
    cp -fp "${backup_path}/versions.yml" ${BACKUP_TARGET_PATH}
    cp -rfp "${backup_path}/mysql_inspection/inspection" ${MYSQL_MOUNT_PATH}
    # 回滚前删除掉遗留系统定时任务
    rm -rf /etc/systemd/system/cantian*.service
    rm -rf /etc/systemd/system/cantian*.timer
    # 拷贝备份目录下的系统定时任务
    cp -f ${backup_path}/config/cantian*.service /etc/systemd/system/
    cp -f ${backup_path}/config/cantian*.timer /etc/systemd/system/
    # 回滚完快照再执行拷贝操作，避免回滚快照使用的是旧脚本

    if [[ ${node_id} == '0' && ! -f ${CHECK_POINT_FLAG} && ${ROLLBACK_MODE} == "offline" && x"${choose}" != x"yes" && ${deploy_mode} != "nas" ]]; then
        rollback_snapshot
        clear_mem
    fi
    logAndEchoInfo "om rollback finished"
}

# 快照回退
function rollback_snapshot() {
    if [[ x"${do_snapshot_choice}" == x"yes" ]];then
        logAndEchoInfo " The ip[${DORADO_IP}] address is unreachable, No snapshot is required."
        return 0
    fi
    local backup_path="/opt/cantian/upgrade_backup/cantian_upgrade_bak_${back_version}"
    logAndEchoInfo "begin to rollback snapshot"
    get_user_input
    echo -e "${dorado_user}\n${dorado_pwd}" | python3 ${CURRENT_PATH}/storage_operate/do_snapshot.py rollback ${DORADO_IP} ${backup_path}
    if [ $? -ne 0 ]; then
        logAndEchoError "rollback snapshot failed"
        exit 1
    fi
    logAndEchoInfo "rollback snapshot success"
    echo -e "${dorado_user}\n${dorado_pwd}" | python3 ${CURRENT_PATH}/storage_operate/do_snapshot.py delete ${DORADO_IP} ${backup_path}
    if [ $? -ne 0 ]; then
        logAndEchoError "delete snapshot failed"
        exit 1
    fi
    logAndEchoInfo "delete snapshot success"
}

# 调用dbstor的脚本在回滚快照后，清除内存占用
function clear_mem() {
    if [[ x"${deploy_mode}" == x"nas" ]];then
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
        su -s /bin/bash - ${user} -c "sh ${CLEAR_MEM_FILE}"
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
    logAndEchoInfo "clear mem before rolling back snapshots success"
}

# 启动参天
function start_cantian() {
    rm -rf /dev/shm/cantian* /dev/shm/FDSA* /dev/shm/cpuinfo_shm /dev/shm/cputimeinfo_shm /dev/shm/diag_server_usr_lock
    logAndEchoInfo "begin to start cantian"
    sh "/opt/cantian/action/start.sh"
    if [ $? -ne 0 ]; then
        logAndEchoError "start cantian after rollback failed"
        stop_cantian
        exit 1
    fi

    logAndEchoInfo "start cantian after rollback success"
}

######################################################################
# 滚动升级场景，通过cms拉起参天，避免其他节点正在进行reform，当前节点执行拉起失败
# 实现流程：
#        1、通过cms模块appctl.sh start 启动cms；
#        2、通过cms res -start db -node {node_id}拉起cantiand
######################################################################
function start_cantiand_by_cms() {
    logAndEchoInfo "begin to start cms"
    sh /opt/cantian/action/cms/appctl.sh start
    if [ $? -ne 0 ]; then
        logAndEchoError "start cms after upgrade failed"
        exit 1
    fi
    logAndEchoInfo "begin to start cantiand"
    for ((i=1; i<=10; i++));do
        su -s /bin/bash - "${cantian_user}" -c "source ~/.bashrc&&cms res -start db -node ${node_id}"
        if [ $? -ne 0 ]; then
            logAndEchoError "start cantiand by cms failed, remaining Attempts: ${i}/10"
            sleep 20
            continue
        else
            # 修改cantian配置文件，后续start不会执行
            su -s /bin/bash - "${cantian_user}" -c "sed -i 's/\"start_status\": \"default\"/\"start_status\": \"started\"/' ${CANTIAN_STATUS}"
            logAndEchoInfo "start cantiand by cms success"
            return
        fi
    done
    logAndEchoError "start cantiand by cms failed" && exit 1
}

# 启动参天后触发一次全量ckpt
function upgrade_checkpoint() {
    su -s /bin/bash - "${user}" -c "echo ${ctsql_pwd} | sh ${CHECK_POINT_FILE} ${node_ip}"
    if [ $? -ne 0 ];then
        logAndEchoError "Execute cantian check point failed."
        exit 1
    fi
}

function clear_tag_file() {
    local ctbackup_flag=/mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/upgrade/rollup_bak_"${back_version}"/call_ctback_tool.success
    local offline_commit_flag="/mnt/dbdata/remote/metadata_${storage_metadata_fs}/upgrade/cantian_offline_upgrade_commit_${source_version}.success"
    TAG_FILES=("${CHECK_POINT_FLAG}" "${ctbackup_flag}" "${offline_commit_flag}" "${UPGRADE_SUCCESS_FLAG}")
    for _file in "${TAG_FILES[@]}";
    do
        if [ -f "${_file}" ];then
            rm -rf "${_file}"
        fi
    done
    # 滚动升级场景进行离线回退，需要清理滚动升级相关文件
    if [[ x"${choose}" == x"yes" && x"${node_id}" != x"0" ]];then
        local commit_success=/mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/upgrade/cantian_rollup_upgrade_commit_${back_version}.success
        local upgrade_flag=/mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/upgrade/rollup_bak_"${back_version}"/cluster_and_node_status
        local modify_sys_tables_failed=/mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/upgrade/rollup_bak_"${back_version}"/updatesys.failed
        local modify_sys_tables_success=/mnt/dbdata/remote/metadata_"${storage_metadata_fs}"/upgrade/rollup_bak_"${back_version}"/updatesys.true
        if [ -d "${upgrade_flag}" ];then
            rm -rf ${upgrade_flag}
        fi
        if [ -f ${modify_sys_tables_failed} ];then
            rm -rf ${modify_sys_tables_failed}
        fi
        if [ -f ${modify_sys_tables_success} ];then
            rm -rf ${modify_sys_tables_success}
        fi
        if [ -f ${commit_success} ];then
            rm -rf ${commit_success}
        fi
    fi
    logAndEchoInfo "clear tag file success"
}

function remove_old_user(){
    if [[ ${version_first_number} -eq 2 ]] && id -u ${cantian_user} > /dev/null 2>&1; then
        userdel -rf ${cantian_user}
        if [ $? -eq 0 ]; then
            logAndEchoInfo "remove user cantian success"
        else
            logAndEchoError "remove user cantian failed"
            exit 1
        fi
    fi
}

# 回退后检查
function check_local_nodes() {
    logAndEchoInfo "begin to post rollback check on local node"
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
        logAndEchoInfo "begin post rollback check for ${check_module}"
        sh "/opt/cantian/action/${check_module}/appctl.sh" post_upgrade
        if [ $? -ne 0 ]; then
            logAndEchoError "${check_module} post rollback check failed"
            logAndEchoError "For details, see the /opt/cantian/${check_module}/log. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            exit 1
        fi

        logAndEchoInfo "${check_module} post rollback check success"
    done
    logAndEchoInfo "local node post rollback check finished"
}

# 预留，如果用户需要保留数据需要回退修改系统表
function rollback_sys_tables() {
    logAndEchoInfo "rollback modify sys tables start"
    return 0
}

# 滚动升级：更改集群/节点升级状态
function modify_cluster_or_node_status() {
    # 串入参数依次是：状态文件绝对路径、新的状态、集群或节点标志
    local cluster_or_node_status_file_path=$1
    local new_status=$2
    local cluster_or_node=$3
    local old_status=""

    if [ -n "${cluster_or_node_status_file_path}" ] && [ ! -e "${cluster_or_node_status_file_path}" ]; then
        logAndEchoInfo "rollback status of '${cluster_or_node}' does not exist."
    fi

    # 若新旧状态一致则不必更新
    if [ -e "${cluster_or_node_status_file_path}" ]; then
        old_status=$(cat ${cluster_or_node_status_file_path})
        if [ "${old_status}" == "${new_status}" ]; then
            logAndEchoInfo "the old status of ${cluster_or_node} is consistent with the new status, both are ${new_status}"
            return 0
        fi
    fi

    echo "${new_status}" > ${cluster_or_node_status_file_path}
    if [ $? -eq 0 ]; then
        logAndEchoInfo "change rollback status of ${cluster_or_node} from '${old_status}' to '${new_status}' success."
        return 0
    else
        logAndEchoInfo "change rollback status of ${cluster_or_node} from '${old_status}' to '${new_status}' failed."
        exit 1
    fi
}

# 滚动升级，升级准备步骤：初始化节点/集群状态标记文件名
function init_cluster_or_node_status_flag() {
    logAndEchoInfo ">>>>> begin to init cluster and node status flag <<<<<"
    source_version=${back_version}
    if [ -z "${source_version}" ]; then
        logAndEchoError "failed to obtain source version"
        exit 1
    fi

    if [[ ${storage_share_fs_name} == 'None' ]]; then
        logAndEchoError "obtain current node  storage_share_fs_name error, please check file: config/deploy_param.json"
        exit 1
    fi
    storage_metadata_fs_path="/mnt/dbdata/remote/metadata_${storage_metadata_fs}/upgrade/rollup_bak_${source_version}"

    cluster_and_node_status_path="${storage_metadata_fs_path}/cluster_and_node_status"
    # 支持重入
    if [ ! -d "${cluster_and_node_status_path}" ]; then
        mkdir -p "${cluster_and_node_status_path}"
    fi

    cluster_status_flag="${cluster_and_node_status_path}/cluster_status.txt"
    local_node_status_flag="${cluster_and_node_status_path}/node${node_id}_status.txt"

    logAndEchoInfo ">>>>> init cluster and node status flag success <<<<<"

    # 判断当前集群升级状态，若为normal或commit则直接退出回滚流程
    if [ -e "${cluster_status_flag}" ]; then
        cluster_status=$(cat ${cluster_status_flag})
        if [[ " ${CLUSTER_COMMIT_STATUS[*]} " == *" ${cluster_status} "* ]]; then
            logAndEchoInfo "the current cluster status is already ${cluster_status}, no need to execute the rollback operation"
            exit 1
        fi
    fi
}

# 滚动升级回退，限制任何时候仅有一个节点处于回退状态
function check_if_any_node_in_rollback_status() {
    logAndEchoInfo ">>>>> begin to check if any node in roll down state  <<<<<"
    # 读取各节点升级状态文件，过滤掉当前节点的状态文件
    node_status_files=($(find "${cluster_and_node_status_path}" -type f | grep -E "^${cluster_and_node_status_path}/node[0-9]+_status\.txt$" | grep -v "node${node_id}"))
    # 共享目录中无状态文件，则符合升级条件
    if [ ${#node_status_files[@]} -eq 0 ]; then
        return 0
    fi

    status_array=()
    for status in "${node_status_files[@]}";
    do
        status_array+=("$(cat ${status})")
    done

    # 如果某个其他节点状态为rollup或rolldown，则该由那个节点先行回退。
    for node_flag in "${status_array[@]}";
    do
        if [[ " ${NODE_NOT_ROLLBACK_STATUS[*]} " == *" ${node_flag} "* ]]; then
            logAndEchoError "there are currently one or more nodes in the 'rolldown' or the 'rollup' state"
            exit 1
        fi
    done
    logAndEchoInfo ">>>>> check pass, currently no nodes are in roll down state  <<<<<"
}

# 滚动升级回退：集群/节点是否支持回退判断
function support_rollback_judgement() {
    logAndEchoInfo ">>>>> begin to check if the cluster and nodes support roll down <<<<<"
    # step1: 判断当前集群是否支持回退
    if [ -z "${cluster_status_flag}" ] || [ ! -e "${cluster_status_flag}" ]; then
        logAndEchoError "the cluster rollback status file does not exist." && exit 1
    fi
    cluster_rollback_status=$(cat "${cluster_status_flag}")
    status_allowed_array=("rollup" "rolldown" "prepared")
    if [[ " ${status_allowed_array[*]} " != *" ${cluster_rollback_status} "* ]]; then
        logAndEchoError "input rollback module must be one of '${status_allowed_array[@]}', instead of '${cluster_rollback_status}'" && exit 1
    fi
    node_rollback_status=$(cat "${local_node_status_flag}")
    if [[ "${node_rollback_status}" == "rolldown_success" ]];then
        logAndEchoInfo "The current node has been rolled back successfully." && exit 0
    fi
    # 更改集群状态
    modify_cluster_or_node_status "${cluster_status_flag}" "rolldown" "cluster"

    # step2: 若修改了系统表，则不允许回退
    modify_sys_tables_success="${storage_metadata_fs_path}/updatesys.success"
    modify_sys_tables_failed="${storage_metadata_fs_path}/updatesys.failed"
    if [ -f "${modify_sys_tables_success}" ] || [ -f "${modify_sys_tables_failed}" ]; then
        logAndEchoError "it is detected that the system table has been modified, please rollback offline" && exit 1
    fi

    dircetory_path="/opt/cantian/upgrade_backup/cantian_upgrade_bak_${source_version}"
    # step3: 判断当前节点是否支持回退
    if [ -z "${local_node_status_flag}" ] || [ ! -e "${local_node_status_flag}" ]; then
        # 若当前节点未进行升级操作，则无需回退
        logAndEchoInfo "the current node has not been upgraded, and there is no need to roll down"
        modify_cluster_or_node_status "${local_node_status_flag}" "rolldown_success" "node${node_id}"
        exit 0
    elif [ ! -f "${dircetory_path}/backup_success" ]; then
         # 若当前节点未进行备份操作，则无需回退
        logAndEchoInfo "the current node is not backed up, and there is no need to roll down"
        modify_cluster_or_node_status "${local_node_status_flag}" "rolldown_success" "node${node_id}"
        exit 0
    fi
    # 更改当前节点升级状态
    modify_cluster_or_node_status "${local_node_status_flag}" "rolldown" "node${node_id}"
    logAndEchoInfo ">>>>> pass check if the cluster and nodes support roll down <<<<<"
}

# 滚动升级回退：检查整个集群的回退状况
function cluster_rolldown_status_check() {
    logAndEchoInfo ">>>>> begin to check cluster rolldown status <<<<<"

    # 统计当前节点数目
    cms_ip=$(python3 ${CURRENT_PATH}/get_config_info.py "cms_ip")
    node_count=$(expr "$(echo "${cms_ip}" | grep -o ";" | wc -l)" + 1)

    # 读取各节点升级状态文件
    node_status_files=($(find "${cluster_and_node_status_path}" -type f | grep -v grep | grep -E "^${cluster_and_node_status_path}/node[0-9]+_status\.txt$"))
    status_array=()
    for status in "${node_status_files[@]}";
    do
        status_array+=("$(cat ${status})")
    done

    # 对升级状态数组去重
    unique_status=($(printf "%s\n" "${status_array[@]}" | uniq))
    # 去重后长度若不为1则直接退出
    if [ ${#unique_status[@]} -ne 1 ]; then
        logAndEchoInfo "existing nodes have not been rollback successfully, details: ${status_array[@]}"
        exit 0
    fi
    # 去重后元素不是rollup_success
    if [ "${unique_status[0]}" != "rolldown_success" ]; then
        logAndEchoError "none of the ${node_count} nodes were rollback successfully"
        exit 1
    fi

    logAndEchoInfo ">>>>> all ${node_count} nodes were rollback successfully, pass check cluster rollback status <<<<<"
}

# 滚动升级回退: 检查所有节点升级后的拉起和入集群情况
function post_rolldown_nodes_status() {
    logAndEchoInfo ">>>>> begin to check the startup and cluster status of all nodes after rollback <<<<<"

    # 统计当前节点数目
    cms_ip=$(python3 ${CURRENT_PATH}/get_config_info.py "cms_ip")
    node_count=$(expr "$(echo "${cms_ip}" | grep -o ";" | wc -l)" + 1)

    cms_res=$(su -s /bin/bash - "${cantian_user}" -c "cms stat")

    # step1: 统计节点拉起情况
    start_array=()
    readarray -t start_array <<< "$(echo "${cms_res}" | awk '{print $3}' | tail -n +$"2")"
    if [ ${#start_array[@]} != "${node_count}" ]; then
        logAndEchoError "only ${#start_array[@]} nodes were detected, instead of ${node_count}" && exit 1
    fi

    unique_start=($(printf "%s\n" "${start_array[@]}" | uniq))
    if [ ${#unique_start[@]} -ne 1 ]; then
        logAndEchoError "existing nodes have not been started successfully, details: ${start_array[@]}" && exit 1
    fi

    if [ "${unique_start[0]}" != "ONLINE" ]; then
        logAndEchoError "none of the ${node_count} nodes were started successfully" && exit 1
    fi

    logAndEchoInfo "all nodes started successfully"

    # step2: 统计节点加入集群的情况
    cluster_join=()
    readarray -t cluster_join <<< "$(echo "${cms_res}" | awk '{print $6}' | tail -n +$"2")"
    unique_join=($(printf "%s\n" "${cluster_join[@]}" | uniq))
    if [ ${#unique_join[@]} -ne 1 ]; then
        logAndEchoError "existing nodes have not joined the cluster successfully, details: ${unique_join[@]}" && exit 1
    fi

    if [ "${unique_join[0]}" != "1" ]; then
        logAndEchoError "none of the nodes joined the cluster" && exit 1
    fi

    modify_cluster_or_node_status "${cluster_status_flag}" "normal" "cluster"
    rm -f ${cluster_and_node_status_path}/node*
    logAndEchoInfo ">>>>> all nodes join the cluster successfully <<<<<"

}

# 滚动升级提交后强制降低版本号
function degrade_version() {
    target_numbers=($(echo "${back_version}" | sed -n 's/\([0-9]*\)\.B.*/\1/p'))
    format_target="${target_numbers[@]//./ }"
    current_cms_version=$(su -s /bin/bash - "${cantian_user}" -c "cms version")
    if [[ "${current_cms_version}" == *"${target_numbers}"* ]];then
        logAndEchoInfo "Current cms version is ${current_cms_version}, rollback version ${target_numbers}."
        return 0
    fi
    for ((i=1;i<11;i++))
    do
        su -s /bin/bash - "${cantian_user}" -c "cms degrade -version -force ${format_target}"
        if [ $? -ne 0 ];then
            logAndEchoError "calling cms tool to degrade the version failed, current attempt:${i}/10".
            sleep 10
            continue
        else
            break
        fi
    done
    if [ $i -eq 11 ];then
        exit 1
    fi
    logAndEchoInfo "calling cms tool to degrade the version success"
}

function rollback_file_system() {
    logAndEchoInfo "Begin to rollback dbstore file system."
    echo -e "${DORADO_IP}\n${dorado_user}\n${dorado_pwd}\n" | python3 "${CURRENT_PATH}"/storage_operate/split_dbstore_fs.py "rollback" "${CURRENT_PATH}"/../config/deploy_param.json
    if [ $? -ne 0 ]; then
        logAndEchoError "rollback dbstore file system failed"
        exit 1
    fi

    logAndEchoInfo "rollback dbstore file system success"

    logAndEchoInfo "rollback to split cms share file system."
    dircetory_path="/opt/cantian/upgrade_backup/cantian_upgrade_bak_${back_version}"
    echo -e "${DORADO_IP}\n${dorado_user}\n${dorado_pwd}\n" | python3 "${CURRENT_PATH}"/storage_operate/migrate_file_system.py "rollback" "${CURRENT_PATH}"/../config/deploy_param.json "${dircetory_path}"/config/deploy_param.json
    if [ $? -ne 0 ]; then
        logAndEchoError "rollback cms file system failed"
        exit 1
    fi

    logAndEchoInfo "rollback cms file system success"
}

# 离线升级回滚入口
function offline_rollback() {
    get_mnt_dir_name
    get_rollback_version
    version_first_number=`echo ${back_version} | awk -F '.' '{print $1}'`
    if [[ ${version_first_number} -eq 2 ]];then
        user=${deploy_user}
    fi
    mode_check
    stopping_check
    if [[ ${node_id} == '0' && -f ${CHECK_POINT_FLAG} ]]; then
        rollback_sys_tables
    fi
    if [[ ${node_id} == '0' && -f ${CHECK_POINT_FLAG} ]]; then
        degrade_version
    fi
    rollback_check
    do_rollback
    if [[ x"${choose}" != x"yes" ]];then
        start_cantian
        check_local_nodes
    fi
    clear_tag_file
    remove_old_user
}

# 滚动升级回滚总入口
function rollup_rollback() {
    # 滚动升级回滚不允许用户输入指定版本号
    ROLLBACK_VERSION=''
    get_mnt_dir_name
    get_rollback_version

    # step1：回退前决策
    init_cluster_or_node_status_flag
    support_rollback_judgement
    check_if_any_node_in_rollback_status

    # step2：各节点回退执行
    local_node_status=$(cat "${local_node_status_flag}")
    if [ "${local_node_status}" != "rolldown_success" ]; then
        stop_cantian
        do_rollback
        start_cantiand_by_cms
        start_cantian
        check_local_nodes
        modify_cluster_or_node_status "${local_node_status_flag}" "rolldown_success" "node${node_id}"
    fi

    # step3：回退后验证（集群侧）
    cluster_rolldown_status_check
    post_rolldown_nodes_status
    clear_tag_file
}

function modify_env() {
    if [[ x"${deploy_mode}" == x"nas" ]];then
        python3 "${CURRENT_PATH}"/modify_env.py
        if [ $? -ne 0 ];then
            echo "Current deploy mode is ${deploy_mode}, modify env.sh failed."
        fi
    fi
}

function main() {
    logAndEchoInfo ">>>>> begin to rollback, current rollback mode: ${ROLLBACK_MODE} <<<<<"
    input_params_check
    get_current_node
    modify_env
    source ${CURRENT_PATH}/env.sh
    user=${cantian_user}

    if [ "${ROLLBACK_MODE}" == "rollup" ]; then
        rollup_rollback
    elif [ "${ROLLBACK_MODE}" == "offline" ]; then
        offline_rollback
    fi
}

main
