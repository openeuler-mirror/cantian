#!/bin/bash
set +x

CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
UPGRADE_MODE=$1
DORADO_IP=$2
SO_PATH=""
FILE_MOD_FILE=${CURRENT_PATH}/file_mod.sh
CMS_CHECK_FILE=${CURRENT_PATH}/fetch_cls_stat.py
MYSQL_MOUNT_PATH=/opt/cantian/image/cantian_connector/for_mysql_official/mf_connector_mount_dir
UPDATE_CONFIG_FILE_PATH=${CURRENT_PATH}/update_config.py
SOURCE_ACTION_PATH=/opt/cantian/action
VERSION_FILE=/opt/cantian/versions.yml
CANTIAN_STATUS=/opt/cantian/cantian/cfg/start_status.json
CONFIG_PATH=/opt/cantian/config
UPGRADE_SUCCESS_FLAG=/opt/cantian/pre_upgrade_${UPGRADE_MODE}.success
UPGRADE_MODE_LIS=("offline" "rollup")
dorado_user=""
dorado_pwd=""
node_id=""
upgrade_module_correct=false
# 滚动升级
CLUSTER_COMMIT_STATUS=("prepared" "commit")
storage_metadata_fs_path=""
cluster_and_node_status_path=""
cluster_status_flag=""
local_node_status_flag=""
local_node_status=""
modify_sys_table_flag=""
deploy_user=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_user")
deploy_group=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_group")
deploy_mode=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_mode")
CLUSTER_PREPARED=3
NFS_TIMEO=50

source ${CURRENT_PATH}/log4sh.sh
source ${FILE_MOD_FILE}

# export此环境变量，方便调用ctbackup
export PATH=/opt/cantian/mysql/install/mysql/bin/:$PATH

if [[ x"${deploy_mode}" == x"nas" ]];then
    python3 "${CURRENT_PATH}"/modify_env.py
    if [  $? -ne 0 ];then
        echo "Current deploy mode is ${deploy_mode}, modify env.sh failed."
    fi
fi

source ${CURRENT_PATH}/env.sh

function rpm_check(){
    local count=2
    if [ x"${deploy_mode}" != x"nas" ];then
      count=3
    fi
    rpm_pkg_count=$(ls "${CURRENT_PATH}"/../repo | wc -l)
    rpm_pkg_info=$(ls -l "${CURRENT_PATH}"/../repo)
    logAndEchoInfo "There are ${rpm_pkg_count} packages in repo dir, which detail is: ${rpm_pkg_info}"
    if [ ${rpm_pkg_count} -ne ${count} ]; then
        logAndEchoError "We have to have only ${count} rpm package,please check"
        exit 1
    fi
}

# 输入参数校验
function input_params_check() {
    logAndEchoInfo ">>>>> begin to check input params <<<<<"
    # 检查升级模式
    if [[ " ${UPGRADE_MODE_LIS[*]} " == *" ${UPGRADE_MODE} "* ]]; then
        logAndEchoInfo "pass upgrade mode check, current upgrade mode: ${UPGRADE_MODE}"
    else
        logAndEchoError "input upgrade module must be one of '${UPGRADE_MODE_LIS[@]}', instead of '${UPGRADE_MODE}'"
        exit 1
    fi

    # 离线升级需要检查阵列侧ip
    if [ "${UPGRADE_MODE}" == "offline" ]; then
        if [ -z "${DORADO_IP}" ]; then
            logAndEchoError "storage array ip must be provided"
            exit 1
        fi

        ping -c 1 ${DORADO_IP} > /dev/null 2>&1
        if [ $? -ne 0 ]; then
            logAndEchoError "try to ping storage array ip '${DORADO_IP}', but failed"
            exit 1
        fi
    fi

    # 若使用入湖，需校验so依赖文件路径进行文件拷贝
    chmod 400 ${CURRENT_PATH}/logicrep/check_logicrep_status.sh
    sh ${CURRENT_PATH}/logicrep/check_logicrep_status.sh
    if [ $? -eq 0 ]; then
        read -p "please input the so rely path of logicrep: " SO_PATH
        if [ ! -d "${SO_PATH}" ]; then
            logAndEchoInfo "pass upgrade mode check, current upgrade mode: ${UPGRADE_MODE}"
            exit 1
        else
            if [ -z "$(ls -A "${SO_PATH}")" ]; then
                logAndEchoInfo "pass upgrade mode check, current upgrade mode: ${UPGRADE_MODE}"
                exit 1
            fi
        fi
    fi
    logAndEchoInfo ">>>>> pass input params check <<<<<"
}

# 获取共享目录名称
function get_mnt_dir_name() {
    storage_share_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_share_fs"`
    storage_archive_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_archive_fs"`
    storage_metadata_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_metadata_fs"`
}
# 获取用户输入的阵列侧用户名ip等
function get_user_input() {
    read -p "please enter dorado_user: " dorado_user
    echo "dbstor_user is: ${dorado_user}"

    read -s -p "please enter dorado_pwd: " dorado_pwd
    echo ''
}

# 获取当前节点
function get_config_info() {
    deploy_mode=$(python3 "${CURRENT_PATH}"/get_config_info.py "deploy_mode")
    node_id=$(python3 ${CURRENT_PATH}/get_config_info.py "node_id")
    if [[ ${node} == 'None' ]]; then
        logAndEchoError "obtain current node id error, please check file: config/deploy_param.json"
        exit 1
    fi

    logAndEchoInfo ">>>>> begin to init cluster and node status flag <<<<<"
    source_version=$(python3 ${CURRENT_PATH}/implement/get_source_version.py)
    if [ -z "${source_version}" ]; then
        logAndEchoError "failed to obtain source version"
        exit 1
    fi
    storage_metadata_fs_path="/mnt/dbdata/remote/metadata_${storage_metadata_fs}/upgrade/${UPGRADE_MODE}_bak_${source_version}"
}

######################################################################
# 滚动升级ctbackup需要输入mysql用户名密码、ininerDB路径、ip和port
######################################################################
function rollup_user_input() {
    read -p "please enter mysql login ip: " mysql_ip
    echo "mysql login ip is: ${mysql_ip}"

    read -p "please enter mysql login port: " mysql_port
    echo "mysql login port is: ${mysql_port}"

    read -p "please enter mysql login user: " mysql_user
    echo "mysql login user is: ${mysql_user}"

    read -s -p "please enter mysql login pwd: " mysql_pwd
    echo ''

    read -p "please enter mysql metadata storage path: " mysql_metadata_path
    echo "mysql metadata storage path: is: ${mysql_metadata_path}"
    read -p "please enter ctbackup storage path: " ct_backup_main_path
    echo "ctbackup storage path: is: ${ct_backup_main_path}"
    local path_length
    path_length=$(echo -n "${ct_backup_main_path}" | wc -c)
    if [[ ${path_length} -gt 100 ]] || [[ ! -d ${ct_backup_main_path} ]];then
        logAndEchoError "The length of the ctbackup path cannot exceed 100, and exists."
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
    py_pid=$(ps -ef | grep "python3 /opt/cantian/ct_om/service/cantian_exporter/exporter/execute.py" | grep -v grep | awk '{print $2}')
    if [ ! -z "${py_pid}" ]; then
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
    echo -e "${dorado_user}\n${dorado_pwd}" | python3 ${CURRENT_PATH}/storage_operate/do_snapshot.py create ${DORADO_IP} ${dircetory_path}
    if [ $? -ne 0 ]; then
        logAndEchoError "create snapshot failed"
        exit 1
    fi

    logAndEchoInfo "create snapshot success"
}

#######################################################################################
##  文件系统拆分
#######################################################################################
function split_dbstore_file_system() {
    logAndEchoInfo "Begin to split dbstore file system."
    echo -e "${DORADO_IP}\n${dorado_user}\n${dorado_pwd}\n" | python3 "${CURRENT_PATH}"/storage_operate/split_dbstore_fs.py "upgrade" "${CURRENT_PATH}"/../config/deploy_param.json
    if [ $? -ne 0 ]; then
        logAndEchoError "Split dbstore file system failed, details see /opt/cantian/deploy/om_deploy/om_deploy.log"
        exit 1
    fi

    logAndEchoInfo "Split dbstore file system success"
}

function migrate_file_system() {
    logAndEchoInfo "Begin to split cms share file system."
    echo -e "${DORADO_IP}\n${dorado_user}\n${dorado_pwd}\n" | python3 "${CURRENT_PATH}"/storage_operate/migrate_file_system.py "upgrade" "${CURRENT_PATH}"/../config/deploy_param.json "${dircetory_path}"/config/deploy_param.json
    if [ $? -ne 0 ]; then
        logAndEchoError "Split cms file system failed, details see /opt/cantian/deploy/om_deploy/om_deploy.log"
        exit 1
    fi

    logAndEchoInfo "Split cms file system success"
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
    find "${dircetory_path}/" -type f \( -name "*.txt" -o -name "*.cfg" -o -name "*.xml" \) -exec chmod 640 {} \;
    logAndEchoInfo "backup resource success"
}

function update_config() {
    # 适配冗余链路
    su -s /bin/bash - "${cantian_user}" -c "python3 -B ${UPDATE_CONFIG_FILE_PATH} --component=cantian_ini --action=update --key=INTERCONNECT_ADDR"
     if [ $? -ne 0 ];then
        logAndEchoError "Update cantiand.ini config file INTERCONNECT_ADDR failed"
        exit 1
    fi
    su -s /bin/bash - "${cantian_user}" -c "python3 -B ${UPDATE_CONFIG_FILE_PATH} --component=cantian_ini --action=update --key=_MAX_OPEN_FILES"
    # 更新log fs id
    log_vstor_id=$(python3 "${CURRENT_PATH}"/get_config_info.py "dbstore_fs_vstore_id")
    su -s /bin/bash - "${cantian_user}" -c "python3 -B ${UPDATE_CONFIG_FILE_PATH} --component=dbstore --action=add --key=LOG_VSTOR --value=${log_vstor_id}"
     if [ $? -ne 0 ];then
        logAndEchoError "Update cantiand.ini config file INTERCONNECT_ADDR failed"
        exit 1
    fi
    #  更新page fs id，当前默认为0，后续如果新增再修改
    su -s /bin/bash - "${cantian_user}" -c "python3 -B ${UPDATE_CONFIG_FILE_PATH} --component=dbstore --action=add --key=PAGE_VSTOR --value=0"
    su -s /bin/bash - "${cantian_user}" -c "python3 -B ${UPDATE_CONFIG_FILE_PATH} --component=cantian_ini --action=add --key=MYSQL_DEPLOY_GROUP_ID"
    if [[ x"${source_version}" != x"2.0.0"* ]];then
        logAndEchoInfo "Current upgrade source version is ${source_version}, no need update config"
        return
    fi
    logAndEchoInfo "Update dbstore config file"
    storage_dbstore_page_fs=$(python3 "${CURRENT_PATH}"/get_config_info.py "storage_dbstore_page_fs")
    su -s /bin/bash - cantian -c "python3 -B ${UPDATE_CONFIG_FILE_PATH} --component=dbstore --action=add --key=NAMESPACE_PAGE_FSNAME --value=${storage_dbstore_page_fs}"
    if [ $? -ne 0 ];then
        logAndEchoError "Update dbstore config file failed"
        exit 1
    fi
    # 增UUID至参天、cms、dostore配置文件
    system_uuid=$(dmidecode -s system-uuid)
    su -s /bin/bash - ${cantian_user} -c "python3 -B ${UPDATE_CONFIG_FILE_PATH} --component=dbstore --action=add --key=SYSTEM_UUID --value=${system_uuid}"
    if [ $? -ne 0 ];then
        logAndEchoError "Update dbstore config file failed"
        exit 1
    fi
    logAndEchoInfo "Update config file cantiand.ini"
    read -s -p "please enter cantian sys pwd: " cantian_sys_pwd
    echo ''
    echo -e "${cantian_sys_pwd}" | su -s /bin/bash - ${cantian_user} -c "python3 -B ${UPDATE_CONFIG_FILE_PATH} --component=cantian_ini --action=update --key=cantian"
    if [ $? -ne 0 ];then
        logAndEchoError "Update cantiand.ini config file failed"
        exit 1
    fi

    logAndEchoInfo "Update config file cms.ini"
    su -s /bin/bash - ${cantian_user} -c "python3 -B ${UPDATE_CONFIG_FILE_PATH} --component=cms_ini --action=update --key=GCC_TYPE  --value=NFS"
    if [ $? -ne 0 ];then
        logAndEchoError "Update cms config file failed"
        exit 1
    fi

    logAndEchoInfo "Update config file cantian_config.json"
    su -s /bin/bash - ${cantian_user} -c "python3 -B ${UPDATE_CONFIG_FILE_PATH} --component=cantian --action=add --key=cantian --value=cantian"
    if [ $? -ne 0 ];then
        logAndEchoError "Update cantian config file failed"
        exit 1
    fi

    logAndEchoInfo "Update config file cms.json"
    su -s /bin/bash - ${cantian_user} -c "python3 -B ${UPDATE_CONFIG_FILE_PATH} --component=cms --action=add --key=cms --value=cms"
    if [ $? -ne 0 ];then
        logAndEchoError "Update cantian config file failed"
        exit 1
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
    RPM_PATH=${CURRENT_PATH}/../repo/cantian-*.rpm
    RPM_UNPACK_PATH_FILE="/opt/cantian/image/cantian_connector/CantianKernel/Cantian-DATABASE-CENTOS-64bit"
    RPM_PACK_ORG_PATH="/opt/cantian/image"

    if [ ! -f  "${CURRENT_PATH}"/../repo/cantian-*.rpm ]; then
        echo "cantian.rpm is not exist."
        exit 1
    fi

    rpm -ivh --replacepkgs ${RPM_PATH} --nodeps --force

    tar -zxf ${RPM_UNPACK_PATH_FILE}/Cantian-RUN-CENTOS-64bit.tar.gz -C ${RPM_PACK_ORG_PATH}
    if [ x"${deploy_mode}" != x"nas" ];then
        echo  "start replace rpm package"
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

function update_user_env() {
    grep 'export CTDB_DATA="/mnt/dbdata/local/cantian/tmp/data"' /home/"${cantian_user}"/.bashrc
    if [[ $? -ne 0 ]];then
        sed -i '$a export CTDB_DATA="/mnt/dbdata/local/cantian/tmp/data"' /home/"${cantian_user}"/.bashrc
    fi
    grep 'export CTDB_HOME="/opt/cantian/cantian/server"' /home/"${cantian_user}"/.bashrc
    if [[ $? -ne 0 ]];then
        sed -i '$a export CTDB_HOME="/opt/cantian/cantian/server"' /home/"${cantian_user}"/.bashrc
    fi
}

#  升级
function do_upgrade() {
    logAndEchoInfo "begin to upgrade"
    correct_files_mod
    # 升级前删除掉遗留系统文件
    rm -rf /etc/systemd/system/cantian*.service
    rm -rf /etc/systemd/system/cantian*.timer
    # 更新系统定时任务文件
    cp -f ${CURRENT_PATH}/../config/*.service /etc/systemd/system/
    cp -f ${CURRENT_PATH}/../config/*.timer /etc/systemd/system/

    cp -fp ${CURRENT_PATH}/* /opt/cantian/action > /dev/null 2>&1
    cp -rfp ${CURRENT_PATH}/inspection /opt/cantian/action
    cp -rfp ${CURRENT_PATH}/implement /opt/cantian/action
    cp -rfp ${CURRENT_PATH}/logic /opt/cantian/action
    cp -rfp ${CURRENT_PATH}/storage_operate /opt/cantian/action
    cp -rfp ${CURRENT_PATH}/utils /opt/cantian/action
    cp -rfp ${CURRENT_PATH}/../config /opt/cantian/
    cp -rfp ${CURRENT_PATH}/../common /opt/cantian/
    rm -rf /opt/cantian/repo/*
    cp -rf ${CURRENT_PATH}/../repo /opt/cantian/
    chmod 400 /opt/cantian/repo/*
    logAndEchoInfo "om upgrade finished"

    uninstall_rpm
    install_rpm

    for upgrade_module in "${UPGRADE_ORDER[@]}";
    do
        logAndEchoInfo "begin to upgrade ${upgrade_module}"
        sh "${CURRENT_PATH}/${upgrade_module}/appctl.sh" upgrade ${UPGRADE_MODE} ${dircetory_path} ${SO_PATH}
        if [ $? -ne 0 ]; then
            logAndEchoError "${upgrade_module} upgrade failed"
            logAndEchoError "For details, see the /opt/cantian/${upgrade_module}/log. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            exit 1
        fi
        logAndEchoInfo "${upgrade_module} upgrade success"
    done
    # 修改巡检相关脚本
    chown -hR ${cantian_user}:${cantian_group} /opt/cantian/action/inspection
    cp -rfp ${CURRENT_PATH}/inspection ${MYSQL_MOUNT_PATH}
    # 更新配置文件
    update_user_env
    update_config
    if [[ -f /mnt/dbdata/local/cantian/tmp/data/cfg/zsql.ini ]];then
        mv /mnt/dbdata/local/cantian/tmp/data/cfg/zsql.ini /mnt/dbdata/local/cantian/tmp/data/cfg/ctsql.ini
    fi
}

#  修改公共文件mod
function correct_files_mod() {
    logAndEchoInfo "begin to correct files mod"

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
    chown -h "${cantian_user}":"${cantian_group}" "${CURRENT_PATH}"/obtains_lsid.py
    chown -h "${cantian_user}":"${cantian_group}" "${CURRENT_PATH}"/implement/update_cantian_passwd.py
    chown -h "${cantian_user}":"${cantian_group}" "${CURRENT_PATH}"/update_config.py
    version_first_number=$(cat /opt/cantian/versions.yml |sed 's/ //g' | grep 'Version:' | awk -F ':' '{print $2}' | awk -F '.' '{print $1}')
    if [[ ${version_first_number} -eq 2 ]];then
        change_new_owner
        export_user_env
        check_sem_id
    fi
    logAndEchoInfo "correct file mod success"
}

#  离线升级2升3 修改文件属主
function change_new_owner() {
    logAndEchoInfo "begin to correct files owner"
    chown -hR "${cantian_user}":"${cantian_group}" /opt/cantian/common/config
    chown -hR "${cantian_user}":"${cantian_group}" /opt/cantian/common/data
    if [[ x"${deploy_mode}" != x"dbstore_unify" ]]; then
        chown -h "${cantian_user}":"${cantian_group}" /mnt/dbdata/remote/share_${storage_share_fs}
        chown -hR "${cantian_user}":"${cantian_group}" /mnt/dbdata/remote/share_${storage_share_fs}/gcc_home > /dev/null 2>&1
        chown -hR "${cantian_user}":"${cantian_group}" /mnt/dbdata/remote/share_${storage_share_fs}/node0 > /dev/null 2>&1
        chown -hR "${cantian_user}":"${cantian_group}" /mnt/dbdata/remote/share_${storage_share_fs}/node1 > /dev/null 2>&1
    fi
    chown -hR "${cantian_user}":"${deploy_group}" /mnt/dbdata/remote/archive_${storage_archive_fs} > /dev/null 2>&1
    chown -hR "${cantian_user}":"${cantian_group}" /mnt/dbdata/local/cantian
    chown -hR "${cantian_user}":"${cantian_group}" /opt/cantian/cantian/server
    chown -hR "${cantian_user}":"${cantian_group}" /mnt/dbdata/local/cantian > /dev/null 2>&1
    node_id=$(python3 ${CURRENT_PATH}/get_config_info.py "node_id")
    chmod 770 /mnt/dbdata/remote/metadata_${storage_metadata_fs}/node${node_id}
    chown ${deploy_user}:${cantian_common_group} /mnt/dbdata/remote/metadata_${storage_metadata_fs}/node${node_id}
    chmod 660 /dev/shm/cantian*
    chown -hR "${cantian_user}":"${deploy_group}" /dev/shm/cantian*
}

# 离线升级2升3 配置环境变量
function export_user_env(){
    logAndEchoInfo "begin to export environment variable"
    cantian_profile="/home/${cantian_user}/.bashrc"
    deploy_user_profile="/home/${deploy_user}/.bashrc"
    grep "CMS_HOME" ${cantian_profile} > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        logAndEchoInfo "export environment variable success"
        return 0
    fi
    rm -f ${cantian_profile}
    cp -fP ${deploy_user_profile} ${cantian_profile}
    chown ${cantian_user}:${cantian_group} ${cantian_profile}
    if [ $? -ne 0 ]; then
        logAndEchoError "export environment variable failed"
        exit 1
    fi
    USER_ENV_CMDS[0]="/^export\sPATH=\"\/opt\/cantian\/cms\/service\/bin\":\$PATH$/d"
    USER_ENV_CMDS[1]="/^export\sPATH=\"\/opt\/cantian\/cantian\/server\/bin\":\$PATH$/d"
    USER_ENV_CMDS[2]="/^export\sLD_LIBRARY_PATH=\"\/opt\/cantian\/cms\/service\/lib\"/d"
    USER_ENV_CMDS[3]="/^export\sLD_LIBRARY_PATH=\"\/opt\/cantian\/cantian\/server\/lib\"/d"
    USER_ENV_CMDS[4]="/^export\sCMS_HOME=/d"
    USER_ENV_CMDS[5]="/^export\sCTDB_HOME=/d"
    USER_ENV_CMDS[6]="/^export\sCTDB_DATA=/d"

    for cmd in ${USER_ENV_CMDS[@]};do
        sed -i ${cmd} ${deploy_user_profile} > /dev/null 2>&1
    done

    logAndEchoInfo "export environment variable success"

}

# 离线升级2升3 如果存在信号量则删除，防止信号量权限异常
function check_sem_id() {
    ret=`lsipc -s -c | grep 0x20161227`
    if [ -n "$ret" ]; then
        arr=($ret)
        sem_id=${arr[1]}
        ipcrm -s $sem_id
    fi
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

######################################################################
# 滚动升级场景，通过cms拉起参天，避免其他节点正在进行reform，当前节点执行拉起失败
# 实现流程：
#        1、通过cms模块appctl.sh start 启动cms；
#        2、通过cms res -start db -node {node_id}拉起cantiand
######################################################################
function start_cantiand_by_cms() {
    logAndEchoInfo "begin to start cms"
    sh "${SOURCE_ACTION_PATH}"/cms/appctl.sh start
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

# 修改系统表
function modify_sys_tables() {
    modify_sys_table_flag="${storage_metadata_fs_path}/updatesys.true"
    modify_sys_tables_success="${storage_metadata_fs_path}/updatesys.success"
    modify_sys_tables_failed="${storage_metadata_fs_path}/updatesys.failed"
    systable_home="/opt/cantian/cantian/server/admin/scripts/rollUpgrade"
    bak_initdb_sql="${dircetory_path}/cantian/cantian_home/server/admin/scripts/initdb.sql"
    old_initdb_sql="${dircetory_path}/initdb.sql"
    new_initdb_sql="${systable_home}/../initdb.sql"
    # 无需修改系统表或者已经修改过系统表
    if [ ! -f "${modify_sys_table_flag}" ] || [ -f "${modify_sys_tables_success}" ]; then
        logAndEchoInfo "detected that the system tables have been modified or does not need to be modified"
        return 0
    fi
    node_ip="127.0.0.1"
    # 解决2.0升级3.0版本备份initdb.sql cantian用户没有读权限问题
    cp -arf "${bak_initdb_sql}" "${old_initdb_sql}"
    # 解决2.0版本initdb.sql版本号配置问题
    if [[ "$back_version" == "2.0.0"* ]];then
        sed -i "1355a --01" "${old_initdb_sql}"
    fi
    # 判断sql文件是否相同，如果不相同需要进行系统表升级，相同场景无需修改（避免B版本升级问题）
    diff "${old_initdb_sql}" "${new_initdb_sql}" > /dev/null
    if [[ $? != 0 ]];then
        logAndEchoInfo "modify sys tables start"
        # 2.0升级3.0场景，更新配置文件时已经输入了ctsql密码，此处不需要在重复输入，3.0需要单独输入
        if [[ "$back_version" != "2.0.0"* ]];then
            read -s -p "please enter cantian sys pwd: " cantian_sys_pwd
        fi
        echo ''
        chown "${cantian_user}":"${cantian_group}" "${old_initdb_sql}"
        echo -e "${cantian_sys_pwd}" | su -s /bin/bash - "${cantian_user}" -c "sh ${systable_home}/upgrade_systable.sh ${node_ip} ${systable_home}/../../../bin ${old_initdb_sql} ${new_initdb_sql} ${systable_home}"
        if [ $? -ne 0 ];then
            logAndEchoError "modify sys tables failed"
            touch "${modify_sys_tables_failed}" && chmod 400 "${modify_sys_tables_failed}"
            exit 1
        fi
        rm "${modify_sys_table_flag}"
        touch "${modify_sys_tables_success}" && chmod 400 "${modify_sys_tables_success}"
        logAndEchoInfo "modify sys tables success"
    fi
}

# 滚动升级：更改集群/节点升级状态
function modify_cluster_or_node_status() {
    # 输入参数依次是：状态文件绝对路径、新的状态、集群或节点标志
    local cluster_or_node_status_file_path=$1
    local new_status=$2
    local cluster_or_node=$3
    local old_status=""

    if [ -n "${cluster_or_node_status_file_path}" ] && [ ! -f "${cluster_or_node_status_file_path}" ]; then
        logAndEchoInfo "rollup upgrade status of '${cluster_or_node}' does not exist."
    fi

    # 若新旧状态一致则不必更新
    if [ -f "${cluster_or_node_status_file_path}" ]; then
        old_status=$(cat ${cluster_or_node_status_file_path})
        if [ "${old_status}" == "${new_status}" ]; then
            logAndEchoInfo "the old status of ${cluster_or_node} is consistent with the new status, both are ${new_status}"
            return 0
        fi
    fi

    echo "${new_status}" > ${cluster_or_node_status_file_path}
    if [ $? -eq 0 ]; then
        logAndEchoInfo "change upgrade status of ${cluster_or_node} from '${old_status}' to '${new_status}' success."
        return 0
    else
        logAndEchoInfo "change upgrade status of ${cluster_or_node} from '${old_status}' to '${new_status}' failed."
        exit 1
    fi
}

# 滚动升级，升级准备步骤：初始化节点/集群状态标记文件名
function init_cluster_or_node_status_flag() {
    cluster_and_node_status_path="${storage_metadata_fs_path}/cluster_and_node_status"
    # 支持重入
    if [ ! -d "${cluster_and_node_status_path}" ]; then
        mkdir -m 755 -p "${cluster_and_node_status_path}"
    fi

    cluster_status_flag="${cluster_and_node_status_path}/cluster_status.txt"
    local_node_status_flag="${cluster_and_node_status_path}/node${node_id}_status.txt"

    logAndEchoInfo ">>>>> init cluster and node status flag success <<<<<"

    # 判断当前集群升级状态，若为prepared或commit则直接退出升级流程
    if [ -f "${cluster_status_flag}" ]; then
        cluster_status=$(cat ${cluster_status_flag})
        if [[ " ${CLUSTER_COMMIT_STATUS[*]} " == *" ${cluster_status} "* ]]; then
            logAndEchoInfo "the current cluster status is already ${cluster_status}, no need to execute the upgrade operation"
            exit 0
        fi
    fi

    # 升级提交之后支持升级重入
    commit_success_file="/mnt/dbdata/remote/metadata_${storage_metadata_fs}/upgrade/cantian_rollup_upgrade_commit_${source_version}.success"
    if [ -f "${commit_success_file}" ]; then
        rm "${commit_success_file}"
    fi
}

# 滚动升级，升级准备步骤：检查是否有其它节点处于升级状态
function check_if_any_node_in_upgrade_status() {
    logAndEchoInfo ">>>>> begin to check if anynode in rollup state  <<<<<"
    # 读取各节点升级状态文件，过滤掉当前节点的状态文件
    node_status_files=($(find "${cluster_and_node_status_path}" -type f | grep -v grep | grep -E "^${cluster_and_node_status_path}/node[0-9]+_status\.txt$" | grep -v "node${node_id}"))
    # 共享目录中无状态文件，则符合升级条件
    if [ ${#node_status_files[@]} -eq 0 ]; then
        return 0
    fi

    status_array=()
    for status in "${node_status_files[@]}";
    do
        status_array+=("$(cat ${status})")
    done

    # 对状态数组去重
    unique_status=($(printf "%s\n" "${status_array[@]}" | uniq))
    # 去重后长度若不为1则直接退出
    if [ ${#unique_status[@]} -ne 1 ]; then
        logAndEchoError "currently existing nodes are in the 'rollup' state, details: ${status_array[@]}"
        exit 1
    fi
    # 去重后元素不是rollup_success
    if [ "${unique_status[0]}" != "rollup_success" ]; then
        logAndEchoError "there are currently one or more nodes in the 'rollup' state"
        exit 1
    fi
    logAndEchoInfo ">>>>> check pass, currently no nodes are in rollup state  <<<<<"
}

# 滚动升级， 升级准备步骤：删除多余的ctback备份文件
function delete_redundant_files() {
    local file_path=$1
    local max_keep_num=$2

    logAndEchoInfo ">>>>> begin to delete redundant ctbackup files <<<<<"
    files_list=$(ls -lt "${file_path}" | grep "^d" | grep "ctbackup" | awk '{print $9}')
    files_count=$(echo "${files_list}" | wc -l)
    logAndEchoInfo "current files num: ${files_count}, max files num allowed: ${max_keep_num}"

    # 如果目录总数超过最大限制，则删除最久远的目录
    if [ "${files_count}" -gt "${max_keep_num}" ]; then
        files_to_delete=$(echo "${files_list}" | tail -n +$((${max_keep_num} + 1)))
        for dir in ${files_to_delete[@]}; do
            rm -rf "${file_path}/${dir}"
        done
    fi

    logAndEchoInfo ">>>>> delete redundant ctbackup files success <<<<<"
}

# 清除信号量
function clear_sem_id() {
    signal_num="0x20161227"
    sem_id=$(lsipc -s -c | grep ${signal_num} | grep -v grep | awk '{print $2}')
    if [ -n "${sem_id}" ]; then
        ipcrm -s ${sem_id}
        if [ $? -ne 0 ]; then
            logAndEchoError "clear sem_id failed"
            exit 1
        fi
        logAndEchoInfo "clear sem_id success"
    fi
}

# 滚动升级， 升级准备步骤：调用ctback工具备份数据
function call_ctbackup_tool() {
    logAndEchoInfo ">>>>> begin to call ctbackup tool <<<<<"
    # 支持参天进程停止后，重入
    if [ -e "${storage_metadata_fs_path}/call_ctback_tool.success" ]; then
        logAndEchoInfo "the ctbackup tool has backed up the data successfully, no need to call it again"
        return 0
    fi
    echo "
     Please choose whether you need to use ctbackup for backup.
     If you haven't performed a backup before the upgrade, it is recommended to select step 1 to stop the upgrade process for backup.
     If the backup is already completed, please choose step 2 to continue the upgrade.
     If you haven't performed a backup before the upgrade, select step 3 during the upgrade process.
     Note: If you choose step 3, the current upgrade process duration will be extended to accommodate the backup time, so please ensure that the upgrade time window allows for it.
     1. stop upgrade and do ctbackup.
     2. No backup required and continue upgrade.
     3. do backup in upgrading."
    read -p "What's your choice, please input [1|2|3]:" ctbackup_choice
    if [[ ${ctbackup_choice} == '1' ]];then
        exit 0
    elif [[ ${ctbackup_choice} == "2" ]]; then
        return
    fi
    rollup_user_input
    # 创建备份目录
    cur_ct_backup_path="${ct_backup_main_path}/bak_$(date +"%Y%m%d%H%M%S")"
    mkdir -m 750 -p "${cur_ct_backup_path}" && chown -hR "${cantian_user}:${cantian_common_group}" ${cur_ct_backup_path}
    if [ $? -ne 0 ]; then
        logAndEchoError "create backup directory for calling ct_backup_tool failed"
        exit 1
    fi

    # 清除信号量，防止调用ctback备份工具失败
    clear_sem_id

    # 调用参天在线备份工具
    su -s /bin/bash - "${cantian_user}" -c "ctbackup --backup --target-dir=${cur_ct_backup_path} --datadir=\"${mysql_metadata_path}\" --user=\"${mysql_user}\" --password=\"${mysql_pwd}\" --host=\"${mysql_ip}\" --port=\"${mysql_port}\""
    if [ $? -ne 0 ]; then
        logAndEchoError "call ctbackup tool failed"
        exit 1
    fi

    # 备份目录下仅保留最多3分备份目录，超量则删除最为久远的备份目录
    max_backup_num_keep="3"
    delete_redundant_files "${ct_backup_main_path}" "${max_backup_num_keep}"
    if [ $? -ne 0 ]; then
        logAndEchoError "delete redundant ctbackup files failed"
    fi

    logAndEchoInfo ">>>>> call ctbackup tool success <<<<<"
}

# 滚动升级：检查当前节点升级状态
function local_node_upgrade_status_check() {
    logAndEchoInfo ">>>>> begin to check local node upgrade status <<<<<"
    if [ -f "${local_node_status_flag}" ]; then
        cur_upgrade_status=$(cat ${local_node_status_flag})
        if [ "${cur_upgrade_status}" == "rollup_success" ]; then
            local_node_status="rollup_success"
            logAndEchoInfo "node_${node_id} has been upgraded successfully"
            return 0
        elif [ "${cur_upgrade_status}" == "rollup" ]; then
            logAndEchoInfo "node_${node_id} is in rollup state"
            return 0
        fi
    fi

    modify_cluster_or_node_status "${local_node_status_flag}" "rollup" "node_${node_id}"
    logAndEchoInfo ">>>>> pass check local node upgrade status <<<<<"
}

# 滚动升级：停止mysql容器，停止参天各组件业务进程
function do_rollup_upgrade() {
    logAndEchoInfo ">>>>> begin to do rollup upgrade for node${node_id} <<<<<"

    stop_cantian

    # 生成调用ct_backup成功的标记文件，避免重入调用时失败
    touch "${storage_metadata_fs_path}/call_ctback_tool.success" && chmod 400 "${storage_metadata_fs_path}/call_ctback_tool.success"
    if [ $? -ne 0 ]; then
        logAndEchoError "create call_ctback_tool.success failed" && exit 1
    fi

    do_backup
    do_upgrade
    # 启动参天前执行一把清理，否则参天会启动失败
    clear_sem_id
    start_cantiand_by_cms
    start_cantian
    check_local_nodes
    logAndEchoInfo ">>>>> do rollup upgrade for node${node_id} success <<<<<"
}

# 滚动升级：检查整个集群的升级状况
function cluster_upgrade_status_check() {
    logAndEchoInfo ">>>>> begin to check cluster upgrade status <<<<<"

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

    # 执行了升级操作的节点数少于计算节点数，直接退出
    if [ "${#status_array[@]}" != "${node_count}" ]; then
        logAndEchoInfo "currently only ${#status_array[@]} nodes have performed the rollup upgrade operation, totals:${node_count}."
        return 0
    fi

    # 对升级状态数组去重
    unique_status=($(printf "%s\n" "${status_array[@]}" | uniq))
    # 去重后长度若不为1则直接退出
    if [ ${#unique_status[@]} -ne 1 ]; then
        logAndEchoInfo "existing nodes have not been upgraded successfully, details: ${status_array[@]}"
        return 0
    fi
    # 去重后元素不是rollup_success
    if [ "${unique_status[0]}" != "rollup_success" ]; then
        logAndEchoError "none of the ${node_count} nodes were upgraded successfully"
        exit 1
    fi

    logAndEchoInfo ">>>>> all ${node_count} nodes were upgraded successfully, pass check cluster upgrade status <<<<<"
    return 3
}

# 滚动升级: 检查所有节点升级后的拉起和入集群情况
function post_upgrade_nodes_status() {
    logAndEchoInfo ">>>>> begin to check the startup and cluster status of all nodes after upgrading <<<<<"

    # 统计当前节点数目
    cms_ip=$(python3 ${CURRENT_PATH}/get_config_info.py "cms_ip")
    node_count=$(expr "$(echo "${cms_ip}" | grep -o ";" | wc -l)" + 1)

    cms_res=$(su -s /bin/bash - "${cantian_user}" -c "cms stat")

    # step1: 统计节点拉起情况
    start_array=()
    readarray -t start_array <<< "$(echo "${cms_res}" | awk '{print $3}' | tail -n +$"2")"
    if [ ${#start_array[@]} != "${node_count}" ]; then
        logAndEchoError "only ${#start_array[@]} nodes were detected, totals:${node_count}" && exit 1
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

    logAndEchoInfo ">>>>> all nodes join the cluster successfully <<<<<"

}

function get_back_version() {
    back_version_detail=$(cat ${BACKUP_NOTE} | awk 'END {print}')
    fullback_version=($(echo ${back_version_detail} | tr ':' ' '))
    back_version=${fullback_version[0]}
}

function offline_upgrade() {
    cantian_status_check
    do_backup
    if [[ ${node_id} == '0' ]] && [[ ${deploy_mode} != "nas" ]]; then
        creat_snapshot
    fi
    get_back_version
    if [[ ${node_id} == '1' && "$back_version" == "2.0.0"* ]]; then
        kerberos_type=$(python3 "${CURRENT_PATH}"/get_config_info.py "kerberos_key")
        share_logic_ip=$(python3 "${CURRENT_PATH}"/get_config_info.py "share_logic_ip")
        storage_share_fs=$(python3 "${CURRENT_PATH}"/get_config_info.py "storage_share_fs")
        umount /mnt/dbdata/remote/share_"${storage_share_fs}"
        sleep 2
        if [[ x"${deploy_mode}" == x"dbstore_unify" ]]; then
            mount -t nfs -o sec="${kerberos_type}",timeo="${NFS_TIMEO}",nosuid,nodev "${share_logic_ip}":/"${storage_share_fs}" /mnt/dbdata/remote/share_"${storage_share_fs}"
        fi
    elif [[ x"${deploy_mode}" == x"dbstore_unify" ]]; then
        umount /mnt/dbdata/remote/share_"${storage_share_fs}"
        rm -rf /mnt/dbdata/remote/share_"${storage_share_fs}"
    fi
    do_upgrade

    start_cantian
    if [[ "$back_version" == "2.0.0"* ]]; then
        logAndEchoInfo "Upgrade ctsql _sys_passwd"
        echo -e "${cantian_sys_pwd}" | su -s /bin/bash - cantian -c "python3 -B ${UPDATE_CONFIG_FILE_PATH} --component=ctsql --action=update --key=_sys_password --value=ctsql"
        if [ $? -ne 0 ];then
            logAndEchoError "Update ctsql _sys_passwd failed"
            exit 1
        fi
    fi
    check_local_nodes
    if [[ ${node_id} == '0' ]]; then
        modify_sys_tables
    fi
    # 升级成功后删除升级检查成功标志文件
    if [ -f ${UPGRADE_SUCCESS_FLAG} ]; then
        rm -f ${UPGRADE_SUCCESS_FLAG}
    fi
}

function rollup_upgrade() {
    # step1：升级前准备
    init_cluster_or_node_status_flag
    check_if_any_node_in_upgrade_status
    # 修改集群和节点状态文件为rollup
    modify_cluster_or_node_status "${cluster_status_flag}" "rollup" "cluster"
    local_node_upgrade_status_check
    call_ctbackup_tool
    # step2：节点升级 todo：当前节点升级状态检查；停止升级启动流程；升级后验证；检查ddl文件，更新系统表接口预留
    if [ "${local_node_status}" != "rollup_success" ]; then
        do_rollup_upgrade
        modify_sys_tables
        modify_cluster_or_node_status "${local_node_status_flag}" "rollup_success" "node_${node_id}"
    fi
    # step3：
    # 节点升级后验证, 检查所有节点是否均升级成功；
    # 检查节点拉起情况，集群加入情况；
    # 升级后版本校验；
    # 更新集群状态
    cluster_upgrade_status_check
    ret=$?
    post_upgrade_nodes_status
    # 升级成功后删除升级检查成功标志文件
    if [ -f ${UPGRADE_SUCCESS_FLAG} ]; then
        rm -f ${UPGRADE_SUCCESS_FLAG}
    fi
    # 当前所有节点都升级完成后更新集群状态
    if [[ "${ret}" == "${CLUSTER_PREPARED}" ]];then
        modify_cluster_or_node_status "${cluster_status_flag}" "prepared" "cluster"
    fi
}

function show_cantian_version() {
    echo '#!/bin/bash
    set +x
    sn=$(dmidecode -s system-uuid)
    name=$(cat /etc/hostname)
    version=$(cat /opt/cantian/versions.yml | grep -oE "([0-9]+\.[0-9]+\.[0-9]+)" | sed "s/\.$//")
    echo SN                          : ${sn}
    echo System Name                 : ${name}
    echo Product Model               : Cantian
    echo Product Version             : ${version}' > /usr/local/bin/show
    chmod 550 /usr/local/bin/show
}

function main() {
    logAndEchoInfo ">>>>> begin to upgrade, current upgrade mode: ${UPGRADE_MODE} <<<<<"
    input_params_check
    get_mnt_dir_name
    get_config_info
    rpm_check

    if [ ${UPGRADE_MODE} == "offline" ]; then
        offline_upgrade
    elif [ ${UPGRADE_MODE} == "rollup" ]; then
        rollup_upgrade
    fi
    # 升级成功后更新版本信息
    show_cantian_version
    cp -fp ${CURRENT_PATH}/../versions.yml /opt/cantian
    logAndEchoInfo ">>>>> ${UPGRADE_MODE} upgrade performed successfully <<<<<"
    return 0
}

main