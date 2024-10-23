#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_PATH=${CURRENT_PATH}/..
PKG_PATH=${CURRENT_PATH}/../..
CONFIG_PATH=${CURRENT_PATH}/../../config
OPT_CONFIG_PATH="/opt/cantian/config"
INIT_CONFIG_PATH=${CONFIG_PATH}/container_conf/init_conf
DORADO_CONFIG_PATH=${CONFIG_PATH}/container_conf/dorado_conf
KMC_CONFIG_PATH=${CONFIG_PATH}/container_conf/kmc_conf
CERT_CONFIG_PATH=${CONFIG_PATH}/container_conf/cert_conf
CERT_PASS="certPass"
CONFIG_NAME="deploy_param.json"
START_STATUS_NAME="start_status.json"
MOUNT_FILE="mount.sh"
VERSION_FILE="versions.yml"
PRE_INSTALL_PY_PATH=${CURRENT_PATH}/../pre_install.py
WAIT_TIMES=120
LOGICREP_HOME='/opt/software/tools/logicrep'
USER_FILE="${LOGICREP_HOME}/create_user.json"
HEALTHY_FILE="/opt/cantian/healthy"
READINESS_FILE="/opt/cantian/readiness"
CMS_CONTAINER_FLAG="/opt/cantian/cms/cfg/container_flag"
SINGLE_FLAG="/opt/cantian/cantian/cfg/single_flag"
DORADO_CONF_PATH="${CURRENT_PATH}/../../config/container_conf/dorado_conf"
DM_USER="DMUser"
DM_PWD="DMPwd"


source ${CURRENT_PATH}/../log4sh.sh

# 创建存活探针
touch ${HEALTHY_FILE}

# 记录pod拉起信息，自动拉起次数
python3 ${CURRENT_PATH}/pod_record.py

# 套餐化更新参数
ret=$(python3 ${CURRENT_PATH}/update_policy_params.py)
if [[ ${ret} -ne 0 ]]; then
    logAndEchoInfo "update policy parmas failed, details: ${ret}"
    exit 1
fi

user=$(cat ${CONFIG_PATH}/${CONFIG_NAME} | grep -Po '(?<="deploy_user": ")[^":\\]*(?:\\.[^"\\]*)*')
cp ${CONFIG_PATH}/${CONFIG_NAME} ${OPT_CONFIG_PATH}/${CONFIG_NAME}
deploy_mode=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_mode")

if [ "${deploy_mode}" == "file" ]; then
    WAIT_TIMES=3600 # 第三方模式拉起时间长
    if ! grep -q '"cluster_id":' ${OPT_CONFIG_PATH}/${CONFIG_NAME}; then
        sed -i '/{/a\    "cluster_id": "0",' ${OPT_CONFIG_PATH}/${CONFIG_NAME}
        sed -i '/{/a\    "cluster_id": "0",' ${CONFIG_PATH}/${CONFIG_NAME}
    fi

    if ! grep -q '"cluster_name":' ${OPT_CONFIG_PATH}/${CONFIG_NAME}; then
        sed -i '/{/a\    "cluster_name": "cantian_file",' ${OPT_CONFIG_PATH}/${CONFIG_NAME}
        sed -i '/{/a\    "cluster_name": "cantian_file",' ${CONFIG_PATH}/${CONFIG_NAME}
    fi

    if ! grep -q '"remote_cluster_name":' ${OPT_CONFIG_PATH}/${CONFIG_NAME}; then
        sed -i '/{/a\    "remote_cluster_name": "cantian_file",' ${OPT_CONFIG_PATH}/${CONFIG_NAME}
        sed -i '/{/a\    "remote_cluster_name": "cantian_file",' ${CONFIG_PATH}/${CONFIG_NAME}
    fi
fi

if ( grep -q 'deploy_user' ${CONFIG_PATH}/${CONFIG_NAME} ); then
    sed -i 's/  "deploy_user": ".*"/  "deploy_user": "'${user}':'${user}'"/g' ${CONFIG_PATH}/${CONFIG_NAME}
    sed -i 's/  "deploy_user": ".*"/  "deploy_user": "'${user}':'${user}'"/g' ${OPT_CONFIG_PATH}/${CONFIG_NAME}
else
    sed -i '2i\  "deploy_user": \"'${user}':'${user}'",' ${CONFIG_PATH}/${CONFIG_NAME}
    sed -i '2i\  "deploy_user": \"'${user}':'${user}'",' ${OPT_CONFIG_PATH}/${CONFIG_NAME}
fi

ulimit -c unlimited
ulimit -l unlimited

storage_share_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_share_fs"`
storage_archive_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_archive_fs"`
storage_metadata_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_metadata_fs"`
node_id=`python3 ${CURRENT_PATH}/get_config_info.py "node_id"`
cms_ip=`python3 ${CURRENT_PATH}/get_config_info.py "cms_ip"`
cantian_user=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_user"`
cantian_group=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_group"`
run_mode=`python3 ${CURRENT_PATH}/get_config_info.py "M_RUNING_MODE"`
deploy_user=`python3 ${CURRENT_PATH}/../get_config_info.py "deploy_user"`
deploy_group=`python3 ${CURRENT_PATH}/../get_config_info.py "deploy_group"`
mes_ssl_switch=`python3 ${CURRENT_PATH}/get_config_info.py "mes_ssl_switch"`
cantian_in_container=`python3 ${CURRENT_PATH}/get_config_info.py "cantian_in_container"`
mysql_metadata_in_cantian=`python3 ${CURRENT_PATH}/get_config_info.py "mysql_metadata_in_cantian"`
cluster_name=`python3 ${CURRENT_PATH}/get_config_info.py "cluster_name"`
cluster_id=`python3 ${CURRENT_PATH}/get_config_info.py "cluster_id"`
primary_keystore="/opt/cantian/common/config/primary_keystore_bak.ks"
standby_keystore="/opt/cantian/common/config/standby_keystore_bak.ks"
VERSION_PATH="/mnt/dbdata/remote/metadata_${storage_metadata_fs}"
gcc_file="/mnt/dbdata/remote/share_${storage_share_fs}/gcc_home/gcc_file"
source_kube_config="/root/.kube/config"
dest_kube_config="/opt/cantian/config/.kube/config"

mkdir -p -m 755 /opt/cantian/config/.kube
cp "$source_kube_config" "$dest_kube_config"
chmod 555 "$dest_kube_config"

if [ ${node_id} -eq 0 ]; then
    node_domain=`echo ${cms_ip} | awk '{split($1,arr,";");print arr[1]}'`
    remote_domain=`echo ${cms_ip} | awk '{split($1,arr,";");print arr[2]}'`
else
    node_domain=`echo ${cms_ip} | awk '{split($1,arr,";");print arr[2]}'`
    remote_domain=`echo ${cms_ip} | awk '{split($1,arr,";");print arr[1]}'`
fi

function change_mtu() {
    ifconfig net1 mtu 5500
    ifconfig net2 mtu 5500
}

function update_mysql_config() {
    local mysql_config_file="${INIT_CONFIG_PATH}/mysql_config.json"
    local my_cnf_file="/opt/cantian/image/cantian_connector/cantian-connector-mysql/scripts/my.cnf"

    logAndEchoInfo "update my.cnf with mem_spec."
    mysql_param=("max_connections")
    for param_name in "${mysql_param[@]}"; do
        param_value=$(python3 "${CURRENT_PATH}/../cantian/get_config_info.py" "${param_name}")
        if [ "${param_value}" != "None" ]; then
            if grep -q "^${param_name}=" "${my_cnf_file}"; then
                sed -i "s/^${param_name}=.*/${param_name}=${param_value}/" "${my_cnf_file}"
                logAndEchoInfo "Updated '${param_name}' with value '${param_value}' in my.cnf."
            else
                echo -e "\n${param_name}=${param_value}" >> "${my_cnf_file}"
                logAndEchoInfo "Added '${param_name}' with value '${param_value}' to my.cnf."
            fi
        fi
    done    
    
    if [ -f "${mysql_config_file}" ]; then
        logAndEchoInfo "mysql_config.json found, updating my.cnf..."

        # 读取 mysql_config.json 更新 my.cnf 置项
        while IFS="=" read -r key value; do
            key=$(echo $key | xargs | tr -d '"')
            value=$(echo $value | xargs | tr -d '"')

            # 处理特定值的逻辑
            if [[ "$value" == "+add" ]]; then
                if grep -q "^${key}" "${my_cnf_file}"; then
                    logAndEchoInfo "Option '${key}' already exists in my.cnf, skipping."
                else
                    echo -e "\n${key}" >> "${my_cnf_file}"
                    logAndEchoInfo "Added '${key}' to my.cnf."
                fi
            elif [[ "$value" == "-del" || "$value" == "-delete" || "$value" == "-remove" ]]; then
                if grep -q "^${key}" "${my_cnf_file}"; then
                    sed -i "/^${key}/d" "${my_cnf_file}"
                    logAndEchoInfo "Removed '${key}' from my.cnf."
                else
                    logAndEchoInfo "Option '${key}' not found in my.cnf, nothing to remove."
                fi
            else
                # 处理普通键值对
                if grep -q "^${key}=" "${my_cnf_file}"; then
                    SPEC_NUM=$(grep "^${key}=" | cut -d= -f2)
                    if [[ "${value}" -lt "${SPEC_NUM}" ]]; then
                        sed -i "s/^${key}=.*/${key}=${value}/" "${my_cnf_file}"
                        logAndEchoInfo "Updated '${key}' with value '${value}' in my.cnf."
                    else
                        logAndEchoInfo "'${key}' up to limit."
                    fi
                else
                    echo -e "\n${key}=${value}" >> "${my_cnf_file}"
                    logAndEchoInfo "Added '${key}' with value '${value}' to my.cnf."
                fi
            fi
        done < <(jq -r 'to_entries|map("\(.key)=\(.value|tostring)")|.[]' "${mysql_config_file}")

        logAndEchoInfo "my.cnf updated successfully."
    fi
}

function wait_config_done() {
    current_domain=$1
    # 等待pod网络配置完成
    logAndEchoInfo "Begin to wait network done. cms_ip: ${current_domain}"
    resolve_times=1
    ping "${current_domain}" -c 1 -w 1
    while [ $? -ne 0 ]
    do
        let resolve_times++
        sleep 5
        if [ ${resolve_times} -eq ${WAIT_TIMES} ]; then
            logAndEchoError "timeout for resolving cms domain name!"
            exit_with_log
        fi
        logAndEchoInfo "wait cms_ip: ${current_domain} ready, it has been ping ${resolve_times} times."
        ping "${current_domain}" -c 1 -w 1
    done
}

function check_mysql_pkg() {
    if [[ "${cantian_in_container}" == "1" ]]; then
        # 归一
        MYSQLD_PKG=/ctdb/cantian_install/Cantian_connector_mysql_*
        if [ "${mysql_metadata_in_cantian,,}" == "false" ];then
            # 非归一 
            mkdir -p /var/lib/mysql-files
            chmod -R 500 /var/lib/mysql-files /var/lib/mysql
            chmod 750 /var/lib/mysql-files /var/lib/mysql
            chown -hR ${deploy_user}:${deploy_group} /var/lib/mysql-files /var/lib/mysql
            MYSQLD_PKG=/ctdb/cantian_install/mysql_*
        fi 
        if [ ! -f ${MYSQLD_PKG} ]; then 
            logAndEchoError "mysql_metadata_in_cantian is ${mysql_metadata_in_cantian}, ${MYSQLD_PKG} is not exist!"
            exit_with_log
        fi
    fi
}

function check_cpu_limit() {
    MY_CPU_NUM=$(cat /proc/1/environ | tr '\0' '\n' | grep MY_CPU_NUM | cut -d= -f2)

    if [[ ! -z "${MY_CPU_NUM}" ]]; then  
        if [[ "${MY_CPU_NUM}" -lt 8 ]]; then
            logAndEchoError "cpu limit cannot be less than 8, current cpu limit is ${MY_CPU_NUM}."
            exit_with_log
        fi
    fi
}

function check_container_context() {
    check_mysql_pkg
    check_cpu_limit
}

function init_container() {
    # 非去nas在后续init_container
    if [ x"${deploy_mode}" != x"dbstor" ]; then
        return 0
    fi
    # Cantian启动前执行init流程，更新各个模块配置文件，初始化cms
    sh ${SCRIPT_PATH}/appctl.sh init_container
    if [ $? -ne 0 ]; then
        exit_with_log
    fi
}

function mount_fs() {
    if [ x"${deploy_mode}" == x"dbstor" ]; then
        logAndEchoInfo "deploy_mode = dbstor, no need to mount file system. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        # 去nas临时创建防止bug，后续版本要删除，权限暂时全开放
        mkdir -m 755 -p /mnt/dbdata/remote/metadata_${storage_metadata_fs}
        mkdir -m 755 -p /mnt/dbdata/remote/share_${storage_share_fs}
        mkdir -m 755 -p /mnt/dbdata/remote/archive_${storage_archive_fs}
        mkdir -m 770 -p /mnt/dbdata/remote/metadata_${storage_metadata_fs}/node0
        chown ${deploy_user}:${cantian_common_group} /mnt/dbdata/remote/metadata_${storage_metadata_fs}/node0
        mkdir -m 770 -p /mnt/dbdata/remote/metadata_${storage_metadata_fs}/node1
        chown ${deploy_user}:${cantian_common_group} /mnt/dbdata/remote/metadata_${storage_metadata_fs}/node1
        chmod 755 /mnt/dbdata/remote
        # 多租会缺少这个标记文件，这里补上
        DEPLOY_MODE_DBSTORE_UNIFY_FLAG=/opt/cantian/deploy/.dbstor_unify_flag
        touch "${DEPLOY_MODE_DBSTORE_UNIFY_FLAG}"
        return 0
    fi
    logAndEchoInfo "Begin to mount file system. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    if [ ! -f ${CURRENT_PATH}/${MOUNT_FILE} ]; then
        logAndEchoError "${MOUNT_FILE} is not exist. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        exit_with_log
    fi

    sh ${CURRENT_PATH}/${MOUNT_FILE}
    if [ $? -ne 0 ]; then
        logAndEchoError "mount file system failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        exit_with_log
    fi
    logAndEchoInfo "mount file system success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
}

function check_version_file() {
    if [ x"${deploy_mode}" == x"dbstor" ]; then
        versions_no_nas=$(su -s /bin/bash - "${cantian_user}" -c 'dbstor --query-file --fs-name='"${storage_share_fs}"' --file-path=/' | grep versions.yml | wc -l)
        if [ ${versions_no_nas} -eq 1 ]; then
            return 0
        else
            return 1
        fi
    else
        if [ -f ${VERSION_PATH}/${VERSION_FILE} ]; then
            return 0
        else
            return 1
        fi
    fi
}

function check_init_status() {
    check_version_file
    if [ $? -eq 0 ]; then
        # 对端节点的cms会使用旧ip建链60s，等待对端节点cms解析新的ip
        logAndEchoInfo "wait remote domain ready."
        wait_config_done "${remote_domain}"
        logAndEchoInfo "The cluster has been initialized, no need create database. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        sed -i "s/\"db_create_status\": \"default\"/\"db_create_status\": \"done\"/g" /opt/cantian/cantian/cfg/${START_STATUS_NAME}
        sed -i "s/\"ever_started\": false/\"ever_started\": true/g" /opt/cantian/cantian/cfg/${START_STATUS_NAME}
        sed -i "s/\"mysql_init\": \"default\"/\"mysql_init\": \"done\"/g" /opt/cantian/cantian/cfg/${START_STATUS_NAME}
        rm -rf ${USER_FILE}
    fi
    
    resolve_times=1
    # 等待节点0启动成功
    check_version_file
    is_version_file_exist=$?

    while [ ${is_version_file_exist} -ne 0 ] && [ ${node_id} -ne 0 ]
    do
        logAndEchoInfo "wait for node 0 pod startup..."
        check_version_file
        is_version_file_exist=$?
        if [ ${resolve_times} -eq ${WAIT_TIMES} ]; then
            logAndEchoError "timeout for wait node 0 startup!"
            exit_with_log
        fi
        let resolve_times++
        sleep 5
    done
}

function prepare_kmc_conf() {
    cp -arf ${KMC_CONFIG_PATH}/standby_keystore.ks /opt/cantian/common/config/
    cp -arf ${KMC_CONFIG_PATH}/primary_keystore.ks /opt/cantian/common/config/
    cp -arf ${KMC_CONFIG_PATH}/standby_keystore.ks /opt/cantian/common/config/standby_keystore_bak.ks
    cp -arf ${KMC_CONFIG_PATH}/primary_keystore.ks /opt/cantian/common/config/primary_keystore_bak.ks
    chown -R ${cantian_user}:${cantian_group} /opt/cantian/common/config/*
}

# 清除信号量
function clear_sem_id() {
    signal_num="0x20161227"
    sem_id=$(lsipc -s -c | grep ${signal_num} | grep -v grep | awk '{print $2}')
    if [ -n "${sem_id}" ]; then
        ipcrm -s ${sem_id}
        if [ $? -ne 0 ]; then
            logAndEchoError "clear sem_id failed"
            tail -f /dev/null
        fi
        logAndEchoInfo "clear sem_id success"
    fi
}

function prepare_certificate() {
    if [[ ${mes_ssl_switch} == "False" ]]; then
        return 0
    fi

    local certificate_dir="/opt/cantian/common/config/certificates"
    mkdir -m 700 -p  "${certificate_dir}"
    local ca_path
    ca_path="${CERT_CONFIG_PATH}"/ca.crt
    local crt_path
    crt_path="${CERT_CONFIG_PATH}"/mes.crt
    local key_path
    key_path="${CERT_CONFIG_PATH}"/mes.key
    cert_password=`cat ${CERT_CONFIG_PATH}/${CERT_PASS}`
    cp -arf "${ca_path}" "${certificate_dir}"/ca.crt
    cp -arf "${crt_path}" "${certificate_dir}"/mes.crt
    cp -arf "${key_path}" "${certificate_dir}"/mes.key
    echo "${cert_password}" > "${certificate_dir}"/mes.pass
    chown -hR "${cantian_user}":"${cantian_group}" "${certificate_dir}"
    su -s /bin/bash - "${cantian_user}" -c "chmod 600 ${certificate_dir}/*"

    tmp_path=${LD_LIBRARY_PATH}
    export LD_LIBRARY_PATH=/opt/cantian/dbstor/lib:${LD_LIBRARY_PATH}
    python3 -B "${CURRENT_PATH}"/resolve_pwd.py "resolve_check_cert_pwd" "${cert_password}"
    if [ $? -ne 0 ]; then
        logAndEchoError "Cert file or passwd check failed."
        exit_with_log
    fi
    export LD_LIBRARY_PATH=${tmp_path}
    clear_sem_id
}

function set_version_file() {
    if [ ! -f ${PKG_PATH}/${VERSION_FILE} ]; then
        logAndEchoError "${VERSION_FILE} is not exist!"
        exit_with_log
    fi
    check_version_file
    is_version_file_exist=$?
    if [ ${is_version_file_exist} -eq 1 ]; then
        if [ x"${deploy_mode}" == x"dbstor" ]; then
            chown "${cantian_user}":"${cantian_group}" "${PKG_PATH}/${VERSION_FILE}"
            su -s /bin/bash - "${cantian_user}" -c 'dbstor --create-file --fs-name='"${storage_share_fs}"' --source-dir='"${PKG_PATH}/${VERSION_FILE}"' --file-name='"${VERSION_FILE}"''
            if [ $? -ne 0 ]; then
                logAndEchoError "Execute dbstor tool command: --create-file failed."
                exit_with_log
            fi
        else
            cp -rf ${PKG_PATH}/${VERSION_FILE} ${VERSION_PATH}/${VERSION_FILE}
        fi
    fi

    if [ -f ${CMS_CONTAINER_FLAG} ]; then
        rm -rf ${CMS_CONTAINER_FLAG}
    fi
}


function start_mysqld() {
    logAndEchoInfo "Begin to start mysqld. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    su -s /bin/bash - ${deploy_user} -c "python3 -B \
        /opt/cantian/image/cantian_connector/CantianKernel/Cantian-DATABASE-CENTOS-64bit/install.py \
        -U ${deploy_user}:${deploy_group} -l /home/${deploy_user}/logs/install.log \
        -M mysqld -m /opt/cantian/image/cantian_connector/cantian-connector-mysql/scripts/my.cnf -g withoutroot"
    if [ $? -ne 0 ]; then
        logAndEchoError "start mysqld failed"
        exit_with_log
    fi
    logAndEchoInfo "start mysqld success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
}

function dr_deploy() {
    dm_user_file="${DORADO_CONF_PATH}/${DM_USER}"
    dm_password_file="${DORADO_CONF_PATH}/${DM_PWD}"

    if [ ! -f "${dm_user_file}" ] || [ ! -f "${dm_password_file}" ]; then
        logAndEchoError "DM User or password file not found."
        exit_with_log
    fi

    dm_user=$(cat "${dm_user_file}")
    dm_password=$(cat "${dm_password_file}")

    role=$(python3 ${CURRENT_PATH}/get_config_info.py "dr_deploy.role")
    if [ "${role}" == "active" ]; then
        expected_dm_user=$(python3 ${CURRENT_PATH}/get_config_info.py "dr_deploy.active.dm_user")
    elif [ "${role}" == "standby" ]; then
        expected_dm_user=$(python3 ${CURRENT_PATH}/get_config_info.py "dr_deploy.standby.dm_user")
    else
        logAndEchoError "Unknown DM role value: ${role}"
        exit_with_log
    fi

    if [ "${dm_user}" != "${expected_dm_user}" ]; then
        logAndEchoError "DM Username does not match. Expected ${expected_dm_user}, but found ${dm_user}."
        exit_with_log
    fi

    ld_path_src=${LD_LIBRARY_PATH}
    export LD_LIBRARY_PATH=/opt/cantian/dbstor/lib:${LD_LIBRARY_PATH}
    password_tmp=$(python3 -B "${CURRENT_PATH}/resolve_pwd.py" "resolve_kmc_pwd" "${dm_password}")
    if [ $? -ne 0 ]; then
        logAndEchoError "Failed to decrypt the  DM password."
        exit_with_log
    fi
    password=$(eval echo ${password_tmp})
    if [ -z "${password}" ]; then
        logAndEchoError "Failed to get dm password"
        exit_with_log
    fi
    export LD_LIBRARY_PATH=${ld_path_src}
    echo -e "${password}" | sh ${SCRIPT_PATH}/appctl.sh dr_operate pre_check ${role} --conf=/opt/cantian/config/deploy_param.json
    if [ $? -ne 0 ]; then
        logAndEchoError "dr_operate pre_check failed."
        exit_with_log
    fi
    logAndEchoInfo "dr_operate pre_check succeeded."

    # 执行 dr_deploy 命令
    echo -e "${password}\n" | sh ${SCRIPT_PATH}/appctl.sh dr_operate deploy ${role} --mysql_cmd='mysql' --mysql_user=root
    if [ $? -ne 0 ]; then
        logAndEchoError "dr_deploy failed."
        exit_with_log
    fi
    logAndEchoInfo "dr_deploy succeeded."
}

function init_start() {
    # 非去nas在这里init_container
    if [ x"${deploy_mode}" != x"dbstor" ]; then
        sh ${SCRIPT_PATH}/appctl.sh init_container
        if [ $? -ne 0 ]; then
            exit_with_log
        fi
    fi

    # 更新 MySQL 配置文件,存在则更新
    update_mysql_config

    # Cantian启动前参数预检查
    logAndEchoInfo "Begin to pre-check the parameters."
    python3 ${PRE_INSTALL_PY_PATH} 'override' ${CONFIG_PATH}/${CONFIG_NAME}
    if [ $? -ne 0 ]; then
        logAndEchoError "parameters pre-check failed."
        exit_with_log
    fi
    logAndEchoInfo "pre-check the parameters success."

    # Cantian启动前先执行升级流程
    sh ${CURRENT_PATH}/container_upgrade.sh
    if [ $? -ne 0 ]; then
        rm -rf ${HEALTHY_FILE}
        exit_with_log
    fi

    role=$(python3 ${CURRENT_PATH}/get_config_info.py "dr_deploy.role")
    dr_setup=$(python3 ${CURRENT_PATH}/get_config_info.py "dr_deploy.dr_setup")
    if [[ X"${dr_setup}" == X"False" ]]; then   
        # Cantian启动
        sh ${SCRIPT_PATH}/appctl.sh start
        if [ $? -ne 0 ]; then
            exit_with_log
        fi
    else
        if [[ X"${role}" == X"active" ]];then
            # Cantian启动
            sh ${SCRIPT_PATH}/appctl.sh start
            if [ $? -ne 0 ]; then
                exit_with_log
            fi
        fi
        # 容灾搭建
        logAndEchoInfo "dr_setup is True, executing dr_deploy tasks."
        dr_deploy
    fi

    set_version_file

    # 安装并拉起MySQL,单进程不执行
    if [[ "${cantian_in_container}" == "1" ]] && [[ "${run_mode}" != "cantiand_with_mysql_in_cluster" ]]; then
        start_mysqld
    fi

    # 创建就绪探针
    touch ${READINESS_FILE}
}

function exit_with_log() {
    # 首次初始化失败，清理gcc_file
    if [ ${node_id} -eq 0 ]; then
        if [[ x"${deploy_mode}" == x"dbstor" ]] && [[ -f ${CMS_CONTAINER_FLAG} ]]; then
            local is_gcc_file_exist=$(su -s /bin/bash - "${cantian_user}" -c 'dbstor --query-file --fs-name='"${storage_share_fs}"' --file-path="gcc_home"' | grep gcc_file | wc -l)
            if [[ ${is_gcc_file_exist} -ne 0 ]]; then
                su -s /bin/bash - "${cantian_user}" -c 'cms gcc -del'
            fi
        else
            if [[ -f ${CMS_CONTAINER_FLAG} ]] && [[ -f ${gcc_file} ]]; then
                rm -rf ${gcc_file}*
            fi
        fi
    fi
    # 失败后保存日志并删除存活探针
    sh ${CURRENT_PATH}/log_backup.sh ${cluster_name} ${cluster_id} ${node_id} ${deploy_user} ${storage_metadata_fs}
    rm -rf ${HEALTHY_FILE}
    tail -f /dev/null
}

function execute_cantian_numa() {
    # 添加cantian-numa命令，实现容器绑核
    ln -sf /ctdb/cantian_install/cantian_connector/action/docker/cantian_numa.py /usr/local/bin/cantian-numa
    chmod +x /ctdb/cantian_install/cantian_connector/action/docker/cantian_numa.py

    /usr/local/bin/cantian-numa
    if [ $? -ne 0 ]; then
        echo "Error occurred in cantian-numa execution."
        return 0
    fi

     logAndEchoInfo "Cantian container initialization completed successfully. [Line:${LINENO}, File:${SCRIPT_NAME}]"
}

function process_logs() {
  while true; do
    /bin/python3 /opt/cantian/common/script/logs_handler/execute.py
    if [ $? -ne 0 ]; then
      echo "Error occurred in execute.py, retrying in 5 seconds..."
      sleep 5
      continue
    fi
    sleep 3600
  done
}

function main() {
    #change_mtu
    wait_config_done "${node_domain}"
    check_container_context
    prepare_kmc_conf
    prepare_certificate
    init_container
    mount_fs
    check_init_status
    init_start
    execute_cantian_numa
    process_logs
}

main