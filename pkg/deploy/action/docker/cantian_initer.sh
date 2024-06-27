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

source ${CURRENT_PATH}/../log4sh.sh

# 创建存活探针
touch ${HEALTHY_FILE}

user=$(cat ${CONFIG_PATH}/${CONFIG_NAME} | grep -Po '(?<="deploy_user": ")[^":\\]*(?:\\.[^"\\]*)*')
cat ${INIT_CONFIG_PATH}/${CONFIG_NAME} > ${CONFIG_PATH}/${CONFIG_NAME}
cat ${INIT_CONFIG_PATH}/${CONFIG_NAME} > ${OPT_CONFIG_PATH}/${CONFIG_NAME}
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

if [ ${node_id} -eq 0 ]; then
    node_domain=`echo ${cms_ip} | awk '{split($1,arr,";");print arr[1]}'`
else
    node_domain=`echo ${cms_ip} | awk '{split($1,arr,";");print arr[2]}'`
fi

function change_mtu() {
    ifconfig net1 mtu 5500
    ifconfig net2 mtu 5500
}

function wait_config_done() {
    # 等待pod网络配置完成
    logAndEchoInfo "Begin to wait network done. cms_ip: ${node_domain}"
    resolve_times=1
    ping ${node_domain} -c 1 -w 1
    while [ $? -ne 0 ]
    do
        let resolve_times++
        sleep 5
        if [ ${resolve_times} -eq ${WAIT_TIMES} ]; then
            logAndEchoError "timeout for resolving cms domain name!"
            exit_with_log
        fi
        logAndEchoInfo "wait cms_ip: ${node_domain} ready, it has been ping ${resolve_times} times."
        ping ${node_domain} -c 1 -w 1
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
        if [[ "${MY_CPU_NUM}" -lt 12 ]]; then  
            logAndEchoError "cpu limit cannot be less than 12, current cpu limit is ${MY_CPU_NUM}."
            exit_with_log
        fi
    fi
}

function check_container_context() {
    check_mysql_pkg
    check_cpu_limit
}

function mount_fs() {
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

function check_init_status() {
    # 对端节点的cms会使用旧ip建链60s，等待对端节点cms解析新的ip
    if [ -f ${VERSION_PATH}/${VERSION_FILE} ]; then
        logAndEchoInfo "The cluster has been initialized, no need create database. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        sed -i "s/\"db_create_status\": \"default\"/\"db_create_status\": \"done\"/g" /opt/cantian/cantian/cfg/${START_STATUS_NAME}
        sed -i "s/\"ever_started\": false/\"ever_started\": true/g" /opt/cantian/cantian/cfg/${START_STATUS_NAME}
        rm -rf ${USER_FILE}
    fi

    resolve_times=1
    # 等待节点0启动成功
    while [ ! -f ${VERSION_PATH}/${VERSION_FILE} ] && [ ${node_id} -ne 0 ]
    do
        logAndEchoInfo "wait for node 0 pod startup..."
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
            exit 1
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

    if [ ! -f ${VERSION_PATH}/${VERSION_FILE} ]; then
        cp -rf ${PKG_PATH}/${VERSION_FILE} ${VERSION_PATH}/${VERSION_FILE}
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

function init_start() {
    # Cantian启动前执行init流程，更新各个模块配置文件，初始化cms
    sh ${SCRIPT_PATH}/appctl.sh init_container
    if [ $? -ne 0 ]; then
        exit_with_log
    fi

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

    # Cantian启动
    sh ${SCRIPT_PATH}/appctl.sh start
    if [ $? -ne 0 ]; then
        exit_with_log
    fi

    set_version_file

    # 安装并拉起MySQL
    if [[ "${cantian_in_container}" == "1" ]]; then
        start_mysqld
    fi

    # 创建就绪探针
    touch ${READINESS_FILE}

    logAndEchoInfo "cantian container init success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
}

function delete_log_if_too_much() {
    local dir_path="$1"
    local max_logs=5 #最大文件限制
    if [ ! -d "${dir_path}" ];then
        logAndEchoError "invalid log dir_path: ${dir_path}"
        exit 1
    fi
    local dirs=$(find ${dir_path} -type d -name "????-??-??-??-??-??*")
    local log_count=$(echo "${dirs}" | wc -l)
    
    if [ "${log_count}" -gt "${max_logs}" ]; then
        logAndEchoInfo "logs > ${max_logs}, begin to delete oldest log"
        local sorted_dirs=$(echo "${dirs}" | sort)
        local oldest_dir=$(echo "${sorted_dirs}" | head -n 1)
        if [ -n "${oldest_dir}" ]; then
            rm -rf "$oldest_dir"
            logAndEchoInfo "found oldest log: ${oldest_dir}, remove complete"
        fi
    fi
}

function exit_with_log() {
    # 首次初始化失败，清理gcc_file
    if [ -f ${CMS_CONTAINER_FLAG} ] && [ -f ${gcc_file} ]; then
        rm -rf ${gcc_file}*
    fi
    # 失败后保存日志并删除存活探针
    DATE=$(date +"%Y-%m-%d-%H-%M-%S")
    mkdir -p /home/mfdb_core/${cluster_name}_${cluster_id}/${DATE}-node${node_id}
    delete_log_if_too_much /home/mfdb_core/${cluster_name}_${cluster_id}
    cd /home/mfdb_core/${cluster_name}_${cluster_id}/${DATE}-node${node_id}
    mkdir cantian cms dbstor core_symbol mysql logicrep
    mkdir cantian/opt cantian/mnt
    mkdir dbstor/opt dbstor/mnt dbstor/ftds dbstor/install
    check_path_and_copy /mnt/dbdata/local/cantian/tmp/data/log cantian/mnt
    check_path_and_copy /mnt/dbdata/local/cantian/tmp/data/cfg cantian/mnt
    check_path_and_copy /opt/cantian/cantian/log cantian/opt
    check_path_and_copy /opt/cantian/deploy cantian/opt
    check_path_and_copy /opt/cantian/cantian_exporter cantian/opt
    check_path_and_copy /opt/cantian/common/config cantian/opt
    check_path_and_copy /opt/cantian/cms/log cms/
    check_path_and_copy /mnt/dbdata/local/cantian/tmp/data/dbstor/data/logs dbstor/mnt
    check_path_and_copy /opt/cantian/cms/dbstor/data/logs dbstor/opt
    check_path_and_copy /opt/cantian/dbstor/data/logs dbstor/install
    check_path_and_copy /mnt/dbdata/local/cantian/tmp/data/dbstor/data/ftds/ftds/data/stat dbstor/ftds
    check_path_and_copy /opt/cantian/cantian/server/bin core_symbol/
    check_path_and_copy /home/${deploy_user}/cantiandinstall.log mysql/
    check_path_and_copy /mnt/dbdata/remote/metadata_${storage_metadata_fs}/node${node_id}/mysql.log mysql/
    check_path_and_copy /opt/software/tools/logicrep/log logicrep/
    check_path_and_copy /opt/software/tools/logicrep/logicrep/run logicrep/
    check_path_and_copy /opt/software/tools/logicrep/logicrep/perf logicrep/
    check_path_and_copy /opt/cantian/logicrep/log/logicrep_deploy.log logicrep/
    rm -rf ${HEALTHY_FILE}
    exit 1
}

function check_path_and_copy() {
    #获取参数
    src_path="$1"
    dst_path="$2"
    #检查是否存在
    if [ -e "${src_path}" ];then
        cp -rf ${src_path} ${dst_path}
    fi
}

function main() {
    #change_mtu
    wait_config_done
    check_container_context
    mount_fs
    check_init_status
    prepare_kmc_conf
    prepare_certificate
    init_start
}

main