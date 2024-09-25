#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
CONFIG_PATH="/mnt/dbdata/local/cantian/tmp/data/cfg"
DORADO_CONF_PATH="${CURRENT_PATH}/../../config/container_conf/dorado_conf"
INIT_CONFIG_PATH="${CURRENT_PATH}/../../config/container_conf/init_conf"
SYS_PASS="sysPass"
CERT_PASS="certPass"
CANTIAN_INSTALL_LOG_FILE="/opt/cantian/cantian/log/cantian_deploy.log"
CANTIAN_CONFIG_NAME="cantiand.ini"
CLUSTER_CONFIG_NAME="cluster.ini"
CTSQL_CONFIG_NAME="ctsql.ini"
CANTIAN_PARAM=("SHM_CPU_GROUP_INFO" "LARGE_POOL_SIZE" "CR_POOL_COUNT" "CR_POOL_SIZE" "TEMP_POOL_NUM" "BUF_POOL_NUM" \
                "LOG_BUFFER_SIZE" "LOG_BUFFER_COUNT" "SHARED_POOL_SIZE" "DATA_BUFFER_SIZE" "TEMP_BUFFER_SIZE" \
                "SESSIONS" "SHM_MEMORY_REDUCTION_RATIO" "SHM_MEMORY_REDUCTION_RATIO" "VARIANT_MEMORY_AREA_SIZE" \
                "DTC_RCY_PARAL_BUF_LIST_SIZE")
CTC_MAX_INST_PER_NODE=1

node_id=`python3 ${CURRENT_PATH}/get_config_info.py "node_id"`
cantian_user=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_user"`
archive_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_archive_fs"`
cluster_id=`python3 ${CURRENT_PATH}/get_config_info.py "cluster_id"`
deploy_mode=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_mode"`
storage_dbstore_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_dbstore_fs"`
cluster_name=`python3 ${CURRENT_PATH}/get_config_info.py "cluster_name"`
max_arch_files_size=`python3 ${CURRENT_PATH}/get_config_info.py "MAX_ARCH_FILES_SIZE"`
cms_ip=`python3 ${CURRENT_PATH}/get_config_info.py "cms_ip"`
mes_ssl_switch=`python3 ${CURRENT_PATH}/get_config_info.py "mes_ssl_switch"`
mysql_metadata_in_cantian=`python3 ${CURRENT_PATH}/get_config_info.py "mysql_metadata_in_cantian"`
storage_metadata_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_metadata_fs"`
primary_keystore="/opt/cantian/common/config/primary_keystore_bak.ks"
standby_keystore="/opt/cantian/common/config/standby_keystore_bak.ks"
mysql_data_dir="/mnt/dbdata/remote/metadata_${storage_metadata_fs}/node${node_id}"

function set_ctsql_config() {
    sys_password=`cat ${DORADO_CONF_PATH}/${SYS_PASS}`
    sed -i -r "s:(SYS_PASSWORD = ).*:\1${sys_password}:g" ${CONFIG_PATH}/${CTSQL_CONFIG_NAME}
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

function set_cantian_config() {
    tmp_path=${LD_LIBRARY_PATH}
    export LD_LIBRARY_PATH=/opt/cantian/dbstor/lib:${LD_LIBRARY_PATH}
    password_tmp=`python3 -B "${CURRENT_PATH}"/../docker/resolve_pwd.py "kmc_to_ctencrypt_pwd" "${sys_password}"`
    export LD_LIBRARY_PATH=${tmp_path}
    clear_sem_id
    # 去除多余空格
    password=`eval echo ${password_tmp}`
    if [ -z "${password}" ]; then
        echo "failed to get _SYS_PASSWORD by ctencrypt" >> ${CANTIAN_INSTALL_LOG_FILE}
        exit 1
    fi
    
    node_domain_0=`echo ${cms_ip} | awk '{split($1,arr,";");print arr[1]}'`
    node_domain_1=`echo ${cms_ip} | awk '{split($1,arr,";");print arr[2]}'`
    if [ -z "${node_domain_1}" ]; then
        node_domain_1="127.0.0.1"
    fi

    if [[ "$deploy_mode" == "dbstor" ]]; then
        sed -i -r "s:(ARCHIVE_DEST_1 = location=).*:\1\/${archive_fs}\/archive:g" ${CONFIG_PATH}/${CANTIAN_CONFIG_NAME}
        sed -i -r "s/(DBSTOR_DEPLOY_MODE = ).*/\11/" ${CONFIG_PATH}/${CANTIAN_CONFIG_NAME}
    else
        sed -i -r "s:(ARCHIVE_DEST_1 = location=/mnt/dbdata/remote/archive_).*:\1${archive_fs}:g" \
            ${CONFIG_PATH}/${CANTIAN_CONFIG_NAME}
    fi

     if [[ "$deploy_mode" == "dbstor" || "$deploy_mode" == "combined" ]]; then
        sed -i -r "s/(ENABLE_DBSTOR = ).*/\1TRUE/" ${CONFIG_PATH}/${CANTIAN_CONFIG_NAME}
    elif [[ "$deploy_mode" == "file" ]]; then
        sed -i -r "s/(ENABLE_DBSTOR = ).*/\1FALSE/" ${CONFIG_PATH}/${CANTIAN_CONFIG_NAME}
        sed -i -r "s/(INTERCONNECT_TYPE = ).*/\1TCP/" ${CONFIG_PATH}/${CANTIAN_CONFIG_NAME}
        sed -i "s|SHARED_PATH.*|SHARED_PATH = /mnt/dbdata/remote/storage_${storage_dbstore_fs}/data|g" ${CONFIG_PATH}/${CANTIAN_CONFIG_NAME}
    else
        echo "Unknown deployment mode: $deploy_mode"
        exit 1
    fi

    sed -i -r "s:(INTERCONNECT_ADDR = ).*:\1${node_domain_0};${node_domain_1}:g" ${CONFIG_PATH}/${CANTIAN_CONFIG_NAME}
    sed -i -r "s:(DBSTOR_NAMESPACE = ).*:\1${cluster_name}:g" ${CONFIG_PATH}/${CANTIAN_CONFIG_NAME}
    sed -i -r "s:(INSTANCE_ID = ).*:\1${node_id}:g" ${CONFIG_PATH}/${CANTIAN_CONFIG_NAME}
    sed -i -r "s:(NODE_ID = ).*:\1${node_id}:g" ${CONFIG_PATH}/${CLUSTER_CONFIG_NAME}
    sed -i -r "s:(MYSQL_DATA_DIR = ).*:\1${mysql_data_dir}:g" ${CONFIG_PATH}/${CLUSTER_CONFIG_NAME}
    sed -i -r "s:(MYSQL_LOG_FILE = ).*:\1${mysql_data_dir}/mysql.log:g" ${CONFIG_PATH}/${CLUSTER_CONFIG_NAME}
    sed -i -r "s:(MAX_ARCH_FILES_SIZE = ).*:\1${max_arch_files_size}:g" ${CONFIG_PATH}/${CANTIAN_CONFIG_NAME}
    sed -i -r "s:(CLUSTER_ID = ).*:\1${cluster_id}:g" ${CONFIG_PATH}/${CANTIAN_CONFIG_NAME}
    sed -i -r "s:(MYSQL_METADATA_IN_CANTIAN = ).*:\1${mysql_metadata_in_cantian^^}:g" ${CONFIG_PATH}/${CANTIAN_CONFIG_NAME}
    sed -i -r "s:(CTC_MAX_INST_PER_NODE = ).*:\1${CTC_MAX_INST_PER_NODE}:g" ${CONFIG_PATH}/${CANTIAN_CONFIG_NAME}
    sed -i -r "s:(_SYS_PASSWORD = ).*:\1${password}:g" ${CONFIG_PATH}/${CANTIAN_CONFIG_NAME}
    if [ ${node_id} == 0 ]; then
        sed -i -r "s:(LSNR_ADDR = ).*:\1127.0.0.1,${node_domain_0}:g" ${CONFIG_PATH}/${CANTIAN_CONFIG_NAME}
    else
        sed -i -r "s:(LSNR_ADDR = ).*:\1127.0.0.1,${node_domain_1}:g" ${CONFIG_PATH}/${CANTIAN_CONFIG_NAME}
    fi

    # 判断单进程，并加入环境变量
    running_mode=$(grep '"M_RUNING_MODE"' /opt/cantian/action/cantian/install_config.json | cut -d '"' -f 4)
    single_mode="multiple"
    if [[ "$running_mode" == "cantiand_with_mysql" ]] ||
        [[ "$running_mode" == "cantiand_with_mysql_in_cluster" ]] ||
        [[ "$running_mode" == "cantiand_with_mysql_in_cluster_st" ]]; then
        single_mode="single"
    fi
    if [ "${single_mode}" == "single" ];then
        echo "MYSQL_CODE_DIR=/opt/cantian/image/cantian_connector/cantian-connector-mysql" >> /home/${cantian_user}/.bashrc
        echo "MYSQL_BIN_DIR=/opt/cantian/mysql/install/mysql" >> /home/${cantian_user}/.bashrc
        echo "MYSQL_DATA_DIR=${mysql_data_dir}" >> /home/${cantian_user}/.bashrc
        echo "MYSQL_LOG_FILE=${mysql_data_dir}/mysql.log" >> /home/${cantian_user}/.bashrc
    fi
    if [[ ${mes_ssl_switch} == "True" ]]; then
        cert_password=`cat ${DORADO_CONF_PATH}/${CERT_PASS}`
        sed -i -r "s:(MES_SSL_KEY_PWD = ).*:\1${cert_password}:g" ${CONFIG_PATH}/${CANTIAN_CONFIG_NAME}
    else
        sed -i -r "s:(MES_SSL_SWITCH = ).*:\1FALSE:g" ${CONFIG_PATH}/${CANTIAN_CONFIG_NAME}
    fi

    # 获取所有NUMA NODE的ID
    nodes=$(ls /sys/devices/system/node/ | grep -E 'node[0-9]+')

    # 遍历每个NUMA NODE，获取对应的CPU数据
    cpus=""
    for node in ${nodes}
    do
        cpu_list=$(cat /sys/devices/system/node/${node}/cpulist)
        cpus="${cpus} ${cpu_list}"
    done
    sed -i -r "s:(SHM_MYSQL_CPU_GROUP_INFO = ).*:\1${cpus}:g" ${CONFIG_PATH}/${CANTIAN_CONFIG_NAME}
    sed -i -r "s:(SHM_CPU_GROUP_INFO = ).*:\1${cpus}:g" ${CONFIG_PATH}/${CANTIAN_CONFIG_NAME}
}

function set_cantian_param() {
    if [ -f ${INIT_CONFIG_PATH}/start_config.json ] || [ -f ${INIT_CONFIG_PATH}/mem_spec ]; then
        for param_name in "${CANTIAN_PARAM[@]}"
        do
            param_value=`python3 ${CURRENT_PATH}/get_config_info.py ${param_name}`
            if [ ! -z ${param_value} ] && [ ${param_value} != "None" ]; then
                sed -i -r "s:(${param_name} = ).*:\1${param_value}:g" ${CONFIG_PATH}/${CANTIAN_CONFIG_NAME}
                if ! grep -q "${param_name}" ${CONFIG_PATH}/${CANTIAN_CONFIG_NAME};then
                  echo "${param_name} = ${param_value}" >> ${CONFIG_PATH}/${CANTIAN_CONFIG_NAME}
                fi
            fi
        done
    fi
}

set_ctsql_config
set_cantian_config
set_cantian_param