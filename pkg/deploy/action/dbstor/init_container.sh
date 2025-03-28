#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
CANTIAN_CONFIG_PATH="/mnt/dbdata/local/cantian/tmp/data/dbstor/conf/dbs"
DBSTOR_CONFIG_PATH="/opt/cantian/dbstor/tools/dbstor_config.ini"
DBSTOR_CONFIG_NAME="dbstor_config.ini"
DORADO_CONF_PATH="${CURRENT_PATH}/../../config/container_conf/dorado_conf"
DBSTOR_USER="dbstorUser"
DBSTOR_PWD="dbstorPwd"

function set_dbstor_config() {
    deploy_mode=`python3 ${CURRENT_PATH}/../cantian/get_config_info.py "deploy_mode"`
    storage_dbstor_fs=`python3 ${CURRENT_PATH}/../cantian/get_config_info.py "storage_dbstor_fs"`
    storage_dbstor_page_fs=`python3 ${CURRENT_PATH}/../cantian/get_config_info.py "storage_dbstor_page_fs"`
    storage_share_fs=`python3 ${CURRENT_PATH}/../cantian/get_config_info.py "storage_share_fs"`
    storage_archive_fs=`python3 ${CURRENT_PATH}/../cantian/get_config_info.py "storage_archive_fs"`
    link_type=`python3 ${CURRENT_PATH}/../cantian/get_config_info.py "link_type"`
    node_id=`python3 ${CURRENT_PATH}/../cantian/get_config_info.py "node_id"`
    cluster_id=`python3 ${CURRENT_PATH}/../cantian/get_config_info.py "cluster_id"`
    log_vstor=`python3 ${CURRENT_PATH}/../cantian/get_config_info.py "dbstor_fs_vstore_id"`
    
    cantian_vlan_name=`python3 ${CURRENT_PATH}/../cantian/get_config_info.py "cantian_vlan_ip"`
    cantian_vlan_ip=""
    dbstor_log_path="/opt/cantian/log/dbstor"

    # vlan_ip分割符支持分号（;）和竖线（|）
    if [[ "${cantian_vlan_name}" == *";"* ]]; then
        separator=";"
    elif [[ "${cantian_vlan_name}" == *"|"* ]]; then
        separator="|"
    else
        separator=""
    fi

    if [[ -n "${separator}" ]]; then
        IFS="${separator}" read -ra vlan_names <<< "${cantian_vlan_name}"
    else
        vlan_names=("${cantian_vlan_name}")
    fi

    for vlan_name in "${vlan_names[@]}"; do
        if [[ ${vlan_name} =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
            if [ -n "${cantian_vlan_ip}" ]; then
                cantian_vlan_ip+="${separator}"
            fi
            cantian_vlan_ip+="${vlan_name}"
        else
            vlan_ip=$(ip add show dev ${vlan_name} | grep -w 'inet' | awk '{print $2}' | awk -F '/' '{print $1}')
            if [ -n "${vlan_ip}" ]; then
                if [ -n "${cantian_vlan_ip}" ]; then
                    cantian_vlan_ip+="${separator}"
                fi
                cantian_vlan_ip+="${vlan_ip}"
            else
                echo "No IP address found for interface ${vlan_name}"
            fi
        fi
    done

    storage_vlan_ip=`python3 ${CURRENT_PATH}/../cantian/get_config_info.py "storage_vlan_ip"`
    dpu_uuid=`uuidgen`
    dbstor_user=`cat ${DORADO_CONF_PATH}/${DBSTOR_USER}`
    dbstor_pwd=`cat ${DORADO_CONF_PATH}/${DBSTOR_PWD}`

    sed -i -r "s:(NAMESPACE_FSNAME = ).*:\1${storage_dbstor_fs}:g" ${DBSTOR_CONFIG_PATH}
    sed -i -r "s:(NAMESPACE_PAGE_FSNAME = ).*:\1${storage_dbstor_page_fs}:g" ${DBSTOR_CONFIG_PATH}
    sed -i -r "s:(DPU_UUID = ).*:\1${dpu_uuid}:g" ${DBSTOR_CONFIG_PATH}
    sed -i -r "s:(LINK_TYPE = ).*:\1${link_type}:g" ${DBSTOR_CONFIG_PATH}
    sed -i -r "s:(LOCAL_IP = ).*:\1${cantian_vlan_ip}:g" ${DBSTOR_CONFIG_PATH}
    sed -i -r "s:(REMOTE_IP = ).*:\1${storage_vlan_ip}:g" ${DBSTOR_CONFIG_PATH}
    sed -i -r "s:(USER_NAME = ).*:\1${dbstor_user}:g" ${DBSTOR_CONFIG_PATH}
    sed -i -r "s:(PASSWORD = ).*:\1${dbstor_pwd}:g" ${DBSTOR_CONFIG_PATH}
    sed -i -r "s:(NODE_ID = ).*:\1${node_id}:g" ${DBSTOR_CONFIG_PATH}
    sed -i -r "s:(CLUSTER_ID = ).*:\1${cluster_id}:g" ${DBSTOR_CONFIG_PATH}
    sed -i -r "s:(LOG_VSTOR = ).*:\1${log_vstor}:g" ${DBSTOR_CONFIG_PATH}
    sed -i -r "s:(DBS_LOG_PATH = ).*:\1${dbstor_log_path}:g" ${DBSTOR_CONFIG_PATH}
    sed -i -r "s:(NAMESPACE_SHARE_FSNAME = ).*:\1${storage_share_fs}:g" ${DBSTOR_CONFIG_PATH}
    sed -i -r "s:(NAMESPACE_ARCHIVE_FSNAME = ).*:\1${storage_archive_fs}:g" ${DBSTOR_CONFIG_PATH}
    python3 ${CURRENT_PATH}/init_unify_config.py
}

function cantian_copy_dbstor_config() {
    cp -arf ${DBSTOR_CONFIG_PATH} ${CANTIAN_CONFIG_PATH}/${DBSTOR_CONFIG_NAME}
    echo 'DBSTOR_OWNER_NAME = cantian' >> ${CANTIAN_CONFIG_PATH}/${DBSTOR_CONFIG_NAME}
    sed -i '/^$/d' ${CANTIAN_CONFIG_PATH}/${DBSTOR_CONFIG_NAME}
}

set_dbstor_config
cantian_copy_dbstor_config