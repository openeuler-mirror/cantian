#!/bin/bash
set +x

CURRENT_PATH=$(dirname $(readlink -f $0))
PARENT_DIR_NAME=$(pwd | awk -F "/" '{print $NF}')
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
DORADO_CONF_PATH="${CURRENT_PATH}/../../config/container_conf/dorado_conf"
CERT_PASS="certPass"
CONFIG_PATH="/opt/cantian/cms/cfg"
CLUSTER_CONFIG_NAME="cluster.ini"
CMS_CONFIG_NAME="cms.ini"
CMS_JSON_NAME="cms.json"

storage_share_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_share_fs"`
storage_archive_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_archive_fs"`
cantian_user=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_user"`
cantian_group=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_group"`
node_id=`python3 ${CURRENT_PATH}/get_config_info.py "node_id"`
cms_ip=`python3 ${CURRENT_PATH}/get_config_info.py "cms_ip"`
cluster_id=`python3 ${CURRENT_PATH}/get_config_info.py "cluster_id"`
cluster_name=`python3 ${CURRENT_PATH}/get_config_info.py "cluster_name"`
mes_ssl_switch=`python3 ${CURRENT_PATH}/get_config_info.py "mes_ssl_switch"`
deploy_mode=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_mode"`
gcc_home="/mnt/dbdata/remote/share_${storage_share_fs}/gcc_home"

function set_cms_ip() {
    node_domain_0=`echo ${cms_ip} | awk '{split($1,arr,";");print arr[1]}'`
    node_domain_1=`echo ${cms_ip} | awk '{split($1,arr,";");print arr[2]}'`

    if [ -z "${node_domain_1}" ]; then
        node_domain_1="127.0.0.1"
    fi
    sed -i -r "s:(NODE_IP\[0\] = ).*:\1${node_domain_0}:g" ${CONFIG_PATH}/${CLUSTER_CONFIG_NAME}
    sed -i -r "s:(NODE_IP\[1\] = ).*:\1${node_domain_1}:g" ${CONFIG_PATH}/${CLUSTER_CONFIG_NAME}
    sed -i -r "s:(LSNR_NODE_IP\[0\] = ).*:\1${node_domain_0}:g" ${CONFIG_PATH}/${CLUSTER_CONFIG_NAME}
    sed -i -r "s:(LSNR_NODE_IP\[1\] = ).*:\1${node_domain_1}:g" ${CONFIG_PATH}/${CLUSTER_CONFIG_NAME}
    if [ ${node_id} == 0 ]; then
        sed -i -r "s:(_IP = ).*:\1${node_domain_0}:g" ${CONFIG_PATH}/${CMS_CONFIG_NAME}
    else
        sed -i -r "s:(_IP = ).*:\1${node_domain_1}:g" ${CONFIG_PATH}/${CMS_CONFIG_NAME}
    fi
}

function set_fs() {
    if [ x"${deploy_mode}" == x"dbstore_unify" ]; then
        gcc_home="/${storage_share_fs}/${cluster_name}_cms/gcc_home"
    fi
    sed -i -r "s:(GCC_HOME = ).*:\1${gcc_home}\/gcc_file:g" ${CONFIG_PATH}/${CLUSTER_CONFIG_NAME}
    sed -i -r "s:(GCC_HOME = ).*:\1${gcc_home}\/gcc_file:g" ${CONFIG_PATH}/${CMS_CONFIG_NAME}
    sed -i -r "s:(GCC_DIR = ).*:\1${gcc_home}:g" ${CONFIG_PATH}/${CMS_CONFIG_NAME}
    sed -i -r "s:(FS_NAME = ).*:\1${storage_share_fs}:g" ${CONFIG_PATH}/${CMS_CONFIG_NAME}
    sed -i -r "s:(archive_).*:\1${storage_archive_fs}:g" ${CONFIG_PATH}/${CMS_CONFIG_NAME}
}

function set_cms_cfg() {
    sed -i -r "s:(NODE_ID = ).*:\1${node_id}:g" ${CONFIG_PATH}/${CMS_CONFIG_NAME}
    sed -i -r "s:(CLUSTER_ID = ).*:\1${cluster_id}:g" ${CONFIG_PATH}/${CMS_CONFIG_NAME}
    sed -i -r "s:(_DBSTOR_NAMESPCE = ).*:\1${cluster_name}:g" ${CONFIG_PATH}/${CMS_CONFIG_NAME}
    if [[ ${mes_ssl_switch} == "True" ]]; then
        cert_password=`cat ${DORADO_CONF_PATH}/${CERT_PASS}`
        sed -i -r "s:(_CMS_MES_SSL_KEY_PWD = ).*:\1${cert_password}:g" ${CONFIG_PATH}/${CMS_CONFIG_NAME}
    else
        sed -i -r "s:(_CMS_MES_SSL_SWITCH = ).*:\1False:g" ${CONFIG_PATH}/${CMS_CONFIG_NAME}
    fi
    if [[ x"${deploy_mode}" == x"dbstore_unify" ]]; then
        sed -i -r "s:(GCC_TYPE = ).*:\1DBS:g" ${CONFIG_PATH}/${CMS_CONFIG_NAME}
    fi
}

# 修改cms配置文件
set_cms_ip
set_fs
set_cms_cfg

if [ -f ${CONFIG_PATH}/${CMS_JSON_NAME} ]; then
    rm -rf ${CONFIG_PATH}/${CMS_JSON_NAME}
fi

if [ ${node_id} -eq 0 ] && [ x"${deploy_mode}" != x"dbstore_unify" ]; then
    # 以700权限创建gcc_home
    mkdir -m 700 -p "${gcc_home}"
    chown ${cantian_user}:${cantian_group} -R ${gcc_home}
fi

python3 ${CURRENT_PATH}/cmsctl.py init_container
if [ $? -ne 0 ]; then
    echo "Execute ${SCRIPT_NAME} cmsctl.py init_container failed"
    exit 1
fi