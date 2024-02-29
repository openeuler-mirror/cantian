#!/bin/bash
set +x

CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)

cluster_or_node=$1
storage_metadata_fs_path=""
cluster_and_node_status_path=""
cluster_status_flag=""
node_status_flag=""

# 输入参数校验
function input_params_validation() {
    if [ "${cluster_or_node}" == "cluster" ]; then
        return 0
    fi

    node_reg_match=$(echo ${cluster_or_node} | grep -v grep | grep -E "^node[0-9]+")
    if [ -n "${node_reg_match}" ]; then
        return 0
    fi
    echo "[error] the input parameter can only be 'cluster' or 'nodex', where 'x' is a specific number, instead of '${cluster_or_node}'" && exit 1
}

# 初始化集群状态flag
function init_cluster_status_flag() {
    source_version=$(python3 ${CURRENT_PATH}/implement/get_source_version.py)
    if [ -z "${source_version}" ]; then
        echo "[error] failed to obtain source version" && exit 1
    fi

    storage_metadata_fs=$(python3 ${CURRENT_PATH}/get_config_info.py "storage_metadata_fs")
    if [[ ${storage_metadata_fs} == 'None' ]]; then
        echo "[error] obtain current node storage_metadata_fs_name error, please check file: config/deploy_param.json" && exit 1
    fi

    storage_metadata_fs_path="/mnt/dbdata/remote/metadata_${storage_metadata_fs}/upgrade/rollup_bak_${source_version}"
    cluster_and_node_status_path="${storage_metadata_fs_path}/cluster_and_node_status"
    cluster_status_flag="${cluster_and_node_status_path}/cluster_status.txt"
    node_status_flag="${cluster_and_node_status_path}/${cluster_or_node}_status.txt"
}

# 集群状态查询
function cluster_status_query() {
    if [ -z "${cluster_status_flag}" ] || [ ! -e "${cluster_status_flag}" ]; then
        echo "[error] cluster status file '${cluster_status_flag}' does not exist" && exit 1
    fi
    echo "$(cat "${cluster_status_flag}")"
}

# 节点状态查询
function node_status_query() {
    if [ -z "${node_status_flag}" ] || [ ! -e "${node_status_flag}" ]; then
        echo "[error] node status file '${node_status_flag}' does not exist" && exit 1
    fi
    echo "$(cat "${node_status_flag}")"
}

# 主函数入口
function main() {
    input_params_validation
    init_cluster_status_flag
    if [ "${cluster_or_node}" == "cluster" ]; then
        cluster_status_query
    else
        node_status_query
    fi
}

main
