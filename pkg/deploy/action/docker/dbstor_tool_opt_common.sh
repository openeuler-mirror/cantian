#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))

deploy_mode=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_mode"`
storage_share_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_share_fs"`
storage_share_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_share_fs"`
storage_metadata_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_metadata_fs"`
cantian_in_container=`python3 ${CURRENT_PATH}/get_config_info.py "cantian_in_container"`
node_id=`python3 ${CURRENT_PATH}/get_config_info.py "node_id"`
lock_file_prefix=upgrade_lock_
METADATA_FS_PATH="/mnt/dbdata/remote/metadata_${storage_metadata_fs}"
VERSION_FILE="versions.yml"


if [[ -f "${CURRENT_PATH}"/../log4sh.sh ]];then
    # 容器内source路径
    source "${CURRENT_PATH}"/../log4sh.sh
    source "${CURRENT_PATH}"/../env.sh
    PKG_PATH="${CURRENT_PATH}"/../../
else
    # 物理部署source路径
    source "${CURRENT_PATH}"/log4sh.sh
    source "${CURRENT_PATH}"/env.sh
    PKG_PATH="${CURRENT_PATH}"/../
fi

#---------container dbstor upgrade prepare------#
#   去NAS场景从文件系统中将升级文件拷贝到本地
#   在本地做判断，保持升级流程与原流程一致，仅
#   需要更新状态时，再拷贝对应文件至文件系统
#-----------------------------------------------#
function update_local_status_file_path_by_dbstor() {
    if [[ "${deploy_mode}" != "dbstor" ]];then
        return 0
    fi
    chown "${cantian_user}":"${cantian_group}" ${METADATA_FS_PATH}
    if [[ "${cantian_in_container}" != "0" ]];then
        # 容器内需要根据versions.yaml判断是否需要升级
        version_file=$(su -s /bin/bash - "${cantian_user}" -c "dbstor --query-file \
        --fs-name=${storage_share_fs} --file-path=/ | grep versions\.yml" | wc -l)
        if [[ ${version_file} -eq 0 ]];then
            return 0
        fi
        if [[ -f ${METADATA_FS_PATH}/versions.yml ]];then
            rm -rf "${METADATA_FS_PATH}"/versions.yml
        fi
        su -s /bin/bash - "${cantian_user}" -c "dbstor --copy-file --fs-name=${storage_share_fs} \
        --source-dir=/ --target-dir=${METADATA_FS_PATH} --file-name=versions.yml"
        if [[ $? -ne 0 ]];then
            logAndEchoError "Copy versions.yml from fs to local failed."
            exit 0
        fi
    fi
    upgrade_dir=$(su -s /bin/bash - "${cantian_user}" -c "dbstor --query-file \
    --fs-name=${storage_share_fs} --file-path=/" | grep -E "^upgrade$" | grep -v grep | wc -l)

    if [[ ${upgrade_dir} -eq 0 ]];then
        return 0
    fi
    if [[ -d ${METADATA_FS_PATH}/upgrade ]];then
        rm -rf "${METADATA_FS_PATH}"/upgrade
    fi
    mkdir -p -m 755 "${METADATA_FS_PATH}"/upgrade
    chown "${cantian_user}":"${cantian_group}" "${METADATA_FS_PATH}"/upgrade
    su -s /bin/bash - "${cantian_user}" -c "dbstor --copy-file \
    --fs-name=${storage_share_fs} --source-dir=/upgrade/ --target-dir=${METADATA_FS_PATH}/upgrade/"

    if [[ $? -ne 0 ]];then
        logAndEchoError "Copy upgrade path [upgrade] from fs to local failed."
        exit 0
    fi
    upgrade_dir=$(su -s /bin/bash - "${cantian_user}" -c "dbstor --query-file \
    --fs-name=${storage_share_fs} --file-path=/upgrade" | grep -E "^cluster_and_node_status" | grep -v grep | wc -l)

    if [[ ${upgrade_dir} -eq 0 ]];then
        return 0
    fi
    mkdir -p -m 755 "${METADATA_FS_PATH}"/upgrade/cluster_and_node_status
    chown "${cantian_user}":"${cantian_group}" "${METADATA_FS_PATH}"/upgrade/cluster_and_node_status
    su -s /bin/bash - "${cantian_user}" -c "dbstor --copy-file --fs-name=${storage_share_fs} \
    --source-dir=/upgrade/cluster_and_node_status/ --target-dir=${METADATA_FS_PATH}/upgrade/cluster_and_node_status/"

    if [[ $? -ne 0 ]];then
        logAndEchoError "Copy upgrade path [cluster_and_node_status] from fs to local failed."
        exit 0
    fi
}

function update_remote_status_file_path_by_dbstor() {
    if [[ "${deploy_mode}" != "dbstor" ]];then
        return 0
    fi
    cluster_or_node_status_file_path=$1
    file_name=$(basename ${cluster_or_node_status_file_path})
    chown -hR "${cantian_user}":"${cantian_group}" ${METADATA_FS_PATH}/upgrade
    relative_path=$(realpath --relative-to="${METADATA_FS_PATH}"/upgrade "${cluster_or_node_status_file_path}")
    if [[ -d "${METADATA_FS_PATH}"/upgrade/"${relative_path}" ]];then
        chmod 755 "${METADATA_FS_PATH}"/upgrade/"${relative_path}"
    fi
    if [[ -f "${METADATA_FS_PATH}"/upgrade/"${relative_path}" ]];then
        chmod 600 "${METADATA_FS_PATH}"/upgrade/"${relative_path}"
    fi
    su -s /bin/bash - "${cantian_user}" -c "dbstor --create-file --fs-name=${storage_share_fs} \
    --file-name=/upgrade/${relative_path} --source-dir=${METADATA_FS_PATH}/upgrade/${relative_path}"

    if [[ $? -ne 0 ]];then
        logAndEchoError "Copy upgrade path from local to fs failed."
        exit 0
    fi
}

function delete_fs_upgrade_file_or_path_by_dbstor() {
    if [[ "${deploy_mode}" != "dbstor" ]];then
        return 0
    fi
    local file_name=$1
    logAndEchoInfo "Start to delete ${file_name} in file path ${file_path}"
    declare -a upgrade_dirs
    # shellcheck disable=SC2207
    upgrade_dirs=($(su -s /bin/bash - "${cantian_user}" -c "dbstor --query-file --fs-name=${storage_share_fs} \
    --file-path=/upgrade" | grep -E "${file_name}"))

    array_length=${#upgrade_dirs[@]}
    if [[ "${array_length}" -gt 0 ]];then
        for _file in "${upgrade_dirs[@]}";
        do
            su -s /bin/bash - "${cantian_user}" -c "dbstor --delete-file \
            --fs-name=${storage_share_fs} --file-name=/upgrade/${_file}"
        done
    fi
}

function update_version_yml_by_dbstor() {
    if [[ "${deploy_mode}" != "dbstor" ]];then
        return 0
    fi
    chown "${cantian_user}":"${cantian_group}" "${PKG_PATH}/${VERSION_FILE}"
    su -s /bin/bash - "${cantian_user}" -c "dbstor --create-file --fs-name=${storage_share_fs} \
    --source-dir=${PKG_PATH}/${VERSION_FILE} --file-name=${VERSION_FILE}"

    if [ $? -ne 0 ]; then
        logAndEchoError "Execute dbstor tool command: --create-file failed."
        exit 1
    fi
}

function upgrade_lock_by_dbstor() {
    if [[ "${deploy_mode}" != "dbstor" ]];then
        return 0
    fi
    node_lock_file=${lock_file_prefix}${node_id}
    upgrade_nodes=($(su -s /bin/bash - "${cantian_user}" -c "dbstor --query-file \
    --fs-name=${storage_share_fs} --file-path=/upgrade" | grep -E "${lock_file_prefix}"))
    nodes_length=${#upgrade_nodes[@]}
    if [[ ${nodes_length} -gt 1 ]];then
        logAndEchoError "Exist upgrade node , details:${upgrade_nodes}"
        exit 1
    fi
    if [[ ${nodes_length} -eq 1 ]] && [[ "${upgrade_nodes[0]}" != "${node_lock_file}" ]];then
        logAndEchoError "Exist upgrade node , details:${upgrade_nodes}"
        exit 1
    fi
    if [[ ${nodes_length} -eq 1 ]] && [[ "${upgrade_nodes[0]}" == "${node_lock_file}" ]];then
        return 0
    fi
    su -s /bin/bash - "${cantian_user}" -c "dbstor --create-file --fs-name=${storage_share_fs} \
    --file-name=/upgrade/${node_lock_file}"
    if [[ $? -ne 0 ]];then
        logAndEchoError "upgrade lock failed"
        exit 1
    fi
    return 0
}

function upgrade_unlock_by_dbstor() {
    if [[ "${deploy_mode}" != "dbstor" ]];then
        return 0
    fi
    node_lock_file=${lock_file_prefix}${node_id}
    lock_file=$(su -s /bin/bash - "${cantian_user}" -c "dbstor --query-file --fs-name=${storage_share_fs} \
    --file-path=/upgrade" | grep  "${node_lock_file}" | wc -l)

    if [[ ${lock_file} -eq 0 ]];then
        return 0
    fi
    su -s /bin/bash - "${cantian_user}" -c "dbstor --delete-file --fs-name=${storage_share_fs} \
    --file-name=/upgrade/${node_lock_file}"

    if [ $? -ne 0 ]; then
        logAndEchoError "Execute clear lock file failed."
        exit 1
    fi
    return 0
}