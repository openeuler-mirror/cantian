#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))

deploy_mode=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_mode"`
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

function get_dbs_version() {
  out=$(su -s /bin/bash - "${cantian_user}" -c "dbstor --query-file --fs-name=${storage_share_fs} --file-dir=/" )
  if [[ $? -ne 0 ]];then
    logAndEchoInfo "Failed to execute dbstor --query-file, dbstor version is old."
    return 1
  else
    return 2
  fi
}

function query_filesystem() {
    dbs_version=$1
    fs=$2
    if [[ $# -gt 2 ]];then
      dir=$3
    else
      dir="/"
    fi
    if [[ x"${dbs_version}" == x"1" ]]; then
      su -s /bin/bash - "${cantian_user}" -c "dbstor --query-file --fs-name=${fs} --file-path=${dir}"
    else
      su -s /bin/bash - "${cantian_user}" -c "dbstor --query-file --fs-name=${fs} --file-dir=${dir}"
    fi
}

function copy_file_from_filesystem() {
    dbs_version=$1
    fs=$2
    source_dir=$3
    target_dir=$4
    if [[ $# -gt 4 ]];then
      file_name=$5
    else
      file_name=""
    fi

    if [[ x"${dbs_version}" == x"1" ]]; then
      if [[ x"${file_name}" == "x" ]];then
        out=$(su -s /bin/bash - "${cantian_user}" -c "dbstor --copy-file --fs-name=${fs} \
        --source-dir=${source_dir} --target-dir=${target_dir}" )
      else
        out=$(su -s /bin/bash - "${cantian_user}" -c "dbstor --copy-file --fs-name=${fs} \
        --source-dir=${source_dir} --target-dir=${target_dir} --file-name=${file_name}" )
      fi
    else
      if [[ x"${file_name}" == "x" ]];then
        out=$(su -s /bin/bash - "${cantian_user}" -c "dbstor --copy-file --export --fs-name=${fs} \
        --source-dir=${source_dir} --target-dir=${target_dir} --overwrite" )
      else
        out=$(su -s /bin/bash - "${cantian_user}" -c "dbstor --copy-file --export --fs-name=${fs} \
        --source-dir=${source_dir} --target-dir=${target_dir} --file-name=${file_name} --overwrite" )
      fi
    fi
    result=$?
    if [[ ${result} -ne 0 ]];then
      logAndEchoError "Failed to execute dbstor --copy-file --export, fs[${fs}], \
      source_dir[${source_dir}], target_dir[${target_dir}], file_name[${file_name}], dbs_version[${dbs_version}]."
    fi
    return ${result}
}

function copy_file_to_filesystem() {
    dbs_version=$1
    fs=$2
    source_dir=$3
    target_dir=$4
    if [[ $# -gt 4 ]];then
      file_name=$5
    else
      file_name=""
    fi

    if [[ x"${dbs_version}" == x"1" ]]; then
      out=$(su -s /bin/bash - "${cantian_user}" -c "dbstor --create-file --fs-name=${fs} \
    --file-name=/${target_dir}/${file_name} --source-dir=${source_dir}/${file_name}" )
    else
      if [[ x"${file_name}" == "x" ]];then
        out=$(su -s /bin/bash - "${cantian_user}" -c "dbstor --copy-file --import --fs-name=${fs} \
        --source-dir=${source_dir} --target-dir=${target_dir} --file-name=${file_name} --overwrite" )
      else
        out=$(su -s /bin/bash - "${cantian_user}" -c "dbstor --copy-file --import --fs-name=${fs} \
        --source-dir=${source_dir} --target-dir=${target_dir} --file-name=${file_name} --overwrite" )
      fi
    fi
    result=$?
    if [[ ${result} -ne 0 ]];then
      logAndEchoError "Failed to execute dbstor --copy-file --import, fs[${fs}], \
      source_dir[${source_dir}], target_dir[${target_dir}], file_name[${file_name}], dbs_version[${dbs_version}]."
    fi
    return ${result}
}

function create_file_in_filesystem() {
    dbs_version=$1
    fs=$2
    file_dir=$3
    if [[ $# -gt 3 ]];then
      file_name=$4
    else
      file_name=""
    fi

    if [[ x"${dbs_version}" == x"1" ]]; then
      out=$(su -s /bin/bash - "${cantian_user}" -c "dbstor --create-file --fs-name=${fs} --file-name=${file_dir}/${file_name}" )
    else
      if [[ x"${file_name}" == "x" ]];then
        out=$(su -s /bin/bash - "${cantian_user}" -c "dbstor --create-file --fs-name=${fs} --file-dir=${file_dir}" )
      else
        out=$(su -s /bin/bash - "${cantian_user}" -c "dbstor --create-file --fs-name=${fs} --file-dir=${file_dir} --file-name=${file_name}" )
      fi
    fi
    result=$?
    if [[ ${result} -ne 0 ]];then
      logAndEchoError "Failed to execute dbstor --create-file, fs[${fs}], \
      file_dir[${file_dir}], file_name[${file_name}], dbs_version[${dbs_version}]."
    fi
    return ${result}
}

function update_local_status_file_path_by_dbstor() {
    if [[ "${deploy_mode}" != "dbstor" ]];then
        return 0
    fi
    chown "${cantian_user}":"${cantian_group}" ${METADATA_FS_PATH}
    get_dbs_version
    dbs_vs=$?
    if [[ "${cantian_in_container}" != "0" ]];then
        # 容器内需要根据versions.yaml判断是否需要升级
        version_file=$(query_filesystem ${dbs_vs} ${storage_share_fs} | grep "versions.yml" | wc -l)
        if [[ ${version_file} -eq 0 ]];then
            return 0
        fi
        if [[ -f ${METADATA_FS_PATH}/versions.yml ]];then
            rm -rf "${METADATA_FS_PATH}"/versions.yml
        fi
      copy_file_from_filesystem ${dbs_vs} ${storage_share_fs} "/" ${METADATA_FS_PATH} ${VERSION_FILE}
        if [[ $? -ne 0 ]];then
            logAndEchoError "Copy versions.yml from fs to local failed."
            exit 0
        fi
    fi
    upgrade_dir=$(query_filesystem ${dbs_vs} ${storage_share_fs} | grep -E "upgrade$" | grep -v grep | wc -l)

    if [[ ${upgrade_dir} -eq 0 ]];then
        return 0
    fi
    if [[ -d ${METADATA_FS_PATH}/upgrade ]];then
        rm -rf "${METADATA_FS_PATH}"/upgrade
    fi
    mkdir -p -m 755 "${METADATA_FS_PATH}"/upgrade
    chown "${cantian_user}":"${cantian_group}" "${METADATA_FS_PATH}"/upgrade
    copy_file_from_filesystem ${dbs_vs} ${storage_share_fs} "/upgrade" "${METADATA_FS_PATH}/upgrade"

    if [[ $? -ne 0 ]];then
        logAndEchoError "Copy upgrade path [upgrade] from fs to local failed."
        exit 0
    fi
    upgrade_dir=$(query_filesystem ${dbs_vs} ${storage_share_fs} "/upgrade" | grep -E "cluster_and_node_status" | grep -v grep | wc -l)

    if [[ ${upgrade_dir} -eq 0 ]];then
        return 0
    fi
    mkdir -p -m 755 "${METADATA_FS_PATH}"/upgrade/cluster_and_node_status
    chown "${cantian_user}":"${cantian_group}" "${METADATA_FS_PATH}"/upgrade/cluster_and_node_status
    copy_file_from_filesystem ${dbs_vs} ${storage_share_fs} "/upgrade/cluster_and_node_status/" "${METADATA_FS_PATH}/upgrade/cluster_and_node_status/"

    if [[ $? -ne 0 ]];then
        logAndEchoError "Copy upgrade path [cluster_and_node_status] from fs to local failed."
        exit 0
    fi
}

function update_remote_status_file_path_by_dbstor() {
    if [[ "${deploy_mode}" != "dbstor" ]];then
        return 0
    fi
    get_dbs_version
    dbs_vs=$?
    cluster_or_node_status_file_path=$1
    chown -hR "${cantian_user}":"${cantian_group}" ${METADATA_FS_PATH}/upgrade
    if [[ -d ${cluster_or_node_status_file_path} ]];then
      relative_path=$(realpath --relative-to="${METADATA_FS_PATH}"/upgrade "${dir_path}")
      if [[ "${relative_path}" == "." ]];then
          relative_path=""
      fi
      chmod 755 "${METADATA_FS_PATH}"/upgrade/"${relative_path}"
      copy_file_to_filesystem ${dbs_vs} ${storage_share_fs} "${METADATA_FS_PATH}/upgrade/${relative_path}" "/upgrade/${relative_path}"
    else
      file_name=$(basename ${cluster_or_node_status_file_path})
      dir_path=$(dirname "${cluster_or_node_status_file_path}")
      relative_path=$(realpath --relative-to="${METADATA_FS_PATH}"/upgrade "${dir_path}")
      if [[ "${relative_path}" == "." ]];then
          relative_path=""
      fi
      if [[ -d "${METADATA_FS_PATH}"/upgrade/"${relative_path}" ]];then
          chmod 755 "${METADATA_FS_PATH}"/upgrade/"${relative_path}"
      fi
      if [[ -f "${METADATA_FS_PATH}"/upgrade/"${relative_path}" ]];then
          chmod 600 "${METADATA_FS_PATH}"/upgrade/"${relative_path}"
      fi
      copy_file_to_filesystem ${dbs_vs} ${storage_share_fs} "${METADATA_FS_PATH}/upgrade/${relative_path}" "/upgrade/${relative_path}" ${file_name}
    fi

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
    get_dbs_version
    dbs_vs=$?
    upgrade_dirs=($(query_filesystem ${dbs_vs} ${storage_share_fs} "/upgrade" | grep -E "${file_name}"))

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
    get_dbs_version
    dbs_vs=$?
    copy_file_to_filesystem ${dbs_vs} ${storage_share_fs} ${PKG_PATH} "/" ${VERSION_FILE}

    if [ $? -ne 0 ]; then
        logAndEchoError "Execute dbstor tool command: --copy-file failed."
        exit 1
    fi
}

function upgrade_lock_by_dbstor() {
    if [[ "${deploy_mode}" != "dbstor" ]];then
        return 0
    fi
    node_lock_file=${lock_file_prefix}${node_id}
    get_dbs_version
    dbs_vs=$?
    upgrade_nodes=$(query_filesystem ${dbs_vs} ${storage_share_fs} "/upgrade" | grep -E "${lock_file_prefix}" | wc -l)
    if [[ ${upgrade_nodes} -gt 1 ]];then
      logAndEchoError "Exist other upgrade node , details:${upgrade_nodes}"
      exit 1
    fi
    upgrade_num=$(query_filesystem ${dbs_vs} ${storage_share_fs} "/upgrade" | grep -E "${node_lock_file}" | wc -l)
    if [[ ${upgrade_nodes} -eq 1 ]] && [[ ${upgrade_num} -eq 0 ]]; then
      logAndEchoError "Exist upgrade node , details:${upgrade_nodes}"
      exit 1
    fi
    if [[ ${upgrade_num} -eq 1 ]]; then
      return 0
    fi 

    create_file_in_filesystem ${dbs_vs} ${storage_share_fs} "/upgrade" ${node_lock_file}
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
    get_dbs_version
    dbs_vs=$?
    node_lock_file=${lock_file_prefix}${node_id}
    lock_file=$(query_filesystem ${dbs_vs} ${storage_share_fs} "upgrade" | grep  "${node_lock_file}" | wc -l)

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