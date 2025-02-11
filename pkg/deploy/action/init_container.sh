#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
DBSTOR_CHECK_FILE=${CURRENT_PATH}/dbstor/check_dbstor_compat.sh
cantian_user=`python3 ${CURRENT_PATH}/cantian/get_config_info.py "deploy_user"`
cantian_group=`python3 ${CURRENT_PATH}/cantian/get_config_info.py "deploy_group"`
deploy_mode=`python3 ${CURRENT_PATH}/cantian/get_config_info.py "deploy_mode"`
storage_share_fs=`python3 ${CURRENT_PATH}/cantian/get_config_info.py "storage_share_fs"`
cluster_name=`python3 ${CURRENT_PATH}/cantian/get_config_info.py "cluster_name"`
node_id=`python3 ${CURRENT_PATH}/cantian/get_config_info.py "node_id"`
storage_metadata_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_metadata_fs"`
storage_dbstor_page_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_dbstor_page_fs"`
metadata_path="/mnt/dbdata/remote/metadata_${storage_metadata_fs}"
dr_setup=`python3 ${CURRENT_PATH}/docker/get_config_info.py "dr_deploy.dr_setup"`

source ${CURRENT_PATH}/env.sh
source ${CURRENT_PATH}/log4sh.sh

# 检查dbstor的user与pwd是否正确
function check_dbstor_usr_passwd() {
    logAndEchoInfo "check username and password of dbstor and check filesystem. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    chown -hR ${cantian_user}:${cantian_group} /opt/cantian/image/Cantian-RUN-CENTOS-64bit/cfg
    su -s /bin/bash - "${cantian_user}" -c "sh ${CURRENT_PATH}/dbstor/check_usr_pwd.sh"
    install_result=$?
    if [ ${install_result} -ne 0 ]; then
        logAndEchoError "check username and password of dbstor or check filesystem failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        exit 1
    else
        logAndEchoInfo "user and password of dbstor check pass and filesystem check pass. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    fi
}

function check_dbstor_client_compatibility() {
    logAndEchoInfo "begin to check dbstor client compatibility."
    if [ ! -f "${DBSTOR_CHECK_FILE}" ];then
        logAndEchoError "${DBSTOR_CHECK_FILE} file is not exists."
        exit 1
    fi
    su -s /bin/bash - "${cantian_user}" -c "sh ${DBSTOR_CHECK_FILE}"
    if [[ $? -ne 0 ]];then
        logAndEchoError "dbstor client compatibility check failed."
        exit 1
    fi
    logAndEchoInfo "dbstor client compatibility check success."
}

function check_gcc_file() {
    # 检查gcc文件
    if [[ ${node_id} -ne 0 ]]; then
        return 0
    fi

    logAndEchoInfo "begin to check versions.yaml and gcc file."
    if [[ x"${deploy_mode}" == x"dbstor" ]]; then
        version_file=$(su -s /bin/bash - "${cantian_user}" \
            -c "dbstor --query-file --fs-name=${storage_share_fs} --file-dir=/" | grep "versions.yml" | wc -l)
    else
        version_file=$(su -s /bin/bash - "${cantian_user}" \
            -c "ls -l ${metadata_path}" | grep "versions.yml" | wc -l)
    fi
    local is_gcc_file_exist=$(su -s /bin/bash - "${cantian_user}" \
        -c 'dbstor --query-file --fs-name='"${storage_share_fs}"' --file-dir="gcc_home"' | grep gcc_file | wc -l)
    if [[ ${version_file} -gt 0 ]] && [[ ${is_gcc_file_exist} -gt 0 ]];then
        logAndEchoInfo "versions.yaml and gcc file is exists."

        logAndEchoInfo "begin to check cluster name."
        is_cluster_name_exist=$(su -s /bin/bash - "${cantian_user}" \
            -c 'dbstor --query-file --fs-name='"${storage_dbstor_page_fs}"' --file-dir=/' | grep "${cluster_name}$" | wc -l)
        if [[ ${is_cluster_name_exist} -eq 0 ]];then
            logAndEchoError "query cluster name failed, please check whether cluster config parameters conflict."
            exit 1
        fi

        if [[ x"${deploy_mode}" == x"dbstor" ]]; then
            start_file=$(su -s /bin/bash - "${cantian_user}" \
                -c "dbstor --query-file --fs-name=${storage_share_fs} --file-dir=/" | grep "onlyStart.file" | wc -l)
        else
            start_file=$(su -s /bin/bash - "${cantian_user}" \
                -c "ls -l ${metadata_path}" | grep "onlyStart.file" | wc -l)
        fi
        if [[ x"${dr_setup}" == x"True" ]] && [[ start_file -gt 0 ]]; then
            logAndEchoError "do not support the automatic disaster recovery process for Cantian that has already been deployed"
            exit 1
        fi
        if [[ x"${deploy_mode}" == x"dbstor" ]]; then
            mkdir -p "${metadata_path}"
            chown "${cantian_user}":"${cantian_group}" "${metadata_path}"
            su -s /bin/bash - "${cantian_user}" \
                -c "dbstor --copy-file --export --fs-name=${storage_share_fs} --source-dir=/ --target-dir=${metadata_path} --file-name=versions.yml"
            if [[ $? -ne 0 ]];then
                logAndEchoError "update local version file failed."
                exit 1
            fi
        fi
        return 0
    elif [[ ${is_gcc_file_exist} -gt 0 ]];then
        logAndEchoError "gcc file already exists, please check if any cluster is running or clustername has been used and not been uninstalled."
        exit 1
    fi
    logAndEchoInfo "gcc file not exist, check success."
}

function init_module() {
    for lib_name in "${INIT_CONTAINER_ORDER[@]}"
    do
        if [[ "${lib_name}" == "dbstor" && x"${deploy_mode}" == x"file" ]]; then
            logAndEchoInfo "Skipping init for ${lib_name} because deploy_mode is 'file'. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            continue
        fi

        logAndEchoInfo "init ${lib_name}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        sh ${CURRENT_PATH}/${lib_name}/appctl.sh init_container >> ${OM_DEPLOY_LOG_FILE} 2>&1
        if [ $? -ne 0 ]; then
            logAndEchoError "init ${lib_name} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            logAndEchoError "For details, see the /opt/cantian/log/${lib_name}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            exit 1
        fi
        logAndEchoInfo "init ${lib_name} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"

        if [[ ${lib_name} = 'dbstor' ]]; then
            check_dbstor_usr_passwd
            # 检查dbstor client 与server端是否兼容
            check_dbstor_client_compatibility
            check_gcc_file
        fi
    done
}

function main() {
    init_module
}

main