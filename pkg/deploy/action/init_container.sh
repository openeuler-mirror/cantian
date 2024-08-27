#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
DBSTORE_CHECK_FILE=${CURRENT_PATH}/dbstor/check_dbstor_compat.sh
cantian_user=`python3 ${CURRENT_PATH}/cantian/get_config_info.py "deploy_user"`
cantian_group=`python3 ${CURRENT_PATH}/cantian/get_config_info.py "deploy_group"`
deploy_mode=`python3 ${CURRENT_PATH}/cantian/get_config_info.py "deploy_mode"`
storage_share_fs=`python3 ${CURRENT_PATH}/cantian/get_config_info.py "storage_share_fs"`
cluster_name=`python3 ${CURRENT_PATH}/cantian/get_config_info.py "cluster_name"`
node_id=`python3 ${CURRENT_PATH}/cantian/get_config_info.py "node_id"`
storage_metadata_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_metadata_fs"`
metadata_path="/mnt/dbdata/remote/metadata_${storage_metadata_fs}"

source ${CURRENT_PATH}/env.sh
source ${CURRENT_PATH}/log4sh.sh

# 检查dbstor的user与pwd是否正确
function check_dbstor_usr_passwd() {
    logAndEchoInfo "check username and password of dbstor. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    chown -hR ${cantian_user}:${cantian_group} /opt/cantian/image/Cantian-RUN-CENTOS-64bit/cfg
    su -s /bin/bash - "${cantian_user}" -c "sh ${CURRENT_PATH}/dbstor/check_usr_pwd.sh"
    install_result=$?
    if [ ${install_result} -ne 0 ]; then
        logAndEchoError "check dbstor passwd failed, possible reasons:
            1 username or password of dbstor storage service is incorrect.
            2 cgw create link failed.
            3 ip address of dbstor storage service is incorrect.
            please contact the engineer to solve. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        exit 1
    else
        logAndEchoInfo "user and password of dbstor check pass. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    fi
}

function check_dbstore_client_compatibility() {
    logAndEchoInfo "begin to check dbstore client compatibility."
    if [ ! -f "${DBSTORE_CHECK_FILE}" ];then
        logAndEchoError "${DBSTORE_CHECK_FILE} file is not exists."
        exit 1
    fi
    su -s /bin/bash - "${cantian_user}" -c "sh ${DBSTORE_CHECK_FILE}"
    if [[ $? -ne 0 ]];then
        logAndEchoError "dbstore client compatibility check failed."
        exit 1
    fi
    logAndEchoInfo "dbstore client compatibility check success."
}

function check_gcc_if_dbstore_unify() {
    # 检查gcc文件
    if [[ x"${deploy_mode}" != x"dbstore_unify" ]] || [[ ${node_id} -ne 0 ]]; then
        return 0
    fi
    logAndEchoInfo "begin to check gcc file."
    local version_file=$(su -s /bin/bash - "${cantian_user}"  -c "dbstor --query-file --fs-name=${storage_share_fs} --file-path=/" | grep "versions.yml" | wc -l)
    if [[ ${version_file} -gt 0 ]];then
        logAndEchoInfo "Versions.yaml file is exists, no need to check gcc file."
        mkdir -p "${metadata_path}"
        chown "${cantian_user}":"${cantian_group}" "${metadata_path}"
        su -s /bin/bash - "${cantian_user}"  -c "dbstor --copy-file --fs-name=${storage_share_fs} --source-dir=/ --target-dir=${metadata_path} --file-name=versions.yml"
        if [[ $? -ne 0 ]];then
            logAndEchoError "Update local version file failed."
            exit 1
        fi
        return 0
    fi
    local is_gcc_file_exist=$(su -s /bin/bash - "${cantian_user}" -c 'dbstor --query-file --fs-name='"${storage_share_fs}"' --file-path="gcc_home"' | grep gcc_file | wc -l)
    if [ ${is_gcc_file_exist} -ne 0 ]; then
        logAndEchoError "gcc file already exists, please check if any cluster is running or clustername has been used and not been uninstalled."
        exit 1
    fi
    logAndEchoInfo "gcc file not exist, check success."
}

function init_module() {
    for lib_name in "${INIT_CONTAINER_ORDER[@]}"
    do
        logAndEchoInfo "init ${lib_name}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        sh ${CURRENT_PATH}/${lib_name}/appctl.sh init_container >> ${OM_DEPLOY_LOG_FILE} 2>&1
        if [ $? -ne 0 ]; then
            logAndEchoError "init ${lib_name} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            logAndEchoError "For details, see the /opt/cantian/${lib_name}/log. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            exit 1
        fi
        logAndEchoInfo "init ${lib_name} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"

        if [[ ${lib_name} = 'dbstor' ]]; then
            check_dbstor_usr_passwd
            # 检查dbstore client 与server端是否兼容
            check_dbstore_client_compatibility
            check_gcc_if_dbstore_unify
        fi
    done
}

function main() {
    init_module
}

main