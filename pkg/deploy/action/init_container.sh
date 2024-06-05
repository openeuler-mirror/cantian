#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
DBSTORE_CHECK_FILE=${CURRENT_PATH}/dbstor/check_dbstor_compat.sh
cantian_user=`python3 ${CURRENT_PATH}/cantian/get_config_info.py "deploy_user"`
cantian_group=`python3 ${CURRENT_PATH}/cantian/get_config_info.py "deploy_group"`

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
        fi
    done
}

function main() {
    init_module
}

main