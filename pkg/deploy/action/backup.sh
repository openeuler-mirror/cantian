#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
BACKUP_ROOT_DIR=/opt/cantian/backup
CURRENT_BACKUP_DIR_PATH=${BACKUP_ROOT_DIR}/$(date +%Y%m%d%H%M%S)
LINK_NAME=files
source ${CURRENT_PATH}/env.sh
source ${CURRENT_PATH}/log4sh.sh
source ${CURRENT_PATH}/../config/backup_list.sh
deploy_user=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_user"`
deploy_group=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_group"`

function cleanDir() {
    # 清理备份文件夹，只保留最新的5个
    cd ${BACKUP_ROOT_DIR}
    local dirCount=$(ls -l |grep "^d"|wc -l)
    logAndEchoInfo "back dir is ${dirCount}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    if [ ${dirCount} -gt 5 ]; then
        local needRm=$(ls -l |grep "^d" |head -1 |awk '{print $9}')
        logAndEchoInfo "Begin to clear ${needRm}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        rm -rf ${BACKUP_ROOT_DIR}/${needRm}
    fi
}

function backFile() {
    mkdir -p ${CURRENT_BACKUP_DIR_PATH}
    chmod 750 "${BACKUP_ROOT_DIR}"
    chmod 750 "${CURRENT_BACKUP_DIR_PATH}"
    chown "${deploy_user}":"${deploy_group}" "${CURRENT_BACKUP_DIR_PATH}"
    if [ $? -ne 0 ]; then
        logAndEchoError "mkdir back dir ${CURRENT_BACKUP_DIR_PATH} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        exit 1
    fi
    logAndEchoInfo "mkdir back dir ${CURRENT_BACKUP_DIR_PATH} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    cd ${BACKUP_ROOT_DIR}
    rm -f ${LINK_NAME}
    ln -s ${CURRENT_BACKUP_DIR_PATH} ${LINK_NAME}
    if [ $? -ne 0 ]; then
        logAndEchoError "create soft link to ${CURRENT_BACKUP_DIR_PATH} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        exit 1
    fi
    logAndEchoInfo "create soft link to ${CURRENT_BACKUP_DIR_PATH} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"

    # 修改备份根目录属主属组，防止备份失败
    chown "${deploy_user}":"${deploy_group}" -R ${BACKUP_ROOT_DIR}
    if [ $? -ne 0 ]; then
        logAndEchoError "change mod of ${BACKUP_ROOT_DIR} to ${deploy_user}:${deploy_group} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        exit 1
    fi

    for bak_file in "${BACKUP_FILE_LIST[@]}"
    do
        _b=($bak_file)
        cp -rf ${_b[0]} ${CURRENT_BACKUP_DIR_PATH}/${_b[1]}
        if [ $? -ne 0 ]; then
            logAndEchoError "copy ${_b} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            exit 1
        fi
        logAndEchoInfo "copy ${_b} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    done
}


logAndEchoInfo "Begin to backup. [Line:${LINENO}, File:${SCRIPT_NAME}]"

backFile

for lib_name in "${BACKUP_ORDER[@]}"
do
    logAndEchoInfo "backup ${lib_name} . [Line:${LINENO}, File:${SCRIPT_NAME}]"
    sh ${CURRENT_PATH}/${lib_name}/appctl.sh backup >> ${OM_DEPLOY_LOG_FILE} 2>&1
    if [ $? -ne 0 ]; then
        logAndEchoError "copy ${lib_name} failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        exit 1
    fi
    logAndEchoInfo "copy ${lib_name} success. [Line:${LINENO}, File:${SCRIPT_NAME}]"
done

cleanDir

exit 0