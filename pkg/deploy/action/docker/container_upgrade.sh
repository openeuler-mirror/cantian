#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
PKG_PATH=${CURRENT_PATH}/../..
VERSION_FILE="versions.yml"
SCRIPT_NAME="container_upgrade.sh"

storage_metadata_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_metadata_fs"`
node_id=`python3 ${CURRENT_PATH}/get_config_info.py "node_id"`
VERSION_PATH="/mnt/dbdata/remote/metadata_${storage_metadata_fs}"

source ${CURRENT_PATH}/../log4sh.sh

function check_if_need_upgrade() {
    if [ ! -f ${VERSION_PATH}/${VERSION_FILE} ]; then
        logAndEchoInfo "this is first to start node, no need to upgrade. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        exit 0
    fi
    logAndEchoInfo "check if the container needs to upgrade. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    local_version=`cat ${PKG_PATH}/${VERSION_FILE} | grep 'Version:' | awk -F ":" '{print $2}' | sed -r 's/[a-z]*[A-Z]*0*([0-9])/\1/'`
    remote_version=`cat ${VERSION_PATH}/${VERSION_FILE} | grep 'Version:' | awk -F ":" '{print $2}' | sed -r 's/[a-z]*[A-Z]*0*([0-9])/\1/'`
    if [[ ${node_id} -eq 0 ]]; then
        if [[ ${local_version} -gt ${remote_version} ]]; then
            return 0
        fi
    else
        if [[ ${local_version} -ne ${remote_version} ]]; then
            logAndEchoError "expect version:${remote_version}, this version:${local_version}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            exit 1
        fi
    fi
    return 1
}

function container_upgrade() {
    logAndEchoInfo "Begin to upgrade. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    upgrade_res=`python3 ${CURRENT_PATH}/upgrade_version_check.py`
    upgrade_stat=`echo ${upgrade_res} | awk '{split($1,arr," ");print arr[1]}'`
    if [ "${upgrade_stat}" == "True" ]; then
        return 0
    else 
        return 1
    fi
}

function update_version_file() {
    if [ ! -f ${PKG_PATH}/${VERSION_FILE} ]; then
        logAndEchoError "${VERSION_FILE} is not exist!"
    fi
    cp -rf ${PKG_PATH}/${VERSION} ${VERSION_PATH}/${VERSION}
}

function container_upgrade_check() {
    check_if_need_upgrade
    if [ $? -eq 0 ]; then
        container_upgrade
        if [ $? -ne 0 ]; then
            logAndEchoError "upgrade failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
            return 1
        fi
        update_version_file
        logAndEchoInfo "upgrade succeded. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    else
        logAndEchoInfo "now is the latest version, no need to upgrade. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    fi
}

container_upgrade_check