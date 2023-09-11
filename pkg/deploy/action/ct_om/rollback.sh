#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${CURRENT_PATH}/$(basename $0)
TARGET_RPM_PACKAGE_NAME=""
INSTALLED_RPM_PACKAGE_NAME=""
BACKUP_FILE_NAME=$1
source ${CURRENT_PATH}/ct_om_log.sh

function get_target_rpm_package_name() {
    TARGET_RPM_PACKAGE_NAME=$(ls ${BACKUP_FILE_NAME}/repo | grep ct_om-)
}

function get_installed_rpm_package_name() {
    INSTALLED_RPM_PACKAGE_NAME=$(rpm -qa | grep "ct_om")
}

function main() {
    logAndEchoInfo "Begin to start ct_om rollback. [Line:${LINENO}, File:${SCRIPT_NAME}]"

    get_target_rpm_package_name
    if [[ -z "${TARGET_RPM_PACKAGE_NAME}" ]]; then
        logAndEchoError "Obtain target rollback rpm package name failed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    # 卸载已安装的rpm包
    get_installed_rpm_package_name
    if [ -n "${INSTALLED_RPM_PACKAGE_NAME}" ]; then
        rpm -e ${INSTALLED_RPM_PACKAGE_NAME}
        if [ $? -ne 0 ]; then
            logAndEchoError "Uninstall old rpm package failed.[Line:${LINENO}, File:${SCRIPT_NAME}]"
            return 1
        fi
    fi

    # 回滚target版本rpm包
    rpm -ivh ${BACKUP_FILE_NAME}/repo/${TARGET_RPM_PACKAGE_NAME}
    if [ $? -ne 0 ]; then
        logAndEchoError "install target rpm package failed.[Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    logAndEchoInfo "Rollback successful. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    return 0
}

main