#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${CURRENT_PATH}/$(basename $0)
MODULE_NAME=ct_om
ct_om_log=/opt/cantian/deploy/logs/ct_om/ct_om.logs
VERSION_YML_PATH="${CURRENT_PATH}/../.."
SOURCE_PATH='/opt/cantian/ct_om/service/cantian_exporter/exporter_data'
TARGET_RPM_PACKAGE_NAME=""
INSTALLED_RPM_PACKAGE_NAME=""
BACKUP_FILE_NAME=$1
CT_OM_BACKUP_FILE_NAME=ct_om_backup_$(date "+%Y%m%d%H%M%S")
version=$(cat ${VERSION_YML_PATH}/versions.yml | grep -E "Version:" | awk '{print $2}' | cut -d '.' -f 1-3)
source ${CURRENT_PATH}/ct_om_log.sh

function get_target_rpm_package_name() {
    TARGET_RPM_PACKAGE_NAME=$(ls ${VERSION_YML_PATH}/repo | grep ct_om-${version})
}

function get_installed_rpm_package_name() {
    INSTALLED_RPM_PACKAGE_NAME=$(rpm -qa | grep "ct_om")
}

function main()
{
    logAndEchoInfo "Begin to ct_om upgrade. ${MODULE_NAME}. [Line:${LINENO}, File:${SCRIPT_NAME}]"

    get_target_rpm_package_name
    if [[ -z "${TARGET_RPM_PACKAGE_NAME}" ]]; then
      logAndEchoError "Obtain rpm package name failed. 'rpm package name' should be a non-empty string.[Line:${LINENO}, File:${SCRIPT_NAME}]"
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

    # 安装target版本rpm包
    rpm -ivh ${VERSION_YML_PATH}/repo/${TARGET_RPM_PACKAGE_NAME}
    if [ $? -ne 0 ]; then
        logAndEchoError "install target rpm package failed.[Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    logAndEchoInfo "Upgrade successful. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    return 0

}

main