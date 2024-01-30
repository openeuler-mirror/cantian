#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${CURRENT_PATH}/$(basename $0)
MAIN_PATH=$(dirname $(dirname ${CURRENT_PATH}))

source ${CURRENT_PATH}/ct_om_log.sh
version=$(cat ${CURRENT_PATH}/../../versions.yml | grep -E "Version:" | awk '{print $2}' | cut -d '.' -f 1-3)

function check_rpm_exist()
{
    rpm -qa | grep "ct_om"
    return $?
}

function install_ctom_rpm()
{
    rpm -ivh ${MAIN_PATH}/repo/ct_om-${version}*.rpm
    return $?
}

function main()
{
    # 检查rpm是否已经安装
    check_rpm_exist > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        logAndEchoInfo "Rpm package has been installed. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        logAndEchoInfo "Begin to remove old rpm package."
        rpm -ev ct_om
        if [ $? -ne 0 ]; then
            logAndEchoError "Remove old rpm package failed."
            return 1
        fi
        logAndEchoInfo "Remove old rpm package success"
    fi

    install_ctom_rpm > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        logAndEchoInfo "Success to install. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 0
    else
        logAndEchoError "Fail to install. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi
}

main
