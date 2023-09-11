#!/bin/bash
set +x
set -e
CURRENT_PATH=$(dirname $(readlink -f $0))
source ${CURRENT_PATH}/log4sh.sh
OM_DEPLOY_LOG_FILE=/opt/cantian/deploy/deploy.log
CHECK_POINT_FILE=${CURRENT_PATH}/cantian/upgrade_checkpoint.sh
CHECK_POINT_FLAG=/opt/cantian/check_point.success
deploy_user=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_user")
node_zore_ip="127.0.0.1"

function get_user_input() {
    read -s -p "please enter zsql_pwd: " zsql_pwd
    echo ''
}

# 回滚后同步数据间gap
function recover_gap() {
    logAndEchoInfo "Do check point start."
    echo -e "${zsql_pwd}" | su - ${deploy_user} -s /bin/bash -c "sh ${CHECK_POINT_FILE} ${node_zore_ip}" >> ${OM_DEPLOY_LOG_FILE}
    if [[ $? -ne 0 ]];then
        logAndEchoError "Check point failed"
        exit 1
    fi
    touch ${CHECK_POINT_FLAG}
    chmod 400 ${CHECK_POINT_FLAG}
    logAndEchoInfo "Do check point success."
}

function check_status() {
    if [ -f ${CHECK_POINT_FLAG} ];then
        rm -rf ${CHECK_POINT_FLAG}
    fi
    logAndEchoInfo "Before check point check cantian status."
    sh /opt/cantian/action/appctl.sh check_status
    if [[ $? -ne 0 ]];then
        logAndEchoError "Cantian if offline, can not do check point."
        exit 1
    fi
}

function main() {
    get_user_input
    check_status
    recover_gap
}
main