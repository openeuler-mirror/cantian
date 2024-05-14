#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)

source ${CURRENT_PATH}/env.sh
source ${CURRENT_PATH}/log4sh.sh

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
    done
}

function main() {
    init_module
}

main