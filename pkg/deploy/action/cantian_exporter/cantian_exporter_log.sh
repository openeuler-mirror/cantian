#!/bin/bash
set +x

OM_DEPLOY_LOG_PATH=/opt/cantian/cantian_exporter/log
OM_DEPLOY_LOG_FILE=/opt/cantian/cantian_exporter/log/cantian_exporter.log
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${CURRENT_PATH}/$(basename $0)

init_ct_om_sh()
{
    if [ ! -d ${OM_DEPLOY_LOG_PATH} ]; then
        mkdir -m 750 -p ${OM_DEPLOY_LOG_PATH}
        touch ${OM_DEPLOY_LOG_FILE}
    fi
}

_logInfo() {
    printf "[%s] [%s] [%-5d] [%s] " "`date -d today \"+%Y-%m-%d %H:%M:%S,%N %z\"`" "INFO" "$$" "$(basename ${BASH_SOURCE[2]}) ${BASH_LINENO[1]}" 1>> ${OM_DEPLOY_LOG_FILE} 2>&1; echo "$@" 1>> ${OM_DEPLOY_LOG_FILE} 2>&1;
}

_logWarn() {
    printf "[%s] [%s] [%-5d] [%s] " "`date -d today \"+%Y-%m-%d %H:%M:%S,%N %z\"`" "WARN" "$$" "$(basename ${BASH_SOURCE[2]}) ${BASH_LINENO[1]}" 1>> ${OM_DEPLOY_LOG_FILE} 2>&1; echo "$@" 1>> ${OM_DEPLOY_LOG_FILE} 2>&1;

}

_logError() {
    printf "[%s] [%s] [%-5d] [%s] " "`date -d today \"+%Y-%m-%d %H:%M:%S,%N %z\"`" "ERROR" "$$" "$(basename ${BASH_SOURCE[2]}) ${BASH_LINENO[1]}" 1>> ${OM_DEPLOY_LOG_FILE} 2>&1; echo "$@" 1>> ${OM_DEPLOY_LOG_FILE} 2>&1;
}
logInfo() { _logInfo "$@"; }
logWarn() { _logWarn "$@"; }
logError() { _logError "$@"; }

logAndEchoInfo() { _logInfo "$@"; echo -ne "[INFO ] $@\n"; }
logAndEchoWarn() { _logWarn "$@"; echo -ne "[WARN ] $@\n"; }
logAndEchoError() { _logError "$@"; echo -ne "[ERROR] $@\n"; }

init_ct_om_sh
