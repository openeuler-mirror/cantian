#!/bin/bash
set +x

OM_DEPLOY_LOG_PATH=/opt/cantian/deploy
OM_DEPLOY_LOG_FILE=/opt/cantian/deploy/deploy.log
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${CURRENT_PATH}/$(basename $0)

initLog4sh()
{
    if [ ! -d ${OM_DEPLOY_LOG_PATH} ]; then
        mkdir -m 755 -p ${OM_DEPLOY_LOG_PATH}
        chmod 755 /opt/cantian
        touch ${OM_DEPLOY_LOG_FILE}
    fi
    chmod 640 ${OM_DEPLOY_LOG_FILE}
}

_logInfo() {
    printf "[%s] [%s] [%-5d] [%s] " "`date -d today \"+%Y-%m-%d %H:%M:%S,%N %z\"`" "INFO" "$$" "$(basename ${BASH_SOURCE[2]}) ${BASH_LINENO[1]}" 1>> ${OM_DEPLOY_LOG_FILE} 2>&1; echo -e "$@" 1>> ${OM_DEPLOY_LOG_FILE} 2>&1;
}

_logWarn() {
    printf "[%s] [%s] [%-5d] [%s] " "`date -d today \"+%Y-%m-%d %H:%M:%S,%N %z\"`" "WARN" "$$" "$(basename ${BASH_SOURCE[2]}) ${BASH_LINENO[1]}" 1>> ${OM_DEPLOY_LOG_FILE} 2>&1; echo -e "$@" 1>> ${OM_DEPLOY_LOG_FILE} 2>&1;

}

_logError() {
    printf "[%s] [%s] [%-5d] [%s] " "`date -d today \"+%Y-%m-%d %H:%M:%S,%N %z\"`" "ERROR" "$$" "$(basename ${BASH_SOURCE[2]}) ${BASH_LINENO[1]}" 1>> ${OM_DEPLOY_LOG_FILE} 2>&1; echo -e "$@" 1>> ${OM_DEPLOY_LOG_FILE} 2>&1;
}
initLog4sh
logInfo() { _logInfo "$@"; }
logWarn() { _logWarn "$@"; }
logError() { _logError "$@"; }

logAndEchoInfo() { _logInfo "$@"; echo -ne "[INFO ] $@\n"; }
logAndEchoWarn() { _logWarn "$@"; echo -ne "[WARN ] $@\n"; }
logAndEchoError() { _logError "$@"; echo -ne "[ERROR] $@\n"; }
