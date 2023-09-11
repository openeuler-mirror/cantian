#!/bin/bash
set +x

OM_DEPLOY_LOG_PATH=/opt/cantian/deploy
OM_DEPLOY_LOG_FILE=/opt/cantian/deploy/deploy_daemon.log
CURRENT_PATH=$(dirname $(readlink -f $0))
SCRIPT_NAME=${CURRENT_PATH}/$(basename $0)
LOG_MOD=640
LOG_MOD_STR='rw-r-----'

initLog4sh()
{
    if [ ! -d ${OM_DEPLOY_LOG_PATH} ]; then
        mkdir ${OM_DEPLOY_LOG_PATH}
    fi
    if [ ! -f ${OM_DEPLOY_LOG_FILE} ];then
        touch ${OM_DEPLOY_LOG_FILE}
        chmod 640 ${OM_DEPLOY_LOG_FILE}
    fi
    # 修改日志文件权限
    file_mod=`ls -l ${OM_DEPLOY_LOG_FILE} | awk '{print $1}'`
    if [[ ! "${file_mod}" =~ ${LOG_MOD_STR} ]]; then
        chmod ${LOG_MOD} ${OM_DEPLOY_LOG_FILE}
        if [ $? -ne 0 ]; then
            logAndEchoError "correct ${OM_DEPLOY_LOG_FILE} mod failed"
            exit 1
        fi
    fi
}

_logInfo() {
    initLog4sh;
    printf "[%s] [%s] [%-5d] [%s] " "`date -d today \"+%Y-%m-%d %H:%M:%S,%N %z\"`" "INFO" "$$" "$(basename ${BASH_SOURCE[2]}) ${BASH_LINENO[1]}" 1>> ${OM_DEPLOY_LOG_FILE} 2>&1; echo "$@" 1>> ${OM_DEPLOY_LOG_FILE} 2>&1;
}

_logWarn() {
    initLog4sh;
    printf "[%s] [%s] [%-5d] [%s] " "`date -d today \"+%Y-%m-%d %H:%M:%S,%N %z\"`" "WARN" "$$" "$(basename ${BASH_SOURCE[2]}) ${BASH_LINENO[1]}" 1>> ${OM_DEPLOY_LOG_FILE} 2>&1; echo "$@" 1>> ${OM_DEPLOY_LOG_FILE} 2>&1;

}

_logError() {
    initLog4sh;
    printf "[%s] [%s] [%-5d] [%s] " "`date -d today \"+%Y-%m-%d %H:%M:%S,%N %z\"`" "ERROR" "$$" "$(basename ${BASH_SOURCE[2]}) ${BASH_LINENO[1]}" 1>> ${OM_DEPLOY_LOG_FILE} 2>&1; echo "$@" 1>> ${OM_DEPLOY_LOG_FILE} 2>&1;
}
logInfo() { _logInfo "$@"; }
logWarn() { _logWarn "$@"; }
logError() { _logError "$@"; }

logAndEchoInfo() { _logInfo "$@"; echo -ne "[INFO ] $@\n"; }
logAndEchoWarn() { _logWarn "$@"; echo -ne "[WARN ] $@\n"; }
logAndEchoError() { _logError "$@"; echo -ne "[ERROR] $@\n"; }
