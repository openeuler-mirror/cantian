#!/bin/bash
set +x

CURRENT_PATH=$(dirname $(readlink -f $0))
PARENT_DIR_NAME=$(pwd | awk -F "/" '{print $NF}')
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
pre_install_date=$(date)
function log() {
  printf "[%s] %s\n" "`date -d today \"+%Y-%m-%d %H:%M:%S\"`" "$1"
}

log -e "++++++++++++++++++++++++++ ${pre_install_date} : Start the installation procedure ++++++++++++++++++++++++++\n"

python3 ${CURRENT_PATH}/cmsctl.py pre_install $1

if [ $? -ne 0 ]; then
    log "Execute ${SCRIPT_NAME} cmsctl.py pre_install failed"
    exit 1
fi