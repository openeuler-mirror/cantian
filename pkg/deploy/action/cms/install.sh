#!/bin/bash
set +x

CURRENT_PATH=$(dirname $(readlink -f $0))
PARENT_DIR_NAME=$(pwd | awk -F "/" '{print $NF}')
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)

function log() {
  printf "[%s] %s\n" "`date -d today \"+%Y-%m-%d %H:%M:%S\"`" "$1"
}

python3 ${CURRENT_PATH}/cmsctl.py install

if [ $? -ne 0 ]; then
    log "Execute ${SCRIPT_NAME} cmsctl.py install failed"
    exit 1
fi

