#!/bin/bash
set +x

CURRENT_PATH=$(dirname $(readlink -f $0))
PARENT_DIR_NAME=$(pwd | awk -F "/" '{print $NF}')
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)

if [ $# -gt 0 ]; then
    UNINSTALL_TYPE=$1
fi
if [ $# -gt 1 ]; then
    FORCE_UNINSTALL=$2
fi

python3 ${CURRENT_PATH}/cmsctl.py uninstall ${UNINSTALL_TYPE} ${FORCE_UNINSTALL}
if [ $? -ne 0 ]; then
    echo "Execute ${SCRIPT_NAME} cmsctl.py uninstall failed"
    exit 1
fi