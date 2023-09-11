#!/bin/bash
set +x

CURRENT_PATH=$(dirname $(readlink -f $0))
PARENT_DIR_NAME=$(pwd | awk -F "/" '{print $NF}')
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)

python3 ${CURRENT_PATH}/cmsctl.py check_status

if [ $? -ne 0 ]; then
    echo "Execute ${SCRIPT_NAME} cmsctl.py check_status failed"
    exit 1
fi
