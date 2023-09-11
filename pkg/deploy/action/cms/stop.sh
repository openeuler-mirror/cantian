#!/bin/bash
set +x

CURRENT_PATH=$(dirname $(readlink -f $0))
PARENT_DIR_NAME=$(pwd | awk -F "/" '{print $NF}')
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)
user=`whoami`

python3 ${CURRENT_PATH}/cmsctl.py stop
if [ $? -ne 0 ]; then
    echo "Execute ${SCRIPT_NAME} cmsctl.py stop failed"
    exit 1
fi

cms_count=`ps -fu ${user} | grep "cms server -start" | grep -vE '(grep|defunct)' | wc -l`
if [ ${cms_count} -ne 0 ]; then
    echo "Execute ${SCRIPT_NAME} cmsctl.py stop failed, cms process is online"
    exit 1
fi
