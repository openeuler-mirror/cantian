#!/bin/bash
CURRENT_PATH=$(dirname $(readlink -f $0))
KEY_TYPE=$1

cantian_user=$(python3 ${CURRENT_PATH}/../cantian/get_config_info.py "deploy_user")
current_user=$(whoami)

if [[ ${cantian_user} != ${current_user} ]]; then
    echo "please switch the current user to ${cantian_user}"
    exit 1
fi

local_path=$LD_LIBRARY_PATH
export LD_LIBRARY_PATH=/opt/cantian/dbstor/lib/:$LD_LIBRARY_PATH
python3 ${CURRENT_PATH}/kmc_adapter.py ${KEY_TYPE}
ret=$?
export LD_LIBRARY_PATH=$local_path
if [ "${ret}" != 0 ]; then
    echo "update key failed!"
    exit 1
fi