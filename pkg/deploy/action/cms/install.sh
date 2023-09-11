#!/bin/bash
set +x

CURRENT_PATH=$(dirname $(readlink -f $0))
PARENT_DIR_NAME=$(pwd | awk -F "/" '{print $NF}')
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)

install_type=$(python3 ${CURRENT_PATH}/../cantian/get_config_info.py "install_type")
if [[ ${install_type} = "override" ]]; then
    read -s -p "Please input private key encryption password:" cert_encrypt_pwd
else
    cert_encrypt_pwd=$(python3 "${CURRENT_PATH}"/get_config_info.py "MES_SSL_KEY_PWD")
fi

echo -e "${cert_encrypt_pwd}" |python3 "${CURRENT_PATH}"/cmsctl.py install

if [ $? -ne 0 ]; then
    echo "Execute ${SCRIPT_NAME} cmsctl.py install failed"
    exit 1
fi

