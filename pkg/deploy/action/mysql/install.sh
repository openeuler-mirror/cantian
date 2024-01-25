#!/bin/bash
MYSQL_LOG_PATH=/opt/cantian/mysql/log
if [ ! -d ${MYSQL_LOG_PATH} ];then
    mkdir -p ${MYSQL_LOG_PATH}
fi
touch ${MYSQL_LOG_PATH}/install.log
chmod 600 ${MYSQL_LOG_PATH}/install.log

sh -x /opt/cantian/image/cantian_connector/for_mysql_official/patch.sh > ${MYSQL_LOG_PATH}/install.log 2>&1
if [ $? -ne 0 ]; then
    echo "Failed to execute /opt/cantian/image/cantian_connector/for_mysql_official/patch.sh."
    exit 1
fi

cp -arf /opt/cantian/image/cantian_connector/for_mysql_official/mf_connector_mount_dir/ /opt/cantian/mysql/server/
if [ $? -ne 0 ]; then
    echo "Failed to copy file from /opt/cantian/image/cantian_connector/for_mysql_official/mf_connector_mount_dir/ to /opt/cantian/mysql/server/"
    exit 1
fi