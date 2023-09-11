#!/bin/bash
set +x

source ~/.bashrc
CURRENT_PATH=$(dirname $(readlink -f $0))
CMS_ENABLE_FLAG=/opt/cantian/cms/cfg/cms_enable
CMS_DEPLOY_LOG_FILE=/opt/cantian/cms/log/cms_deploy.log
# 返回结果前等待1s
LOOP_TIME=1

ACTION=$1
case "$ACTION" in
    enable)
        echo "[cms reg] begin to set cms daemon enable. [Line:${LINENO}, File:${SCRIPT_NAME}]" >> ${CMS_DEPLOY_LOG_FILE}
        if [ ! -f ${CMS_ENABLE_FLAG} ]; then
            touch ${CMS_ENABLE_FLAG}
            if [ $? -eq 0 ];then
                chmod 400 ${CMS_ENABLE_FLAG}
                sleep ${LOOP_TIME}
                echo "RES_SUCCESS"
                exit 0
            else
                echo "Error: [cms reg] set cms daemon enable failed. [Line:${LINENO}, File:${SCRIPT_NAME}]" >> ${CMS_DEPLOY_LOG_FILE}
                exit 1
            fi
        fi
        sleep ${LOOP_TIME}
        echo "RES_SUCCESS"
        exit 0
        ;;
    disable)
        echo "[cms reg] begin to set cms daemon disable. [Line:${LINENO}, File:${SCRIPT_NAME}]" >> ${CMS_DEPLOY_LOG_FILE}
        if [ -f ${CMS_ENABLE_FLAG} ]; then
            rm -f ${CMS_ENABLE_FLAG}
            if [ $? -eq 0 ];then
                sleep ${LOOP_TIME}
                echo "RES_SUCCESS"
                exit 0
            else
                echo "Error: [cms reg] set cms daemon disable failed. [Line:${LINENO}, File:${SCRIPT_NAME}]" >> ${CMS_DEPLOY_LOG_FILE}
                exit 1
            fi
        fi
        sleep ${LOOP_TIME}
        echo "RES_SUCCESS"
        exit 0
        ;;
    *)
        echo "action not support"
        ;;
esac