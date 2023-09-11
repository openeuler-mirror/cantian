# 确定相对路径
set +x
#当前路径
CURRENT_PATH=$(dirname $(readlink -f $0))
CANTIAN_CHECK_STATUS_PY_NAME="cantian_check_status.py"

CANTIAN_INSTALL_LOG_FILE=/opt/cantian/cantian/log/cantian_deploy.log
# 判断是否存在对应的文件，不存在返回报错，存在则继续运行
function check_cantian_status()
{
    user=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_user"`
    if [ ! -f  ${CURRENT_PATH}/${CANTIAN_CHECK_STATUS_PY_NAME} ]; then
        echo "${CANTIAN_CHECK_STATUS_PY_NAME} is not exist.]" >> ${CANTIAN_INSTALL_LOG_FILE}
        return 1
    fi

    python3 ${CURRENT_PATH}/cantian_check_status.py

    if [ $? -ne 0 ]; then
        echo "Instance cantiand has not started." >> ${CANTIAN_INSTALL_LOG_FILE}
        return 1
    fi

    echo "Instance cantiand has been started." >> ${CANTIAN_INSTALL_LOG_FILE}
    return 0
}

check_cantian_status