# 确定相对路径
set +x
#当前路径
CURRENT_PATH=$(dirname $(readlink -f $0))
CANTIAN_STOP_PY_NAME="cantian_stop.py"
CANTIAN_STOP_CONFIG_NAME="cantian_uninstall_config.json"
CANTIAN_CHECK_STATUS_PY_NAME="cantian_check_status.py"
CANTIAN_START_STATUS=`python3 ${CURRENT_PATH}/get_config_info.py "CANTIAN_START_STATUS"`
CANTIAN_START_STATUS_FILE="/opt/cantian/cantian/cfg/start_status.json"
CANTIAN_INSTALL_LOG_FILE=/opt/cantian/cantian/log/cantian_deploy.log

function log() {
  printf "[%s] %s\n" "`date -d today \"+%Y-%m-%d %H:%M:%S\"`" "$1"
}

# 判断是否存在对应的文件，不存在返回报错，存在则继续运行
function cantian_stop()
{
    user=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_user"`
    group=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_group"`
    if [ ! -f  ${CURRENT_PATH}/${CANTIAN_CHECK_STATUS_PY_NAME} ]; then
        log "${CANTIAN_CHECK_STATUS_PY_NAME} is not exist.]"
        return 1
    fi

    python3 ${CURRENT_PATH}/cantian_check_status.py

    if [ $? -ne 0 ] && [ ${CANTIAN_START_STATUS} == "default" ]; then
        log "Cantian status is default, instance cantiand has not started."
        return 0
    fi

    if [ ! -f  ${CURRENT_PATH}/${CANTIAN_STOP_PY_NAME} ]; then
        log "${CANTIAN_STOP_PY_NAME} is not exist.]"
        return 1
    fi

    # # 进入user
    python3 ${CURRENT_PATH}/cantian_stop.py

    ret=$?
    if [ ${ret} -ne 0 ]; then
        log "Execute ${CANTIAN_STOP_PY_NAME} return ${ret}."
        return 1
    fi
    log "cantian stop success."
    return 0
}

cantian_stop &>> ${CANTIAN_INSTALL_LOG_FILE}
