# 确定相对路径
set +x
#当前路径
CURRENT_PATH=$(dirname $(readlink -f $0))
CANTIAN_START_PY_NAME="cantian_start.py"
CANTIAN_STOP_SH_NAME="stop.sh"
CANTIAN_INSTALL_LOG_FILE=/opt/cantian/cantian/log/cantian_deploy.log
START_MODE=$1

function log() {
  printf "[%s] %s\n" "`date -d today \"+%Y-%m-%d %H:%M:%S\"`" "$1" >> ${CANTIAN_INSTALL_LOG_FILE}
}

function check_cantian_exporter_daemon_status()
{
    for i in {1..3}
    do
        sleep 1
        cantiand_pid=$(ps -ef | grep -v grep | grep cantiand | grep -w '\-D /mnt/dbdata/local/cantian/tmp/data' | awk '{print $2}')
    done
    # ce_pid不存在
    if [ -z "${cantiand_pid}" ];then
        return 1
    fi
    log "Cantiand process has exist."
    return 0
} 

# 判断是否存在对应的文件，不存在返回报错，存在则继续运行
function cantian_start()
{
    if [ ! -f  ${CURRENT_PATH}/${CANTIAN_START_PY_NAME} ]; then
        log "${CANTIAN_START_PY_NAME} is not exist.]"
        return 1
    fi
    # 容灾备站点拉起时，无需创库。设置创库状态为done
    if [[ x"${START_MODE}" == x"standby" ]];then
        sed -i 's/"db_create_status": "default"/"db_create_status": "done"/g'  /opt/cantian/cantian/cfg/start_status.json
    fi
    export LD_LIBRARY_PATH=/opt/cantian/dbstor/lib:${LD_LIBRARY_PATH}
    python3 ${CURRENT_PATH}/${CANTIAN_START_PY_NAME}
    ret=$?

    if [ ${ret} -ne 0 ]; then
        log "Execute ${CANTIAN_START_PY_NAME} return ${ret}."
        return 1
    fi

    log "cantian start success."
    return 0
}

# 读取参天创库流程状态，如果参天在创库流程被中断，则需要卸载后修改namespace并重新安装
function check_cantian_db_create_status()
{
    CANTIAN_SQL_EXECUTE_STATUS=`python3 ${CURRENT_PATH}/get_config_info.py "CANTIAN_DB_CREATE_STATUS"`

    if [ -z ${CANTIAN_SQL_EXECUTE_STATUS} ]; then
        log "Failed to get db create status, please check file start_status.json or reinstall cantian."
        exit 1
    fi

    if [ ${CANTIAN_SQL_EXECUTE_STATUS} == "creating" ]; then
        log "Failed to create namespace at last startup, please reinstall it after uninstalling cantian and modifying namespace."
        exit 1
    fi
}

function check_cantian_start_status()
{
    CANTIAN_START_STATUS=`python3 ${CURRENT_PATH}/get_config_info.py "CANTIAN_START_STATUS"`

    # 1.参天拉起状态为starting，即参天拉起过程中异常退出了。此时，若参天进程不存在，stop后重新拉起参天
    # 在database的创建流程之外参天被异常退出时，参天还可以再次被拉起
    ret=check_cantian_exporter_daemon_status
    if [[ ${CANTIAN_START_STATUS} == "starting" && ${ret} -ne 0 ]]; then
        log "Last startup process was interrupted, trying to stop existing cantian process and restart it."
        sh ${CURRENT_PATH}/${CANTIAN_STOP_SH_NAME}
    fi

    # 2.参天拉起状态为started
    #（2.1）参天进程在，直接返回0（成功）
    #（2.2）参天进程不在，先强制stop，再重新拉起参天
    if [ ${CANTIAN_START_STATUS} == "started" ]; then
        check_cantian_exporter_daemon_status
        if [ $? -eq 0 ]; then
            log "Cantian is already started, no need to restart it."
            exit 0
        else
            log "Cantian status is started, but no process is detected, trying to restart it."
            sh ${CURRENT_PATH}/${CANTIAN_STOP_SH_NAME}
        fi
    fi
}

check_cantian_db_create_status
check_cantian_start_status
cantian_start