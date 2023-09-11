# 确定相对路径
set +x
#当前路径
CURRENT_PATH=$(dirname $(readlink -f $0))
CANTIAN_START_PY_NAME="cantian_start.py"
CANTIAN_STOP_SH_NAME="stop.sh"
CANTIAN_SYS_PWD=""
CANTIAN_INSTALL_LOG_FILE=/opt/cantian/cantian/log/cantian_deploy.log
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
    echo "Cantiand process has exist." >> ${CANTIAN_INSTALL_LOG_FILE}
    return 0
} 

# 判断是否存在对应的文件，不存在返回报错，存在则继续运行
function cantian_start()
{
    if [ ! -f  ${CURRENT_PATH}/${CANTIAN_START_PY_NAME} ]; then
        echo "${CANTIAN_START_PY_NAME} is not exist.]" >> ${CANTIAN_INSTALL_LOG_FILE}
        return 1
    fi

    export LD_LIBRARY_PATH=/opt/cantian/dbstor/lib:${LD_LIBRARY_PATH}
    DEPLOY_MODE=$(python3 "${CURRENT_PATH}"/get_config_info.py "deploy_mode")
    if [ x"${DEPLOY_MODE}" == x"--nas" ];then
        read -s -p "please enter cantian_sys_pwd: " CANTIAN_SYS_PWD
        echo ''
    fi
    echo -e "${CANTIAN_SYS_PWD}" | python3 "${CURRENT_PATH}"/${CANTIAN_START_PY_NAME}
    ret=$?

    if [ ${ret} -ne 0 ]; then
        echo "Execute ${CANTIAN_START_PY_NAME} return ${ret}." >> ${CANTIAN_INSTALL_LOG_FILE}
        return 1
    fi

    echo "cantian start success." >> ${CANTIAN_INSTALL_LOG_FILE}
    return 0
}

# 读取参天创库流程状态，如果参天在创库流程被中断，则需要卸载后修改namespace并重新安装
function check_cantian_db_create_status()
{
    CANTIAN_SQL_EXECUTE_STATUS=`python3 ${CURRENT_PATH}/get_config_info.py "CANTIAN_DB_CREATE_STATUS"`

    if [ -z ${CANTIAN_SQL_EXECUTE_STATUS} ]; then
        echo "Failed to get db create status, please check file start_status.json or reinstall cantian." >> ${CANTIAN_INSTALL_LOG_FILE}
        exit 1
    fi

    if [ ${CANTIAN_SQL_EXECUTE_STATUS} == "creating" ]; then
        echo "Failed to create namespace at last startup, please reinstall it after uninstalling cantian and modifying namespace." >> ${CANTIAN_INSTALL_LOG_FILE}
        exit 1
    fi
}

function check_cantian_start_status()
{
    CANTIAN_START_STATUS=`python3 ${CURRENT_PATH}/get_config_info.py "CANTIAN_START_STATUS"`
    # 1.参天拉起状态为default
    #（1.1）参天进程在，强制stop后进入拉起流程
    #（1.2）参天进程不在，直接进入启动流程
    if [ ${CANTIAN_START_STATUS} == "default" ]; then
        check_cantian_exporter_daemon_status
        if [ $? -eq 0 ]; then
            echo "Cantian has not started, but process cantiand was detected, trying to stop and restart it." >> ${CANTIAN_INSTALL_LOG_FILE}
            sh ${CURRENT_PATH}/${CANTIAN_STOP_SH_NAME}
        fi
    fi

    # 2.参天拉起状态为starting，此时正在拉起参天，但异常退出了。需要强制stop，重新拉起参天
    # 在database的创建流程之外参天被异常退出时，参天还可以再次被拉起
    if [ ${CANTIAN_START_STATUS} == "starting" ]; then
        echo "Last startup process was interrupted, trying to stop existing cantian process and restart it." >> ${CANTIAN_INSTALL_LOG_FILE}
        sh ${CURRENT_PATH}/${CANTIAN_STOP_SH_NAME}
    fi

    # 3.参天拉起状态为started
    #（3.1）参天进程在，直接返回0（成功）
    #（3.2）参天进程不在，先强制stop，再重新拉起参天
    if [ ${CANTIAN_START_STATUS} == "started" ]; then
        check_cantian_exporter_daemon_status
        if [ $? -eq 0 ]; then
            echo "Cantian is already started, no need to restart it." >> ${CANTIAN_INSTALL_LOG_FILE}
            exit 0
        else
            echo "Cantian status is started, but no process is detected, trying to restart it." >> ${CANTIAN_INSTALL_LOG_FILE}
            sh ${CURRENT_PATH}/${CANTIAN_STOP_SH_NAME}
        fi
    fi
}

check_cantian_db_create_status
check_cantian_start_status
check_cantian_exporter_daemon_status
if [ $? -ne 0 ]; then 
    cantian_start
fi