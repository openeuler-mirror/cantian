# 确定相对路径
set +x
#当前路径
CURRENT_PATH=$(dirname $(readlink -f $0))

CANTIAN_PRE_INSTALL_PY_NAME="cantian_pre_install.py"

function log() {
  printf "[%s] %s\n" "`date -d today \"+%Y-%m-%d %H:%M:%S\"`" "$1"
}

CANTIAN_INSTALL_LOG_FILE=/opt/cantian/log/cantian/cantian_deploy.log

# 判断是否存在对应的文件，不存在返回报错，存在则继续运行
function cantian_pre_install()
{
    if [ ! -f  ${CURRENT_PATH}/${CANTIAN_PRE_INSTALL_PY_NAME} ]; then
        echo " ${CANTIAN_PRE_INSTALL_PY_NAME} is not exist.]"
        return 1
    fi

    if [ ! -d /opt/cantian/log/cantian ]; then
        mkdir -p -m 750 /opt/cantian/log/cantian
    fi

    python3 ${CURRENT_PATH}/cantian_pre_install.py

    if [ $? -ne 0 ]; then
        echo "Execute ${CANTIAN_PRE_INSTALL_PY_NAME} return $?."
        return 1
    fi

    log "Cantian pre install success."

    return 0
}

cantian_pre_install &>> ${CANTIAN_INSTALL_LOG_FILE}