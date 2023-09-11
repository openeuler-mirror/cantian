# 确定相对路径
set +x
#当前路径
CURRENT_PATH=$(dirname $(readlink -f $0))
DBSTOR_UNINSTALL_PY_NAME="dbstor_uninstall.py"

UNINSTALL_TYPE=""
FORCE_UNINSTALL=""
if [ $# -gt 0 ]; then
    UNINSTALL_TYPE=$1
fi
if [ $# -gt 1 ]; then
    FORCE_UNINSTALL=$2
fi
# 判断是否存在对应的文件，不存在返回报错，存在则继续运行
function dbstor_uninstall()
{
    if [ ! -f  ${CURRENT_PATH}/${DBSTOR_UNINSTALL_PY_NAME} ]; then
        echo " ${DBSTOR_UNINSTALL_PY_NAME} is not exist.]"
        return 1
    fi

    python3 ${CURRENT_PATH}/dbstor_uninstall.py ${UNINSTALL_TYPE} ${FORCE_UNINSTALL}

    if [ $? -ne 0 ]; then
        echo "Execute ${DBSTOR_UNINSTALL_PY_NAME} return $?."
        return 1
    fi
#    删除kmc动态库
    rm -rf /opt/cantian/dbstor/lib
#    删除cstool工具
    rm -rf /opt/cantian/dbstor/tools
    return 0
}
# 卸载时删除信号量
ret=`lsipc -s -c | grep 0x20161227`
if [ -n "$ret" ]; then
    arr=($ret)
    sem_id=${arr[1]}
    ipcrm -s $sem_id
fi

dbstor_uninstall