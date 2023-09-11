# 确定相对路径
set +x
#当前路径
CURRENT_PATH=$(dirname $(readlink -f $0))
DBSTOR_UNINSTALL_PY_NAME="dbstor_backup.py"

# 判断是否存在对应的文件，不存在返回报错，存在则继续运行
function dbstor_backup()
{
    if [ ! -f  ${CURRENT_PATH}/${DBSTOR_UNINSTALL_PY_NAME} ]; then
        echo " ${DBSTOR_UNINSTALL_PY_NAME} is not exist.]"
        return 1
    fi

    python3 ${CURRENT_PATH}/dbstor_backup.py

    if [ $? -ne 0 ]; then
        echo "Execute ${DBSTOR_UNINSTALL_PY_NAME} return $?."
        return 1
    fi

    return 0
}

dbstor_backup