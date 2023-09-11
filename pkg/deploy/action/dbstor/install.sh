# 确定相对路径
set +x
#当前路径
CURRENT_PATH=$(dirname $(readlink -f $0))
DBSTOR_INSTALL_PY_NAME="dbstor_install.py"
RPM_UNPACK_PATH="/opt/cantian/image/Cantian-RUN-CENTOS-64bit"
CILENT_TEST_PATH="/opt/cantian/dbstor/tools"

# 判断是否存在对应的文件，不存在返回报错，存在则继续运行
function dbstor_install()
{
    if [ ! -f  ${CURRENT_PATH}/${DBSTOR_INSTALL_PY_NAME} ]; then
        echo " ${DBSTOR_INSTALL_PY_NAME} is not exist.]"
        return 1
    fi

    if [ ! -d ${RPM_UNPACK_PATH} ]; then
      echo "/opt/cantian/image/Cantian-RUN-CENTOS-64bit not exist"
      exit 1
    fi

    local tmp_path=${LD_LIBRARY_PATH}
    export LD_LIBRARY_PATH=/opt/cantian/dbstor/lib:${LD_LIBRARY_PATH}
    python3 ${CURRENT_PATH}/dbstor_install.py
    local ret=$?
    export LD_LIBRARY_PATH=${tmp_path}

    if [ $ret -eq 2 ]; then
        echo "Failed to ping some remote ip."
        return 2
    fi

    if [ $ret -ne 0 ]; then
        echo "Execute ${DBSTOR_INSTALL_PY_NAME} return $?."
        return 1
    fi
    return 0
}

dbstor_install