# 确定相对路径
set +x
#当前路径
CURRENT_PATH=$(dirname $(readlink -f $0))
CANTIAN_UNINSTALL_PY_NAME="cantian_uninstall.py"
CANTIAN_INSTALL_LOG_FILE=/opt/cantian/cantian/log/cantian_deploy.log
# 判断是否存在对应的文件，不存在返回报错，存在则继续运行
function cantian_uninstall()
{
    echo "shell uninstall step 0 $(date)"
    in_container=`python3 ${CURRENT_PATH}/get_config_info.py "in_container"`
    echo "shell uninstall step 1 $(date)"
    user=`python3 ${CURRENT_PATH}/get_config_info.py "deploy_user"`
    echo "shell uninstall step 2 $(date)"
    cantian_data=$(cat ${CURRENT_PATH}/install_config.json |
              awk -F ',' '{for(i=1;i<=NF;i++){if($i~"D_DATA_PATH"){print $i}}}' |
              sed 's/ //g' | sed 's/:/=/1' | sed 's/"//g' |
              awk -F '=' '{print $2}')
    cantian_count=`ps -fu ${user} | grep "\-D ${cantian_data}" | grep -vE '(grep|defunct)' | wc -l`
    if [ ${cantian_count} -ge 1 ];then
        echo "Error: cantian process is running, please stop before uninstall"
        return 1
    fi
    echo "shell uninstall step 3 $(date)"
    if [[ -d /home/regress/cantian_data/data && ${in_container} -eq 1 ]]; then
        echo " run in_container "
        rm -rf /home/regress/cantian_data/data
    fi
    echo "shell uninstall step 4 $(date)"
    if [ ${in_container} -eq 1 ]; then 
        rm -rf /home/regress/cantian_data/data
        rm -rf /mnt/dbdata/local/cantian/tmp/data
        chown -hR root:root /mnt/dbdata/local
        chown -hR root:root /opt/cantian/cantian
    fi
    echo "shell uninstall step 5 $(date)"
    if [ ! -f  ${CURRENT_PATH}/${CANTIAN_UNINSTALL_PY_NAME} ]; then
        echo "${CANTIAN_UNINSTALL_PY_NAME} is not exist.]"
        return 1
    fi
    echo "shell uninstall step 6 $(date)"
    storage_metadata_fs=`python3 ${CURRENT_PATH}/get_config_info.py "storage_metadata_fs"`
    node_id=`python3 ${CURRENT_PATH}/get_config_info.py "node_id"`
    mysql_data_dir="/mnt/dbdata/remote/metadata_${storage_metadata_fs}/node${node_id}"
    if [ -d ${mysql_data_dir} ]; then
        chmod -R 750 ${mysql_data_dir}/*
    fi
    python3 ${CURRENT_PATH}/cantian_uninstall.py ${uninstall_type} ${force_uninstall}

    ret=$?
    if [ ${ret} -ne 0 ]; then
        echo "Execute ${CANTIAN_UNINSTALL_PY_NAME} return ${ret}."
        return 1
    fi

    echo "shell uninstall step 7 $(date)"
    if [ -d /mnt/dbdata/local/cantian/tmp/data/log ]; then
        mkdir -p -m 750 /opt/cantian/cantian/log/cantian_start_log
        yes | cp -arf /mnt/dbdata/local/cantian/tmp/data/log /opt/cantian/cantian/log/cantian_start_log
    fi

    if [ $? -ne 0 ]; then
        echo "Copy log file or dir failed, please check the permission and manually repair this."
        return 1
    fi

    echo "shell uninstall step 8 $(date)"
    if [ -d /mnt/dbdata/local/cantian/tmp/data/dbstor/data/logs ]; then
        mkdir -p -m 750 /opt/cantian/dbstor/log/dbstore_start_log
        yes | cp -arf /mnt/dbdata/local/cantian/tmp/data/dbstor/data/logs /opt/cantian/dbstor/log/dbstore_start_log
    fi

    if [ $? -ne 0 ]; then
        echo "Copy log file or dir failed, please check the permission and manually repair this."
        return 1
    fi

    echo "shell uninstall step 9 $(date)"
    if [ -d /mnt/dbdata/local/cantian/tmp/data ]; then
        rm -rf /mnt/dbdata/local/cantian/tmp/data
    fi

    if [ $? -ne 0 ]; then
        echo "Remove data file or dir failed, please check the permission and manually repair this."
        return 1
    fi

    echo "shell uninstall step 10 $(date)"
    echo "cantian uninstall success."

    return 0
}

uninstall_type=$1
force_uninstall=$2
cantian_uninstall &>> ${CANTIAN_INSTALL_LOG_FILE}