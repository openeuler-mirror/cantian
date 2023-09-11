# 确定相对路径
set +x
#当前路径
CURRENT_PATH=$(dirname $(readlink -f $0))

CANTIAN_INSTALL_LOG_FILE=/opt/cantian/cantian/log/cantian_deploy.log
CANTIAN_INSTALL_CONFIG=/opt/cantian/cantian/cfg
# 判断是否存在对应的文件，不存在返回报错，存在则继续运行
function cantian_backup()
{
    if [ ! -d /opt/cantian/backup/files/cantian ]; then
        mkdir -p -m 700 /opt/cantian/backup/files/cantian
    fi

    if [ -f /mnt/dbdata/local/cantian/tmp/data/dbstor/conf/dbs/dbstor_config.ini ]; then
        cp -af /mnt/dbdata/local/cantian/tmp/data/dbstor/conf/dbs/dbstor_config.ini /opt/cantian/backup/files/cantian/
    fi

    if [ -f /mnt/dbdata/local/cantian/tmp/data/cfg/cantiand.ini ]; then
        cp -af /mnt/dbdata/local/cantian/tmp/data/cfg/cantiand.ini /opt/cantian/backup/files/cantian/
    fi

    if [ -d /mnt/dbdata/local/cantian/tmp/data/cfg ]; then
        cp -ar /mnt/dbdata/local/cantian/tmp/data/cfg /opt/cantian/backup/files/cantian/
    fi

    if [ -f ${CANTIAN_INSTALL_CONFIG}/cantian_config.json ]; then
        cp -af ${CANTIAN_INSTALL_CONFIG}/cantian_config.json /opt/cantian/backup/files/cantian/
    fi
  
    echo "cantian back up success." >> ${CANTIAN_INSTALL_LOG_FILE}
    return 0
}

cantian_backup