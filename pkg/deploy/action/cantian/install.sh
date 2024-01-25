# 确定相对路径
set +x
#当前路径
CURRENT_PATH=$(dirname $(readlink -f $0))
CANTIAN_INSTALL_PY_NAME="cantian_install.py"
RPM_UNPACK_PATH="/opt/cantian/image/Cantian-RUN-CENTOS-64bit"

CANTIAN_INSTALL_LOG_FILE=/opt/cantian/cantian/log/cantian_deploy.log
CANTIAN_INSTALL_CONFIG=/opt/cantian/cantian/cfg

function log() {
  printf "[%s] %s\n" "`date -d today \"+%Y-%m-%d %H:%M:%S\"`" "$1" >> ${CANTIAN_INSTALL_LOG_FILE}
}

# 判断是否存在对应的文件，不存在返回报错，存在则继续运行
function cantian_install()
{

    install_type=$(python3 ${CURRENT_PATH}/get_config_info.py "install_type")
    node_id=$(python3 ${CURRENT_PATH}/get_config_info.py "node_id")
    cantian_use=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_user")
    cantian_group=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_group")
    mes_type=$(python3 ${CURRENT_PATH}/get_config_info.py "mes_type")
    cert_encrypt_pwd=""
    user_pwd=""

    if [[ ${install_type} = "override" ]]; then
        is_encrept=0
        read -s -p "Please Input SYS_PassWord: " user_pwd
        if [[ x"${mes_type}" == x"TCP" ]];then
            read -s -p "Please Input cert passwd: " cert_encrypt_pwd
        fi
    else
        is_encrept=1
        SYS_PASSWORD=`python3 ${CURRENT_PATH}/get_config_info.py "SYS_PASSWORD"`
        if [[ ${SYS_PASSWORD} != "" ]]; then
            user_is_encrept=${SYS_PASSWORD}
        else
            log "SYS_PASSWORD NOT FOUND"
            return 1
        fi
    fi

    if [ ! -f  ${CURRENT_PATH}/${CANTIAN_INSTALL_PY_NAME} ]; then
        log " ${CANTIAN_INSTALL_PY_NAME} is not exist."
        return 1
    fi

    if [ -d /mnt/dbdata/local/cantian/tmp/data ]; then
        rm -rf /mnt/dbdata/local/cantian/tmp/data
    fi

    if [ ! -d /opt/cantian/cantian/server ]; then
        mkdir -p -m 750 /opt/cantian/cantian/server
    fi

    if [ ! -d /mnt/dbdata/local/cantian/tmp/data ]; then
        mkdir -p -m 750 /mnt/dbdata/local/cantian/tmp/data
    fi
    chmod 750 /mnt/dbdata/local/cantian/tmp

    if [ ! -d /opt/cantian/cantian/log ]; then
        mkdir -p -m 750 /opt/cantian/cantian/log
    fi

    cp -rf ${RPM_UNPACK_PATH}/add-ons /opt/cantian/cantian/server/
    cp -rf ${RPM_UNPACK_PATH}/bin /opt/cantian/cantian/server/
    cp -rf ${RPM_UNPACK_PATH}/lib /opt/cantian/cantian/server/
    cp -rf ${RPM_UNPACK_PATH}/admin /opt/cantian/cantian/server/
    cp -rf ${RPM_UNPACK_PATH}/cfg /opt/cantian/cantian/server/
    cp -rf ${RPM_UNPACK_PATH}/package.xml /opt/cantian/cantian/server/
    chmod 700 -R /opt/cantian/cantian/server
    log "rpm files copy success."

    # 执行主文件
    cd ${CURRENT_PATH}
    if [ ${is_encrept} -eq 0 ]; then
        source ~/.bashrc
        export LD_LIBRARY_PATH=/opt/cantian/dbstor/lib:${LD_LIBRARY_PATH}
        echo -e "${user_pwd}\n${cert_encrypt_pwd}" | python3 ${CURRENT_PATH}/cantian_install.py -s password
        ret=$?
        if [ $ret -ne 0 ]; then
            log "Execute ${CANTIAN_INSTALL_PY_NAME} return $ret."
            return 1
        fi
    else
        cp -r /opt/cantian/backup/files/cantian/dbstor_config.ini /mnt/dbdata/local/cantian/tmp/data/dbstor/conf/dbs/
        cp -f /opt/cantian/backup/files/cantian/cantiand.ini /mnt/dbdata/local/cantian/tmp/data/cfg/
        cp -f /opt/cantian/backup/files/cantian/ctsql.ini /mnt/dbdata/local/cantian/tmp/data/cfg/
        cp -f /opt/cantian/backup/files/cantian/cantian_config.json ${CANTIAN_INSTALL_CONFIG}/
        echo -e "${user_is_encrept}\n${cert_encrypt_pwd}" | python3 ${CURRENT_PATH}/cantian_install.py -s password -t reserve
        ret=$?
        if [ $ret -ne 0 ]; then
            log "Execute ${CANTIAN_INSTALL_PY_NAME} return $ret."
            return 1
        fi
    fi

    if [[ ${is_encrept} -eq 1 ]]; then
        rm -rf /mnt/dbdata/local/cantian/tmp/data/dbstor/conf/dbs/dbstor_config.ini
        cp -r /opt/cantian/backup/files/cantian/dbstor_config.ini /mnt/dbdata/local/cantian/tmp/data/dbstor/conf/dbs/
        rm -rf /mnt/dbdata/local/cantian/tmp/data/cfg
        cp -rf /opt/cantian/backup/files/cantian/cfg /mnt/dbdata/local/cantian/tmp/data/
        rm -rf ${CURRENT_PATH}/cantian_config.json
        cp -f /opt/cantian/backup/files/cantian/cantian_config.json ${CURRENT_PATH}/
    fi

    log "cantian install success."

    return 0
}

cantian_install