#!/bin/bash
################################################################################
# 【功能说明】
# 1.appctl.sh由管控面调用
# 2.完成如下流程
#     服务初次安装顺序:pre_install->install->start->check_status
#     服务带配置安装顺序:pre_install->install->restore->start->check_status
#     服务卸载顺序:stop->uninstall
#     服务带配置卸载顺序:backup->stop->uninstall
#     服务重启顺序:stop->start->check_status

#     服务A升级到B版本:pre_upgrade(B)->stop(A)->update(B)->start(B)->check_status(B)
#                      update(B)=备份A数据，调用A脚本卸载，调用B脚本安装，恢复A数据(升级数据)
#     服务B回滚到A版本:stop(B)->rollback(B)->start(A)->check_status(A)->online(A)
#                      rollback(B)=根据升级失败标志调用A或是B的卸载脚本，调用A脚本安装，数据回滚特殊处理
# 3.典型流程路线：install(A)-upgrade(B)-upgrade(C)-rollback(B)-upgrade(C)-uninstall(C)
# 【返回】
# 0：成功
# 1：失败
#
# 【注意事项】
# 1.所有的操作需要支持失败可重入
################################################################################
set +x
#当前路径
CURRENT_PATH=$(dirname $(readlink -f "$0"))

#脚本名称
PARENT_DIR_NAME=$(pwd | awk -F "/" '{print $NF}')
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename "$0")

#依赖文件
source "${CURRENT_PATH}"/../log4sh.sh
source "${CURRENT_PATH}"/../env.sh

#组件名称
COMPONENTNAME="logicrep"
LOGICREP_HOME='/opt/software/tools/logicrep'
LOGICREP_PKG="${CURRENT_PATH}/../../zlogicrep/build/Cantian_PKG/file"

tools_home='/opt/cantian/logicrep'
tools_scripts='/opt/cantian/action/logicrep'

LOG_FILE="${tools_home}/log/logicrep_deploy.log"
FLAG_FILE="${LOGICREP_HOME}/start.success"
ENABLE_FILE="${LOGICREP_HOME}/enable.success"
#在首次安装和无logicrep版本离线升级时使用
USER_FILE="${LOGICREP_HOME}/create_user.json"

deploy_group=$(python3 "${CURRENT_PATH}"/../get_config_info.py "deploy_group")
node_id=$(python3 "${CURRENT_PATH}"/../get_config_info.py "node_id")
node_count=$(python3 "${CURRENT_PATH}"/../get_config_info.py "cluster_scale")
storage_metadata_fs_name=$(python3 "${CURRENT_PATH}"/../get_config_info.py "storage_metadata_fs")
storage_archive_fs_name=$(python3 "${CURRENT_PATH}"/../get_config_info.py "storage_archive_fs")
storage_archive_fs_path="/mnt/dbdata/remote/archive_${storage_archive_fs_name}"
install_type=$(python3 "${CURRENT_PATH}"/../get_config_info.py "install_type")
startup_lock="/mnt/dbdata/remote/metadata_${storage_metadata_fs_name}/logicre_startup.lock"
startup_status="/mnt/dbdata/remote/metadata_${storage_metadata_fs_name}/logicrep_status"


so_name_all=("libssl.so" "libcrypto.so" "libstdc++.so" "libsql2bl.so")
so_name=("" "" "" "")
link_name=("libssl.so.10" "libcrypto.so.10" "libstdc++.so.6" "libsql2bl.so")
driver_name="com.huawei.cantian.jdbc.CantianDriver-Cantian.jar"

function usage()
{
    echo "Usage: ${0##*/} {start|startup|shutdown|stop|install|uninstall|pre_upgrade|
                           upgrade_backup|upgrade|rollback|check_status}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    exit 1
}

function log() {
	printf "[%s] %s\n" "`date -d today \"+%Y-%m-%d %H:%M:%S.%N\"`" "$1"
}


# 通用入口
function do_deploy()
{
    local action=$1
    local mode=$2

    if [ ! -f  "${CURRENT_PATH}"/logicrep_ctl.py ]; then
        echo "${COMPONENTNAME} logicrep_ctl.py is not exist. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    su -s /bin/bash - "${cantian_user}" -c "export LD_LIBRARY_PATH=${LOGICREP_HOME}/lib:${LD_LIBRARY_PATH} && cd ${CURRENT_PATH} && python3 -B ${CURRENT_PATH}/logicrep_ctl.py ${action} ${mode}"
    ret=$?
    if [ $ret -ne 0 ]; then
        echo "Execute ${COMPONENTNAME} logicrep_ctl.py return ${ret}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi
    return 0
}


function chown_mod_scripts() {
    current_path_reg=$(echo "${CURRENT_PATH}" | sed 's/\//\\\//g')
    scripts=$(ls "${CURRENT_PATH}" | awk '{if($1!="appctl.sh"){print $1}}' | sed "s/^/${current_path_reg}\//g")
    chown "${cantian_user}":"${cantian_group}" ${scripts}
    chmod 400 "${CURRENT_PATH}"/*.py "${CURRENT_PATH}"/*.sh
    find "${CURRENT_PATH}/../../zlogicrep/" -type f -print0 | xargs -0 chmod 600
    find "${CURRENT_PATH}/../../zlogicrep/" -type f \( -name "*.sh" -o -name "*.so" \) -exec chmod 500 {} \;
    find "${CURRENT_PATH}/../../zlogicrep/" -type d -print0 | xargs -0 chmod 700
}

# 复制logicrep主体和部署脚本
function copy_logicrep()
{
    if [ ! -d /opt/software/tools ]
    then
        mkdir -m 750 -p /opt/software/tools
    fi
    chmod 755 /opt/software
    if [ -d ${LOGICREP_HOME} ]
    then
        rm -rf ${LOGICREP_HOME}
    fi
    rm -rf ${tools_scripts}
    cp -rfp "${CURRENT_PATH}" ${tools_scripts}

    if [[ "${node_id}" == "0" ]];then
        rm -rf "${storage_archive_fs_path}"/{binlog,logicrep_conf}
        mkdir -m 770 -p "${storage_archive_fs_path}"/{binlog,logicrep_conf}
        cp -rf "${LOGICREP_PKG}"/conf/init.properties "${storage_archive_fs_path}"/logicrep_conf/
        cp -rf "${LOGICREP_PKG}"/conf/repconf/repconf_db.xml "${storage_archive_fs_path}"/logicrep_conf/
        chmod 660 "${storage_archive_fs_path}"/logicrep_conf/*
        chown -hR "${cantian_user}":"${deploy_group}" "${storage_archive_fs_path}"/{binlog,logicrep_conf}
    fi

    cp -r "${LOGICREP_PKG}"  ${LOGICREP_HOME}
    rm -rf ${LOGICREP_HOME}/conf/sec/*
    touch ${LOGICREP_HOME}/conf/sec/primary_keystore.ks ${LOGICREP_HOME}/conf/sec/standby_keystore.ks
    chmod 600 ${LOGICREP_HOME}/conf/sec/*
    cp -a /opt/cantian/image/Cantian-RUN-CENTOS-64bit/kmc_shared/* ${LOGICREP_HOME}/lib
    ln -s ${LOGICREP_HOME}/com.huawei.cantian.logicrep-*.jar ${LOGICREP_HOME}/com.huawei.cantian.logicrep.jar
    rm -rf "${LOGICREP_HOME}"/conf/init.properties
    rm -rf "${LOGICREP_HOME}"/conf/repconf/repconf_db.xml
    ln -s "${storage_archive_fs_path}"/logicrep_conf/init.properties ${LOGICREP_HOME}/conf/init.properties
    ln -s "${storage_archive_fs_path}"/logicrep_conf/repconf_db.xml ${LOGICREP_HOME}/conf/repconf/repconf_db.xml
    chmod 750 ${LOGICREP_HOME} /opt/software/tools

    if [[ "${node_id}" == "0" ]];then
        touch ${USER_FILE} &>/dev/null
        chmod 400 ${USER_FILE}
    fi

    chown -hR "${cantian_user}":"${cantian_group}" /opt/software/tools
}

# 替换升级文件，升级模式使用
function safe_update()
{
    version_first_number=$(cat /opt/cantian/versions.yml |sed 's/ //g' | grep 'Version:' | awk -F ':' '{print $2}' | awk -F '.' '{print $1}')
    if [[ ${version_first_number} -ne 2 ]]; then
        rm -rf ${tools_scripts}
        cp -rfp "${CURRENT_PATH}" ${tools_scripts}
        rm -f ${LOGICREP_HOME}/com.huawei.cantian.logicrep.jar
        find ${LOGICREP_HOME}/lib -type f ! -name "libssl.*" ! -name "libcrypto.*" ! -name "libstdc++.*" ! -name "libsql2bl.*" -delete
        cp -fp "${LOGICREP_PKG}"/com.huawei.cantian.logicrep-*.jar "${LOGICREP_HOME}"/com.huawei.cantian.logicrep-*.jar
        cp -arf "${LOGICREP_PKG}"/lib/* "${LOGICREP_HOME}"/lib
        cp -arf "${LOGICREP_PKG}"/repconf_db_confige.py "${LOGICREP_HOME}"/
        cp -arf "${LOGICREP_PKG}"/shutdown_all_logicrep.sh "${LOGICREP_HOME}"/
        cp -arf "${LOGICREP_PKG}"/shutdown.sh "${LOGICREP_HOME}"/
        # startup前进行依赖文件拷贝操作
        copy_bin "${SO_PATH}"
        cp -arf "${LOGICREP_PKG}"/startup.sh "${LOGICREP_HOME}"/
        cp -arf "${LOGICREP_PKG}"/watchdog_logicrep.sh "${LOGICREP_HOME}"/
        cp -arf "${LOGICREP_PKG}"/watchdog_shutdown.sh "${LOGICREP_HOME}"/
        cp -a /opt/cantian/image/Cantian-RUN-CENTOS-64bit/kmc_shared/* ${LOGICREP_HOME}/lib
        ln -s ${LOGICREP_HOME}/com.huawei.cantian.logicrep-*.jar ${LOGICREP_HOME}/com.huawei.cantian.logicrep.jar
        chmod 600 "${startup_lock}" > /dev/null 2>&1
        chown -hR "${cantian_user}":"${cantian_group}" /opt/software/tools
    else
        ACTION="install"
        main_deploy
    fi
}

# 日志目录
function check_and_create_home()
{
    if [ ! -d ${tools_home} ]; then
        mkdir -m 755 -p ${tools_home}
    fi
    if [ ! -d ${tools_home}/log ]; then
        mkdir -m 750 -p ${tools_home}/log
        touch ${LOG_FILE}
        chmod 640 ${LOG_FILE}
    fi
    chown "${cantian_user}":"${cantian_group}" -hR ${tools_home}/log
}

# 检查获取最新so
function get_newest_filelist() {
    local path=$1
    for i in {0..3};do
        for data in `ls -r $path`;do
            # 如果是文件夹则跳过
            if [ -d $path"/"$data ];then
                continue
            fi
            # 正则匹配，取最新版依赖名称
            if [ `echo $data|grep ^${so_name_all[$i]}` ];then
                so_name[i]=$data
                break
            fi
        done
    done
}

# 复制电信的so文件
function copy_bin()
{
    local path=$1
    if [ -z "$path" ];then
        return 0
    fi
    if [ ! -d "$path" ];then
        echo "error bin path"
        exit 1
    fi
    if [ -d "${path}"/"${driver_name}" ]; then
        echo "error: jar not found"
        exit 1
    fi
    cp -f "${path}"/"${driver_name}" "${LOGICREP_HOME}"/lib
    get_newest_filelist "${path}"
    if [ $? -ne 0 ]; then
        echo "error: no enough so files"
        exit 1
    fi
    for i in {0..3};do
        rm -f  ${LOGICREP_HOME}/lib/"${so_name[$i]}"
        rm -f  ${LOGICREP_HOME}/lib/"${link_name[$i]}"
        cp -f "${path}"/"${so_name[$i]}" "${LOGICREP_HOME}"/lib
        chmod 500 "${LOGICREP_HOME}"/lib/"${so_name[$i]}"
        ln -s "${LOGICREP_HOME}"/lib/"${so_name[$i]}" "${LOGICREP_HOME}"/lib/"${link_name[$i]}"
        if [ $? -ne 0 ];then
            exit 1
        fi
    done
    chown -hR  "${cantian_user}":"${cantian_group}" /opt/software/tools
}

function check_status() {
    # 检查守护进程
    watchdog_pid=$(ps -ef | grep "/opt/software/tools/logicrep/watchdog_logicrep.sh -n logicrep -N" | grep -v grep | awk '{print $2}')
    if [[ -f /opt/software/tools/logicrep/start.success ]] && [[ -z ${watchdog_pid} ]];then
        logAndEchoError "Logicrep watchdog process is offline."
        exit 1
    fi
    # 检查logicrep进程
    logicrep_pid=$(ps -ef | grep ZLogCatcherMain | grep -v grep | awk '{print $2}')
    if [[ -f ${ENABLE_FILE} ]] && [[ -z ${logicrep_pid} ]];then
        logAndEchoError "Logicrep process is offline."
        exit 1
    fi
}

function check_startup_status() {
  timeout=900
  while (( timeout > 0 )); do
    sleep 1
    ((timeout--))
    if [ ! -f "/mnt/dbdata/remote/metadata_${storage_metadata_fs_name}/logicrep_status" ]; then
      continue
    fi
    startup_status=$(cat "/mnt/dbdata/remote/metadata_${storage_metadata_fs_name}/logicrep_status")
    if [[ x${startup_status} == x"started" ]]; then
      log "--------logicrep startup success--------"
      return 0
    fi
    if ((timeout % 10 == 0)); then
      log "Current status: ${startup_status}, Remaining timeout: ${timeout} seconds" >> ${LOG_FILE}
    fi
  done
  return 1
}

check_and_create_home

ACTION=$1
SUP_ACTION="set_resource_limit"
BACKUP_UPGRADE_PATH=""
BIN_PATH=""
START_MODE="active"
SO_PATH=""
if [ $# -gt 1 ]; then
    BACKUP_UPGRADE_PATH=$2
    BIN_PATH=$2
    START_MODE=$2
fi
if [ $# -gt 2 ]; then
    BACKUP_UPGRADE_PATH=$3
fi
if [ $# -gt 3 ]; then
    SO_PATH=$4
fi

function main_deploy()
{
    case "$ACTION" in
        start)
            if [[ -f ${USER_FILE} ]] && [[ x"${install_type}" == x"override" ]];then
                do_deploy "--act ${ACTION}" "--mode ${START_MODE}"
                ret=$?
                if [ $ret -eq 0 ]; then
                    rm -f ${USER_FILE}
                else
                    exit $ret
                fi
            fi
            do_deploy "--act ${SUP_ACTION}" "--mode ${START_MODE}"
            ret=$?
            exit ${ret}
            ;;
        startup)
            sysctl -w kernel.sched_rt_runtime_us=-1
            copy_bin "$BIN_PATH"
            do_deploy "--act ${ACTION}"
            if [ $? -ne 0 ]; then
               exit 1
            fi
            touch ${FLAG_FILE}
            chmod 400 ${FLAG_FILE}
            chown -h "${cantian_user}":"${cantian_group}" ${FLAG_FILE}
            logicrep_pid=$(ps -ef | grep "/opt/software/tools/logicrep/watchdog_logicrep.sh -n logicrep -N" | grep -v grep | awk '{print $2}')
            if [[ -z ${logicrep_pid} ]];then
                su -s /bin/bash - ${cantian_user} -c "nohup sh ${LOGICREP_HOME}/watchdog_logicrep.sh -n logicrep -N ${node_count} &" >> /opt/cantian/deploy/deploy.log 2>&1
                check_startup_status
            fi
            exit $?
            ;;
        shutdown)
            if [ -f ${FLAG_FILE} ];then
                rm ${FLAG_FILE}
            fi
            su -s /bin/bash - ${cantian_user} -c "sh ${LOGICREP_HOME}/watchdog_shutdown.sh -n logicrep -f"
            do_deploy "--act ${ACTION}"
            if [ $? -ne 0 ]; then
               exit 1
            fi
            if [ -f ${ENABLE_FILE} ];then
                rm -rf ${ENABLE_FILE}
            fi
            exit $?
            ;;
        stop)
            su -s /bin/bash - ${cantian_user} -c "sh ${LOGICREP_HOME}/watchdog_shutdown.sh -n logicrep -f"
            do_deploy "--act ${ACTION}"
            if [ $? -ne 0 ]; then
               exit 1
            fi
            if [ -f ${ENABLE_FILE} ];then
                rm -rf ${ENABLE_FILE}
            fi
            exit $?
            ;;
        install)
            chown_mod_scripts
            copy_logicrep
            do_deploy "--act ${ACTION}"
            exit $?
            ;;
        uninstall)
            rm -rf ${LOGICREP_HOME}
            if [[ -f ${startup_lock} ]];then
                rm -rf "${startup_lock}"
            fi
            if [[ -f ${startup_status} ]];then
                rm -rf "${startup_status}"
            fi
            exit $?
            ;;
        pre_upgrade)
            chown -hR "${cantian_user}":"${cantian_group}" "${CURRENT_PATH}"/../inspection
            chmod 600 "${startup_lock}" > /dev/null 2>&1
            chown -hR "${cantian_user}":"${cantian_group}" "${startup_lock}" > /dev/null 2>&1
            chown_mod_scripts
            do_deploy "--act ${ACTION}"
            exit $?
            ;;
        upgrade_backup)
            if [ -d ${LOGICREP_HOME} ]; then
                mkdir -m 750 "${BACKUP_UPGRADE_PATH}"/logicrep
                cp -rfp ${LOGICREP_HOME} "${BACKUP_UPGRADE_PATH}"/logicrep
            fi
            exit $?
            ;;
        upgrade)
            safe_update
            exit $?
            ;;
        rollback)
            if [ ! -d "${BACKUP_UPGRADE_PATH}"/logicrep/logicrep ]; then
                exit 0
            fi
            if [ -d ${LOGICREP_HOME} ]; then
                rm -rf ${LOGICREP_HOME}
            fi
            cp -rfp "${BACKUP_UPGRADE_PATH}"/logicrep/logicrep ${LOGICREP_HOME}
            exit $?
            ;;
        check_status)
            check_status
            chown -hR "${cantian_user}":"${cantian_group}" "${CURRENT_PATH}"/../inspection
            do_deploy "--act pre_upgrade"
            exit $?
            ;;
        *)
            usage
            ;;
    esac
}

main_deploy