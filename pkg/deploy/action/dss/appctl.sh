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
DSS_SOURCE=${CURRENT_PATH}/../../dss
dss_scripts=/opt/cantian/action/dss

#依赖文件
source "${CURRENT_PATH}"/../log4sh.sh
source "${CURRENT_PATH}"/../env.sh

function usage()
{
    echo "Usage: ${0##*/} {start|startup|shutdown|stop|install|uninstall|pre_upgrade|
                           upgrade_backup|upgrade|rollback|check_status|init_container}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    return 1
}

function log() {
	printf "[%s] %s\n" "`date -d today \"+%Y-%m-%d %H:%M:%S.%N\"`" "$1"
}

# 通用入口
function do_deploy()
{
    local action=$1
    local mode=$2
    su -s /bin/bash - "${cantian_user}" -c "python3 -B ${CURRENT_PATH}/dssctl.py ${action} ${mode}"
    ret=$?
    if [ $ret -ne 0 ]; then
        echo "Execute ${COMPONENTNAME} dssctl.py return ${ret}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi
    return 0
}

function permission_opt() {
    chmod 500 "${DSS_SOURCE}"/bin/*
    chown -hR "${cantian_user}":"${cantian_group}" "${DSS_SOURCE}"
    chown -hR "${cantian_user}":"${cantian_group}" "${CURRENT_PATH}"/*
    chown root:root "${CURRENT_PATH}"/appctl.sh
    mkdir -p /opt/cantian/log/dss
    touch /opt/cantian/log/dss/dss_deploy.log
    chmod -R 750 /opt/cantian/log/dss/
    chown -hR "${cantian_user}":"${cantian_group}" /opt/cantian/log/dss/
    mkdir -m 750 -p /opt/cantian/dss/
    chown -hR "${cantian_user}":"${cantian_group}" /opt/cantian/dss/
}

function copy_dss_scripts()
{
    echo "copying the cms scripts"
    clean_dss_scripts
    mkdir -p ${dss_scripts}
    chmod 755 ${dss_scripts}
    cp -arf ${CURRENT_PATH}/* ${dss_scripts}/
}

function clean_dss_scripts()
{
    if [ -d ${dss_scripts} ]; then
        rm -rf ${dss_scripts}
    fi
}

ACTION=$1
if [ $# -gt 1 ]; then
    BACKUP_UPGRADE_PATH=$2
    BIN_PATH=$2
    START_MODE=$2
fi
if [ $# -gt 2 ]; then
    BACKUP_UPGRADE_PATH=$3
fi


function main()
{
    case "$ACTION" in
        start)
            do_deploy "--action=${ACTION}"
            exit $?
            ;;
        stop)
            do_deploy "--action=${ACTION}"
            exit $?
            ;;
        pre_install)
            permission_opt
            do_deploy "--action=${ACTION}"
            exit $?
            ;;
        install)
            permission_opt
            copy_dss_scripts
            do_deploy "--action=${ACTION} --mode=${START_MODE}"
            exit $?
            ;;
        uninstall)
            permission_opt
            do_deploy "--action=${ACTION} --mode=${START_MODE}"
            exit $?
            ;;
        backup)
            exit 0
            ;;
        pre_upgrade)
            do_deploy "--action=${ACTION}"
            exit $?
            ;;
        upgrade_backup)
            do_deploy "--action=${ACTION}"
            exit $?
            ;;
        upgrade)
            do_deploy "--action=${ACTION}"
            exit $?
            ;;
        rollback)
            do_deploy "--action=${ACTION}"
            exit $?
            ;;
        check_status)
            do_deploy "--action=${ACTION}"
            exit $?
            ;;
        *)
            usage
            exit $?
            ;;
    esac
}
main