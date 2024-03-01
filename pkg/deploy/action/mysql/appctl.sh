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
CURRENT_PATH=$(dirname $(readlink -f $0))

#脚本名称
PARENT_DIR_NAME=$(pwd | awk -F "/" '{print $NF}')
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)

INSTALL_NAME="install.sh"
source ${CURRENT_PATH}/../log4sh.sh

deploy_user=`python3 ${CURRENT_PATH}/../get_config_info.py "deploy_user"`
deploy_group=`python3 ${CURRENT_PATH}/../get_config_info.py "deploy_group"`

function usage()
{
    logAndEchoInfo "Usage: ${0##*/} {install}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    exit 1
}

function do_deploy()
{
    local script_name_param=$1

    if [ ! -f  ${CURRENT_PATH}/${script_name_param} ]; then
        logAndEchoError "${COMPONENT_NAME} ${script_name_param} is not exist. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    su -s /bin/bash - ${deploy_user} -c "cd ${CURRENT_PATH} && sh ${CURRENT_PATH}/${script_name_param}"
    ret=$?

    if [ $ret -ne 0 ]; then
        logAndEchoError "Execute ${COMPONENT_NAME} ${script_name_param} return ${ret}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    return 0
}

owner=$(stat -c %U ${CURRENT_PATH})

function chown_mod_scripts()
{
    set -e
    echo -e "\nInstall User:${deploy_user}   Scripts Owner:${owner} "
    current_path_reg=$(echo $CURRENT_PATH | sed 's/\//\\\//g')
    scripts=$(ls ${CURRENT_PATH} | sed '/appctl.sh/d' | sed '/chmod_file.sh/d' | sed "s/^/${current_path_reg}\/&/g")
    chown -h ${deploy_user}:${deploy_group} ${scripts}
    chown -hR ${deploy_user}:${deploy_group} /opt/cantian/image/cantian_connector/for_mysql_official/
    chmod -R 400 ${CURRENT_PATH}
    chmod 755 ${CURRENT_PATH}
    set +e
}

function do_install2chown4mysql()
{
    chown_mod_scripts
    if [ -d /opt/cantian/mysql/server/ ]; then
        rm -rf /opt/cantian/mysql/server/
    fi
    set -e
    cp -arfp ${CURRENT_PATH} /opt/cantian/action/
    if [ -f /opt/cantian/cantian/server/admin/scripts/cantian_defs.sql ];then
        mkdir -p -m 700 /opt/cantian/mysql/scripts
        cp /opt/cantian/cantian/server/admin/scripts/cantian_defs.sql /opt/cantian/mysql/scripts/
        chmod 600 /opt/cantian/mysql/scripts/cantian_defs.sql
        chown -hR cantiandba:cantiandba /opt/cantian/mysql/scripts/
    fi
    do_deploy ${INSTALL_NAME}
    set +e
    if [ -f "${BACKUP_UPGRADE_PATH}"/mysql/mysqld ];then
       cp -arf "${BACKUP_UPGRADE_PATH}"/mysql/mysqld /opt/cantian/image/cantian_connector/for_mysql_official/mf_connector_mount_dir/plugin/
    fi
    sh ${CURRENT_PATH}/chmod_file.sh
    exit $?
}

function do_install2chown4mysqlrollback()
{
    backup_dir=$1
    if [ ! -d ${backup_dir}/action/mysql ];then
        echo "Error: backup_dir ${backup_dir}/action/mysql does not exist"
        return 1
    fi
    chown_mod_scripts
    if [ -d /opt/cantian/mysql/server/ ]; then
        rm -rf /opt/cantian/mysql/server/
    fi
    set -e
    cp -arfp ${backup_dir}/action/mysql /opt/cantian/action/
    if [ -f /opt/cantian/cantian/server/admin/scripts/cantian_defs.sql ];then
        mkdir -p -m 700 /opt/cantian/mysql/scripts
        cp /opt/cantian/cantian/server/admin/scripts/cantian_defs.sql /opt/cantian/mysql/scripts/
        chmod 600 /opt/cantian/mysql/scripts/cantian_defs.sql
        chown -hR cantiandba:cantiandba /opt/cantian/mysql/scripts/
    fi
    do_deploy ${INSTALL_NAME}
    set +e
    if [ -f ${backup_dir}/mysql/mysqld ];then
        cp -arf ${backup_dir}/mysql/mysqld /opt/cantian/image/cantian_connector/for_mysql_official/mf_connector_mount_dir/plugin/
    fi
    sh ${CURRENT_PATH}/chmod_file.sh
    exit $?
}

function do_upgrade_backup() {
    local backup_dir
    backup_dir=$1
    if [ ! -d ${backup_dir}/mysql ];then
        mkdir ${backup_dir}/mysql
    fi
    local mysqld_path
    mysqld_path=/opt/cantian/image/cantian_connector/for_mysql_official/mf_connector_mount_dir/plugin/mysqld
    if [ -f ${mysqld_path} ];then
        cp -arf ${mysqld_path} ${backup_dir}/mysql/
    fi
}

##################################### main #####################################
ACTION=$1
BACKUP_UPGRADE_PATH=$3

case "$ACTION" in
    install)
        do_install2chown4mysql
        ;;
    pre_upgrade)
        exit 0
        ;;
    upgrade_backup)
        BACKUP_PATH=$2
        do_upgrade_backup ${BACKUP_PATH}
        exit 0
        ;;
    upgrade)
        # 安装新包中即可
        do_install2chown4mysql
        ;;
    post_upgrade)
        exit 0
        ;;
    rollback)
        # 安装旧包即可
        do_install2chown4mysqlrollback ${BACKUP_UPGRADE_PATH}
        ;;
    *)
        usage
        ;;
esac
