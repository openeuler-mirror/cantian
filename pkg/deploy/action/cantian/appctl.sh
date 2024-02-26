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

#组件名称
COMPONENTNAME=cantian

INSTALL_NAME="install.sh"
UNINSTALL_NAME="uninstall.sh"
START_NAME="start.sh"
STOP_NAME="stop.sh"
PRE_INSTALL_NAME="pre_install.sh"
BACKUP_NAME="backup.sh"
RESTORE_NAME="restore.sh"
STATUS_NAME="check_status.sh"
UPGRADE_NAME="upgrade.sh"
ROLLBACK_NAME="rollback.sh"
source ${CURRENT_PATH}/cantiand_cgroup_calculate.sh
LOG_FILE="/opt/cantian/cantian/log/cantian_deploy.log"

cantian_home=/opt/cantian/cantian
cantian_local=/mnt/dbdata/local/cantian
cantian_scripts=/opt/cantian/action/cantian
storage_metadata_fs=$(python3 ${CURRENT_PATH}/../get_config_info.py "storage_metadata_fs")

source ${CURRENT_PATH}/../env.sh
cantian_user="${cantian_user}":"${cantian_group}"

function usage()
{
    echo "Usage: ${0##*/} {start|stop|install|uninstall|pre_install|
                          pre_upgrade|check_status|upgrade|post_upgrade|rollback|upgrade_backup}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    exit 1
}

function do_deploy()
{
    local script_name_param=$1
    local uninstall_type=$2
    local force_uninstall=$3

    if [ ! -f  ${CURRENT_PATH}/${script_name_param} ]; then
        echo "${COMPONENTNAME} ${script_name_param} is not exist. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi
    su -s /bin/bash - ${user} -c "cd ${CURRENT_PATH} && sh ${CURRENT_PATH}/${script_name_param} ${uninstall_type} ${force_uninstall}"

    ret=$?
    if [ $ret -ne 0 ]; then
        echo "Execute ${COMPONENTNAME} ${script_name_param} return ${ret}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    return 0
}

function create_cgroup_path()
{
    if [[ -d /sys/fs/cgroup/memory/cantiand ]]; then
        rmdir /sys/fs/cgroup/memory/cantiand
    fi
    mkdir -p /sys/fs/cgroup/memory/cantiand
    echo "cantiand cgroup path created successfully."
}

function cgroup_config()
{
    cantiand_cgroup_config

    local cantiand_pid=$(pidof cantiand)
    sh -c "echo ${cantiand_pid} > /sys/fs/cgroup/memory/cantiand/tasks"
    if [ $? -eq 0 ]; then
        echo "cantiand pid : ${cantiand_pid} success"
    else
        echo "cantiand pid : ${cantiand_pid} failed"
    fi
}

function cgroup_clean()
{
    if [[ -d /sys/fs/cgroup/memory/cantiand ]]; then
        rmdir /sys/fs/cgroup/memory/cantiand
    fi
    echo "cantiand cgroup config is removed."
}

function check_backup_files()
{
    backup_list=$1
    dest_dir=$2
    orig_dir=$3
    echo "check backup files in ${dest_dir} from ${orig_dir}"
    while read orig_path_line
    do
        record_orig_size=$(echo ${orig_path_line} | sed 's/ //g' | sed 's/\[//g' | awk -F ']' '{print $1}')
        orig_path=$(echo "${orig_path_line}" | sed 's/ //g' | awk -F ']' '{print $2}')
        if [ -z ${orig_path} ];then
            continue
        fi
        if [[ ${orig_path} == *-\>* ]];then
            orig_path=$(echo ${orig_path} | awk -F '->' '{print $1}')
        fi

        if [[ ${orig_path} == ${orig_dir}* ]];then
            if [[ ${orig_path} == ${orig_dir}/log* ]];then
                continue
            fi
            orig_dir_reg=$(echo ${orig_dir} | sed 's/\//\\\//g')
            dest_dir_reg=$(echo ${dest_dir} | sed 's/\//\\\//g')
            dest_path=$(echo ${orig_path} | sed "s/^${orig_dir_reg}/${dest_dir_reg}/")
            if [ ! -e ${dest_path} ];then
                echo "Error: the corresponding file is not found : ${orig_path} -> ${dest_path}"
                return 1
            fi
            if [ -f ${dest_path} ];then
                orig_size=`ls -l ${orig_path} | awk '{print $5}'`
                dest_size=`ls -l ${dest_path} | awk '{print $5}'`
                if [ ${orig_size} != ${dest_size} ];then
                    echo "file: ${orig_path} ---> ${dest_path}"
                    echo "size: ${orig_size} ---> ${dest_size}"
                    echo "Error: the corresponding file size is different : ${orig_size} -> ${dest_size}"
                    return 1
                fi
                if [ ${record_orig_size} != ${dest_size} ];then
                    echo "file: ${orig_path} ---> ${dest_path}"
                    echo "size: ${record_orig_size} ---> ${dest_size}"
                    echo "Error: the corresponding file size is different from record orig size : ${record_orig_size} -> ${dest_size}"
                    return 1
                fi
            fi
        fi
    done < ${backup_list}
}

function check_rollback_files()
{
    backup_list=$1
    dest_dir=$2
    orig_dir=$3
    echo "check backup files in ${dest_dir} from ${orig_dir}"
    while read orig_path_line
    do
        record_orig_size=$(echo ${orig_path_line} | sed 's/ //g' | sed 's/\[//g' | awk -F ']' '{print $1}')
        orig_path=$(echo ${orig_path_line} | sed 's/ //g' | awk -F ']' '{print $2}')
        if [ -z ${orig_path} ];then
            continue
        fi
        if [[ ${orig_path} == *-\>* ]];then
            orig_path=$(echo ${orig_path} | awk -F '->' '{print $1}')
        fi

        if [[ ${orig_path} == ${orig_dir}* ]];then
            if [[ ${orig_path} == ${orig_dir}/log* ]];then
                continue
            fi
            orig_dir_reg=$(echo ${orig_dir} | sed 's/\//\\\//g')
            dest_dir_reg=$(echo ${dest_dir} | sed 's/\//\\\//g')
            dest_path=$(echo ${orig_path} | sed "s/^${orig_dir_reg}/${dest_dir_reg}/")
            if [ ! -e ${orig_path} ];then
                echo "Error: the corresponding file is not found : ${orig_path} -> ${dest_path}"
                return 1
            fi
            if [ -f ${orig_path} ];then
                orig_size=`ls -l ${orig_path} | awk '{print $5}'`
                dest_size=`ls -l ${dest_path} | awk '{print $5}'`
                if [ ${orig_size} != ${dest_size} ];then
                    echo "file: ${dest_path} ---> ${orig_path}"
                    echo "size: ${dest_size} ---> ${orig_size}"
                    echo "Error: the corresponding file size is different : ${orig_size} -> ${dest_size}"
                    return 1
                fi
                if [ ${orig_size} != ${record_orig_size} ];then
                    echo "file: ${dest_path} ---> ${orig_path}"
                    echo "size: ${dest_size} ---> ${record_orig_size}"
                    echo "Error: the corresponding file size is different from record orig size : ${record_orig_size} -> ${dest_size}"
                    return 1
                fi
            fi
        fi
    done < ${backup_list}
}

function check_cantian_status() {
    if [[ ${version_first_number} -eq 2 ]];then
        user=${d_user}
    fi
    echo "check cantian cluster status processes: cms stat"
    su -s /bin/bash - ${user} -c "source ~/.bashrc && cms stat"

    if [ X$node_id == X0 ];then
        online_stat_count=$(su -s /bin/bash - ${user} -c "source ~/.bashrc && cms stat" | grep 'db' | awk '{if($1==0){print $3}}' | grep 'ONLINE' | wc -l)
        work_stat_count=$(su -s /bin/bash - ${user} -c "source ~/.bashrc && cms stat" | grep 'db' | awk '{if($1==0){print $6}}' | grep '1' | wc -l)
    else
        online_stat_count=$(su -s /bin/bash - ${user} -c "source ~/.bashrc && cms stat" | grep 'db' | awk '{if($1==1){print $3}}' | grep 'ONLINE' | wc -l)
        work_stat_count=$(su -s /bin/bash - ${user} -c "source ~/.bashrc && cms stat" | grep 'db' | awk '{if($1==1){print $6}}' | grep '1' | wc -l)
    fi
    if [ ${online_stat_count} -ne 1 ];then
        echo "Error: the online status of the database is abnormal"
        return 1
    fi
    if [ ${work_stat_count} -ne 1 ];then
        echo "Error: the work status of the database is abnormal"
        return 1
    fi

    cantian_count=`ps -fu ${user} | grep "\-D ${cantian_local}/tmp/data" | grep -vE '(grep|defunct)' | wc -l`
    if [ ${cantian_count} -eq 1 ];then
        echo "cantian process is running, upgrade is normal at the moment"
    else
        echo "Error: the cantiand process is abnormal"
        return 1
    fi
    if [[ ${version_first_number} -eq 2 ]];then
        return 0
    fi
    su -s /bin/bash - "${user}" -c "source ~/.bashrc && export LD_LIBRARY_PATH=/opt/cantian/dbstor/lib:${LD_LIBRARY_PATH} && python3 -B ${CURRENT_PATH}/cantian_post_upgrade.py"
    if [ $? -ne 0 ]; then
        echo "Error: db status check failed."
        return 1
    fi
}

function pre_upgrade()
{
    set -e
    echo -e "\n======================== check cantian module status before upgrade ========================"
    echo "check cantian home: ${cantian_home}"
    if [ ! -d ${cantian_home}/server ];then
        echo "Error: cantian home server does not exist, cantian module may be not installed!"
        return 1
    fi

    echo "check cantian local data: ${cantian_local}/tmp/data"
    if [ ! -d ${cantian_local}/tmp/data ];then
        echo "Error: cantian local data dir does not exist, cantian module may be not installed!"
        return 1
    fi

    start_status=$(cat ${cantian_home}/cfg/start_status.json |
              awk -F ',' '{for(i=1;i<=NF;i++){if($i~"start_status"){print $i}}}' |
              sed 's/ //g' | sed 's/:/=/1' | sed 's/"//g' | sed 's/}//g' | sed 's/{//g' |
              awk -F '=' '{print $2}')
    db_create_status=$(cat ${cantian_home}/cfg/start_status.json |
          awk -F ',' '{for(i=1;i<=NF;i++){if($i~"db_create_status"){print $i}}}' |
          sed 's/ //g' | sed 's/:/=/1' | sed 's/"//g' | sed 's/}//g' | sed 's/{//g' |
          awk -F '=' '{print $2}')
    if [[ ${start_status} != "started" ]];then
        echo "Error: start cantian process before pre_upgrade!"
        return 1
    fi
    if [[ ${db_create_status} != "done" ]] && [[ ${node_id} == "0" ]];then
        echo "Error: the cantian database is not running and no database is created in node 0,
        you can directly install the cantian database instead of upgrading it！"
        return 1
    fi

    check_cantian_status
    echo "======================== check cantian module status before upgrade successfully ========================"
    set +e
    return 0
}

function post_upgrade()
{
    set -e
    echo -e "\n======================== begin to check cantian module status after upgrade ========================"
    echo "check cantian home: ${cantian_home}"
    cantian_home_files=`ls -l ${cantian_home}/server | wc -l`
    if [ ${cantian_home_files} == 0 ];then
        echo "Error: cantian home server files do not exist, cantian module may be not upgraded successfully!"
        return 1
    fi
    ls -l ${cantian_home}/server

    echo "check cantian scripts: ${cantian_scripts}"
    cantian_scripts_files=`ls -l ${cantian_scripts} | wc -l`
    if [ ${cantian_scripts_files} == 0 ];then
        echo "Error: cantian scripts do not exist, cantian module may be not upgraded successfully!"
        return 1
    fi
    ls -l ${cantian_scripts}

    echo "check cantian local data: ${cantian_local}/tmp/data"
    if [ ! -d ${cantian_local}/tmp/data ];then
        echo "Error: cantian local data dir does not exist, cantian module may be not upgraded successfully!"
        return 1
    fi

    check_cantian_status
    echo "======================== check cantian module status after upgrade successfully ========================"
    set +e
    return 0
}

function record_cantian_info() {
    backup_dir=$1
    echo "record the list of all cantian module files before the upgrade."
    tree -afis ${cantian_home} >> ${backup_dir}/cantian/cantian_home_files_list.txt
    tree -afis ${cantian_scripts} >> ${backup_dir}/cantian/cantian_scripts_files_list.txt
    tree -afis ${cantian_local} >> ${backup_dir}/cantian/cantian_local_files_list.txt

    echo "record the backup statistics information to file: backup.bak"
    echo "cantian backup information for upgrade" >> ${backup_dir}/cantian/backup.bak
    echo "time:
          $(date)" >> ${backup_dir}/cantian/backup.bak
    echo "deploy_user:
              ${cantian_user}" >> ${backup_dir}/cantian/backup.bak
    echo "cantian_home:
              total_size=$(du -sh ${cantian_home})
              total_files=$(tail ${backup_dir}/cantian/cantian_home_files_list.txt -n 1)" >> ${backup_dir}/cantian/backup.bak
    echo "cantian_scripts:
              total_size=$(du -sh ${cantian_scripts})
              total_files=$(tail ${backup_dir}/cantian/cantian_scripts_files_list.txt -n 1)" >> ${backup_dir}/cantian/backup.bak
    echo "cantian_local:
              total_size=$(du -sh ${cantian_local})
              total_files=$(tail ${backup_dir}/cantian/cantian_local_files_list.txt -n 1)" >> ${backup_dir}/cantian/backup.bak

    return 0
}

function safety_upgrade_backup()
{
    set -e
    echo -e "\n======================== begin to backup cantian module for upgrade ========================"

    old_cantian_owner=$(stat -c %U ${cantian_home})
    if [[ ${version_first_number} -eq 2 ]];then
        user=${d_user}
    fi
    if [ ${old_cantian_owner} != ${user} ]; then
        echo "Error: the upgrade user is different from the installed user"
        return 1
    fi

    backup_dir=$1

    if [ -d ${backup_dir}/cantian ];then
        echo "Error: ${backup_dir} alreadly exists, check whether data has been backed up"
        return 1
    fi

    echo "create bak dir for cantian : ${backup_dir}/cantian"
    mkdir -m 755 ${backup_dir}/cantian

    echo "backup cantian home, from ${cantian_home} to ${backup_dir}/cantian/cantian_home"
    mkdir -m 755 ${backup_dir}/cantian/cantian_home
    path_reg=$(echo ${cantian_home} | sed 's/\//\\\//g')
    cantian_home_backup=$(ls ${cantian_home} | awk '{if($1!="log"){print $1}}' | sed "s/^/${path_reg}\//g")
    cp -arf ${cantian_home_backup} ${backup_dir}/cantian/cantian_home

    echo "backup cantian scripts, from ${cantian_scripts} to ${backup_dir}/cantian/cantian_scripts"
    mkdir -m 755 ${backup_dir}/cantian/cantian_scripts
    cp -arf ${cantian_scripts}/* ${backup_dir}/cantian/cantian_scripts

    echo "backup cantian local, from ${cantian_local} to ${backup_dir}/cantian/cantian_local"
    mkdir -m 755 ${backup_dir}/cantian/cantian_local
    cp -arf ${cantian_local}/* ${backup_dir}/cantian/cantian_local

    record_cantian_info ${backup_dir}

    echo "check that all files are backed up to ensure that no data is lost for safety upgrade and rollback"
    check_backup_files ${backup_dir}/cantian/cantian_home_files_list.txt ${backup_dir}/cantian/cantian_home ${cantian_home}
    check_backup_files ${backup_dir}/cantian/cantian_scripts_files_list.txt ${backup_dir}/cantian/cantian_scripts ${cantian_scripts}
    check_backup_files ${backup_dir}/cantian/cantian_local_files_list.txt ${backup_dir}/cantian/cantian_local ${cantian_local}

    echo "======================== backup cantian module for upgrade successfully ========================"
    set +e
    return 0
}

function copy_cantian_dbstor_cfg()
{
    if [[ x"${deploy_mode}" == x"nas" ]]; then
        return 0
    fi
    echo "update the cantian local config files for dbstor in ${cantian_local}"
    link_type=$1
    cantian_local_data_dir=${cantian_local}/tmp/data
    rm -rf ${cantian_local_data_dir}/dbstor/conf/infra/config/node_config.xml
    if [ ${link_type} == 1 ] || [ ${link_type} == 2 ];then
        echo "link_type is rdma, copy node_config_rdma.xml"
        cp -arf ${cantian_home}/server/cfg/node_config_rdma.xml \
        ${cantian_local_data_dir}/dbstor/conf/infra/config/node_config.xml
    else
        echo "link_type is tcp, copy node_config_tcp.xml"
        cp -arf ${cantian_home}/server/cfg/node_config_tcp.xml \
        ${cantian_local_data_dir}/dbstor/conf/infra/config/node_config.xml
    fi
    rm -rf ${cantian_local_data_dir}/dbstor/conf/infra/config/osd.cfg
    cp -arf ${cantian_home}/server/cfg/osd.cfg \
        ${cantian_local_data_dir}/dbstor/conf/infra/config/osd.cfg
}

function chown_mod_cantian_server()
{
    echo "chown and chmod the files in ${cantian_home}/server"
    chmod -R 700 ${cantian_home}/server
    find ${cantian_home}/server/add-ons -type f | xargs chmod 500
    find ${cantian_home}/server/admin -type f | xargs chmod 400
    find ${cantian_home}/server/bin -type f | xargs chmod 500
    find ${cantian_home}/server/lib -type f | xargs chmod 500
    find ${cantian_home}/server/cfg -type f | xargs chmod 600
    chmod 750 ${cantian_home}/server
    chmod 750 ${cantian_home}/server/admin
    chmod 750 ${cantian_home}/server/admin/scripts
    chmod 400 ${cantian_home}/server/package.xml
    chown -hR ${cantian_user} ${cantian_home}
    return 0
}

function update_cantian_server()
{
    echo "update the server files in ${cantian_home}/server"
    RPM_PACK_ORG_PATH=/opt/cantian/image
    cantian_pkg_file=${RPM_PACK_ORG_PATH}/Cantian-RUN-CENTOS-64bit
    rm -rf ${cantian_home}/server/*
    cp -arf ${cantian_pkg_file}/add-ons ${cantian_pkg_file}/admin ${cantian_pkg_file}/bin \
       ${cantian_pkg_file}/cfg ${cantian_pkg_file}/lib ${cantian_pkg_file}/package.xml ${cantian_home}/server

    if [[ x"${deploy_mode}" == x"nas" ]]; then
        return 0
    fi

    link_type=$1
    if [ ${link_type} == 1 ];then
        echo "link_type is rdma"
        cp -arf ${cantian_home}/server/add-ons/mlnx/lib* ${cantian_home}/server/add-ons/
    elif [ ${link_type} == 0 ];then
        cp -arf ${cantian_home}/server/add-ons/nomlnx/lib* ${cantian_home}/server/add-ons/
        echo "link_type is tcp"
    else
        cp -arf ${cantian_home}/server/add-ons/1823/lib* ${cantian_home}/server/add-ons/
        echo "link_type is rdma_1823"
    fi
    return 0
}

function update_cantian_scripts() {
    echo "update the cantian scripts in ${cantian_scripts}, except start_status.json"
    path_reg=$(echo ${cantian_scripts} | sed 's/\//\\\//g')
    cantian_scripts_upgrade=$(ls ${cantian_scripts} | awk '{if($1!="start_status.json"){print $1}}' | sed "s/^/${path_reg}\/&/g")
    path_reg=$(echo ${CURRENT_PATH} | sed 's/\//\\\//g')
    cantian_scripts_upgrade=$(ls ${CURRENT_PATH} | awk '{if($1!="start_status.json"){print $1}}' | sed "s/^/${path_reg}\//g")
    cp -arf ${cantian_scripts_upgrade} ${cantian_scripts}
    return 0
}

function safety_upgrade()
{
    set -e
    echo -e "\n======================== begin to upgrade cantian module ========================"

    link_type=$(cat ${CURRENT_PATH}/../../config/deploy_param.json  |
          awk -F ',' '{for(i=1;i<=NF;i++){if($i~"link_type"){print $i}}}' |
          sed 's/ //g' | sed 's/:/=/1' | sed 's/"//g' |
          awk -F '=' '{print $2}')
    deploy_mode=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_mode")

    update_cantian_server ${link_type}

    chown_mod_cantian_server

    copy_cantian_dbstor_cfg ${link_type}

    update_cantian_scripts

    echo "======================== upgrade cantian module successfully ========================"
    set +e
    return 0
}

function safety_rollback()
{
    set -e
    echo -e "\n======================== begin to rollback cantian module ========================"

    version=$(cat ${CURRENT_PATH}/../../versions.yml |
              sed 's/ //g' | grep 'Version:' | awk -F ':' '{print $2}')
    backup_dir=$2
    if [ ! -d ${backup_dir}/cantian ];then
        echo "Error: backup_dir ${backup_dir}/cantian does not exist"
        return 1
    fi
    echo "rollback from backup dir ${backup_dir}, cantian version is ${version}"

    echo "rollback cantian home ${cantian_home}"
    if [ ! -d ${backup_dir}/cantian/cantian_home ];then
        echo "Error: dir ${backup_dir}/cantian/cantian_home does not exist"
        return 1
    fi
    path_reg=$(echo ${cantian_home} | sed 's/\//\\\//g')
    cantian_home_backup=$(ls ${cantian_home} | awk '{if($1!="log"){print $1}}' | sed "s/^/${path_reg}\//g")
    rm -rf ${cantian_home_backup}
    cp -arf ${backup_dir}/cantian/cantian_home/* ${cantian_home}

    echo "rollback cantian scripts ${cantian_scripts}"
    if [ ! -d ${backup_dir}/cantian/cantian_scripts ];then
        echo "Error: dir ${backup_dir}/cantian/cantian_scripts does not exist"
        return 1
    fi
    rm -rf ${cantian_scripts}/*
    cp -arf ${backup_dir}/cantian/cantian_scripts/* ${cantian_scripts}

    echo "rollback cantian local ${cantian_local}"
    if [ ! -d ${backup_dir}/cantian/cantian_local ];then
        echo "Error: dir ${backup_dir}/cantian/cantian_local does not exist"
        return 1
    fi
    rm -rf ${cantian_local}/*
    cp -arf ${backup_dir}/cantian/cantian_local/* ${cantian_local}

    echo "check that all files are rolled back to ensure that no data is lost for safety rollback"
    check_rollback_files ${backup_dir}/cantian/cantian_home_files_list.txt ${backup_dir}/cantian/cantian_home ${cantian_home}
    check_rollback_files ${backup_dir}/cantian/cantian_scripts_files_list.txt ${backup_dir}/cantian/cantian_scripts ${cantian_scripts}
    check_rollback_files ${backup_dir}/cantian/cantian_local_files_list.txt ${backup_dir}/cantian/cantian_local ${cantian_local}

    echo "======================== rollback cantian module successfully ========================"
    set +e
    return 0
}

deploy_user=$(cat ${CURRENT_PATH}/../../config/deploy_param.json |
              awk -F ',' '{for(i=1;i<=NF;i++){if($i~"deploy_user"){print $i}}}' |
              sed 's/ //g' | sed 's/:/=/1' | sed 's/"//g' |
              awk -F '=' '{print $2}')
d_user=$(echo ${deploy_user} | awk -F ':' '{print $2}')
node_id=$(cat ${CURRENT_PATH}/../../config/deploy_param.json |
              awk -F ',' '{for(i=1;i<=NF;i++){if($i~"node_id"){print $i}}}' |
              sed 's/ //g' | sed 's/:/=/1' | sed 's/"//g' |
              awk -F '=' '{print $2}')

user=$(echo ${cantian_user} | awk -F ':' '{print $2}')
owner=$(stat -c %U ${CURRENT_PATH})

function chown_mod_scripts() {
    set -e
    current_path_reg=$(echo $CURRENT_PATH | sed 's/\//\\\//g')
    scripts=$(ls ${CURRENT_PATH} | awk '{if($1!="appctl.sh"){print $1}}' | awk '{if($1!="cantiand_cgroup_calculate.sh"){print $1}}' |
            sed "s/^/${current_path_reg}\//")
    chown ${cantian_user} -h ${scripts}
    chmod 400 ${CURRENT_PATH}/*.sh ${CURRENT_PATH}/*.py
    chmod 600 ${CURRENT_PATH}/*.json
    set +e
}

function copy_cantian_scripts()
{
    if [ -d ${cantian_scripts} ]; then
        rm -rf ${cantian_scripts}
    fi
    mkdir -m 700 -p ${cantian_scripts}
    chown -h ${cantian_user} ${cantian_scripts}
    cp -arf ${CURRENT_PATH}/* ${cantian_scripts}/
}

function create_mysql_dir()
{
    if [ ! -d /opt/cantian/mysql/install/mysql ];then
        mkdir -m 750 -p /opt/cantian/mysql/install/mysql
    fi
    chown ${deploy_user} -hR /opt/cantian/mysql/install
}

function clean_mysql_dir()
{
    if [ -d /opt/cantian/mysql/install/mysql ];then
        rm -rf /opt/cantian/mysql/install/mysql/*
    fi

    if [[ -d /mnt/dbdata/remote/metadata_${storage_metadata_fs}/node${node_id} && x"${UNINSTALL_TYPE}" == x"override" ]];then
        rm -rf /mnt/dbdata/remote/metadata_${storage_metadata_fs}/node${node_id}/*
    fi
}

function clean_cantian_scripts()
{
    if [ -d ${cantian_scripts} ]; then
        rm -rf ${cantian_scripts}
    fi
}

function check_old_install()
{
    if [ -d ${cantian_home}/server ]; then
        echo "Error: cantian has been installed in ${cantian_home}"
        exit 1
    fi

    #解决root包卸载残留问题
    chown ${cantian_user} -hR ${cantian_home}
    chmod 750 -R ${cantian_home}
    find ${cantian_home}/log -type f | xargs chmod 640

    #解决root包卸载残留问题
    cantian_local_owner=$(stat -c %U ${cantian_local})
    if [ ${cantian_local_owner} != ${user} ];then
        chown ${cantian_user} -hR ${cantian_local}
        chmod 750 -R ${cantian_local}/..
    fi
}

function check_and_create_cantian_home()
{
    if [ ! -d ${cantian_home} ]; then
        mkdir -m 750 -p ${cantian_home}
        chown ${cantian_user} -hR ${cantian_home}
    fi

    if [ ! -d ${cantian_home}/log ]; then
        mkdir -m 750 -p ${cantian_home}/log
        chown ${cantian_user} -hR ${cantian_home}/log
    fi

    if [ ! -d ${cantian_home}/cfg ]; then
        mkdir -m 700 -p ${cantian_home}/cfg
        chown ${cantian_user} -hR ${cantian_home}/cfg
    fi

    if [ ! -f ${LOG_FILE} ]; then
        touch ${LOG_FILE}
        chmod 640 ${LOG_FILE}
        chown ${cantian_user} -hR /opt/cantian/cantian > /dev/null 2>&1
    fi

    if [ ! -d ${cantian_local} ]; then
        mkdir -m 750 -p ${cantian_local}
        chown ${cantian_user} -hR ${cantian_local}
    fi

}

check_and_create_cantian_home

##################################### main #####################################
ACTION=$1
if [ $# -gt 1 ]; then
    INSTALL_TYPE=$2
    UNINSTALL_TYPE=$2
    BACKUP_UPGRADE_PATH=$2
    UPGRADE_TYPE=$2
    ROLLBACK_TYPE=$2
fi
if [ $# -gt 2 ]; then
    FORCE_UNINSTALL=$3
    BACKUP_UPGRADE_PATH=$3
fi

function main_deploy() {
    case "$ACTION" in
        start)
            create_cgroup_path
            do_deploy ${START_NAME} ${INSTALL_TYPE}
            if [[ $? -ne 0 ]]; then
                exit 1
            fi
            exit $?
            ;;
        stop)
            do_deploy ${STOP_NAME}
            exit $?
            ;;
        pre_install)
            check_old_install
            chown_mod_scripts
            do_deploy ${PRE_INSTALL_NAME} ${INSTALL_TYPE}
            exit $?
            ;;
        install)
            copy_cantian_scripts
            create_mysql_dir
            do_deploy ${INSTALL_NAME} ${INSTALL_TYPE}
            exit $?
            ;;
        uninstall)
            do_deploy ${UNINSTALL_NAME} ${UNINSTALL_TYPE} ${FORCE_UNINSTALL}
            if [[ $? -ne 0 ]]; then
                exit 1
            fi
            clean_mysql_dir
            cgroup_clean
            exit $?
            ;;
        check_status)
            do_deploy ${STATUS_NAME}
            exit $?
            ;;
        backup)
            do_deploy ${BACKUP_NAME}
            exit $?
            ;;
        restore)
            do_deploy ${RESTORE_NAME}
            exit $?
            ;;
        pre_upgrade)
            version_first_number=$(cat /opt/cantian/versions.yml |sed 's/ //g' | grep 'Version:' | awk -F ':' '{print $2}' | awk -F '.' '{print $1}')
            chown_mod_scripts
            pre_upgrade
            exit $?
            ;;
        upgrade_backup)
            version_first_number=$(cat /opt/cantian/versions.yml |sed 's/ //g' | grep 'Version:' | awk -F ':' '{print $2}' | awk -F '.' '{print $1}')
            safety_upgrade_backup ${BACKUP_UPGRADE_PATH}
            exit $?
            ;;
        upgrade)
            safety_upgrade ${UPGRADE_TYPE} ${BACKUP_UPGRADE_PATH}
            exit $?
            ;;
        rollback)
            safety_rollback ${ROLLBACK_TYPE} ${BACKUP_UPGRADE_PATH}
            exit $?
            ;;
        post_upgrade)
            post_upgrade
            exit $?
            ;;
        *)
            usage
            ;;
    esac
}

main_deploy &>> ${LOG_FILE}