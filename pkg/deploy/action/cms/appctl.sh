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
set -e -u
#当前路径
CURRENT_PATH=$(dirname $(readlink -f $0))
source "${CURRENT_PATH}"/../env.sh

#脚本名称
PARENT_DIR_NAME=$(pwd | awk -F "/" '{print $NF}')
SCRIPT_NAME=${PARENT_DIR_NAME}/$(basename $0)

#组件名称
COMPONENTNAME=cms

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

#cgroup预留cms内存隔离值，单位G
DEFAULT_MEM_SIZE=10
cms_home=/opt/cantian/cms
cantian_home=/opt/cantian/cantian
cms_scripts=/opt/cantian/action/cms
cms_tmp_file="${cms_home}/cms_server.lck ${cms_home}/local ${cms_home}/gcc_backup ${cms_home}/cantian.ctd.cms*"
shm_home=/dev/shm
cantian_in_container=`python3 ${CURRENT_PATH}/get_config_info.py "cantian_in_container"`

LOG_FILE="${cms_home}/log/cms_deploy.log"

cantian_user_and_group=${cantian_user}:${cantian_group}

function usage()
{
    echo "Usage: ${0##*/} {start|stop|install|uninstall|pre_install|
                          pre_upgrade|check_status|upgrade|post_upgrade|rollback|upgrade_backup}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
    exit 1
}

function do_deploy()
{
    local script_name_param=$1
    local uninstall_type=""
    local force_uninstall=""
    if [ $# -gt 1 ]; then
        uninstall_type=$2
    fi
    if [ $# -gt 2 ]; then
        force_uninstall=$3
    fi

    if [ ! -f  ${CURRENT_PATH}/${script_name_param} ]; then
        echo "${COMPONENTNAME} ${script_name_param} is not exist. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi

    set +e
    su -s /bin/bash - ${cantian_user} -c "cd ${CURRENT_PATH} && sh ${CURRENT_PATH}/${script_name_param} ${uninstall_type} ${force_uninstall} >> ${LOG_FILE}"
    ret=$?
    set -e
    if [ $ret -ne 0 ]; then
        echo "Execute ${COMPONENTNAME} ${script_name_param} return ${ret}. [Line:${LINENO}, File:${SCRIPT_NAME}]"
        return 1
    fi
    return 0
}

function create_cgroup_path()
{
    mkdir -p /sys/fs/cgroup/memory/cms
    echo "cms cgroup path created successfully."
}

function cgroup_config()
{
    sh -c "echo \"${DEFAULT_MEM_SIZE}G\" > /sys/fs/cgroup/memory/cms/memory.limit_in_bytes"
    echo "cms cgroup memory size: ${DEFAULT_MEM_SIZE}G"

    local cms_pid=$(ps -ef | grep cms | grep server | grep start | grep -v grep | awk 'NR==1 {print $2}')
    sh -c "echo ${cms_pid} > /sys/fs/cgroup/memory/cms/tasks"
    echo "cms pid : ${cms_pid}"
}

function cgroup_clean()
{
    if [[ -d /sys/fs/cgroup/memory/cms ]]; then
        rmdir /sys/fs/cgroup/memory/cms
    fi
    echo "cms cgroup config is removed."
}

function clear_shm()
{
    local proc_name=cantiand
    local cantiand_pid=`pidof $proc_name`
    if [ -n "$cantiand_pid" ];then
        echo "no need clean shm"
        return
    fi
    rm -rf ${shm_home}/cantian.[0-9]* > /dev/null 2>&1
}

function iptables_accept() {
    echo "start accept iptables"
    ret=`iptables -L INPUT -w 60 | grep ACCEPT | grep 14587 | grep udp | wc -l`
    if [ ${ret} != 0 ];then
        iptables -I INPUT -p udp --sport 14587 -j ACCEPT -w 60
    fi
    ret=`iptables -L FORWARD -w 60 | grep ACCEPT | grep 14587 | grep udp | wc -l`
    if [ ${ret} != 0 ];then
        iptables -I FORWARD -p udp --sport 14587 -j ACCEPT -w 60
    fi
    ret=`iptables -L OUTPUT -w 60 | grep ACCEPT | grep 14587 | grep udp | wc -l`
    if [ ${ret} != 0 ];then
        iptables -I OUTPUT -p udp --sport 14587 -j ACCEPT -w 60
    fi
}

function iptables_delete() {
    echo "start delete iptables"
    ret=`iptables -L INPUT -w 60 | grep ACCEPT | grep 14587 | grep udp | wc -l`
    if [ ${ret} != 0 ];then
        iptables -D INPUT -p udp --sport 14587 -j ACCEPT -w 60
    fi
    ret=`iptables -L FORWARD -w 60 | grep ACCEPT | grep 14587 | grep udp | wc -l`
    if [ ${ret} != 0 ];then
        iptables -D FORWARD -p udp --sport 14587 -j ACCEPT -w 60
    fi
    ret=`iptables -L OUTPUT -w 60 | grep ACCEPT | grep 14587 | grep udp | wc -l`
    if [ ${ret} != 0 ];then
        iptables -D OUTPUT -p udp --sport 14587 -j ACCEPT -w 60
    fi
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

function check_cms_node_and_res_list()
{
    echo "check cms node status: cms node -list"
    su -s /bin/bash - ${cantian_user} -c "source ~/.bashrc && cms node -list"
    node0=$(su -s /bin/bash - ${cantian_user} -c "source ~/.bashrc && cms node -list" | grep 'node0' | wc -l)
    node1=$(su -s /bin/bash - ${cantian_user} -c "source ~/.bashrc && cms node -list" | grep 'node1' | wc -l)
    if [ ${node0} != 1 ];then
        echo "Error: the node 0 information cannot be found"
        return 1
    fi
    if [ ${node1} != 1 ];then
        echo "Error: the node 1 information cannot be found"
        return 1
    fi

    echo "check cms res status: cms res -list"
    su -s /bin/bash - ${cantian_user} -c "source ~/.bashrc && cms res -list"
    res=$(su -s /bin/bash - ${cantian_user} -c "source ~/.bashrc && cms res -list" | grep 'db' | wc -l)
    if [ ${res} == 0 ];then
        echo "Error: the resource information cannot be found"
        return 1
    fi
    return 0
}

function pre_upgrade()
{
    echo -e "\n======================== check cms module status before upgrade ========================"
    echo "check cms home: ${cms_home}"
    if [ ! -d ${cms_home}/service ];then
        echo "Error: cms home service does not exist, cms module may be not installed!"
        return 1
    fi

    if [[ x"${deploy_mode}" != x"dbstore_unify" ]]; then
        echo "check gcc home: /mnt/dbdata/remote/share_${storage_share_fs}"
        if [ ! -d /mnt/dbdata/remote/share_${storage_share_fs}/gcc_home ];then
            echo "Error: gcc home does not exist!"
            return 1
        fi
    fi

    if [[ ${version_first_number} -eq 2 ]];then
        cantian_user=${d_user}
    fi

    echo "check cms server processes: cms stat -server"
    su -s /bin/bash - ${cantian_user} -c "source ~/.bashrc && cms stat -server"
    cms_count=`ps -fu ${cantian_user} | grep 'cms server -start' | grep -vE '(grep|defunct)' | wc -l`
    if [ ${cms_count} -ne 1 ];then
        echo "Error: start cms process before pre_upgrade!"
        return 1
    fi

    check_cms_node_and_res_list

    echo "======================== check cms module status before upgrade successfully ========================"
    return 0
}

function post_upgrade()
{
    echo -e "\n======================== begin to check cms module status after upgrade ========================"
    echo "check cms home: ${cms_home}"
    cms_home_files=`ls -l ${cms_home}/service | wc -l`
    if [ ${cms_home_files} == 0 ];then
        echo "Error: cms home service files do not exist, cms module may be not upgraded successfully!"
        return 1
    fi
    ls -l ${cms_home}/service

    echo "check cms scripts: ${cms_scripts}"
    cms_scripts_files=`ls -l ${cms_scripts} | wc -l`
    if [ ${cms_scripts_files} == 0 ];then
        echo "Error: cms scripts do not exist, cms module may be not upgraded successfully!"
        return 1
    fi
    ls -l ${cms_scripts}

    if [[ x"${deploy_mode}" != x"dbstore_unify" ]]; then
        echo "check gcc home: /mnt/dbdata/remote/share_${storage_share_fs}"
        if [ ! -d /mnt/dbdata/remote/share_${storage_share_fs}/gcc_home ];then
            echo "Error: gcc home does not exist!"
            return 1
        fi
        ls -l /mnt/dbdata/remote/share_${storage_share_fs}/gcc_home
    fi

    echo "check cms server processes: cms stat -server"
    su -s /bin/bash - ${cantian_user} -c "source ~/.bashrc && cms stat -server"
    cms_count=`ps -fu ${cantian_user} | grep "cms server -start" | grep -vE '(grep|defunct)' | wc -l`
    if [ ${cms_count} -ne 1 ];then
        echo "cms process is not running, upgrade is abnormal"
        return 1
    fi

    check_cms_node_and_res_list

    echo "======================== check cms module status after upgrade successfully ========================"
    return 0
}

function record_cms_info() {
    backup_dir=$1
    echo "record the list of all cms module files before the upgrade."
    tree -afis ${cms_home} >> ${backup_dir}/cms/cms_home_files_list.txt
    tree -afis ${cms_scripts} >> ${backup_dir}/cms/cms_scripts_files_list.txt

    echo "record the backup statistics information to file: backup.bak"
    echo "cms backup information for upgrade" >> ${backup_dir}/cms/backup.bak
    echo "time:
              $(date)" >> ${backup_dir}/cms/backup.bak
    echo "deploy_user:
              ${cantian_user_and_group}" >> ${backup_dir}/cms/backup.bak
    echo "cms_home:
              total_size=$(du -sh ${cms_home})
              total_files=$(tail ${backup_dir}/cms/cms_home_files_list.txt -n 1)" >> ${backup_dir}/cms/backup.bak
    echo "cms_scripts:
              total_size=$(du -sh ${cms_scripts})
              total_files=$(tail ${backup_dir}/cms/cms_scripts_files_list.txt -n 1)" >> ${backup_dir}/cms/backup.bak
    return 0
}

function safety_upgrade_backup()
{
    echo -e "\n======================== begin to backup cms module for upgrade ========================"

    old_cms_owner=$(stat -c %U ${cms_home})
    if [[ ${version_first_number} -eq 2 ]];then
        cantian_user=${d_user}
    fi
    if [ ${old_cms_owner} != ${cantian_user} ]; then
        echo "Error: the upgrade user is different from the installed user"
        return 1
    fi

    backup_dir=$1

    if [ -d ${backup_dir}/cms ];then
        echo "Error: ${backup_dir} alreadly exists, check whether data has been backed up"
        return 1
    fi

    echo "create bak dir for cms : ${backup_dir}/cms"
    mkdir -m 750 ${backup_dir}/cms

    echo "backup cms home, from ${cms_home} to ${backup_dir}/cms/cms_home"
    mkdir -m 750 ${backup_dir}/cms/cms_home
    path_reg=$(echo ${cms_home} | sed 's/\//\\\//g')
    cms_home_backup=$(ls ${cms_home} | awk '{if($1!="log"){print $1}}' | sed "s/^/${path_reg}\//g")
    cp -arf ${cms_home_backup} ${backup_dir}/cms/cms_home

    echo "backup cms scripts, from ${cms_scripts} to ${backup_dir}/cms/cms_scripts"
    mkdir -m 750 ${backup_dir}/cms/cms_scripts
    cp -arf ${cms_scripts}/* ${backup_dir}/cms/cms_scripts

    record_cms_info ${backup_dir}

    echo "check that all files are backed up to ensure that no data is lost for safety upgrade and rollback"
    check_backup_files ${backup_dir}/cms/cms_home_files_list.txt ${backup_dir}/cms/cms_home ${cms_home}
    check_backup_files ${backup_dir}/cms/cms_scripts_files_list.txt ${backup_dir}/cms/cms_scripts ${cms_scripts}

    echo "======================== backup cms module for upgrade successfully ========================"
    return 0
}

function update_cms_service() {
    echo "update the bin/lib files in ${cms_home}/service"
    RPM_PACK_ORG_PATH=/opt/cantian/image
    cms_pkg_file=${RPM_PACK_ORG_PATH}/Cantian-RUN-CENTOS-64bit
    rm -rf ${cms_home}/service/*
    rm -rf ${cantian_home}/server/*
    cp -arf ${cms_pkg_file}/add-ons ${cms_pkg_file}/admin ${cms_pkg_file}/bin \
       ${cms_pkg_file}/cfg ${cms_pkg_file}/lib ${cms_pkg_file}/package.xml ${cms_home}/service

    cp -arf ${cms_pkg_file}/add-ons ${cms_pkg_file}/admin ${cms_pkg_file}/bin \
       ${cms_pkg_file}/cfg ${cms_pkg_file}/lib ${cms_pkg_file}/package.xml ${cantian_home}/server

    deploy_mode=$(python3 ${CURRENT_PATH}/get_config_info.py "deploy_mode")
    if [[ x"${deploy_mode}" == x"nas" ]]; then
        return 0
    fi

    link_type=$1
    if [ ${link_type} == 1 ];then
        echo "link_type is rdma"
        cp -arf ${cms_home}/service/add-ons/mlnx/lib* ${cms_home}/service/add-ons/
    elif [ ${link_type} == 0 ];then
        cp -arf ${cms_home}/service/add-ons/nomlnx/lib* ${cms_home}/service/add-ons/
        echo "link_type is tcp"
    else
        cp -arf ${cms_home}/service/add-ons/1823/lib* ${cms_home}/service/add-ons/
        echo "link_type is rdma_1823"
    fi
    cp -arf ${cms_home}/service/add-ons/kmc_shared/lib* ${cms_home}/service/add-ons/
}

function chown_mod_cms_service()
{
    echo "chown and chmod the files in ${cms_home}/service"
    chown -hR ${cantian_user_and_group} ${cms_home}
    chown -hR ${cantian_user_and_group} ${cantian_home}
    chmod -R 700 ${cms_home}/service
    chmod -R 700 ${cantian_home}/server
    find ${cms_home}/service/add-ons -type f | xargs chmod 500
    find ${cms_home}/service/admin -type f | xargs chmod 400
    find ${cms_home}/service/bin -type f | xargs chmod 500
    find ${cms_home}/service/lib -type f | xargs chmod 500
    find ${cms_home}/service/cfg -type f | xargs chmod 400

    find ${cantian_home}/server/add-ons -type f | xargs chmod 500
    find ${cantian_home}/server/admin -type f | xargs chmod 400
    find ${cantian_home}/server/bin -type f | xargs chmod 500
    find ${cantian_home}/server/lib -type f | xargs chmod 500
    find ${cantian_home}/server/cfg -type f | xargs chmod 400

    chmod 400 ${cms_home}/service/package.xml
    chmod 400 ${cantian_home}/server/package.xml
    return 0
}

function update_cms_scripts() {
    echo "update the cms scripts in ${cms_scripts}"
    rm -rf ${cms_scripts}/*
    cp -arf ${CURRENT_PATH}/* ${cms_scripts}
    return 0
}

function update_cms_config() {
    echo "update the cms ini in ${cms_home}/cfg"
    if [[ x"${deploy_mode}" != x"dbstore_unify" ]] || [[ x"${deploy_mode_backup}" == x"dbstore_unify" ]]; then
        return 0
    fi

    su -s /bin/bash - ${cantian_user} -c "cd ${CURRENT_PATH} && python3 ${CURRENT_PATH}/cmsctl.py upgrade"
    su -s /bin/bash - ${cantian_user} -c "python3 -B ${CURRENT_PATH}/../update_config.py --component=cms_ini --action=update --key=GCC_TYPE --value=DBS"
    su -s /bin/bash - ${cantian_user} -c "python3 -B ${CURRENT_PATH}/../update_config.py --component=cms_ini --action=update --key=GCC_HOME --value=/${storage_share_fs}/${cluster_name}_cms/gcc_home/gcc_file"
    su -s /bin/bash - ${cantian_user} -c "python3 -B ${CURRENT_PATH}/../update_config.py --component=cms_ini --action=add --key=GCC_DIR --value=/${storage_share_fs}/${cluster_name}_cms/gcc_home"
    su -s /bin/bash - ${cantian_user} -c "python3 -B ${CURRENT_PATH}/../update_config.py --component=cms_ini --action=add --key=CLUSTER_NAME --value=${cluster_name}"
    su -s /bin/bash - ${cantian_user} -c "python3 -B ${CURRENT_PATH}/../update_config.py --component=cms_ini --action=add --key=FS_NAME --value=${storage_share_fs}"
}

function update_cms_gcc_file() {
    echo "update the cms gcc file in share fs"
    if [[ x"${deploy_mode}" != x"dbstore_unify" ]] || [[ x"${deploy_mode_backup}" == x"dbstore_unify" ]]; then
        return 0
    fi
    su -s /bin/bash - ${cantian_user} -c "sh ${CURRENT_PATH}/start_cms.sh -P install_cms"
}

function safety_upgrade()
{
    echo -e "\n======================== begin to upgrade cms module ========================"

    link_type=$(cat ${CURRENT_PATH}/../../config/deploy_param.json  |
              awk -F ',' '{for(i=1;i<=NF;i++){if($i~"link_type"){print $i}}}' |
              sed 's/ //g' | sed 's/:/=/1' | sed 's/"//g' |
              awk -F '=' '{print $2}')

    deploy_mode_backup=$(cat ${BACKUP_UPGRADE_PATH}/config/deploy_param.json  |
              awk -F ',' '{for(i=1;i<=NF;i++){if($i~"deploy_mode"){print $i}}}' |
              sed 's/ //g' | sed 's/:/=/1' | sed 's/"//g' |
              awk -F '=' '{print $2}')

    update_cms_service ${link_type}

    chown_mod_cms_service

    update_cms_config

    update_cms_scripts

    update_cms_gcc_file

    echo "clean the old tmp files in cms home"
    rm -rf ${cms_tmp_file}

    echo "======================== upgrade cms module successfully ========================"
    return 0
}

function safety_rollback()
{
    echo -e "\n======================== begin to rollback cms module ========================"

    version=$(cat ${CURRENT_PATH}/../../versions.yml |
              sed 's/ //g' | grep 'Version:' | awk -F ':' '{print $2}')
    backup_dir=$2
    if [ ! -d ${backup_dir}/cms ];then
        echo "Error: backup_dir ${backup_dir}/cms does not exist"
        return 1
    fi
    echo "rollback from backup dir ${backup_dir}, cantian version is ${version}"

    echo "rollback cms home ${cms_home}"
    if [ ! -d ${backup_dir}/cms/cms_home ];then
        echo "Error: dir ${backup_dir}/cms/cms_home does not exist"
        return 1
    fi
    path_reg=$(echo ${cms_home} | sed 's/\//\\\//g')
    cms_home_backup=$(ls ${cms_home} | awk '{if($1!="log"){print $1}}' | sed "s/^/${path_reg}\//g")
    rm -rf ${cms_home_backup}
    cp -arf ${backup_dir}/cms/cms_home/* ${cms_home}

    echo "rollback cms scripts ${cms_scripts}"
    if [ ! -d ${backup_dir}/cms/cms_scripts ];then
        echo "Error: dir ${backup_dir}/cms/cms_scripts does not exist"
        return 1
    fi
    rm -rf ${cms_scripts}/*
    cp -arf ${backup_dir}/cms/cms_scripts/* ${cms_scripts}

    echo "check that all files are rolled back to ensure that no data is lost for safety rollback"
    check_rollback_files ${backup_dir}/cms/cms_home_files_list.txt ${backup_dir}/cms/cms_home ${cms_home}
    check_rollback_files ${backup_dir}/cms/cms_scripts_files_list.txt ${backup_dir}/cms/cms_scripts ${cms_scripts}

    echo "======================== rollback cms module successfully ========================"
    return 0
}

function chown_mod_scripts() {
    echo -e "\nInstall User:${cantian_user}"
    current_path_reg=$(echo ${CURRENT_PATH} | sed 's/\//\\\//g')
    scripts=$(ls ${CURRENT_PATH} | awk '{if($1!="appctl.sh"){print $1}}' | sed "s/^/${current_path_reg}\//g")
    chown -h ${cantian_user_and_group} ${scripts}
    chmod 400 ${CURRENT_PATH}/*.sh ${CURRENT_PATH}/*.py
    chmod 500 ${CURRENT_PATH}/cms_reg.sh
}

function copy_cms_scripts()
{
    echo "copying the cms scripts"
    clean_cms_scripts
    mkdir -p ${cms_scripts}
    chmod 755 ${cms_scripts}
    cp -arf ${CURRENT_PATH}/* ${cms_scripts}/
}

function clean_cms_scripts()
{
    if [ -d ${cms_scripts} ]; then
        rm -rf ${cms_scripts}
    fi
}

function check_and_create_cms_home()
{
    if [ ! -d ${cms_home} ]; then
        mkdir -m 750 -p ${cms_home}
        chown ${cantian_user_and_group} -hR ${cms_home}
    fi
    if [ ! -d ${cms_home}/cfg ];then
        mkdir -m 750 -p ${cms_home}/cfg
        chown ${cantian_user_and_group} -hR ${cms_home}/cfg
    fi
    if [ ! -d ${cms_home}/log ]; then
        mkdir -m 750 -p ${cms_home}/log
        touch ${LOG_FILE}
    fi
    chmod 640 ${LOG_FILE}
    chown ${cantian_user_and_group} -hR ${cms_home}/log
}

function check_old_install()
{
    if [ -d ${cms_home}/service ]; then
        echo "Error: cms has been installed in ${cms_home}"
        return 1
    fi
    chmod 750 -R ${cms_home}
    find ${cms_home}/log -type f | xargs chmod 640
}

deploy_user=$(cat ${CURRENT_PATH}/../../config/deploy_param.json |
              awk -F ',' '{for(i=1;i<=NF;i++){if($i~"deploy_user"){print $i}}}' |
              sed 's/ //g' | sed 's/:/=/1' | sed 's/"//g' |
              awk -F '=' '{print $2}')
d_user=$(echo ${deploy_user} | awk -F ':' '{print $2}')
storage_share_fs=$(cat ${CURRENT_PATH}/../../config/deploy_param.json |
              awk -F ',' '{for(i=1;i<=NF;i++){if($i~"storage_share_fs"){print $i}}}' |
              sed 's/ //g' | sed 's/:/=/1' | sed 's/"//g' |
              awk -F '=' '{print $2}')
cluster_name=$(cat ${CURRENT_PATH}/../../config/deploy_param.json |
              awk -F ',' '{for(i=1;i<=NF;i++){if($i~"cluster_name"){print $i}}}' |
              sed 's/ //g' | sed 's/:/=/1' | sed 's/"//g' |
              awk -F '=' '{print $2}')
deploy_mode=$(cat ${CURRENT_PATH}/../../config/deploy_param.json |
              awk -F ',' '{for(i=1;i<=NF;i++){if($i~"deploy_mode"){print $i}}}' |
              sed 's/ //g' | sed 's/:/=/1' | sed 's/"//g' |
              awk -F '=' '{print $2}')

check_and_create_cms_home

ACTION=$1
INSTALL_TYPE=""
UNINSTALL_TYPE=""
FORCE_UNINSTALL=""
BACKUP_UPGRADE_PATH=""
UPGRADE_TYPE=""
ROLLBACK_TYPE=""
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

function main_deploy()
{
    case "$ACTION" in
        start)
            set +e
            cgroup_clean
            set -e
            create_cgroup_path
            iptables_accept
            clear_shm
            do_deploy ${START_NAME}
            exit $?
            ;;
        stop)
            do_deploy ${STOP_NAME}
            iptables_delete
            exit $?
            ;;
        pre_install)
            if [[ ${INSTALL_TYPE} == "reserve" ]];then
                su -s /bin/bash - ${cantian_user} -c "python3 -B ${CURRENT_PATH}/../update_config.py -c cms -a add -k cms_reserve -v cms"
            fi
            check_old_install
            chown_mod_scripts
            do_deploy ${PRE_INSTALL_NAME}
            exit $?
            ;;
        install)
            if [[ "${cantian_in_container}" == "0" && "${deploy_mode}" != "dbstore_unify" ]]; then
                chown ${cantian_user_and_group} /mnt/dbdata/remote/share_${storage_share_fs}
            fi
            copy_cms_scripts
            do_deploy ${INSTALL_NAME}
            if [ $? -ne 0 ];then
                exit 1
            fi
            if [[ ${INSTALL_TYPE} == "reserve" ]];then
                su -s /bin/bash - ${cantian_user} -c "python3 -B ${CURRENT_PATH}/../update_config.py -component=cms_ini --action=update --key=_DISK_DETECT_FILE --value=gcc_file_detect_disk,"
            fi
            exit $?
            ;;
        uninstall)
            do_deploy ${UNINSTALL_NAME} ${UNINSTALL_TYPE} ${FORCE_UNINSTALL}
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
            if [ $? -ne 0 ];then
                exit 1
            fi
            su -s /bin/bash - ${cantian_user} -c "python3 -B ${CURRENT_PATH}/../update_config.py --component=cms_ini --action=update --key=_DISK_DETECT_FILE --value=gcc_file_detect_disk,"
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