#!/bin/bash
set +x

CURRENT_PATH=$(dirname $(readlink -f $0))
ACTION_PATH=/opt/cantian/action
REPO_PATH=/opt/cantian/repo
COMMON_PATH=/opt/cantian/common
CONFIG_PATH=/opt/cantian/config
VERSION_FILE_PATH=/opt/cantian/versions.yml
MYSQL_INSPECTION_PATH=/opt/cantian/image/cantian_connector/for_mysql_official/mf_connector_mount_dir/inspection
BACKUP_NOTE=/opt/backup_note
BACKUP_NOTE_LIMITED=2
source_version=''
dircetory_path=''

source ${CURRENT_PATH}/log4sh.sh
source ${CURRENT_PATH}/env.sh

#  获取源版本版本号
function get_source_version() {
    source_version=$(python3 ${CURRENT_PATH}/implement/get_source_version.py)
    if [ -z "${source_version}" ]; then
        logAndEchoError "failed to obtain source version"
        exit 1
    fi
    logAndEchoInfo "success to obtain source version, source version is: ${source_version}"
}
get_source_version

# 检查备份是否已存在
function backup_exist_check() {
    dircetory_path="/opt/cantian/upgrade_backup/cantian_upgrade_bak_${source_version}"
    if [ -f "${dircetory_path}/backup_success" ]; then
        logAndEchoInfo "upgrade_backup already success"
        return 0
    fi

    return 1
}

#  创建备份路径
function create_backup_directory() {
    logAndEchoInfo "begin to create backup directory"

    if [[ -n ${dircetory_path} ]]; then
        mkdir -m 755 -p ${dircetory_path}
        if [ $? -ne 0 ]; then
            logAndEchoError "create backup directory: ${dircetory_path} failed"
            exit 1
        fi
        rm -rf ${dircetory_path}/*  # 避免底层模块备份重入失败
    fi
    # 创建mysql巡检备份路径
    mkdir -m 750 -p ${dircetory_path}/mysql_inspection
    if [ $? -ne 0 ]; then
        logAndEchoError "create mysql inspection backup directory: ${dircetory_path}/mysql_inspection failed"
        exit 1
    fi
    logAndEchoInfo "create backup directory: ${dircetory_path} success"
}

#  拷贝备份文件
function copy_source_resource() {
    logAndEchoInfo "begin to copy source resource"
    cp -rfp ${ACTION_PATH} ${dircetory_path}
    cp -rfp ${REPO_PATH} ${dircetory_path}
    cp -rfp ${COMMON_PATH} ${dircetory_path}
    cp -rfp ${CONFIG_PATH} ${dircetory_path}
    cp -fp ${VERSION_FILE_PATH} ${dircetory_path}
    cp -rfp ${MYSQL_INSPECTION_PATH} ${dircetory_path}/mysql_inspection
    if [ $? -ne 0 ]; then
        logAndEchoError "backup mysql inspection failed"
    else
        rm -rf ${MYSQL_INSPECTION_PATH}
    fi

    logAndEchoInfo "copy source resource finished"
}

# 更新升级备份记录文件
function upgrade_buckup_info() {
    logAndEchoInfo "begin to take backup note"
    if [ ! -f ${BACKUP_NOTE} ]; then
        touch ${BACKUP_NOTE}
        chmod 640 ${BACKUP_NOTE}
    fi

    # 限制backup_note文件记录行数
    backup_note_lines=$(cat ${BACKUP_NOTE} | wc -l)
    if [ ${backup_note_lines} -gt ${BACKUP_NOTE_LIMITED} ]; then
        point_num=$(expr ${backup_note_lines} - ${BACKUP_NOTE_LIMITED})
        sed -i "1,${point_num}d" ${BACKUP_NOTE}
    fi

    # 获取当前时间戳
    current=$(date "+%Y-%m-%d %H:%M:%S")
    timeStamp=$(date -d "$current" +%s)
    currentTimeStamp=$((timeStamp*1000+10#$(date "+%N")/1000000))
    echo "${source_version}:${currentTimeStamp}" >> ${BACKUP_NOTE}
    logAndEchoInfo "upgrade buckup info success"
}

backup_exist_check
if [[ $? -ne 0 ]]; then
    create_backup_directory
    copy_source_resource
    upgrade_buckup_info
    return 0
fi

return 1
