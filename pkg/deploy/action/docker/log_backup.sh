CURRENT_PATH=$(dirname $(readlink -f $0))
source ${CURRENT_PATH}/../log4sh.sh
if [[ $# -ne 5 ]] && [[ $# -ne 4 ]];then
    logAndEchoError "Usage: Please input 4 or 5 params: cluster_name cluster_id node_id deploy_user [storage_metadata_fs]"
    exit 1
fi
cluster_name=$1
cluster_id=$2
node_id=$3
deploy_user=$4
storage_metadata_fs=$5

function delete_log_if_too_much() {
    local dir_path="$1"
    local max_logs=5 #最大文件限制
    if [ ! -d "${dir_path}" ];then
        logAndEchoError "invalid log dir_path: ${dir_path}"
        exit 1
    fi
    local dirs=$(find ${dir_path} -type d -name "????-??-??-??-??-??*")
    local log_count=$(echo "${dirs}" | wc -l)
    
    if [ "${log_count}" -gt "${max_logs}" ]; then
        logAndEchoInfo "logs more than ${max_logs}, begin to delete oldest log"
        local sorted_dirs=$(echo "${dirs}" | sort)
        local oldest_dir=$(echo "${sorted_dirs}" | head -n 1)
        if [ -n "${oldest_dir}" ]; then
            rm -rf "$oldest_dir"
            logAndEchoInfo "found oldest log: ${oldest_dir}, remove complete"
        fi
    fi
}

function check_path_and_copy() {
    #获取参数
    src_path="$1"
    dst_path="$2"
    #检查是否存在
    if [ -e "${src_path}" ];then
        cp -rf ${src_path} ${dst_path}
    fi
}

function main() {
    logAndEchoInfo "Backup log begin."
    DATE=$(date +"%Y-%m-%d-%H-%M-%S")
    mkdir -p /home/mfdb_core/${cluster_name}_${cluster_id}/${DATE}-node${node_id}
    delete_log_if_too_much /home/mfdb_core/${cluster_name}_${cluster_id}
    cd /home/mfdb_core/${cluster_name}_${cluster_id}/${DATE}-node${node_id}
    mkdir cantian cms dbstor core_symbol mysql logicrep
    mkdir cantian/opt cantian/mnt
    mkdir dbstor/opt dbstor/mnt dbstor/ftds dbstor/install
    check_path_and_copy /mnt/dbdata/local/cantian/tmp/data/log cantian/mnt
    check_path_and_copy /mnt/dbdata/local/cantian/tmp/data/cfg cantian/mnt
    check_path_and_copy /opt/cantian/cantian/log cantian/opt
    check_path_and_copy /opt/cantian/deploy cantian/opt
    check_path_and_copy /opt/cantian/cantian_exporter cantian/opt
    check_path_and_copy /opt/cantian/common/config cantian/opt
    check_path_and_copy /opt/cantian/cms/log cms/
    check_path_and_copy /mnt/dbdata/local/cantian/tmp/data/dbstor/data/logs dbstor/mnt
    check_path_and_copy /opt/cantian/cms/dbstor/data/logs dbstor/opt
    check_path_and_copy /opt/cantian/dbstor/data/logs dbstor/install
    check_path_and_copy /mnt/dbdata/local/cantian/tmp/data/dbstor/data/ftds/ftds/data/stat dbstor/ftds
    check_path_and_copy /opt/cantian/cantian/server/bin core_symbol/
    check_path_and_copy /home/${deploy_user}/cantiandinstall.log mysql/
    check_path_and_copy /mnt/dbdata/remote/metadata_${storage_metadata_fs}/node${node_id}/mysql.log mysql/
    check_path_and_copy /opt/software/tools/logicrep/log logicrep/
    check_path_and_copy /opt/software/tools/logicrep/logicrep/run logicrep/
    check_path_and_copy /opt/software/tools/logicrep/logicrep/perf logicrep/
    check_path_and_copy /opt/cantian/logicrep/log/logicrep_deploy.log logicrep/
    logAndEchoInfo "Backup log complete."
}

main

