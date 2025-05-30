#!/bin/bash
set +x
CURRENT_PATH=$(dirname $(readlink -f $0))
storage_archive_fs=$(python3 ${CURRENT_PATH}/../cantian/get_config_info.py "storage_archive_fs")
deploy_mode=$(python3 ${CURRENT_PATH}/../cantian/get_config_info.py "deploy_mode")
max_arch_files_size=$(python3 ${CURRENT_PATH}/../cantian/get_config_info.py "MAX_ARCH_FILES_SIZE")
LOG_PATH=/opt/cantian/log/dbstor/install.log

declare -A CAPACITY_UNIT_MAP=(
    ["T"]=$((1024*1024*1024))
    ["G"]=$((1024*1024))
    ["M"]=$((1024))
    ["K"]=$((1))
)

function query_dbstor_tocal_capacity_and_check() {
    if [[ x"${deploy_mode}" != x"dbstor" ]]; then
        echo "${deploy_mode} no need to check" >> ${LOG_PATH}
        return
    fi

    length_max_arch_files_size=${#max_arch_files_size}
    capacity_unit=${max_arch_files_size:0-1:1}
    capacity_num=${max_arch_files_size:0:length_max_arch_files_size-1}
    capacity_unit_num=${CAPACITY_UNIT_MAP[$capacity_unit]}
    
    total_capacity=$(/opt/cantian/image/Cantian-RUN-CENTOS-64bit/bin/dbstor --query-fs-info --fs-name=${storage_archive_fs} \
    --vstore_id=0 | grep total_capacity | grep -oP "[0-9]+")
    if [[ x"${total_capacity}" = x"" ]]; then
        echo "total_capacity ${total_capacity} not find" >> ${LOG_PATH}
        exit 1
    fi

    # total_capacity为扇区个数，需要乘0.5换成kb单位,且max_arch_files_size不应该超过archive文件系统一半的80%，所以为0.5*0.5*0.8=0.2
    precent_num=0.2
    finall_arch_files_size=$((capacity_num * capacity_unit_num))
    arch_files_size=$(echo "$total_capacity * $precent_num" | bc)
    result=$(echo "$finall_arch_files_size > $arch_files_size" | bc)
    if [[ "$result" -eq 1 ]]; then
        echo "finall_arch_files_size ${finall_arch_files_size} is larger than arch_files_size ${arch_files_size}, \
        max_arch_files_size is ${max_arch_files_size}" >> ${LOG_PATH}
        exit 1
    fi

    echo "finall_arch_files_size is ${finall_arch_files_size}, arch_files_size is ${arch_files_size}, \
    max_arch_files_size is ${max_arch_files_size}" >> ${LOG_PATH}
}

function main()
{
    export LD_LIBRARY_PATH=/opt/cantian/image/Cantian-RUN-CENTOS-64bit/lib:/opt/cantian/dbstor/add-ons
    query_dbstor_tocal_capacity_and_check
    unset LD_LIBRARY_PATH
}

main $@