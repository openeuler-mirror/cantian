#!/bin/bash

# 计算参天内存隔离值大小(单位MB)并写入memory.limit_in_bytes

set +x
CANTIAND_INI_FILE=/mnt/dbdata/local/cantian/tmp/data/cfg/cantiand.ini
#cgroup预留内存隔离值LOG_BUFFER_SIZE + MES_POOL_SIZE，单位MB
LOG_BUF_AND_MES_POOL_SIZE=3072
# 预留reform流程内存 MB
REFORM_MEM_SIZE=25600
#cgroup cantiand总预留隔离值（需累加各值），单位MB
DEFAULT_MEM_SIZE=0

CUR_RESULT=0
DATA_BUFFER_SIZE=0
SHARED_POOL_SIZE=0
SESSIONS=0
#单个SESSION占用内存(字节)
SESSION_SIZE=2566824

#define
NODE_COUNT=2
PAGE_SIZE=8192
#OTHER_DLS_COUNT = CT_MAX_USERS * 4 + CT_MAX_SPACES
OTHER_DLS_COUNT=61024
TABLE_SIZE=13
#DLS_CNT_PER_TABLE=(CT_SIMPLE_PART_NUM * CT_MAX_TABLE_INDEXES + CT_SIMPLE_PART_NUM + 3)
DLS_CNT_PER_TABLE=33795
RES_BUCKET_SIZE=12
BUF_RES_SIZE=144
LOCAL_DLS_RES_SIZE=48
GLOBAL_DLS_RES_SIZE=120

function calculate_mem()
{
    line=$3
    local unit=""
    CUR_RESULT=$(echo $line | tr -cd "[0-9]")
    unit=$(echo ${line#*$CUR_RESULT})
    if [[ $unit == "G" ]]; then
        CUR_RESULT=$(expr "${CUR_RESULT}" \* 1024)
    fi
    DEFAULT_MEM_SIZE=$(expr "${DEFAULT_MEM_SIZE}" + "${CUR_RESULT}")
}

function calculate_session_mem()
{
    line=$3
    SESSIONS=$(echo $line | tr -cd "[0-9]")
    SESSION_MEM=$(expr "${SESSIONS}" \* "${SESSION_SIZE}" \/ 1024 \/ 1024) #MB
    DEFAULT_MEM_SIZE=$(expr "${DEFAULT_MEM_SIZE}" + "${SESSION_MEM}")
}

function calculate_drc_mem()
{
    #buf res cnt计算公式: DATA_BUFFER_SIZE / page_size(8192)
    #buf res mem size计算公式: (cnt * 2) * sizeof(drc_res_bucket_t) + cnt * sizeof(drc_buf_res_t)
    local size_mb=$(expr 1024 \* 1024)
    local buf_res_cnt=0
    local buf_res_mem_size=0
    buf_res_cnt=$(expr "${DATA_BUFFER_SIZE}" \* "${size_mb}" \/ "${PAGE_SIZE}" \* "${NODE_COUNT}")
    buf_res_mem_size=$(expr "${buf_res_cnt}" \* 2 \* "${RES_BUCKET_SIZE}" + "${buf_res_cnt}" \* "${BUF_RES_SIZE}")
    buf_res_mem_size=$(expr "${buf_res_mem_size}" \/ "${size_mb}")

    #local dls res cnt计算公式: total_table_dls_cnt = (dc_pool_size / table_size) * dls_cnt_per
    #                          local dls res cnt = total_table_dls_cnt * (1 - CT_SEGMENT_DLS_RATIO) + MIN(buf res cnt,
    #                           total_table_dls_cnt * CT_SEGMENT_DLS_RATIO) + other_dls_count
    #local dls res mem size计算公式: cnt*2*sizeof(drc_res_bucket_t) + cnt * sizeof(drc_local_lock_res_t)
    local local_dls_res_cnt=0
    local local_dls_res_mem_size=0
    local total_table_dls_cnt=0
    local dc_pool_size=0
    local segment_ratio_cnt=0
    dc_pool_size=$(expr "${SHARED_POOL_SIZE}" \/ 2)
    total_table_dls_cnt=$(expr "${dc_pool_size}" \/ "${TABLE_SIZE}" \* "${DLS_CNT_PER_TABLE}")
    local_dls_res_cnt=$(expr "${total_table_dls_cnt}" \/ 10 + "${OTHER_DLS_COUNT}")
    segment_ratio_cnt=$(expr "${total_table_dls_cnt}" \* 9 \/ 10) #CT_SEGMENT_DLS_RATIO = 0.9
    if [ ${buf_res_cnt} -gt ${segment_ratio_cnt} ];then
        local_dls_res_cnt=$(expr "${local_dls_res_cnt}" + "${segment_ratio_cnt}")
    else
        local_dls_res_cnt=$(expr "${local_dls_res_cnt}" + "${buf_res_cnt}")
    fi
    local_dls_res_mem_size=$(expr "${local_dls_res_cnt}" \* 2 \* "${RES_BUCKET_SIZE}" + "${local_dls_res_cnt}" \* "${LOCAL_DLS_RES_SIZE}")
    local_dls_res_mem_size=$(expr "${local_dls_res_mem_size}" \/ "${size_mb}")

    #global dls res cnt计算公式: local dls res cnt * node_count
    #global dls res mem size计算公式: cnt*2*sizeof(drc_res_bucket_t) + cnt * sizeof(drc_master_res_t)
    local global_dls_res_cnt=0
    local global_dls_res_mem_size=0
    global_dls_res_cnt=$(expr "${local_dls_res_cnt}" \* "${NODE_COUNT}")
    global_dls_res_mem_size=$(expr "${global_dls_res_cnt}" \* 2 \* "${RES_BUCKET_SIZE}" + "${global_dls_res_cnt}" \* "${GLOBAL_DLS_RES_SIZE}")
    global_dls_res_mem_size=$(expr "${global_dls_res_mem_size}" \/ "${size_mb}")

    DEFAULT_MEM_SIZE=$(expr "${DEFAULT_MEM_SIZE}" + "${buf_res_mem_size}" + "${local_dls_res_mem_size}" + "${global_dls_res_mem_size}")
}

function cantiand_cgroup_config() 
{
    if [ ! -f ${CANTIAND_INI_FILE} ]; then
        echo "${CANTIAND_INI_FILE} not exist, limited cantiand memory failed"
        return
    fi

    DEFAULT_MEM_SIZE=$(expr ${LOG_BUF_AND_MES_POOL_SIZE} + ${REFORM_MEM_SIZE})
    while read line
    do
        if [[ $line =~ "TEMP_BUFFER_SIZE" ]]; then
                calculate_mem $line
        fi
        if [[ $line =~ "DATA_BUFFER_SIZE" ]]; then
                calculate_mem $line
                DATA_BUFFER_SIZE=${CUR_RESULT}
        fi
        if [[ $line =~ "SHARED_POOL_SIZE" ]]; then
                calculate_mem $line
                SHARED_POOL_SIZE=${CUR_RESULT}
        fi
        if [[ $line =~ "CR_POOL_SIZE" ]]; then
                calculate_mem $line
        fi
        if [[ $line =~ "LARGE_POOL_SIZE" ]]; then
                calculate_mem $line
        fi
        if [[ $line =~ "VARIANT_MEMORY_AREA_SIZE" ]]; then
                calculate_mem $line
        fi
        if [[ $line =~ "_INDEX_BUFFER_SIZE" ]]; then
                calculate_mem $line
        fi
        if [[ $line =~ "SESSIONS" ]]; then
                calculate_session_mem $line
        fi
    done < /mnt/dbdata/local/cantian/tmp/data/cfg/cantiand.ini
    calculate_drc_mem
}