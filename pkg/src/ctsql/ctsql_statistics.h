/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2024 Huawei Technologies Co.,Ltd.
 *
 * Cantian is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *          http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 * -------------------------------------------------------------------------
 *
 * ctsql_statistics.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/ctsql_statistics.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_STATISTICS_H__
#define __SQL_STATISTICS_H__

#include "cm_defs.h"
#include "cm_date.h"
#include "cm_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_sys_stat {
    SYS_STAT_SELECTS = 0,
    SYS_STAT_SELECT_TIME = 1,
    SYS_STAT_UPDATES = 2,
    SYS_STAT_UPDATE_TIME = 3,
    SYS_STAT_INSERTS = 4,
    SYS_STAT_INSERT_TIME = 5,
    SYS_STAT_DELETES = 6,
    SYS_STAT_DELETE_TIME = 7,
    SYS_STAT_LOCAL_TXN_COMMITS = 8,
    SYS_STAT_LOCAL_TXN_ROLLBACKS = 9,
    SYS_STAT_LOCAL_TXN_TIME = 10,
    SYS_STAT_XA_TXN_COMMITS = 11,
    SYS_STAT_XA_TXN_ROLLBACKS = 12,
    SYS_STAT_XA_TXN_TIME = 13,
    SYS_STAT_MAX_COUNT = 14
} sys_stat_t;

typedef struct st_vm_stat {
    uint64 open_pages;
    uint64 close_pages;
    uint64 max_open_pages;
    uint64 alloc_pages;
    uint64 free_pages;
    uint64 swap_in_pages;
    uint64 swap_out_pages;
    uint64 time_elapsed;
    timeval_t time_begin;
} vm_stat_t;

typedef struct st_knl_analyze_stat {
    uint64 vm_open_pages;
    uint64 vm_close_pages;
    uint64 vm_alloc_pages;
    uint64 vm_free_pages;
    uint64 vm_swapin_pages;
    uint64 vm_swapout_pages;
    uint64 vm_time_elapsed;
    uint64 sort_time;
    uint64 cpu_time;
    timeval_t begin_tv;
    uint32 stats_threads;
    bool8 is_statitics;
    bool8 is_finished;
    uint64 execute_time;
} knl_analyze_stat_t;

// sql context accumulation
typedef struct st_ctx_accum {
    atomic_t executions;
    atomic_t disk_reads;
    atomic_t disk_writes;
    atomic_t buffer_gets;
    atomic_t dcs_buffer_gets;
    atomic_t dcs_cr_gets;
    atomic_t parse_calls;
    atomic_t processed_rows;
    atomic_t io_wait_time;
    atomic_t con_wait_time;
    atomic_t dcs_wait_time; // dac network time
    atomic_t cpu_time;
    atomic_t elapsed_time;

    // stat info about datafile
    atomic_t scattered_reads;
    atomic_t sequential_reads;
    atomic_t scattered_time;
    atomic_t sequential_time;
    atomic_t aio_reads;
    atomic_t wait_map;
    atomic_t wait_map_time;
    atomic_t segment_extends;
    atomic_t segment_extend_time;

    // stat info about buffer
    atomic_t buf_busy_waits;
    atomic_t buf_busy_wait_time;
    atomic_t cr_gets; // Number of successful acquisitions of cr page
    atomic_t segment_header;
    atomic_t segment_header_time;
    atomic_t undo_header;
    atomic_t undo_header_time;
    atomic_t free_list;
    atomic_t free_list_time;
    atomic_t undo_block;
    atomic_t undo_block_time;
    atomic_t data_block;
    atomic_t data_block_time;
    atomic_t buff_pool_alloc;
    atomic_t buff_pool_alloc_time;

    // stat info about redo log
    atomic_t log_arch;
    atomic_t log_arch_time;
    atomic_t log_ckpt;
    atomic_t log_ckpt_time;
    atomic_t log_sync;
    atomic_t log_sync_time;
    atomic_t log_bytes;

    // stat info about transaction
    atomic_t row_lock;
    atomic_t row_lock_time;
    atomic_t key_lock;
    atomic_t key_lock_time;
    atomic_t itl_alloc;
    atomic_t itl_alloc_time;
    atomic_t table_slock;
    atomic_t table_slock_time;
    atomic_t table_xlock;
    atomic_t table_xlock_time;
    atomic_t read_wait;
    atomic_t read_wait_time;

    // stat info about temp space
    atomic_t temp_reads;
    atomic_t temp_read_time;
    atomic_t temp_writes;
    atomic_t temp_write_time;
    atomic_t sorts;
    atomic_t sort_time;
    atomic_t disk_sorts;
    vm_stat_t vm_stat;           // vm pages statistical info
    knl_analyze_stat_t knl_stat; // gather statistics info

    date_t first_load_time;    // Timestamp of the parent creation time
    date_t last_load_time;     // Time at which the query plan (heap 6) was loaded into the library cache
    atomic_t last_active_time; // TIme at which the query plan was last active
    uint64 parse_time;         // sql parse time
    int64 proc_oid;            // Program identifier
    uint16 proc_line;          // program line number

#ifdef Z_SHARDING
    atomic_t network_time; // cn to dn network transmission time consuming
    atomic_t shd_sql_executions;
    date_t shd_sql_begin_time_m;
    date_t shd_sql_end_time_m;
#endif
} ctx_stat_t;

typedef struct st_exec_prev_stat {
    struct timeval tv_start;
    uint32 stat_level;
    uint64 io_wait_time;     // user io wait
    uint64 con_wait_time;    // concurrency wait
    uint64 res_io_wait_time; // resource io wait
    uint64 dcs_net_time;     // daac network buffer read
} exec_prev_stat_t;

typedef struct st_ctx_prev_stat {
    struct timeval tv_start;
    uint64 processed_rows;
    uint64 disk_reads;
    uint64 buffer_gets;
    uint64 dcs_buffer_gets;
    uint64 dcs_buffer_sends;
    uint64 dcs_cr_gets;
    uint64 dcs_cr_sends;
    uint64 cr_reads;
    uint64 dcs_cr_reads;
    uint64 io_wait_time;  // user io wait
    uint64 con_wait_time; // concurrency wait
    uint64 dcs_net_time;

    // stat info about datafile
    atomic_t scattered_reads;
    atomic_t sequential_reads;
    atomic_t scattered_time;
    atomic_t sequential_time;
    atomic_t aio_reads;
    atomic_t wait_map;
    atomic_t wait_map_time;
    atomic_t segment_extends;
    atomic_t segment_extend_time;

    // stat info about buffer
    atomic_t buf_busy_waits;
    atomic_t buf_busy_wait_time;
    atomic_t cr_gets; // Number of successful acquisitions of cr page
    atomic_t segment_header;
    atomic_t segment_header_time;
    atomic_t undo_header;
    atomic_t undo_header_time;
    atomic_t free_list;
    atomic_t free_list_time;
    atomic_t undo_block;
    atomic_t undo_block_time;
    atomic_t data_block;
    atomic_t data_block_time;
    atomic_t buff_pool_alloc;
    atomic_t buff_pool_alloc_time;

    // stat info about redo log
    atomic_t log_arch;
    atomic_t log_arch_time;
    atomic_t log_ckpt;
    atomic_t log_ckpt_time;
    atomic_t log_sync;
    atomic_t log_sync_time;
    atomic_t log_bytes;

    // stat info about transaction
    atomic_t row_lock;
    atomic_t row_lock_time;
    atomic_t key_lock;
    atomic_t key_lock_time;
    atomic_t itl_alloc;
    atomic_t itl_alloc_time;
    atomic_t table_slock;
    atomic_t table_slock_time;
    atomic_t table_xlock;
    atomic_t table_xlock_time;
    atomic_t read_wait;
    atomic_t read_wait_time;

    // stat info about temp space
    atomic_t temp_reads;
    atomic_t temp_read_time;
    atomic_t temp_writes;
    atomic_t temp_write_time;
    atomic_t sorts;
    atomic_t sort_time;
    atomic_t disk_sorts;
    vm_stat_t vm_stat; // vm pages statistical info
} ctx_prev_stat_t;

// sql stat accumulation
typedef struct st_sql_stat {
    uint64 exec_count;
    uint64 directly_execs;
    uint64 exec_time;
    uint64 cpu_time;
    uint64 io_wait_time;
    uint64 dcs_net_time;
    uint64 exec_selects;
    uint64 exec_select_time;
    uint64 exec_updates;
    uint64 exec_update_time;
    uint64 exec_inserts;
    uint64 exec_insert_time;
    uint64 exec_deletes;
    uint64 exec_delete_time;
    uint64 parses;
    uint64 hard_parses;
    uint64 fetch_count;
    uint64 fetched_rows;
    uint64 parses_time_elapse;
    uint64 parses_time_cpu;
    /* stats for resource control */
    uint64 res_io_wait_time;
    uint64 res_io_waits;
    uint64 res_sess_queue_time;
    uint64 res_sess_queues;

#ifdef Z_SHARDING
    uint64 dis_exec_selects_single_shard;
    uint64 dis_exec_select_time_single_shard;
    uint64 dis_exec_updates_single_shard;
    uint64 dis_exec_update_time_single_shard;
    uint64 dis_exec_inserts_single_shard;
    uint64 dis_exec_insert_time_single_shard;
    uint64 dis_exec_deletes_single_shard;
    uint64 dis_exec_delete_time_single_shard;
    uint64 dis_exec_selects_multi_shard;
    uint64 dis_exec_select_time_multi_shard;
    uint64 dis_exec_updates_multi_shard;
    uint64 dis_exec_update_time_multi_shard;
    uint64 dis_exec_inserts_multi_shard;
    uint64 dis_exec_insert_time_multi_shard;
    uint64 dis_exec_deletes_multi_shard;
    uint64 dis_exec_delete_time_multi_shard;
#endif
} sql_stat_t;

#define SQL_SESSION_STAT_REFRESH_SHREHOLD_MIN (1)
#define SQL_SESSION_STAT_REFRESH_SHREHOLD \
    (int64)(SQL_SESSION_STAT_REFRESH_SHREHOLD_MIN * SECONDS_PER_MIN * MICROSECS_PER_SECOND)

typedef struct st_cbo_cost {
    int64 card; // cardinality
    double cost;
} cbo_cost_t;

static inline char *get_sys_stat_name(sys_stat_t item)
{
    switch (item) {
        case SYS_STAT_SELECTS:
            return "user selects";
        case SYS_STAT_UPDATES:
            return "user updates";
        case SYS_STAT_INSERTS:
            return "user inserts";
        case SYS_STAT_DELETES:
            return "user deletes";
        case SYS_STAT_SELECT_TIME:
            return "select cost time(us)";
        case SYS_STAT_UPDATE_TIME:
            return "update cost time(us)";
        case SYS_STAT_INSERT_TIME:
            return "insert cost time(us)";
        case SYS_STAT_DELETE_TIME:
            return "delete cost time(us)";
        case SYS_STAT_LOCAL_TXN_COMMITS:
            return "local txn commits";
        case SYS_STAT_XA_TXN_COMMITS:
            return "xa txn commits";
        case SYS_STAT_LOCAL_TXN_ROLLBACKS:
            return "local txn rollbacks";
        case SYS_STAT_XA_TXN_ROLLBACKS:
            return "xa txn rollbacks";
        case SYS_STAT_LOCAL_TXN_TIME:
            return "local txn cost avg time(us)";
        case SYS_STAT_XA_TXN_TIME:
            return "xa txn cost avg time(us)";
        default:
            return "unknown name";
    }
}

void sql_begin_ctx_stat(void *handle);
void sql_end_ctx_stat(void *handle);
void sql_begin_exec_stat(void *handle);
void sql_end_exec_stat(void *handle);
void sql_accumulate_c2d_time(void *handle, int64 elapsed_time);
void sql_record_knl_stats_info(void *handle);
void sql_reset_knl_stats_info(void *handle, status_t analyze_succeed);
#ifdef __cplusplus
}
#endif

#endif
