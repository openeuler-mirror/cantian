/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * knl_recovery.h
 *
 *
 * IDENTIFICATION
 * src/kernel/persist/knl_recovery.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_RECOVERY_H__
#define __KNL_RECOVERY_H__

#include "cm_defs.h"
#include "cm_utils.h"
#include "knl_session.h"
#include "knl_log.h"
#include "knl_archive.h"
#include "knl_buffer_access.h"
#include "knl_compress.h"

#ifdef __cplusplus
extern "C" {
#endif

/* auto block repair, we just replay one page */
#define IS_BLOCK_RECOVER(session)  ((session)->kernel->rcy_ctx.abr_rcy_flag)
#define RCY_SLEEP_TIME_THRESHOLD   (10 * 1000 * 1000) // 10s
#define IS_FILE_RECOVER(session)   ((session)->kernel->rcy_ctx.is_file_repair)
#define IS_PITR_RECOVER(rcy)       ((rcy)->action == RECOVER_UNTIL_SCN || (rcy)->action == RECOVER_UNTIL_TIME)
#define RCY_IGNORE_CORRUPTED_LOG(rcy)       ((rcy)->action == RECOVER_UNTIL_CANCEL)
#define RCY_NO_LAG_TRESHOLD(size)  ((uint64)(0.9 * (size)))
#define IS_ENCTYPT_OR_COMPRESS_BACKUPSET(bak) \
        ((bak)->encrypt_info.encrypt_alg != ENCRYPT_NONE || (bak)->record.attr.compress != COMPRESS_NONE)
#define RCY_PAGE_LIST_BITMAP_LEN 64     // must power of 2
#define RCY_PAGE_LIST_NUM_MAX 4194304   // 4M
#define PCY_PAGE_LIST_MOD_MASK 4194303  // RCY_PAGE_LIST_NUM_MAX - 1
#define RCY_PAGE_LIST_MOD_BITLEN 22     // log2(RCY_PAGE_LIST_NUM_MAX)
#define RCY_PAGE_MAX_COUNT (RCY_PAGE_LIST_BITMAP_LEN * RCY_PAGE_LIST_NUM_MAX)
#define DAMAGE_PAGE_CACHE_COUNT 100

typedef enum en_rcy_wait_stats {
    TXN_END_WAIT_COUNT = PAGE_TYPE_COUNT,
    PRELOAD_DISK_PAGES,
    PRELOAD_BUFFER_PAGES,
    LOGIC_GROUP_COUNT,
    WAIT_RELAPY_COUNT,
    PRELOAD_NO_READ,
    PRELOAD_REAMIN,
    READ_LOG_TIME,
    PARAL_PROC_WAIT_TIME,
    GROUP_ANALYZE_TIME,
    READ_LOG_SIZE,
    REPALY_SPEED,
    ADD_PAGE_TIME,
    ADD_BUCKET_TIME,
    BUCKET_OVERFLOW_COUNT,
    PRELOAD_WAIT_TIME,
    /* add new item here */
    RCY_WAIT_STATS_COUNT,
} rcy_wait_stats_e;

typedef struct st_pcn_verify {
    uint32 pcn;
    bool8 failed;
    bool8 skip;
    uint16 unused;
} pcn_verify_t;

typedef struct st_pcn_verify_list {
    pcn_verify_t *list;
    uint32 count;
} pcn_verify_list_t;

typedef struct st_rcy_paral_item {
    uint32 page_index;
    uint32 slot;
    uint8 next_bucket_id; // the bucket id which will replay next enter page
    uint8 unused[3];
} rcy_paral_item_t;

typedef struct st_rcy_paral_group {
    log_group_t *group;
    uint16 enter_count;
    uint16 curr_enter_id;
    uint32 tx_id;
    uint32 id;
    uint8 tx_next_bid;   // the bucket id which will replay next tx entry
    uint8 unused[3];
    uint32 group_list_idx;
    uint64 ddl_lsn_pitr;
    rcy_paral_item_t items[];
} rcy_paral_group_t;

typedef struct st_rcy_paral_stat_t {
    uint32 session_id;
    uint32 session_util_rate;
    uint64 rcy_read_disk_page_num;
    uint64 rcy_read_disk_total_time;
    uint64 rcy_read_disk_avg_time;
    uint64 session_work_time;
    uint64 session_used_time;
    uint64 sleep_time_in_log_add_bucket;
    uint64 session_replay_log_group_count;
} rcy_paral_stat_t;

typedef struct st_rcy_bucket {
    spinlock_t lock;
    uint32 count;
    uint32 id;
    volatile uint32 head;
    volatile uint32 tail;
    rcy_paral_group_t **first;
    knl_session_t *session;
    date_t last_replay_time;
    cm_thread_eventfd_t eventfd;
    volatile uint32 waiting_index;
    thread_t thread;
    rcy_paral_stat_t rcy_stat;
} rcy_bucket_t;

typedef struct st_rcy_page {
    uint32 page;
    uint32 file;
    volatile uint32 current_group;
    volatile uint32 group_count;
    uint32 hash_next;
    uint32 gid;
    uint8 option;
    uint8 unused[3];
    rcy_paral_item_t *prev_enter; // prev enter page item for this page id
} rcy_page_t;

typedef struct st_rcy_page_bucket {
    uint32 count;
    uint32 first;
} rcy_page_bucket_t;

typedef struct st_rcy_preload_info {
    knl_session_t *session;
    uint32 curr;
    uint32 proc_id;
    volatile uint32 group_id; // last group which pages have been preloaded
} rcy_preload_info_t;

typedef struct st_rcy_context {
    spinlock_t lock;
    bool32 paral_rcy;
    bool32 rcy_end;
    bool32 is_working;

    recover_action_t action;
    knl_scn_t max_scn;
    aligned_buf_t read_buf;  // for recovery , need free()
    aligned_buf_t read_buf2;  // for lrpl
    bool32 swich_buf;
    uint32 capacity;
    char *buf;
    rcy_bucket_t bucket[GS_MAX_PARAL_RCY];
    int32 handle[GS_MAX_LOG_FILES];  // online logfile handle
    arch_file_t arch_file;
    bool8 is_closing;
    bool8 is_demoting; // if true, recovery will not stop at lrp point
    uint16 reserved;
    bool32 loading_curr_file;  // if true, batches are loaded from current file
    rcy_paral_group_t *group_list;
    rcy_paral_group_t *curr_group;
    rcy_page_t *page_list[RCY_PAGE_LIST_BITMAP_LEN];
    uint64 page_list_bitmap;
    rcy_page_bucket_t *page_bucket;
    uint16 *page_bitmap;
    log_point_t last_point;
    uint32 page_list_count;
    volatile uint32 tx_end_count;
    volatile uint32 current_tid;
    rcy_paral_group_t *prev_tx_group;
    /* repair corrupted page using old page in backup, need replay it to latest status */
    bool32 abr_rcy_flag;
    db_status_t abr_db_status;
    page_id_t abr_pagid;
    buf_ctrl_t *abr_ctrl;

    uint32 preload_proc_num;
    atomic_t preload_hwm;
    volatile uint32 curr_group_id;
    volatile bool32 replay_no_lag;

    uint64 wait_stats_view[RCY_WAIT_STATS_COUNT];
    thread_t preload_thread[GS_MAX_PARAL_RCY];
    rcy_preload_info_t preload_info[GS_MAX_PARAL_RCY];

    date_t last_lrpl_time;
    date_t add_page_time;
    date_t add_bucket_time;
    uint16 repair_file_id;
    bool32 is_file_repair;
    bool32 log_decrypt_failed;

    // use for load from compressed archive log
    knl_compress_t cmp_ctx;
    aligned_buf_t cmp_read_buf;
    uint32 cur_pos;             // record position of read_buf
    uint32 write_len;           // record data's len in read_buf
    int64 cmp_file_offset;
    int64 cur_arc_read_pos;
    bool32 is_first_arch_file;

    timeval_t paral_rcy_thread_start_work_time;
    uint64 max_lrp_lsn;
} rcy_context_t;

static void inline rcy_eventfd_init(rcy_context_t *ctx)
{
    for (uint32 i = 0; i < GS_MAX_PARAL_RCY; i++) {
        ctx->bucket[i].eventfd.efd = -1;
        ctx->bucket[i].eventfd.epfd = -1;
    }
}

status_t rcy_recover(knl_session_t *session);
status_t rcy_init(knl_session_t *session);
void rcy_close(knl_session_t *session);
bool32 rcy_validate_batch(log_batch_t *batch, log_batch_tail_t *tail);
void rcy_init_log_cursor(log_cursor_t *cursor, log_batch_t *batch);
void rcy_replay_batch(knl_session_t *session, log_batch_t *batch);

/*
 * Standby log receiver flush point always be updated by lrcv_process_batch, even current log is fetched by LFTC.
 * log receiver and LFTC can running same time, but log receiver may send log from batch 120,
 * LFTC send log from batch 100.
 * If standby failover when LFTC just send log end with batch 110, the log in [110, 120] is not exsit.
 * In this case, LRPL end point is 110, and log receiver flush point may be 130 and GBP lrp_point may be 129, GBP
 * status is unsafe, will not use gbp. So we do not need to update log receiver flush point here when LFTC running.
 */
void rcy_analysis_batch(knl_session_t *session, log_batch_t *batch);
void rcy_replay_logic(knl_session_t *session, log_entry_t *log);
void gbp_aly_gbp_logic(knl_session_t *session, log_entry_t *log, uint64 lsn);
void print_replay_logic(log_entry_t *log);
void ctrcy_bak_logic_entry(knl_session_t *ct_se, log_entry_t *log_entry, bool32 *stop_backup);
uint64 rcy_fetch_batch_lsn(knl_session_t *session, log_batch_t *batch);
status_t rcy_load(knl_session_t *session, log_point_t *point, uint32 *data_size, uint32 *block_size);
void rcy_close_file(knl_session_t *session);
status_t rcy_load_arch(knl_session_t *session, uint32 rst_id, uint32 asn, arch_file_t *file, bool32 *is_compress);
status_t rcy_load_from_arch(knl_session_t *session, log_point_t *point, uint32 *data_size, arch_file_t *file,
                            aligned_buf_t *align_buf);
status_t rcy_load_from_online(knl_session_t *session, uint32 file_id, log_point_t *point, uint32 *data_size,
                              int32 *handle, aligned_buf_t *align_buf);
status_t rcy_replay(knl_session_t *session, log_point_t *point, uint32 data_size_input, log_batch_t *batch,

                    uint32 block_size, bool32 *need_more_log, bool32 *replay_fail, bool32 is_analysis);
status_t rcy_analysis(knl_session_t *session, log_point_t *point, uint32 data_size, log_batch_t *batch,
                      uint32 block_size, bool32 *need_more_log);
status_t rcy_verify_checksum(knl_session_t *session, log_batch_t *batch);
void rcy_init_proc(knl_session_t *session);
void rcy_close_proc(knl_session_t *session);
void rcy_wait_preload_complete(knl_session_t *session);
void rcy_wait_replay_complete(knl_session_t *session);
status_t rcy_alloc_cmp(rcy_context_t *rcy);
bool32 db_terminate_lfn_reached(knl_session_t *session, uint64 curr_lfn);

void rcy_add_pages(rcy_paral_group_t *paral_group, log_group_t *group, uint32 group_slot, rcy_context_t *rcy,
                   bool32 *logic, rcy_paral_group_t **next_group);
void rcy_replay_logic_group(knl_session_t *session, rcy_paral_group_t *paral_group);
void rcy_add_replay_bucket(rcy_paral_group_t *paral_group, rcy_context_t *rcy);
void rcy_replay_group(knl_session_t *session, log_context_t *ctx, log_group_t *group);
void rcy_free_buffer(rcy_context_t *rcy);
status_t rcy_init_context(knl_session_t *session);
void print_rcy_skip_page_limit(knl_session_t *session);

/*
 * Version       : v 1.0
 * Author        :
 * Created       : 2017-04-25
 * Last Modified :
 * Description   : log diagnosis
 * Arguments     :
 * knl_handle_t session   handle of session
 * Return        : N/A
 */
#ifdef LOG_DIAG
void log_diag_page(knl_session_t *session);
#endif

void log_get_manager(log_manager_t **lmgr, uint32 *count);
void log_get_logic_manager(logic_log_manager_t **lmgr, uint32 *count);
const char* rcy_redo_name(log_entry_t *log);
#ifdef __cplusplus
}
#endif

#endif
