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
 * knl_ckpt.h
 *
 *
 * IDENTIFICATION
 * src/kernel/persist/knl_ckpt.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_CKPT_H__
#define __KNL_CKPT_H__

#include "cm_defs.h"
#include "cm_thread.h"
#include "cm_spinlock.h"
#include "cm_utils.h"
#include "knl_log.h"
#include "knl_buffer_access.h"
#include "knl_session.h"
#include "knl_page.h"
#include "knl_datafile.h"

#ifndef WIN32
#include <semaphore.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define CKPT_LATCH_WAIT    30
#define CKPT_LATCH_TIMEOUT 3
#define CKPT_PAGE_CLEAN_RATIO(session)  ((session)->kernel->attr.page_clean_ratio)
#define CKPT_IS_TRIGGER(mode) ((mode) == CKPT_TRIGGER_INC || (mode) == CKPT_TRIGGER_FULL || \
                               (mode) == CKPT_TRIGGER_CLEAN)
#define CKPT_WAIT_MS 200
#define CKPT_BITS_PER_BYTE 8

#define GS_CKPT_EDP_GROUP_SIZE (uint32)(GS_CKPT_GROUP_SIZE / 3)
#define GS_CLEAN_EDP_GROUP_SIZE (uint32)(GS_CKPT_GROUP_SIZE * 2)
#define PAGE_CLEAN_MAX_BYTES (GS_MAX_BUF_POOL_NUM / CKPT_BITS_PER_BYTE)
typedef struct st_ckpt_edp_group {
    spinlock_t lock;
    uint32 count;
    edp_page_info_t pages[GS_CKPT_GROUP_SIZE + 1];
} ckpt_edp_group_t;

typedef struct st_ckpt_clean_edp_group {
    spinlock_t lock;
    uint32 count;
    edp_page_info_t pages[GS_CLEAN_EDP_GROUP_SIZE + 1];
} ckpt_clean_edp_group_t;

typedef enum e_ckpt_mode {
    /* Both trigger_task and timed_task can be idle */
    CKPT_MODE_IDLE = 0,
   
    /* Types of trigger_task action */
    CKPT_TRIGGER_INC,
    CKPT_TRIGGER_FULL,
    CKPT_TRIGGER_CLEAN,

    /* Types of timed_task action */
    CKPT_TIMED_INC,
    CKPT_TIMED_CLEAN,

    /* For counting */
    CKPT_MODE_NUM,
} ckpt_mode_t;

typedef enum e_page_clean_mode {
    /* clean page for single buffer set when prepare page */
    PAGE_CLEAN_MODE_SINGLESET = 0,
    /* clean page for all buffer set when prepare page */
    PAGE_CLEAN_MODE_ALLSET,
} page_clean_t;

typedef struct st_trigger_task {
    bool32 guarantee; // If set, keep on trying assigning the task while condition is not satisfied.
    bool32 join;
    bool32 wait; // If set, wait for the task to be finished after assigning the task.
    ckpt_mode_t mode; // The type of the task to be assigned.
} trigger_task_t;

typedef struct st_ckpt_queue {
    spinlock_t lock;
    volatile uint32 count;

    log_point_t trunc_point;
    buf_ctrl_t *first;
    buf_ctrl_t *last;
} ckpt_queue_t;

typedef struct st_ckpt_sort_item {
    buf_ctrl_t *ctrl;
    uint32 buf_id;
    bool8 need_punch;
} ckpt_sort_item;

typedef struct st_rcy_sort_item {
    page_head_t *page;
    uint32 buf_id;
} rcy_sort_item_t;

typedef struct st_ckpt_group {
    uint32 count;
    char *buf;
    char *iocbs_buf;
    ckpt_sort_item items[GS_CKPT_GROUP_SIZE];
} ckpt_group_t;

typedef struct st_ckpt_part_group {
    uint32 count;
    uint32 item_index[GS_CKPT_GROUP_SIZE];
} ckpt_part_group_t;

#ifdef WIN32
typedef HANDLE cm_sem_t;
#else
typedef sem_t cm_sem_t;
#endif

typedef struct st_ckpt_asyncio_ctx {
    cm_io_context_t aio_ctx;
    datafile_t *datafiles[GS_CKPT_GROUP_SIZE];
    int32 *handles[GS_CKPT_GROUP_SIZE];
    uint64 offsets[GS_CKPT_GROUP_SIZE];
} ckpt_asyncio_ctx_t;

typedef struct st_dbwr_context {
    thread_t thread;
    knl_session_t *session;
    uint16 begin;
    uint16 end;
    bool32 dbwr_trigger;
    cm_sem_t sem;
    int32 datafiles[GS_MAX_DATA_FILES];  // data file handles
    bool32 flags[GS_MAX_DATA_FILES];
    ckpt_asyncio_ctx_t async_ctx;
    uint32 io_cnt;
    uint32 id;
} dbwr_context_t;

typedef struct st_ckpt_part_stat {
    uint64 flush_times;
    uint64 zero_flush_times;
    uint64 flush_pagaes;
    uint64 min_flush_pages;
    uint64 max_flush_pages;
    uint64 cur_flush_pages;
} ckpt_part_stat_t;

typedef struct st_ckpt_stat {
    uint64 double_writes;
    uint64 double_write_time;
    uint64 disk_writes;
    uint64 disk_write_time;
    uint64 ckpt_total_neighbors_times;
    uint64 ckpt_total_neighbors_len;
    uint32 ckpt_last_neighbors_len;
    uint32 ckpt_curr_neighbors_times;
    uint32 ckpt_curr_neighbors_len;
    uint64 task_count[CKPT_MODE_NUM]; // FOR TEST: viewing
    uint64 task_us[CKPT_MODE_NUM];
    uint64 flush_pages[CKPT_MODE_NUM];
    uint64 clean_edp_count[CKPT_MODE_NUM];
    uint64 proc_wait_cnt;
    ckpt_part_stat_t part_stat[GS_MAX_DBWR_PROCESS];
    date_t ckpt_begin_time[CKPT_MODE_NUM];
} ckpt_stat_t;

typedef struct st_ckpt_clean_ctx {
    buf_ctrl_t *ctrl[GS_MAX_BUF_POOL_NUM];
    uint64 clean_count[GS_MAX_BUF_POOL_NUM];
    uint8 bitmap[PAGE_CLEAN_MAX_BYTES];
    uint32 next_index;
} ckpt_clean_ctx_t;

typedef struct st_ckpt_ctx {
    thread_t thread;
    dbwr_context_t dbwr[GS_MAX_DBWR_PROCESS];
    spinlock_t lock;

    volatile bool32 ckpt_enabled;
    volatile uint64 trigger_finish_num; // total number of all finished trigger task
    atomic_t full_trigger_active_num; // number of full trigger task in waiting and running
    volatile ckpt_mode_t trigger_task;
    volatile ckpt_mode_t timed_task;
    cm_thread_cond_t ckpt_cond;

    uint32 dbwr_count;
    log_point_t trunc_point_snapshot; // used only for (cascaded) standby node
    log_point_t lrp_point;  // least recovery point
    knl_scn_t lrp_scn;
    uint64 trunc_lsn;
    uint64 consistent_lfn;

    bool32 double_write;
    int32 dw_file;    // double write file handle
    uint32 dw_ckpt_start;  // double write start
    uint32 dw_ckpt_end;    // double write end

    atomic_t prev_io_read;

    ckpt_queue_t queue;
    ckpt_group_t group;
    ckpt_part_group_t ckpt_part_group[GS_MAX_DBWR_PROCESS];
    rcy_sort_item_t rcy_items[GS_CKPT_GROUP_SIZE];
    ckpt_stat_t stat;

    buf_ctrl_t *batch_end;   // end position of current ckpt
    buf_ctrl_t *clean_end;   // end position of current page clean
    bool32 has_compressed;
    ckpt_edp_group_t edp_group;                    // local edp pages found in ckpt
    ckpt_edp_group_t remote_edp_clean_group;       // page owner request other nodes to clean edp pages
    ckpt_clean_edp_group_t remote_edp_group;       // request from other nodes for page owner to flush page
    ckpt_clean_edp_group_t local_edp_clean_group;  // request from other nodes to clean edp pages
    volatile bool8 ckpt_blocked;    // to block the checkpoint temporarily.
    uint8 reserved[3];
} ckpt_context_t;

status_t ckpt_init(knl_session_t *session);
void ckpt_load(knl_session_t *session);
void ckpt_close(knl_session_t *session);
void ckpt_proc(thread_t *thread);
void dbwr_proc(thread_t *thread);
void dbwr_end(knl_session_t *session, dbwr_context_t *dbwr);
status_t dbwr_fdatasync(knl_session_t *session, dbwr_context_t *dbwr);
status_t dbwr_save_page(knl_session_t *session, dbwr_context_t *dbwr, page_head_t *page);
void dbwr_compress_checksum(knl_session_t *session, page_head_t *page);
void ckpt_trigger(knl_session_t *session, bool32 wait, ckpt_mode_t mode);
void ckpt_enque_page(knl_session_t *session);
void ckpt_enque_one_page(knl_session_t *session, buf_ctrl_t *ctrl);
void ckpt_get_trunc_point(knl_session_t *session, log_point_t *point);
void ckpt_set_trunc_point(knl_session_t *session, log_point_t *point);
status_t ckpt_recover_partial_write(knl_session_t *session);
bool32 ckpt_check(knl_session_t *session);
void ckpt_reset_point(knl_session_t *session, log_point_t *point);
page_id_t page_first_group_id(knl_session_t *session, page_id_t page_id);
void ckpt_disable(knl_session_t *session);
void ckpt_enable(knl_session_t *session);
void ckpt_remove_df_page(knl_session_t *session, datafile_t *df, bool32 need_disable);
bool32 ckpt_try_latch_ctrl(knl_session_t *session, buf_ctrl_t *ctrl);
void ckpt_pop_page(knl_session_t *session, ckpt_context_t *ctx, buf_ctrl_t *ctrl);
status_t ckpt_checksum(knl_session_t *session, ckpt_context_t *ctx);
status_t ckpt_encrypt(knl_session_t *session, ckpt_context_t *ctx);
status_t ckpt_recover_partial_write_node(knl_session_t *session, uint32 node_id);

void ckpt_put_to_part_group(knl_session_t *session, ckpt_context_t *ctx, buf_ctrl_t *to_flush_ctrl);

#ifdef __cplusplus
}
#endif

#endif
