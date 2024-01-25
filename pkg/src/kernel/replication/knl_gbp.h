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
 * knl_gbp.h
 *
 *
 * IDENTIFICATION
 * src/kernel/replication/knl_gbp.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __KNL_GBP_H__
#define __KNL_GBP_H__

#include "knl_page.h"
#include "knl_session.h"
#include "knl_gbp_message.h"
#include "knl_log.h"
#include "knl_archive.h"
#include "cs_listener.h"

#ifdef __cplusplus
extern "C"{
#endif

#define GBP_ALY_MAX_FILE            10

#ifdef WIN32
#define GBP_ALY_MAX_BUCKET_PER_FILE 1
#else
#define GBP_ALY_MAX_BUCKET_PER_FILE (uint64)SIZE_K(200)  // total memery 20*5*100K*32=320M, can save 50G tpcc log
#endif

#define GBP_CONNECT_TIMEOUT         5000 // 5s
#define GBP_RECYCLE_TIMEOUT         (uint64)10000000 // 10s
#define GBP_ALY_BUCKET_AVERAGE_NUM  5
#define GBP_ALY_MAX_ITEM            (GBP_ALY_MAX_FILE * GBP_ALY_MAX_BUCKET_PER_FILE * GBP_ALY_BUCKET_AVERAGE_NUM)
#define GBP_ALY_MAX_ITEM_SIZE       (GBP_ALY_MAX_ITEM * sizeof(gbp_analyse_item_t))
#define GBP_ALY_MAX_BUCKET_SIZE     (GBP_ALY_MAX_FILE * GBP_ALY_MAX_BUCKET_PER_FILE * sizeof(gbp_analyse_bucket_t))
#define GBP_ALY_PAGE_COUNT          200000
#define GBP_ALY_PAGE_BUCKET_SIZE    ((GBP_ALY_PAGE_COUNT + 1) * sizeof(gbp_aly_page_t)) // 4.8M

#define GBP_MAX_REQ_BUF_SIZE        (sizeof(gbp_write_req_t))
#define GBP_MAX_RESP_BUF_SIZE       (sizeof(gbp_batch_read_resp_t))
#define GBP_HEARTBEAT_INTERVAL      (2000 * MICROSECS_PER_MILLISEC) // 2s
#define GBP_MAX_READ_WAIT_TIME      10000 // 10s

/* gbp config params */
typedef struct st_gbp_attr {
    spinlock_t addr_lock;
    bool32 server_addr_changed;
    volatile bool32 gbp_off_triggered;
    volatile bool32 use_gbp;
    char lsnr_addr[CM_MAX_IP_LEN];
    uint16 lsnr_port;

    char server_addr[CT_MAX_LSNR_HOST_COUNT][CM_MAX_IP_LEN];
    char server_addr2[CT_MAX_LSNR_HOST_COUNT][CM_MAX_IP_LEN];
    uint32 server_count;
    uint32 server_count2;
    char local_gbp_host[CM_MAX_IP_LEN];
    char trans_type[CT_MAX_NAME_LEN];
    uint64 gbp_buf_size;
    bool32 gbp_for_recovery;
    bool32 gbp_debug_rcy_check;
    uint64 lrpl_res_logsize;
} gbp_attr_t;

typedef struct st_gbp_buf_manager {
    uint32 queue_id;               /* corresponding thread */
    thread_t thread;
    buf_set_t *buf_pool_ctx;       /* pointer to gbp_sga->buf_context_t */
    uint32 buf_pool_count;

    spinlock_t lru_lock;           /* protect following field */
    buf_ctrl_t *lru_first;
    buf_ctrl_t *lru_last;
    uint32 lru_count;              /* buffer count in LRU queue */
    buf_ctrl_t *lru_current;
    bool32 lru_first_read;         /* if first read, reset lru_current to lru_first */

    volatile bool32 gbp_reading;
    volatile bool32 gbp_writing;

    uint64 buf_skip;                /* when failover read, old page skip count */
    uint64 buf_read;                /* when failover read, page read count */
    uint64 buf_write;
    uint64 buf_fresh;

    log_point_t gbp_begin_point;
    log_point_t gbp_trunc_point;
    log_point_t gbp_lrp_point;
    uint64 max_lsn;                 /* max lsn of pages */

    volatile bool32 is_connected;
    uint32 connected_id;
    cs_pipe_t pipe_const;
    cs_pipe_t pipe_temp;

    date_t last_hb_time;
    spinlock_t fisrt_pipe_lock;      /* lock auto heart beat with GBP, let pipe send other request */
} gbp_buf_manager_t;

typedef struct st_gbp_queue {
    spinlock_t lock;
    uint32 id;
    volatile bool32 has_gap;       /* page in queue maybe recycled */
    volatile uint32 count;

    log_point_t trunc_point;

    buf_ctrl_t *first;
    buf_ctrl_t *last;
} gbp_queue_t;

/* gbp context */
typedef struct st_gbp_context {
    knl_session_t *gbp_bg_sessions[CT_GBP_SESSION_COUNT];
    /* buffer manager on gbp */
    gbp_buf_manager_t gbp_buf_manager[CT_GBP_SESSION_COUNT];
    /* page need to send to gbp */
    gbp_queue_t queue[CT_GBP_SESSION_COUNT];
    /* request and response buffer. on primary, it is request buffer. on standby, it is response buffer */
    char *batch_buf[CT_GBP_SESSION_COUNT];
    aligned_buf_t pipe_buf;
    /* gbp agnet on kernel */
    thread_t gbp_agent_thread;

    /* concurrent control for sessions read same page from gbp */
    spinlock_t buf_read_lock[CT_GBP_RD_LOCK_COUNT];

    volatile bool32 log_flushing;
    volatile bool32 gbp_read_completed;     /* gbp page read completed flag */
    volatile uint32 gbp_read_version;       /* the version of reading gbp pages */
    atomic_t gbp_read_thread_num;           /* the number of threads which is reading page from gbp */

    log_point_t gbp_begin_point;            /* gbp read begin point */
    log_point_t gbp_end_point;              /* gbp read begin point */
    date_t gbp_begin_read_time;             /* gbp read begin time */
    date_t gbp_end_read_time;               /* gbp read end time */
    uint64 gbp_window_start;
    uint64 gbp_window_end;
} gbp_context_t;

typedef struct st_gbp_aly_page {
    page_id_t page_id;
    uint64 lsn;         // expect lsn after failover done
    uint64 lfn;         // the lfn of batch contain this page
} gbp_aly_page_t;

typedef struct st_gbp_page_bucket {
    spinlock_t lock;
    thread_t thread;
    uint32 count;
    volatile uint32 head;
    volatile uint32 tail;
    gbp_aly_page_t *first;
} gbp_page_bucket_t;

typedef struct st_gbp_aly_context {
    thread_t thread;
    uint32 sid;

    spinlock_t extend_lock;
    aligned_buf_t read_buf;
    aligned_buf_t log_decrypt_buf;
    aligned_buf_t bucket_buf;
    gbp_page_bucket_t page_bucket;
    volatile bool32 is_started;
    volatile bool32 is_closing;
    volatile bool32 is_done;
    bool32 has_gap;
    bool32 has_return_replay;
    bool32 loading_curr_file;

    log_point_t begin_point;
    log_point_t curr_point;
    date_t begin_time;
    date_t end_time;
    date_t last_recycle_time;

    arch_file_t arch_file;
    int32 log_handle[CT_MAX_LOG_FILES];
} gbp_aly_ctx_t;

typedef enum en_gbp_page_status {
    GBP_PAGE_NONE = 0,              /* init */
    GBP_PAGE_ERROR = 1,             /* gbp page read error(eg. GBP disconnect or GBP down) */
    GBP_PAGE_MISS = 2,              /* no expected page on GBP */
    GBP_PAGE_HIT = 3,               /* GBP page->LSN = expected LSN */
    GBP_PAGE_USABLE = 4,            /* local page->LSN < GBP page->LSN < expected LSN */
    GBP_PAGE_OLD = 5,               /* GBP page->LSN < local page->LSN */
    GBP_PAGE_AHEAD = 6,             /* GBP page->LSN > expected LSN  */
    GBP_PAGE_NOREAD = 7,            /* page is not loaded to buffer and enter by ENTER_PAGE_NO_READ */
} gbp_page_status_e;

/* interface */
status_t gbp_agent_start_client(knl_session_t *session);
void gbp_agent_stop_client(knl_session_t *session);
status_t gbp_agent_start(knl_session_t *session);
void gbp_agent_close(knl_session_t *session);

void gbp_enque_pages(knl_session_t *session);
void gbp_enque_one_page(knl_session_t *session, buf_ctrl_t *ctrl);
void gbp_queue_set_gap(knl_session_t *session, buf_ctrl_t *ctrl);

void gbp_queue_set_trunc_point(knl_session_t *session, log_point_t *point);
log_point_t gbp_queue_get_trunc_point(knl_session_t *session);
uint64 gbp_queue_get_page_count(knl_session_t *session);

void gbp_set_unsafe(knl_session_t *session, log_type_t type);
void gbp_reset_unsafe(knl_session_t *session);
void gbp_unsafe_redo_check(knl_session_t *session);
bool32 gbp_pre_check(knl_session_t *session, log_point_t aly_end_point);
bool32 gbp_replay_in_window(knl_session_t *session, log_point_t curr_point);

void gbp_knl_begin_read(knl_session_t *session, log_point_t *curr_point);
void gbp_knl_end_read(knl_session_t *session);

void gbp_knl_check_end_point(knl_session_t *session);
gbp_page_status_e knl_read_page_from_gbp(knl_session_t *session, buf_ctrl_t *ctrl);
status_t gbp_alloc_bg_session(uint8 queue_index, knl_session_t **session);
void gbp_release_bg_session(knl_session_t *session);

status_t gbp_aly_mem_init(knl_session_t *session);
void gbp_aly_mem_free(knl_session_t *session);

/*
 * Set page's latest lsn for standby node. After analysis all redo, we can know all page's expected latest lsn.
 * Analyse item count is limit, if some page is not in gbp_aly_items, it expected latest lsn can be read from disk.
 *
 * Add item(page/lsn/lfn):
 * 1. if find the same page item, update it;
 * 2. if not find, add a new one page item;
 * 3. if item lfn < rcy point lfn, reuse it. Because this page's all redo has been replayed and been flushed to
 *       disk. So this page's latest lsn can be read from disk, and this item can be reused.
 * 4. if can not add a new page item, this page expected lsn can not be record, we will forbide use gbp when failover.
 */
void gbp_aly_set_page_lsn(knl_session_t *session, page_id_t page_id, uint64 lsn, uint64 lfn);
uint64 gbp_aly_get_page_lsn(knl_session_t *session, page_id_t page_id);
gbp_analyse_item_t *gbp_aly_get_page_item(knl_session_t *session, page_id_t page_id);

/*
 * Verify page lsn which need load from GBP, if gbp_page_lsn is large local page lsn, we can use it
 * 1. item == NULL, this page not in redo between gbp_skip_point and lrpl_end_point, we don't need to refresh
 * 2. item->is_verified == 1, this gbp page has been verifyed, we don't need to refresh second time
 * 3. curr_page_lsn == 0, page is not load from disk (include ENTER_PAGE_NO_READ),
 * 4. gbp_page_lsn == expect_lsn, we can refresh local buffer page as gbp page
 * 5. gbp_page_lsn < expect_lsn && gbp_page_lsn > curr_page_lsn, we can refresh it, then replay to expect_lsn
 * 6. gbp_page_lsn < curr_page_lsn(or disk_page_lsn), gbp page is old, can not refresh local page
 *
 * This fuction is runing only rcy_with_gbp == 1, so there two stage to verify gbp page:
 * A. Before failover done:
 *      in this stage, we skip some redo and only replay a few redo, and redo_curr_lsn will increase. and
 *      must have curr_page_lsn <= expect_lsn && disk_page_lsn <= expect_lsn && disk_page_lsn <= redo_curr_lsn,
 * B. After failover done:
 *      in this stage, lrpl has done, DB is open, but gbp_bg_proc still pull pages. redo_curr_lsn is lrpl end lsn and
 *      not change, so redo_curr_lsn may less than curr_page_lsn. Beacause DB is open, curr_page_lsn may large than
 *      expect_lsn, so if gbp_page_lsn == expect_lsn, we must check if gbp_page_lsn > curr_page_lsn.
 * Notify, if page already freshed as gbp page, then it flush to disk and recycled, and we buf_load_page again,
 * curr_page_lsn is 0, and gbp_page_lsn == expect_lsn, but we can not refresh again, becasue disk_page_lsn is newer.
 * So we only verify each page once, then set is_verified = 1, to ensure that page refreshed as gbp page at most once.
 */
gbp_page_status_e gbp_page_verify(knl_session_t *session, page_id_t page_id, uint64 gbp_page_lsn,
                                  uint64 curr_page_lsn);

uint32 gbp_aly_free_space_percent(knl_session_t *session);
status_t gbp_aly_init(knl_session_t *session);
void gbp_aly_close(knl_session_t *session);
void gbp_aly_unsafe_entry(knl_session_t *session, log_entry_t *log, uint64 lsn);
void gbp_aly_safe_entry(knl_session_t *session, log_entry_t *log, uint64 lsn);
status_t gbp_aly_get_file_end_point(knl_session_t *session, log_point_t *point, uint16 file_id);
bool32 gbp_promote_triggered(knl_handle_t knl_handle);
void gbp_record_promote_time(knl_session_t *session, const char *stage, const char *promote_type);
status_t gbp_knl_query_gbp_point(knl_session_t *session, gbp_read_ckpt_resp_t *response, bool32 check_end_point);

/** @}**/
#ifdef __cplusplus
}
#endif

#endif
