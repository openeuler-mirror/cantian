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
 * knl_buffer.h
 *
 *
 * IDENTIFICATION
 * src/kernel/buffer/knl_buffer.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_BUFFER_H__
#define __KNL_BUFFER_H__

#include "cm_defs.h"
#include "cm_hash.h"
#include "knl_common.h"
#include "knl_interface.h"
#include "knl_log.h"
#include "knl_page.h"
#include "knl_session.h"
#include "knl_buffer_persistent.h"

#ifdef __cplusplus
extern "C" {
#endif

#define ENTER_PAGE_NORMAL         (uint8)0x00  // normal access for single page
#define ENTER_PAGE_RESIDENT       (uint8)0x01  // resident in memory, not in LRU
#define ENTER_PAGE_PINNED         (uint8)0x02  // temp pinned for undo rollback
#define ENTER_PAGE_NO_READ        (uint8)0x04  // don't read from disk,caller will initialize
#define ENTER_PAGE_TRY            (uint8)0x08  // try to read from buffer, don't read from disk
#define ENTER_PAGE_SEQUENTIAL     (uint8)0x10  // for situation like table full scan to descrease impact on buffer
#define ENTER_PAGE_HIGH_AGE       (uint8)0x20  // decrease possibility to be recycled of page
#define ENTER_PAGE_TRY_PREFETCH (uint8)0x40    // try to prefetch for heap noread
#define ENTER_PAGE_FROM_REMOTE (uint8)0x80     // remote access mode

#define RD_ENTER_PAGE_MASK        (~(ENTER_PAGE_PINNED | ENTER_PAGE_NO_READ | ENTER_PAGE_TRY | ENTER_PAGE_RESIDENT))

#define BUF_IS_RESIDENT(ctrl)     ((ctrl)->is_resident)
#define BUF_IN_USE(ctrl)          ((ctrl)->ref_num > 0)
#define BUF_IS_HOT(ctrl)          ((ctrl)->touch_number >= BUF_TCH_AGE)
#define BUF_IN_USE_IS_RECYCLABLE(ctrl) \
    ((ctrl)->is_pinned == 0 && (ctrl)->is_dirty == 0 && (ctrl)->is_remote_dirty == 0 && \
     (ctrl)->is_marked == 0 && (ctrl)->is_edp == 0)
#define BUF_CAN_EXPIRE_PAGE(ctrl) (BUF_IN_USE_IS_RECYCLABLE(ctrl) && !BUF_IN_USE(ctrl))
#define BUF_CAN_EXPIRE_CACHE(ctrl)  (BUF_CAN_EXPIRE_PAGE(ctrl) && !(ctrl)->is_resident)
#define BUF_CAN_EVICT(ctrl)         (BUF_CAN_EXPIRE_CACHE(ctrl) && !BUF_IS_HOT(ctrl))

#define BUF_ON_LIST(ctrl)               ((ctrl)->prev != NULL || (ctrl)->next != NULL)
#define FILE_COMPRESS_START_PAGE        0
#define PAGE_IS_COMPRESS_HEAD(page_id)  ((((page_id).page) - FILE_COMPRESS_START_PAGE) % PAGE_GROUP_COUNT == 0)
#define BUF_IS_COMPRESS(ctrl)     ((ctrl)->compress_group[0] != NULL)

#define BUF_UNPIN(ctrl)        \
    {                          \
        (ctrl)->is_pinned = 0; \
    }
#define BUF_GET_BUCKET(buf, id) (&(buf)->buckets[(id)])

#define BUF_ACCESS_WINDOW    3000000     // us, increase buf_ctrl_t::touch_number if access interval > BUF_ACCESS_WINDOW
#define BUF_TCH_AGE          3           // consider buffer is hot if its touch_number >= BUF_TCH_AGE
#define BUF_LRU_OLD_RATIO    0.6         // the position of LRU old list pointer in the LRU list
#define BUF_MAX_PREFETCH_NUM (uint32)128 // prefetch at most BUF_MAX_PREFETCH_NUM pages
#define BUF_PREFETCH_UNIT    8

#define BUF_LRU_OLD_TOLERANCE 256   // adjust LRU old list pointer if the distance from OLD RATION > BUF_LRU_OLD_TOLERANCE
#define BUF_LRU_OLD_MIN_LEN   65536 // use LRU old list if >= BUF_LRU_OLD_MIN_LEN buffer pages in memory
#define BUF_LRU_STATS_LEN     1024  // full scan LRU list len
#define BUF_POOL_SIZE_THRESHOLD (((uint64)SIZE_M(1024)) * 1) // if total/buf_pool_num < 1G, then use one buffer pool
#define BUCKET_TIMES          3     // the times of buckets against buffer ctrl
#define BUF_IOCBS_MAX_NUM     1024
#define BUF_CTRL_PER_IOCB     128
#define BUF_CURR_OPTIONS(session)   ((session)->page_stack.options[(session)->page_stack.depth - 1])
#define BUF_LRU_SEARCH_THRESHOLD(set, session) ((set)->capacity * (session)->kernel->attr.lru_search_threshold / 100)
#define BUF_AGE_DECREASE_FACTOR 2
#define BUF_BALANCE_RATIO 0.5
#define BUF_NEED_BALANCE(set) ((set)->scan_list.count < (uint32)((set)->main_list.count * BUF_BALANCE_RATIO))
#define BUF_OPTIMIZE_MIN_PAGES 131072   // use scan list only when buffer set size less than 1G

#define PAGE_GROUP_COUNT 8
#define MAX_PCB_VM_COUNT 8192           // CT_MAX_TAB_COMPRESS_BUF_SIZE(1G)  / 128k (vm page size)

extern uint32 g_cks_level;

typedef enum en_buf_add_pos {
    BUF_ADD_HOT = 0,
    BUF_ADD_OLD = 1,
    BUF_ADD_COLD = 2,
} buf_add_pos_t;

typedef enum en_buf_lru_list_type {
    LRU_LIST_MAIN = 0,
    LRU_LIST_SCAN = 1,
    LRU_LIST_WRITE = 2,
    LRU_LIST_TYPE_COUNT,
} buf_lru_list_type_t;

typedef enum en_buf_load_status {
    BUF_NEED_LOAD = 0x00,
    BUF_IS_LOADED = 0x01,
    BUF_LOAD_FAILED = 0x02,
} buf_load_status_t;

typedef struct st_buf_latch {
    volatile uint16 shared_count;
    volatile uint16 stat;
    volatile uint16 sid;   // the first session latched buffer, less than CT_MAX_SESSIONS(8192)
    volatile uint16 xsid;  // the last session exclusively latched buffer, less than CT_MAX_SESSIONS(8192)
} buf_latch_t;

typedef enum en_buf_expire_type {
    BUF_EVICT = 0,
    BUF_EXPIRE_PAGE,
    BUF_EXPIRE_CACHE,
} buf_expire_type_t;

typedef enum st_buf_transfer_status {
    BUF_TRANS_NONE = 0,
    BUF_TRANS_TRY_REMOTE, // means need ask master/coordinator for latest version
    BUF_TRANS_REL_OWNER,  // means curr node is releasing owner
} buf_transfer_status;

struct st_buf_gbp_ctrl;

#ifdef WIN32
typedef struct st_buf_ctrl
#else
typedef struct __attribute__((aligned(128))) st_buf_ctrl
#endif
{
    buf_latch_t latch;  // for page operations
    uint32 bucket_id;   // the cache id of the bucket

    volatile uint8 is_resident;  // resident buffer not in LRU queue
    volatile uint8 is_pinned;    // pinned buffer in LRU queue
    volatile uint8 is_readonly;
    volatile uint8 is_dirty;

    volatile uint8 is_remote_dirty;
    volatile uint8 is_marked;
    volatile uint8 load_status;
    volatile uint8 in_old;
    volatile uint8 list_id;

    volatile uint8 buf_pool_id;
    volatile uint8 in_ckpt;
    volatile uint8 lock_mode;  // used only in DTC, 0: Null, 1: Shared lock, 2: Exclusive lock

    volatile uint8 is_edp;  // used only in DTC, 0: no, 1: yes, this page is old version, can be discard only after
                            // latest version in other instance is cleaned
    volatile bool8 force_request;  // force to request page from remote
    volatile uint8 remote_access;  // remote access statistics
    volatile uint8 transfer_status;   // page transfer status, used only in TDC

    volatile uint16 ref_num;
    volatile uint16 touch_number;   // touch number for LRU

    page_id_t page_id;
    date_t access_time;             // last access time

    log_point_t trunc_point;
    uint64 lastest_lfn;

    volatile uint8 is_fixed;  // true means this control has been fixed according to buf res after recovery
                              // reset to 0 when get page ownership
    uint8 align[7];
    struct st_buf_ctrl *ckpt_prev;
    struct st_buf_ctrl *ckpt_next;
    struct st_buf_ctrl *prev;       // for LRU queue or free control list
    struct st_buf_ctrl *next;       // for LRU queue or free control list
    struct st_buf_ctrl *hash_next;  // next cache id in the same bucket

    page_head_t *page;
    struct st_buf_ctrl *compress_group[PAGE_GROUP_COUNT];
    struct st_buf_gbp_ctrl *gbp_ctrl;
    knl_scn_t edp_scn;   // set when become edp
} buf_ctrl_t;

typedef struct st_buf_gbp_ctrl {
    volatile uint8 is_gbpdirty;      // page need flush to gbp
    volatile uint8 is_from_gbp;      // page is read from gbp
    volatile uint8 gbp_read_version; // curren version of gbp page, if version is expected, it is newest page
    volatile uint8 page_status;      // page status
    log_point_t gbp_lrp_point;       // gbp page lrp point
    log_point_t gbp_trunc_point;     // gbp dirty page trunc point
    buf_ctrl_t *gbp_next;            // next gbp dirty page
    spinlock_t init_lock;
} buf_gbp_ctrl_t;

typedef struct st_buf_bucket {
    spinlock_t lock;
    uint32 count;
    buf_ctrl_t *first;
} buf_bucket_t;

typedef struct st_buf_lru_list {
    buf_ctrl_t *lru_first;
    buf_ctrl_t *lru_last;
    buf_ctrl_t *lru_old;
    spinlock_t lock;
    uint32 count;      // buffer count in LRU queue
    uint32 old_count;  // old buffer in LRU list
    uint8 type;        // lru list type
} buf_lru_list_t;

typedef struct st_buf_set {
    spinlock_t lock;
    char *addr;
    uint64 size;
    cm_thread_cond_t set_cond;
    
    uint32 capacity;    // total page count
    uint32 hwm;         // high water mark
    uint32 bucket_num;  // total bucket count
    uint32 padding;

    buf_bucket_t *buckets;                         // bucket pool
    buf_ctrl_t *ctrls;                             // page control pool
    buf_gbp_ctrl_t *gbp_ctrls;                     // page gbp control pool
    char *page_buf;                                // page buffer
    union {
        buf_lru_list_t list[LRU_LIST_TYPE_COUNT];
        struct {
            buf_lru_list_t main_list;
            buf_lru_list_t scan_list;
            buf_lru_list_t write_list;
        };
    };
} buf_set_t;

typedef struct st_buf_context {
    buf_set_t buf_set[CT_MAX_BUF_POOL_NUM];
    uint32 buf_set_count;
    thread_lock_t buf_mutex;
} buf_context_t;

typedef struct st_buf_iocb {
    cm_iocb_t iocb;           // io control block of os
    struct st_buf_iocb *next; // next buffer iocb
    uint32 large_pool_id;     // large pool page id managed by this iocb
    page_id_t page_id;        // first page id  managed by this iocb
    uint32 page_cnt;          // buffer page count managed by this iocb
    uint32 used;              // buffer iocb is uesed or not
    char *large_buf;          // point to large pool buffer
    knl_session_t *session;   // session of prefetch
    buf_ctrl_t *ctrls[BUF_CTRL_PER_IOCB]; // ctrls allocated for this iocb
}buf_iocb_t;

typedef struct st_knl_aio_iocbs {
    spinlock_t lock;
    uint32 count;
    buf_iocb_t *iocbs;
    buf_iocb_t *first;
    buf_iocb_t *last;
} knl_aio_iocbs_t;

typedef struct st_buf_aio_ctx {
    thread_t thread;                // thread of async prefetch
    cm_io_context_t io_ctx;         // async io context of os, managing all iocbs
    knl_aio_iocbs_t buf_aio_iocbs;  // io control blocks
} buf_aio_ctx_t;

typedef struct st_compress_buf_ctrl {
    volatile bool32 used;
    vm_page_t *vm_page;
} compress_buf_ctrl_t;

typedef struct st_compress_buf_context {
    spinlock_t lock;
    compress_buf_ctrl_t com_bufs[MAX_PCB_VM_COUNT];
    volatile uint32 opt_count;
} pcb_context_t;

typedef struct st_pcb_assist {
    char *ori_buf;
    char *aligned_buf;
    uint32 buf_id;
    bool32 from_vm;
} pcb_assist_t;

typedef struct st_edp_page_info {
    page_id_t page;
    uint64 lsn;
    uint8 action;
} edp_page_info_t;

static const buf_lru_list_t g_init_list_t = {0};

static inline uint32 hash_page(uint32 hash)
{
    /* a hash algorithm */
    uint32 h = hash;
    h ^= (h >> 20) ^ (h >> 12);
    return h ^ (h >> 7) ^ (h >> 4);
}

static inline uint32 buf_page_hash_value(page_id_t page_id)
{
    /* better if file size < 256G, file count < 128 */
    return hash_page((page_id.page & 0x1FFFFFF) | (((uint32)page_id.file & (uint32)0x7F) << 25));
}

static inline uint32 buf_get_pool_id(page_id_t page_id, uint32 buf_pool_num)
{
    return buf_page_hash_value(page_id) % buf_pool_num;
}

static inline buf_ctrl_t *buf_find_from_bucket(buf_bucket_t *bucket, page_id_t page_id)
{
    buf_ctrl_t *ctrl = bucket->first;

    while (ctrl != NULL) {
        if (IS_SAME_PAGID(ctrl->page_id, page_id)) {
            return ctrl;
        }

        ctrl = ctrl->hash_next;
    }

    return NULL;
}

static inline void buf_add_to_bucket(buf_bucket_t *bucket, buf_ctrl_t *ctrl)
{
    ctrl->hash_next = bucket->first;
    bucket->first = ctrl;
    bucket->count++;
}

static inline void buf_remove_from_bucket(buf_bucket_t *bucket, buf_ctrl_t *ctrl)
{
    buf_ctrl_t *item = bucket->first;

    if (item == ctrl) {
        bucket->first = ctrl->hash_next;
    } else {
        while (item->hash_next != ctrl) {
            item = item->hash_next;
        }

        item->hash_next = ctrl->hash_next;
    }

    /* if the count of bucket is zero, the function will not be called */
    bucket->count--;
}

status_t buf_init(knl_session_t *session);
uint32 buf_expire_cache(knl_session_t *session, buf_set_t *set);
void buf_expire_page(knl_session_t *session, page_id_t page_id);
buf_ctrl_t *buf_find_by_pageid(knl_session_t *session, page_id_t page_id);
buf_ctrl_t *buf_alloc_ctrl(knl_session_t *session, page_id_t page_id, latch_mode_t mode, uint32 options);
buf_ctrl_t *buf_try_alloc_ctrl(knl_session_t *session, page_id_t page_id, latch_mode_t mode, uint32 options,
                               buf_add_pos_t add_pos);
buf_ctrl_t *buf_alloc_compress(knl_session_t *session, page_id_t wanted_page, latch_mode_t mode, uint32 options);
buf_ctrl_t *buf_try_alloc_compress(knl_session_t *session, page_id_t wanted_page, latch_mode_t mode, uint32 options,
                                   buf_add_pos_t add_pos);
void buf_lru_add_ctrl(buf_lru_list_t *list, buf_ctrl_t *ctrl, buf_add_pos_t pos);
void buf_stash_marked_page(buf_set_t *set, buf_lru_list_t *list, buf_ctrl_t *ctrl);
void buf_reset_cleaned_pages(buf_set_t *set, buf_lru_list_t *list);
void buf_reset_cleaned_pages_all_bufset(buf_context_t *buf_ctx, buf_lru_list_t *list);
void buf_balance_set_list(buf_set_t *set);
void buf_check_page_version(knl_session_t *session, buf_ctrl_t *ctrl);
bool32 buf_check_resident_page_version(knl_session_t *session, page_id_t page_id);
bool32 buf_check_resident_page_version_with_ctrl(knl_session_t *session, void *buf_ctrl, page_id_t page_id);
void buf_expire_datafile_pages(knl_session_t *session, uint32 file_id);
status_t pcb_get_buf(knl_session_t *session, pcb_assist_t *pcb_assist);
void pcb_release_buf(knl_session_t *session, pcb_assist_t *pcb_assist);
status_t pcb_init_ctx(knl_session_t *session);
status_t buf_invalidate_page(knl_session_t *session, page_id_t page_id);
EXTER_ATTACK status_t buf_invalidate_page_with_version(knl_session_t *session, page_id_t page_id, uint64 req_version);
EXTER_ATTACK status_t buf_invalidate_page_owner(knl_session_t *session, page_id_t page_id, uint64 req_version);
bool32 buf_clean_edp(knl_session_t *session, edp_page_info_t page);
buf_ctrl_t *buf_try_latchx_page(knl_session_t *session, page_id_t page_id, bool32 check_io);
buf_ctrl_t *buf_try_latch_ckpt_page(knl_session_t *session, page_id_t page_id, bool32 *latched);
void buf_unlatch_page(knl_session_t *session, buf_ctrl_t *ctrl);
void buf_dec_ref(knl_session_t *session, buf_ctrl_t *ctrl);
void buf_set_force_request(knl_session_t *session, page_id_t page_id);
buf_bucket_t *buf_find_bucket(knl_session_t *session, page_id_t page_id);

#ifdef __cplusplus
}
#endif

#endif
