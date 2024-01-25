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
 * knl_common.h
 *
 *
 * IDENTIFICATION
 * src/kernel/common/knl_common.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_COMMON_H__
#define __KNL_COMMON_H__

#include <stdio.h>
#include "knl_common_module.h"
#include "cm_types.h"
#include "cm_log.h"
#include "knl_interface.h"

#ifdef __cplusplus
extern "C" {
#endif
    
typedef enum en_seg_op {
    HEAP_DROP_SEGMENT = 0,
    HEAP_DROP_PART_SEGMENT,
    HEAP_TRUNCATE_SEGMENT,
    HEAP_TRUNCATE_PART_SEGMENT,
    BTREE_DROP_SEGMENT,
    BTREE_DROP_PART_SEGMENT,
    BTREE_TRUNCATE_SEGMENT,
    BTREE_TRUNCATE_PART_SEGMENT,
    LOB_DROP_SEGMENT,
    LOB_DROP_PART_SEGMENT,
    LOB_TRUNCATE_SEGMENT,
    LOB_TRUNCATE_PART_SEGMENT,
    HEAP_PURGE_SEGMENT,
    BTREE_PURGE_SEGMENT,
    LOB_PURGE_SEGMENT,
    BTREE_DELAY_DROP_SEGMENT,
    BTREE_DELAY_DROP_PART_SEGMENT,
    SEG_OP_CNT
} seg_op_t;

typedef struct st_seg_stat {
    uint64 logic_reads;
    uint64 physical_reads;
    uint64 physical_writes;
    uint32 buf_busy_waits;
    uint32 itl_waits;
    uint32 row_lock_waits;
} seg_stat_t;

typedef struct st_idx_chg_stats {
    int64 delete_size;
    int64 insert_size;
    int64 alloc_pages;
    uint64 empty_size;
    uint64 first_empty_size;
    atomic_t ow_del_scn;
} idx_chg_stats_t;

typedef struct st_idx_recycle_stats {
    uint32 total_leafs;
    uint32 normal_leafs;
    uint32 unrecycled_empty_leafs;
    uint32 parent_first_leafs;
    uint32 active_txn_pages;
    uint32 sparse_pages;
    uint32 recycled_pages;
    uint32 force_recycled_pages;
    uint32 free_pages;
    uint32 unexpire_pages;
    uint64 total_sleep_msecs;
    knl_scn_t initerval_scn;
    uint64 xid_val;
    bool32 need_coalesce;
} idx_recycle_stats_t;

typedef enum en_async_shrink_status {
    ASHRINK_END = 0,
    ASHRINK_COMPACT = 1,
    ASHRINK_WAIT_SHRINK = 2,
} ashrink_status_t;

#define MAX_WAIT_TICKS (100000)
/* heap storage entity */
typedef struct st_heap {
    drlock_t lock;
    drlatch_t latch;
    page_id_t entry;
    volatile struct st_heap_segment *segment;
    volatile bool8 extending;
    volatile bool8 compacting;
    volatile uint8 ashrink_stat;
    volatile bool8 loaded;
    volatile uint8 extend_owner;
    uint32 max_pages;
    struct st_table *table;
    seg_stat_t stat;
    uint8 cipher_reserve_size;
    uint32 wait_ticks;
} heap_t;

/* btree storage entity */
typedef struct st_btree {
    drlatch_t struct_latch;
    spinlock_t extend_lock;
    page_id_t entry;
    volatile struct st_btree_segment *segment;
    volatile char *root_copy;
    struct st_index *index;
    atomic_t struct_ver;
    volatile bool8 is_splitting;
    volatile uint8 split_owner;
    bool8 is_shadow;
    bool8 wait_recycle;
    bool8 is_recycling;

    seg_stat_t stat;
    idx_chg_stats_t chg_stats;
    uint8 cipher_reserve_size;
    knl_scn_t min_scn;
    uint32 wait_ticks;
    int64 pre_struct_ver;
    void *buf_ctrl;
} btree_t;

/* lob storage entity */
typedef struct st_lob_entity {
    drlatch_t seg_latch;
    page_id_t entry;
    volatile struct st_lob_segment *segment;
    struct st_lob *lob;
    volatile bool32 shrinking;
    uint8 cipher_reserve_size;
} lob_entity_t;

#ifdef _CANTIAN_LCOV_TEST_
#define knl_panic(condition)                                                                                        \
    do {                                                                                                            \
        if (SECUREC_UNLIKELY(!(condition))) {                                                                       \
            CT_LOG_RUN_ERR("Assertion throws an exception at line %u", (uint32)__LINE__);                           \
            cm_fync_logfile();                                                                                      \
            *((uint32 *)NULL) = 1;                                                                                  \
        }                                                                                                           \
    } while (0);

#define knl_panic_log(condition, format, ...)                                                                      \
    do {                                                                                                           \
        if (SECUREC_UNLIKELY(!(condition))) {                                                                      \
            cm_write_normal_log(LOG_RUN, LEVEL_ERROR, (char *)__FILE__, (uint32)__LINE__, (int)MODULE_ID, CT_TRUE, \
                                format, ##__VA_ARGS__);                                                            \
            cm_fync_logfile();                                                                                     \
            *((uint32 *)NULL) = 1;                                                                                 \
        }                                                                                                          \
    } while (0);

#define knl_securec_check(err)                                            \
    {                                                                     \
        if (SECUREC_UNLIKELY(EOK != (err))) {                             \
            CT_LOG_RUN_ERR("Secure C lib has thrown an error %d", (err)); \
            cm_fync_logfile();                                            \
            *((uint32 *)NULL) = 1;                                        \
        }                                                                 \
    }

/* Used in sprintf_s or scanf_s cluster function */
#define knl_securec_check_ss(err)                                         \
    {                                                                     \
        if (SECUREC_UNLIKELY((err) == -1)) {                              \
            CT_LOG_RUN_ERR("Secure C lib has thrown an error %d", (err)); \
            cm_fync_logfile();                                            \
            *((uint32 *)NULL) = 1;                                        \
        }                                                                 \
    }
#else
#define knl_panic(condition)                                                                                        \
    do {                                                                                                            \
        if (SECUREC_UNLIKELY(!(condition))) {                                                                       \
            if (LOG_RUN_ERR_ON) {                                                                                   \
                CT_LOG_RUN_ERR("Assertion throws an exception at line %u", (uint32)__LINE__);                       \
                cm_fync_logfile();                                                                                  \
            }                                                                                                       \
            *((uint32 *)NULL) = 1;                                                                                  \
        }                                                                                                           \
    } while (0);

#define knl_panic_log(condition, format, ...)                                                                          \
    do {                                                                                                               \
        if (SECUREC_UNLIKELY(!(condition))) {                                                                          \
            if (LOG_RUN_ERR_ON) {                                                                                      \
                cm_write_normal_log(LOG_RUN, LEVEL_ERROR, (char *)__FILE__, (uint32)__LINE__, (int)MODULE_ID, CT_TRUE, \
                                    format, ##__VA_ARGS__);                                                            \
                cm_fync_logfile();                                                                                     \
            }                                                                                                          \
            knl_panic(0);                                                                                              \
        }                                                                                                              \
    } while (0);

#define knl_securec_check(err)                                            \
    {                                                                     \
        if (SECUREC_UNLIKELY(EOK != (err))) {                             \
            CT_LOG_RUN_ERR("Secure C lib has thrown an error %d", (err)); \
            cm_fync_logfile();                                            \
            knl_panic(0);                                                 \
        }                                                                 \
    }

/* Used in sprintf_s or scanf_s cluster function */
#define knl_securec_check_ss(err)                                         \
    {                                                                     \
        if (SECUREC_UNLIKELY((err) == -1)) {                              \
            CT_LOG_RUN_ERR("Secure C lib has thrown an error %d", (err)); \
            cm_fync_logfile();                                            \
            knl_panic(0);                                                 \
        }                                                                 \
    }
#endif

/* memset_sp can not reset memory that size >= 2G, so the second and fourth parameter of memset_sp should < 2G */
static inline void knl_reset_large_memory(char *dest, uint64 size)
{
    uint64 remain_size = size;
    uint64 memset_size;
    errno_t ret;

    while (remain_size > 0) {
        memset_size = (remain_size > SECUREC_MEM_MAX_LEN) ? SECUREC_MEM_MAX_LEN : remain_size;
        ret = memset_sp(dest + (size - remain_size), (size_t)memset_size, 0, (size_t)memset_size);
        knl_securec_check(ret);
        remain_size -= memset_size;
    }
}

/*
 * kernel increase scn
 * We define scn on true time precision see knl_scn_t.
 * If current time is smaller than database init time, inc scn in serial number.
 * If current time is smaller than current kernel scn, inc scn in serial number.
 * If current time is bigger than current kernel scn, set scn as true time.
 * @param database init time, current time pointer, increased based scn pointer
 */
static inline knl_scn_t knl_inc_scn(time_t init_time, timeval_t *p_now, uint64 seq, atomic_t *p_scn, int64 threshold)
{
    knl_scn_t curr_scn;
    timeval_t db_time;

    if (p_now->tv_sec < init_time) {
        return KNL_INC_SCN(p_scn);
    }

    curr_scn = KNL_TIMESEQ_TO_SCN(p_now, init_time, seq);
    if (curr_scn <= KNL_GET_SCN(p_scn)) {
        return KNL_INC_SCN(p_scn);
    }

    if (threshold != 0) {
        KNL_SCN_TO_TIME(*p_scn, &db_time, init_time);
        if ((int64)(p_now->tv_sec - db_time.tv_sec) > threshold) {
            knl_panic_log(0, "[SCN] ABORT INFO: system time has been changed exceed the range allowed");
        }
    }

    KNL_SET_SCN(p_scn, curr_scn);
    return curr_scn;
}

static inline page_id_t knl_get_rowid_page(rowid_t rowid)
{
    page_id_t page_id;
    page_id.file = (uint16)rowid.file;
    page_id.page = (uint32)rowid.page;
    page_id.aligned = 0;
    return page_id;
}

static inline void knl_set_rowid_page(rowid_t *rowid, page_id_t page)
{
    rowid->file = page.file;
    rowid->page = (uint32)page.page;
}

#define GET_ROWID_PAGE knl_get_rowid_page
#define SET_ROWID_PAGE knl_set_rowid_page

/*
 * check cursor SSI conflict
 * If we has detected conflict in current cursor, and we has locked
 * some rows or we are going to lock current row, we should throw
 * a serialize access error.
 * @param kernel cursor, locking
 */
static inline status_t knl_cursor_ssi_conflict(knl_cursor_t *cursor, bool32 is_locking)
{
    if (cursor->isolevel != (uint8)ISOLATION_SERIALIZABLE || cursor->action == CURSOR_ACTION_SELECT ||
        !cursor->ssi_conflict) {
        return CT_SUCCESS;
    }

    if (cursor->is_locked || is_locking) {
        CT_THROW_ERROR(ERR_SERIALIZE_ACCESS);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static const char *g_checksum_level_str[] = { "OFF", "TYPICAL", "FULL" };
static inline const char *knl_checksum_level(uint32 level)
{
    if (level > CKS_FULL) {
        return "INVALID";
    }
    return g_checksum_level_str[level];
}

#ifdef __cplusplus
}
#endif

#endif
