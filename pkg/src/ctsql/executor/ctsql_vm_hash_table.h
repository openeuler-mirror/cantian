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
 * ctsql_vm_hash_table.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_vm_hash_table.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CM_HASH_TABLE_H__
#define __CM_HASH_TABLE_H__
#include "cm_defs.h"
#include "cm_row.h"
#include "cm_hash.h"
#include "cm_memory.h"
#include "cm_pma.h"

typedef uint32 (*hash_func_t)(const char *buf);
typedef status_t (*equal_func_t)(bool32 *equal, void *callback_ctx, const char *lbuf, uint32 lsize, const char *rbuf,
    uint32 rsize);
typedef status_t (*oper_func_t)(void *callback_ctx, const char *new_buf, uint32 new_size, const char *old_buf,
    uint32 old_size, bool32 found);

typedef struct st_page_entry {
    uint32 page_id : 31;
    uint32 pm_flag : 1; // flag indicates page was allocated from PMA
} page_entry_t;

typedef struct st_hash_segment {
    handle_t sess;
    vm_pool_t *pool;
    pm_pool_t *pm_pool;
    uint32 pages_hold; // means not closed
    uint32 last_page_used;
    page_entry_t last_page;
    id_list_t vm_list;
} hash_segment_t;

typedef struct st_hash_entry {
    union {
        uint32 vmid;
        page_entry_t page;
    };
    uint32 offset;
} hash_entry_t;

typedef enum en_hash_scan_mode {
    HASH_FULL_SCAN,
    HASH_KEY_SCAN,
} hash_scan_mode_t;

typedef struct st_hash_scan_assist {
    hash_scan_mode_t scan_mode;
    char *buf;
    uint32 size;
} hash_scan_assist_t;

typedef hash_entry_t hash_table_entry_t;

typedef struct st_hash_node {
    hash_entry_t next;
    uint32 hash_value;
    uint32 size : 24;
    uint32 is_new_key : 1; // mark whether is new key
    uint32 is_deleted : 1; // mark the node is deleted
    uint32 unused : 6;
    char data[0];
} hash_node_t;

typedef struct st_vm_hash_table {
    hash_func_t hash;
    equal_func_t equal;
    oper_func_t i_oper; // insert callback
    oper_func_t q_oper; // query callback
    void *callback_ctx;
    hash_segment_t *seg;
    uint32 bucket_num; // number of bucket - must be 2^K
    uint32 max_bucket; // initial equals to bucket_num - 1
    uint32 low_mask;   // equals to 2^K - 1
    uint32 high_mask;  // equals to 2^(K+1) - 1
    uint32 rnums;      // number of records
    float ffact;       // maximum fill factor
    hash_entry_t self; // table entry in a virtual page
    bool8 has_null_key;
    bool8 is_empty;
    uint8 unused[2];
    uint32 nentries;
    page_entry_t page_entries[0];
} hash_table_t;

#define ITER_FETCH_DEL 0x01  // fetch deleted node
#define ITER_IGNORE_DEL 0x02 // ignore deleted node

typedef struct st_hash_table_iter {
    void *callback_ctx;       // for hash table fetch
    hash_table_t *hash_table; // hash table entry
    hash_entry_t curr_match;  // current matched hash node
    uint32 curr_bucket;       // for full scan, current bucket number
    uint16 scan_mode;
    uint16 flags;
} hash_table_iter_t;

static void inline sql_init_hash_iter(hash_table_iter_t *iter, handle_t ctx)
{
    iter->curr_bucket = 0;
    iter->curr_match.vmid = CT_INVALID_ID32;
    iter->callback_ctx = ctx;
    iter->hash_table = NULL;
    iter->scan_mode = HASH_FULL_SCAN;
    iter->flags = 0;
}

static inline uint32 sql_hash_func(const char *buf)
{
    return cm_hash_func((uint8 *)buf, ((row_head_t *)buf)->size);
}

static inline status_t sql_hash_equal_func(bool32 *equal, void *callback_ctx, const char *lbuf, uint32 lsize,
    const char *rbuf, uint32 rsize)
{
    *equal = cm_row_equal(lbuf, rbuf);
    return CT_SUCCESS;
}
/*
@\brief Initialize the hash segment
@\param sess - session for this segment
@\param pool - temp pool for temporary memory management
@\param seg - handle for this segment
@\param pma - PMA memory area
@\param pages_hold - maximum temporary memory pages hold
@\param max_size - maximum PMA memory this hash table can allocate
*/
void vm_hash_segment_init(handle_t sess, vm_pool_t *pool, hash_segment_t *segment, pma_t *pma, uint32 pages_hold,
                          uint64 max_size);

/* de-initialize the segment and release all memory */
void vm_hash_segment_deinit(hash_segment_t *segment);

/*
Close the memory page specified by the page_entry
1. If the page was allocated from temp pool, this function calls vm_close
2. If the page was allocated from PMA, this function does nothing
*/
void vm_hash_close_page(hash_segment_t *seg, page_entry_t *entry);

/*
Open the memory page specified by the page_entry
1. If the page was allocated from temp pool, this function calls vm_open
2. If the page was allocated from PMA, this function calls pm_open
*/
status_t vm_hash_open_page(hash_segment_t *seg, page_entry_t *entry, char **page_buf);
status_t vm_hash_table_alloc(hash_table_entry_t *table, hash_segment_t *seg, uint32 temp_bucket_num);
status_t vm_hash_table_init(hash_segment_t *seg, hash_table_entry_t *table, oper_func_t i_oper, oper_func_t q_oper,
    void *oper_ctx);
status_t vm_hash_table_set_func(hash_segment_t *seg, hash_table_entry_t *table, hash_func_t hash, equal_func_t equal);

/*
Insert a record to hash table, records has duplicate key are accepted.
In this function:
1.The callback hash function is used to calculate hash bucket.
2.The callback evaluate function is used to judge whether two key is matched.
*/
status_t vm_hash_table_insert(bool32 *found, hash_segment_t *seg, hash_table_entry_t *table, const char *buf,
    uint32 size);

/*
Insert a record to hash table, records has duplicate key are rejected.
In this function:
1.The callback hash function is used to calculate hash bucket.
2.The callback evaluate function is used to judge whether two key is matched.
3.The callback operation function is used to aggregate records, no matter whether record is found, it will be invoked.
*/
status_t vm_hash_table_insert2(bool32 *found, hash_segment_t *seg, hash_table_entry_t *table, const char *buf,
    uint32 size);
status_t vm_hash_table_has_null_key(bool32 *has_null_key, hash_segment_t *seg, hash_table_entry_t *table);
status_t vm_hash_table_empty(bool32 *empty, hash_segment_t *seg, hash_table_entry_t *table);
status_t vm_hash_table_get_rows(uint32 *rnums, hash_segment_t *seg, hash_table_entry_t *table);
status_t vm_hash_table_probe(bool32 *eof, hash_segment_t *seg, hash_table_entry_t *table,
    hash_scan_assist_t *scan_assit);
status_t vm_hash_table_fetch(bool32 *eof, hash_segment_t *seg, hash_table_entry_t *table, hash_table_iter_t *table_iter);
status_t vm_hash_table_open(hash_segment_t *seg, hash_table_entry_t *table, hash_scan_assist_t *scan_assit,
    bool32 *found, hash_table_iter_t *iter);
status_t vm_hash_table_delete(hash_segment_t *seg, hash_table_entry_t *table, hash_table_iter_t *table_iter);

#endif
