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
 * ctsql_btree.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_btree.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_BTREE_H__
#define __SQL_BTREE_H__
#include "cm_memory.h"

typedef status_t (*cmp_func_t)(int32 *result, void *callback_ctx, char *lbuf, uint32 lsize, char *rbuf, uint32 rsize);
typedef status_t (*oper_func_t)(void *callback_ctx, const char *new_buf, uint32 new_size, const char *old_buf,
    uint32 old_size, bool32 found);

typedef struct st_sql_btree_row {
    uint32 size; // exclude sizeof(sql_btree_row)
    uint32 key_size;
    char data[0];
} sql_btree_row_t;

typedef struct st_sql_btree_segment {
    void *callback_ctx;
    handle_t sess;
    vm_pool_t *pool;
    uint32 pages_hold; // means not closed
    uint32 root_node_vmid;
    uint32 first_data_vmid;
    cmp_func_t cmp;
    oper_func_t insert_oper;
    id_list_t vm_list;
} sql_btree_segment_t;

typedef struct st_sql_btree_cursor {
    vm_page_t *cur_page;
    sql_btree_row_t *btree_row;
    uint32 cur_rows;
} sql_btree_cursor_t;

typedef struct st_sql_btree_page_head {
    bool32 is_leaf;
    uint32 free_begin;
    uint32 row_count;
    uint32 last_vmid;
    uint32 next_vmid;
} sql_btree_page_head_t;

// leaf node
typedef struct st_sql_btree_page_leaf_slot {
    uint32 offset; // must be first member
} sql_btree_page_leaf_slot_t;

// Non-leaf node
typedef struct st_sql_btree_page_slot {
    uint32 offset; // must be first member
    uint32 child_node_vmid;
} sql_btree_page_slot_t;

status_t sql_btree_init(sql_btree_segment_t *segment, handle_t sess, vm_pool_t *pool, void *callback_ctx,
                        cmp_func_t cmp, oper_func_t insert_oper);
void sql_btree_deinit(sql_btree_segment_t *segment);
status_t sql_btree_insert(sql_btree_segment_t *seg, char *buf, uint32 size, uint32 key_size);
status_t sql_btree_open(sql_btree_segment_t *segment, sql_btree_cursor_t *cursor);
status_t sql_btree_fetch(sql_btree_segment_t *segment, sql_btree_cursor_t *cursor, bool32 *eof);
#endif
