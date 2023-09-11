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
 * knl_ashrink.h
 *
 *
 * IDENTIFICATION
 * src/kernel/daemon/knl_ashrink.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __KNL_ASHRINK_H__
#define __KNL_ASHRINK_H__

#include "cm_defs.h"
#include "cm_thread.h"
#include "knl_session.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_ashrink_item {
    uint32 uid;
    uint32 oid;
    date_t begin_time;
    knl_scn_t shrinkable_scn;
    uint32 prev;
    uint32 next;
} ashrink_item_t;

typedef struct st_ashrink_ctx {
    spinlock_t lock;
    bool32 working;
    thread_t thread;
    id_list_t free_list;
    id_list_t ashrink_list;
    uint32 large_pool_id;
    uint32 hwm;
    uint32 capacity;
    ashrink_item_t *array;
} ashrink_ctx_t;

#define ASHRINK_TABLE(table)      ((table) != NULL && (table)->ashrink_stat != ASHRINK_END)
#define ASHRINK_HEAP(table, heap) ((table) != NULL && (table)->ashrink_stat != ASHRINK_END && \
                                   (heap) != NULL && (heap)->ashrink_stat != ASHRINK_END)

status_t ashrink_init(knl_session_t *session);
void ashrink_proc(thread_t *thread);
void ashrink_close(knl_session_t *session);
status_t ashrink_add(knl_session_t *session, knl_dictionary_t *dc, knl_scn_t shrinkable_scn);
void ashrink_clean(knl_session_t *session);

#ifdef __cplusplus
}
#endif

#endif
