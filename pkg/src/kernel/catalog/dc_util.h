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
 * dc_util.h
 *
 *
 * IDENTIFICATION
 * src/kernel/catalog/dc_util.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_DC_UTIL_H__
#define __KNL_DC_UTIL_H__

#include "knl_dc.h"

#ifdef __cplusplus
extern "C" {
#endif

void dc_lru_add(dc_lru_queue_t *queue, dc_entity_t *entity);
void dc_list_add(dc_list_t *list, dc_list_node_t *node);
void *dc_list_remove(dc_list_t *list);
void dc_lru_remove(dc_lru_queue_t *queue, dc_entity_t *entity);
status_t dc_init_lru(dc_context_t *ctx);
status_t dc_alloc_synonym_link(knl_session_t *session, dc_entry_t *entry);
bool32 dc_locked_by_self(knl_session_t *session, dc_entry_t *entry);
bool32 dc_try_recycle(dc_context_t *ctx, dc_lru_queue_t *queue, dc_entity_t *entity);
void dc_lru_shift(dc_lru_queue_t *dc_lru, dc_entity_t *entity);
bool32 dc_try_reuse_entry(dc_user_t *user, dc_entry_t **entry);
void dc_try_remove_entry(dc_user_t *user, dc_entry_t *entry);

#ifdef __cplusplus
}
#endif

#endif