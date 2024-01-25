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
 * pl_memory.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/persist/pl_memory.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_MEMORY_H__
#define __PL_MEMORY_H__

#include "pl_dc_util.h"

#ifdef __cplusplus
extern "C" {
#endif
status_t pl_alloc_mem_in_mngr(uint32 size, void **buffer);
status_t pl_alloc_mem(void *entity_in, uint32 size, void **buffer);
status_t pl_alloc_entry(pl_entry_t **entry_out);
status_t pl_alloc_context(pl_entity_t **pl_ctx, sql_context_t *context);
status_t pl_alloc_entity(pl_entry_t *entry, pl_entity_t **entity_out);
void pl_free_entity(pl_entity_t *entity);
bool32 pl_recycle_internal(void);
bool32 pl_recycle(void);
void pl_recycle_all(void);

#ifdef __cplusplus
}
#endif

#endif
