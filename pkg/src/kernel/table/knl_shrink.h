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
 * knl_shrink.h
 *
 *
 * IDENTIFICATION
 * src/kernel/table/knl_shrink.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_SHRINK_H__
#define __KNL_SHRINK_H__

#include "cm_defs.h"
#include "knl_common.h"

#ifdef __cplusplus
extern "C" {
#endif

void heap_shrink_initialize_map_path(knl_session_t *session, knl_handle_t heap_handle, map_path_t *path);
void heap_traversal_map_for_shrink(knl_session_t *session, map_path_t *path, page_id_t *page_id);
void heap_shrink_hwm(knl_session_t *session, knl_handle_t heap_handle, bool32 async_shrink);
void heap_fetch_shrink_hwm(knl_session_t *session, page_id_t cmp_hwm, page_id_t *hwm);
void heap_shrink_mappage(map_page_t *page, uint16 slot);

#ifdef __cplusplus
}
#endif

#endif
