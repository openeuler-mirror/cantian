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
 * knl_space_manage.h
 *
 *
 * IDENTIFICATION
 * src/kernel/tablespace/knl_space_manage.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_SPACE_MANAGE_H__
#define __KNL_SPACE_MANAGE_H__

#include "knl_space_base.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t spc_alloc_extent(knl_session_t *session, space_t *space, uint32 extent_size, page_id_t *extent,
    bool32 is_compress);
bool32 spc_alloc_undo_extent(knl_session_t *session, space_t *space, page_id_t *extent, uint32 *extent_size);
void spc_free_extent(knl_session_t *session, space_t *space, page_id_t extent);
void spc_free_undo_extents(knl_session_t *session, space_t *space, undo_page_list_t *extents);
void spc_free_extents(knl_session_t *session, space_t *space, page_list_t *extents);
status_t spc_try_alloc_extent(knl_session_t *session, space_t *space, page_id_t *extent,
    uint32 *extent_size, bool32 *is_degrade, bool32 is_compress);

void spc_alloc_datafile_hwm_extent(knl_session_t *session, space_t *space, uint32 id, page_id_t *extent,
    uint32 extent_size);
status_t spc_df_alloc_extent(knl_session_t *session, space_t *space, uint32 extent_size, page_id_t *extent,
    datafile_t *df);

void spc_create_segment(knl_session_t *session, space_t *space);
void spc_drop_segment(knl_session_t *session, space_t *space);
status_t spc_free_extent_from_list(knl_session_t *session, space_t *space, const char *oper);

status_t spc_rebuild_space(knl_session_t *session, space_t *space);
void spc_wait_data_buffer(knl_session_t *session, space_t *space);
void spc_reset_space(knl_session_t *session, space_t *space);
status_t spc_remove_space(knl_session_t *session, space_t *space, uint32 options, bool32 ignore_error);
status_t spc_remove_space_online(knl_session_t *session, space_t *space, uint32 options);
status_t spc_active_undo_encrypt(knl_session_t *session, uint32 space_id);
status_t spc_active_swap_encrypt(knl_session_t *session);
uint32 spc_get_encrypt_space_count(knl_session_t *session);
status_t spc_try_inactive_swap_encrypt(knl_session_t *session);
void spc_init_swap_space(knl_session_t *session, space_t *space);
void spc_set_datafile_autoextend(knl_session_t *session, datafile_t *df, knl_autoextend_def_t *def);
status_t space_get_dev_type(knl_session_t *session, text_t *spc_name, device_type_t *type);

#ifdef __cplusplus
}
#endif

#endif

