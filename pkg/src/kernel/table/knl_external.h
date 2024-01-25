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
 * knl_external.h
 *
 *
 * IDENTIFICATION
 * src/kernel/table/knl_external.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_EXTERNAL_H__
#define __KNL_EXTERNAL_H__

#include "cm_defs.h"
#include "cm_row.h"
#include "knl_context.h"

#ifdef __cplusplus
extern "C" {
#endif
    

typedef struct st_knl_directory_desc {
    uint32 uid;
    char name[CT_MAX_NAME_LEN];
    char path[CT_MAX_PATH_BUFFER_SIZE];
} knl_directory_desc_t;

status_t external_heap_fetch(knl_handle_t handle, knl_cursor_t *cursor);
status_t db_create_directory(knl_session_t *session, knl_directory_def_t *def);
status_t db_drop_directory(knl_session_t *session, knl_drop_def_t *def);
status_t db_fetch_directory_path(knl_session_t *session, const char *dir_name,
    char *dire_path, uint32 dire_len, bool32 *is_found);

#ifdef __cplusplus
}
#endif

#endif
