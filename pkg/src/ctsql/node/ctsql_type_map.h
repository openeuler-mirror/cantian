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
 * ctsql_type_map.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/node/ctsql_type_map.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CTSQL_TYPE_MAP_H__
#define __CTSQL_TYPE_MAP_H__

#include "var_inc.h"
#include "cm_list.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_sql_typemap_item {
    typmode_t src_type;
    typmode_t dst_type;
} sql_type_item_t;

typedef struct st_sql_user_typemap {
    bool32 is_like;
    char user_buf[CT_NAME_BUFFER_SIZE];
    text_t user;
    list_t type_map_list; // sql_type_item_t
} sql_user_typemap_t;

status_t sql_load_type_map(void);
void sql_try_match_type_map(text_t *curr_user, typmode_t *type);

#ifdef __cplusplus
}
#endif

#endif
