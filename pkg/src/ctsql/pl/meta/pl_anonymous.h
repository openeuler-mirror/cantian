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
 * pl_anonymous.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/meta/pl_anonymous.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __PL_ANONYMOUS_H__
#define __PL_ANONYMOUS_H__

#include "ast.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_anonymous_desc_t anonymous_desc_t;
typedef struct st_anonymous anonymous_t;
typedef struct st_pl_anony_sql_info pl_anony_sql_info_t;

struct st_anonymous_desc_t {
    uint32 uid;       // current uid, just for dv_pl_entity
    uint32 schema_id; // current schema id ,not current user id
    uint32 sql_hash;
    uint32 head_page; // first page of sql text
    uint32 sql_len;
    bool32 is_direct_route;
    text_t sql; // first page sql
};

struct st_anonymous {
    pl_line_begin_t *body;
    anonymous_desc_t desc;
};

struct st_pl_anony_sql_info {
    text_t *sql;
    uint32 sql_hash;
    uint32 lru_hash;
    uint32 find_hash;
};

void pl_anony_set_sql_info(text_t *sql, pl_anony_sql_info_t *anony_sql_info);
bool32 pl_get_entity_cache(sql_stmt_t *stmt, pl_anony_sql_info_t *anony_sql_info);
status_t pl_write_anony_desc(sql_stmt_t *stmt, text_t *sql, uint32 hash_val);
status_t pl_cache_anony_entity(sql_stmt_t *stmt, pl_anony_sql_info_t *sql_info);

#ifdef __cplusplus
}
#endif

#endif