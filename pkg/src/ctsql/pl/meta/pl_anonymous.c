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
 * pl_anonymous.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/meta/pl_anonymous.c
 *
 * -------------------------------------------------------------------------
 */

#include "pl_anonymous.h"
#include "srv_instance.h"
#include "dml_parser.h"
#include "pl_memory.h"

void pl_anony_set_sql_info(text_t *sql, pl_anony_sql_info_t *anony_sql_info)
{
    anony_sql_info->sql = sql;
    anony_sql_info->sql_hash = cm_hash_text(sql, INFINITE_HASH_RANGE);
    anony_sql_info->lru_hash = cm_hash_text(sql, PL_ANONY_LRU_SIZE);
    anony_sql_info->find_hash = cm_hash_text(sql, PL_ANONY_BUCKET_SIZE);
}

bool32 pl_get_entity_cache(sql_stmt_t *stmt, pl_anony_sql_info_t *anony_sql_info)
{
    return CT_FALSE;
}

// alloc new page when sql_len > remaining length of current page
status_t pl_memory_need_extend(pl_entity_t *entity, text_t *sql)
{
    memory_context_t *mem_context = entity->memory;
    memory_pool_t *pool = mem_context->pool;
    uint32 align_size = CM_ALIGN8(sql->len);
    if (mem_context->alloc_pos + align_size <= pool->page_size) {
        return CT_SUCCESS;
    }

    while (!mctx_try_extend(mem_context)) {
        if (!pl_recycle()) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

status_t pl_write_anony_desc(sql_stmt_t *stmt, text_t *sql, uint32 hash_val)
{
    knl_session_t *knl_session = KNL_SESSION(stmt);
    pl_entity_t *entity = (pl_entity_t *)stmt->pl_context;
    anonymous_desc_t *anony_desc = &entity->anonymous->desc;
    uint32 remain_size = sql->len;
    uint32 buf_size, copy_size;
    dc_user_t *dc_user = NULL;
    char *piece_str = sql->str;
    char *buf = NULL;

    if (pl_memory_need_extend(entity, sql) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (dc_open_user_by_id(knl_session, knl_session->uid, &dc_user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    anony_desc->uid = dc_user->desc.id;
    anony_desc->schema_id = stmt->session->curr_schema_id;
    anony_desc->sql_hash = hash_val;
    anony_desc->sql_len = sql->len;
    anony_desc->sql.str = NULL;
    anony_desc->sql.len = 0;
    anony_desc->head_page = entity->memory->curr_page_id;

    while (remain_size > 0) {
        while (!mctx_try_alloc_exhausted(entity->memory, remain_size, (void **)&buf, &buf_size)) {
            if (!pl_recycle()) {
                return CT_ERROR;
            }
        }

        copy_size = (buf_size > remain_size) ? remain_size : buf_size;
        if (copy_size != 0) {
            MEMS_RETURN_IFERR(memcpy_sp(buf, (size_t)buf_size, piece_str, (size_t)copy_size));
        }

        if (anony_desc->sql.str == NULL) {
            anony_desc->sql.str = buf;
            anony_desc->sql.len = copy_size;
        }

        piece_str += copy_size;
        remain_size -= copy_size;
    }

    return CT_SUCCESS;
}
