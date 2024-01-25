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
 * ctsql_unpivot.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_unpivot.c
 *
 * -------------------------------------------------------------------------
 */

#include "ctsql_unpivot.h"
#include "ctsql_select.h"
#include "ctsql_mtrl.h"

static status_t sql_alloc_unpivot_ctx(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    CT_RETURN_IFERR(vmc_alloc(&cursor->vmc, sizeof(unpivot_ctx_t), (void **)&cursor->unpivot_ctx));
    cursor->unpivot_ctx->row_buf_len = 0;
    return vmc_alloc(&cursor->vmc, CT_MAX_ROW_SIZE, (void **)&cursor->unpivot_ctx->row_buf);
}

status_t sql_execute_unpivot(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    CT_RETURN_IFERR(sql_execute_query_plan(stmt, cursor, plan->unpivot_p.next));
    cursor->exec_data.unpivot_row = 0;
    return sql_alloc_unpivot_ctx(stmt, cursor);
}

static inline status_t unpivot_group_fetch_func(sql_cursor_t *cursor, const char *old_buf, uint32 old_size)
{
    MEMS_RETURN_IFERR(memcpy_sp(cursor->unpivot_ctx->row_buf, CT_MAX_ROW_SIZE, old_buf, old_size));
    cursor->unpivot_ctx->row_buf_len = old_size;
    mtrl_cursor_t *mtrl_cur = &cursor->mtrl.cursor;
    mtrl_cur->eof = CT_FALSE;
    mtrl_cur->type = MTRL_CURSOR_HASH_GROUP;
    mtrl_cur->row.data = cursor->unpivot_ctx->row_buf;
    cm_decode_row(mtrl_cur->row.data, mtrl_cur->row.offsets, mtrl_cur->row.lens, NULL);

    return CT_SUCCESS;
}

static status_t sql_make_unpivot_row(sql_stmt_t *stmt, unpivot_plan_t *unpivot_plan, uint32 group_id, char *buf,
    uint32 *size, bool32 *nulls)
{
    galist_t *group_exprs = (galist_t *)cm_galist_get(unpivot_plan->group_sets, group_id);
    variant_t value;
    row_assist_t row_ass;
    expr_tree_t *expr = NULL;
    uint32 alias_count = unpivot_plan->alias_rs_count;

    *nulls = CT_TRUE;
    row_init(&row_ass, buf, CT_MAX_ROW_SIZE, group_exprs->count);
    for (uint32 i = 0; i < group_exprs->count; i++) {
        expr = (expr_tree_t *)cm_galist_get(group_exprs, i);
        CT_RETURN_IFERR(sql_exec_expr(stmt, expr, &value));
        if (i >= alias_count && !value.is_null) {
            *nulls = CT_FALSE;
        }
        CT_RETURN_IFERR(sql_put_row_value(stmt, NULL, &row_ass, expr->root->datatype, &value));
    }
    *size = (uint32)row_ass.head->size;

    return CT_SUCCESS;
}

status_t sql_fetch_unpivot(sql_stmt_t *stmt, sql_cursor_t *cur, plan_node_t *plan, bool32 *eof)
{
    uint32 *unpivot_row = &cur->exec_data.unpivot_row;
    char *buffer = NULL;
    uint32 size;
    bool32 nulls = CT_TRUE;
    bool32 include_nulls = plan->unpivot_p.include_nulls;

    CTSQL_SAVE_STACK(stmt);
    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buffer));
    for (;;) {
        if (*unpivot_row == 0) {
            CT_RETURN_IFERR(sql_fetch_cursor(stmt, cur, plan->unpivot_p.next, &cur->eof));

            if (*eof) {
                break;
            }
            *eof = cur->eof;
        }

        CT_RETURN_IFERR(sql_make_unpivot_row(stmt, &plan->unpivot_p, *unpivot_row, buffer, &size, &nulls));
        (*unpivot_row)++;
        *unpivot_row = (*unpivot_row) == plan->unpivot_p.rows ? 0 : (*unpivot_row);
        if (!nulls || include_nulls) {
            CT_RETURN_IFERR(unpivot_group_fetch_func(cur, buffer, size));
            break;
        }
    }

    CTSQL_RESTORE_STACK(stmt);
    return CT_SUCCESS;
}
