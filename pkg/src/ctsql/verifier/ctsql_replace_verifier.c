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
 * ctsql_replace_verifier.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/verifier/ctsql_replace_verifier.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_replace_verifier.h"
#include "ctsql_insert_verifier.h"
#include "base_compiler.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t sql_verify_replace_into_values(sql_verifier_t *verif, sql_replace_t *replace_ctx)
{
    column_value_pair_t *pair = NULL;
    sql_insert_t *insert_ctx = &replace_ctx->insert_ctx;
    verif->excl_flags = SQL_EXCL_AGGR | SQL_EXCL_STAR | SQL_EXCL_ROWNUM | SQL_EXCL_ROWID | SQL_EXCL_ROWSCN |
        SQL_EXCL_WIN_SORT | SQL_EXCL_GROUPING;

    for (uint32 i = 0; i < insert_ctx->pairs->count; i++) {
        pair = (column_value_pair_t *)cm_galist_get(insert_ctx->pairs, i);
        if (sql_static_check_dml_pair(verif, pair) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_verify_partkeys_if_part_table(sql_verifier_t *verif, sql_insert_t *insert_ctx, knl_dictionary_t *dc,
    uint32 col_count)
{
    uint16 col_id, partkeys;

    if (knl_is_part_table(dc->handle)) {
        CT_RETURN_IFERR(sql_alloc_mem(verif->context, sizeof(uint16) * col_count, (void **)&insert_ctx->part_key_map));
        MEMS_RETURN_IFERR(memset_s(insert_ctx->part_key_map, sizeof(uint16) * col_count, (int)CT_INVALID_ID16,
            sizeof(uint16) * col_count));
        partkeys = knl_part_key_count(dc->handle);
        for (uint16 i = 0; i < partkeys; i++) {
            col_id = knl_part_key_column_id(dc->handle, i);
            insert_ctx->part_key_map[col_id] = i;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_verify_replace_context(sql_verifier_t *verif, sql_replace_t *replace_ctx)
{
    uint32 col_count;
    knl_dictionary_t *dc = NULL;
    knl_column_t *column = NULL;
    sql_insert_t *insert_ctx = &replace_ctx->insert_ctx;

    CT_RETURN_IFERR(sql_verify_insert_tabs(verif->stmt, insert_ctx));
    dc = &insert_ctx->table->entry->dc;
    col_count = knl_get_column_count(dc->handle);
    if (col_count == 0) {
        CT_THROW_ERROR(ERR_INVALID_DC, T2S(&insert_ctx->table->name));
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_alloc_mem(verif->context, sizeof(uint32) * col_count, (void **)&insert_ctx->col_map));

    MEMS_RETURN_IFERR(
        memset_s(insert_ctx->col_map, sizeof(uint32) * col_count, (int)CT_INVALID_ID32, sizeof(uint32) * col_count));
    if (!(insert_ctx->flags & INSERT_COLS_SPECIFIED)) {
        CT_RETURN_IFERR(sql_extract_insert_columns(verif, insert_ctx));
    } else {
        CT_RETURN_IFERR(sql_verify_insert_columns(verif, insert_ctx));

        for (uint32 i = 0; i < col_count; ++i) {
            column = knl_get_column(dc->handle, i);
            if (KNL_COLUMN_INVISIBLE(column)) {
                continue;
            }
            if (column->default_text.len != 0) {
                CT_RETURN_IFERR(sql_add_sequence_node(verif->stmt, ((expr_tree_t *)column->default_expr)->root));
            }
        }
    }

    CT_RETURN_IFERR(sql_verify_partkeys_if_part_table(verif, insert_ctx, dc, col_count));

    if (insert_ctx->select_ctx) {
        CT_RETURN_IFERR(sql_verify_select_context(verif, insert_ctx->select_ctx));
        if (verif->has_ddm_col == CT_TRUE) {
            CT_THROW_ERROR(ERR_INVALID_OPERATION, ", the command references a redacted object");
            return CT_ERROR;
        }
        if (insert_ctx->select_ctx->first_query->rs_columns->count != insert_ctx->pairs->count) {
            CT_THROW_ERROR((insert_ctx->select_ctx->first_query->rs_columns->count > insert_ctx->pairs->count) ?
                ERR_TOO_MANY_VALUES :
                ERR_NOT_ENOUGH_VALUES);
            return CT_ERROR;
        }
    } else {
        CT_RETURN_IFERR(sql_verify_replace_into_values(verif, replace_ctx));
    }

    return CT_SUCCESS;
}

status_t sql_verify_replace_into(sql_stmt_t *stmt, sql_replace_t *replace_ctx)
{
    sql_verifier_t verif = { 0 };

    verif.stmt = stmt;
    verif.table = replace_ctx->insert_ctx.table;
    verif.context = stmt->context;
    verif.pl_dc_lst = replace_ctx->insert_ctx.pl_dc_lst;
    verif.do_expr_optmz = CT_TRUE;
    plc_get_verify_obj(stmt, &verif);
    return sql_verify_replace_context(&verif, replace_ctx);
}

#ifdef __cplusplus
}
#endif
