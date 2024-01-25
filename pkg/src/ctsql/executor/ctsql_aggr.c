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
 * ctsql_aggr.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_aggr.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_aggr.h"
#include "ctsql_select.h"
#include "ctsql_proj.h"
#include "ctsql_mtrl.h"
#include "ctsql_group.h"
#include "knl_mtrl.h"
#include "ctsql_scan.h"
#include "ctsql_sort.h"

#ifdef Z_SHARDING
#include "srv_instance.h"
#include "shd_group.h"
#endif // Z_SHARDING

static status_t sql_mtrl_aggr_page_alloc(sql_stmt_t *stmt, sql_cursor_t *cursor, uint32 size, void **result);


static inline status_t sql_aggr_alloc(sql_stmt_t *stmt, sql_cursor_t *cursor, uint32 size, char **buffer)
{
    mtrl_context_t *ctx = &stmt->mtrl;
    mtrl_segment_t *segment = ctx->segments[cursor->mtrl.aggr];
    mtrl_page_t *page = (mtrl_page_t *)segment->curr_page->data;

    if (size > CT_MAX_ROW_SIZE) {
        CT_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, size, CT_MAX_ROW_SIZE);
        return CT_ERROR;
    }

    if (page->free_begin + size + sizeof(uint32) > CT_VMEM_PAGE_SIZE - MTRL_DIR_SIZE(page)) {
        if (mtrl_extend_segment(ctx, segment) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (mtrl_open_page(ctx, segment->vm_list.last, &segment->curr_page) != CT_SUCCESS) {
            return CT_ERROR;
        }

        page = (mtrl_page_t *)segment->curr_page->data;
        mtrl_init_page(page, segment->vm_list.last);
    }

    *buffer = (char *)page + page->free_begin;
    page->free_begin += size;

    return CT_SUCCESS;
}

static inline status_t sql_copy_aggr_value_by_string(sql_stmt_t *stmt, sql_cursor_t *cursor, variant_t *value,
    aggr_var_t *result)
{
    if (value->v_text.len == 0) {
        return CT_SUCCESS;
    }

    if (value->v_text.len > CT_MAX_ROW_SIZE) {
        CT_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, value->v_text.len, CT_MAX_ROW_SIZE);
        return CT_ERROR;
    }

    aggr_str_t *aggr_str = GET_AGGR_VAR_STR_EX(result);

    if (value->v_text.len > aggr_str->aggr_bufsize) {
        aggr_str->aggr_bufsize = MAX(aggr_str->aggr_bufsize * AGGR_BUF_SIZE_FACTOR, value->v_text.len);
        CT_RETURN_IFERR(sql_aggr_alloc(stmt, cursor, aggr_str->aggr_bufsize, &result->var.v_text.str));
    }
    MEMS_RETURN_IFERR(memcpy_s(result->var.v_text.str, aggr_str->aggr_bufsize, value->v_text.str, value->v_text.len));
    result->var.v_text.len = value->v_text.len;

    return CT_SUCCESS;
}

static inline status_t sql_copy_aggr_value_by_binary(sql_stmt_t *stmt, sql_cursor_t *cursor, variant_t *value,
    aggr_var_t *result)
{
    if (value->v_bin.size == 0) {
        return CT_SUCCESS;
    }

    if (value->v_bin.size > CT_MAX_ROW_SIZE) {
        CT_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, value->v_bin.size, CT_MAX_ROW_SIZE);
        return CT_ERROR;
    }

    aggr_str_t *aggr_str = GET_AGGR_VAR_STR_EX(result);

    if (aggr_str == NULL) {
        CT_THROW_ERROR(ERR_ASSERT_ERROR, "aggr_str != NULL");
        return CT_ERROR;
    }

    if (value->v_bin.size > aggr_str->aggr_bufsize) {
        aggr_str->aggr_bufsize = MAX(aggr_str->aggr_bufsize * AGGR_BUF_SIZE_FACTOR, value->v_bin.size);
        CT_RETURN_IFERR(sql_aggr_alloc(stmt, cursor, aggr_str->aggr_bufsize, (char **)&result->var.v_bin.bytes));
    }
    MEMS_RETURN_IFERR(memcpy_s(result->var.v_bin.bytes, aggr_str->aggr_bufsize, value->v_bin.bytes, value->v_bin.size));
    result->var.v_bin.size = value->v_bin.size;

    return CT_SUCCESS;
}

static inline status_t sql_copy_aggr_value(sql_stmt_t *stmt, sql_cursor_t *cursor, variant_t *value, aggr_var_t *result)
{
    switch (result->var.type) {
        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_NUMBER2:
            result->var.ctrl = value->ctrl;
            cm_dec_copy(&result->var.v_dec, &value->v_dec);
            return CT_SUCCESS;
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_BIGINT:
        case CT_TYPE_REAL:
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_TZ:
        case CT_TYPE_TIMESTAMP_LTZ:
        case CT_TYPE_INTERVAL_DS:
        case CT_TYPE_INTERVAL_YM:
        case CT_TYPE_BOOLEAN:
            var_copy(value, &result->var);
            break;

        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
            return sql_copy_aggr_value_by_string(stmt, cursor, value, result);

        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            return sql_copy_aggr_value_by_binary(stmt, cursor, value, result);

        default:
            CT_SET_ERROR_MISMATCH_EX(result->var.type);
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_aggr_get_value_from_vm(sql_stmt_t *stmt, sql_cursor_t *cursor, aggr_var_t *aggr_var,
    bool32 keep_old_open)
{
    aggr_str_t *aggr_str = GET_AGGR_VAR_STR_EX(aggr_var);
    mtrl_rowid_t *rid = &aggr_str->str_result;
    mtrl_segment_t *segment = stmt->mtrl.segments[cursor->mtrl.aggr_str];
    mtrl_page_t *page = (mtrl_page_t *)segment->curr_page->data;

    if (rid->vmid != CT_INVALID_ID32) {
        if (page != NULL && page->id != rid->vmid) {
            if (!keep_old_open) {
                mtrl_close_page(&stmt->mtrl, page->id);
                segment->curr_page = NULL;
            }
            page = NULL;
        }
        if (page == NULL) {
            CT_RETURN_IFERR(mtrl_open_page(&stmt->mtrl, rid->vmid, &segment->curr_page));
            page = (mtrl_page_t *)segment->curr_page->data;
        }
        aggr_var->var.v_text.str = MTRL_GET_ROW(page, rid->slot) + sizeof(row_head_t) + sizeof(uint16);
    }
    return CT_SUCCESS;
}

static status_t sql_aggr_ensure_str_buf(sql_stmt_t *stmt, sql_cursor_t *cursor, aggr_var_t *aggr_var,
    uint32 ensure_size, bool32 keep_value)
{
    char *buf = NULL;
    mtrl_rowid_t rid;
    uint32 rsv_size, row_size;

    if (ensure_size > CT_MAX_ROW_SIZE) {
        CT_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, ensure_size, CT_MAX_ROW_SIZE);
        return CT_ERROR;
    }

    aggr_str_t *aggr_str = GET_AGGR_VAR_STR_EX(aggr_var);

    if (ensure_size <= aggr_str->aggr_bufsize) {
        return CT_SUCCESS;
    }

    if (cursor->mtrl.aggr_str == CT_INVALID_ID32) {
        CT_RETURN_IFERR(mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_EXTRA_DATA, NULL, &cursor->mtrl.aggr_str));
        CT_RETURN_IFERR(mtrl_open_segment(&stmt->mtrl, cursor->mtrl.aggr_str));
    }

    rsv_size = MAX(SQL_GROUP_CONCAT_STR_LEN, aggr_str->aggr_bufsize * AGGR_BUF_SIZE_FACTOR);
    rsv_size = MAX(rsv_size, ensure_size);
    rsv_size = MIN(rsv_size, CT_MAX_ROW_SIZE);

    CT_RETURN_IFERR(sql_push(stmt, (uint32)(CT_MAX_ROW_SIZE + sizeof(row_head_t) + sizeof(uint16)), (void **)&buf));
    row_head_t *head = (row_head_t *)buf;
    head->flags = 0;
    head->itl_id = CT_INVALID_ID8;
    head->column_count = (uint16)1;
    row_size = rsv_size + sizeof(row_head_t) + sizeof(uint16);
    head->size = row_size;

    if (mtrl_insert_row(&stmt->mtrl, cursor->mtrl.aggr_str, buf, &rid) != CT_SUCCESS) {
        CTSQL_POP(stmt);
        return CT_ERROR;
    }
    CTSQL_POP(stmt);

    if (keep_value && !aggr_var->var.is_null && aggr_var->var.v_text.len > 0) {
        // read old value from vm
        uint32 old_vmid = aggr_str->str_result.vmid;
        CT_RETURN_IFERR(sql_aggr_get_value_from_vm(stmt, cursor, aggr_var, CT_FALSE));
        variant_t old_var = aggr_var->var;
        // save new value to vm, keep the old page open
        aggr_str->str_result = rid;
        CT_RETURN_IFERR(sql_aggr_get_value_from_vm(stmt, cursor, aggr_var, CT_TRUE));
        MEMS_RETURN_IFERR(memcpy_s(aggr_var->var.v_text.str, rsv_size, old_var.v_text.str, old_var.v_text.len));
        if (old_vmid != rid.vmid && old_vmid != CT_INVALID_ID32) {
            mtrl_close_page(&stmt->mtrl, old_vmid);
        }
    } else {
        aggr_str->str_result = rid;
    }
    aggr_str->aggr_bufsize = rsv_size;
    return CT_SUCCESS;
}

static status_t sql_aggr_save_aggr_str_value(sql_stmt_t *stmt, sql_cursor_t *cursor, aggr_var_t *aggr_var,
    variant_t *value)
{
    if (value->is_null) {
        return CT_SUCCESS;
    }

    if (value->v_text.len != 0) {
        aggr_str_t *aggr_str = GET_AGGR_VAR_STR_EX(aggr_var);

        CT_RETURN_IFERR(sql_aggr_ensure_str_buf(stmt, cursor, aggr_var, value->v_text.len, CT_FALSE));
        CT_RETURN_IFERR(sql_aggr_get_value_from_vm(stmt, cursor, aggr_var, CT_FALSE));
        MEMS_RETURN_IFERR(
            memcpy_s(aggr_var->var.v_text.str, aggr_str->aggr_bufsize, value->v_text.str, value->v_text.len));
    }

    aggr_var->var.v_text.len = value->v_text.len;
    aggr_var->var.is_null = CT_FALSE;
    return CT_SUCCESS;
}


static inline status_t sql_aggr_none(aggr_assist_t *ctsql_stmt, aggr_var_t *aggr_var, variant_t *value)
{
    CT_THROW_ERROR(ERR_UNKNOWN_ARRG_OPER);
    return CT_ERROR;
}

static inline status_t sql_aggr_count(aggr_assist_t *ctsql_stmt, aggr_var_t *aggr_var, variant_t *value)
{
    VALUE(int64, &aggr_var->var) += VALUE(int64, value);
    return CT_SUCCESS;
}

static inline status_t sql_aggr_cume_dist(aggr_assist_t *ctsql_stmt, aggr_var_t *aggr_var, variant_t *value)
{
    GET_AGGR_VAR_AVG(aggr_var)->ex_avg_count += ctsql_stmt->avg_count;
    if (SECUREC_LIKELY(!aggr_var->var.is_null)) {
        return sql_aggr_sum_value(ctsql_stmt->stmt, &aggr_var->var, value);
    }
    var_copy(value, &aggr_var->var);
    return CT_SUCCESS;
}

static inline status_t sql_aggr_sum(aggr_assist_t *ctsql_stmt, aggr_var_t *aggr_var, variant_t *value)
{
    if (SECUREC_LIKELY(!aggr_var->var.is_null)) {
        return sql_aggr_sum_value(ctsql_stmt->stmt, &aggr_var->var, value);
    }
    if (value->type != aggr_var->var.type) {
        // avg/sum are used for numeric data types, which are non-buffer consuming data types
        // thus directory applying var_convert is more efficient.
        if (aggr_var->var.type != CT_TYPE_UNKNOWN) {
            CT_RETURN_IFERR(var_convert(SESSION_NLS(ctsql_stmt->stmt), value, aggr_var->var.type, NULL));
        }
    }
    var_copy(value, &aggr_var->var);
    return CT_SUCCESS;
}

static inline status_t sql_aggr_avg(aggr_assist_t *ctsql_stmt, aggr_var_t *aggr_var, variant_t *value)
{
    GET_AGGR_VAR_AVG(aggr_var)->ex_avg_count += ctsql_stmt->avg_count;
    return sql_aggr_sum(ctsql_stmt, aggr_var, value);
}

static status_t sql_aggr_min_max(aggr_assist_t *ass, aggr_var_t *var, variant_t *value)
{
    if (value->type != var->var.type) {
        if (var->var.type == CT_TYPE_UNKNOWN) {
            var->var.type = value->type;
            if (CT_IS_VARLEN_TYPE(var->var.type)) {
                aggr_str_t *aggr_str = NULL;
                CT_RETURN_IFERR(sql_mtrl_aggr_page_alloc(ass->stmt, ass->cursor, sizeof(aggr_str_t), (void **)&aggr_str));
                var->extra_offset = (uint32)((char *)aggr_str - (char *)var);
                var->extra_size = sizeof(aggr_str_t);
                aggr_str->aggr_bufsize = 0;
                aggr_str->str_result.vmid = CT_INVALID_ID32;
                aggr_str->str_result.slot = CT_INVALID_ID32;
            }
        } else {
            CT_RETURN_IFERR(sql_convert_variant(ass->stmt, value, var->var.type));
        }
    }
    int32 cmp_result;

    if (var->var.is_null) {
        var->var.is_null = CT_FALSE;
        return sql_copy_aggr_value(ass->stmt, ass->cursor, value, var);
    }

    CT_RETURN_IFERR(sql_compare_variant(ass->stmt, &var->var, value, &cmp_result));

    if ((ass->aggr_type == AGGR_TYPE_MIN && cmp_result > 0) || (ass->aggr_type == AGGR_TYPE_MAX && cmp_result < 0)) {
        return sql_copy_aggr_value(ass->stmt, ass->cursor, value, var);
    }

    return CT_SUCCESS;
}

static status_t sql_aggr_listagg_sort(aggr_assist_t *ctsql_stmt, aggr_var_t *aggr_var, variant_t *value)
{
    status_t status = CT_ERROR;
    char *buf = NULL;
    row_assist_t ra;
    uint32 seg_id = ctsql_stmt->cursor->mtrl.sort_seg;

    if (value->is_null) {
        return CT_SUCCESS;
    }

    CTSQL_SAVE_STACK(ctsql_stmt->stmt);
    sql_keep_stack_variant(ctsql_stmt->stmt, value);
    if (sql_push(ctsql_stmt->stmt, CT_MAX_ROW_SIZE, (void **)&buf) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(ctsql_stmt->stmt);
        return CT_ERROR;
    }
    row_init(&ra, buf, CT_MAX_ROW_SIZE, ctsql_stmt->aggr_node->sort_items->count + 1);

    do {
        // make sort rows
        CT_BREAK_IF_ERROR(sql_hash_group_make_sort_row(ctsql_stmt->stmt, ctsql_stmt->aggr_node, &ra, value));
        aggr_group_concat_t *aggr_group = GET_AGGR_VAR_GROUPCONCAT(aggr_var);

        // the separator is stored in aggr_var->extra
        if (aggr_group->total_len != 0 && !aggr_group->extra.is_null) {
            aggr_group->total_len += aggr_group->extra.v_text.len;
        }
        aggr_group->total_len += value->v_text.len;

        if (aggr_group->total_len > CT_MAX_ROW_SIZE) {
            CT_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, aggr_group->total_len, CT_MAX_ROW_SIZE);
            break;
        }
        status = sql_hash_group_mtrl_insert_row(ctsql_stmt->stmt, seg_id, ctsql_stmt->aggr_node, aggr_var, buf);
        aggr_var->var.is_null = CT_FALSE;
    } while (0);

    CTSQL_RESTORE_STACK(ctsql_stmt->stmt);
    return status;
}

static status_t sql_aggr_listagg(aggr_assist_t *ass, aggr_var_t *aggr_var, variant_t *val)
{
    if (ass->aggr_node->sort_items != NULL) {
        return sql_aggr_listagg_sort(ass, aggr_var, val);
    }
    status_t status = CT_ERROR;
    aggr_group_concat_t *aggr_group = GET_AGGR_VAR_GROUPCONCAT(aggr_var);
    variant_t *sep_var = &aggr_group->extra;
    bool32 has_sep = (bool32)(!sep_var->is_null && sep_var->v_text.len > 0);

    if (val->is_null) {
        return CT_SUCCESS;
    }

    CTSQL_SAVE_STACK(ass->stmt);
    sql_keep_stack_variant(ass->stmt, val);

    do {
        if (aggr_var->var.is_null) {
            status = sql_aggr_save_aggr_str_value(ass->stmt, ass->cursor, aggr_var, val);
            break;
        }
        uint32 len = aggr_var->var.v_text.len + val->v_text.len;
        if (has_sep) {
            len += sep_var->v_text.len;
        }
        CT_BREAK_IF_ERROR(sql_aggr_ensure_str_buf(ass->stmt, ass->cursor, aggr_var, len, CT_TRUE));
        CT_BREAK_IF_ERROR(sql_aggr_get_value_from_vm(ass->stmt, ass->cursor, aggr_var, CT_FALSE));
        char *cur_buffer = aggr_var->var.v_text.str + aggr_var->var.v_text.len;
        uint32 remain_len = len - aggr_var->var.v_text.len;

        if (has_sep) {
            MEMS_RETURN_IFERR(memcpy_sp(cur_buffer, remain_len, sep_var->v_text.str, sep_var->v_text.len));
            cur_buffer += sep_var->v_text.len;
            remain_len -= sep_var->v_text.len;
        }
        if (val->v_text.len != 0) {
            MEMS_RETURN_IFERR(memcpy_sp(cur_buffer, remain_len, val->v_text.str, val->v_text.len));
        }
        status = CT_SUCCESS;
        aggr_var->var.v_text.len = len;
    } while (0);

    CTSQL_RESTORE_STACK(ass->stmt);
    return status;
}

static status_t sql_compare_sort_row_for_rank(sql_stmt_t *ctsql_stmt, expr_node_t *aggr_node, bool32 *flag)
{
    int32 cmp_result = 0;
    variant_t sort_var, constant;
    sort_item_t *sort_item = NULL;
    expr_tree_t *arg = NULL;

    arg = aggr_node->argument;
    CTSQL_SAVE_STACK(ctsql_stmt);
    for (uint32 i = 0; i < aggr_node->sort_items->count; ++i) {
        CTSQL_RESTORE_STACK(ctsql_stmt);
        sort_item = (sort_item_t *)cm_galist_get(aggr_node->sort_items, i);

        CT_RETURN_IFERR(sql_exec_expr(ctsql_stmt, sort_item->expr, &sort_var));
        sql_keep_stack_variant(ctsql_stmt, &sort_var);
        CT_RETURN_IFERR(sql_exec_expr(ctsql_stmt, arg, &constant));
        sql_keep_stack_variant(ctsql_stmt, &constant);
        if (!(CT_IS_NUMERIC_TYPE(sort_var.type))) {
            CT_RETURN_IFERR(sql_convert_variant(ctsql_stmt, &constant, sort_var.type));
            sql_keep_stack_variant(ctsql_stmt, &constant);
        }

        CT_RETURN_IFERR(var_compare(SESSION_NLS(ctsql_stmt), &constant, &sort_var, &cmp_result));

        if (constant.is_null && sort_var.is_null) {
            cmp_result = 0;
        } else if (constant.is_null || sort_var.is_null) {
            if (sort_item->nulls_pos == SORT_NULLS_FIRST || sort_item->nulls_pos == SORT_NULLS_DEFAULT) {
                cmp_result = -cmp_result;
            }
        } else {
            if (sort_item->direction == SORT_MODE_DESC) {
                cmp_result = -cmp_result;
            }
        }

        if (cmp_result < 0) {
            *flag = CT_FALSE;
            return CT_SUCCESS;
        } else if (cmp_result > 0) {
            return CT_SUCCESS;
        } else {
            arg = arg->next;
        }
    }
    *flag = CT_FALSE;
    return CT_SUCCESS;
}

static status_t sql_aggr_make_sort_row(sql_stmt_t *stmt, expr_node_t *aggr_node, row_assist_t *ra)
{
    uint32 i;
    variant_t sort_var;
    sort_item_t *sort_item = NULL;

    for (i = 0; i < aggr_node->sort_items->count; ++i) {
        sort_item = (sort_item_t *)cm_galist_get(aggr_node->sort_items, i);
        CT_RETURN_IFERR(sql_exec_expr(stmt, sort_item->expr, &sort_var));
        CT_RETURN_IFERR(sql_put_row_value(stmt, NULL, ra, sort_var.type, &sort_var));
    }

    return CT_SUCCESS;
}

static status_t sql_aggr_dense_rank(aggr_assist_t *ctsql_stmt, aggr_var_t *aggr_var, variant_t *value)
{
    status_t status = CT_ERROR;
    char *buf = NULL;
    row_assist_t ra;
    bool32 flag = CT_TRUE;
    bool32 row_exist = CT_FALSE;
    aggr_dense_rank_t *aggr_dense_rank = GET_AGGR_VAR_DENSE_RANK(aggr_var);
    if (aggr_var->var.is_null) {
        aggr_var->var.is_null = CT_FALSE;
    }

    CTSQL_SAVE_STACK(ctsql_stmt->stmt);
    if (sql_push(ctsql_stmt->stmt, CT_MAX_ROW_SIZE, (void **)&buf) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(ctsql_stmt->stmt);
        return CT_ERROR;
    }
    row_init(&ra, buf, CT_MAX_ROW_SIZE, ctsql_stmt->aggr_node->sort_items->count);

    do {
        CT_BREAK_IF_ERROR(sql_compare_sort_row_for_rank(ctsql_stmt->stmt, ctsql_stmt->aggr_node, &flag));
        if (flag) {
            // make row for sorting
            CT_BREAK_IF_ERROR(sql_aggr_make_sort_row(ctsql_stmt->stmt, ctsql_stmt->aggr_node, &ra));
            CT_BREAK_IF_ERROR(vm_hash_table_insert2(&row_exist, &aggr_dense_rank->hash_segment,
                &aggr_dense_rank->table_entry, buf, ra.head->size));
        }
        status = CT_SUCCESS;
    } while (0);

    CTSQL_RESTORE_STACK(ctsql_stmt->stmt);
    return status;
}

static status_t sql_aggr_rank(aggr_assist_t *ctsql_stmt, aggr_var_t *aggr_var, variant_t *value)
{
    bool32 flag = CT_TRUE;
    if (aggr_var->var.is_null) {
        aggr_var->var.is_null = CT_FALSE;
    }
    CTSQL_SAVE_STACK(ctsql_stmt->stmt);
    if (sql_compare_sort_row_for_rank(ctsql_stmt->stmt, ctsql_stmt->aggr_node, &flag) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(ctsql_stmt->stmt);
        return CT_ERROR;
    }
    if (flag) {
        VALUE(uint32, &aggr_var->var) += 1;
    }
    CTSQL_RESTORE_STACK(ctsql_stmt->stmt);
    return CT_SUCCESS;
}

static inline status_t sql_aggr_calc_group_concat_sort(sql_stmt_t *stmt, sql_cursor_t *cursor, expr_node_t *aggr_node,
    aggr_var_t *aggr_var)
{
    return sql_hash_group_calc_listagg(stmt, cursor, aggr_node, aggr_var, &cursor->exec_data.sort_concat);
}

static status_t sql_aggr_median(aggr_assist_t *ctsql_stmt, aggr_var_t *aggr_var, variant_t *value)
{
    status_t status = CT_ERROR;
    char *buf = NULL;
    row_assist_t ra;
    uint32 seg_id = ctsql_stmt->cursor->mtrl.sort_seg;
    ct_type_t type = TREE_DATATYPE(ctsql_stmt->aggr_node->argument);

    GET_AGGR_VAR_MEDIAN(aggr_var)->median_count += ctsql_stmt->avg_count;

    if (value->is_null) {
        return CT_SUCCESS;
    }
    if (aggr_var->var.is_null) {
        if (!CT_IS_NUMERIC_TYPE(value->type) && !CT_IS_DATETIME_TYPE(value->type)) {
            CT_THROW_ERROR(ERR_TYPE_MISMATCH, "NUMERIC", get_datatype_name_str(value->type));
            return CT_ERROR;
        }
        var_copy(value, &aggr_var->var);
    }
    if (type == CT_TYPE_UNKNOWN) {
        type = aggr_var->var.type;
    }

    CTSQL_SAVE_STACK(ctsql_stmt->stmt);
    sql_keep_stack_variant(ctsql_stmt->stmt, value);
    if (sql_push(ctsql_stmt->stmt, CT_MAX_ROW_SIZE, (void **)&buf) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(ctsql_stmt->stmt);
        return CT_ERROR;
    }
    row_init(&ra, buf, CT_MAX_ROW_SIZE, 1);

    do {
        // make sort rows
        CT_BREAK_IF_ERROR(sql_put_row_value(ctsql_stmt->stmt, NULL, &ra, type, value));
        status = sql_hash_group_mtrl_insert_row(ctsql_stmt->stmt, seg_id, ctsql_stmt->aggr_node, aggr_var, buf);
    } while (0);

    CTSQL_RESTORE_STACK(ctsql_stmt->stmt);
    return status;
}

static status_t sql_aggr_stddev(aggr_assist_t *ctsql_stmt, aggr_var_t *aggr_var, variant_t *value)
{
    aggr_stddev_t *aggr_stddev = GET_AGGR_VAR_STDDEV(aggr_var);

    // First calculation
    if (aggr_var->var.is_null == CT_TRUE) {
        aggr_var->var.is_null = CT_FALSE;
        aggr_var->var.type = CT_TYPE_NUMBER;
        cm_zero_dec(&aggr_var->var.v_dec);
        aggr_stddev->extra.is_null = CT_FALSE;
        aggr_stddev->extra.type = CT_TYPE_NUMBER;
        cm_zero_dec(&aggr_stddev->extra.v_dec);
    }

    variant_t tmp_square_var;
    tmp_square_var.is_null = CT_FALSE;
    tmp_square_var.type = CT_TYPE_NUMBER;
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_MUL, SESSION_NLS(ctsql_stmt->stmt), value, value,
        &tmp_square_var)); // Xi^2
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_ADD, SESSION_NLS(ctsql_stmt->stmt), &aggr_var->var, &tmp_square_var,
        &aggr_var->var)); // sum(Xi^2)
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_ADD, SESSION_NLS(ctsql_stmt->stmt), &aggr_stddev->extra, value,
        &aggr_stddev->extra)); // sum(Xi)

    aggr_stddev->ex_count++;
    return CT_SUCCESS;
}

static status_t sql_aggr_corr(aggr_assist_t *ctsql_stmt, aggr_var_t *aggr_var, variant_t *values)
{
    sql_stmt_t *stmt = ctsql_stmt->stmt;
    variant_t *value = &values[0];
    variant_t *value_extra = &values[1];
    variant_t tmp_square_var;
    tmp_square_var.is_null = CT_FALSE;
    tmp_square_var.type = CT_TYPE_NUMBER;
    aggr_corr_t *a_corr = GET_AGGR_VAR_CORR(aggr_var);

    if (aggr_var->var.is_null == CT_TRUE) {
        aggr_var->var.is_null = CT_FALSE;
        aggr_var->var.type = CT_TYPE_NUMBER;
        a_corr->extra[CORR_VAR_SUM_X].is_null = CT_FALSE;
        a_corr->extra[CORR_VAR_SUM_Y].is_null = CT_FALSE;
        a_corr->extra[CORR_VAR_SUM_XX].is_null = CT_FALSE;
        a_corr->extra[CORR_VAR_SUM_YY].is_null = CT_FALSE;
        a_corr->extra[CORR_VAR_SUM_X].type = CT_TYPE_NUMBER;  // extra : sum(Xi)
        a_corr->extra[CORR_VAR_SUM_Y].type = CT_TYPE_NUMBER;  // extra_1 : sum(Yi)
        a_corr->extra[CORR_VAR_SUM_XX].type = CT_TYPE_NUMBER; // extra_2 : sum(Xi*Xi)
        a_corr->extra[CORR_VAR_SUM_YY].type = CT_TYPE_NUMBER; // extra_3 : sum(Yi*Yi)
        cm_zero_dec(&aggr_var->var.v_dec);
        cm_zero_dec(&a_corr->extra[CORR_VAR_SUM_X].v_dec);
        cm_zero_dec(&a_corr->extra[CORR_VAR_SUM_Y].v_dec);
        cm_zero_dec(&a_corr->extra[CORR_VAR_SUM_XX].v_dec);
        cm_zero_dec(&a_corr->extra[CORR_VAR_SUM_YY].v_dec);
    }
    if (value->is_null || value_extra->is_null) {
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_MUL, SESSION_NLS(stmt), value, value_extra, &tmp_square_var)); // Xi*Yi
    CT_RETURN_IFERR(
        opr_exec(OPER_TYPE_ADD, SESSION_NLS(stmt), &aggr_var->var, &tmp_square_var, &aggr_var->var)); // sum(Xi*Yi)
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_ADD, SESSION_NLS(stmt), &a_corr->extra[CORR_VAR_SUM_X], value,
        &a_corr->extra[CORR_VAR_SUM_X])); // sum(Xi)
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_ADD, SESSION_NLS(stmt), &a_corr->extra[CORR_VAR_SUM_Y], value_extra,
        &a_corr->extra[CORR_VAR_SUM_Y]));                                                    // sum(Yi)
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_MUL, SESSION_NLS(stmt), value, value, &tmp_square_var)); // Xi*Xi
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_ADD, SESSION_NLS(stmt), &a_corr->extra[CORR_VAR_SUM_XX], &tmp_square_var,
        &a_corr->extra[CORR_VAR_SUM_XX])); // sum(Xi*Xi)
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_MUL, SESSION_NLS(stmt), value_extra, value_extra, &tmp_square_var)); // Yi*Yi
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_ADD, SESSION_NLS(stmt), &a_corr->extra[CORR_VAR_SUM_YY], &tmp_square_var,
        &a_corr->extra[CORR_VAR_SUM_YY])); // sum(Yi*Yi)
    a_corr->ex_count++;
    return CT_SUCCESS;
}

static status_t sql_aggr_covar(aggr_assist_t *ass, aggr_var_t *v_aggr, variant_t *values)
{
    sql_stmt_t *stmt = ass->stmt;
    variant_t *value = &values[0];
    variant_t *value_extra = &values[1];
    variant_t tmp_square_var;
    tmp_square_var.is_null = CT_FALSE;
    tmp_square_var.type = CT_TYPE_NUMBER;
    aggr_covar_t *aggr_covar = GET_AGGR_VAR_COVAR(v_aggr);
    if (value->is_null || value_extra->is_null) {
        return CT_SUCCESS;
    }

    if (v_aggr->var.is_null == CT_TRUE) {
        v_aggr->var.is_null = CT_FALSE;
        v_aggr->var.type = CT_TYPE_NUMBER; // var   : sum(Xi*Yi)
        aggr_covar->extra.is_null = CT_FALSE;
        aggr_covar->extra.type = CT_TYPE_NUMBER; // extra : sum(Xi)
        aggr_covar->extra_1.is_null = CT_FALSE;
        aggr_covar->extra_1.type = CT_TYPE_NUMBER; // extra_1 : sum(Yi)
        cm_zero_dec(&v_aggr->var.v_dec);
        cm_zero_dec(&aggr_covar->extra.v_dec);
        cm_zero_dec(&aggr_covar->extra_1.v_dec);
    }

    CT_RETURN_IFERR(opr_exec(OPER_TYPE_MUL, SESSION_NLS(stmt), value, value_extra,
        &tmp_square_var)); // Xi*Yi
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_ADD, SESSION_NLS(stmt), &v_aggr->var, &tmp_square_var,
        &v_aggr->var)); // sum(Xi*Yi)
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_ADD, SESSION_NLS(stmt), &aggr_covar->extra, value,
        &aggr_covar->extra)); // sum(Xi)
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_ADD, SESSION_NLS(stmt), &aggr_covar->extra_1, value_extra,
        &aggr_covar->extra_1)); // sum(Yi)
    aggr_covar->ex_count++;

    return CT_SUCCESS;
}

static status_t sql_aggr_array_agg(aggr_assist_t *ctsql_stmt, aggr_var_t *aggr_var, variant_t *value)
{
    var_array_t *varray = &aggr_var->var.v_array;
    array_assist_t array_a;

    if (SECUREC_UNLIKELY(varray->type == CT_TYPE_UNKNOWN)) {
        varray->type = value->type;
        if (!cm_datatype_arrayable(value->type)) {
            CT_SRC_THROW_ERROR(ctsql_stmt->aggr_node->argument->root->loc, ERR_INVALID_ARG_TYPE);
            return CT_ERROR;
        }
    }
    CT_RETURN_IFERR(sql_convert_variant(ctsql_stmt->stmt, value, varray->type));

    if (varray->value.type == CT_LOB_FROM_KERNEL) {
        vm_lob_t vlob;
        vlob.node_id = 0;
        vlob.unused = 0;
        CT_RETURN_IFERR(sql_get_array_from_knl_lob(ctsql_stmt->stmt, (knl_handle_t)(varray->value.knl_lob.bytes), &vlob));
        varray->value.vm_lob = vlob;
        varray->value.type = CT_LOB_FROM_VMPOOL;
    }

    varray->count++;
    ARRAY_INIT_ASSIST_INFO(&array_a, ctsql_stmt->stmt);

    CT_RETURN_IFERR(sql_exec_array_element(ctsql_stmt->stmt, &array_a, varray->count, value, CT_TRUE, &varray->value.vm_lob));
    return array_update_head_datatype(&array_a, &varray->value.vm_lob, value->type);
}

static status_t sql_aggr_distinct_value(aggr_assist_t *ass, variant_t *value, bool32 *var_exist)
{
    char *buf = NULL;
    row_assist_t ra;
    hash_segment_t *hash_segment = NULL;
    hash_table_entry_t *hash_table_entry = NULL;
    sql_stmt_t *stmt = ass->stmt;

    CTSQL_SAVE_STACK(stmt);
    sql_keep_stack_variant(stmt, value);
    if (sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buf) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    row_init(&ra, buf, CT_MAX_ROW_SIZE, 1);
    if (sql_put_row_value(stmt, NULL, &ra, value->type, value) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    /* it was asserted that cursor->va_set.aggr_dis.vid not being CT_INVALID_ID32,
       so we won't guard the case that varea_read() returned a NULL
       we'd rather it cored if that really has happened.
     */
    hash_segment = (hash_segment_t *)ass->cursor->exec_data.aggr_dis;
    hash_table_entry = (hash_table_entry_t *)((char *)hash_segment + sizeof(hash_segment_t));
    if (vm_hash_table_insert2(var_exist, hash_segment, &hash_table_entry[ass->aggr_node->dis_info.idx], buf,
        ra.head->size) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    CTSQL_RESTORE_STACK(stmt);

    return CT_SUCCESS;
}


status_t sql_aggr_value(aggr_assist_t *ctsql_stmt, uint32 id, variant_t *value)
{
    aggr_var_t *aggr_var = NULL;
    if (value->is_null && value->type != CT_TYPE_ARRAY && ctsql_stmt->aggr_type != AGGR_TYPE_DENSE_RANK &&
        ctsql_stmt->aggr_type != AGGR_TYPE_RANK) {
        if (ctsql_stmt->aggr_node->nullaware && (ctsql_stmt->aggr_type == AGGR_TYPE_MIN || ctsql_stmt->aggr_type == AGGR_TYPE_MAX)) {
            aggr_var = sql_get_aggr_addr(ctsql_stmt->cursor, id);
            aggr_var->var.is_null = CT_TRUE;
            ctsql_stmt->cursor->eof = CT_TRUE;
        }
        return CT_SUCCESS;
    }

    if (ctsql_stmt->aggr_node->dis_info.need_distinct) {
        bool32 var_exist = CT_FALSE;
        CT_RETURN_IFERR(sql_aggr_distinct_value(ctsql_stmt, value, &var_exist));
        if (var_exist) {
            return CT_SUCCESS;
        }

        if (ctsql_stmt->aggr_type == AGGR_TYPE_COUNT) {
            value->type = CT_TYPE_BIGINT;
            value->v_bigint = 1;
        }
    }
    aggr_var = sql_get_aggr_addr(ctsql_stmt->cursor, id);
    if (ctsql_stmt->aggr_type == AGGR_TYPE_SUM && SECUREC_LIKELY(!aggr_var->var.is_null) && VAR_IS_NUMBERIC_ZERO(value)) {
        return CT_SUCCESS;
    }
    return sql_get_aggr_func(ctsql_stmt->aggr_type)->invoke(ctsql_stmt, aggr_var, value);
}

static inline status_t sql_aggr_calc_none(aggr_assist_t *ctsql_stmt, aggr_var_t *aggr_var)
{
    return CT_SUCCESS;
}

// for avg/avg_collect
static inline status_t sql_aggr_calc_avg(aggr_assist_t *ctsql_stmt, aggr_var_t *aggr_var)
{
    variant_t v_rows;
    v_rows.type = CT_TYPE_BIGINT;
    v_rows.is_null = CT_FALSE;
    v_rows.v_bigint = (int64)GET_AGGR_VAR_AVG(aggr_var)->ex_avg_count;
    return opr_exec(OPER_TYPE_DIV, SESSION_NLS(ctsql_stmt->stmt), &aggr_var->var, &v_rows, &aggr_var->var);
}

static inline status_t sql_aggr_calc_cume_dist(aggr_assist_t *ctsql_stmt, aggr_var_t *aggr_var)
{
    variant_t v_rows;
    v_rows.type = CT_TYPE_BIGINT;
    v_rows.is_null = CT_FALSE;
    // as if this param is been inserted
    v_rows.v_bigint = (int64)GET_AGGR_VAR_AVG(aggr_var)->ex_avg_count + 1;
    CT_RETURN_IFERR(var_as_bigint(&aggr_var->var));
    aggr_var->var.v_bigint += 1;
    return opr_exec(OPER_TYPE_DIV, SESSION_NLS(ctsql_stmt->stmt), &aggr_var->var, &v_rows, &aggr_var->var);
}

static inline status_t sql_aggr_calc_dense_rank(aggr_assist_t *ctsql_stmt, aggr_var_t *aggr_var)
{
    uint32 rnums;
    aggr_dense_rank_t *aggr_dense_rank = GET_AGGR_VAR_DENSE_RANK(aggr_var);
    CT_RETURN_IFERR(vm_hash_table_get_rows(&rnums, &aggr_dense_rank->hash_segment, &aggr_dense_rank->table_entry));
    VALUE(uint32, &aggr_var->var) += rnums;
    return CT_SUCCESS;
}

static inline status_t sql_aggr_calc_listagg(aggr_assist_t *ctsql_stmt, aggr_var_t *aggr_var)
{
    if (ctsql_stmt->aggr_node->sort_items != NULL) {
        return sql_hash_group_calc_listagg(ctsql_stmt->stmt, ctsql_stmt->cursor, ctsql_stmt->aggr_node, aggr_var,
            &ctsql_stmt->cursor->exec_data.sort_concat);
    }
    return CT_SUCCESS;
}

static inline status_t sql_aggr_calc_median(aggr_assist_t *ctsql_stmt, aggr_var_t *aggr_var)
{
    return sql_hash_group_calc_median(ctsql_stmt->stmt, ctsql_stmt->cursor, ctsql_stmt->aggr_node, aggr_var);
}

static status_t sql_aggr_calc_stddev(aggr_assist_t *ctsql_stmt, aggr_var_t *aggr_var)
{
    aggr_stddev_t *aggr_stddev = GET_AGGR_VAR_STDDEV(aggr_var);

    if (aggr_stddev->ex_count == 0) {
        aggr_var->var.is_null = CT_TRUE;
        return CT_SUCCESS;
    }
    if (aggr_stddev->ex_count == 1) {
        switch (ctsql_stmt->aggr_type) {
            case AGGR_TYPE_STDDEV:
            case AGGR_TYPE_STDDEV_POP:
            case AGGR_TYPE_VARIANCE:
            case AGGR_TYPE_VAR_POP:
                aggr_var->var.v_bigint = 0;
                aggr_var->var.type = CT_TYPE_BIGINT;
                break;
            case AGGR_TYPE_STDDEV_SAMP:
            case AGGR_TYPE_VAR_SAMP:
            default:
                aggr_var->var.is_null = CT_TRUE;
                break;
        }
        return CT_SUCCESS;
    }

    variant_t v_rows;   // N
    variant_t v_rows_m; // N-1
    variant_t tmp_result;
    tmp_result.type = CT_TYPE_NUMBER;
    tmp_result.is_null = CT_FALSE;
    v_rows.type = CT_TYPE_BIGINT;
    v_rows.is_null = CT_FALSE;
    v_rows.v_bigint = (int64)aggr_stddev->ex_count;
    v_rows_m.type = CT_TYPE_BIGINT;
    v_rows_m.is_null = CT_FALSE;
    v_rows_m.v_bigint = v_rows.v_bigint - 1;
    /*
     * STDDEV:
     * S = sqrt[ 1/(N-1) * ( sum(Xi^2) - 1/N * sum(Xi)^2 ) ]
     */
    (void)opr_exec(OPER_TYPE_MUL, SESSION_NLS(ctsql_stmt->stmt), &aggr_stddev->extra, &aggr_stddev->extra,
        &aggr_stddev->extra); // sum(Xi)^2
    (void)opr_exec(OPER_TYPE_DIV, SESSION_NLS(ctsql_stmt->stmt), &aggr_stddev->extra, &v_rows,
        &aggr_stddev->extra); // 1/N * sum(Xi)^2
    (void)opr_exec(OPER_TYPE_SUB, SESSION_NLS(ctsql_stmt->stmt), &aggr_var->var, &aggr_stddev->extra,
        &aggr_var->var); // (sum(Xi^2) - 1/N * sum(Xi)^2)
    switch (ctsql_stmt->aggr_type) {
        /* 1/(N-1)  or 1/N */
        case AGGR_TYPE_STDDEV:
        case AGGR_TYPE_STDDEV_SAMP:
        case AGGR_TYPE_VARIANCE:
        case AGGR_TYPE_VAR_SAMP:
            CT_RETURN_IFERR(opr_exec(OPER_TYPE_DIV, SESSION_NLS(ctsql_stmt->stmt), &aggr_var->var, &v_rows_m, &tmp_result));
            break;
        case AGGR_TYPE_STDDEV_POP:
        case AGGR_TYPE_VAR_POP:
            CT_RETURN_IFERR(opr_exec(OPER_TYPE_DIV, SESSION_NLS(ctsql_stmt->stmt), &aggr_var->var, &v_rows, &tmp_result));
            break;
        default:
            break;
    }
    CT_RETURN_IFERR(var_as_decimal(&aggr_var->var));
    CT_RETURN_IFERR(var_as_decimal(&tmp_result));
    if (IS_DEC8_NEG(&tmp_result.v_dec)) {
        aggr_var->var.v_bigint = 0;
        aggr_var->var.type = CT_TYPE_BIGINT;
        return CT_SUCCESS;
    }

    if (ctsql_stmt->aggr_type == AGGR_TYPE_VARIANCE || ctsql_stmt->aggr_type == AGGR_TYPE_VAR_POP ||
        ctsql_stmt->aggr_type == AGGR_TYPE_VAR_SAMP) {
        aggr_var->var.v_dec = tmp_result.v_dec;
        return CT_SUCCESS;
    }

    return cm_dec_sqrt(&tmp_result.v_dec, &aggr_var->var.v_dec);
}

static status_t sql_aggr_calc_corr(aggr_assist_t *ctsql_stmt, aggr_var_t *aggr_var)
{
    sql_stmt_t *stmt = ctsql_stmt->stmt;
    aggr_corr_t *aggr_corr = GET_AGGR_VAR_CORR(aggr_var);

    if (aggr_corr->ex_count == 0 || aggr_corr->ex_count == 1) {
        aggr_var->var.is_null = CT_TRUE;
        return CT_SUCCESS;
    }

    variant_t v_rows;
    variant_t tmp_result;
    tmp_result.type = CT_TYPE_NUMBER;
    tmp_result.is_null = CT_FALSE;
    variant_t tmp_result_1;
    tmp_result_1.type = CT_TYPE_NUMBER;
    tmp_result_1.is_null = CT_FALSE;
    variant_t tmp_result_2;
    tmp_result_2.type = CT_TYPE_NUMBER;
    tmp_result_2.is_null = CT_FALSE;
    v_rows.type = CT_TYPE_BIGINT;
    v_rows.is_null = CT_FALSE;
    v_rows.v_bigint = (int64)aggr_corr->ex_count;

    // COVAR_POP: S = 1/N * ( sum(Xi*Yi) - 1/N * sum(Xi)*sun(Yi) )
    // STDDEV_pop:  S = sqrt[ 1/N * ( sum(Xi^2) - 1/N * sum(Xi)^2 ) ]
    // CORR: S = COVAR_POP(Xi, Yi) / (STDDEV_POP(Xi) * STDDEV_POP(Yi))
    // COVAR_POP(Xi, Yi):
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_MUL, SESSION_NLS(stmt), &aggr_corr->extra[CORR_VAR_SUM_X],
        &aggr_corr->extra[CORR_VAR_SUM_Y], &tmp_result)); // sum(Xi)*sum(Yi)
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_DIV, SESSION_NLS(stmt), &tmp_result, &v_rows,
        &tmp_result)); // 1/N * sum(Xi)*sum(Yi)
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_SUB, SESSION_NLS(stmt), &aggr_var->var, &tmp_result,
        &aggr_var->var)); // (sum(Xi*Yi) - 1/N * sum(Xi)*sum(Yi))
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_DIV, SESSION_NLS(stmt), &aggr_var->var, &v_rows, &tmp_result));

    // STDDEV_pop(Xi):
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_MUL, SESSION_NLS(stmt), &aggr_corr->extra[CORR_VAR_SUM_X],
        &aggr_corr->extra[CORR_VAR_SUM_X], &tmp_result_1)); // sum(Xi)^2
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_DIV, SESSION_NLS(stmt), &tmp_result_1, &v_rows,
        &tmp_result_1)); // 1/N * sum(Xi)^2
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_SUB, SESSION_NLS(stmt), &aggr_corr->extra[CORR_VAR_SUM_XX], &tmp_result_1,
        &aggr_var->var)); // (sum(Xi^2) - 1/N * sum(Xi)^2)
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_DIV, SESSION_NLS(stmt), &aggr_var->var, &v_rows, &aggr_var->var));
    CT_RETURN_IFERR(cm_dec_sqrt(&aggr_var->var.v_dec, &tmp_result_1.v_dec));

    // STDDEV_pop(Yi):
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_MUL, SESSION_NLS(stmt), &aggr_corr->extra[CORR_VAR_SUM_Y],
        &aggr_corr->extra[CORR_VAR_SUM_Y], &tmp_result_2)); // sum(Yi)^2
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_DIV, SESSION_NLS(stmt), &tmp_result_2, &v_rows,
        &tmp_result_2)); // 1/N * sum(Yi)^2
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_SUB, SESSION_NLS(stmt), &aggr_corr->extra[CORR_VAR_SUM_YY], &tmp_result_2,
        &aggr_var->var)); // (sum(Yi^2) - 1/N * sum(Yi)^2)
    CT_RETURN_IFERR(opr_exec(OPER_TYPE_DIV, SESSION_NLS(stmt), &aggr_var->var, &v_rows, &aggr_var->var));
    CT_RETURN_IFERR(cm_dec_sqrt(&aggr_var->var.v_dec, &tmp_result_2.v_dec));

    // the divisor was zero
    if (DECIMAL8_IS_ZERO(&tmp_result_1.v_dec) || DECIMAL8_IS_ZERO(&tmp_result_2.v_dec)) {
        aggr_var->var.is_null = CT_TRUE;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(opr_exec(OPER_TYPE_MUL, SESSION_NLS(stmt), &tmp_result_1, &tmp_result_2,
        &tmp_result_2)); // (STDDEV_POP(Xi) * STDDEV_POP(Yi))

    CT_RETURN_IFERR(opr_exec(OPER_TYPE_DIV, SESSION_NLS(stmt), &tmp_result, &tmp_result_2,
        &tmp_result)); // COVAR_POP(Xi, Yi) / (STDDEV_POP(Xi) * STDDEV_POP(Yi))

    CT_RETURN_IFERR(var_as_decimal(&aggr_var->var));
    CT_RETURN_IFERR(var_as_decimal(&tmp_result));
    aggr_var->var.v_dec = tmp_result.v_dec;

    return CT_SUCCESS;
}

static status_t sql_aggr_calc_covar(aggr_assist_t *ctsql_stmt, aggr_var_t *aggr_var)
{
    sql_stmt_t *stmt = ctsql_stmt->stmt;
    aggr_covar_t *aggr_covar = GET_AGGR_VAR_COVAR(aggr_var);

    if (aggr_covar->ex_count == 0) {
        aggr_var->var.is_null = CT_TRUE;
        return CT_SUCCESS;
    }
    if (aggr_covar->ex_count == 1) {
        switch (ctsql_stmt->aggr_type) {
            case AGGR_TYPE_COVAR_POP:
                aggr_var->var.v_bigint = 0;
                aggr_var->var.type = CT_TYPE_BIGINT;
                return CT_SUCCESS;
            case AGGR_TYPE_COVAR_SAMP:
            default:
                aggr_var->var.is_null = CT_TRUE;
                return CT_SUCCESS;
        }
    }

    variant_t v_rows, v_rows_m, tmp_result; // v_rows : N, v_rows_m : N-1
    tmp_result.type = CT_TYPE_NUMBER;
    tmp_result.is_null = CT_FALSE;
    v_rows.type = CT_TYPE_BIGINT;
    v_rows.is_null = CT_FALSE;
    v_rows.v_bigint = (int64)aggr_covar->ex_count;
    v_rows_m.type = CT_TYPE_BIGINT;
    v_rows_m.is_null = CT_FALSE;
    v_rows_m.v_bigint = v_rows.v_bigint - 1;
    /*
     * COVAR_POP:
     * S = 1/N * ( sum(Xi*Yi) - 1/N * sum(Xi)*sun(Yi) )
     * COVAR_SAMP:
     * S = 1/(N-1) * ( sum(Xi*Yi) - 1/N * sum(Xi)*sun(Yi) )
     */
    (void)opr_exec(OPER_TYPE_MUL, SESSION_NLS(stmt), &aggr_covar->extra, &aggr_covar->extra_1,
        &aggr_covar->extra); // sum(Xi)*sum(Yi)
    (void)opr_exec(OPER_TYPE_DIV, SESSION_NLS(stmt), &aggr_covar->extra, &v_rows,
        &aggr_covar->extra); // 1/N * sum(Xi)*sum(Yi)
    (void)opr_exec(OPER_TYPE_SUB, SESSION_NLS(stmt), &aggr_var->var, &aggr_covar->extra,
        &aggr_var->var); // (sum(Xi*Yi) - 1/N * sum(Xi)*sum(Yi))

    switch (ctsql_stmt->aggr_type) {
        /* 1/(N-1)  or 1/N */
        case AGGR_TYPE_COVAR_SAMP:
            CT_RETURN_IFERR(opr_exec(OPER_TYPE_DIV, SESSION_NLS(stmt), &aggr_var->var, &v_rows_m, &tmp_result));
            break;
        case AGGR_TYPE_COVAR_POP:
            CT_RETURN_IFERR(opr_exec(OPER_TYPE_DIV, SESSION_NLS(stmt), &aggr_var->var, &v_rows, &tmp_result));
            break;
        default:
            break;
    }
    aggr_var->var.v_dec = tmp_result.v_dec;
    return CT_SUCCESS;
}

status_t sql_exec_aggr(sql_stmt_t *stmt, sql_cursor_t *cursor, galist_t *aggrs, plan_node_t *plan)
{
    const sql_func_t *func = NULL;
    aggr_var_t *aggr_var = NULL;
    aggr_assist_t ctsql_stmt;
    SQL_INIT_AGGR_ASSIST(&ctsql_stmt, stmt, cursor);

    /* init the sort concat data buf */
    cursor->exec_data.sort_concat.len = 0;

    for (uint32 i = 0; i < aggrs->count; i++) {
        ctsql_stmt.aggr_node = (expr_node_t *)cm_galist_get(aggrs, i);
        func = GET_AGGR_FUNC(ctsql_stmt.aggr_node);
        /* modified by Z_SHARDING, add AGGR_TYPE_AVG_COLLECT for sharding */
        if (func->aggr_type == AGGR_TYPE_SUM || func->aggr_type == AGGR_TYPE_COUNT ||
            func->aggr_type == AGGR_TYPE_MIN || func->aggr_type == AGGR_TYPE_MAX ||
            func->aggr_type == AGGR_TYPE_ARRAY_AGG || func->aggr_type == AGGR_TYPE_RANK) {
            continue;
        }

        aggr_var = sql_get_aggr_addr(cursor, i);
        if (aggr_var->var.is_null) {
            continue;
        }
        ctsql_stmt.aggr_type = func->aggr_type;
        CT_RETURN_IFERR(sql_aggr_calc_value(&ctsql_stmt, aggr_var));
    }
    return CT_SUCCESS;
}

status_t sql_exec_aggr_extra(sql_stmt_t *stmt, sql_cursor_t *cursor, galist_t *aggrs, plan_node_t *plan)
{
    uint32 i;
    expr_node_t *aggr_node = NULL;
    const sql_func_t *func = NULL;
    aggr_var_t *aggr_var = NULL;
    aggr_dense_rank_t *aggr_dense_rank = NULL;

    for (i = 0; i < aggrs->count; i++) {
        aggr_node = (expr_node_t *)cm_galist_get(aggrs, i);
        func = GET_AGGR_FUNC(aggr_node);
        sql_aggr_type_t func_type = func->aggr_type;
        aggr_var = sql_get_aggr_addr(cursor, i);

        switch (func_type) {
            case AGGR_TYPE_DENSE_RANK:
                aggr_dense_rank = GET_AGGR_VAR_DENSE_RANK(aggr_var);
                vm_hash_segment_deinit(&aggr_dense_rank->hash_segment);
                aggr_dense_rank->table_entry.vmid = CT_INVALID_ID32;
                aggr_dense_rank->table_entry.offset = CT_INVALID_ID32;
            /* fall-through */
            case AGGR_TYPE_RANK:
            case AGGR_TYPE_CUME_DIST:
                aggr_var->var.is_null = CT_FALSE;
                break;
            default:
                break;
        }
    }
    return CT_SUCCESS;
}

status_t sql_aggr_get_cntdis_value(sql_stmt_t *stmt, galist_t *cntdis_columns, expr_node_t *aggr_node, variant_t *value)
{
    expr_node_t *cntdis_column = NULL;
    uint32 group_id = aggr_node->dis_info.group_id;

    if (value->v_bigint == 0 || group_id == CT_INVALID_ID32) {
        value->is_null = CT_TRUE;
        return CT_SUCCESS;
    }

    cntdis_column = (expr_node_t *)cm_galist_get(cntdis_columns, group_id);
    CT_RETURN_IFERR(sql_exec_expr_node(stmt, cntdis_column, value));
    if (!value->is_null && CT_IS_LOB_TYPE(value->type)) {
        CT_SRC_THROW_ERROR(aggr_node->argument->loc, ERR_SQL_SYNTAX_ERROR, "unexpected lob column occurs");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static inline bool32 sql_aggr_is_nullaware(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    expr_node_t *aggr_node = NULL;
    sql_func_t *func = NULL;

    if (plan->aggr.items->count == 1) {
        aggr_node = (expr_node_t *)cm_galist_get(plan->aggr.items, 0);
        func = sql_get_func(&aggr_node->value.v_func);
        if (aggr_node->nullaware && (func->aggr_type == AGGR_TYPE_MIN || func->aggr_type == AGGR_TYPE_MAX)) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

status_t sql_mtrl_aggr(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 par_exe_flag)
{
    uint32 i, avgs, rows;
    variant_t *value = NULL;
    const sql_func_t *func = NULL;
    uint32 aggr_cnt = plan->aggr.items->count;
    aggr_assist_t ctsql_stmt;
    SQL_INIT_AGGR_ASSIST(&ctsql_stmt, stmt, cursor);

    cursor->mtrl.cursor.type = MTRL_CURSOR_OTHERS;
    CT_RETURN_IFERR(sql_init_aggr_page(stmt, cursor, plan->aggr.items));
    CT_RETURN_IFERR(sql_init_aggr_values(stmt, cursor, plan->aggr.next, plan->aggr.items, &avgs));
    CT_RETURN_IFERR(sql_execute_query_plan(stmt, cursor, plan->aggr.next));

    if (cursor->eof) {
        // signed aggr_fetched to make cursor eof, thus, compare ALL will always returns TRUE
        if (sql_aggr_is_nullaware(stmt, cursor, plan)) {
            cursor->mtrl.aggr_fetched = CT_TRUE;
        }
        return CT_SUCCESS;
    }

    /* prepare value and aggr_nodes */
    uint32 alloc_size = sizeof(variant_t) * (FO_VAL_MAX - 1) + sizeof(expr_node_t *) * aggr_cnt;
    CT_RETURN_IFERR(sql_push(stmt, alloc_size, (void **)&value));
    expr_node_t **aggr_nodes = (expr_node_t **)((char *)value + sizeof(variant_t) * (FO_VAL_MAX - 1));
    for (i = 0; i < aggr_cnt; i++) {
        aggr_nodes[i] = (expr_node_t *)cm_galist_get(plan->aggr.items, i);
    }

    CTSQL_SAVE_STACK(stmt);
    CT_RETURN_IFERR(sql_fetch_query(stmt, cursor, plan->aggr.next, &cursor->eof));

    rows = 0;
    while (!cursor->eof) {
        rows++;

        for (i = 0; i < aggr_cnt; i++) {
            ctsql_stmt.avg_count = 1;
            ctsql_stmt.aggr_node = aggr_nodes[i];
            func = GET_AGGR_FUNC(ctsql_stmt.aggr_node);
            CT_RETURN_IFERR(sql_exec_expr_node(stmt, AGGR_VALUE_NODE(func, ctsql_stmt.aggr_node), value));
            if (CT_IS_LOB_TYPE(value->type)) {
                CT_RETURN_IFERR(sql_get_lob_value(stmt, value));
            }

            if (ctsql_stmt.aggr_node->dis_info.need_distinct && func->aggr_type == AGGR_TYPE_COUNT) {
                CT_RETURN_IFERR(sql_aggr_get_cntdis_value(stmt, plan->aggr.cntdis_columns, ctsql_stmt.aggr_node, value));
            }

            ctsql_stmt.aggr_type = func->aggr_type;
            CT_RETURN_IFERR(sql_aggr_value(&ctsql_stmt, i, value));
        }

        CTSQL_RESTORE_STACK(stmt);
        CT_RETURN_IFERR(sql_fetch_query(stmt, cursor, plan->aggr.next, &cursor->eof));
    }

    CTSQL_RESTORE_STACK(stmt);
    CTSQL_POP(stmt);

    // release next query mtrl
    CT_RETURN_IFERR(sql_free_query_mtrl(stmt, cursor, plan->aggr.next));

    if ((avgs > 0 && rows > 0) && (par_exe_flag == CT_FALSE)) {
        CT_RETURN_IFERR(sql_exec_aggr(stmt, cursor, plan->aggr.items, plan));
    }
    if (rows == 0 && sql_aggr_is_nullaware(stmt, cursor, plan)) {
        // signed aggr_fetched to make cursor eof, thus, compare ALL will always returns TRUE
        cursor->mtrl.aggr_fetched = CT_TRUE;
    }

    // Include table with only 0 row.
    return sql_exec_aggr_extra(stmt, cursor, plan->aggr.items, plan);
}

// Only get the maximum through index can invoke this function
static status_t sql_mtrl_index_aggr(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    uint32 avgs;
    uint32 rows = 0;
    bool32 result = CT_FALSE;
    variant_t *value = NULL;
    const sql_func_t *func = NULL;
    aggr_assist_t ass;
    SQL_INIT_AGGR_ASSIST(&ass, stmt, cursor);

    if (plan->aggr.next->type != PLAN_NODE_SCAN) {
        return CT_ERROR;
    }

    cursor->mtrl.cursor.type = MTRL_CURSOR_OTHERS;
    CT_RETURN_IFERR(sql_init_aggr_page(stmt, cursor, plan->aggr.items));
    CT_RETURN_IFERR(sql_init_aggr_values(stmt, cursor, plan->aggr.next, plan->aggr.items, &avgs));
    CT_RETURN_IFERR(sql_execute_scan(stmt, cursor, plan->aggr.next));

    sql_table_t *table = plan->aggr.next->scan_p.table;
    sql_table_cursor_t *tab_cur = &cursor->tables[table->id];

    for (;;) {
        CT_RETURN_IFERR(sql_fetch_one_part(stmt, tab_cur, table));
        if (!tab_cur->knl_cur->eof) {
            rows++;
            ass.aggr_node = (expr_node_t *)cm_galist_get(plan->aggr.items, 0);
            func = GET_AGGR_FUNC(ass.aggr_node);
            CT_RETURN_IFERR(sql_push(stmt, func->value_cnt * sizeof(variant_t), (void **)&value));
            if (sql_exec_expr_node(stmt, AGGR_VALUE_NODE(func, ass.aggr_node), value) != CT_SUCCESS) {
                CTSQL_POP(stmt);
                return CT_ERROR;
            }
            ass.aggr_type = func->aggr_type;
            ass.avg_count = 0;
            if (sql_aggr_value(&ass, (uint32)0, value) != CT_SUCCESS) {
                CTSQL_POP(stmt);
                return CT_ERROR;
            }
            CTSQL_POP(stmt);
        }
        CT_RETURN_IFERR(sql_try_switch_part(stmt, tab_cur, table, &result));
        if (!result) {
            break;
        }
    }
    if (rows == 0 && sql_aggr_is_nullaware(stmt, cursor, plan)) {
        cursor->mtrl.aggr_fetched = CT_TRUE;
    }
    return CT_SUCCESS;
}

void clean_mtrl_seg(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    mtrl_close_segment(&stmt->mtrl, cursor->mtrl.aggr);
    mtrl_release_segment(&stmt->mtrl, cursor->mtrl.aggr);
    cursor->mtrl.aggr = CT_INVALID_ID32;
}

status_t sql_execute_aggr(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
#ifdef TIME_STATISTIC
    clock_t start;
    double timeuse;
    start = cm_cal_time_bengin();
#endif

    CT_RETURN_IFERR(mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_AGGR, NULL, &cursor->mtrl.aggr));

    CT_RETURN_IFERR(mtrl_open_segment(&stmt->mtrl, cursor->mtrl.aggr));

    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));
    if (sql_mtrl_aggr(stmt, cursor, plan, cursor->par_ctx.par_exe_flag) != CT_SUCCESS) {
        SQL_CURSOR_POP(stmt);
        clean_mtrl_seg(stmt, cursor);
        return CT_ERROR;
    }
    SQL_CURSOR_POP(stmt);

    cursor->eof = CT_FALSE;
#ifdef TIME_STATISTIC
    timeuse = cm_cal_time_end(start);
    stmt->mt_time += timeuse;
#endif
    return CT_SUCCESS;
}

status_t sql_execute_index_aggr(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    if (mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_AGGR, NULL, &cursor->mtrl.aggr) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (mtrl_open_segment(&stmt->mtrl, cursor->mtrl.aggr) != CT_SUCCESS) {
        return CT_ERROR;
    }
    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));
    if (sql_mtrl_index_aggr(stmt, cursor, plan) != CT_SUCCESS) {
        SQL_CURSOR_POP(stmt);
        return CT_ERROR;
    }
    SQL_CURSOR_POP(stmt);
    cursor->eof = CT_FALSE;
    return CT_SUCCESS;
}

static inline status_t sql_aggr_reset_default(aggr_var_t *aggr_var)
{
    if (!CT_IS_VARLEN_TYPE(aggr_var->var.type)) {
        MEMS_RETURN_IFERR(memset_s(&aggr_var->var, sizeof(variant_t), 0, sizeof(variant_t)));
    } else {
        // don't reset aggr_var->var.v_text.str and aggr_var->var.v_bin.bytes
        aggr_var->var.type = 0;
        aggr_var->var.is_null = CT_FALSE;
        aggr_var->var.v_text.len = 0;
        aggr_var->var.v_bin.size = 0;
    }
    return CT_SUCCESS;
}

static inline status_t sql_aggr_reset_median(aggr_var_t *aggr_var)
{
    aggr_var->var.is_null = CT_TRUE;
    GET_AGGR_VAR_MEDIAN(aggr_var)->median_count = 0;
    GET_AGGR_VAR_MEDIAN(aggr_var)->sort_rid.vmid = CT_INVALID_ID32;
    GET_AGGR_VAR_MEDIAN(aggr_var)->sort_rid.slot = CT_INVALID_ID32;
    return sql_aggr_reset_default(aggr_var);
}

static inline status_t sql_aggr_reset_avg(aggr_var_t *aggr_var)
{
    aggr_var->var.v_bigint = 0;
    GET_AGGR_VAR_AVG(aggr_var)->ex_avg_count = 0;
    return sql_aggr_reset_default(aggr_var);
}

// for rank/dense_rank
static inline status_t sql_aggr_reset_rank(aggr_var_t *aggr_var)
{
    aggr_var->var.is_null = CT_TRUE;
    aggr_var->var.type = CT_TYPE_INTEGER;
    VALUE(uint32, &aggr_var->var) = 1;
    return sql_aggr_reset_default(aggr_var);
}

static inline status_t sql_aggr_reset_min_max(aggr_var_t *aggr_var)
{
    if (CT_IS_VARLEN_TYPE(aggr_var->var.type)) {
        aggr_str_t *aggr_str = GET_AGGR_VAR_STR(aggr_var);
        aggr_str->str_result.vmid = CT_INVALID_ID32;
        aggr_str->str_result.slot = CT_INVALID_ID32;
    }
    return sql_aggr_reset_default(aggr_var);
}

static inline status_t sql_aggr_reset_listagg(aggr_var_t *aggr_var)
{
    /* no need to reset aggr_var->extra  because the possible separator would be calculate only once */
    aggr_group_concat_t *aggr_group = GET_AGGR_VAR_GROUPCONCAT(aggr_var);
    aggr_group->total_len = 0;
    aggr_group->aggr_str.str_result.vmid = CT_INVALID_ID32;
    aggr_group->aggr_str.str_result.slot = CT_INVALID_ID32;
    aggr_group->sort_rid.vmid = CT_INVALID_ID32;
    aggr_group->sort_rid.slot = CT_INVALID_ID32;
    return sql_aggr_reset_default(aggr_var);
}

static inline status_t sql_aggr_reset_array_agg(aggr_var_t *aggr_var)
{
    aggr_var->var.type = CT_TYPE_ARRAY;
    cm_reset_vm_lob(&aggr_var->var.v_array.value.vm_lob);
    return sql_aggr_reset_default(aggr_var);
}

static inline status_t sql_aggr_reset_covar(aggr_var_t *aggr_var)
{
    aggr_covar_t *aggr_covar = GET_AGGR_VAR_COVAR(aggr_var);
    aggr_covar->ex_count = 0;
    MEMS_RETURN_IFERR(memset_s(&aggr_covar->extra, sizeof(variant_t), 0, sizeof(variant_t)));
    MEMS_RETURN_IFERR(memset_s(&aggr_covar->extra_1, sizeof(variant_t), 0, sizeof(variant_t)));
    return sql_aggr_reset_default(aggr_var);
}

static inline status_t sql_aggr_reset_corr(aggr_var_t *aggr_var)
{
    aggr_corr_t *corr = GET_AGGR_VAR_CORR(aggr_var);
    MEMS_RETURN_IFERR(memset_s(&corr->extra, sizeof(corr->extra), 0, sizeof(corr->extra)));
    return sql_aggr_reset_default(aggr_var);
}

static inline status_t sql_aggr_reset_stddev(aggr_var_t *aggr_var)
{
    aggr_stddev_t *aggr_stddev = GET_AGGR_VAR_STDDEV(aggr_var);
    aggr_stddev->ex_count = 0;
    MEMS_RETURN_IFERR(memset_s(&aggr_stddev->extra, sizeof(variant_t), 0, sizeof(variant_t)));
    return sql_aggr_reset_default(aggr_var);
}

static inline status_t sql_aggr_init_count(aggr_assist_t *ctsql_stmt, aggr_var_t *aggr_var)
{
    aggr_var->var.type = CT_TYPE_BIGINT;
    aggr_var->var.is_null = CT_FALSE;
    aggr_var->var.v_bigint = 0;
    return CT_SUCCESS;
}

static inline status_t sql_aggr_init_median(aggr_assist_t *ctsql_stmt, aggr_var_t *aggr_var)
{
    aggr_var->var.is_null = CT_TRUE;
    aggr_var->var.type = ctsql_stmt->aggr_node->datatype;
    GET_AGGR_VAR_MEDIAN(aggr_var)->median_count = 0;
    GET_AGGR_VAR_MEDIAN(aggr_var)->sort_rid.vmid = CT_INVALID_ID32;
    GET_AGGR_VAR_MEDIAN(aggr_var)->sort_rid.slot = CT_INVALID_ID32;
    ctsql_stmt->avg_count++;
    return CT_SUCCESS;
}

// for rank/dense_rank
static status_t sql_aggr_init_rank(aggr_assist_t *ctsql_stmt, aggr_var_t *aggr_var)
{
    aggr_dense_rank_t *aggr_dense_rank = NULL;
    if (ctsql_stmt->aggr_type == AGGR_TYPE_DENSE_RANK) {
        aggr_dense_rank = GET_AGGR_VAR_DENSE_RANK(aggr_var);
        vm_hash_segment_init(KNL_SESSION(ctsql_stmt->stmt), ctsql_stmt->stmt->mtrl.pool, &aggr_dense_rank->hash_segment, PMA_POOL,
            HASH_PAGES_HOLD, HASH_AREA_SIZE);
        aggr_dense_rank->table_entry.vmid = CT_INVALID_ID32;
        aggr_dense_rank->table_entry.offset = CT_INVALID_ID32;
        CT_RETURN_IFERR(vm_hash_table_alloc(&aggr_dense_rank->table_entry, &aggr_dense_rank->hash_segment, 0));
        CT_RETURN_IFERR(
            vm_hash_table_init(&aggr_dense_rank->hash_segment, &aggr_dense_rank->table_entry, NULL, NULL, NULL));
    }
    aggr_var->var.is_null = CT_TRUE;
    aggr_var->var.type = CT_TYPE_INTEGER;
    VALUE(uint32, &aggr_var->var) = 1;
    ctsql_stmt->avg_count++;
    return CT_SUCCESS;
}

static inline status_t sql_aggr_init_gc_sort_data(sql_cursor_t *cursor)
{
    text_buf_t *sort_concat = &cursor->exec_data.sort_concat;

    /* allocate from vmc if not initialized before */
    if (cursor->exec_data.sort_concat.str == NULL) {
        CT_RETURN_IFERR(vmc_alloc(&cursor->vmc, CT_MAX_ROW_SIZE, (void **)&sort_concat->str));
        sort_concat->max_size = CT_MAX_ROW_SIZE;
        sort_concat->len = 0;
    }

    return CT_SUCCESS;
}

static status_t sql_aggr_init_listagg(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_group_concat_t *aggr_group = GET_AGGR_VAR_GROUPCONCAT(aggr_var);
    aggr_group->sort_rid.slot = CT_INVALID_ID32;
    aggr_group->sort_rid.vmid = CT_INVALID_ID32;
    aggr_group->total_len = 0;
    aggr_group->aggr_str.str_result.vmid = CT_INVALID_ID32;
    aggr_group->aggr_str.str_result.slot = CT_INVALID_ID32;
    aggr_var->var.type = CT_TYPE_STRING;
    aggr_var->var.is_null = CT_TRUE;
    aggr_var->var.v_text.len = 0;
    if (ass->aggr_node->sort_items != NULL) {
        ass->avg_count++;
    }
    return sql_aggr_init_gc_sort_data(ass->cursor);
}

static inline status_t sql_aggr_init_array_agg(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    array_assist_t array_a;
    id_list_t *vm_list = sql_get_exec_lob_list(ass->stmt);
    aggr_var->var.is_null = CT_FALSE;
    aggr_var->var.type = CT_TYPE_ARRAY;
    aggr_var->var.v_array.count = 0;
    aggr_var->var.v_array.value.type = CT_LOB_FROM_VMPOOL;
    aggr_var->var.v_array.type = ass->aggr_node->typmod.datatype;
    return array_init(&array_a, KNL_SESSION(ass->stmt), ass->stmt->mtrl.pool, vm_list,
        &aggr_var->var.v_array.value.vm_lob);
}

static inline status_t sql_aggr_init_stddev(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_var->var.is_null = CT_TRUE;
    aggr_var->var.type = ass->aggr_node->datatype;
    aggr_stddev_t *aggr_stddev = GET_AGGR_VAR_STDDEV(aggr_var);
    aggr_stddev->extra.is_null = CT_TRUE;
    aggr_stddev->ex_count = 0;
    ass->avg_count++;
    return CT_SUCCESS;
}

static inline status_t sql_aggr_init_covar(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_covar_t *aggr_covar = GET_AGGR_VAR_COVAR(aggr_var);
    aggr_covar->extra.is_null = CT_TRUE;
    aggr_covar->extra_1.is_null = CT_TRUE;
    aggr_covar->ex_count = 0;
    aggr_var->var.is_null = CT_TRUE;
    aggr_var->var.type = CT_TYPE_NUMBER;
    ass->avg_count++;
    return CT_SUCCESS;
}

static inline status_t sql_aggr_init_corr(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_var->var.is_null = CT_TRUE;
    aggr_var->var.type = ass->aggr_node->datatype;
    aggr_corr_t *aggr_corr = GET_AGGR_VAR_CORR(aggr_var);
    aggr_corr->extra[CORR_VAR_SUM_X].is_null = CT_TRUE;
    aggr_corr->extra[CORR_VAR_SUM_Y].is_null = CT_TRUE;
    aggr_corr->extra[CORR_VAR_SUM_XX].is_null = CT_TRUE;
    aggr_corr->extra[CORR_VAR_SUM_YY].is_null = CT_TRUE;
    aggr_corr->ex_count = 0;
    ass->avg_count++;
    return CT_SUCCESS;
}

static inline status_t sql_aggr_init_cume_dist(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    GET_AGGR_VAR_AVG(aggr_var)->ex_avg_count = 0;
    aggr_var->var.type = CT_TYPE_REAL;
    aggr_var->var.is_null = CT_TRUE;
    VALUE(double, &aggr_var->var) = 1;
    ass->avg_count++;
    return CT_SUCCESS;
}

static status_t sql_aggr_init_default(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    expr_node_t *aggr_node = ass->aggr_node;

    if (CT_IS_VARLEN_TYPE(aggr_node->datatype)) {
        aggr_str_t *aggr_str = GET_AGGR_VAR_STR(aggr_var);
        aggr_str->str_result.vmid = CT_INVALID_ID32;
        aggr_str->str_result.slot = CT_INVALID_ID32;
    }

    if (SECUREC_UNLIKELY(ass->aggr_type == AGGR_TYPE_SUM &&
        aggr_node->value.v_func.orig_func_id == ID_FUNC_ITEM_COUNT)) {
        aggr_var->var.type = CT_TYPE_BIGINT;
        aggr_var->var.is_null = CT_FALSE;
        aggr_var->var.v_bigint = 0;
    } else {
        aggr_var->var.type = aggr_node->datatype;
        aggr_var->var.is_null = CT_TRUE;
        /* modified by Z_SHARDING, add AGGR_TYPE_AVG_COLLECT for sharding */
        if (ass->aggr_type == AGGR_TYPE_AVG || ass->aggr_type == AGGR_TYPE_AVG_COLLECT) {
            GET_AGGR_VAR_AVG(aggr_var)->ex_avg_count = 0;
            ass->avg_count++;
            if (aggr_node->datatype <= CT_TYPE_REAL) {
                aggr_var->var.type = CT_TYPE_REAL;
            } else {
                aggr_var->var.type = CT_TYPE_NUMBER;
            }
        }
    }
    return CT_SUCCESS;
}

static status_t sql_reset_sort_segment(sql_stmt_t *ctsql_stmt, sql_cursor_t *cursor)
{
    mtrl_page_t *page = NULL;
    mtrl_segment_t *segment = NULL;

    if (cursor->mtrl.sort_seg == CT_INVALID_ID32) {
        return CT_SUCCESS;
    }
    segment = ctsql_stmt->mtrl.segments[cursor->mtrl.sort_seg];
    if (segment->vm_list.count == 0 || segment->curr_page == NULL) {
        return CT_SUCCESS;
    }
    page = (mtrl_page_t *)segment->curr_page->data;
    if (segment->vm_list.count == 1 && page->rows == 0) {
        return CT_SUCCESS;
    }
    mtrl_close_segment2(&ctsql_stmt->mtrl, segment);
    sql_free_segment_in_vm(ctsql_stmt, cursor->mtrl.sort_seg);
    vm_free_list(ctsql_stmt->mtrl.session, ctsql_stmt->mtrl.pool, &segment->vm_list);
    CT_RETURN_IFERR(mtrl_extend_segment(&ctsql_stmt->mtrl, segment));
    return mtrl_open_segment2(&ctsql_stmt->mtrl, segment);
}

static status_t sql_aggr_init_distinct(aggr_assist_t *ass, plan_node_t *plan)
{
    if (ass->aggr_node->dis_info.need_distinct) {
        hash_segment_t *hash_segment = (hash_segment_t *)ass->cursor->exec_data.aggr_dis;
        hash_table_entry_t *hash_table_entry = (hash_table_entry_t *)((char *)hash_segment + sizeof(hash_segment_t));
        // estimate hash distinct rows
        uint32 bucket_num = sql_get_plan_hash_rows(ass->stmt, plan);
        CT_RETURN_IFERR(vm_hash_table_alloc(&hash_table_entry[ass->aggr_node->dis_info.idx], hash_segment, bucket_num));
        CT_RETURN_IFERR(
            vm_hash_table_init(hash_segment, &hash_table_entry[ass->aggr_node->dis_info.idx], NULL, NULL, NULL));
    }
    return CT_SUCCESS;
}


/*
 * this function is called every time the calculation of one group of rows is done.
 */
status_t sql_init_aggr_values(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, galist_t *aggrs, uint32 *avgs)
{
    const aggr_func_t *aggr_func = NULL;
    aggr_var_t *aggr_var = NULL;
    hash_segment_t *hash_segment = NULL;
    aggr_assist_t ass;
    SQL_INIT_AGGR_ASSIST(&ass, stmt, cursor);

    if (cursor->exec_data.aggr_dis != NULL) {
        hash_segment = (hash_segment_t *)cursor->exec_data.aggr_dis;
        vm_hash_segment_deinit(hash_segment);
        vm_hash_segment_init(KNL_SESSION(stmt), stmt->mtrl.pool, hash_segment, PMA_POOL, HASH_PAGES_HOLD,
            HASH_AREA_SIZE);
    }

    for (uint32 i = 0; i < aggrs->count; i++) {
        ass.aggr_node = (expr_node_t *)cm_galist_get(aggrs, i);
        ass.aggr_type = GET_AGGR_FUNC(ass.aggr_node)->aggr_type;
        aggr_var = sql_get_aggr_addr(cursor, i);
        aggr_func = sql_get_aggr_func(ass.aggr_type);
        CT_RETURN_IFERR(aggr_func->reset(aggr_var));
        CT_RETURN_IFERR(aggr_func->init(&ass, aggr_var));
        CT_RETURN_IFERR(sql_aggr_init_distinct(&ass, plan));
    }

    CT_RETURN_IFERR(sql_reset_sort_segment(stmt, cursor));

    (*avgs) = (uint32)ass.avg_count;
    return CT_SUCCESS;
}

status_t sql_mtrl_aggr_page_alloc(sql_stmt_t *stmt, sql_cursor_t *cursor, uint32 size, void **result)
{
    CM_POINTER4(stmt, cursor, cursor->aggr_page, result);

    /* currently we use only one page(64K) */
    if (cursor->aggr_page->free_begin + size > CT_VMEM_PAGE_SIZE - sizeof(mtrl_page_t)) {
        CT_THROW_ERROR(ERR_NO_FREE_VMEM, "one page free size is smaller than needed memory");
        return CT_ERROR;
    }

    *result = sql_get_aggr_free_start_addr(cursor);
    cursor->aggr_page->free_begin += size;

    return CT_SUCCESS;
}

static bool32 sql_judge_func_arg_type(sql_stmt_t *stmt, expr_node_t *aggr_node, variant_t *sep_val)
{
    const sql_func_t *func = GET_AGGR_FUNC(aggr_node);
    CTSQL_SAVE_STACK(stmt);
    if (func->builtin_func_id == ID_FUNC_ITEM_GROUP_CONCAT) {
        if (!CT_IS_STRING_TYPE(sep_val->type)) {
            CT_THROW_ERROR(ERR_INVALID_SEPARATOR, T2S(&func->name));
            return CT_ERROR;
        }
    }
    if (func->builtin_func_id == ID_FUNC_ITEM_LISTAGG) {
        if (!CT_IS_STRING_TYPE(sep_val->type) && !CT_IS_NUMERIC_TYPE(sep_val->type) &&
            !CT_IS_DATETIME_TYPE(sep_val->type)) {
            CT_SRC_THROW_ERROR(aggr_node->loc, ERR_SQL_SYNTAX_ERROR,
                "the separator argument of listagg must be a string or number or date variant.");
            return CT_ERROR;
        }
        if (!CT_IS_STRING_TYPE(sep_val->type)) {
            if (sql_var_as_string(stmt, sep_val) != CT_SUCCESS) {
                CTSQL_RESTORE_STACK(stmt);
                return CT_ERROR;
            }
        }
    }
    CTSQL_RESTORE_STACK(stmt);
    return CT_SUCCESS;
}

static status_t sql_init_group_concat_sepvar(sql_stmt_t *stmt, sql_cursor_t *cursor, expr_node_t *aggr_node,
    aggr_group_concat_t *aggr_group)
{
    expr_tree_t *sep = NULL;
    variant_t sep_val;
    variant_t *sep_cpy = NULL;

    // the first argument is separator
    sep = aggr_node->argument; /* get the optional argument "separator" */
    sep_cpy = &aggr_group->extra;
    if (sep != NULL) {
        CT_RETURN_IFERR(sql_exec_expr_node(stmt, sep->root, &sep_val));
        CT_RETURN_IFERR(sql_judge_func_arg_type(stmt, aggr_node, &sep_val));

        sep_cpy->type = sep_val.type;
        sep_cpy->is_null = sep_val.is_null;
        if (sep_cpy->is_null == CT_FALSE) {
            /* make the buffer for storing separator in mtrl page, too */
            CT_RETURN_IFERR(sql_mtrl_aggr_page_alloc(stmt, cursor, sep_val.v_text.len, (void **)&sep_cpy->v_text.str));
            sep_cpy->v_text.len = sep_val.v_text.len;
            if (sep_val.v_text.len != 0) {
                MEMS_RETURN_IFERR(
                    memcpy_s(sep_cpy->v_text.str, sep_val.v_text.len, sep_val.v_text.str, sep_val.v_text.len));
            }
        }
    } else {
        sep_cpy->is_null = CT_TRUE;
        sep_cpy->type = CT_TYPE_STRING;
        sep_cpy->v_text.len = CT_INVALID_ID32;
        sep_cpy->v_text.str = NULL;
    }
    return CT_SUCCESS;
}

static status_t sql_init_sort_4_listagg(sql_stmt_t *stmt, sql_cursor_t *cursor, expr_node_t *aggr_node,
    aggr_var_t *aggr_var)
{
    aggr_group_concat_t *aggr_group = GET_AGGR_VAR_GROUPCONCAT(aggr_var);
    CT_RETURN_IFERR(sql_init_group_concat_sepvar(stmt, cursor, aggr_node, aggr_group));
    aggr_var->var.type = aggr_node->datatype;

    if (aggr_node->sort_items != NULL && cursor->mtrl.sort_seg == CT_INVALID_ID32) {
        CT_RETURN_IFERR(mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_SORT_SEG, NULL, &cursor->mtrl.sort_seg));
        CT_RETURN_IFERR(mtrl_open_segment(&stmt->mtrl, cursor->mtrl.sort_seg));
    }

    if (aggr_node->sort_items != NULL && aggr_group->type_buf == NULL) {
        CT_RETURN_IFERR(sql_sort_mtrl_record_types(&cursor->vmc, MTRL_SEGMENT_CONCAT_SORT, aggr_node->sort_items,
            &aggr_group->type_buf));
    }
    return CT_SUCCESS;
}

static status_t sql_init_sort_4_median(sql_stmt_t *stmt, sql_cursor_t *cursor, expr_node_t *aggr_node,
    aggr_var_t *aggr_var)
{
    if (cursor->mtrl.sort_seg == CT_INVALID_ID32) {
        CT_RETURN_IFERR(mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_SORT_SEG, NULL, &cursor->mtrl.sort_seg));
        CT_RETURN_IFERR(mtrl_open_segment(&stmt->mtrl, cursor->mtrl.sort_seg));
    }

    aggr_median_t *aggr_median = GET_AGGR_VAR_MEDIAN(aggr_var);
    if (aggr_node->sort_items != NULL && aggr_median->type_buf == NULL) {
        CT_RETURN_IFERR(sql_sort_mtrl_record_types(&cursor->vmc, MTRL_SEGMENT_CONCAT_SORT, aggr_node->sort_items,
            &aggr_median->type_buf));
    }
    return CT_SUCCESS;
}

static status_t sql_aggr_alloc_listagg(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_group_concat_t *aggr_group = NULL;
    CT_RETURN_IFERR(
        sql_mtrl_aggr_page_alloc(ass->stmt, ass->cursor, sizeof(aggr_group_concat_t), (void **)&aggr_group));
    aggr_var->extra_offset = (uint32)((char *)aggr_group - (char *)aggr_var);
    aggr_var->extra_size = sizeof(aggr_group_concat_t);
    aggr_group->aggr_str.aggr_bufsize = 0;
    aggr_group->total_len = 0;
    aggr_group->aggr_str.str_result.vmid = CT_INVALID_ID32;
    aggr_group->aggr_str.str_result.slot = CT_INVALID_ID32;
    aggr_group->sort_rid.slot = CT_INVALID_ID32;
    aggr_group->type_buf = NULL;

    /*
     * if the aggr function is group_concat, we need to create two buffers for it in the mtrl page.
     * one is for the possible separator, the other for the temporary result for string concat
     */
    return sql_init_sort_4_listagg(ass->stmt, ass->cursor, ass->aggr_node, aggr_var);
}

static status_t sql_aggr_alloc_min_max(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_str_t *aggr_str = NULL;
    if (CT_IS_VARLEN_TYPE(ass->aggr_node->datatype)) {
        CT_RETURN_IFERR(sql_mtrl_aggr_page_alloc(ass->stmt, ass->cursor, sizeof(aggr_str_t), (void **)&aggr_str));
        aggr_var->extra_offset = (uint32)((char *)aggr_str - (char *)aggr_var);
        aggr_var->extra_size = sizeof(aggr_str_t);
        aggr_str->aggr_bufsize = 0;
        aggr_str->str_result.vmid = CT_INVALID_ID32;
        aggr_str->str_result.slot = CT_INVALID_ID32;
    } else {
        aggr_var->extra_offset = 0;
        aggr_var->extra_size = 0;
    }
    return CT_SUCCESS;
}

static inline status_t sql_aggr_alloc_stddev(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_stddev_t *aggr_stddev = NULL;
    CT_RETURN_IFERR(sql_mtrl_aggr_page_alloc(ass->stmt, ass->cursor, sizeof(aggr_stddev_t), (void **)&aggr_stddev));
    aggr_var->extra_offset = (uint32)((char *)aggr_stddev - (char *)aggr_var);
    aggr_var->extra_size = sizeof(aggr_stddev_t);
    aggr_stddev->extra.is_null = CT_TRUE;
    return CT_SUCCESS;
}

static inline status_t sql_aggr_alloc_covar(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_covar_t *aggr_covar = NULL;
    CT_RETURN_IFERR(sql_mtrl_aggr_page_alloc(ass->stmt, ass->cursor, sizeof(aggr_covar_t), (void **)&aggr_covar));
    aggr_var->extra_offset = (uint32)((char *)aggr_covar - (char *)aggr_var);
    aggr_var->extra_size = sizeof(aggr_covar_t);
    aggr_covar->extra.is_null = CT_TRUE;
    aggr_covar->extra_1.is_null = CT_TRUE;
    return CT_SUCCESS;
}

static inline status_t sql_aggr_alloc_corr(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_corr_t *aggr_corr = NULL;
    CT_RETURN_IFERR(sql_mtrl_aggr_page_alloc(ass->stmt, ass->cursor, sizeof(aggr_corr_t), (void **)&aggr_corr));
    aggr_var->extra_offset = (uint32)((char *)aggr_corr - (char *)aggr_var);
    aggr_var->extra_size = sizeof(aggr_corr_t);
    return CT_SUCCESS;
}

// for avg/cume_dist/avg_collect
static inline status_t sql_aggr_alloc_avg(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_avg_t *aggr_avg = NULL;
    CT_RETURN_IFERR(sql_mtrl_aggr_page_alloc(ass->stmt, ass->cursor, sizeof(aggr_avg_t), (void **)&aggr_avg));
    aggr_var->extra_offset = (uint32)((char *)aggr_avg - (char *)aggr_var);
    aggr_var->extra_size = sizeof(aggr_avg_t);
    aggr_avg->ex_avg_count = 0;
    return CT_SUCCESS;
}

static inline status_t sql_aggr_alloc_median(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_median_t *aggr_median = NULL;
    CT_RETURN_IFERR(sql_mtrl_aggr_page_alloc(ass->stmt, ass->cursor, sizeof(aggr_median_t), (void **)&aggr_median));
    aggr_var->extra_offset = (uint32)((char *)aggr_median - (char *)aggr_var);
    aggr_var->extra_size = sizeof(aggr_median_t);
    aggr_median->median_count = 0;
    aggr_median->sort_rid.vmid = CT_INVALID_ID32;
    aggr_median->sort_rid.slot = CT_INVALID_ID32;
    aggr_median->type_buf = NULL;
    /* allocate sort segment for median sort */
    return sql_init_sort_4_median(ass->stmt, ass->cursor, ass->aggr_node, aggr_var);
}

static inline status_t sql_aggr_alloc_dense_rank(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_dense_rank_t *aggr_dense_rank = NULL;
    CT_RETURN_IFERR(
        sql_mtrl_aggr_page_alloc(ass->stmt, ass->cursor, sizeof(aggr_dense_rank_t), (void **)&aggr_dense_rank));
    aggr_var->extra_offset = (uint32)((char *)aggr_dense_rank - (char *)aggr_var);
    aggr_var->extra_size = sizeof(aggr_dense_rank_t);
    return CT_SUCCESS;
}

static inline status_t sql_aggr_alloc_default(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_var->extra_size = 0;
    aggr_var->extra_offset = 0;
    return CT_SUCCESS;
}

/*
 * aggr_var_t for the aggregate function such as group_concat needs to store the
 * intermediate result in a buffer. as the aggr_var_t itself is allocated in the
 * mtrl page, so we can create the buffer in the mtrl page, too.
 *
 * @Note
 * this function is called only once after the mtrl page created.
 * pay attention to the difference from the timing of sql_init_aggr_values()
 */
status_t sql_init_aggr_page(sql_stmt_t *stmt, sql_cursor_t *cursor, galist_t *aggrs)
{
    const sql_func_t *func = NULL;
    char *aggr_vars_start = NULL;
    aggr_assist_t ass;
    SQL_INIT_AGGR_ASSIST(&ass, stmt, cursor);

    cursor->aggr_page = mtrl_curr_page(&stmt->mtrl, cursor->mtrl.aggr);

    if (cursor->aggr_page->free_begin + aggrs->count * sizeof(aggr_var_t) > CT_VMEM_PAGE_SIZE - sizeof(mtrl_page_t)) {
        CT_THROW_ERROR(ERR_TOO_MANY_ARRG);
        return CT_ERROR;
    }
    cursor->aggr_page->free_begin += aggrs->count * sizeof(aggr_var_t);
    cursor->aggr_page->rows = 0;
    aggr_vars_start = ((char *)cursor->aggr_page + sizeof(mtrl_page_t));
    MEMS_RETURN_IFERR(
        memset_s((void *)aggr_vars_start, aggrs->count * sizeof(aggr_var_t), 0, aggrs->count * sizeof(aggr_var_t)));

    for (uint32 i = 0; i < aggrs->count; i++) {
        aggr_var_t *aggr_var = sql_get_aggr_addr(cursor, i);
        ass.aggr_node = (expr_node_t *)cm_galist_get(aggrs, i);
        func = GET_AGGR_FUNC(ass.aggr_node);
        aggr_var->aggr_type = func->aggr_type;
        ass.aggr_type = func->aggr_type;
        CT_RETURN_IFERR(sql_aggr_alloc_buf(&ass, aggr_var));
    }

    return CT_SUCCESS;
}

status_t sql_fetch_aggr(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    if (cursor->mtrl.aggr_fetched) {
        if (cursor->mtrl.aggr != CT_INVALID_ID32) {
            mtrl_close_segment(&stmt->mtrl, cursor->mtrl.aggr);
            mtrl_release_segment(&stmt->mtrl, cursor->mtrl.aggr);
            cursor->mtrl.aggr = CT_INVALID_ID32;
            cursor->aggr_page = NULL;
        }

        CTSQL_RELEASE_SEGMENT(stmt, cursor->mtrl.aggr_str);

        if (cursor->mtrl.sort_seg != CT_INVALID_ID32) {
            mtrl_close_segment(&stmt->mtrl, cursor->mtrl.sort_seg);
            sql_free_segment_in_vm(stmt, cursor->mtrl.sort_seg);
            mtrl_release_segment(&stmt->mtrl, cursor->mtrl.sort_seg);
            cursor->mtrl.sort_seg = CT_INVALID_ID32;
        }
        *eof = CT_TRUE;
        return CT_SUCCESS;
    }
    *eof = CT_FALSE;
    cursor->mtrl.aggr_fetched = CT_TRUE;
    return CT_SUCCESS;
}

static inline status_t sql_aggr_alloc_appx_cntdis(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_appx_cntdis_t *appx_cdist = NULL;
    CT_RETURN_IFERR(sql_mtrl_aggr_page_alloc(ass->stmt, ass->cursor, sizeof(aggr_appx_cntdis_t), (void **)&appx_cdist));
    CT_RETURN_IFERR(vmc_alloc_mem(&ass->cursor->vmc, APPX_MAP_SIZE, (void **)&appx_cdist->bitmap));

    aggr_var->extra_offset = (uint32)((char *)appx_cdist - (char *)aggr_var);
    aggr_var->extra_size = sizeof(aggr_appx_cntdis_t);
    return CT_SUCCESS;
}

static inline status_t sql_aggr_init_appx_cntdis(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    aggr_var->var.type = CT_TYPE_BIGINT;
    aggr_var->var.is_null = CT_FALSE;
    aggr_var->var.v_bigint = 0;
    ass->avg_count++;
    return CT_SUCCESS;
}

static inline status_t sql_aggr_reset_appx_cntdis(aggr_var_t *aggr_var)
{
    aggr_appx_cntdis_t *aggr_appx = GET_AGGR_VAR_APPX_CDIST(aggr_var);
    MEMS_RETURN_IFERR(memset_sp(aggr_appx->bitmap, APPX_MAP_SIZE, 0, APPX_MAP_SIZE));
    return sql_aggr_reset_default(aggr_var);
}

static status_t sql_aggr_appx_cntdis(aggr_assist_t *ass, aggr_var_t *aggr_var, variant_t *value)
{
    if (value->is_null) {
        return CT_SUCCESS;
    }

    // 1) calc hash value
    uint32 hashval = value->v_bigint;

    // 2) calc bitmap bucket
    uint32 bucket = hashval & (APPX_MAP_SIZE - 1);

    // 3) calc first non-zero position
    uint8 bits = 0;
    hashval >>= APPX_BITS;
    while (bits < (UINT32_BITS - APPX_BITS) && CT_BIT_TEST(hashval, CT_GET_MASK(bits)) == 0) {
        bits++;
    }
    aggr_appx_cntdis_t *appx = GET_AGGR_VAR_APPX_CDIST(aggr_var);
    appx->bitmap[bucket] = MAX(appx->bitmap[bucket], bits + 1);

    aggr_var->var.is_null = CT_FALSE;
    return CT_SUCCESS;
}

static status_t sql_aggr_calc_appx_cntdis(aggr_assist_t *ass, aggr_var_t *aggr_var)
{
    uint32 eblocks = 0;
    double appx_sum = 0;
    double appx_value = 0;
    aggr_appx_cntdis_t *appx = GET_AGGR_VAR_APPX_CDIST(aggr_var);

    for (uint32 i = 0; i < APPX_MAP_SIZE; ++i) {
        appx_sum += 1.0 / ((uint32)1 << appx->bitmap[i]);
        eblocks += (appx->bitmap[i] == 0) ? 1 : 0;
    }

    if (appx_sum > 0) {
        appx_value = APPX_ALPHA_MM / appx_sum;
        if (appx_value <= APPX_MIN_VAL && eblocks > 0) {
            appx_value = APPX_MAP_SIZE * log((double)APPX_MAP_SIZE / eblocks);
        } else if (appx_value > APPX_MAX_VAL) {
            appx_value = -log(1 - appx_value / ((uint64)1 << UINT32_BITS)) * ((uint64)1 << UINT32_BITS);
        }
    }
    aggr_var->var.v_bigint = (int64)appx_value;
    aggr_var->var.type = CT_TYPE_BIGINT;
    aggr_var->var.is_null = CT_FALSE;
    return CT_SUCCESS;
}


/*
 * **NOTE:**
 * 1. The function must be arranged by alphabetical ascending order.
 * 2. An enum stands for function index was added in ctsql_func.h.
 * if any built-in function added or removed from the following array,
 * please modify the enum definition, too.
 * 3. add function should add the define id in en_sql_aggr_type at ctsql_func.h.
 */
/* **NOTE:** The function must be arranged as the same order of en_sql_aggr_type. */
aggr_func_t g_aggr_func_tab[] = {
    { AGGR_TYPE_NONE, sql_aggr_alloc_default, sql_aggr_init_default, sql_aggr_reset_default, sql_aggr_none, sql_aggr_calc_none },
    { AGGR_TYPE_AVG, sql_aggr_alloc_avg, sql_aggr_init_default, sql_aggr_reset_avg, sql_aggr_avg, sql_aggr_calc_avg },
    { AGGR_TYPE_SUM, sql_aggr_alloc_default, sql_aggr_init_default, sql_aggr_reset_default, sql_aggr_sum, sql_aggr_calc_none },
    { AGGR_TYPE_MIN, sql_aggr_alloc_min_max, sql_aggr_init_default, sql_aggr_reset_min_max, sql_aggr_min_max, sql_aggr_calc_none },
    { AGGR_TYPE_MAX, sql_aggr_alloc_min_max, sql_aggr_init_default, sql_aggr_reset_min_max, sql_aggr_min_max, sql_aggr_calc_none },
    { AGGR_TYPE_COUNT, sql_aggr_alloc_default, sql_aggr_init_count, sql_aggr_reset_default, sql_aggr_count, sql_aggr_calc_none },
    { AGGR_TYPE_AVG_COLLECT, sql_aggr_alloc_avg, sql_aggr_init_default, sql_aggr_reset_avg, sql_aggr_avg, sql_aggr_calc_avg },
    { AGGR_TYPE_GROUP_CONCAT, sql_aggr_alloc_listagg, sql_aggr_init_listagg, sql_aggr_reset_listagg, sql_aggr_listagg, sql_aggr_calc_listagg },
    { AGGR_TYPE_STDDEV, sql_aggr_alloc_stddev, sql_aggr_init_stddev, sql_aggr_reset_stddev, sql_aggr_stddev, sql_aggr_calc_stddev },
    { AGGR_TYPE_STDDEV_POP, sql_aggr_alloc_stddev, sql_aggr_init_stddev, sql_aggr_reset_stddev, sql_aggr_stddev, sql_aggr_calc_stddev },
    { AGGR_TYPE_STDDEV_SAMP, sql_aggr_alloc_stddev, sql_aggr_init_stddev, sql_aggr_reset_stddev, sql_aggr_stddev, sql_aggr_calc_stddev },
    { AGGR_TYPE_LAG, sql_aggr_alloc_default, sql_aggr_init_default, sql_aggr_reset_default, sql_aggr_none, sql_aggr_calc_none },
    { AGGR_TYPE_ARRAY_AGG, sql_aggr_alloc_default, sql_aggr_init_array_agg, sql_aggr_reset_array_agg, sql_aggr_array_agg, sql_aggr_calc_none },
    { AGGR_TYPE_NTILE, sql_aggr_alloc_default, sql_aggr_init_default, sql_aggr_reset_default, sql_aggr_none, sql_aggr_calc_none },
    { AGGR_TYPE_MEDIAN, sql_aggr_alloc_median, sql_aggr_init_median, sql_aggr_reset_median, sql_aggr_median, sql_aggr_calc_median },
    { AGGR_TYPE_CUME_DIST, sql_aggr_alloc_avg, sql_aggr_init_cume_dist, sql_aggr_reset_avg, sql_aggr_cume_dist, sql_aggr_calc_cume_dist },
    { AGGR_TYPE_VARIANCE, sql_aggr_alloc_stddev, sql_aggr_init_stddev, sql_aggr_reset_stddev, sql_aggr_stddev, sql_aggr_calc_stddev },
    { AGGR_TYPE_VAR_POP, sql_aggr_alloc_stddev, sql_aggr_init_stddev, sql_aggr_reset_stddev, sql_aggr_stddev, sql_aggr_calc_stddev },
    { AGGR_TYPE_VAR_SAMP, sql_aggr_alloc_stddev, sql_aggr_init_stddev, sql_aggr_reset_stddev, sql_aggr_stddev, sql_aggr_calc_stddev },
    { AGGR_TYPE_COVAR_POP, sql_aggr_alloc_covar, sql_aggr_init_covar, sql_aggr_reset_covar, sql_aggr_covar, sql_aggr_calc_covar },
    { AGGR_TYPE_COVAR_SAMP, sql_aggr_alloc_covar, sql_aggr_init_covar, sql_aggr_reset_covar, sql_aggr_covar, sql_aggr_calc_covar },
    { AGGR_TYPE_CORR, sql_aggr_alloc_corr, sql_aggr_init_corr, sql_aggr_reset_corr, sql_aggr_corr, sql_aggr_calc_corr },
    { AGGR_TYPE_DENSE_RANK, sql_aggr_alloc_dense_rank, sql_aggr_init_rank, sql_aggr_reset_rank, sql_aggr_dense_rank, sql_aggr_calc_dense_rank },
    { AGGR_TYPE_FIRST_VALUE, sql_aggr_alloc_default, sql_aggr_init_default, sql_aggr_reset_default, sql_aggr_none, sql_aggr_calc_none },
    { AGGR_TYPE_LAST_VALUE, sql_aggr_alloc_default, sql_aggr_init_default, sql_aggr_reset_default, sql_aggr_none, sql_aggr_calc_none },
    { AGGR_TYPE_RANK, sql_aggr_alloc_default, sql_aggr_init_rank, sql_aggr_reset_rank, sql_aggr_rank, sql_aggr_calc_none },
    { AGGR_TYPE_APPX_CNTDIS, sql_aggr_alloc_appx_cntdis, sql_aggr_init_appx_cntdis, sql_aggr_reset_appx_cntdis, sql_aggr_appx_cntdis, sql_aggr_calc_appx_cntdis },
};
