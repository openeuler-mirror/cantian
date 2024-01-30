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
 * ctsql_winsort.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_winsort.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_WINSORT_H__
#define __SQL_WINSORT_H__

#include "knl_mtrl.h"
#include "ctsql_select.h"
#include "ctsql_aggr.h"
#include "srv_instance.h"

#define MAX_PAGE_LIST 16384

typedef struct st_aggr_count {
    bool32 has_distinct;
    hash_segment_t ex_hash_segment;
    hash_table_entry_t ex_table_entry;
} aggr_count_t;

#define GET_AGGR_VAR_COUNT(aggr_var)                                                                     \
    ((aggr_count_t *)(((aggr_var)->extra_offset == 0 || (aggr_var)->extra_offset >= CT_VMEM_PAGE_SIZE || \
        (aggr_var)->extra_size != sizeof(aggr_count_t) || (aggr_var)->aggr_type != AGGR_TYPE_COUNT) ?    \
        NULL :                                                                                           \
        ((char *)(aggr_var) + (aggr_var)->extra_offset)))

#define IS_WINSORT_SUPPORT_RESERVED(res_id)                                                                  \
    ((res_id) == RES_WORD_ROWID || (res_id) == RES_WORD_ROWNUM || (res_id) == RES_WORD_ROWSCN ||             \
        (res_id) == RES_WORD_LEVEL || (res_id) == RES_WORD_CONNECT_BY_ISLEAF || (res_id) == RES_WORD_NULL || \
        (res_id) == RES_WORD_CURDATE || (res_id) == RES_WORD_CURTIMESTAMP || (res_id) == RES_WORD_SYSDATE)

typedef struct st_winsort_slider {
    aggr_var_t *curr_var;
    mtrl_rowid_t rid;
} winsort_slider_t;

static inline status_t sql_win_aggr_stack_alloc(sql_stmt_t *stmt, sql_aggr_type_t aggr_type, uint32 extra_size,
    void **buf)
{
    CT_RETURN_IFERR(sql_push(stmt, sizeof(aggr_var_t) + extra_size, buf));
    ((aggr_var_t *)(*buf))->extra_offset = extra_size > 0 ? sizeof(aggr_var_t) : 0;
    ((aggr_var_t *)(*buf))->extra_size = extra_size;
    ((aggr_var_t *)(*buf))->aggr_type = aggr_type;
    return CT_SUCCESS;
}

static inline status_t sql_stack_alloc_aggr_var(sql_stmt_t *stmt, sql_aggr_type_t type, void **buf)
{
    switch (type) {
        case AGGR_TYPE_MIN:
        case AGGR_TYPE_MAX:
            return sql_win_aggr_stack_alloc(stmt, type, sizeof(aggr_str_t), buf);

        case AGGR_TYPE_COVAR_POP:
        case AGGR_TYPE_COVAR_SAMP:
            return sql_win_aggr_stack_alloc(stmt, type, sizeof(aggr_covar_t), buf);

        case AGGR_TYPE_STDDEV:
        case AGGR_TYPE_STDDEV_POP:
        case AGGR_TYPE_STDDEV_SAMP:
        case AGGR_TYPE_VARIANCE:
        case AGGR_TYPE_VAR_POP:
        case AGGR_TYPE_VAR_SAMP:
            return sql_win_aggr_stack_alloc(stmt, type, sizeof(aggr_stddev_t), buf);

        case AGGR_TYPE_CORR:
            return sql_win_aggr_stack_alloc(stmt, type, sizeof(aggr_corr_t), buf);

        case AGGR_TYPE_SUM:
        case AGGR_TYPE_LAG:
        case AGGR_TYPE_LAST_VALUE:
            return sql_win_aggr_stack_alloc(stmt, type, 0, buf);

        case AGGR_TYPE_FIRST_VALUE:
            return sql_win_aggr_stack_alloc(stmt, type, sizeof(aggr_fir_val_t), buf);

        case AGGR_TYPE_COUNT:
            return sql_win_aggr_stack_alloc(stmt, type, sizeof(aggr_count_t), buf);

        case AGGR_TYPE_AVG:
            return sql_win_aggr_stack_alloc(stmt, type, sizeof(aggr_avg_t), buf);

        default:
            return CT_ERROR;
    }
}

static inline void sql_winsort_release_pages(sql_stmt_t *stmt, uint32 seg_id, uint32 *maps, uint32 max_pages)
{
    if (seg_id == CT_INVALID_ID32) {
        return;
    }

    mtrl_win_release_segment(&stmt->mtrl, seg_id, maps, max_pages);
}

static inline status_t sql_copy_aggr(sql_aggr_type_t type, aggr_var_t *src, aggr_var_t *dest)
{
    if (src->extra_offset == 0 || src->extra_offset >= CT_VMEM_PAGE_SIZE || src->extra_size == 0) {
        MEMS_RETURN_IFERR(memcpy_s(dest, sizeof(aggr_var_t), src, sizeof(aggr_var_t)));
        return CT_SUCCESS;
    }

    switch (type) {
        case AGGR_TYPE_MIN:
        case AGGR_TYPE_MAX:
            MEMS_RETURN_IFERR(memcpy_s(&dest->var, sizeof(variant_t), &src->var, sizeof(variant_t)));
            MEMS_RETURN_IFERR(
                memcpy_s(GET_AGGR_VAR_STR(dest), sizeof(aggr_str_t), GET_AGGR_VAR_STR(src), sizeof(aggr_str_t)));
            break;
        case AGGR_TYPE_COVAR_POP:
        case AGGR_TYPE_COVAR_SAMP:
            MEMS_RETURN_IFERR(memcpy_s(&dest->var, sizeof(variant_t), &src->var, sizeof(variant_t)));
            MEMS_RETURN_IFERR(memcpy_s(GET_AGGR_VAR_COVAR(dest), sizeof(aggr_covar_t), GET_AGGR_VAR_COVAR(src),
                sizeof(aggr_covar_t)));
            break;
        case AGGR_TYPE_CORR:
            MEMS_RETURN_IFERR(memcpy_s(&dest->var, sizeof(variant_t), &src->var, sizeof(variant_t)));
            MEMS_RETURN_IFERR(
                memcpy_s(GET_AGGR_VAR_CORR(dest), sizeof(aggr_corr_t), GET_AGGR_VAR_CORR(src), sizeof(aggr_corr_t)));
            break;
        case AGGR_TYPE_STDDEV:
        case AGGR_TYPE_STDDEV_POP:
        case AGGR_TYPE_STDDEV_SAMP:
        case AGGR_TYPE_VARIANCE:
        case AGGR_TYPE_VAR_POP:
        case AGGR_TYPE_VAR_SAMP:
            MEMS_RETURN_IFERR(memcpy_s(&dest->var, sizeof(variant_t), &src->var, sizeof(variant_t)));
            MEMS_RETURN_IFERR(memcpy_s(GET_AGGR_VAR_STDDEV(dest), sizeof(aggr_stddev_t), GET_AGGR_VAR_STDDEV(src),
                sizeof(aggr_stddev_t)));
            break;
        case AGGR_TYPE_FIRST_VALUE:
            GET_AGGR_VAR_FIR_VAL(dest)->ex_has_val = GET_AGGR_VAR_FIR_VAL(src)->ex_has_val;
            // don't break
        case AGGR_TYPE_SUM:
        case AGGR_TYPE_LAG:
        case AGGR_TYPE_GROUP_CONCAT:
            MEMS_RETURN_IFERR(memcpy_s(dest, sizeof(aggr_var_t), src, sizeof(aggr_var_t)));
            break;

        case AGGR_TYPE_COUNT:
            MEMS_RETURN_IFERR(memcpy_s(&dest->var, sizeof(variant_t), &src->var, sizeof(variant_t)));
            MEMS_RETURN_IFERR(memcpy_s(GET_AGGR_VAR_COUNT(dest), sizeof(aggr_count_t), GET_AGGR_VAR_COUNT(src),
                sizeof(aggr_count_t)));
            break;
        case AGGR_TYPE_AVG:
            GET_AGGR_VAR_AVG(dest)->ex_avg_count = GET_AGGR_VAR_AVG(src)->ex_avg_count;
            MEMS_RETURN_IFERR(memcpy_s(&dest->var, sizeof(variant_t), &src->var, sizeof(variant_t)));
            break;

        default:
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

static inline uint32 sql_win_page_max_count(void)
{
    return (CT_VMEM_PAGE_SIZE - sizeof(uint32) - sizeof(mtrl_page_t)) / sizeof(winsort_slider_t);
}

static inline status_t sql_win_slider_alloc(sql_stmt_t *stmt, uint32 seg_id, uint32 len, mtrl_rowid_t *rid)
{
    winsort_slider_t *var = NULL;
    CT_RETURN_IFERR(mtrl_win_aggr_alloc(&stmt->mtrl, seg_id, (void **)&var, len, rid, CT_FALSE));
    MEMS_RETURN_IFERR(memset_s(var, len, 0, len));
    return CT_SUCCESS;
}

static inline void get_page_and_offset(uint32 act_count, uint32 max_count, uint32 param_offset, uint32 ind, uint32 *idx,
    uint32 *offset)
{
    if (act_count < max_count) {
        *idx = 0;
        *offset = ind % act_count;
    } else {
        *idx = (uint32)((ind % param_offset) / act_count);
        *offset = (uint32)((ind % param_offset) % act_count);
    }
}

static inline status_t get_page_from_maps(sql_stmt_t *stmt, uint32 seg_id, winsort_slider_t **aggr_silder, uint32 *maps,
    uint32 idx)
{
    mtrl_rowid_t page_rid;
    char *row = NULL;

    if (idx > MAX_PAGE_LIST) {
        return CT_ERROR;
    }

    page_rid.slot = 0;
    page_rid.vmid = maps[idx];
    if (mtrl_win_aggr_get(&stmt->mtrl, seg_id, (char **)&row, &page_rid, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    *aggr_silder = (winsort_slider_t *)row;
    return CT_SUCCESS;
}

static inline status_t sql_win_aggr_page_alloc(sql_stmt_t *stmt, sql_aggr_type_t aggr_type, sql_cursor_t *cursor,
    aggr_var_t **aggr_var, uint32 extra_size, mtrl_rowid_t *rid)
{
    CT_RETURN_IFERR(mtrl_win_aggr_alloc(&stmt->mtrl, cursor->mtrl.winsort_aggr.sid, (void **)aggr_var,
        sizeof(aggr_var_t) + extra_size, rid, CT_TRUE));
    MEMS_RETURN_IFERR(memset_s(*aggr_var, sizeof(aggr_var_t) + extra_size, 0, sizeof(aggr_var_t) + extra_size));
    (*aggr_var)->extra_offset = extra_size > 0 ? sizeof(aggr_var_t) : 0;
    (*aggr_var)->extra_size = extra_size;
    (*aggr_var)->aggr_type = aggr_type;
    return CT_SUCCESS;
}

static inline status_t sql_win_aggr_count_alloc(sql_stmt_t *stmt, sql_aggr_type_t aggr_type, expr_tree_t *func_expr,
    sql_cursor_t *cursor, aggr_var_t **aggr_var, mtrl_rowid_t *rid)
{
    CT_RETURN_IFERR(sql_win_aggr_page_alloc(stmt, aggr_type, cursor, aggr_var, sizeof(aggr_count_t), rid));

    aggr_count_t *data = GET_AGGR_VAR_COUNT(*aggr_var);
    CT_RETVALUE_IFTRUE(data == NULL, CT_ERROR);

    data->has_distinct = func_expr->root->dis_info.need_distinct;
    if (data->has_distinct) {
        vm_hash_segment_init(&stmt->session->knl_session, stmt->mtrl.pool, &data->ex_hash_segment, PMA_POOL,
            HASH_PAGES_HOLD, HASH_AREA_SIZE);
        data->ex_table_entry.vmid = CT_INVALID_ID32;
        data->ex_table_entry.offset = CT_INVALID_ID32;

        CT_RETURN_IFERR(vm_hash_table_alloc(&data->ex_table_entry, &data->ex_hash_segment, 0));
        CT_RETURN_IFERR(vm_hash_table_init(&data->ex_hash_segment, &data->ex_table_entry, NULL, NULL, NULL));
    }
    return CT_SUCCESS;
}

static inline status_t sql_win_aggr_alloc(sql_stmt_t *stmt, sql_aggr_type_t aggr_type, sql_cursor_t *cursor,
    aggr_var_t **aggr_var, mtrl_rowid_t *rid)
{
    switch (aggr_type) {
        case AGGR_TYPE_MIN:
        case AGGR_TYPE_MAX:
            return sql_win_aggr_page_alloc(stmt, aggr_type, cursor, aggr_var, sizeof(aggr_str_t), rid);

        case AGGR_TYPE_STDDEV:
        case AGGR_TYPE_STDDEV_POP:
        case AGGR_TYPE_STDDEV_SAMP:
        case AGGR_TYPE_VARIANCE:
        case AGGR_TYPE_VAR_POP:
        case AGGR_TYPE_VAR_SAMP:
            return sql_win_aggr_page_alloc(stmt, aggr_type, cursor, aggr_var, sizeof(aggr_stddev_t), rid);
        case AGGR_TYPE_COVAR_POP:
        case AGGR_TYPE_COVAR_SAMP:
            return sql_win_aggr_page_alloc(stmt, aggr_type, cursor, aggr_var, sizeof(aggr_covar_t), rid);
        case AGGR_TYPE_CORR:
            return sql_win_aggr_page_alloc(stmt, aggr_type, cursor, aggr_var, sizeof(aggr_corr_t), rid);
        case AGGR_TYPE_SUM:
        case AGGR_TYPE_LAG:
        case AGGR_TYPE_GROUP_CONCAT:
        case AGGR_TYPE_LAST_VALUE:
            return sql_win_aggr_page_alloc(stmt, aggr_type, cursor, aggr_var, 0, rid);

        case AGGR_TYPE_FIRST_VALUE:
            return sql_win_aggr_page_alloc(stmt, aggr_type, cursor, aggr_var, sizeof(aggr_fir_val_t), rid);

        case AGGR_TYPE_AVG:
            return sql_win_aggr_page_alloc(stmt, aggr_type, cursor, aggr_var, sizeof(aggr_avg_t), rid);

        case AGGR_TYPE_NTILE:
        case AGGR_TYPE_CUME_DIST:
            return sql_win_aggr_page_alloc(stmt, aggr_type, cursor, aggr_var, sizeof(mtrl_rowid_t), rid);

        default:
            return CT_ERROR;
    }
}

static inline status_t sql_win_aggr_var_alloc(sql_stmt_t *stmt, sql_aggr_type_t aggr_type, sql_cursor_t *cursor,
    aggr_var_t **aggr_var, ct_type_t datatype, mtrl_rowid_t *rid, expr_tree_t *func_expr)
{
    if (aggr_type == AGGR_TYPE_COUNT) {
        CT_RETURN_IFERR(sql_win_aggr_count_alloc(stmt, aggr_type, func_expr, cursor, aggr_var, rid));
    } else {
        CT_RETURN_IFERR(sql_win_aggr_alloc(stmt, aggr_type, cursor, aggr_var, rid));
    }
    (*aggr_var)->var.is_null = CT_TRUE;
    (*aggr_var)->var.type = datatype;
    return CT_SUCCESS;
}

static inline status_t sql_win_aggr_append_data_ext(sql_stmt_t *stmt, sql_cursor_t *cursor, aggr_var_t *aggr_var,
    char *data, uint32 size)
{
    mtrl_rowid_t rid;
    aggr_var_t *agg_var_next = NULL;
    uint32 aggr_size = sizeof(aggr_var_t) + aggr_var->extra_size;
    uint32 total_size = aggr_size + size;

    CT_RETURN_IFERR(mtrl_win_aggr_alloc(&stmt->mtrl, cursor->mtrl.winsort_aggr_ext.sid, (void **)&agg_var_next,
        total_size, &rid, CT_TRUE));
    agg_var_next->aggr_type = aggr_var->aggr_type;
    agg_var_next->extra_offset = sizeof(aggr_var_t);
    agg_var_next->extra_size = aggr_size - sizeof(aggr_var_t);
    CT_RETURN_IFERR(sql_copy_aggr(aggr_var->aggr_type, aggr_var, agg_var_next));
    MEMS_RETURN_IFERR(memcpy_s((char *)agg_var_next + aggr_size, size, data, size));
    aggr_var->var.type = CT_TYPE_VM_ROWID;
    aggr_var->var.v_vmid.vmid = rid.vmid;
    aggr_var->var.v_vmid.slot = rid.slot;
    return CT_SUCCESS;
}

static inline status_t sql_win_aggr_append_data(sql_stmt_t *stmt, sql_cursor_t *cursor, aggr_var_t *aggr_var)
{
    variant_t inner_var = aggr_var->var;
    if (inner_var.is_null) {
        return CT_SUCCESS;
    }
    switch (inner_var.type) {
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
            if (mtrl_win_cur_page_is_enough(&stmt->mtrl, cursor->mtrl.winsort_aggr.sid, inner_var.v_text.len)) {
                return mtrl_win_aggr_append_data(&stmt->mtrl, cursor->mtrl.winsort_aggr.sid, inner_var.v_text.str,
                    inner_var.v_text.len);
            }
            return sql_win_aggr_append_data_ext(stmt, cursor, aggr_var, inner_var.v_text.str, inner_var.v_text.len);

        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            if (mtrl_win_cur_page_is_enough(&stmt->mtrl, cursor->mtrl.winsort_aggr.sid, inner_var.v_bin.size)) {
                return mtrl_win_aggr_append_data(&stmt->mtrl, cursor->mtrl.winsort_aggr.sid,
                    (char *)inner_var.v_bin.bytes, inner_var.v_bin.size);
            }
            return sql_win_aggr_append_data_ext(stmt, cursor, aggr_var, (char *)inner_var.v_bin.bytes,
                inner_var.v_bin.size);
        default:
            return CT_SUCCESS;
    }
}

static inline void sql_win_aggr_ntile_set_row(mtrl_segment_t *segment, mtrl_rowid_t *rid, int64 *value, int64 *bucket)
{
    mtrl_page_t *page = NULL;
    char *row = NULL;
    int64 *in_value = NULL;

    page = (mtrl_page_t *)segment->curr_page->data;
    row = (char *)MTRL_GET_ROW(page, rid->slot);

    in_value = (int64 *)row;
    *in_value = *value;
    in_value = (int64 *)((char *)row + sizeof(int64));
    *in_value = *bucket;
}

static inline status_t sql_win_aggr_ntile_set(sql_stmt_t *stmt, mtrl_rowid_t *rid, int64 *group, int64 *bucket,
    uint32 seg_id)
{
    mtrl_context_t *ctx = &stmt->mtrl;
    mtrl_segment_t *segment = ctx->segments[seg_id];
    vm_page_t *tmp_page = NULL;
    CM_POINTER(segment->curr_page);

    if (segment->curr_page->vmid != rid->vmid) {
        tmp_page = segment->curr_page;
        segment->curr_page = NULL;
        if (mtrl_open_page(ctx, rid->vmid, &segment->curr_page) != CT_SUCCESS) {
            segment->curr_page = tmp_page;
            return CT_ERROR;
        }

        sql_win_aggr_ntile_set_row(segment, rid, group, bucket);

        mtrl_close_page(ctx, segment->curr_page->vmid);
        segment->curr_page = tmp_page;
    } else {
        sql_win_aggr_ntile_set_row(segment, rid, group, bucket);
    }
    return CT_SUCCESS;
}

typedef status_t (*winsort_invoke_func_t)(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan);
typedef status_t (*winsort_verify_func_t)(sql_verifier_t *verifier, expr_node_t *winsort);
typedef void (*winsort_default_func_t)(variant_t *value);
typedef status_t (*winsort_actual_func_t)(sql_stmt_t *stmt, sql_cursor_t *cursor, expr_node_t *node, variant_t *value);

typedef struct st_winsort_func {
    text_t name;
    winsort_invoke_func_t invoke;
    winsort_verify_func_t verify;
    winsort_default_func_t default_val;
    winsort_actual_func_t actual_val;
} winsort_func_t;

status_t sql_win_aggr_get(sql_stmt_t *stmt, sql_cursor_t *cursor, mtrl_rowid_t *rid, variant_t *value, uint32 seg_id);
status_t sql_get_winsort_func_id(sql_text_t *func_name, var_func_t *v);
winsort_func_t *sql_get_winsort_func(var_func_t *v_func);
status_t sql_fetch_winsort(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);
status_t sql_execute_winsort(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan);
status_t sql_get_winsort_value(sql_stmt_t *stmt, expr_node_t *node, variant_t *value);
status_t sql_send_sort_row_filter(sql_stmt_t *stmt, sql_cursor_t *cursor, bool32 *is_full);
void sql_winsort_func_binsearch(sql_text_t *func_name, var_func_t *v);
void sql_winsort_aggr_value_null(aggr_var_t *aggr_var, expr_tree_t *func_expr, sql_aggr_type_t aggr_type,
    variant_t *result);
status_t sql_get_winsort_aggr_value(aggr_assist_t *aggr_ass, aggr_var_t *aggr_var, const char *buf, variant_t *vars,
                                    variant_t *result);
status_t sql_winsort_aggr_value_end(sql_stmt_t *stmt, sql_aggr_type_t aggr_type, sql_cursor_t *cursor,
    aggr_var_t *aggr_result);
status_t sql_winsort_get_aggr_type(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_aggr_type_t type, expr_tree_t *func_expr,
    ct_type_t *datatype);

static inline const char *sql_get_winsort_border_name(uint32 type)
{
    switch (type) {
        case WB_TYPE_UNBOUNDED_PRECED:
            return "UNBOUNDED PRECEDING";
        case WB_TYPE_VALUE_PRECED:
            return " PRECEDING";
        case WB_TYPE_CURRENT_ROW:
            return "CURRENT ROW";
        case WB_TYPE_VALUE_FOLLOW:
            return " FOLLOWING";
        case WB_TYPE_UNBOUNDED_FOLLOW:
            return "UNBOUNDED FOLLOWING";
        default:
            return " ";
    }
}

#endif
