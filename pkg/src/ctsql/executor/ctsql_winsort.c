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
 * ctsql_winsort.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_winsort.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_aggr.h"
#include "ctsql_proj.h"
#include "ctsql_select.h"
#include "ctsql_mtrl.h"
#include "ctsql_winsort.h"
#include "srv_instance.h"
#include "ctsql_winsort_window.h"

#define MAX_WINSORT_SIZE 8

typedef struct st_winsort_pair {
    bool32 need_free;
    plan_node_t *plan;
    sql_cursor_t *cursor;
} winsort_pair_t;

typedef struct st_winsort_assist {
    uint32 count;
    winsort_pair_t pairs[MAX_WINSORT_SIZE];
} winsort_assist_t;

static status_t sql_win_set_aggr_value(sql_stmt_t *stmt, variant_t *var, variant_t *result, const char *buf)
{
    switch (result->type) {
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_BIGINT:
        case CT_TYPE_REAL:
        case CT_TYPE_NUMBER:
        case CT_TYPE_NUMBER2:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_TZ:
        case CT_TYPE_TIMESTAMP_LTZ:
        case CT_TYPE_INTERVAL_DS:
        case CT_TYPE_INTERVAL_YM:
            *result = *var;
            break;

        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
            if (var->v_text.len == 0) {
                return CT_SUCCESS;
            } else if (var->v_text.len > CT_MAX_ROW_SIZE) {
                CT_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, var->v_text.len, CT_MAX_ROW_SIZE);
                return CT_ERROR;
            }
            result->v_text.str = (char *)((result->v_text.str == NULL) ? buf : result->v_text.str);
            MEMS_RETURN_IFERR(memcpy_s(result->v_text.str, CT_MAX_ROW_SIZE, var->v_text.str, var->v_text.len));
            result->v_text.len = var->v_text.len;
            break;

        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            if (var->v_bin.size == 0) {
                return CT_SUCCESS;
            } else if (var->v_bin.size > CT_MAX_ROW_SIZE) {
                CT_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, var->v_bin.size, CT_MAX_ROW_SIZE);
                return CT_ERROR;
            }
            result->v_text.str = (char *)((result->v_text.str == NULL) ? buf : result->v_text.str);
            MEMS_RETURN_IFERR(memcpy_s(result->v_bin.bytes, CT_MAX_ROW_SIZE, var->v_bin.bytes, var->v_bin.size));

            result->v_bin.size = var->v_bin.size;
            break;

        default:
            CT_SET_ERROR_MISMATCH_EX(result->type);
            return CT_ERROR;
    }
    return CT_SUCCESS;
}

static inline status_t sql_win_aggr_last_value(sql_stmt_t *stmt, variant_t *res, variant_t *var, const char *buf,
    bool8 ignore_nulls)
{
    res->is_null = var->is_null;
    return sql_win_set_aggr_value(stmt, var, res, buf);
}

static status_t sql_win_aggr_min_or_max(sql_stmt_t *stmt, sql_aggr_type_t type, variant_t *result, variant_t *var,
    const char *buf)
{
    int32 cmp_result;

    if (result->type != var->type) {
        CT_RETURN_IFERR(sql_convert_variant(stmt, var, result->type));
    }

    if (result->is_null) {
        result->is_null = CT_FALSE;
        return sql_win_set_aggr_value(stmt, var, result, buf);
    }

    CT_RETURN_IFERR(sql_compare_variant(stmt, result, var, &cmp_result));

    if ((type == AGGR_TYPE_MIN && cmp_result > 0) || (type == AGGR_TYPE_MAX && cmp_result < 0)) {
        return sql_win_set_aggr_value(stmt, var, result, buf);
    }
    return CT_SUCCESS;
}

static status_t sql_win_aggr_count(sql_stmt_t *stmt, aggr_var_t *aggr_var, variant_t *var)
{
    char *buf = NULL;
    row_assist_t ra;
    bool32 var_exist = CT_FALSE;
    variant_t *result = &aggr_var->var;
    aggr_count_t *data = GET_AGGR_VAR_COUNT(aggr_var);
    CT_RETVALUE_IFTRUE(data == NULL, CT_ERROR);

    if (data->has_distinct) {
        CTSQL_SAVE_STACK(stmt);
        sql_keep_stack_variant(stmt, var);
        if (sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buf) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }
        row_init(&ra, buf, CT_MAX_ROW_SIZE, 1);
        if (sql_put_row_value(stmt, NULL, &ra, var->type, var) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }
        if (vm_hash_table_insert2(&var_exist, &data->ex_hash_segment, &data->ex_table_entry, buf, ra.head->size) !=
            CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }

        CTSQL_RESTORE_STACK(stmt);
        if (var_exist) {
            return CT_SUCCESS;
        }
    }
    result->is_null = CT_FALSE;
    result->v_bigint++;
    return CT_SUCCESS;
}

static status_t sql_win_aggr_listagg(sql_stmt_t *stmt, expr_node_t *aggr_node, sql_aggr_type_t type,
    aggr_var_t *aggr_var, const char *buf)
{
    variant_t value;
    expr_tree_t *arg = aggr_node->argument;

    CTSQL_SAVE_STACK(stmt);
    aggr_var->var.v_text.str = aggr_var->var.is_null ? (char *)buf : aggr_var->var.v_text.str;

    while (arg != NULL) {
        if (aggr_var->var.is_null) {
            aggr_var->var.is_null = CT_FALSE;
            arg = arg->next;
            continue;
        }
        CT_RETURN_IFERR(sql_exec_expr(stmt, arg, &value));
        if (value.is_null) {
            arg = arg->next;
            continue;
        }
        if (!CT_IS_STRING_TYPE(value.type)) {
            if (sql_var_as_string(stmt, &value) != CT_SUCCESS) {
                CTSQL_RESTORE_STACK(stmt);
                return CT_ERROR;
            }
        }

        if (value.v_text.len + aggr_var->var.v_text.len > CT_MAX_ROW_SIZE) {
            CTSQL_RESTORE_STACK(stmt);
            CT_THROW_ERROR(ERR_EXCEED_MAX_ROW_SIZE, value.v_text.len + aggr_var->var.v_text.len, CT_MAX_ROW_SIZE);
            return CT_ERROR;
        }
        if (value.v_text.len > 0) {
            MEMS_RETURN_IFERR(memcpy_s(aggr_var->var.v_text.str + aggr_var->var.v_text.len,
                CT_MAX_ROW_SIZE - aggr_var->var.v_text.len, value.v_text.str, value.v_text.len));
            aggr_var->var.v_text.len += value.v_text.len;
            aggr_var->var.is_null = CT_FALSE;
        }
        arg = arg->next;
        CTSQL_RESTORE_STACK(stmt);
    }
    return CT_SUCCESS;
}

static status_t sql_win_aggr_lag(sql_stmt_t *stmt, sql_aggr_type_t type, variant_t *result, variant_t *var,
    const char *buf)
{
    CT_RETURN_IFERR(sql_win_set_aggr_value(stmt, var, result, buf));
    return CT_SUCCESS;
}

void sql_winsort_aggr_value_null(aggr_var_t *aggr_var, expr_tree_t *func_expr, sql_aggr_type_t aggr_type,
    variant_t *result)
{
    switch (aggr_type) {
        case AGGR_TYPE_LAG:
            result->is_null = CT_TRUE;
            break;
        case AGGR_TYPE_LAST_VALUE:
            if (!func_expr->root->ignore_nulls) {
                result->is_null = CT_TRUE;
            }
            break;
        case AGGR_TYPE_FIRST_VALUE:
            if (!func_expr->root->ignore_nulls && !GET_AGGR_VAR_FIR_VAL(aggr_var)->ex_has_val) {
                result->is_null = CT_TRUE;
                GET_AGGR_VAR_FIR_VAL(aggr_var)->ex_has_val = CT_TRUE;
            }
            break;
        default:
            break;
    }
}

static inline void sql_winsort_value_set_notnull(variant_t *result)
{
    if (result->is_null) {
        result->is_null = CT_FALSE;
        if (CT_IS_NUMBER_TYPE(result->type)) {
            cm_zero_dec(&result->v_dec);
        }
    }
}

status_t sql_get_winsort_aggr_value(aggr_assist_t *aggr_ass, aggr_var_t *aggr_var, const char *buf, variant_t *vars,
    variant_t *result)
{
    switch (aggr_ass->aggr_type) {
        case AGGR_TYPE_STDDEV:
        case AGGR_TYPE_STDDEV_POP:
        case AGGR_TYPE_STDDEV_SAMP:
        case AGGR_TYPE_VARIANCE:
        case AGGR_TYPE_VAR_POP:
        case AGGR_TYPE_VAR_SAMP:
        case AGGR_TYPE_CORR:
            return sql_aggr_invoke(aggr_ass, aggr_var, vars);
        case AGGR_TYPE_COVAR_POP:
        case AGGR_TYPE_COVAR_SAMP:
            if ((vars[0].is_null) || (vars[1].is_null)) {
                return CT_SUCCESS;
            } else {
                GET_AGGR_VAR_COVAR(aggr_var)->extra.is_null = CT_FALSE;
                GET_AGGR_VAR_COVAR(aggr_var)->extra_1.is_null = CT_FALSE;
                return sql_aggr_invoke(aggr_ass, aggr_var, vars);
            }
        case AGGR_TYPE_AVG:
            GET_AGGR_VAR_AVG(aggr_var)->ex_avg_count++;
            /* fall-through */
        case AGGR_TYPE_SUM:
            sql_winsort_value_set_notnull(result);
            return sql_aggr_sum_value(aggr_ass->stmt, result, vars);

        case AGGR_TYPE_LAG:
            result->is_null = CT_FALSE;
            return sql_win_aggr_lag(aggr_ass->stmt, aggr_ass->aggr_type, result, vars, buf);

        case AGGR_TYPE_FIRST_VALUE:
            if (GET_AGGR_VAR_FIR_VAL(aggr_var)->ex_has_val) {
                return CT_SUCCESS;
            }
            GET_AGGR_VAR_FIR_VAL(aggr_var)->ex_has_val = CT_TRUE;
            return sql_win_aggr_last_value(aggr_ass->stmt, result, vars, buf, aggr_ass->aggr_node->ignore_nulls);

        case AGGR_TYPE_LAST_VALUE:
            return sql_win_aggr_last_value(aggr_ass->stmt, result, vars, buf, aggr_ass->aggr_node->ignore_nulls);

        case AGGR_TYPE_MIN:
        case AGGR_TYPE_MAX:
            return sql_win_aggr_min_or_max(aggr_ass->stmt, aggr_ass->aggr_type, result, vars, buf);

        case AGGR_TYPE_COUNT:
            return sql_win_aggr_count(aggr_ass->stmt, aggr_var, vars);

        case AGGR_TYPE_GROUP_CONCAT:
            return sql_win_aggr_listagg(aggr_ass->stmt, aggr_ass->aggr_node, aggr_ass->aggr_type, aggr_var, buf);

        default:
            return CT_ERROR;
    }
}

static status_t sql_winsort_aggr_value(sql_stmt_t *stmt, sql_aggr_type_t aggr_type, expr_tree_t *func_expr,
    aggr_var_t *aggr_var, const char *buf)
{
    variant_t vars[FO_VAL_MAX - 1];
    variant_t *result = &aggr_var->var;

    CT_RETURN_IFERR(sql_exec_expr(stmt, func_expr->root->argument, &vars[0]));
    if (aggr_type == AGGR_TYPE_CORR || aggr_type == AGGR_TYPE_COVAR_POP || aggr_type == AGGR_TYPE_COVAR_SAMP) {
        CT_RETURN_IFERR(sql_exec_expr(stmt, func_expr->root->argument->next, &vars[1]));
    } else {
        vars[1].is_null = CT_TRUE;
    }
    if (aggr_type == AGGR_TYPE_GROUP_CONCAT) {
        CT_RETURN_IFERR(sql_exec_expr(stmt, func_expr->root->argument->next, &vars[0]));
    }
    if (vars[0].is_null) {
        sql_winsort_aggr_value_null(aggr_var, func_expr, aggr_type, result);
        return CT_SUCCESS;
    }

    aggr_assist_t aggr_ass;
    SQL_INIT_AGGR_ASSIST(&aggr_ass, stmt, NULL);
    aggr_ass.aggr_type = aggr_type;
    aggr_ass.aggr_node = func_expr->root;
    return sql_get_winsort_aggr_value(&aggr_ass, aggr_var, buf, vars, result);
}

static status_t sql_verify_winsort_row_number(sql_verifier_t *verf, expr_node_t *winsort)
{
    expr_node_t *func_node = winsort->argument->root;
    if (winsort->win_args->sort_items == NULL) {
        CT_THROW_ERROR_EX(ERR_NO_ORDER_BY_CLAUSE, "%s", T2S((text_t *)&func_node->word.func.name));
        return CT_ERROR;
    }
    if (winsort->win_args->windowing != NULL) {
        CT_SRC_THROW_ERROR(func_node->loc, ERR_UNSUPPORT_FUNC, "Windowing clause is",
            "in function ROW_NUMBER/RANK/DENSE_RANK");
        return CT_ERROR;
    }
    CT_RETURN_IFERR(sql_verify_func_node(verf, func_node, 0, 0, CT_INVALID_ID32));
    winsort->datatype = CT_TYPE_INTEGER;
    winsort->size = sizeof(uint32);
    return CT_SUCCESS;
}

static inline status_t sql_winsort_calc_aggr(sql_stmt_t *stmt, sql_aggr_type_t type, aggr_var_t *aggr_var)
{
    aggr_assist_t aggr_ass;
    SQL_INIT_AGGR_ASSIST(&aggr_ass, stmt, NULL);
    aggr_ass.aggr_type = type;
    return sql_aggr_calc_value(&aggr_ass, aggr_var);
}

static status_t sql_func_winsort_row_number(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    mtrl_row_t *row = NULL;
    uint32 row_number = 0;
    bool32 grp_changed, ord_changed;
    uint32 rs_col_id = VALUE(uint32, &plan->winsort_p.winsort->value);

    CT_RETURN_IFERR(mtrl_open_cursor(&stmt->mtrl, cursor->mtrl.winsort_sort.sid, &cursor->mtrl.cursor));

    for (;;) {
        SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt);
        CT_RETURN_IFERR(
            mtrl_fetch_winsort_rid(&stmt->mtrl, &cursor->mtrl.cursor, WINSORT_PART, &grp_changed, &ord_changed));
        if (cursor->mtrl.cursor.eof) {
            break;
        }

        row = &cursor->mtrl.cursor.row;
        if (row->lens[rs_col_id] != sizeof(uint32)) {
            CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "row->lens[rs_col_id](%u) == sizeof(uint32)",
                (uint32)row->lens[rs_col_id]);
            return CT_ERROR;
        }
        *(uint32 *)(row->data + row->offsets[rs_col_id]) = ++row_number;
        row_number = grp_changed ? 0 : row_number;
    }
    mtrl_close_cursor(&stmt->mtrl, &cursor->mtrl.cursor);
    return CT_SUCCESS;
}

static status_t sql_func_winsort_dense_rank(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    mtrl_row_t *row = NULL;
    bool32 grp_changed, ord_changed;
    uint32 rs_col_id = VALUE(uint32, &plan->winsort_p.winsort->value);
    uint32 dense_rank = 1;

    CT_RETURN_IFERR(mtrl_open_cursor(&stmt->mtrl, cursor->mtrl.winsort_sort.sid, &cursor->mtrl.cursor));

    for (;;) {
        SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt);
        CT_RETURN_IFERR(mtrl_fetch_winsort_rid(&stmt->mtrl, &cursor->mtrl.cursor, WINSORT_PART | WINSORT_ORDER,
            &grp_changed, &ord_changed));
        if (cursor->mtrl.cursor.eof) {
            break;
        }

        row = &cursor->mtrl.cursor.row;
        if (row->lens[rs_col_id] != sizeof(uint32)) {
            CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "row->lens[rs_col_id](%u) == sizeof(uint32)",
                (uint32)row->lens[rs_col_id]);
            return CT_ERROR;
        }

        *(uint32 *)(row->data + row->offsets[rs_col_id]) = dense_rank;
        if (ord_changed) {
            dense_rank++;
        }
        dense_rank = grp_changed ? 1 : dense_rank;
    }
    mtrl_close_cursor(&stmt->mtrl, &cursor->mtrl.cursor);
    return CT_SUCCESS;
}

static status_t sql_func_winsort_rank(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    mtrl_row_t *row = NULL;
    bool32 grp_changed, ord_changed;
    uint32 rs_col_id = VALUE(uint32, &plan->winsort_p.winsort->value);
    uint32 rank = 1;
    uint32 equal_cnt = 1;
    bool32 last_changed = CT_FALSE;

    CT_RETURN_IFERR(mtrl_open_cursor(&stmt->mtrl, cursor->mtrl.winsort_sort.sid, &cursor->mtrl.cursor));

    for (;;) {
        SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt);
        CT_RETURN_IFERR(mtrl_fetch_winsort_rid(&stmt->mtrl, &cursor->mtrl.cursor, WINSORT_PART | WINSORT_ORDER,
            &grp_changed, &ord_changed));
        if (cursor->mtrl.cursor.eof) {
            break;
        }

        row = &cursor->mtrl.cursor.row;
        if (row->lens[rs_col_id] != sizeof(uint32)) {
            CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "row->lens[rs_col_id](%u) == sizeof(uint32)",
                (uint32)row->lens[rs_col_id]);
            return CT_ERROR;
        }

        if (last_changed) {
            rank += equal_cnt;
            equal_cnt = 1;
        }
        *(uint32 *)(row->data + row->offsets[rs_col_id]) = rank;

        if (ord_changed) {
            last_changed = CT_TRUE;
        } else {
            equal_cnt++;
            last_changed = CT_FALSE;
        }

        if (grp_changed) {
            rank = 1;
            equal_cnt = 1;
            last_changed = CT_FALSE;
        }
    }
    mtrl_close_cursor(&stmt->mtrl, &cursor->mtrl.cursor);
    return CT_SUCCESS;
}

static inline void sql_winsort_row_number_default(variant_t *value)
{
    value->type = CT_TYPE_INTEGER;
    value->is_null = CT_FALSE;
    value->v_int = 0;
}

static inline status_t sql_winsort_row_number_actual(sql_stmt_t *stmt, sql_cursor_t *cursor, expr_node_t *node,
    variant_t *value)
{
    uint32 id = VALUE(uint32, &node->value);
    mtrl_row_assist_t row_assist;
    mtrl_row_init(&row_assist, &cursor->mtrl.cursor.row);
    return mtrl_get_column_value(&row_assist, cursor->mtrl.cursor.eof, id, CT_TYPE_INTEGER, CT_FALSE, value);
}

static inline int64 sql_func_ntile_bucket(int64 row_num, int64 count, int64 bucket_count)
{
    int64 temp = count / bucket_count;
    int64 each_group_count;
    int64 bucket_plus_count;
    if (temp >= 1) {
        each_group_count = temp;
        bucket_plus_count = count % bucket_count;
    } else {
        each_group_count = 1;
        bucket_plus_count = 0;
    }
    if (bucket_plus_count * (each_group_count + 1) >= row_num) {
        return (row_num - 1) / (each_group_count + 1) + 1;
    } else {
        return (row_num - bucket_plus_count - 1) / each_group_count + 1;
    }
}

static inline status_t sql_win_aggr_get_ntile(sql_stmt_t *stmt, sql_cursor_t *cursor, mtrl_rowid_t *mtrl_rid,
    variant_t *value)
{
    char *row = NULL;
    int64 *group = NULL;
    variant_t row_number;
    int64 *bucket_count = NULL;
    if (mtrl_win_aggr_get(&stmt->mtrl, cursor->mtrl.winsort_aggr.sid, (char **)&row, mtrl_rid, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    row_number = ((aggr_var_t *)row)->var;
    mtrl_rowid_t group_rowid_addr = *(mtrl_rowid_t *)(row + sizeof(aggr_var_t));
    if (mtrl_win_aggr_get(&stmt->mtrl, cursor->mtrl.winsort_aggr.sid, (char **)&group, &group_rowid_addr, CT_TRUE) !=
        CT_SUCCESS) {
        return CT_ERROR;
    }
    bucket_count = (int64 *)((char *)group + sizeof(int64));
    value->v_bigint = sql_func_ntile_bucket(row_number.v_bigint, *group, *bucket_count);
    value->is_null = CT_FALSE;
    value->type = CT_TYPE_BIGINT;
    return CT_SUCCESS;
}

static inline status_t sql_winsort_ntile_actual(sql_stmt_t *stmt, sql_cursor_t *cursor, expr_node_t *node,
    variant_t *value)
{
    uint32 id = VALUE(uint32, &node->value);
    mtrl_rowid_t mtrl_rid;
    mtrl_row_t *row = NULL;

    row = &cursor->mtrl.cursor.row;
    if (row->lens[id] != sizeof(mtrl_rowid_t)) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "row->lens[id](%u) == sizeof(mtrl_rowid_t)(%u)", (uint32)row->lens[id],
            (uint32)sizeof(mtrl_rowid_t));
        return CT_ERROR;
    }
    mtrl_rid = *(mtrl_rowid_t *)(row->data + row->offsets[id]);
    return sql_win_aggr_get_ntile(stmt, cursor, &mtrl_rid, value);
}

static status_t sql_verify_winsort_sum(sql_verifier_t *verif, expr_node_t *winsort)
{
    uint32 excl_flags = verif->excl_flags;
    expr_node_t *func_node = winsort->argument->root;

    verif->excl_flags = excl_flags | SQL_EXCL_STAR | SQL_EXCL_AGGR;

    CT_RETURN_IFERR(sql_verify_func_node(verif, func_node, 1, 1, CT_INVALID_ID32));

    verif->excl_flags = excl_flags;

    CT_RETURN_IFERR(opr_infer_type_sum(func_node->argument->root->datatype, &func_node->typmod));

    winsort->typmod = func_node->typmod;
    return CT_SUCCESS;
}

static inline status_t sql_winsort_calc_avg(sql_stmt_t *stmt, aggr_var_t *aggr_result)
{
    variant_t v_rows;

    if (aggr_result->var.is_null) {
        return CT_SUCCESS;
    }
    v_rows.type = CT_TYPE_BIGINT;
    v_rows.is_null = CT_FALSE;
    v_rows.v_bigint = (int64)GET_AGGR_VAR_AVG(aggr_result)->ex_avg_count;
    if (v_rows.v_bigint <= 0) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "v_rows.v_bigint(%lld) > 0", v_rows.v_bigint);
        return CT_ERROR;
    }
    return opr_exec(OPER_TYPE_DIV, SESSION_NLS(stmt), &aggr_result->var, &v_rows, &aggr_result->var);
}

static inline status_t sql_winsort_count_end(sql_stmt_t *stmt, aggr_var_t *aggr_result)
{
    aggr_count_t *data = GET_AGGR_VAR_COUNT(aggr_result);
    CT_RETVALUE_IFTRUE(data == NULL, CT_ERROR);
    if (data->has_distinct) {
        vm_hash_segment_deinit(&data->ex_hash_segment);
    }

    if (aggr_result->var.is_null) {
        aggr_result->var.is_null = CT_FALSE;
        aggr_result->var.v_bigint = 0;
    }
    return CT_SUCCESS;
}

status_t sql_winsort_aggr_value_end(sql_stmt_t *stmt, sql_aggr_type_t aggr_type, sql_cursor_t *cursor,
    aggr_var_t *aggr_result)
{
    switch (aggr_type) {
        case AGGR_TYPE_STDDEV:
        case AGGR_TYPE_STDDEV_POP:
        case AGGR_TYPE_STDDEV_SAMP:
        case AGGR_TYPE_VARIANCE:
        case AGGR_TYPE_VAR_POP:
        case AGGR_TYPE_VAR_SAMP:
        case AGGR_TYPE_COVAR_POP:
        case AGGR_TYPE_COVAR_SAMP:
        case AGGR_TYPE_CORR:
            return sql_winsort_calc_aggr(stmt, aggr_type, aggr_result);

        case AGGR_TYPE_AVG:
            return sql_winsort_calc_avg(stmt, aggr_result);

        case AGGR_TYPE_COUNT:
            return sql_winsort_count_end(stmt, aggr_result);

        default:
            return sql_win_aggr_append_data(stmt, cursor, aggr_result);
    }
}

status_t sql_winsort_get_aggr_type(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_aggr_type_t type, expr_tree_t *func_expr,
    ct_type_t *datatype)
{
    variant_t value;
    if (*datatype != CT_TYPE_UNKNOWN) {
        return CT_SUCCESS;
    }

    switch (type) {
        case AGGR_TYPE_LAG:
        case AGGR_TYPE_AVG:
        case AGGR_TYPE_FIRST_VALUE:
        case AGGR_TYPE_LAST_VALUE:
        case AGGR_TYPE_MIN:
        case AGGR_TYPE_MAX:
            if (func_expr->root->argument->root->type != EXPR_NODE_GROUP) {
                CT_RETURN_IFERR(sql_exec_expr(stmt, func_expr->root->argument, &value));
                *datatype = value.type;
            } else {
                var_vm_col_t *v_vm_col = VALUE_PTR(var_vm_col_t, &func_expr->root->argument->root->value);
                ct_type_t *types = (ct_type_t *)((char *)cursor->mtrl.winsort_rs.buf + sizeof(uint32));
                *datatype = types[v_vm_col->id];
            }
            break;
        default:
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "cannot get aggregation datatype");
    }
    return CT_SUCCESS;
}

static status_t sql_func_winsort_aggr_default(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan,
    sql_aggr_type_t type, const char *buf)
{
    mtrl_row_t *row = NULL;
    aggr_var_t *old_aggr = NULL;
    mtrl_rowid_t mtrl_rid;
    aggr_var_t *aggr_result = NULL;
    bool32 grp_changed, ord_changed;
    status_t status = CT_ERROR;
    sql_cursor_t *query_cursor = CTSQL_CURR_CURSOR(stmt);
    uint32 rs_col_id = VALUE(uint32, &plan->winsort_p.winsort->value);
    expr_tree_t *func = plan->winsort_p.winsort->argument;
    ct_type_t datatype = func->root->datatype;
    uint32 cmp_flag = (type == AGGR_TYPE_GROUP_CONCAT) ? WINSORT_PART : (WINSORT_PART | WINSORT_ORDER);

    CT_RETURN_IFERR(sql_winsort_get_aggr_type(stmt, cursor, type, func, &datatype));
    CT_RETURN_IFERR(sql_win_aggr_var_alloc(stmt, type, query_cursor, &aggr_result, datatype, &mtrl_rid, func));
    CT_RETURN_IFERR(mtrl_open_cursor(&stmt->mtrl, cursor->mtrl.winsort_sort.sid, &cursor->mtrl.cursor));
    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));

    for (;;) {
        SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt);
        CT_BREAK_IF_ERROR(mtrl_fetch_winsort_rid(&stmt->mtrl, &cursor->mtrl.cursor, cmp_flag, &grp_changed, &ord_changed));
        if (cursor->mtrl.cursor.eof) {
            status = sql_winsort_aggr_value_end(stmt, type, query_cursor, aggr_result);
            break;
        }
        row = &cursor->mtrl.cursor.row;
        if (row->lens[rs_col_id] != sizeof(mtrl_rowid_t)) {
            CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "row->lens[rs_col_id](%u) == sizeof(mtrl_rowid_t)(%u)",
                (uint32)row->lens[rs_col_id], (uint32)sizeof(mtrl_rowid_t));
            break;
        }

        // save vmid to rs row, maybe more rs row has the same vmid
        *(mtrl_rowid_t *)(row->data + row->offsets[rs_col_id]) = mtrl_rid;

        CT_BREAK_IF_ERROR(sql_winsort_aggr_value(stmt, type, func, aggr_result, buf));

        if (grp_changed || ord_changed) {
            CTSQL_SAVE_STACK(stmt);
            if (ord_changed) {
                CT_BREAK_IF_ERROR(sql_stack_alloc_aggr_var(stmt, type, (void **)&old_aggr));
                CT_BREAK_IF_ERROR(sql_copy_aggr(type, aggr_result, old_aggr));
            }
            CT_BREAK_IF_ERROR(sql_winsort_aggr_value_end(stmt, type, query_cursor, aggr_result));
            // alloc next aggr row
            CT_BREAK_IF_ERROR(sql_win_aggr_var_alloc(stmt, type, query_cursor, &aggr_result, datatype, &mtrl_rid, func));
            if (ord_changed) {
                CT_BREAK_IF_ERROR(sql_copy_aggr(type, old_aggr, aggr_result));
            }
            CTSQL_RESTORE_STACK(stmt);
        }
    }
    SQL_CURSOR_POP(stmt);
    mtrl_close_cursor(&stmt->mtrl, &cursor->mtrl.cursor);
    return status;
}

static inline status_t sql_func_winsort_aggr(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan,
    sql_aggr_type_t type, const char *buffer)
{
    if (plan->winsort_p.winsort->win_args->windowing == NULL) {
        return sql_func_winsort_aggr_default(stmt, cursor, plan, type, buffer);
    }
    if (plan->winsort_p.winsort->win_args->windowing->is_range) {
        return sql_func_winsort_aggr_range(stmt, cursor, plan, type, buffer);
    }
    return sql_func_winsort_aggr_rows(stmt, cursor, plan, type, buffer);
}


static status_t sql_win_aggr_func_lag_offset(sql_stmt_t *stmt, expr_tree_t *arg_expr, int32 *aggr_offset)
{
    variant_t arg_variant;
    expr_node_t *node = NULL;
    int32 offset;

    node = arg_expr->root;
    if (node->type != EXPR_NODE_PARAM && node->type != EXPR_NODE_CONST) {
        CT_THROW_ERROR(ERR_INVALID_NUMBER, "-- not supprort the offset expr type");
        return CT_ERROR;
    }
    CT_RETURN_IFERR(sql_get_expr_node_value(stmt, node, &arg_variant));

    if (arg_variant.is_null == CT_TRUE) {
        CT_THROW_ERROR(ERR_INVALID_NUMBER, "-- text is empty or too long");
        return CT_ERROR;
    }

    if (var_as_floor_integer(&arg_variant) != CT_SUCCESS) {
        return CT_ERROR;
    }
    offset = VALUE(int32, &arg_variant);
    if (offset < 0) {
        CT_THROW_ERROR(ERR_FUNC_ARGUMENT_OUT_OF_RANGE, 2, "out of range");
        return CT_ERROR;
    }

    *(int32 *)aggr_offset = offset;
    return CT_SUCCESS;
}

static status_t sql_win_aggr_verify_ntile_bucket(sql_stmt_t *stmt, expr_tree_t *arg_expr, int64 *arg)
{
    variant_t arg_variant;
    expr_node_t *node = NULL;
    int64 bucket_count;

    node = arg_expr->root;
    CT_RETURN_IFERR(sql_get_expr_node_value(stmt, node, &arg_variant));

    if (arg_variant.is_null) {
        CT_THROW_ERROR(ERR_INVALID_NUMBER, "-- bucket count can not be null");
        return CT_ERROR;
    }

    if (arg_variant.type == CT_TYPE_BOOLEAN) {
        CT_THROW_ERROR(ERR_INVALID_NUMBER, "-- bucket type can not be bool");
        return CT_ERROR;
    }

    if (var_as_floor_bigint(&arg_variant) != CT_SUCCESS) {
        return CT_ERROR;
    }
    bucket_count = VALUE(int64, &arg_variant);
    if (bucket_count <= 0) {
        CT_THROW_ERROR(ERR_FUNC_ARGUMENT_OUT_OF_RANGE, 1, "out of range");
        return CT_ERROR;
    }

    if (arg != NULL) {
        *arg = bucket_count;
    }
    return CT_SUCCESS;
}

static status_t sql_func_winsort_init_slider(sql_stmt_t *stmt, sql_aggr_type_t type, sql_cursor_t *query_cursor,
    expr_tree_t *expr, winsort_slider_t *aggr_silder, expr_node_t *expr_node)
{
    mtrl_rowid_t mtrl_rid;
    aggr_var_t *aggr_result = NULL;

    CT_RETURN_IFERR(sql_win_aggr_alloc(stmt, type, query_cursor, &aggr_result, &mtrl_rid));
    aggr_result->var.is_null = CT_TRUE;

    aggr_silder->rid = mtrl_rid;
    if (expr != NULL) {
        aggr_result->var.type = expr->root->datatype;
        CT_RETURN_IFERR(sql_get_expr_node_value(stmt, expr->root, &aggr_result->var));
    } else {
        aggr_result->var.type = expr_node->datatype;
    }

    if (!aggr_result->var.is_null) {
        CT_RETURN_IFERR(sql_win_aggr_append_data(stmt, query_cursor, aggr_result));
    }

    return CT_SUCCESS;
}

static status_t sql_func_winsort_make_result(sql_stmt_t *stmt, sql_cursor_t *query_cursor, expr_tree_t *expr,
    winsort_slider_t *aggr_silder, sql_aggr_type_t type, const char *buf)
{
    mtrl_rowid_t rid;
    aggr_var_t *aggr_result = NULL;

    ct_type_t datatype = expr->root->datatype;
    CT_RETURN_IFERR(sql_winsort_get_aggr_type(stmt, query_cursor, type, expr, &datatype));
    CT_RETURN_IFERR(sql_win_aggr_var_alloc(stmt, type, query_cursor, &aggr_result, datatype, &rid, NULL));
    aggr_silder->rid = rid;
    CT_RETURN_IFERR(sql_winsort_aggr_value(stmt, type, expr, aggr_result, buf));
    CT_RETURN_IFERR(sql_win_aggr_append_data(stmt, query_cursor, aggr_result));

    return CT_SUCCESS;
}

static status_t sql_func_winsort_check_arg(sql_stmt_t *stmt, expr_tree_t *root_expr, int32 *aggr_offset)
{
    int32 offset;
    expr_tree_t *offset_expr = NULL;
    offset_expr = root_expr->next;
    if (offset_expr != NULL) {
        CT_RETURN_IFERR(sql_win_aggr_func_lag_offset(stmt, offset_expr, &offset));
        *aggr_offset = offset;
    } else {
        *aggr_offset = 1;
    }

    return CT_SUCCESS;
}

static status_t sql_func_winsort_cume_dist_row(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan,
    sql_aggr_type_t type, const char *buf)
{
    mtrl_row_t *row = NULL;
    uint32 rs_col_id = VALUE(uint32, &plan->winsort_p.winsort->value);
    bool32 grp_changed, ord_changed;
    uint32 rnd = 0;
    sql_cursor_t *query_cursor = CTSQL_CURR_CURSOR(stmt);
    aggr_var_t *aggr_group = NULL;
    aggr_var_t *aggr_row_cume = NULL;
    mtrl_rowid_t rid_group, rid_row_cume;
    mtrl_rowid_t *rid_group_addr = NULL;
    vm_page_t *group_page = NULL;

    CT_RETURN_IFERR(sql_win_aggr_alloc(stmt, type, query_cursor, &aggr_group, &rid_group));
    CT_RETURN_IFERR(vm_open(stmt->mtrl.session, stmt->mtrl.pool, rid_group.vmid, &group_page));
    CT_RETURN_IFERR(sql_win_aggr_alloc(stmt, type, query_cursor, &aggr_row_cume, &rid_row_cume));
    aggr_group->var.is_null = CT_TRUE;
    aggr_group->var.type = CT_TYPE_BIGINT;
    aggr_group->var.v_bigint = 0;

    CT_RETURN_IFERR(mtrl_open_cursor(&stmt->mtrl, cursor->mtrl.winsort_sort.sid, &cursor->mtrl.cursor));
    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));

    for (;;) {
        SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt);
        CT_RETURN_IFERR(mtrl_fetch_winsort_rid(&stmt->mtrl, &cursor->mtrl.cursor, WINSORT_PART | WINSORT_ORDER,
            &grp_changed, &ord_changed));
        if (cursor->mtrl.cursor.eof) {
            aggr_group->var.is_null = CT_FALSE;
            aggr_group->var.v_bigint = rnd;
            vm_close(stmt->mtrl.session, stmt->mtrl.pool, rid_group.vmid, VM_ENQUE_TAIL);
            break;
        }

        rnd++;

        row = &cursor->mtrl.cursor.row;
        if (row->lens[rs_col_id] != sizeof(mtrl_rowid_t)) {
            CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "row->lens[rs_col_id](%u) == sizeof(mtrl_rowid_t)",
                (uint32)row->lens[rs_col_id]);
            return CT_ERROR;
        }

        // this col set rid = rid_row_cume
        *(mtrl_rowid_t *)(row->data + row->offsets[rs_col_id]) = rid_row_cume;

        // set this col value : aggr_row_cume , and its offset to the rid_group
        aggr_row_cume->var.is_null = CT_FALSE;
        aggr_row_cume->var.type = CT_TYPE_BIGINT;
        aggr_row_cume->var.v_bigint = rnd;
        rid_group_addr = (mtrl_rowid_t *)(((char *)aggr_row_cume) + aggr_row_cume->extra_offset);
        *rid_group_addr = rid_group;

        if (grp_changed || ord_changed) {
            if (grp_changed) {
                aggr_group->var.is_null = CT_FALSE;
                aggr_group->var.v_bigint = rnd;
                rnd = 0;
                vm_close(stmt->mtrl.session, stmt->mtrl.pool, rid_group.vmid, VM_ENQUE_TAIL);
                CT_RETURN_IFERR(sql_win_aggr_alloc(stmt, type, query_cursor, &aggr_group, &rid_group));
                CT_RETURN_IFERR(vm_open(stmt->mtrl.session, stmt->mtrl.pool, rid_group.vmid, &group_page));
                aggr_group->var.is_null = CT_FALSE;
                aggr_group->var.type = CT_TYPE_BIGINT;
                aggr_group->var.v_bigint = 0;
            }
            CT_RETURN_IFERR(sql_win_aggr_alloc(stmt, type, query_cursor, &aggr_row_cume, &rid_row_cume));
            aggr_row_cume->var.is_null = CT_FALSE;
            aggr_row_cume->var.type = CT_TYPE_BIGINT;
            aggr_row_cume->var.v_bigint = 0;
        }
    }
    SQL_CURSOR_POP(stmt);
    mtrl_close_cursor(&stmt->mtrl, &cursor->mtrl.cursor);
    return CT_SUCCESS;
}

static status_t sql_func_winsort_lag_row(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan,
    sql_aggr_type_t type, const char *buf)
{
    status_t status = CT_ERROR;
    mtrl_row_t *row = NULL;
    winsort_slider_t *aggr_silder = NULL;
    winsort_slider_t *cur_slider = NULL;
    bool32 grp_changed, ord_changed;
    sql_cursor_t *query_cursor = CTSQL_CURR_CURSOR(stmt);
    uint32 rs_col_id = VALUE(uint32, &plan->winsort_p.winsort->value);
    int32 aggr_offset = 0;
    uint32 ind = 0;
    uint32 page_cnt = 0;
    uint32 map_idx = 0;
    uint32 *page_maps = NULL;
    uint32 page_offset, slider_seg_id;
    expr_tree_t *func_expr = plan->winsort_p.winsort->argument;
    expr_tree_t *root_expr = func_expr->root->argument;
    mtrl_rowid_t offset_rid;
    expr_tree_t *default_expr = root_expr->next == NULL ? NULL : root_expr->next->next;

    CT_RETURN_IFERR(sql_func_winsort_check_arg(stmt, root_expr, &aggr_offset));
    if (aggr_offset == 0) {
        return sql_func_winsort_aggr(stmt, cursor, plan, AGGR_TYPE_LAG, buf);
    }
    uint32 max_cnt = sql_win_page_max_count();
    // aggr-offset greater than 0 in check:sql_win_aggr_func_lag_offset
    uint32 act_cnt = MIN((uint32)aggr_offset, max_cnt);
    uint32 min_len = act_cnt * sizeof(winsort_slider_t);
    uint32 max_pages = CM_ALIGN8((uint32)aggr_offset / max_cnt + (uint32)1);
    if (max_pages > MAX_PAGE_LIST) {
        CT_THROW_ERROR(ERR_FUNC_ARGUMENT_OUT_OF_RANGE, 2, "out of range");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_push(stmt, max_pages * sizeof(uint32), (void **)&page_maps));
    CT_RETURN_IFERR(mtrl_open_cursor(&stmt->mtrl, cursor->mtrl.winsort_sort.sid, &cursor->mtrl.cursor));
    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));
    // winsort slider
    CT_RETURN_IFERR(mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_WINSORT_AGGR, NULL, &slider_seg_id));
    CT_RETURN_IFERR(mtrl_open_segment(&stmt->mtrl, slider_seg_id));
    CT_RETURN_IFERR(sql_win_slider_alloc(stmt, slider_seg_id, min_len, &offset_rid));
    page_maps[page_cnt++] = offset_rid.vmid;

    for (;;) {
        SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt);
        CT_BREAK_IF_ERROR(mtrl_fetch_winsort_rid(&stmt->mtrl, &cursor->mtrl.cursor, WINSORT_PART | WINSORT_ORDER,
            &grp_changed, &ord_changed));
        if (cursor->mtrl.cursor.eof) {
            status = CT_SUCCESS;
            break;
        }

        row = &cursor->mtrl.cursor.row;
        if (row->lens[rs_col_id] != sizeof(mtrl_rowid_t)) {
            CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "row->lens[rs_col_id](%u) == sizeof(mtrl_rowid_t)(%u)",
                (uint32)row->lens[rs_col_id], (uint32)sizeof(mtrl_rowid_t));
            status = CT_ERROR;
            break;
        }

        get_page_and_offset(act_cnt, max_cnt, aggr_offset, ind, &map_idx, &page_offset);
        if (map_idx == page_cnt) {
            CT_RETURN_IFERR(sql_win_slider_alloc(stmt, slider_seg_id, min_len, &offset_rid));
            page_maps[page_cnt++] = offset_rid.vmid;
        }

        if (get_page_from_maps(stmt, slider_seg_id, (winsort_slider_t **)&aggr_silder, page_maps, map_idx) !=
            CT_SUCCESS) {
            CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "get page addr error ,  page_idx = %u", map_idx);
            status = CT_ERROR;
            break;
        }

        cur_slider = &aggr_silder[page_offset];
        if (ind < (uint32)aggr_offset) {
            CT_BREAK_IF_ERROR(
                sql_func_winsort_init_slider(stmt, type, query_cursor, default_expr, cur_slider, root_expr->root));
            *(mtrl_rowid_t *)(row->data + row->offsets[rs_col_id]) = cur_slider->rid;
        } else {
            *(mtrl_rowid_t *)(row->data + row->offsets[rs_col_id]) = cur_slider->rid;
        }

        CT_BREAK_IF_ERROR(sql_func_winsort_make_result(stmt, query_cursor, func_expr, cur_slider, type, buf));
        ind++;

        if (grp_changed) {
            ind = 0;
        }
    }

    SQL_CURSOR_POP(stmt);
    cm_pop(stmt->session->stack);
    sql_winsort_release_pages(stmt, slider_seg_id, page_maps, page_cnt);
    mtrl_close_cursor(&stmt->mtrl, &cursor->mtrl.cursor);
    return status;
}

static status_t sql_func_winsort_ntile_core(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan,
    sql_aggr_type_t type)
{
    mtrl_row_t *row = NULL;
    uint32 rs_col_id = VALUE(uint32, &plan->winsort_p.winsort->value);
    bool32 grp_changed = CT_FALSE;
    bool32 ord_changed = CT_FALSE;
    sql_cursor_t *query_cursor = CTSQL_CURR_CURSOR(stmt);
    int64 *group_row = NULL;
    char *aggr_row_number = NULL;
    mtrl_rowid_t rid_group, rid_row_num;
    mtrl_rowid_t *rid_group_addr = NULL;
    int64 group = 0;
    int64 bucket;
    bool32 need_verify = CT_TRUE;
    expr_tree_t *arg = plan->winsort_p.winsort->argument->root->argument;

    CT_RETURN_IFERR(mtrl_win_aggr_alloc(&stmt->mtrl, query_cursor->mtrl.winsort_aggr.sid, (void **)&group_row,
        sizeof(int64) + sizeof(int64), &rid_group, CT_TRUE));
    MEMS_RETURN_IFERR(memset_s(group_row, sizeof(int64) + sizeof(int64), 0, sizeof(int64) + sizeof(int64)));
    CT_RETURN_IFERR(mtrl_open_cursor(&stmt->mtrl, cursor->mtrl.winsort_sort.sid, &cursor->mtrl.cursor));
    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cursor));

    for (;;) {
        SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt);
        CT_RETURN_IFERR(sql_win_aggr_alloc(stmt, type, query_cursor, (aggr_var_t **)&aggr_row_number, &rid_row_num));
        CT_RETURN_IFERR(
            mtrl_fetch_winsort_rid(&stmt->mtrl, &cursor->mtrl.cursor, WINSORT_PART, &grp_changed, &ord_changed));

        if (need_verify) {
            CT_RETURN_IFERR(sql_win_aggr_verify_ntile_bucket(stmt, arg, &bucket));
            need_verify = CT_FALSE;
        }

        if (cursor->mtrl.cursor.eof) {
            CT_RETURN_IFERR(
                sql_win_aggr_ntile_set(stmt, &rid_group, &group, &bucket, query_cursor->mtrl.winsort_aggr.sid));
            break;
        }
        row = &cursor->mtrl.cursor.row;
        if (row->lens[rs_col_id] != sizeof(mtrl_rowid_t)) {
            CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "row->lens[rs_col_id](%u) == sizeof(mtrl_rowid_t)",
                (uint32)row->lens[rs_col_id]);
            return CT_ERROR;
        }
        *(mtrl_rowid_t *)(row->data + row->offsets[rs_col_id]) = rid_row_num;

        group++;
        ((aggr_var_t *)aggr_row_number)->var.type = CT_TYPE_BIGINT;
        ((aggr_var_t *)aggr_row_number)->var.v_bigint = group;
        rid_group_addr = (mtrl_rowid_t *)(aggr_row_number + ((aggr_var_t *)aggr_row_number)->extra_offset);

        *rid_group_addr = rid_group;

        if (grp_changed) {
            need_verify = CT_TRUE;
            CT_RETURN_IFERR(
                sql_win_aggr_ntile_set(stmt, &rid_group, &group, &bucket, query_cursor->mtrl.winsort_aggr.sid));
            CT_RETURN_IFERR(mtrl_win_aggr_alloc(&stmt->mtrl, query_cursor->mtrl.winsort_aggr.sid, (void **)&group_row,
                sizeof(int64) + sizeof(int64), &rid_group, CT_TRUE));
            MEMS_RETURN_IFERR(memset_s(group_row, sizeof(int64) + sizeof(int64), 0, sizeof(int64) + sizeof(int64)));
            group = 0;
        }
    }
    SQL_CURSOR_POP(stmt);
    mtrl_close_cursor(&stmt->mtrl, &cursor->mtrl.cursor);
    return CT_SUCCESS;
}

static status_t sql_func_winsort_sum(sql_stmt_t *stmt, sql_cursor_t *cur, plan_node_t *plan)
{
    return sql_func_winsort_aggr(stmt, cur, plan, AGGR_TYPE_SUM, NULL);
}

static status_t sql_func_winsort_stddev(sql_stmt_t *stmt, sql_cursor_t *cur, plan_node_t *plan)
{
    return sql_func_winsort_aggr(stmt, cur, plan, AGGR_TYPE_STDDEV, NULL);
}

static status_t sql_func_winsort_stddev_pop(sql_stmt_t *stmt, sql_cursor_t *cur, plan_node_t *plan)
{
    return sql_func_winsort_aggr(stmt, cur, plan, AGGR_TYPE_STDDEV_POP, NULL);
}

static status_t sql_func_winsort_stddev_samp(sql_stmt_t *stmt, sql_cursor_t *cur, plan_node_t *plan)
{
    return sql_func_winsort_aggr(stmt, cur, plan, AGGR_TYPE_STDDEV_SAMP, NULL);
}

static status_t sql_func_winsort_variance(sql_stmt_t *stmt, sql_cursor_t *cur, plan_node_t *plan)
{
    return sql_func_winsort_aggr(stmt, cur, plan, AGGR_TYPE_VARIANCE, NULL);
}

static status_t sql_func_winsort_var_pop(sql_stmt_t *stmt, sql_cursor_t *cur, plan_node_t *plan)
{
    return sql_func_winsort_aggr(stmt, cur, plan, AGGR_TYPE_VAR_POP, NULL);
}

static status_t sql_func_winsort_var_samp(sql_stmt_t *stmt, sql_cursor_t *cur, plan_node_t *plan)
{
    return sql_func_winsort_aggr(stmt, cur, plan, AGGR_TYPE_VAR_SAMP, NULL);
}

static status_t sql_func_winsort_covar_pop(sql_stmt_t *stmt, sql_cursor_t *cur, plan_node_t *plan)
{
    return sql_func_winsort_aggr(stmt, cur, plan, AGGR_TYPE_COVAR_POP, NULL);
}

static status_t sql_func_winsort_covar_samp(sql_stmt_t *stmt, sql_cursor_t *cur, plan_node_t *plan)
{
    return sql_func_winsort_aggr(stmt, cur, plan, AGGR_TYPE_COVAR_SAMP, NULL);
}

static status_t sql_func_winsort_corr(sql_stmt_t *stmt, sql_cursor_t *cur, plan_node_t *plan)
{
    return sql_func_winsort_aggr(stmt, cur, plan, AGGR_TYPE_CORR, NULL);
}

static status_t sql_verify_winsort_covar_or_corr(sql_verifier_t *verif, expr_node_t *winsort)
{
    uint32 excl_flags = verif->excl_flags;
    expr_node_t *func_node = winsort->argument->root;

    verif->excl_flags = excl_flags | SQL_EXCL_STAR | SQL_EXCL_AGGR;

    CT_RETURN_IFERR(sql_verify_func_node(verif, func_node, 2, 2, CT_INVALID_ID32));
    if (func_node->dis_info.need_distinct) {
        CT_SRC_THROW_ERROR(func_node->argument->loc, ERR_SQL_SYNTAX_ERROR,
            "DISTINCT option not allowed for this function");
        return CT_ERROR;
    }

    verif->excl_flags = excl_flags;
    func_node->datatype = func_node->argument->root->datatype;
    winsort->datatype = CT_TYPE_NUMBER;
    winsort->size = CT_MAX_DEC_OUTPUT_ALL_PREC;
    return CT_SUCCESS;
}

static status_t sql_verify_winsort_min_max(sql_verifier_t *verif, expr_node_t *winsort)
{
    uint32 excl_flags = verif->excl_flags;
    expr_node_t *func_node = winsort->argument->root;

    verif->excl_flags = excl_flags | SQL_EXCL_STAR | SQL_EXCL_AGGR;

    CT_RETURN_IFERR(sql_verify_func_node(verif, func_node, 1, 1, CT_INVALID_ID32));

    verif->excl_flags = excl_flags;
    func_node->datatype = func_node->argument->root->datatype;
    winsort->datatype = func_node->datatype;
    winsort->size = (uint16)cm_get_datatype_strlen(func_node->datatype, func_node->argument->root->size);
    return CT_SUCCESS;
}

static status_t sql_verify_winsort_first_last_value(sql_verifier_t *verif, expr_node_t *winsort)
{
    return sql_verify_winsort_min_max(verif, winsort);
}

static status_t sql_clone_within_group_args(void *ctx, expr_node_t *src_args, winsort_args_t **dst_args,
    ga_alloc_func_t sql_alloc_mem)
{
    if (src_args->sort_items != NULL) {
        sort_item_t *item = NULL;
        sort_item_t *new_item = NULL;

        CT_RETURN_IFERR(sql_alloc_mem(ctx, sizeof(galist_t), (void **)&(*dst_args)->sort_items));
        cm_galist_init((*dst_args)->sort_items, ctx, sql_alloc_mem);
        for (uint32 i = 0; i < src_args->sort_items->count; i++) {
            item = (sort_item_t *)cm_galist_get(src_args->sort_items, i);
            CT_RETURN_IFERR(cm_galist_new((*dst_args)->sort_items, sizeof(sort_item_t), (void **)&new_item));
            CT_RETURN_IFERR(sql_clone_expr_tree(ctx, item->expr, &new_item->expr, sql_alloc_mem));
            new_item->direction = item->direction;
            new_item->nulls_pos = item->nulls_pos;
            new_item->sort_mode = item->sort_mode;
        }
        (*dst_args)->sort_columns += src_args->sort_items->count;
    }
    return CT_SUCCESS;
}

static status_t sql_verify_winsort_listagg(sql_verifier_t *verif, expr_node_t *winsort)
{
    uint32 excl_flags = verif->excl_flags;
    expr_node_t *func = winsort->argument->root;

    verif->excl_flags = excl_flags | SQL_EXCL_STAR | SQL_EXCL_AGGR;
    CT_RETURN_IFERR(sql_verify_listagg(verif, func));
    if (winsort->win_args->sort_items != NULL) {
        CT_SRC_THROW_ERROR_EX(func->argument->loc, ERR_SQL_SYNTAX_ERROR, " over of %s does not allow order by ",
            T2S(&func->word.func.name));
        return CT_ERROR;
    }
    CT_RETURN_IFERR(sql_clone_within_group_args(verif->stmt->context, func, &winsort->win_args, sql_alloc_mem));
    verif->excl_flags = excl_flags;
    winsort->datatype = func->datatype;
    winsort->size = (uint16)cm_get_datatype_strlen(func->datatype, func->argument->root->size);
    return CT_SUCCESS;
}

static inline bool8 sql_node_bigint_is_int32(expr_node_t *node)
{
    return node->datatype == CT_TYPE_BIGINT && node->type == EXPR_NODE_CONST &&
        node->value.v_bigint <= (int64)CT_MAX_INT32 && node->value.v_bigint >= (int64)CT_MIN_INT32;
}

static status_t sql_verify_winsort_lag_row(sql_verifier_t *verif, expr_node_t *winsort)
{
    uint32 excl_flags = verif->excl_flags;
    expr_node_t *func_node = winsort->argument->root;
    expr_tree_t *default_expr = NULL;
    expr_node_t *default_root = NULL;
    uint16 default_expr_len = 0;
    text_buf_t buffer;
    char *buf = NULL;

    if (winsort->win_args->windowing != NULL) {
        CT_SRC_THROW_ERROR(func_node->loc, ERR_UNSUPPORT_FUNC, "Windowing clause is", "in function LEAD or LAG");
        return CT_ERROR;
    }
    verif->excl_flags = excl_flags | SQL_EXCL_STAR | SQL_EXCL_AGGR;
    CT_RETURN_IFERR(sql_verify_func_node(verif, func_node, 1, 3, CT_INVALID_ID32));

    verif->excl_flags = excl_flags;
    func_node->datatype = func_node->argument->root->datatype;
    winsort->datatype = func_node->datatype;
    winsort->size = (uint16)cm_get_datatype_strlen(func_node->datatype, func_node->argument->root->size);

    if ((func_node->value.v_func.arg_cnt == 3)) {
        default_expr = func_node->argument->next->next;
        if ((CT_IS_STRING_TYPE(func_node->datatype))) {
            default_expr_len = cm_get_datatype_strlen(default_expr->root->datatype, default_expr->root->size);
            if (sql_node_bigint_is_int32(default_expr->root)) {
                default_expr_len = CT_MAX_INT32_STRLEN;
            }

            if (default_expr_len > winsort->size) {
                CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "the length of default value as string is larger");
                return CT_ERROR;
            }
        }

        default_root = default_expr->root;
        if (default_root->type == EXPR_NODE_CONST) {
            CTSQL_SAVE_STACK(verif->stmt);
            if (sql_push(verif->stmt, CT_STRING_BUFFER_SIZE, (void **)&buf) != CT_SUCCESS) {
                CTSQL_RESTORE_STACK(verif->stmt);
                return CT_ERROR;
            }

            CM_INIT_TEXTBUF(&buffer, CT_STRING_BUFFER_SIZE, buf);
            if (var_convert(SESSION_NLS(verif->stmt), &default_root->value, winsort->datatype, (text_buf_t *)&buffer) !=
                CT_SUCCESS) {
                CT_THROW_ERROR(ERR_INVALID_DATA_TYPE, "--invalid datatype");
                CTSQL_RESTORE_STACK(verif->stmt);
                return CT_ERROR;
            }
            CTSQL_RESTORE_STACK(verif->stmt);
        }
    }

    return CT_SUCCESS;
}

static status_t sql_verify_winsort_lead_row(sql_verifier_t *verif, expr_node_t *winsort)
{
    return sql_verify_winsort_lag_row(verif, winsort);
}

static status_t sql_verify_winsort_ntile(sql_verifier_t *verif, expr_node_t *winsort)
{
    uint32 excl_flags = verif->excl_flags;
    expr_node_t *func_node = winsort->argument->root;
    expr_tree_t *root_node = func_node->argument;

    if (winsort->win_args->sort_items == NULL) {
        CT_THROW_ERROR(ERR_NO_ORDER_BY_CLAUSE, "no order by clause");
        return CT_ERROR;
    }
    if (winsort->win_args->windowing != NULL) {
        CT_SRC_THROW_ERROR(func_node->loc, ERR_UNSUPPORT_FUNC, "Windowing clause is", "in function NTILE");
        return CT_ERROR;
    }

    verif->excl_flags = excl_flags | SQL_EXCL_STAR | SQL_EXCL_AGGR | SQL_EXCL_ROWID | SQL_EXCL_ROWSCN | SQL_EXCL_ARRAY;
    if (sql_verify_func_node(verif, func_node, 1, 1, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    verif->excl_flags = excl_flags;
    func_node->datatype = func_node->argument->root->datatype;
    if (root_node->root->type == EXPR_NODE_CONST) {
        CT_RETURN_IFERR(sql_win_aggr_verify_ntile_bucket(verif->stmt, root_node, NULL));
    }
    winsort->datatype = CT_TYPE_BIGINT;
    winsort->size = (uint16)sizeof(int64);
    return CT_SUCCESS;
}

static status_t sql_func_winsort_first_value(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    char *buffer = NULL;
    status_t status;

    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buffer));
    status = sql_func_winsort_aggr(stmt, cursor, plan, AGGR_TYPE_FIRST_VALUE, buffer);
    cm_pop(stmt->session->stack);
    return status;
}

static status_t sql_func_winsort_last_value(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    char *buffer = NULL;
    status_t status;

    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buffer));
    status = sql_func_winsort_aggr(stmt, cursor, plan, AGGR_TYPE_LAST_VALUE, buffer);
    cm_pop(stmt->session->stack);
    return status;
}

static status_t sql_func_winsort_max(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    char *buffer = NULL;
    status_t status;

    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buffer));
    status = sql_func_winsort_aggr(stmt, cursor, plan, AGGR_TYPE_MAX, buffer);
    cm_pop(stmt->session->stack);
    return status;
}

static status_t sql_func_winsort_cume_dist(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    char *buffer = NULL;
    status_t status;

    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buffer));
    status = sql_func_winsort_cume_dist_row(stmt, cursor, plan, AGGR_TYPE_CUME_DIST, buffer);
    cm_pop(stmt->session->stack);
    return status;
}

static status_t sql_func_winsort_lag(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    char *buffer = NULL;
    status_t status;

    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buffer));
    status = sql_func_winsort_lag_row(stmt, cursor, plan, AGGR_TYPE_LAG, buffer);
    cm_pop(stmt->session->stack);
    return status;
}

static status_t sql_func_winsort_lead(sql_stmt_t *stmt, sql_cursor_t *cur, plan_node_t *plan)
{
    return sql_func_winsort_lag(stmt, cur, plan);
}

static status_t sql_func_winsort_listagg(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    char *buffer = NULL;
    status_t status;

    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buffer));
    status = sql_func_winsort_aggr(stmt, cursor, plan, AGGR_TYPE_GROUP_CONCAT, buffer);
    cm_pop(stmt->session->stack);
    return status;
}

static status_t sql_func_winsort_min(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    char *buffer = NULL;
    status_t status;

    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buffer));
    status = sql_func_winsort_aggr(stmt, cursor, plan, AGGR_TYPE_MIN, buffer);
    cm_pop(stmt->session->stack);
    return status;
}

static status_t sql_func_winsort_ntile(sql_stmt_t *stmt, sql_cursor_t *cur, plan_node_t *plan)
{
    return sql_func_winsort_ntile_core(stmt, cur, plan, AGGR_TYPE_NTILE);
}

static inline void sql_winsort_aggr_default(variant_t *value)
{
    value->type = CT_TYPE_VM_ROWID;
    value->is_null = CT_FALSE;
    value->v_vmid.vmid = 0;
    value->v_vmid.slot = 0;
}

static inline status_t sql_winsort_aggr_actual(sql_stmt_t *stmt, sql_cursor_t *cursor, expr_node_t *node,
    variant_t *value)
{
    mtrl_rowid_t rid;
    mtrl_row_t *row = &cursor->mtrl.cursor.row;
    uint32 id = VALUE(uint32, &node->value);
    if (row->lens[id] != sizeof(mtrl_rowid_t)) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "row->lens[id](%u) == sizeof(mtrl_rowid_t)(%u)", (uint32)row->lens[id],
            (uint32)sizeof(mtrl_rowid_t));
        return CT_ERROR;
    }
    rid = *(mtrl_rowid_t *)(row->data + row->offsets[id]);

    return sql_win_aggr_get(stmt, cursor, &rid, value, cursor->mtrl.winsort_aggr.sid);
}

#define WINSORT_RESULT_HAS_EXTRA_SIZE(row)                                                                  \
    (((aggr_var_t *)(row))->extra_offset != 0 && ((aggr_var_t *)(row))->extra_offset < CT_VMEM_PAGE_SIZE && \
        ((aggr_var_t *)(row))->extra_size > 0)

status_t sql_win_aggr_get(sql_stmt_t *stmt, sql_cursor_t *cursor, mtrl_rowid_t *rid, variant_t *value, uint32 seg_id)
{
    char *row = NULL;
    mtrl_rowid_t next_vid;
    variant_t result;

    if (mtrl_win_aggr_get(&stmt->mtrl, seg_id, (char **)&row, rid, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    *value = ((aggr_var_t *)row)->var;
    switch (value->type) {
        case CT_TYPE_VM_ROWID:
            next_vid = value->v_vmid;
            return sql_win_aggr_get(stmt, cursor, &next_vid, value, cursor->mtrl.winsort_aggr_ext.sid);

        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
            result.v_text.str = row + sizeof(aggr_var_t);
            if (WINSORT_RESULT_HAS_EXTRA_SIZE(row)) {
                result.v_text.str += ((aggr_var_t *)row)->extra_size;
            }
            if (value->v_text.len != 0) {
                if (sql_push(stmt, value->v_text.len, (void **)&value->v_text.str) != CT_SUCCESS) {
                    return CT_ERROR;
                }
                MEMS_RETURN_IFERR(memcpy_s(value->v_text.str, value->v_text.len, result.v_text.str, value->v_text.len));
            } else {
                value->v_text.str = NULL;
            }

            return CT_SUCCESS;

        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            result.v_bin.bytes = (uint8 *)row + sizeof(aggr_var_t);
            if (WINSORT_RESULT_HAS_EXTRA_SIZE(row)) {
                result.v_bin.bytes += ((aggr_var_t *)row)->extra_size;
            }
            if (value->v_bin.size != 0) {
                if (sql_push(stmt, value->v_bin.size, (void **)&value->v_bin.bytes) != CT_SUCCESS) {
                    return CT_ERROR;
                }
                MEMS_RETURN_IFERR(
                    memcpy_s(value->v_bin.bytes, value->v_bin.size, result.v_bin.bytes, value->v_bin.size));
            } else {
                value->v_bin.bytes = NULL;
            }
        // fall through
        default:
            return CT_SUCCESS;
    }
}

static inline status_t sql_win_aggr_cume_dist_get(sql_stmt_t *stmt, mtrl_rowid_t *rid, variant_t *value, uint32 seg_id)
{
    char *row = NULL;
    char *grp = NULL;
    aggr_var_t *temp = NULL;
    mtrl_rowid_t extra_rid;
    uint32 row_cume;
    uint32 group;

    if (mtrl_win_aggr_get(&stmt->mtrl, seg_id, (char **)&row, rid, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    temp = (aggr_var_t *)row;
    row_cume = temp->var.v_uint32;

    extra_rid = *((mtrl_rowid_t *)(row + temp->extra_offset));
    if (mtrl_win_aggr_get(&stmt->mtrl, seg_id, (char **)&grp, &extra_rid, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    group = ((aggr_var_t *)grp)->var.v_uint32;

    value->is_null = CT_FALSE;
    value->type = CT_TYPE_REAL;
    value->v_real = ((double)row_cume) / group;

    return CT_SUCCESS;
}

static inline status_t sql_winsort_cume_dist_actual(sql_stmt_t *stmt, sql_cursor_t *cursor, expr_node_t *node,
    variant_t *value)
{
    mtrl_rowid_t rid;
    mtrl_row_t *row = &cursor->mtrl.cursor.row;
    uint32 id = VALUE(uint32, &node->value);
    if (row->lens[id] != sizeof(mtrl_rowid_t)) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "row->lens[id](%u) == sizeof(mtrl_rowid_t)(%u)", (uint32)row->lens[id],
            (uint32)sizeof(mtrl_rowid_t));
        return CT_ERROR;
    }
    rid = *(mtrl_rowid_t *)(row->data + row->offsets[id]);

    return sql_win_aggr_cume_dist_get(stmt, &rid, value, cursor->mtrl.winsort_aggr.sid);
}

static status_t sql_verify_winsort_avg(sql_verifier_t *verif, expr_node_t *winsort)
{
    uint32 excl_flags = verif->excl_flags;
    expr_node_t *func_node = winsort->argument->root;

    verif->excl_flags = excl_flags | SQL_EXCL_AGGR;

    CT_RETURN_IFERR(sql_verify_avg(verif, func_node));

    verif->excl_flags = excl_flags;
    winsort->typmod = func_node->typmod;
    return CT_SUCCESS;
}

static status_t sql_verify_winsort_cume_dist(sql_verifier_t *verif, expr_node_t *winsort)
{
    uint32 excl_flags = verif->excl_flags;
    expr_node_t *func_node = winsort->argument->root;

    if (winsort->win_args->windowing != NULL) {
        CT_SRC_THROW_ERROR(func_node->loc, ERR_UNSUPPORT_FUNC, "Windowing clause is", "in function CUME_DIST");
        return CT_ERROR;
    }
    verif->excl_flags = excl_flags | SQL_EXCL_AGGR;
    CT_RETURN_IFERR(sql_verify_func_node(verif, func_node, 0, 0, CT_INVALID_ID32));

    winsort->datatype = CT_TYPE_REAL;
    winsort->size = CT_REAL_SIZE;

    func_node->datatype = CT_TYPE_REAL;
    func_node->size = CT_REAL_SIZE;

    verif->excl_flags = excl_flags;
    winsort->typmod = func_node->typmod;
    return CT_SUCCESS;
}

static status_t sql_func_winsort_avg(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    return sql_func_winsort_aggr(stmt, cursor, plan, AGGR_TYPE_AVG, NULL);
}

static status_t sql_verify_winsort_stddev(sql_verifier_t *verif, expr_node_t *winsort)
{
    uint32 excl_flags = verif->excl_flags;
    expr_node_t *func_node = winsort->argument->root;

    verif->excl_flags = excl_flags | SQL_EXCL_STAR | SQL_EXCL_AGGR;

    CT_RETURN_IFERR(sql_verify_func_node(verif, func_node, 1, 1, CT_INVALID_ID32));

    verif->excl_flags = excl_flags;
    winsort->datatype = CT_TYPE_NUMBER;
    winsort->size = CT_MAX_DEC_OUTPUT_ALL_PREC;
    return CT_SUCCESS;
}

static status_t sql_func_winsort_count(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    return sql_func_winsort_aggr(stmt, cursor, plan, AGGR_TYPE_COUNT, NULL);
}

static status_t sql_verify_winsort_count(sql_verifier_t *verif, expr_node_t *winsort)
{
    uint32 excl_flags = verif->excl_flags;
    expr_node_t *func_node = winsort->argument->root;

    verif->excl_flags = excl_flags | SQL_EXCL_AGGR;

    CT_RETURN_IFERR(sql_verify_count(verif, func_node));

    verif->excl_flags = excl_flags;
    winsort->typmod = func_node->typmod;
    return CT_SUCCESS;
}

static winsort_func_t g_winsort_funcs[] = {
    { { (char *)"avg", 3 }, sql_func_winsort_avg, sql_verify_winsort_avg, sql_winsort_aggr_default, sql_winsort_aggr_actual },
    { { (char *)"corr", 4 }, sql_func_winsort_corr, sql_verify_winsort_covar_or_corr, sql_winsort_aggr_default, sql_winsort_aggr_actual },
    { { (char *)"count", 5 }, sql_func_winsort_count, sql_verify_winsort_count, sql_winsort_aggr_default, sql_winsort_aggr_actual },
    { { (char *)"covar_pop", 9 }, sql_func_winsort_covar_pop, sql_verify_winsort_covar_or_corr, sql_winsort_aggr_default, sql_winsort_aggr_actual },
    { { (char *)"covar_samp", 10 }, sql_func_winsort_covar_samp, sql_verify_winsort_covar_or_corr, sql_winsort_aggr_default, sql_winsort_aggr_actual },
    { { (char *)"cume_dist", 9 }, sql_func_winsort_cume_dist, sql_verify_winsort_cume_dist, sql_winsort_aggr_default, sql_winsort_cume_dist_actual },
    { { (char *)"dense_rank", 10 }, sql_func_winsort_dense_rank, sql_verify_winsort_row_number, sql_winsort_row_number_default, sql_winsort_row_number_actual },
    { { (char *)"first_value", 11 }, sql_func_winsort_first_value, sql_verify_winsort_first_last_value, sql_winsort_aggr_default, sql_winsort_aggr_actual },
    { { (char *)"lag", 3 }, sql_func_winsort_lag, sql_verify_winsort_lag_row, sql_winsort_aggr_default, sql_winsort_aggr_actual },
    { { (char *)"last_value", 10 }, sql_func_winsort_last_value, sql_verify_winsort_first_last_value, sql_winsort_aggr_default, sql_winsort_aggr_actual },
    { { (char *)"lead", 4 }, sql_func_winsort_lead, sql_verify_winsort_lead_row, sql_winsort_aggr_default, sql_winsort_aggr_actual },
    { { (char *)"listagg", 7 }, sql_func_winsort_listagg, sql_verify_winsort_listagg, sql_winsort_aggr_default, sql_winsort_aggr_actual },
    { { (char *)"max", 3 }, sql_func_winsort_max, sql_verify_winsort_min_max, sql_winsort_aggr_default, sql_winsort_aggr_actual },
    { { (char *)"min", 3 }, sql_func_winsort_min, sql_verify_winsort_min_max, sql_winsort_aggr_default, sql_winsort_aggr_actual },
    { { (char *)"ntile", 5 }, sql_func_winsort_ntile, sql_verify_winsort_ntile, sql_winsort_aggr_default, sql_winsort_ntile_actual },
    { { (char *)"rank", 4 }, sql_func_winsort_rank, sql_verify_winsort_row_number, sql_winsort_row_number_default, sql_winsort_row_number_actual },
    { { (char *)"row_number", 10 }, sql_func_winsort_row_number, sql_verify_winsort_row_number, sql_winsort_row_number_default, sql_winsort_row_number_actual },
    { { (char *)"stddev", 6 }, sql_func_winsort_stddev, sql_verify_winsort_stddev, sql_winsort_aggr_default, sql_winsort_aggr_actual },
    { { (char *)"stddev_pop", 10 }, sql_func_winsort_stddev_pop, sql_verify_winsort_stddev, sql_winsort_aggr_default, sql_winsort_aggr_actual },
    { { (char *)"stddev_samp", 11 }, sql_func_winsort_stddev_samp, sql_verify_winsort_stddev, sql_winsort_aggr_default, sql_winsort_aggr_actual },
    { { (char *)"sum", 3 }, sql_func_winsort_sum, sql_verify_winsort_sum, sql_winsort_aggr_default, sql_winsort_aggr_actual },
    { { (char *)"variance", 8 }, sql_func_winsort_variance, sql_verify_winsort_stddev, sql_winsort_aggr_default, sql_winsort_aggr_actual },
    { { (char *)"var_pop", 7 }, sql_func_winsort_var_pop, sql_verify_winsort_stddev, sql_winsort_aggr_default, sql_winsort_aggr_actual },
    { { (char *)"var_samp", 8 }, sql_func_winsort_var_samp, sql_verify_winsort_stddev, sql_winsort_aggr_default, sql_winsort_aggr_actual }
};

#define SQL_WINSORT_FUNC_COUNT (sizeof(g_winsort_funcs) / sizeof(winsort_func_t))

static text_t *sql_winsort_func_name(void *set, uint32 id)
{
    return &g_winsort_funcs[id].name;
}

winsort_func_t *sql_get_winsort_func(var_func_t *v_func)
{
    return &g_winsort_funcs[v_func->func_id];
}

void sql_winsort_func_binsearch(sql_text_t *func_name, var_func_t *v)
{
    v->func_id = sql_func_binsearch((text_t *)func_name, sql_winsort_func_name, NULL, SQL_WINSORT_FUNC_COUNT);
    v->is_winsort_func = CT_TRUE;
}

status_t sql_get_winsort_func_id(sql_text_t *func_name, var_func_t *v)
{
    sql_winsort_func_binsearch(func_name, v);
    if (v->func_id == CT_INVALID_ID32) {
        CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "WINSORT function does not support %s function",
            T2S((text_t *)func_name));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_get_winsort_value(sql_stmt_t *stmt, expr_node_t *node, variant_t *value)
{
    expr_node_t *func_node = node->argument->root;
    sql_cursor_t *query_cursor = CTSQL_CURR_CURSOR(stmt);
    winsort_func_t *func = sql_get_winsort_func(&func_node->value.v_func);

    if (query_cursor->winsort_ready == CT_FALSE) {
        func->default_val(value);
        return CT_SUCCESS;
    }
    return func->actual_val(stmt, query_cursor, node, value);
}

status_t sql_fetch_winsort(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    if (mtrl_fetch_sort(&stmt->mtrl, &cursor->mtrl.cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }
    cursor->mtrl.cursor.type = MTRL_CURSOR_OTHERS;
    *eof = cursor->mtrl.cursor.eof;
    return CT_SUCCESS;
}

static inline status_t sql_push_winsort_pairs(sql_cursor_t *cursor, plan_node_t *plan, bool32 need_free,
    winsort_assist_t *assist)
{
    if (assist->count >= MAX_WINSORT_SIZE) {
        CT_THROW_ERROR(ERR_COLUM_LIST_EXCEED, MAX_WINSORT_SIZE);
        return CT_ERROR;
    }
    assist->pairs[assist->count].plan = plan;
    assist->pairs[assist->count].cursor = cursor;
    assist->pairs[assist->count].need_free = need_free;
    assist->count++;
    return CT_SUCCESS;
}

static inline void sql_free_winsort_pairs(sql_stmt_t *stmt, winsort_assist_t *assist)
{
    for (uint32 i = 0; i < assist->count; i++) {
        if (assist->pairs[i].cursor != NULL && assist->pairs[i].need_free) {
            sql_free_cursor(stmt, assist->pairs[i].cursor);
        }
    }
}

static inline status_t sql_mtrl_winsort_pair(sql_stmt_t *stmt, mtrl_rowid_t *rs_rid, winsort_pair_t *pair)
{
    char *buffer = NULL;
    mtrl_rowid_t rid;
    plan_node_t *plan = pair->plan;
    sql_cursor_t *cursor = pair->cursor;

    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buffer));
    if (sql_make_mtrl_winsort_row(stmt, plan->winsort_p.winsort->win_args, rs_rid, buffer,
        cursor->mtrl.winsort_sort.buf) != CT_SUCCESS) {
        CTSQL_POP(stmt);
        return CT_ERROR;
    }
    if (mtrl_insert_row(&stmt->mtrl, cursor->mtrl.winsort_sort.sid, buffer, &rid) != CT_SUCCESS) {
        CTSQL_POP(stmt);
        return CT_ERROR;
    }
    CTSQL_POP(stmt);
    return CT_SUCCESS;
}

static inline status_t sql_mtrl_winsort_pairs(sql_stmt_t *stmt, mtrl_rowid_t *rs_rid, winsort_assist_t *assist)
{
    for (uint32 i = 0; i < assist->count; i++) {
        CT_RETURN_IFERR(sql_mtrl_winsort_pair(stmt, rs_rid, &assist->pairs[i]));
    }
    return CT_SUCCESS;
}

static inline void sql_winsort_close_pairs_segment(sql_stmt_t *stmt, winsort_assist_t *assist, uint32 count)
{
    winsort_pair_t *pair = NULL;
    for (uint32 i = 0; i < count; i++) {
        pair = &assist->pairs[i];
        mtrl_close_segment(&stmt->mtrl, pair->cursor->mtrl.winsort_sort.sid);
    }
}


static status_t sql_winsort_mtrl_window_types(sql_stmt_t *stmt, sql_cursor_t *cursor, mtrl_resource_t *sort,
    winsort_args_t *args)
{
    windowing_args_t *windowing = args->windowing;
    uint32 type_cnt = 0;
    uint32 mem_cost_size;
    char **buffer = &sort->buf;
    ct_type_t *types = NULL;
    if (windowing == NULL) {
        return CT_SUCCESS;
    }
    bool32 need_ltype = windowing->l_expr != NULL && !TREE_IS_CONST(windowing->l_expr);
    bool32 need_rtype = windowing->r_expr != NULL && !TREE_IS_CONST(windowing->r_expr);
    if (need_ltype) {
        type_cnt++;
    }
    if (need_rtype) {
        type_cnt++;
    }
    if (type_cnt == 0) {
        return CT_SUCCESS;
    }

    if (*buffer == NULL) {
        if (args->group_exprs != NULL) {
            type_cnt += args->group_exprs->count;
        }
        if (args->sort_items != NULL) {
            type_cnt += args->sort_items->count;
        }
        mem_cost_size = sizeof(uint32) + type_cnt * sizeof(ct_type_t);
        CT_RETURN_IFERR(vmc_alloc(&cursor->vmc, mem_cost_size, (void **)buffer));
        *(uint32 *)*buffer = mem_cost_size;
    }
    types = (ct_type_t *)(*buffer + PENDING_HEAD_SIZE);
    if (need_rtype) {
        types[--type_cnt] = windowing->r_expr->root->datatype;
    }
    if (need_ltype) {
        types[--type_cnt] = windowing->l_expr->root->datatype;
    }

    stmt->mtrl.segments[sort->sid]->pending_type_buf = sort->buf;
    return CT_SUCCESS;
}

static inline status_t sql_start_mtrl_winsort_pairs(sql_stmt_t *stmt, winsort_assist_t *assist)
{
    uint32 loop;
    winsort_pair_t *pair = NULL;

    for (loop = 0; loop < assist->count; loop++) {
        pair = &assist->pairs[loop];
        CT_BREAK_IF_ERROR(mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_WINSORT,
            (handle_t)pair->plan->winsort_p.winsort->win_args, &pair->cursor->mtrl.winsort_sort.sid));
        CT_BREAK_IF_ERROR(mtrl_open_segment(&stmt->mtrl, pair->cursor->mtrl.winsort_sort.sid));
        stmt->mtrl.segments[pair->cursor->mtrl.winsort_sort.sid]->cmp_flag = (WINSORT_PART | WINSORT_ORDER);
        CT_RETURN_IFERR(sql_winsort_mtrl_window_types(stmt, pair->cursor, &pair->cursor->mtrl.winsort_sort,
            pair->plan->winsort_p.winsort->win_args));
    }

    if (loop != assist->count) {
        sql_winsort_close_pairs_segment(stmt, assist, loop);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static inline void sql_win_pair_reset_pending_buf(mtrl_context_t *mtrl_ctx, mtrl_resource_t *winsort)
{
    if (mtrl_ctx->segments[winsort->sid]->pending_type_buf == NULL) {
        mtrl_ctx->segments[winsort->sid]->pending_type_buf = winsort->buf;
    }
}

static inline status_t sql_end_mtrl_winsort_pairs(sql_stmt_t *stmt, winsort_assist_t *assist)
{
    status_t status = CT_SUCCESS;
    winsort_pair_t *pair = NULL;

    for (uint32 i = 0; i < assist->count; i++) {
        pair = &assist->pairs[i];
        mtrl_close_segment(&stmt->mtrl, pair->cursor->mtrl.winsort_sort.sid);
        if (status == CT_SUCCESS && mtrl_sort_segment(&stmt->mtrl, pair->cursor->mtrl.winsort_sort.sid) != CT_SUCCESS) {
            status = CT_ERROR;
        }
        sql_win_pair_reset_pending_buf(&stmt->mtrl, &pair->cursor->mtrl.winsort_sort);
    }
    return status;
}

status_t sql_winsort_mtrl_rs_record_types(sql_stmt_t *stmt, sql_cursor_t *cursor, galist_t *winsort_rs_columns)
{
    rs_column_t *rs_col = NULL;
    uint32 mem_cost_size;
    ct_type_t *types = NULL;
    char **buf = &cursor->mtrl.winsort_rs.buf;

    if (*buf == NULL) {
        mem_cost_size = sizeof(uint32) + winsort_rs_columns->count * sizeof(ct_type_t);
        CT_RETURN_IFERR(vmc_alloc(&cursor->vmc, mem_cost_size, (void **)buf));
        *(uint32 *)*buf = mem_cost_size;
    }
    types = (ct_type_t *)(*buf + PENDING_HEAD_SIZE);
    for (uint32 i = 0; i < winsort_rs_columns->count; i++) {
        rs_col = (rs_column_t *)cm_galist_get(winsort_rs_columns, i);
        types[i] = rs_col->datatype;
    }
    stmt->mtrl.segments[cursor->mtrl.winsort_rs.sid]->pending_type_buf = cursor->mtrl.winsort_rs.buf;
    return CT_SUCCESS;
}

static status_t sql_prepare_winsort_rs(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan,
    galist_t *winsort_rs_columns, winsort_assist_t *assist)
{
    status_t status = CT_ERROR;
    bool32 eof = CT_FALSE;
    char *buf = NULL;
    mtrl_rowid_t rid;

    // winsort aggr
    CT_RETURN_IFERR(mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_WINSORT_AGGR, NULL, &cursor->mtrl.winsort_aggr.sid));
    CT_RETURN_IFERR(mtrl_open_segment(&stmt->mtrl, cursor->mtrl.winsort_aggr.sid));
    // winsort aggr_ext
    CT_RETURN_IFERR(
        mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_WINSORT_AGGR, NULL, &cursor->mtrl.winsort_aggr_ext.sid));
    CT_RETURN_IFERR(mtrl_open_segment(&stmt->mtrl, cursor->mtrl.winsort_aggr_ext.sid));
    // winsort rs
    CT_RETURN_IFERR(mtrl_create_segment(&stmt->mtrl, MTRL_SEGMENT_WINSORT_RS, NULL, &cursor->mtrl.winsort_rs.sid));
    CT_RETURN_IFERR(mtrl_open_segment(&stmt->mtrl, cursor->mtrl.winsort_rs.sid));
    if (cursor->select_ctx != NULL && cursor->select_ctx->pending_col_count > 0) {
        CT_RETURN_IFERR(sql_winsort_mtrl_rs_record_types(stmt, cursor, winsort_rs_columns));
    }

    // prepare mtrl segment
    if (sql_start_mtrl_winsort_pairs(stmt, assist) != CT_SUCCESS) {
        mtrl_close_segment(&stmt->mtrl, cursor->mtrl.winsort_rs.sid);
        return CT_ERROR;
    }

    if (sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buf) != CT_SUCCESS) {
        mtrl_close_segment(&stmt->mtrl, cursor->mtrl.winsort_rs.sid);
        sql_winsort_close_pairs_segment(stmt, assist, assist->count);
        return CT_ERROR;
    }

    CTSQL_SAVE_STACK(stmt);
    for (;;) {
        CT_BREAK_IF_ERROR(sql_fetch_query(stmt, cursor, plan, &eof));

        if (eof) {
            status = CT_SUCCESS;
            break;
        }

        CT_BREAK_IF_ERROR(sql_make_mtrl_rs_row(stmt, cursor->mtrl.winsort_rs.buf, winsort_rs_columns, buf));
        CT_BREAK_IF_ERROR(mtrl_insert_row(&stmt->mtrl, cursor->mtrl.winsort_rs.sid, buf, &rid));
        CT_BREAK_IF_ERROR(sql_mtrl_winsort_pairs(stmt, &rid, assist));

        CTSQL_RESTORE_STACK(stmt);
    }
    CTSQL_RESTORE_STACK(stmt);
    CTSQL_POP(stmt);
    mtrl_close_segment(&stmt->mtrl, cursor->mtrl.winsort_rs.sid);
    if (status != CT_SUCCESS) {
        sql_winsort_close_pairs_segment(stmt, assist, assist->count);
        return CT_ERROR;
    }
    return sql_end_mtrl_winsort_pairs(stmt, assist);
}

static status_t sql_execute_winsort_plan(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan_node,
    galist_t *winsort_rs_columns, winsort_assist_t *assist)
{
    sql_cursor_t *sub_cursor = NULL;
    plan_node_t *plan = plan_node;

    while (plan->type == PLAN_NODE_WINDOW_SORT) {
        if (plan->winsort_p.winsort->win_args->is_rs_node) {
            CT_RETURN_IFERR(sql_push_winsort_pairs(cursor, plan, CT_FALSE, assist));
            plan = plan->winsort_p.next;
            continue;
        }
        CT_RETURN_IFERR(sql_alloc_cursor(stmt, &sub_cursor));
        sql_init_ssa_cursor_maps(sub_cursor, CT_MAX_SUBSELECT_EXPRS);
        sub_cursor->is_open = CT_TRUE;
        sub_cursor->scn = cursor->scn;
        sub_cursor->ancestor_ref = cursor->ancestor_ref;
        CT_RETURN_IFERR(sql_push_winsort_pairs(sub_cursor, plan, CT_TRUE, assist));
        plan = plan->winsort_p.next;
    }
    CT_RETURN_IFERR(sql_execute_query_plan(stmt, cursor, plan));
    if (cursor->eof) {
        return CT_SUCCESS;
    }

    return sql_prepare_winsort_rs(stmt, cursor, plan, winsort_rs_columns, assist);
}

static status_t sql_invoke_winsort_func(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    expr_node_t *func_node = NULL;
    winsort_func_t *func = NULL;
    func_node = plan->winsort_p.winsort->argument->root;
    func = sql_get_winsort_func(&func_node->value.v_func);
    return func->invoke(stmt, cursor, plan);
}

status_t sql_execute_winsort(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    winsort_pair_t *pair = NULL;
    winsort_assist_t ass;
    galist_t *winsort_rs_columns = plan->winsort_p.rs_columns;

    ass.count = 0;

    if (sql_execute_winsort_plan(stmt, cursor, plan, winsort_rs_columns, &ass) != CT_SUCCESS) {
        sql_free_winsort_pairs(stmt, &ass);
        return CT_ERROR;
    }

    if (cursor->eof) {
        sql_free_winsort_pairs(stmt, &ass);
        return CT_SUCCESS;
    }

    for (uint32 i = 0; i < ass.count; i++) {
        pair = &ass.pairs[i];

        if (sql_invoke_winsort_func(stmt, pair->cursor, pair->plan) != CT_SUCCESS) {
            sql_free_winsort_pairs(stmt, &ass);
            return CT_ERROR;
        }
        if (pair->need_free) {
            sql_free_cursor(stmt, pair->cursor);
            pair->cursor = NULL;
        }
    }

    CT_RETURN_IFERR(mtrl_open_cursor(&stmt->mtrl, cursor->mtrl.winsort_sort.sid, &cursor->mtrl.cursor));
    cursor->winsort_ready = CT_TRUE;
    return CT_SUCCESS;
}

status_t sql_send_sort_row_filter(sql_stmt_t *stmt, sql_cursor_t *cursor, bool32 *is_full)
{
    uint32 i;
    rs_column_t *rs_column = NULL;
    variant_t rs_var;
    uint32 count = cursor->columns->count;

    CT_RETURN_IFERR(my_sender(stmt)->send_row_begin(stmt, count));
    for (i = 0; i < count; i++) {
        rs_column = (rs_column_t *)cm_galist_get(cursor->columns, i);
        CT_RETURN_IFERR(sql_exec_expr(stmt, rs_column->expr, &rs_var));
        if (sql_send_value(stmt, cursor->mtrl.rs.buf, rs_column->datatype, &rs_column->typmod, &rs_var) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    CT_RETURN_IFERR(my_sender(stmt)->send_row_end(stmt, is_full));
    sql_inc_rows(stmt, cursor);
    return CT_SUCCESS;
}
