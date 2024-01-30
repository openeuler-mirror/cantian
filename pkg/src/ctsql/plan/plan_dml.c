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
 * ctplan_dml.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/plan/ctplan_dml.c
 *
 * -------------------------------------------------------------------------
 */
#include "plan_dml.h"
#include "plan_query.h"
#include "plan_range.h"
#include "dml_parser.h"
#include "ctsql_func.h"
#include "ctsql_table_func.h"
#include "expr_parser.h"
#include "srv_instance.h"
#include "ctsql_verifier.h"
#include "ctsql_transform.h"

#ifdef __cplusplus
extern "C" {
#endif


static status_t sql_create_union_columns(sql_stmt_t *stmt, union_plan_t *union_plan, plan_node_t *left_plan)
{
    plan_node_t *child_plan = NULL;

    switch (left_plan->type) {
        case PLAN_NODE_UNION:
            union_plan->union_columns = left_plan->set_p.union_p.union_columns;
            union_plan->rs_columns = left_plan->set_p.union_p.rs_columns;
            break;
        case PLAN_NODE_MINUS:
        case PLAN_NODE_HASH_MINUS:
            union_plan->union_columns = left_plan->set_p.minus_p.minus_columns;
            union_plan->rs_columns = left_plan->set_p.minus_p.rs_columns;
            break;
        case PLAN_NODE_QUERY:
            union_plan->union_columns = left_plan->query.ref->rs_columns;
            CT_RETURN_IFERR(sql_create_mtrl_plan_rs_columns(stmt, left_plan->query.ref, &union_plan->rs_columns));
            break;
        case PLAN_NODE_UNION_ALL:
            /* child plan of union all can not be union all */
            child_plan = (plan_node_t *)cm_galist_get(left_plan->set_p.list, 0);
            if (child_plan->type == PLAN_NODE_UNION || child_plan->type == PLAN_NODE_MINUS ||
                child_plan->type == PLAN_NODE_HASH_MINUS) {
                CT_RETURN_IFERR(sql_create_union_columns(stmt, union_plan, child_plan->set_p.left));
            } else if (child_plan->type == PLAN_NODE_QUERY) {
                union_plan->union_columns = child_plan->query.ref->rs_columns;
                CT_RETURN_IFERR(sql_create_mtrl_plan_rs_columns(stmt, child_plan->query.ref, &union_plan->rs_columns));
            } else {
                CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Not support the plan type(%d)", child_plan->type);
                return CT_ERROR;
            }
            break;

        default:
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Not support the plan type(%d)", left_plan->type);
            return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_create_minus_columns(sql_stmt_t *stmt, minus_plan_t *minus_plan, plan_node_t *left_plan)
{
    plan_node_t *child_plan = NULL;
    minus_plan->minus_left = CT_TRUE;

    switch (left_plan->type) {
        case PLAN_NODE_UNION:
            minus_plan->minus_columns = left_plan->set_p.union_p.union_columns;
            minus_plan->rs_columns = left_plan->set_p.union_p.rs_columns;
            break;

        case PLAN_NODE_MINUS:
        case PLAN_NODE_HASH_MINUS:
            minus_plan->minus_columns = left_plan->set_p.minus_p.minus_columns;
            minus_plan->rs_columns = left_plan->set_p.minus_p.rs_columns;
            break;

        case PLAN_NODE_QUERY:
            minus_plan->minus_columns = left_plan->query.ref->rs_columns;
            CT_RETURN_IFERR(sql_create_mtrl_plan_rs_columns(stmt, left_plan->query.ref, &minus_plan->rs_columns));
            break;

        case PLAN_NODE_UNION_ALL:
            /* child plan of union all can not be union all */
            child_plan = (plan_node_t *)cm_galist_get(left_plan->set_p.list, 0);
            if (child_plan->type == PLAN_NODE_UNION || child_plan->type == PLAN_NODE_MINUS ||
                child_plan->type == PLAN_NODE_HASH_MINUS) {
                CT_RETURN_IFERR(sql_create_minus_columns(stmt, minus_plan, child_plan->set_p.left));
            } else if (child_plan->type == PLAN_NODE_QUERY) {
                minus_plan->minus_columns = child_plan->query.ref->rs_columns;
                CT_RETURN_IFERR(sql_create_mtrl_plan_rs_columns(stmt, child_plan->query.ref, &minus_plan->rs_columns));
            } else {
                CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Not support the plan type(%d)", child_plan->type);
                return CT_ERROR;
            }
            break;

        default:
            CT_THROW_ERROR_EX(ERR_SQL_SYNTAX_ERROR, "Not support the plan type(%d)", left_plan->type);
            return CT_ERROR;
    }
    return CT_SUCCESS;
}

/*
    UA: UNION ALL
    MP:  MINUS PLAN
    QP:  QUERY PLAN

                 UA
               /    \
              UA     t6            UA(t1,t2,MP,t6)
            /    \                         / \
          UA      MP         =>    UA(t3,t4)  t5
          / \    /  \
         t1  t2 UA  t5
                / \
               t3 t4
*/
static status_t sql_create_select_plan(sql_stmt_t *stmt, select_node_t *node, plan_node_t **node_plan,
                                       plan_assist_t *parent);
static status_t sql_create_union_all_plan(sql_stmt_t *stmt, select_node_t *node, set_plan_t *set_plan,
    plan_assist_t *parent)
{
    plan_node_t *plan = NULL;

    if (node->type == SELECT_NODE_UNION_ALL) {
        CT_RETURN_IFERR(sql_create_union_all_plan(stmt, node->left, set_plan, parent));
        CT_RETURN_IFERR(sql_create_union_all_plan(stmt, node->right, set_plan, parent));
    } else {
        CT_RETURN_IFERR(sql_create_select_plan(stmt, node, &plan, parent));
        CT_RETURN_IFERR(cm_galist_insert(set_plan->list, plan));
    }

    return CT_SUCCESS;
}

static status_t sql_create_select_plan(sql_stmt_t *stmt, select_node_t *node, plan_node_t **node_plan,
                                       plan_assist_t *parent)
{
    set_plan_t *set_plan = NULL;

    if (node->type == SELECT_NODE_QUERY) {
        return sql_create_query_plan(stmt, node->query, SQL_SELECT_NODE, node_plan, parent);
    }

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)node_plan));
    (*node_plan)->plan_id = stmt->context->plan_count++;
    switch (node->type) {
        case SELECT_NODE_UNION:
            (*node_plan)->type = PLAN_NODE_UNION;
            break;

        case SELECT_NODE_UNION_ALL:
            (*node_plan)->type = PLAN_NODE_UNION_ALL;
            (*node_plan)->set_p.union_all_p.exec_id = stmt->context->clause_info.union_all_count++;
            set_plan = &(*node_plan)->set_p;
            CT_RETURN_IFERR(sql_create_list(stmt, &set_plan->list));
            return sql_create_union_all_plan(stmt, node, set_plan, parent);

        case SELECT_NODE_INTERSECT:
            (*node_plan)->type = PLAN_NODE_MINUS;
            (*node_plan)->set_p.minus_p.minus_type = INTERSECT;
            break;

        case SELECT_NODE_MINUS:
        case SELECT_NODE_EXCEPT:
            (*node_plan)->type = PLAN_NODE_MINUS;
            break;
        case SELECT_NODE_INTERSECT_ALL:
            (*node_plan)->type = PLAN_NODE_MINUS;
            (*node_plan)->set_p.minus_p.minus_type = INTERSECT_ALL;
            break;
        case SELECT_NODE_EXCEPT_ALL:
            (*node_plan)->type = PLAN_NODE_MINUS;
            (*node_plan)->set_p.minus_p.minus_type = EXCEPT_ALL;
            break;
        default:
            return CT_SUCCESS;
    }

    set_plan = &(*node_plan)->set_p;

    CT_RETURN_IFERR(sql_create_select_plan(stmt, node->left, &set_plan->left, parent));
    CT_RETURN_IFERR(sql_create_select_plan(stmt, node->right, &set_plan->right, parent));

    if ((*node_plan)->type == PLAN_NODE_UNION) {
        return sql_create_union_columns(stmt, &set_plan->union_p, set_plan->left);
    }

    CT_RETURN_IFERR(sql_create_minus_columns(stmt, &set_plan->minus_p, set_plan->left));
    return CT_SUCCESS;
}

static status_t sql_create_select_sort_plan(sql_stmt_t *stmt, sql_select_t *select_ctx, plan_node_t **sort_plan,
    plan_assist_t *parent)
{
    plan_node_t *plan = NULL;
    uint32 plan_id = stmt->context->plan_count++;

    if (sql_create_select_plan(stmt, select_ctx->root, &plan, parent) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)sort_plan) != CT_SUCCESS) {
        return CT_ERROR;
    }

    (*sort_plan)->type = PLAN_NODE_SELECT_SORT;
    (*sort_plan)->plan_id = plan_id;
    (*sort_plan)->select_sort.items = select_ctx->select_sort_items;
    (*sort_plan)->select_sort.next = plan;

    if (sql_create_mtrl_plan_rs_columns(stmt, select_ctx->first_query, &(*sort_plan)->select_sort.rs_columns) !=
        CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_create_select_limit_plan(sql_stmt_t *stmt, sql_select_t *select_ctx, plan_node_t **limit_plan,
    plan_assist_t *parent)
{
    plan_node_t *plan = NULL;
    uint32 plan_id = stmt->context->plan_count++;

    if (select_ctx->select_sort_items->count > 0) {
        if (sql_create_select_sort_plan(stmt, select_ctx, &plan, parent) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (sql_create_select_plan(stmt, select_ctx->root, &plan, parent) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)limit_plan) != CT_SUCCESS) {
        return CT_ERROR;
    }

    (*limit_plan)->type = PLAN_NODE_SELECT_LIMIT;
    (*limit_plan)->plan_id = plan_id;
    (*limit_plan)->limit.item = select_ctx->limit;
    (*limit_plan)->limit.next = plan;
    (*limit_plan)->limit.calc_found_rows = select_ctx->calc_found_rows;
    return CT_SUCCESS;
}

static void sql_get_query_rs_type(sql_select_t *select_context, plan_node_t *plan)
{
    select_context->rs_plan = plan->query.next;

    // optimize table function in making result period by putting row into send-packet directly
    // like 'select * from table(get_tab_rows(x,x,x,x,x))'
    // but any other complex query cannot.
    if (select_context->rs_type == RS_TYPE_ROW && plan->query.next->type == PLAN_NODE_SCAN) {
        return;
    }

    switch (plan->query.next->type) {
        case PLAN_NODE_QUERY_SORT:
            select_context->rs_type = RS_TYPE_SORT;
            break;
        case PLAN_NODE_QUERY_SORT_PAR:
	    knl_panic(0);
            break;
        case PLAN_NODE_QUERY_SIBL_SORT:
            select_context->rs_type = RS_TYPE_SIBL_SORT;
            break;
        case PLAN_NODE_HAVING:
            select_context->rs_type = RS_TYPE_HAVING;
            break;
        case PLAN_NODE_SORT_GROUP:
            select_context->rs_type = RS_TYPE_SORT_GROUP;
            break;
        case PLAN_NODE_HASH_GROUP:
            select_context->rs_type = RS_TYPE_HASH_GROUP;
            break;
        case PLAN_NODE_MERGE_SORT_GROUP:
            select_context->rs_type = RS_TYPE_MERGE_SORT_GROUP;
            break;
        case PLAN_NODE_INDEX_GROUP:
            select_context->rs_type = RS_TYPE_INDEX_GROUP;
            break;
        case PLAN_NODE_HASH_GROUP_PAR:
	    knl_panic(0);
            break;
        case PLAN_NODE_SORT_DISTINCT:
            select_context->rs_type = RS_TYPE_SORT_DISTINCT;
            break;
        case PLAN_NODE_HASH_DISTINCT:
            select_context->rs_type = RS_TYPE_HASH_DISTINCT;
            break;
        case PLAN_NODE_INDEX_DISTINCT:
            select_context->rs_type = RS_TYPE_INDEX_DISTINCT;
            break;
        case PLAN_NODE_QUERY_LIMIT:
            select_context->rs_type = RS_TYPE_LIMIT;
            break;

#ifdef Z_SHARDING
        case PLAN_NODE_REMOTE_SCAN:
	    knl_panic(0);
            break;
        case PLAN_NODE_GROUP_MERGE:
            select_context->rs_type = RS_TYPE_GROUP_MERGE;
            break;
#endif
        case PLAN_NODE_WINDOW_SORT:
            select_context->rs_type = RS_TYPE_WINSORT;
            break;
        case PLAN_NODE_HASH_MTRL:
            select_context->rs_type = RS_TYPE_HASH_MTRL;
            break;
        case PLAN_NODE_GROUP_CUBE:
            select_context->rs_type = RS_TYPE_GROUP_CUBE;
            break;
        case PLAN_NODE_ROWNUM:
            select_context->rs_type = RS_TYPE_ROWNUM;
            break;
        case PLAN_NODE_FOR_UPDATE:
            select_context->rs_type = RS_TYPE_FOR_UPDATE;
            break;
        case PLAN_NODE_WITHAS_MTRL:
            select_context->rs_type = RS_TYPE_WITHAS_MTRL;
            break;
        default:
            if (plan->query.ref->aggrs->count > 0) {
                select_context->rs_type = RS_TYPE_AGGR;
            } else {
                select_context->rs_type = RS_TYPE_NORMAL;
            }
            break;
    }
}

static void sql_select_get_rs_type(sql_select_t *select_ctx, select_plan_t *select_p)
{
    select_ctx->rs_plan = select_p->next;

    switch (select_p->next->type) {
        case PLAN_NODE_UNION:
            select_ctx->rs_type = RS_TYPE_UNION;
            break;
        case PLAN_NODE_UNION_ALL:
            select_ctx->rs_type = RS_TYPE_UNION_ALL;
            break;
        case PLAN_NODE_MINUS:
            select_ctx->rs_type = RS_TYPE_MINUS;
            break;
        case PLAN_NODE_HASH_MINUS:
            select_ctx->rs_type = RS_TYPE_HASH_MINUS;
            break;
        case PLAN_NODE_SELECT_SORT:
            select_ctx->rs_type = RS_TYPE_SORT;
            break;
        case PLAN_NODE_SELECT_LIMIT:
            select_ctx->rs_type = RS_TYPE_LIMIT;
            break;
        default:
            sql_get_query_rs_type(select_ctx, select_p->next);
            break;
    }
}

static void clear_query_cbo_extra_attr(sql_query_t *sql_query)
{
    if (sql_query->vmc == NULL) {
        return;
    }
    for (uint32 i = 0; i < sql_query->tables.count; ++i) {
        sql_table_t *table = (sql_table_t *)sql_array_get(&sql_query->tables, i);
        TABLE_CBO_ATTR_OWNER(table) = NULL;
        TABLE_CBO_DEP_TABLES(table) = NULL;
        TABLE_CBO_SAVE_TABLES(table) = NULL;
        TABLE_CBO_SUBGRP_TABLES(table) = NULL;
        TABLE_CBO_IDX_REF_COLS(table) = NULL;
        TABLE_CBO_FILTER_COLS(table) = NULL;
        TABLE_CBO_DRV_INFOS(table) = NULL;
    }
    if (sql_query->s_query != NULL) {
        clear_query_cbo_extra_attr(sql_query->s_query);
    }
    sql_query->filter_infos = NULL;
    vmc_free(sql_query->vmc);
    sql_query->vmc = NULL;
}

static inline void clear_select_cbo_extra_attr(select_node_t *select_node)
{
    if (select_node->type == SELECT_NODE_QUERY) {
        clear_query_cbo_extra_attr(select_node->query);
    } else {
        clear_select_cbo_extra_attr(select_node->left);
        clear_select_cbo_extra_attr(select_node->right);
    }
}

status_t sql_generate_select_plan(sql_stmt_t *stmt, sql_select_t *select_ctx, plan_assist_t *plan_ass)
{
    select_plan_t *select_p = NULL;

    if (select_ctx->plan != NULL || select_ctx->type == SELECT_AS_SET) {
        clear_select_cbo_extra_attr(select_ctx->root);
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)&select_ctx->plan));

    select_ctx->plan->type = PLAN_NODE_SELECT;
    select_ctx->plan->plan_id = stmt->context->plan_count++;
    select_p = &select_ctx->plan->select_p;
    select_p->select = select_ctx;

    if (LIMIT_CLAUSE_OCCUR(&select_ctx->limit)) {
        CT_RETURN_IFERR(sql_create_select_limit_plan(stmt, select_ctx, &select_p->next, plan_ass));
    } else if (select_ctx->select_sort_items->count > 0) {
        CT_RETURN_IFERR(sql_create_select_sort_plan(stmt, select_ctx, &select_p->next, plan_ass));
    } else {
        CT_RETURN_IFERR(sql_create_select_plan(stmt, select_ctx->root, &select_p->next, plan_ass));
    }
    sql_select_get_rs_type(select_ctx, select_p);
    if (select_ctx->type == SELECT_AS_TABLE) {
        CT_RETURN_IFERR(sql_create_mtrl_plan_rs_columns(stmt, select_ctx->first_query, &select_p->rs_columns));
    }
    clear_select_cbo_extra_attr(select_ctx->root);
    return CT_SUCCESS;
}

status_t sql_create_subselect_expr_plan(sql_stmt_t *stmt, sql_array_t *ssa, plan_assist_t *plan_ass)
{
    sql_select_t *select_ctx = NULL;
    for (uint32 i = 0; i < ssa->count; i++) {
        select_ctx = (sql_select_t *)sql_array_get(ssa, i);
        // sub-queries that have been converted to hash join will create execution plan in
        // sql_create_subselect_table_plan
        if (select_ctx->type == SELECT_AS_TABLE) {
            continue;
        }
        if (plan_ass != NULL) {
            plan_ass->cbo_flags = CBO_NONE_FLAG;
            select_ctx->drive_card = plan_ass->query->cost.card;
        } else {
            select_ctx->drive_card = 1;
        }
        SQL_LOG_OPTINFO(stmt, ">>>>> Start create subselect expr plan[id=%u,drive_card=%lld]", i,
            select_ctx->drive_card);
        CT_RETURN_IFERR(sql_generate_select_plan(stmt, select_ctx, plan_ass));
    }
    return CT_SUCCESS;
}

static inline sql_withas_factor_t *get_withas_factor(sql_stmt_t *stmt, sql_select_t *select_ctx, uint32 *match_id)
{
    sql_withas_factor_t *factor = NULL;
    sql_withas_t *withas = (sql_withas_t *)stmt->context->withas_entry;
    for (uint32 i = 0; i < withas->withas_factors->count; ++i) {
        factor = (sql_withas_factor_t *)cm_galist_get(withas->withas_factors, i);
        if (factor->subquery_ctx == select_ctx) {
            *match_id = i;
            return factor;
        }
    }
    return NULL;
}

#define MATCH_LOCAL_WITHAS(t, v) ((t)->session->withas_subquery == (v))
#define MATCH_GLOBAL_WITHAS(t, v) \
    ((t)->session->withas_subquery == WITHAS_UNSET && g_instance->sql.withas_subquery == (v))
#define MATCH_WITHAS_SUBQUERY(t, v) (MATCH_LOCAL_WITHAS(t, v) || MATCH_GLOBAL_WITHAS(t, v))

static inline bool32 if_create_withas_mtrl_plan(sql_stmt_t *stmt, sql_withas_factor_t *factor)
{
    if (factor == NULL) {
        return CT_FALSE;
    }
    sql_select_t *select_ctx = (sql_select_t *)factor->subquery_ctx;
    if (HAS_SPEC_TYPE_HINT(select_ctx->first_query->hint_info, OPTIM_HINT, HINT_KEY_WORD_INLINE)) {
        factor->is_mtrl = CT_FALSE;
    } else if (HAS_SPEC_TYPE_HINT(select_ctx->first_query->hint_info, OPTIM_HINT, HINT_KEY_WORD_MATERIALIZE)) {
        factor->is_mtrl = CT_TRUE;
    } else if (MATCH_WITHAS_SUBQUERY(stmt, WITHAS_INLINE)) {
        factor->is_mtrl = CT_FALSE;
    } else if (MATCH_WITHAS_SUBQUERY(stmt, WITHAS_MATERIALIZE)) {
        factor->is_mtrl = CT_TRUE;
    } else {
        factor->is_mtrl = (factor->refs > 1) ? CT_TRUE : CT_FALSE;
    }
    return factor->is_mtrl;
}

static status_t sql_create_withas_mtrl_plan(sql_stmt_t *stmt, sql_table_t *sql_tab)
{
    if (sql_tab->type != WITH_AS_TABLE) {
        return CT_SUCCESS;
    }
    uint32 match_idx;
    sql_withas_factor_t *factor = get_withas_factor(stmt, sql_tab->select_ctx, &match_idx);
    if (!if_create_withas_mtrl_plan(stmt, factor)) {
        return CT_SUCCESS;
    }
    plan_node_t *plan = NULL;
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)&plan));
    plan->type = PLAN_NODE_WITHAS_MTRL;
    plan->withas_p.id = match_idx;
    plan->withas_p.rs_columns = sql_tab->select_ctx->plan->select_p.rs_columns;
    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, CT_NAME_BUFFER_SIZE, (void **)&plan->withas_p.name.str));
    PRTS_RETURN_IFERR(
        snprintf_s(plan->withas_p.name.str, CT_NAME_BUFFER_SIZE, CT_NAME_BUFFER_SIZE - 1, "VW_FWQ_%u", match_idx));
    plan->withas_p.name.len = (uint32)strlen(plan->withas_p.name.str);
    plan->withas_p.next = sql_tab->select_ctx->plan->select_p.next;
    sql_tab->select_ctx->plan->select_p.next = plan;
    plan->cost = plan->withas_p.next->cost;
    plan->rows = plan->withas_p.next->rows;
    return CT_SUCCESS;
}

static status_t sql_create_subselect_table_plan(sql_stmt_t *stmt, sql_array_t *tables, plan_assist_t *plan_ass)
{
    sql_table_t *sql_tab = NULL;
    for (uint32 i = 0; i < tables->count; i++) {
        sql_tab = (sql_table_t *)sql_array_get(tables, i);
        if (CT_IS_SUBSELECT_TABLE(sql_tab->type) && sql_tab->select_ctx->plan == NULL) {
            plan_ass->cbo_flags = CBO_NONE_FLAG;
            plan_ass->ignore_hj = sql_tab->is_push_down;
            CT_RETURN_IFERR(sql_generate_select_plan(stmt, sql_tab->select_ctx, plan_ass));
            CT_RETURN_IFERR(sql_create_withas_mtrl_plan(stmt, sql_tab));
        }
    }
    return CT_SUCCESS;
}

status_t sql_create_subselect_plan(sql_stmt_t *stmt, sql_query_t *query, plan_assist_t *plan_ass)
{
    CT_RETURN_IFERR(sql_create_subselect_expr_plan(stmt, &query->ssa, plan_ass));
    return sql_create_subselect_table_plan(stmt, &query->tables, plan_ass);
}

static bool32 sql_cmp_exists_subslct_tab(sql_query_t *query, cmp_node_t *cmp_node)
{
    sql_table_t *table = NULL;
    expr_tree_t *l_expr = cmp_node->left;
    expr_tree_t *r_expr = cmp_node->right;

    for (uint32 i = 0; i < query->tables.count; ++i) {
        table = (sql_table_t *)sql_array_get(&query->tables, i);
        if (table->type == NORMAL_TABLE) {
            continue;
        }
        if (l_expr && sql_expr_exist_table(l_expr, table->id)) {
            return CT_TRUE;
        }
        if (r_expr && sql_expr_exist_table(r_expr, table->id)) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

static status_t sql_extract_update_cond(sql_query_t *query, cond_node_t *cond_node)
{
    switch (cond_node->type) {
        case COND_NODE_AND:
            CT_RETURN_IFERR(sql_extract_update_cond(query, cond_node->left));
            CT_RETURN_IFERR(sql_extract_update_cond(query, cond_node->right));
            try_eval_logic_and(cond_node);
            break;

        case COND_NODE_OR:
            CT_RETURN_IFERR(sql_extract_update_cond(query, cond_node->left));
            CT_RETURN_IFERR(sql_extract_update_cond(query, cond_node->right));
            try_eval_logic_or(cond_node);
            break;

        case COND_NODE_COMPARE:
            if (sql_cmp_exists_subslct_tab(query, cond_node->cmp)) {
                cond_node->type = COND_NODE_TRUE;
            }
            break;
        default:
            break;
    }
    return CT_SUCCESS;
}

status_t sql_generate_delete_plan(sql_stmt_t *stmt, sql_delete_t *delete_ctx, plan_assist_t *plan_ass)
{
    plan_node_t *next_plan = NULL;
    delete_plan_t *del_plan = NULL;

    CT_RETURN_IFERR(SQL_NODE_PUSH(stmt, delete_ctx->query));
    if (delete_ctx->query->tables.count > 1 && delete_ctx->query->cond) {
        CT_RETURN_IFERR(sql_clone_cond_tree(stmt->context, delete_ctx->query->cond, &delete_ctx->cond, sql_alloc_mem));
        CT_RETURN_IFERR(sql_extract_update_cond(delete_ctx->query, delete_ctx->cond->root));
    } else {
        delete_ctx->cond = delete_ctx->query->cond;
    }

    CT_RETURN_IFERR(sql_create_query_plan(stmt, delete_ctx->query, SQL_DELETE_NODE, &next_plan, plan_ass));

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)&delete_ctx->plan));

    delete_ctx->plan->type = PLAN_NODE_DELETE;
    del_plan = &delete_ctx->plan->delete_p;
    del_plan->next = next_plan;
    del_plan->objects = delete_ctx->objects;
    del_plan->rowid = delete_ctx->query->rs_columns;

    SQL_NODE_POP(stmt);
    return CT_SUCCESS;
}

status_t sql_generate_update_plan(sql_stmt_t *stmt, sql_update_t *update_ctx, plan_assist_t *parent)
{
    plan_node_t *next_plan = NULL;
    update_plan_t *update_plan = NULL;

    CT_RETURN_IFERR(SQL_NODE_PUSH(stmt, update_ctx->query));
    if (update_ctx->query->tables.count > 1 && update_ctx->query->cond) {
        CT_RETURN_IFERR(sql_clone_cond_tree(stmt->context, update_ctx->query->cond, &update_ctx->cond, sql_alloc_mem));
        CT_RETURN_IFERR(sql_extract_update_cond(update_ctx->query, update_ctx->cond->root));
    } else {
        update_ctx->cond = update_ctx->query->cond;
    }

    CT_RETURN_IFERR(sql_create_query_plan(stmt, update_ctx->query, SQL_UPDATE_NODE, &next_plan, parent));

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)&update_ctx->plan));
    update_ctx->plan->type = PLAN_NODE_UPDATE;
    update_plan = &update_ctx->plan->update_p;
    update_plan->next = next_plan;
    update_plan->objects = update_ctx->objects;
    update_plan->check_self_update = update_ctx->check_self_update;

    SQL_NODE_POP(stmt);
    return CT_SUCCESS;
}

status_t sql_create_insert_sub_plan(sql_stmt_t *stmt, sql_insert_t *insert_ctx, plan_assist_t *parent)
{
    if (insert_ctx->select_ctx != NULL) {
        CT_RETURN_IFERR(sql_generate_select_plan(stmt, insert_ctx->select_ctx, parent));
    }
    return sql_create_subselect_expr_plan(stmt, &insert_ctx->ssa, parent);
}

status_t sql_generate_insert_plan(sql_stmt_t *stmt, sql_insert_t *insert_ctx, plan_assist_t *parent)
{
    insert_plan_t *insert_p = NULL;
    if (sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)&insert_ctx->plan) != CT_SUCCESS) {
        return CT_ERROR;
    }

    insert_ctx->plan->type = PLAN_NODE_INSERT;
    insert_p = &insert_ctx->plan->insert_p;
    insert_p->table = insert_ctx->table;

    CT_RETURN_IFERR(sql_create_insert_sub_plan(stmt, insert_ctx, parent));
    return CT_SUCCESS;
}

static inline void set_merge_into_tables_plan_id(merge_plan_t *merge_p, bool32 is_hash)
{
    merge_p->merge_into_table->plan_id = is_hash ? 0 : 1;
    merge_p->using_table->plan_id = is_hash ? 1 : 0;
}

static status_t sql_generate_merge_into_join_plan(sql_stmt_t *stmt, sql_merge_t *merge_ctx, merge_plan_t *merge_p,
    plan_assist_t *plan_ass)
{
    join_oper_t oper = JOIN_OPER_NL;
    sql_table_t *using_table = (sql_table_t *)sql_array_get(&merge_ctx->query->tables, 1);
    sql_table_t *merge_into_table = (sql_table_t *)sql_array_get(&merge_ctx->query->tables, 0);
    set_merge_into_tables_plan_id(merge_p, CT_FALSE);
    cond_tree_t *merge_cond = merge_ctx->query->cond;
    // using table can't use plan_ass.cond to check indexable when has insert
    cond_tree_t *using_cond = merge_ctx->insert_ctx != NULL ? NULL : merge_ctx->query->cond;

    oper = JOIN_OPER_NL;
    plan_ass->cbo_flags = (oper == JOIN_OPER_NL) ? CBO_CHECK_JOIN_IDX : CBO_CHECK_FILTER_IDX;
    CT_RETURN_IFERR(sql_check_table_indexable(stmt, plan_ass, merge_into_table, merge_cond));
    CT_RETURN_IFERR(sql_create_table_scan_plan(stmt, plan_ass, merge_cond, merge_into_table,
                                               &merge_p->merge_into_scan_p));
    plan_ass->cbo_flags = CBO_CHECK_FILTER_IDX;
    CT_RETURN_IFERR(sql_check_table_indexable(stmt, plan_ass, using_table, using_cond));
    CT_RETURN_IFERR(sql_create_table_scan_plan(stmt, plan_ass, using_cond, using_table, &merge_p->using_table_scan_p));

    {
        if (merge_into_table->scan_mode == SCAN_MODE_TABLE_FULL) {
            plan_ass->cond = NULL;
            CT_RETURN_IFERR(sql_create_part_scan_ranges(stmt, plan_ass, merge_p->merge_into_table,
                &merge_p->merge_into_scan_p->scan_p.part_array));
        }
    }
    return CT_SUCCESS;
}

status_t sql_generate_merge_into_plan(sql_stmt_t *stmt, sql_merge_t *merge_ctx, plan_assist_t *parent)
{
    merge_plan_t *merge_plan = NULL;
    sql_table_t *merge_into_table = (sql_table_t *)sql_array_get(&merge_ctx->query->tables, 0);
    sql_table_t *using_table = (sql_table_t *)sql_array_get(&merge_ctx->query->tables, 1);
    plan_assist_t plan_ass;

    CT_RETURN_IFERR(sql_alloc_mem(stmt->context, sizeof(plan_node_t), (void **)&merge_ctx->plan));

    merge_ctx->plan->type = PLAN_NODE_MERGE;
    merge_plan = &merge_ctx->plan->merge_p;
    merge_plan->using_table = using_table;
    merge_plan->merge_into_table = merge_into_table;

    sql_init_plan_assist(stmt, &plan_ass, merge_ctx->query, SQL_MERGE_NODE, parent);

    CT_RETURN_IFERR(sql_generate_merge_into_join_plan(stmt, merge_ctx, merge_plan, &plan_ass));

    CT_RETURN_IFERR(sql_create_subselect_plan(stmt, merge_ctx->query, &plan_ass));

    return CT_SUCCESS;
}

static inline bool8 sql_is_query_unsupport_parallel(sql_query_t *query)
{
    if (query->has_distinct != CT_FALSE || query->sort_items->count > 0 || query->filter_cond != NULL ||
        query->having_cond != NULL || query->start_with_cond != NULL || query->connect_by_cond != NULL ||
        LIMIT_CLAUSE_OCCUR(&query->limit) || RS_ARRAY_OCCUR(query) || QUERY_HAS_ROWNUM(query)) {
        return CT_TRUE;
    }

    return CT_FALSE;
}

static inline bool8 sql_is_join_unsupport_parallel(join_plan_t *join_p)
{
    if (join_p->left->type != PLAN_NODE_SCAN || join_p->right->type != PLAN_NODE_SCAN) {
        return CT_TRUE;
    }

    if (join_p->left->scan_p.table->type == SUBSELECT_AS_TABLE &&
        sql_is_query_unsupport_parallel(join_p->left->scan_p.table->select_ctx->first_query)) {
        return CT_TRUE;
    }

    if (join_p->right->scan_p.table->type == SUBSELECT_AS_TABLE &&
        sql_is_query_unsupport_parallel(join_p->right->scan_p.table->select_ctx->first_query)) {
        return CT_TRUE;
    }

    return CT_FALSE;
}

static void sql_get_par_node(plan_node_t *plan, plan_node_t **par_node, plan_node_t **hash_node);
static void sql_get_par_node_join(join_plan_t *join_p, plan_node_t **par_node, plan_node_t **hash_node)
{
    switch (join_p->oper) {
        case JOIN_OPER_NL:
        case JOIN_OPER_NL_BATCH:
            sql_get_par_node(join_p->left, par_node, hash_node);
            break;

        case JOIN_OPER_HASH:
        case JOIN_OPER_HASH_SEMI:
        case JOIN_OPER_HASH_ANTI:
        case JOIN_OPER_HASH_ANTI_NA:
            *par_node = NULL;
            if (!sql_is_join_unsupport_parallel(join_p)) {
                if (join_p->hash_left) {
                    sql_get_par_node(join_p->right, par_node, hash_node);
                } else {
                    sql_get_par_node(join_p->left, par_node, hash_node);
                }
            }
            break;

        default:
            *par_node = NULL;
            break;
    }
}

static galist_t *sql_par_get_aggrs(plan_node_t *plan)
{
    if (plan->type == PLAN_NODE_AGGR) {
        return plan->aggr.items;
    } else if (plan->type == PLAN_NODE_HASH_GROUP) {
        return plan->group.aggrs;
    }

    return NULL;
}

static bool8 sql_is_aggr_func_unsupport_parallel(plan_node_t *plan)
{
    uint32 i = 0;
    expr_node_t *aggr_node = NULL;
    sql_func_t *func = NULL;

    galist_t *aggrs = sql_par_get_aggrs(plan);
    if (aggrs == NULL) {
        return CT_FALSE;
    }

    for (i = 0; i < aggrs->count; i++) {
        aggr_node = (expr_node_t *)cm_galist_get(aggrs, i);
        func = sql_get_func(&aggr_node->value.v_func);

        switch (func->aggr_type) {
            case AGGR_TYPE_COUNT:
                if (aggr_node->dis_info.need_distinct) {
                    return CT_TRUE;
                }
            /* fall-through */
            case AGGR_TYPE_AVG:
            case AGGR_TYPE_AVG_COLLECT:
            case AGGR_TYPE_SUM:
            case AGGR_TYPE_MIN:
            case AGGR_TYPE_MAX:
            case AGGR_TYPE_APPX_CNTDIS:
                break;
            case AGGR_TYPE_GROUP_CONCAT:
                if (aggr_node->sort_items == NULL) {
                    break;
                }
                return CT_TRUE;
            default:
                return CT_TRUE;
        }
    }

    return CT_FALSE;
}

static void sql_get_par_node(plan_node_t *plan, plan_node_t **par_node, plan_node_t **hash_node)
{
    switch (plan->type) {
        case PLAN_NODE_AGGR:
            if (!sql_is_aggr_func_unsupport_parallel(plan)) {
                sql_get_par_node(plan->aggr.next, par_node, hash_node);
            }
            break;

        case PLAN_NODE_JOIN:
            if (plan->join_p.oper == JOIN_OPER_HASH) {
                *hash_node = plan;
            }
            sql_get_par_node_join(&plan->join_p, par_node, hash_node);
            break;

        case PLAN_NODE_HASH_GROUP:
            if (!sql_is_aggr_func_unsupport_parallel(plan)) {
                sql_get_par_node(plan->group.next, par_node, hash_node);
            }
            break;

        case PLAN_NODE_SCAN:
            *par_node = NULL;
            sql_table_t *table = plan->scan_p.table;
            if (table->type == NORMAL_TABLE && !SQL_IS_DUAL_TABLE(table)) {
                *par_node = plan;
            }
            break;

        default:
            break;
    }
    return;
}

static inline bool8 sql_all_normal_tables(sql_context_t *context)
{
    uint32 i;
    sql_table_entry_t *entry = NULL;

    for (i = 0; i < context->tables->count; i++) {
        entry = (sql_table_entry_t *)cm_galist_get(context->tables, i);
        if (entry->dc.type != DICT_TYPE_TABLE) {
            return CT_FALSE;
        }
    }

    return CT_TRUE;
}

void check_table_stats(sql_stmt_t *stmt)
{
    if (!CBO_ON) {
        stmt->context->opt_by_rbo = CT_TRUE;
        return;
    }

    sql_table_entry_t *table = NULL;
    for (uint32 i = 0; i < stmt->context->tables->count; i++) {
        table = (sql_table_entry_t *)cm_galist_get(stmt->context->tables, i);
        dc_entity_t *entity = (dc_entity_t *)table->dc.handle;
        if (entity->type == DICT_TYPE_VIEW) {
            continue;
        }

        if (!entity->stat_exists) {
            stmt->context->opt_by_rbo = CT_TRUE;
            return;
        }
    }

    return;
}

status_t sql_generate_replace_plan(sql_stmt_t *stmt, sql_replace_t *replace_ctx, plan_assist_t *parent)
{
    sql_insert_t *insert_ctx = &(replace_ctx->insert_ctx);

    return sql_generate_insert_plan(stmt, insert_ctx, parent);
}

status_t sql_create_dml_plan(sql_stmt_t *stmt)
{
    void *entry = stmt->context->entry;
    status_t ret = CT_SUCCESS;
    plan_assist_t *parent = NULL;
    SQL_LOG_OPTINFO(stmt, ">>> Begin create DML plan, SQL = %s", T2S(&stmt->session->lex->text.value));

    SAVE_AND_RESET_NODE_STACK(stmt);
    stmt->context->plan_count = 0;
    switch (stmt->context->type) {
        case CTSQL_TYPE_SELECT:
            ret = sql_generate_select_plan(stmt, (sql_select_t *)entry, parent);
            break;
        case CTSQL_TYPE_INSERT:
            ret = sql_generate_insert_plan(stmt, (sql_insert_t *)entry, parent);
            break;
        case CTSQL_TYPE_DELETE:
            ret = sql_generate_delete_plan(stmt, (sql_delete_t *)entry, parent);
            break;
        case CTSQL_TYPE_UPDATE:
            ret = sql_generate_update_plan(stmt, (sql_update_t *)entry, parent);
            break;
        case CTSQL_TYPE_MERGE:
            ret = sql_generate_merge_into_plan(stmt, (sql_merge_t *)entry, parent);
            break;
        case CTSQL_TYPE_REPLACE:
            ret = sql_generate_replace_plan(stmt, (sql_replace_t *)entry, parent);
            break;
        default:
            ret = CT_ERROR;
            break;
    }

    if (ret != CT_SUCCESS) {
        return CT_ERROR;
    }

    SQL_RESTORE_NODE_STACK(stmt);

    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
