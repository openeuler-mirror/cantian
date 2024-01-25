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
 * ctsql_expr_verifier.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/verifier/ctsql_expr_verifier.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_expr_verifier.h"
#include "ctsql_select_verifier.h"
#include "ctsql_table_verifier.h"
#include "ctsql_func.h"
#include "ctsql_package.h"
#include "srv_instance.h"
#include "pl_compiler.h"
#include "pl_executor.h"
#include "expr_parser.h"
#include "ctsql_winsort.h"
#include "pl_udt.h"
#include "decl_cl.h"
#include "ctsql_dependency.h"

#ifdef __cplusplus
extern "C" {
#endif

// for the function in sequence
static text_t g_nextval = { "NEXTVAL", 7 };
static text_t g_currval = { "CURRVAL", 7 };
static text_t g_rowid = { "ROWID", 5 };
static text_t g_rowscn = { "ROWSCN", 6 };

static bool32 reserved_has_single_column(expr_node_t *node)
{
    switch (VALUE(int32, &node->value)) {
        case RES_WORD_ROWID:
            return ROWID_NODE_ANCESTOR(node) == 0;
        case RES_WORD_LEVEL:
        case RES_WORD_ROWNUM:
        case RES_WORD_CONNECT_BY_ISCYCLE:
        case RES_WORD_CONNECT_BY_ISLEAF:
            return CT_TRUE;
        default:
            return CT_FALSE;
    }
}

static status_t check_single_column(visit_assist_t *visit_ass, expr_node_t **node)
{
    if (visit_ass->result0) {
        return CT_SUCCESS;
    }
    switch ((*node)->type) {
        case EXPR_NODE_COLUMN:
            visit_ass->result0 = VAR_ANCESTOR(&(*node)->value) == 0;
            break;
        case EXPR_NODE_RESERVED:
            visit_ass->result0 = reserved_has_single_column(*node);
            break;
        case EXPR_NODE_PRIOR:
            visit_ass->result0 = CT_TRUE;
            break;
        // avg/count/max/min/sum
        case EXPR_NODE_AGGR:
        default:
            break;
    }
    return CT_SUCCESS;
}

bool32 sql_check_has_single_column(sql_verifier_t *verif, expr_node_t *node)
{
    visit_assist_t visit_ass;
    sql_init_visit_assist(&visit_ass, NULL, NULL);
    visit_ass.excl_flags = VA_EXCL_PRIOR;
    visit_ass.param0 = (void *)verif;
    visit_ass.result0 = CT_FALSE;

    (void)visit_expr_node(&visit_ass, &node, check_single_column);

    return visit_ass.result0;
}

static status_t check_table_column_exists(visit_assist_t *visit_ass, expr_node_t **node)
{
    if (visit_ass->result0 == CT_TRUE) {
        return CT_SUCCESS;
    }
    switch ((*node)->type) {
        case EXPR_NODE_SELECT:
            if (((sql_select_t *)(*node)->value.v_obj.ptr)->parent_refs->count > 0) {
                visit_ass->result0 = CT_TRUE;
            }
            break;
        case EXPR_NODE_COLUMN:
            if (NODE_ANCESTOR(*node) == 0) {
                visit_ass->result0 = CT_TRUE;
            }
            break;
        case EXPR_NODE_RESERVED:
            if (!sql_check_reserved_is_const(*node)) {
                visit_ass->result0 = CT_TRUE;
            }
            break;
        case EXPR_NODE_CONST:
        case EXPR_NODE_PARAM:
        case EXPR_NODE_V_ADDR:
        case EXPR_NODE_PROC:
        case EXPR_NODE_NEW_COL:
        case EXPR_NODE_OLD_COL:
        case EXPR_NODE_PL_ATTR:
            break;
        default:
            visit_ass->result0 = CT_TRUE;
            break;
    }
    return CT_SUCCESS;
}

bool32 sql_check_table_column_exists(sql_stmt_t *stmt, sql_query_t *query, expr_node_t *node)
{
    // if modify this function, do modify sql_match_group_node_by_node_type at the same time
    visit_assist_t visit_ass;
    sql_init_visit_assist(&visit_ass, stmt, query);
    visit_ass.excl_flags = VA_EXCL_PRIOR;
    visit_ass.result0 = CT_FALSE;
    if (visit_expr_node(&visit_ass, &node, check_table_column_exists) == CT_SUCCESS && visit_ass.result0 == CT_FALSE) {
        return CT_FALSE;
    }
    return CT_TRUE;
}

status_t sql_verify_expr_array_attr(expr_node_t *node, expr_tree_t *expr)
{
    if (node->typmod.is_array == CT_TRUE && expr->root->typmod.is_array != CT_TRUE) {
        if (!var_datatype_matched(CT_TYPE_ARRAY, expr->root->datatype)) {
            CT_SRC_ERROR_MISMATCH(TREE_LOC(expr), CT_TYPE_ARRAY, expr->root->datatype);
            return CT_ERROR;
        }
    }

    if (node->typmod.is_array != CT_TRUE && expr->root->typmod.is_array == CT_TRUE) {
        if (!var_datatype_matched(CT_TYPE_ARRAY, node->datatype)) {
            CT_SRC_ERROR_MISMATCH(NODE_LOC(node), CT_TYPE_ARRAY, node->datatype);
            return CT_ERROR;
        }
        node->typmod.is_array = CT_TRUE;
        node->datatype = expr->root->datatype;
    }

    /* element datatype should match */
    if (!var_datatype_matched(node->datatype, expr->root->datatype)) {
        CT_SRC_ERROR_MISMATCH(TREE_LOC(expr), node->datatype, expr->root->datatype);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

ct_type_t sql_get_case_expr_compatible_datatype(ct_type_t case_datatype, ct_type_t expr_datatype)
{
    if (!g_instance->sql.strict_case_datatype) {
        if ((CT_IS_BINSTR_TYPE(case_datatype) && CT_IS_NUMERIC_TYPE(expr_datatype)) ||
            (CT_IS_NUMERIC_TYPE(case_datatype) && CT_IS_BINSTR_TYPE(expr_datatype))) {
            return (CT_IS_STRING_TYPE(case_datatype) || CT_IS_STRING_TYPE(expr_datatype)) ? CT_TYPE_STRING :
                                                                                            CT_TYPE_VARBINARY;
        }
    }

    return get_cmp_datatype(case_datatype, expr_datatype);
}

static status_t sql_verify_update_case_expr_node(expr_node_t *node, expr_tree_t *expr, bool32 *is_null_value)
{
    if (TREE_IS_RES_NULL(expr)) {
        // ignore null node
        return CT_SUCCESS;
    }
    *is_null_value = CT_FALSE;

    if (TREE_DATATYPE(expr) == CT_TYPE_UNKNOWN) {
        return CT_SUCCESS;
    }

    /* the initial datatype of case..when is set to CT_TYPE_UNKNOWN  */
    if (node->datatype == CT_TYPE_UNKNOWN) {
        node->datatype = expr->root->datatype;
        node->precision = expr->root->precision;
        node->scale = expr->root->scale;
        node->typmod.is_array = expr->root->typmod.is_array;
    } else {
        if (node->typmod.is_array || expr->root->typmod.is_array) {
            CT_RETURN_IFERR(sql_verify_expr_array_attr(node, expr));
        } else if (!var_datatype_matched(node->datatype, expr->root->datatype)) {
            CT_SRC_ERROR_MISMATCH(TREE_LOC(expr), node->datatype, expr->root->datatype);
            return CT_ERROR;
        }

        ct_type_t datatype = sql_get_case_expr_compatible_datatype(node->datatype, TREE_DATATYPE(expr));
        if (datatype == INVALID_CMP_DATATYPE) {
            CT_SET_ERROR_MISMATCH(node->datatype, TREE_DATATYPE(expr));
            return CT_ERROR;
        }
        if (node->datatype != TREE_DATATYPE(expr) && node->typmod.is_array == expr->root->typmod.is_array) {
            node->datatype = datatype;
        } else if (expr->root->typmod.is_array) {
            node->datatype = TREE_DATATYPE(expr);
            node->typmod.is_array = expr->root->typmod.is_array;
        }
    }
    uint32 size = cm_get_datatype_strlen(expr->root->datatype, expr->root->size);
    size = MIN(expr->root->size, size);
    node->size = MAX(node->size, size);

    if (CT_IS_NUMBER_TYPE(node->datatype) &&
        (expr->root->precision != node->precision || expr->root->scale != node->scale)) {
        // if precision and scale not same, set them to unspecified values
        node->precision = CT_UNSPECIFIED_NUM_PREC;
        node->scale = CT_UNSPECIFIED_NUM_SCALE;
    } else {
        node->precision = MAX(node->precision, expr->root->precision);
        node->scale = MAX(node->scale, expr->root->scale);
    }

    return CT_SUCCESS;
}

#define CONST_EXPR_INFER_RET(mode, value, node)          \
    do {                                                 \
        (mode) = NODE_OPTIMIZE_MODE((value)->root);      \
        switch (mode) {                                  \
            case OPTIMIZE_NONE:                          \
                SQL_SET_OPTMZ_MODE(node, OPTIMIZE_NONE); \
                return;                                  \
            case OPTIMIZE_AS_CONST:                      \
            case OPTIMIZE_AS_PARAM:                      \
                break;                                   \
            default:                                     \
                return;                                  \
        }                                                \
    } while (0)

/* * scan the case when arguments, and decide the optmz mode */
void sql_infer_case_when_optmz_mode(sql_verifier_t *verif, expr_node_t *node)
{
    case_expr_t *case_expr = (case_expr_t *)node->value.v_pointer;
    case_pair_t *case_pair = NULL;

    optmz_mode_t mode = OPTMZ_INVAILD;
    if (case_expr->expr != NULL && mode > NODE_OPTIMIZE_MODE(case_expr->expr->root)) {
        CONST_EXPR_INFER_RET(mode, case_expr->expr, node);
    }

    for (uint32 i = 0; i < case_expr->pairs.count; i++) {
        case_pair = (case_pair_t *)cm_galist_get(&case_expr->pairs, i);
        if (case_expr->is_cond) {
            if (case_pair->when_cond->root->type != COND_NODE_TRUE &&
                case_pair->when_cond->root->type != COND_NODE_FALSE) {
                return;
            }
        } else {
            CONST_EXPR_INFER_RET(mode, case_pair->when_expr, node);
        }
        CONST_EXPR_INFER_RET(mode, case_pair->value, node);
    }

    if (case_expr->default_expr != NULL && mode > NODE_OPTIMIZE_MODE(case_expr->default_expr->root)) {
        CONST_EXPR_INFER_RET(mode, case_expr->default_expr, node);
    }

    // Step 2: decide the optmz mode
    // if all value and default are constant, the case when can be constantly optimized.
    if (mode == OPTIMIZE_AS_CONST || mode == OPTIMIZE_AS_PARAM) {
        SQL_SET_OPTMZ_MODE(node, mode);
        return;
    }
}

static status_t sql_verify_case_expr(sql_verifier_t *verif, expr_node_t *node)
{
    case_expr_t *case_expr = (case_expr_t *)node->value.v_pointer;
    case_pair_t *case_pair = NULL;
    bool32 is_null_value = CT_TRUE;
    uint32 old_excl_flags = verif->excl_flags;
    uint32 new_excl_flags = verif->excl_flags & (SQL_EXCL_LOB_COL ^ 0xffffffff);

    node->size = 0;
    node->datatype = CT_TYPE_UNKNOWN;

    if (!case_expr->is_cond) {
        verif->excl_flags = new_excl_flags;
        CT_RETURN_IFERR(sql_verify_expr(verif, case_expr->expr));
        verif->excl_flags = old_excl_flags;
    }

    for (uint32 i = 0; i < case_expr->pairs.count; i++) {
        verif->excl_flags = new_excl_flags;

        case_pair = (case_pair_t *)cm_galist_get(&case_expr->pairs, i);
        if (case_expr->is_cond) {
            CT_RETURN_IFERR(sql_verify_cond(verif, case_pair->when_cond));
        } else {
            CT_RETURN_IFERR(sql_verify_expr(verif, case_pair->when_expr));
        }

        verif->excl_flags = old_excl_flags;
        CT_RETURN_IFERR(sql_verify_expr(verif, case_pair->value));
        CT_RETURN_IFERR(sql_verify_update_case_expr_node(node, case_pair->value, &is_null_value));
    }

    if (case_expr->default_expr != NULL) {
        CT_RETURN_IFERR(sql_verify_expr(verif, case_expr->default_expr));
        CT_RETURN_IFERR(sql_verify_update_case_expr_node(node, case_expr->default_expr, &is_null_value));
    }

    if (is_null_value) {
        node->datatype = CT_DATATYPE_OF_NULL;
        node->size = CT_SIZE_OF_NULL;
    }

    sql_infer_case_when_optmz_mode(verif, node);
    return CT_SUCCESS;
}

status_t sql_gen_winsort_rs_column(sql_stmt_t *stmt, sql_query_t *query, rs_column_t *rs_column);
static inline status_t sql_append_rowid_rs_column(sql_verifier_t *verif, sql_query_t *subquery, expr_node_t *rid_node)
{
    rs_column_t *rs_col = NULL;

    CT_RETURN_IFERR(cm_galist_new(subquery->rs_columns, sizeof(rs_column_t), (pointer_t *)&rs_col));
    CT_RETURN_IFERR(sql_alloc_mem(verif->stmt->context, sizeof(expr_tree_t), (void **)&rs_col->expr));

    rs_col->name = g_rowid;
    rs_col->expr->owner = verif->stmt->context;
    rs_col->expr->root = rid_node;
    rs_col->typmod = rid_node->typmod;
    rs_col->type = RS_COL_CALC;
    CT_BIT_RESET(rs_col->rs_flag, RS_EXIST_ALIAS);

    if (subquery->winsort_list->count > 0) {
        /* switch current query to winsort query */
        sql_query_t *curr_query = verif->curr_query;
        verif->curr_query = subquery;
        CT_RETURN_IFERR(sql_gen_winsort_rs_column(verif->stmt, verif->curr_query, rs_col));
        verif->curr_query = curr_query;
    }
    return CT_SUCCESS;
}

static inline void sql_make_rowid_column_node(expr_node_t *node, uint32 col_id, uint32 tab_id, uint32 ancestor)
{
    node->type = EXPR_NODE_COLUMN;
    node->value.v_col.col = col_id;
    node->value.v_col.tab = tab_id;
    node->value.v_col.ancestor = ancestor;
    node->value.v_col.datatype = CT_TYPE_STRING;
    node->value.v_col.is_rowid = CT_TRUE;
}

static inline status_t sql_find_rowid_in_query(sql_table_t *table, sql_query_t *query, expr_node_t *node,
    uint32 ancestor, bool32 *has_rowid_column)
{
    rs_column_t *rs_col = NULL;
    expr_node_t *col_node = NULL;
    uint32 i;

    for (i = 0; i < query->rs_columns->count; i++) {
        rs_col = (rs_column_t *)cm_galist_get(query->rs_columns, i);
        if (!CT_BIT_TEST(rs_col->rs_flag, RS_EXIST_ALIAS) && cm_text_equal(&rs_col->name, &g_rowid)) {
            sql_make_rowid_column_node(node, i, table->id, ancestor);
            *has_rowid_column = CT_TRUE;
            continue;
        }

        if (rs_col->type == RS_COL_COLUMN) {
            if (rs_col->v_col.is_rowid == CT_TRUE) {
                sql_make_rowid_column_node(node, i, table->id, ancestor);
                *has_rowid_column = CT_TRUE;
            }
            continue;
        }

        // RS_COL_CALC
        col_node = rs_col->expr->root;
        if (col_node->type == EXPR_NODE_RESERVED) {
            if (col_node->value.v_res.res_id == RES_WORD_ROWNUM) {
                CT_SRC_THROW_ERROR(node->loc, ERR_SELECT_ROWID);
                return CT_ERROR;
            }
            if (col_node->value.v_res.res_id == RES_WORD_ROWID) {
                sql_make_rowid_column_node(node, i, table->id, ancestor);
                *has_rowid_column = CT_TRUE;
            }
        }
    }

    return CT_SUCCESS;
}

static status_t sql_verify_table_rowid(sql_verifier_t *verif, sql_table_t *table, expr_node_t *node, uint32 ancestor);

static inline status_t sql_verify_subselect_rowid(sql_verifier_t *verif, expr_node_t *node, sql_table_t *table,
    uint32 ancestor)
{
    query_field_t query_field;
    sql_query_t *query = NULL;
    sql_table_t *sub_table = NULL;
    bool32 has_rowid_column = CT_FALSE;
    expr_node_t *rid_node = NULL;
    uint32 col_id;

    if (table->select_ctx->root->type != SELECT_NODE_QUERY) {
        CT_SRC_THROW_ERROR(node->loc, ERR_SELECT_ROWID);
        return CT_ERROR;
    }

    query = table->select_ctx->root->query;
    if (query->group_sets->count > 0 || query->aggrs->count > 0) {
        CT_SRC_THROW_ERROR(node->loc, ERR_SELECT_ROWID);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_find_rowid_in_query(table, query, node, ancestor, &has_rowid_column));

    if (has_rowid_column) {
        return CT_SUCCESS;
    }

    if (query->has_distinct || query->tables.count > 1) {
        CT_SRC_THROW_ERROR(node->loc, ERR_SELECT_ROWID);
        return CT_ERROR;
    }
    sub_table = (sql_table_t *)sql_array_get(&query->tables, 0);

    CT_RETURN_IFERR(sql_alloc_mem(verif->stmt->context, sizeof(expr_node_t), (void **)&rid_node));
    rid_node->loc = node->loc;
    rid_node->type = EXPR_NODE_RESERVED;
    rid_node->datatype = CT_TYPE_STRING;
    rid_node->size = ROWID_LENGTH;
    rid_node->value.type = CT_TYPE_INTEGER;
    rid_node->value.v_rid.res_id = RES_WORD_ROWID;

    CT_RETURN_IFERR(sql_verify_table_rowid(verif, sub_table, rid_node, 0));
    LOC_RETURN_IFERR(sql_append_rowid_rs_column(verif, query, rid_node), node->loc);

    col_id = query->rs_columns->count - 1;
    SQL_SET_QUERY_FIELD_INFO(&query_field, CT_TYPE_STRING, col_id, CT_FALSE, CT_INVALID_ID32, CT_INVALID_ID32);
    LOC_RETURN_IFERR(sql_table_cache_query_field(verif->stmt, table, &query_field), node->loc);
    sql_make_rowid_column_node(node, col_id, table->id, ancestor);

    return CT_SUCCESS;
}

status_t sql_verify_table_rowid(sql_verifier_t *verif, sql_table_t *table, expr_node_t *node, uint32 ancestor)
{
    if (ancestor > 0) {
        verif->has_acstor_col = CT_TRUE;
    }

    switch (table->type) {
        case NORMAL_TABLE:
            node->value.v_rid.tab_id = table->id;
            node->value.v_rid.ancestor = ancestor;
            table->rowid_exists = CT_TRUE;
            return CT_SUCCESS;

        case VIEW_AS_TABLE:
        case SUBSELECT_AS_TABLE:
        case WITH_AS_TABLE:
            return sql_verify_subselect_rowid(verif, node, table, ancestor);

        default:
            CT_SRC_THROW_ERROR(node->loc, ERR_SELECT_ROWID);
            return CT_ERROR;
    }
}

static inline void sql_make_rownodeid_column_node(expr_node_t *node, uint32 col_id, uint32 tab_id, uint32 ancestor)
{
    node->type = EXPR_NODE_COLUMN;
    node->value.v_col.col = col_id;
    node->value.v_col.tab = tab_id;
    node->value.v_col.ancestor = ancestor;
    node->value.v_col.datatype = CT_TYPE_UINT32;
    node->value.v_col.is_rownodeid = CT_TRUE;
}

static status_t sql_verify_rowid(sql_verifier_t *verif, expr_node_t *node)
{
    uint32 ancestor = 0;
    column_word_t *col = NULL;
    sql_table_t *table = NULL;

    if (verif->excl_flags & SQL_EXCL_ROWID) {
        CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected rowid occurs");
        return CT_ERROR;
    }

    verif->incl_flags |= SQL_INCL_ROWID;
    col = &node->word.column;
    node->datatype = CT_TYPE_STRING;
    node->size = ROWID_LENGTH;

    // if the rowid column has no affiliation
    if (col->table.len == 0) {
        if (verif->tables == NULL) {
            // for nonselect
            table = verif->table;
        } else {
            // for select
            if (verif->tables->count > 1) {
                CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "rowid ambiguously defined at");
                return CT_ERROR;
            }
            table = (sql_table_t *)sql_array_get(verif->tables, 0);
        }

        return sql_verify_table_rowid(verif, table, node, 0);
    }

    if (sql_search_table(verif, node, (text_t *)&col->user, (text_t *)&col->table, &table, &ancestor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_verify_table_rowid(verif, table, node, ancestor);
}

static inline status_t sql_verify_rowscn(sql_verifier_t *verif, expr_node_t *node)
{
    uint32 level = 0;
    column_word_t *col = NULL;
    sql_table_t *table = NULL;

    if (verif->excl_flags & SQL_EXCL_ROWSCN) {
        CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected rowscn occurs");
        return CT_ERROR;
    }

    col = &node->word.column;
    node->datatype = CT_TYPE_BIGINT;
    node->size = sizeof(int64);

    if (col->table.len == 0) {
        if (verif->tables == NULL) {
            // for noselect
            table = verif->table;
        } else {
            // for select
            if (verif->tables->count > 1) {
                CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "rowscn ambiguously defined at");
                return CT_ERROR;
            }
            table = (sql_table_t *)sql_array_get(verif->tables, 0);
        }

        node->value.v_rid.tab_id = 0;
        if (table->type != NORMAL_TABLE) {
            CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "Unable to use clause to select ROWSCN from view.");
            return CT_ERROR;
        }

        return CT_SUCCESS;
    }

    if (sql_search_table(verif, node, (text_t *)&col->user, (text_t *)&col->table, &table, &level) != CT_SUCCESS) {
        return CT_ERROR;
    }

    node->value.v_rid.tab_id = table->id;
    node->value.v_rid.ancestor = level;
    if (table->type != NORMAL_TABLE) {
        CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "Unable to use clause to select ROWSCN from view.");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static inline status_t sql_verify_trig_res(sql_verifier_t *verif, expr_node_t *node)
{
    if (verif->context == NULL || verif->context->type != CTSQL_TYPE_CREATE_TRIG) {
        CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR,
            "'DELETING' or 'UPDATING' or 'INSERTING' must be in a trigger");
        return CT_ERROR;
    }

    node->datatype = CT_TYPE_BOOLEAN;
    node->size = sizeof(bool32);
    node->optmz_info.mode = OPTIMIZE_NONE;
    return CT_SUCCESS;
}

static status_t sql_verify_column_value(sql_verifier_t *verif, expr_node_t *node)
{
    column_word_t *col = NULL;
    uint32 ancestor = 0;
    sql_table_t *table = NULL;

    col = &node->word.column;

    if (col->table.len == 0) {
        if (verif->tables == NULL) {
            // for nonselect
            table = verif->table;
        } else {
            // for select
            if (verif->tables->count > 1) {
                CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "rowid ambiguously defined at");
                return CT_ERROR;
            }
            table = (sql_table_t *)sql_array_get(verif->tables, 0);
        }
    }

    if (sql_search_table(verif, node, (text_t *)&col->user, (text_t *)&col->table, &table, &ancestor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_verify_connect_pseudocolumn(sql_verifier_t *verif, expr_node_t *node, uint32 excl_flag)
{
    if (verif->curr_query == NULL || verif->curr_query->connect_by_cond == NULL) {
        CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "CONNECT BY clause required in this query block");
        return CT_ERROR;
    }

    if (verif->excl_flags & excl_flag) {
        CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "CONNECT BY pseudocolumn not allowed here");
        return CT_ERROR;
    }

    verif->incl_flags |= SQL_INCL_CONNECTBY_ATTR;
    node->datatype = CT_TYPE_INTEGER;
    node->size = sizeof(int32);
    return CT_SUCCESS;
}

/* When an expr_node_t is a reserved word, its reserved type is stored in
 * node->value->rowid */
static inline status_t sql_verify_reserved_value(sql_verifier_t *verif, expr_node_t *node)
{
    status_t status = CT_SUCCESS;

    switch (VALUE(uint32, &node->value)) {
        case RES_WORD_ROWNUM:
            if (verif->excl_flags & SQL_EXCL_ROWNUM) {
                CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected rownum occurs");
                return CT_ERROR;
            }
            if (verif->curr_query != NULL) {
                verif->curr_query->incl_flags |=
                    verif->incl_flags & SQL_INCL_COND_COL ? COND_INCL_ROWNUM : EXPR_INCL_ROWNUM;
            }
            node->datatype = CT_TYPE_INTEGER;
            node->size = sizeof(int32);
            verif->incl_flags |= SQL_INCL_ROWNUM;
            break;

        case RES_WORD_ROWID:
            status = sql_verify_rowid(verif, node);
            break;

        case RES_WORD_ROWSCN:
            node->datatype = CT_TYPE_BIGINT;
            node->size = sizeof(int64);
            status = sql_verify_rowscn(verif, node);
            break;

        case RES_WORD_CURDATE:
            node->datatype = CT_TYPE_DATE;
            node->size = sizeof(date_t);
            sql_add_first_exec_node(verif, node);
            break;

        case RES_WORD_SYSDATE:
            node->datatype = CT_TYPE_DATE;
            node->size = sizeof(date_t);
            sql_add_first_exec_node(verif, node);
            break;

        case RES_WORD_CURTIMESTAMP:
            if (verif->stmt->session->call_version >= CS_VERSION_8) {
                node->datatype = CT_TYPE_TIMESTAMP_TZ;
                node->size = sizeof(timestamp_tz_t);
            } else {
                node->datatype = CT_TYPE_TIMESTAMP_TZ_FAKE;
                node->size = sizeof(timestamp_t);
            }

            node->precision = CT_DEFAULT_DATETIME_PRECISION;
            sql_add_first_exec_node(verif, node);
            break;

        case RES_WORD_SYSTIMESTAMP:
            if (verif->stmt->session->call_version >= CS_VERSION_8) {
                node->datatype = CT_TYPE_TIMESTAMP_TZ;
                node->size = sizeof(timestamp_tz_t);
            } else {
                node->datatype = CT_TYPE_TIMESTAMP_TZ_FAKE;
                node->size = sizeof(timestamp_t);
            }

            node->precision = CT_DEFAULT_DATETIME_PRECISION;
            sql_add_first_exec_node(verif, node);
            break;

        case RES_WORD_LOCALTIMESTAMP:
            node->datatype = CT_TYPE_TIMESTAMP;
            node->size = sizeof(timestamp_t);
            node->precision = CT_DEFAULT_DATETIME_PRECISION;
            sql_add_first_exec_node(verif, node);
            break;

        case RES_WORD_UTCTIMESTAMP:
            node->datatype = CT_TYPE_DATE;
            node->size = sizeof(timestamp_t);
            sql_add_first_exec_node(verif, node);
            break;

        case RES_WORD_DEFAULT:
            if (verif->excl_flags & SQL_EXCL_DEFAULT) {
                CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected DEFAULT occurs");
                return CT_ERROR;
            }

            node->datatype = CT_TYPE_UNKNOWN;
            node->size = 0;
            break;

        case RES_WORD_NULL:
            if (node->owner->root->type == EXPR_NODE_NEGATIVE) {
                node->datatype = CT_TYPE_NUMBER;
            } else {
                node->datatype = CT_DATATYPE_OF_NULL;
            }

            node->size = CT_SIZE_OF_NULL;
            node->optmz_info.mode = OPTIMIZE_AS_CONST;
            break;

        case RES_WORD_TRUE:
        case RES_WORD_FALSE:
            node->datatype = CT_TYPE_BOOLEAN;
            node->size = sizeof(bool32);
            node->optmz_info.mode = OPTIMIZE_AS_CONST;
            break;

        case RES_WORD_DELETING:
        case RES_WORD_INSERTING:
        case RES_WORD_UPDATING:
            status = sql_verify_trig_res(verif, node);
            break;

        case RES_WORD_LEVEL:
            status = sql_verify_connect_pseudocolumn(verif, node, SQL_EXCL_LEVEL);
            break;

        case RES_WORD_CONNECT_BY_ISLEAF:
            status = sql_verify_connect_pseudocolumn(verif, node, SQL_EXCL_CONNECTBY_ATTR);
            break;

        case RES_WORD_CONNECT_BY_ISCYCLE:
            CT_RETURN_IFERR(sql_verify_connect_pseudocolumn(verif, node, SQL_EXCL_CONNECTBY_ATTR));
            if (!verif->curr_query->connect_by_nocycle) {
                CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR,
                    "NOCYCLE keyword is required with CONNECT_BY_ISCYCLE pseudocolumn");
                return CT_ERROR;
            }
            verif->curr_query->connect_by_iscycle = CT_TRUE;
            break;

        case RES_WORD_USER:
            node->datatype = CT_TYPE_STRING;
            node->size = CT_NAME_BUFFER_SIZE;
            break;

        case RES_WORD_DATABASETZ:
            node->datatype = CT_TYPE_STRING;
            node->size = TIMEZONE_OFFSET_STRLEN;
            break;

        case RES_WORD_SESSIONTZ:
            node->datatype = CT_TYPE_STRING;
            node->size = TIMEZONE_OFFSET_STRLEN;
            break;
        case RES_WORD_COLUMN_VALUE:
            status = sql_verify_column_value(verif, node);
            break;

        default:
            break;
    }

    return status;
}

static inline status_t sql_verify_oper_node(sql_verifier_t *verif, expr_node_t *node)
{
    if (sql_verify_expr_node(verif, node->left) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_verify_expr_node(verif, node->right) != CT_SUCCESS) {
        return CT_ERROR;
    }

    sql_infer_oper_optmz_mode(verif, node);

    return CT_SUCCESS;
}

static inline status_t sql_verify_unary_oper_node(sql_verifier_t *verif, expr_node_t *node)
{
    if (node->right == NULL) {
        CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "missing expression");
        return CT_ERROR;
    }

    if (sql_verify_expr_node(verif, node->right) != CT_SUCCESS) {
        return CT_ERROR;
    }

    sql_infer_unary_oper_optmz_mode(verif, node);

    return CT_SUCCESS;
}

static inline status_t sql_verify_prior_node(sql_verifier_t *verif, expr_node_t *node)
{
    if (verif->excl_flags & SQL_EXCL_PRIOR) {
        CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "'prior' operator not allowed here");
        return CT_ERROR;
    }

    if (verif->curr_query == NULL || verif->curr_query->connect_by_cond == NULL) {
        CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "If there is no 'connect by', 'prior' is not allowed");
        return CT_ERROR;
    }

    if (node->right == NULL) {
        CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "missing expression");
        return CT_ERROR;
    }

    uint32 saved_flags = verif->excl_flags;
    verif->excl_flags |= SQL_PRIOR_EXCL;
    if (sql_verify_expr_node(verif, node->right) != CT_SUCCESS) {
        return CT_ERROR;
    }
    verif->excl_flags = saved_flags;
    verif->curr_query->connect_by_prior = CT_TRUE;
    SQL_SET_OPTMZ_MODE(node, OPTIMIZE_NONE);

    node->typmod = node->right->typmod;
    return CT_SUCCESS;
}

static inline status_t sql_verify_cat(sql_verifier_t *verif, expr_node_t *node)
{
    uint32 concat_len;

    if (sql_verify_expr_node(verif, node->left) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_verify_expr_node(verif, node->right) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (CT_IS_BLOB_TYPE(NODE_DATATYPE(node->left)) || CT_IS_BLOB_TYPE(NODE_DATATYPE(node->right))) {
        OPR_THROW_ERROR("||", NODE_DATATYPE(node->left), NODE_DATATYPE(node->right));
        return CT_ERROR;
    }

    if (CT_IS_CLOB_TYPE(NODE_DATATYPE(node->left)) || CT_IS_CLOB_TYPE(NODE_DATATYPE(node->right))) {
        node->datatype = CT_TYPE_CLOB;
    } else {
        node->datatype = CT_TYPE_STRING;
    }

    sql_infer_oper_optmz_mode(verif, node);

    concat_len = cm_get_datatype_strlen(node->left->datatype, node->left->size) +
        cm_get_datatype_strlen(node->right->datatype, node->right->size);
    node->size = (uint16)MIN(concat_len, CT_MAX_STRING_LEN);
    node->typmod.is_char = node->left->typmod.is_char || node->right->typmod.is_char;

    if (NODE_IS_OPTMZ_CONST(node)) {
        if (node->size > SQL_MAX_OPTMZ_CONCAT_LEN) {
            sql_add_first_exec_node(verif, node);
        }
    } else if (NODE_IS_FIRST_EXECUTABLE(node)) {
        verif->context->fexec_vars_bytes += node->size;
    }

    return CT_SUCCESS;
}

static status_t sql_verify_select_expr(sql_verifier_t *verif, expr_node_t *node)
{
    sql_select_t *select_ctx = (sql_select_t *)node->value.v_obj.ptr;
    rs_column_t *rs_column = NULL;

    if (verif->excl_flags & SQL_EXCL_SUBSELECT) {
        CT_SRC_THROW_ERROR(node->loc, ERR_UNEXPECTED_KEY, "SUBSELECT");
        return CT_ERROR;
    }

    if (sql_verify_sub_select(verif->stmt, select_ctx, verif) != CT_SUCCESS) {
        return CT_ERROR;
    }

    rs_column = (rs_column_t *)cm_galist_get(select_ctx->first_query->rs_columns, 0);
    node->typmod = rs_column->typmod;

    if (select_ctx->has_ancestor == 0 && select_ctx->type == SELECT_AS_VARIANT) {
        sql_add_first_exec_node(verif, node);
    }

    return CT_SUCCESS;
}

static void sql_infer_neg_type(ct_type_t right_type, ct_type_t *result)
{
    switch (right_type) {
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_BIGINT:
        case CT_TYPE_UINT64:
            *result = CT_TYPE_BIGINT;
            break;
        case CT_TYPE_REAL:
        case CT_TYPE_FLOAT:
            *result = CT_TYPE_REAL;
            break;

        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
            *result = CT_TYPE_NUMBER;
            break;

        case CT_TYPE_NUMBER2:
            *result = CT_TYPE_NUMBER2;
            break;
        default:
            *result = right_type;
            break;
    }
    return;
}

static status_t sql_adjust_node_datatype(sql_verifier_t *verif, expr_node_t *node)
{
    if (node->type == EXPR_NODE_NEGATIVE) {
        sql_infer_neg_type(node->right->datatype, &node->datatype);
        node->typmod.is_array = node->right->typmod.is_array;
    } else {
        if (opr_infer_type((operator_type_t)node->type, node->left->datatype, node->right->datatype, &node->datatype) !=
            CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t sql_adjust_oper_node(sql_verifier_t *verif, expr_node_t *node)
{
    CT_RETURN_IFERR(sql_adjust_node_datatype(verif, node));
    switch (node->datatype) {
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_BOOLEAN:
            node->size = sizeof(int32);
            break;
        case CT_TYPE_UINT64:
        case CT_TYPE_BIGINT:
        case CT_TYPE_REAL:
            node->size = sizeof(int64);
            break;
        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_NUMBER2:
            node->size = CT_MAX_DEC_OUTPUT_ALL_PREC;
            break;
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
            node->size = sizeof(timestamp_t);
            node->precision = CT_MAX_DATETIME_PRECISION;
            break;

        case CT_TYPE_TIMESTAMP_TZ:
            node->size = sizeof(timestamp_tz_t);
            node->precision = CT_MAX_DATETIME_PRECISION;
            break;

        case CT_TYPE_INTERVAL_DS:
            node->size = sizeof(interval_ds_t);
            node->typmod.day_prec = ITVL_MAX_DAY_PREC;
            node->typmod.frac_prec = ITVL_MAX_SECOND_PREC;
            break;

        case CT_TYPE_INTERVAL_YM:
            node->size = sizeof(interval_ym_t);
            node->typmod.year_prec = ITVL_MAX_YEAR_PREC;
            break;

        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
        case CT_TYPE_UNKNOWN:
            break;
        default:
            CT_THROW_ERROR(ERR_CONVERT_TYPE, get_datatype_name_str((int32)node->datatype), "NUMERIC");
            return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_verify_windowing_expr_type(winsort_args_t *win_args, expr_tree_t *expr, bool32 is_range)
{
    if (is_range) {
        if (win_args->sort_items->count > 1) {
            CT_SRC_THROW_ERROR_EX(expr->loc, ERR_SQL_SYNTAX_ERROR,
                "only one expression is allowed when RANGE value is specified in windowing clause");
            return CT_ERROR;
        }

        sort_item_t *sort_item = (sort_item_t *)cm_galist_get(win_args->sort_items, 0);
        if (CT_IS_DATETIME_TYPE(sort_item->expr->root->datatype)) {
            if (CT_IS_DSITVL_TYPE(expr->root->datatype) || CT_IS_YMITVL_TYPE(expr->root->datatype)) {
                return CT_SUCCESS;
            }
        } else if (!CT_IS_NUMERIC_TYPE(sort_item->expr->root->datatype)) {
            CT_SRC_THROW_ERROR(expr->loc, ERR_INVALID_DATA_TYPE, "order by expression when RANGE is specified");
            return CT_ERROR;
        }
    }

    if (TREE_IS_CONST(expr)) {
        if (expr->root->value.is_null) {
            CT_SRC_THROW_ERROR_EX(expr->loc, ERR_SQL_SYNTAX_ERROR, "windowing border value cannot be NULL");
            return CT_ERROR;
        }
        CT_RETURN_IFERR(var_as_num(&expr->root->value));
        if (var_is_negative(&expr->root->value)) {
            CT_SRC_THROW_ERROR_EX(expr->loc, ERR_SQL_SYNTAX_ERROR, "windowing border value cannot be negative");
            return CT_ERROR;
        }
    } else if (TREE_IS_RES_NULL(expr)) {
        CT_SRC_THROW_ERROR_EX(expr->loc, ERR_SQL_SYNTAX_ERROR, "windowing border value cannot be NULL");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_verify_windowing_exprs(sql_verifier_t *verif, expr_node_t *winsort)
{
    windowing_args_t *args = winsort->win_args->windowing;
    verif->excl_flags |= SQL_EXCL_ROWID | SQL_EXCL_ROWSCN;
    CT_RETURN_IFERR(sql_verify_expr(verif, args->l_expr));
    CT_RETURN_IFERR(sql_verify_expr(verif, args->r_expr));

    if (args->l_expr != NULL) {
        CT_RETURN_IFERR(sql_verify_windowing_expr_type(winsort->win_args, args->l_expr, args->is_range));
        if (!TREE_IS_CONST(args->l_expr)) {
            winsort->win_args->sort_columns++;
        }
    }
    if (args->r_expr != NULL) {
        CT_RETURN_IFERR(sql_verify_windowing_expr_type(winsort->win_args, args->r_expr, args->is_range));
        if (!TREE_IS_CONST(args->r_expr)) {
            winsort->win_args->sort_columns++;
        }
    }
    return CT_SUCCESS;
}

static status_t sql_verify_windowing_clause(sql_verifier_t *verif, expr_node_t *winsort)
{
    windowing_args_t *args = winsort->win_args->windowing;

    if (args->l_type > args->r_type) {
        CT_SRC_THROW_ERROR_EX(winsort->argument->root->loc, ERR_SQL_SYNTAX_ERROR,
            "left border must be less than right border in windowing clause");
        return CT_ERROR;
    }
    if (args->r_type == WB_TYPE_UNBOUNDED_PRECED) {
        CT_SRC_THROW_ERROR_EX(winsort->argument->root->loc, ERR_SQL_SYNTAX_ERROR,
            "UNBOUNED PRECEDING cannot be the right border in windowing clause");
        return CT_ERROR;
    }
    if (args->l_type == WB_TYPE_UNBOUNDED_FOLLOW) {
        CT_SRC_THROW_ERROR_EX(winsort->argument->root->loc, ERR_SQL_SYNTAX_ERROR,
            "UNBOUNED FOLLOWING cannot be the left border in windowing clause");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_verify_windowing_exprs(verif, winsort));

    if (args->l_type != args->r_type) {
        if (args->l_expr != NULL && TREE_IS_CONST(args->l_expr) && var_is_zero(&args->l_expr->root->value)) {
            args->l_expr = NULL;
            args->l_type = WB_TYPE_CURRENT_ROW;
        }
        if (args->r_expr != NULL && TREE_IS_CONST(args->r_expr) && var_is_zero(&args->r_expr->root->value)) {
            args->r_expr = NULL;
            args->r_type = WB_TYPE_CURRENT_ROW;
        }
    }
    return CT_SUCCESS;
}

static status_t sql_verify_winsort(sql_verifier_t *verif, expr_node_t *node)
{
    expr_tree_t *expr = NULL;
    sort_item_t *item = NULL;
    expr_node_t *func_node = node->argument->root;
    winsort_func_t *func = NULL;
    uint32 excl_flags = verif->excl_flags;

    if (verif->excl_flags & SQL_EXCL_WIN_SORT) {
        CT_SRC_THROW_ERROR(node->loc, ERR_UNEXPECTED_KEY, "windows sort analytic function");
        return CT_ERROR;
    }
    verif->incl_flags |= SQL_INCL_WINSORT;
    // not support analytic functions in analytic clause
    verif->excl_flags |= SQL_EXCL_WIN_SORT;
    verif->excl_flags |= SQL_EXCL_SEQUENCE;

    CT_RETURN_IFERR(cm_galist_insert(verif->curr_query->winsort_list, node));

    if (node->win_args->group_exprs != NULL) {
        for (uint32 i = 0; i < node->win_args->group_exprs->count; i++) {
            expr = (expr_tree_t *)cm_galist_get(node->win_args->group_exprs, i);
            CT_RETURN_IFERR(sql_verify_expr(verif, expr));
            if (expr->root->type == EXPR_NODE_ARRAY || expr->root->typmod.is_array) {
                CT_SRC_THROW_ERROR(expr->loc, ERR_INVALID_DATA_TYPE, "comparision");
                return CT_ERROR;
            }
            node->win_args->sort_columns++;
        }
    }

    if (node->win_args->sort_items != NULL) {
        if (func_node->dis_info.need_distinct) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "ORDER BY not allowed OVER function, when has DISTINCT");
            return CT_ERROR;
        }
        for (uint32 i = 0; i < node->win_args->sort_items->count; i++) {
            item = (sort_item_t *)cm_galist_get(node->win_args->sort_items, i);

            CT_RETURN_IFERR(sql_verify_expr(verif, item->expr));
            if (item->expr->root->type == EXPR_NODE_ARRAY || item->expr->root->typmod.is_array) {
                CT_SRC_THROW_ERROR(item->expr->loc, ERR_INVALID_DATA_TYPE, "comparision");
                return CT_ERROR;
            }
            node->win_args->sort_columns++;
        }
        if (node->win_args->windowing != NULL) {
            CT_RETURN_IFERR(sql_verify_windowing_clause(verif, node));
        }
    }

    CT_RETURN_IFERR(sql_get_winsort_func_id(&func_node->word.func.name, &func_node->value.v_func));
    func = sql_get_winsort_func(&func_node->value.v_func);
    CT_RETURN_IFERR(func->verify(verif, node));
    verif->excl_flags = excl_flags;
    return CT_SUCCESS;
}

static status_t sql_verify_array_type(expr_node_t *array_node, expr_node_t *expr_node)
{
    typmode_t tmr;
    uint32 max_str_size, datatype_len;
    ct_type_t node_type = NODE_DATATYPE(expr_node);
    ct_type_t array_type = NODE_DATATYPE(array_node);

    if (!cm_datatype_arrayable(node_type)) {
        CT_SRC_THROW_ERROR(NODE_LOC(expr_node), ERR_DATATYPE_NOT_SUPPORT_ARRAY, get_datatype_name_str(node_type));
        return CT_ERROR;
    }

    if (NODE_IS_RES_NULL(expr_node)) {
        return CT_SUCCESS;
    }

    if (array_type == CT_TYPE_UNKNOWN) {
        NODE_TYPMODE(array_node) = NODE_TYPMODE(expr_node);
        return CT_SUCCESS;
    }

    /* all elements should have the same datatype or can be converted */
    if (!var_datatype_matched(array_type, node_type)) {
        CT_SRC_ERROR_MISMATCH(NODE_LOC(expr_node), array_type, node_type);
        return CT_ERROR;
    }

    /* try to infer the array type */
    if (CT_IS_STRING_TYPE(array_type) && !CT_IS_STRING_TYPE(node_type)) {
        datatype_len = cm_get_datatype_strlen(node_type, array_node->typmod.size);
        max_str_size = MAX(datatype_len, array_node->typmod.size);
        array_node->typmod.size = max_str_size;
        return CT_SUCCESS;
    }

    if (!CT_IS_STRING_TYPE(array_type) && CT_IS_STRING_TYPE(node_type)) {
        NODE_TYPMODE(array_node) = NODE_TYPMODE(expr_node);
        datatype_len = cm_get_datatype_strlen(array_type, expr_node->typmod.size);
        max_str_size = MAX(datatype_len, array_node->typmod.size);
        array_node->typmod.size = max_str_size;
        return CT_SUCCESS;
    }

    /* boolean type may have different size, only compare type */
    if (CT_IS_BOOLEAN_TYPE2(array_type, node_type)) {
        return CT_SUCCESS;
    }

    if (cm_combine_typmode(NODE_TYPMODE(array_node), CT_FALSE, NODE_TYPMODE(expr_node), NODE_IS_VALUE_NULL(expr_node),
        &tmr) != CT_SUCCESS) {
        return CT_ERROR;
    }

    NODE_TYPMODE(array_node) = tmr;
    return CT_SUCCESS;
}

static status_t sql_verify_array(sql_verifier_t *verif, expr_node_t *node)
{
    expr_tree_t *expr = node->argument;

    if (verif->excl_flags & SQL_EXCL_ARRAY) {
        CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected array expression");
        return CT_ERROR;
    }
    verif->incl_flags |= SQL_INCL_ARRAY;
    node->datatype = CT_TYPE_UNKNOWN;
    while (expr != NULL) {
        if (expr->root->type == EXPR_NODE_PARAM) {
            CT_SRC_THROW_ERROR(expr->loc, ERR_SQL_SYNTAX_ERROR, "unexpected bind parameter in array");
            return CT_ERROR;
        }
        if (sql_verify_expr_node(verif, expr->root) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (sql_verify_array_type(node, expr->root) != CT_SUCCESS) {
            return CT_ERROR;
        }

        expr = expr->next;
    }

    if (node->datatype == CT_TYPE_UNKNOWN) {
        node->datatype = CT_TYPE_VARCHAR;
        node->size = 0;
    }

    node->typmod.is_array = CT_TRUE;
    return CT_SUCCESS;
}

static inline status_t sql_verify_connect_by_oper(sql_verifier_t *verif, expr_node_t *node)
{
    if (node->unary == UNARY_OPER_ROOT) {
        if (verif->curr_query == NULL || verif->curr_query->connect_by_cond == NULL) {
            CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "CONNECT BY clause required in this query block");
            return CT_ERROR;
        }
        if (verif->excl_flags & SQL_EXCL_ROOT) {
            CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR,
                "CONNECT BY ROOT operator"
                " is not supported in the START WITH or in the CONNECT BY condition");
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static inline status_t sql_verify_unary(sql_verifier_t *verif, expr_node_t *node)
{
    if (node->type != EXPR_NODE_NEGATIVE) {
        return CT_SUCCESS;
    }

    if (CT_IS_UNSIGNED_INTEGER_TYPE(node->datatype)) {
        node->datatype = CT_TYPE_BIGINT;
        return CT_SUCCESS;
    }
    if (CT_IS_NUMERIC_TYPE(node->datatype) || CT_IS_UNKNOWN_TYPE(node->datatype)) {
        return CT_SUCCESS;
    }

    if (CT_IS_STRING_TYPE(node->datatype) || CT_IS_BINARY_TYPE(node->datatype)) {
        node->datatype = CT_TYPE_NUMBER;
        node->precision = CT_UNSPECIFIED_NUM_PREC; /* *< 0 stands for precision is not defined when create table */
        node->scale = CT_UNSPECIFIED_NUM_SCALE;
        node->size = MAX_DEC_BYTE_SZ;
        return CT_SUCCESS;
    }

    CT_SRC_THROW_ERROR(node->loc, ERR_TYPE_MISMATCH, "NUMERIC", get_datatype_name_str((int32)(node->datatype)));
    return CT_ERROR;
}

static inline status_t pl_check_forline_core(pl_line_for_t *line, plv_id_t vid, source_location_t loc)
{
    if (PL_VID_EQUAL(line->id->vid, vid)) {
        CT_SRC_THROW_ERROR(loc, ERR_PL_INVALID_LOOP_INDEX, T2S(&line->id->name));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t pl_check_forline(pl_line_ctrl_t *line, plv_id_t vid, source_location_t loc)
{
    if ((line != NULL) && (line->type == LINE_FOR)) {
        return pl_check_forline_core((pl_line_for_t *)line, vid, loc);
    }
    return CT_SUCCESS;
}

static status_t pl_verify_expr_param_node(sql_verifier_t *verif, expr_node_t *node)
{
    expr_node_t *input_node = NULL;
    pl_compiler_t *compiler = (pl_compiler_t *)verif->stmt->pl_compiler;
    if (compiler == NULL) {
        node->datatype = CT_TYPE_UNKNOWN;
        return CT_SUCCESS;
    }
    pl_line_ctrl_t *last_line = compiler->last_line;
    input_node = plc_get_param_vid(compiler, VALUE(uint32, &node->value));
    if (input_node == NULL) {
        node->datatype = CT_TYPE_UNKNOWN;
        return CT_SUCCESS;
    }

    var_address_pair_t *pair = sql_get_last_addr_pair(input_node);
    if (pair == NULL) {
        CT_THROW_ERROR(ERR_PLSQL_ILLEGAL_LINE_FMT, "unexpected param");
        return CT_ERROR;
    }
    if (pair->type == UDT_STACK_ADDR) {
        if ((pair->stack->decl->type == PLV_COLLECTION) && (verif->excl_flags & SQL_EXCL_COLL)) {
            CT_THROW_ERROR(ERR_PL_NOT_ALLOW_COLL);
            return CT_ERROR;
        }
        CT_RETURN_IFERR(pl_check_forline(last_line, pair->stack->decl->vid, node->loc));
    } else {
        CT_RETURN_IFERR(udt_get_addr_node_type(verif, input_node));
        if ((input_node->datatype == CT_TYPE_COLLECTION) && (verif->excl_flags & SQL_EXCL_COLL)) {
            CT_THROW_ERROR(ERR_PL_NOT_ALLOW_COLL);
            return CT_ERROR;
        }
    }

    node->datatype = CT_TYPE_UNKNOWN;
    return CT_SUCCESS;
}

static status_t pl_verify_expr_in_fetch(sql_verifier_t *verif, expr_node_t *node)
{
    uint32 param_id = VALUE(uint32, &node->value);
    if (param_id >= verif->stmt->context->params->count) {
        CT_SRC_THROW_ERROR(node->loc, ERR_INVALID_PARAMETER);
        return CT_ERROR;
    }

    sql_param_t *param = &verif->stmt->param_info.params[param_id];
    node->datatype = param->value.type;
    node->size = var_get_size(&param->value);
    if (CT_IS_DATETIME_TYPE(param->value.type)) {
        // may be we lost the origin typmod,so set the default
        node->precision = CT_MAX_DATETIME_PRECISION;
        node->scale = 0;
        node->size = sizeof(timestamp_t);
    } else if (CT_IS_NUMBER_TYPE(param->value.type)) {
        node->precision = 0;
        node->scale = 0;
        node->size = sizeof(dec8_t);
    }
    return CT_SUCCESS;
}

static inline status_t sql_verify_column_nodetype(sql_verifier_t *verif, expr_node_t *node)
{
    if ((verif->excl_flags & SQL_EXCL_ARRAY) && node->typmod.is_array == CT_TRUE) {
        CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected array expression");
        return CT_ERROR;
    }
    if ((verif->excl_flags & SQL_EXCL_COLUMN) &&
        (node->type == EXPR_NODE_COLUMN || node->type == EXPR_NODE_DIRECT_COLUMN)) {
        CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected column expression");
        return CT_ERROR;
    }
    if ((verif->excl_flags & SQL_EXCL_AGGR) && node->type == EXPR_NODE_AGGR) {
        CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected aggr expression");
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t sql_verify_pl_attr(sql_verifier_t *verif, expr_node_t *node)
{
    switch (node->value.v_plattr.type) {
        case PLV_ATTR_ISOPEN:
        case PLV_ATTR_FOUND:
        case PLV_ATTR_NOTFOUND:
            node->datatype = CT_TYPE_BOOLEAN;
            node->size = sizeof(bool32);
            break;
        case PLV_ATTR_ROWCOUNT:
            node->datatype = CT_TYPE_INTEGER;
            node->size = sizeof(bool32);
            break;
        default:
            CT_THROW_ERROR(ERR_PL_INVALID_ATTR_FMT);
            return CT_ERROR;
    }
    return CT_SUCCESS;
}

static inline status_t sql_verify_pl_decl(sql_verifier_t *verif, pl_compiler_t *compiler, plv_decl_t *decl,
    expr_node_t *node, plv_id_t vid)
{
    switch (decl->type) {
        case PLV_VAR:
            CT_RETURN_IFERR(pl_check_forline(compiler->last_line, vid, node->loc));
            node->typmod = decl->variant.type;
            break;
        case PLV_ARRAY:
            CT_RETURN_IFERR(pl_check_forline(compiler->last_line, vid, node->loc));
            node->typmod = decl->array.type;
            break;
        case PLV_CUR:
            if (decl->cursor.ctx != NULL && !decl->cursor.ctx->is_sysref) {
                CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected cursor type");
                return CT_ERROR;
            }
            node->datatype = CT_TYPE_CURSOR;
            break;
        case PLV_RECORD:
            node->datatype = CT_TYPE_RECORD;
            node->udt_type = (void *)decl->record;
            break;
        case PLV_OBJECT:
            node->datatype = CT_TYPE_OBJECT;
            node->udt_type = (void *)decl->object;
            break;
        case PLV_COLLECTION:
            node->datatype = CT_TYPE_COLLECTION;
            node->udt_type = (void *)decl->collection;
            break;
        case PLV_PARAM:
            if (verif->excl_flags & SQL_EXCL_BIND_PARAM) {
                CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected param occurs");
                return CT_ERROR;
            }
        // fall-through
        default:
            node->datatype = CT_TYPE_UNKNOWN;
            break;
    }
    return CT_SUCCESS;
}

static inline status_t sql_verify_pl_param(sql_verifier_t *verif, pl_compiler_t *compiler, plv_decl_t *decl,
    expr_node_t *node)
{
    pl_using_expr_t *using_expr = NULL;

    // DYNAMIC SQL VERIFY
    if (verif->excl_flags & SQL_EXCL_BIND_PARAM) {
        CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected param occurs");
        return CT_ERROR;
    }

    sql_stmt_t *parent = (sql_stmt_t *)compiler->stmt;
    if (parent == NULL || (parent->plsql_mode != PLSQL_DYNSQL && parent->plsql_mode != PLSQL_DYNBLK)) {
        // OTHER don't verify
        node->datatype = CT_TYPE_UNKNOWN;
        return CT_SUCCESS;
    }

    if (ple_get_dynsql_parent(compiler->stmt, &parent) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (ple_get_dynsql_using_expr(parent, decl->pnid, &using_expr) != CT_SUCCESS) {
        return CT_ERROR;
    }

    node->datatype = CT_TYPE_UNKNOWN;
    return CT_SUCCESS;
}

status_t sql_verify_pl_var(sql_verifier_t *verif, plv_id_t vid, expr_node_t *node)
{
    pl_compiler_t *compiler = (pl_compiler_t *)verif->stmt->pl_compiler;
    plv_decl_t *decl = NULL;

    CT_RETSUC_IFTRUE(compiler == NULL);
    decl = plc_find_decl_by_id(compiler, vid);
    CT_RETSUC_IFTRUE(decl == NULL); // do not verify dynamic sql

    return sql_verify_pl_decl(verif, compiler, decl, node, vid);
}

status_t sql_verify_expr_node_core(sql_verifier_t *verif, expr_node_t *node)
{
    status_t status;
    CM_POINTER2(node, verif);
    cm_reset_error_loc();
    CT_RETURN_IFERR(sql_verify_connect_by_oper(verif, node));

    switch (node->type) {
        case EXPR_NODE_CONST:
            node->datatype = node->value.type;
            node->size = (uint16)var_get_size(&node->value);
            node->optmz_info.mode = OPTIMIZE_AS_CONST;
            if (CT_IS_STRING_TYPE(node->datatype)) {
                node->typmod.is_char = CT_FALSE;
            }
            return CT_SUCCESS;

        case EXPR_NODE_PARAM:
            if ((verif->excl_flags & SQL_EXCL_BIND_PARAM) != 0) {
                CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected param occurs");
                return CT_ERROR;
            }

            // if parameter exists in condition, then need bind peeking
            if (verif->incl_flags & SQL_INCL_COND_COL) {
                verif->stmt->context->need_vpeek = CT_TRUE;
            }

            node->optmz_info.mode = OPTIMIZE_AS_PARAM;
            if (verif->stmt->pl_compiler != NULL) {
                return pl_verify_expr_param_node(verif, node);
            }
            if (verif->stmt->cursor_info.reverify_in_fetch) {
                return pl_verify_expr_in_fetch(verif, node);
            }
            node->datatype = CT_TYPE_UNKNOWN;
            return CT_SUCCESS;

        case EXPR_NODE_RESERVED:
            if (node->value.v_res.namable) {
                cm_set_ignore_log(CT_TRUE);
                if (sql_verify_column_expr(verif, node) == CT_SUCCESS) {
                    node->type = EXPR_NODE_COLUMN;
                    cm_set_ignore_log(CT_FALSE);
                    return CT_SUCCESS;
                }
                cm_set_ignore_log(CT_FALSE);
                cm_reset_error();
                node->value.type = CT_TYPE_INTEGER;
            }
            return sql_verify_reserved_value(verif, node);

        case EXPR_NODE_COLUMN:
        case EXPR_NODE_DIRECT_COLUMN:
            CT_RETURN_IFERR(sql_verify_column_expr(verif, node));
            status = sql_verify_column_nodetype(verif, node);
            break;

        case EXPR_NODE_CASE:
            if ((verif->excl_flags & SQL_EXCL_CASE) != 0) {
                CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected case when occurs");
                return CT_ERROR;
            }
            return sql_verify_case_expr(verif, node);

        case EXPR_NODE_JOIN:
            if (verif->excl_flags & SQL_EXCL_JOIN) {
                CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "invalid usage outer join symbol");
                return CT_ERROR;
            }

            verif->incl_flags |= SQL_INCL_JOIN;
            node->type = EXPR_NODE_COLUMN;
            CT_RETURN_IFERR(sql_verify_column_expr(verif, node));
            return sql_verify_column_nodetype(verif, node);

        case EXPR_NODE_SELECT:
            verif->incl_flags |= SQL_INCL_SUBSLCT;
            return sql_verify_select_expr(verif, node);

        case EXPR_NODE_CAT:
            status = sql_verify_cat(verif, node);
            break;

        /* The following case branches are used to compute constant expressions. */
        case EXPR_NODE_ADD:
        case EXPR_NODE_SUB:
        case EXPR_NODE_MUL:
        case EXPR_NODE_DIV:
        case EXPR_NODE_MOD: {
            CT_RETURN_IFERR(sql_verify_oper_node(verif, node));
            status = sql_adjust_oper_node(verif, node);
            break;
        }
        case EXPR_NODE_NEGATIVE: {
            CT_RETURN_IFERR(sql_verify_unary_oper_node(verif, node));
            status = sql_adjust_oper_node(verif, node);
            break;
        }
        case EXPR_NODE_PRIOR: {
            status = sql_verify_prior_node(verif, node);
            break;
        }
        case EXPR_NODE_BITAND:
        case EXPR_NODE_BITOR:
        case EXPR_NODE_BITXOR:
        case EXPR_NODE_LSHIFT:
        case EXPR_NODE_RSHIFT:
            CT_RETURN_IFERR(sql_verify_oper_node(verif, node));
            node->datatype = CT_TYPE_BIGINT;
            node->size = sizeof(int64);
            status = CT_SUCCESS;
            break;

        case EXPR_NODE_FUNC:
        case EXPR_NODE_PROC:
        case EXPR_NODE_USER_FUNC:
        case EXPR_NODE_USER_PROC:
            CT_RETURN_IFERR(sql_verify_func(verif, node));
            status = sql_add_ref_func_node(verif, node);
            break;

        case EXPR_NODE_STAR:
            if ((verif->excl_flags & SQL_EXCL_STAR) != 0) {
                CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexcpected '*'");
                return CT_ERROR;
            }
            status = CT_SUCCESS;
            break;

        case EXPR_NODE_AGGR:
        case EXPR_NODE_GROUP:
            return CT_SUCCESS;

        case EXPR_NODE_V_ADDR:
            return udt_verify_v_address(verif, node);

        case EXPR_NODE_V_METHOD:
            return udt_verify_v_method(verif, node);

        case EXPR_NODE_V_CONSTRUCT:
            return udt_verify_v_construct(verif, node);

        case EXPR_NODE_PL_ATTR:
            return sql_verify_pl_attr(verif, node);

        case EXPR_NODE_OVER:
            return sql_verify_winsort(verif, node);

        case EXPR_NODE_ARRAY:
            return sql_verify_array(verif, node);

        default:
            CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unknown expr node type");
            return CT_ERROR;
    }

    if (status != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_try_optimize_const_expr(verif->stmt, node);
}

status_t sql_verify_expr_node(sql_verifier_t *verif, expr_node_t *node)
{
    if (node->has_verified) {
        return CT_SUCCESS;
    }
    CT_RETURN_IFERR(sql_stack_safe(verif->stmt));

    CT_RETURN_IFERR(sql_verify_expr_node_core(verif, node));

    return sql_verify_unary(verif, node);
}

status_t sql_verify_current_expr(sql_verifier_t *verif, expr_tree_t *verf_expr)
{
    if (sql_verify_expr_node(verif, verf_expr->root) != CT_SUCCESS) {
        cm_try_set_error_loc(verf_expr->root->loc);
        return CT_ERROR;
    }

    if ((CT_IS_LOB_TYPE(verf_expr->root->datatype)) && ((verif->excl_flags & SQL_EXCL_LOB_COL) != 0)) {
        CT_SRC_THROW_ERROR(verf_expr->loc, ERR_SQL_SYNTAX_ERROR, "unexpected lob column occurs");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_verify_expr(sql_verifier_t *verif, expr_tree_t *expr)
{
    expr_tree_t *verf_expr = expr;

    // The expr_tree may be a expr tree list
    while (verf_expr != NULL) {
        CT_RETURN_IFERR(sql_verify_current_expr(verif, verf_expr));
        verf_expr = verf_expr->next;
    }

    return CT_SUCCESS;
}

status_t sql_try_verify_dbmsconst(sql_verifier_t *verif, expr_node_t *node, bool32 *result)
{
    sql_func_t *func = NULL;
    var_func_t v;
    column_word_t *col;

    col = &node->word.column;
    *result = CT_FALSE;

    sql_convert_pack_func(&col->table.value, &col->name.value, &v);
    if (v.func_id == CT_INVALID_ID32) {
        return CT_SUCCESS;
    }

    func = sql_get_pack_func(&v);

    CT_RETURN_IFERR(func->verify(verif, node));

    node->type = EXPR_NODE_FUNC;
    node->value.type = CT_TYPE_INTEGER;
    node->value.v_func.pack_id = v.pack_id;
    node->value.v_func.func_id = v.func_id;
    node->value.v_func.orig_func_id = v.orig_func_id;

    *result = CT_TRUE;
    return CT_SUCCESS;
}

static status_t sql_append_dependency_sequences(sql_verifier_t *verif, expr_node_t *node)
{
    object_address_t ref;
    dc_sequence_t *sequence = NULL;
    sequence_entry_t *entry = NULL;
    int32 errcode;
    if (verif->stmt->context->ref_objects != NULL) {
        knl_dictionary_t dc_seq;
        if (dc_seq_open(KNL_SESSION(verif->stmt), &node->value.v_seq.user, &node->value.v_seq.name, &dc_seq) ==
            CT_SUCCESS) {
            sequence = (dc_sequence_t *)dc_seq.handle;
            entry = sequence->entry;
            ref.tid = OBJ_TYPE_SEQUENCE;
            ref.oid = dc_seq.oid;
            ref.uid = dc_seq.uid;
            ref.scn = entry->chg_scn;
            errcode = strcpy_s(ref.name, CT_NAME_BUFFER_SIZE, entry->name);
            dc_seq_close(&dc_seq);
            MEMS_RETURN_IFERR(errcode);
            if (!sql_check_ref_exists(verif->stmt->context->ref_objects, &ref)) {
                CT_RETURN_IFERR(
                    cm_galist_copy_append(verif->stmt->context->ref_objects, sizeof(object_address_t), &ref));
            }
        } else {
            sql_check_user_priv(verif->stmt, &node->value.v_seq.user);
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}


status_t sql_try_verify_sequence(sql_verifier_t *verif, expr_node_t *node, bool32 *result)
{
    column_word_t *col = &node->word.column;
    seq_mode_t mode;
    text_t schema;

    *result = CT_FALSE;

    if (cm_text_equal_ins((text_t *)&col->name, &g_nextval)) {
        mode = SEQ_NEXT_VALUE;
    } else if (cm_text_equal_ins((text_t *)&col->name, &g_currval)) {
        mode = SEQ_CURR_VALUE;
    } else {
        return CT_SUCCESS;
    }

    if (verif->excl_flags & SQL_EXCL_SEQUENCE) {
        CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "unexpected sequence occurs");
        return CT_ERROR;
    }

    node->datatype = CT_TYPE_BIGINT;
    node->size = sizeof(int64);
    node->value.v_seq.mode = mode;
    node->value.v_seq.name = col->table.value;

    if (col->user.value.len == 0) {
        cm_str2text(verif->stmt->session->curr_schema, &schema);
        if (sql_copy_name(verif->stmt->context, &schema, &node->value.v_seq.user) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (sql_copy_prefix_tenant(verif->stmt, &col->user.value, &node->value.v_seq.user, sql_copy_name) !=
            CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    if (node->value.v_seq.name.len == 0) {
        return CT_SUCCESS;
    }

    /* add the referenced sequences info to ref_objects list */
    CT_RETURN_IFERR(sql_append_dependency_sequences(verif, node));
    node->type = EXPR_NODE_SEQUENCE;
    *result = CT_TRUE;
    CT_RETURN_IFERR(sql_add_sequence_node(verif->stmt, node));
    return CT_SUCCESS;
}

status_t sql_try_verify_rowid(sql_verifier_t *verif, expr_node_t *node, bool32 *result)
{
    column_word_t *col = &node->word.column;
    *result = CT_FALSE;

    if (!cm_text_equal((text_t *)&col->name, &g_rowid)) {
        return CT_SUCCESS;
    }

    node->type = EXPR_NODE_RESERVED;
    node->value.v_int = RES_WORD_ROWID;
    *result = CT_TRUE;
    return sql_verify_rowid(verif, node);
}

status_t sql_try_verify_rowscn(sql_verifier_t *verif, expr_node_t *node, bool32 *result)
{
    column_word_t *col = &node->word.column;
    *result = CT_FALSE;

    if (!cm_text_equal((text_t *)&col->name, &g_rowscn)) {
        return CT_SUCCESS;
    }

    node->type = EXPR_NODE_RESERVED;
    node->value.v_int = RES_WORD_ROWSCN;
    *result = CT_TRUE;
    return sql_verify_rowscn(verif, node);
}

#ifdef __cplusplus
}
#endif
