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
 * ctsql_cond_verifier.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/verifier/ctsql_cond_verifier.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_select_verifier.h"
#include "dml_parser.h"
#include "ctsql_func.h"
#include "expr_parser.h"
#include "ctsql_cond_rewrite.h"
#include "srv_instance.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MIN_REGEXP_LIKE_ARG_NUM 2
#define MAX_REGEXP_LIKE_ARG_NUM 3

bool32 sql_can_expr_node_optm_by_hash(expr_node_t *node)
{
    session_t *sess = knl_get_curr_sess();
    if (sql_stack_safe(sess->current_stmt) != CT_SUCCESS) {
        return CT_FALSE;
    }
    expr_tree_t *arg = NULL;

    if (NODE_IS_FIRST_EXECUTABLE(node)) {
        return CT_TRUE;
    }

    switch (node->type) {
        case EXPR_NODE_ADD:
        case EXPR_NODE_SUB:
        case EXPR_NODE_MUL:
        case EXPR_NODE_DIV:
        case EXPR_NODE_MOD:
        case EXPR_NODE_CAT:
        case EXPR_NODE_BITAND:
        case EXPR_NODE_BITOR:
        case EXPR_NODE_BITXOR:
        case EXPR_NODE_LSHIFT:
        case EXPR_NODE_RSHIFT:
            return (bool32)(sql_can_expr_node_optm_by_hash(node->left) && sql_can_expr_node_optm_by_hash(node->right));

        case EXPR_NODE_CONST:
        case EXPR_NODE_PARAM:
        case EXPR_NODE_CSR_PARAM:
            return CT_TRUE;

        case EXPR_NODE_RESERVED:
            return (bool32)(VAR_RES_ID(&node->value) == RES_WORD_SYSDATE ||
                VAR_RES_ID(&node->value) == RES_WORD_SYSTIMESTAMP || VAR_RES_ID(&node->value) == RES_WORD_NULL ||
                VAR_RES_ID(&node->value) == RES_WORD_TRUE || VAR_RES_ID(&node->value) == RES_WORD_FALSE);

        case EXPR_NODE_FUNC:
            if (node->value.v_func.func_id == ID_FUNC_ITEM_LNNVL) {
                return CT_FALSE;
            }
            arg = node->argument;
            while (arg != NULL) {
                if (!sql_can_expr_node_optm_by_hash(arg->root)) {
                    return CT_FALSE;
                }
                arg = arg->next;
            }
            return CT_TRUE;

        default:
            return CT_FALSE;
    }
}

static bool32 sql_can_optmz_by_hash_table(expr_tree_t *list, uint32 left_expr_count)
{
    uint32 expr_count, list_count;
    expr_tree_t *expr = list;

    if (left_expr_count > SQL_MAX_HASH_OPTM_KEYS) {
        return CT_FALSE;
    }

    expr_count = list_count = 0;

    while (expr != NULL) {
        if (!sql_can_expr_node_optm_by_hash(expr->root)) {
            return CT_FALSE;
        }
        if (++expr_count == left_expr_count) {
            expr_count = 0;
            ++list_count;
        }
        expr = expr->next;
    }
    return (list_count >= SQL_HASH_OPTM_THRESHOLD) ? CT_TRUE : CT_FALSE;
}

static inline void sql_add_hash_optm_node(sql_context_t *ctx, expr_node_t *node)
{
    if (ctx->hash_optm_count < SQL_MAX_HASH_OPTM_COUNT) {
        node->optmz_info.idx = ctx->hash_optm_count++;
        node->optmz_info.mode = OPTMZ_AS_HASH_TABLE;
    }
}

static inline bool32 in_can_convert_2_eq(cmp_node_t *cmp)
{
    if (cmp->type != CMP_TYPE_IN || cmp->left->next != NULL || cmp->right->next != NULL) {
        return CT_FALSE;
    }
    return CT_TRUE;
}

static status_t sql_verify_in_subselect_rs_col(sql_verifier_t *verif, sql_select_t *select_ctx)
{
    if (!(verif->excl_flags & SQL_EXCL_ARRAY)) {
        return CT_SUCCESS;
    }

    rs_column_t *rs_col = NULL;
    for (uint32 i = 0; i < select_ctx->first_query->rs_columns->count; i++) {
        rs_col = (rs_column_t *)cm_galist_get(select_ctx->first_query->rs_columns, i);
        if (rs_col->typmod.is_array) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "unsupported ARRAY expression in IN list");
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

static inline status_t sql_verify_in_rs_col(sql_verifier_t *verif, expr_tree_t *expr)
{
    sql_select_t *select_ctx = NULL;
    while (expr != NULL) {
        if (expr->root->type == EXPR_NODE_SELECT) {
            select_ctx = (sql_select_t *)expr->root->value.v_obj.ptr;
            CT_RETURN_IFERR(sql_verify_in_subselect_rs_col(verif, select_ctx));
        }
        expr = expr->next;
    }
    return CT_SUCCESS;
}

static status_t sql_verify_in_list(sql_verifier_t *verif, cmp_node_t *node)
{
    if (in_can_convert_2_eq(node)) {
        // a in (10) ==> a = 10
        node->type = CMP_TYPE_EQUAL;
        return CT_SUCCESS;
    }
    uint32 left_expr_count = sql_expr_list_len(node->left);
    if (verif->do_expr_optmz && !(node->type == CMP_TYPE_NOT_IN && left_expr_count > 1) &&
        !(sql_is_const_expr_tree(node->left) && sql_is_const_expr_tree(node->right)) &&
        sql_can_optmz_by_hash_table(node->right, left_expr_count)) {
        // not support multiple keys hash join anti
        sql_add_hash_optm_node(verif->context, node->left->root);
    }
    return CT_SUCCESS;
}

static status_t sql_verify_in_subselect(sql_verifier_t *verif, cmp_node_t *node)
{
    expr_tree_t *left_expr = node->left;
    uint32 left_expr_count = sql_expr_list_len(left_expr);
    sql_select_t *select_ctx = (sql_select_t *)node->right->root->value.v_obj.ptr;

    if (left_expr_count != select_ctx->first_query->rs_columns->count) {
        CT_THROW_ERROR((left_expr_count > select_ctx->first_query->rs_columns->count) ? ERR_NOT_ENOUGH_VALUES :
                                                                                        ERR_TOO_MANY_VALUES);
        return CT_ERROR;
    }
    if (!verif->do_expr_optmz || select_ctx->has_ancestor || select_ctx->type == SELECT_AS_VARIANT || IS_COORDINATOR ||
        (node->type == CMP_TYPE_NOT_IN && left_expr_count > 1)) {
        return CT_SUCCESS;
    }

    while (left_expr != NULL) {
        if (TREE_DATATYPE(left_expr) == CT_TYPE_UNKNOWN) {
            return CT_SUCCESS;
        }
        left_expr = left_expr->next;
    }

    sql_add_hash_optm_node(verif->context, node->left->root);
    return CT_SUCCESS;
}

static status_t sql_verify_in(sql_verifier_t *verif, cmp_node_t *node)
{
    sql_select_t *select_ctx = NULL;
    bool32 left_subslct = (bool32)(node->left->root->type == EXPR_NODE_SELECT);
    bool32 right_subslct = (bool32)(node->right->root->type == EXPR_NODE_SELECT);

    if (left_subslct) {
        select_ctx = (sql_select_t *)node->left->root->value.v_obj.ptr;
        select_ctx->type = SELECT_AS_VARIANT;
    }

    verif->excl_flags |= SQL_EXCL_JOIN;
    CT_RETURN_IFERR(sql_verify_expr(verif, node->left));
    CT_RETURN_IFERR(sql_verify_expr(verif, node->right));
    CT_RETURN_IFERR(sql_verify_in_rs_col(verif, node->left));
    CT_RETURN_IFERR(sql_verify_in_rs_col(verif, node->right));

    if (!left_subslct && !right_subslct) {
        return sql_verify_in_list(verif, node);
    }

    if (right_subslct && node->right->next == NULL) {
        return sql_verify_in_subselect(verif, node);
    }

    return CT_SUCCESS;
}

static status_t sql_verify_any_all(sql_verifier_t *verif, cmp_node_t *node)
{
    uint32 left_expr_count;
    sql_select_t *select_ctx = NULL;

    CT_RETURN_IFERR(sql_verify_expr(verif, node->left));
    CT_RETURN_IFERR(sql_verify_expr(verif, node->right));

    if (node->right->root->type == EXPR_NODE_SELECT) {
        left_expr_count = sql_expr_list_len(node->left);
        select_ctx = (sql_select_t *)node->right->root->value.v_obj.ptr;
        if (left_expr_count != select_ctx->first_query->rs_columns->count) {
            CT_THROW_ERROR(left_expr_count > select_ctx->first_query->rs_columns->count ? ERR_NOT_ENOUGH_VALUES :
                                                                                          ERR_TOO_MANY_VALUES);
            return CT_ERROR;
        }
        CT_RETURN_IFERR(sql_verify_in_subselect_rs_col(verif, select_ctx));
    }
    return CT_SUCCESS;
}

static status_t sql_verify_like(sql_verifier_t *verif, cmp_node_t *node)
{
    verif->excl_flags |= SQL_EXCL_JOIN;

    CT_RETURN_IFERR(sql_verify_expr(verif, node->left));

    CT_RETURN_IFERR(sql_verify_expr(verif, node->right));

    return CT_SUCCESS;
}

static status_t sql_verify_regexp(sql_verifier_t *verif, cmp_node_t *node)
{
    return sql_verify_like(verif, node);
}

static status_t sql_verify_regexp_like(sql_verifier_t *verif, expr_tree_t *expr)
{
    uint32 param_count = 0;
    expr_tree_t *curr = expr;
    while (curr != NULL) {
        ++param_count;
        curr = curr->next;
    }
    if (param_count > MAX_REGEXP_LIKE_ARG_NUM || param_count < MIN_REGEXP_LIKE_ARG_NUM) {
        CT_SRC_THROW_ERROR(expr->loc, ERR_INVALID_FUNC_PARAM_COUNT, "REGEXP_LIKE", MIN_REGEXP_LIKE_ARG_NUM,
            MAX_REGEXP_LIKE_ARG_NUM);
        return CT_ERROR;
    }
    CT_RETURN_IFERR(sql_verify_expr(verif, expr));
    return CT_SUCCESS;
}

static inline bool32 chk_subqry_rs_4_any2exists(sql_query_t *sub_query, rs_column_t *rs_col)
{
    if (rs_col->type == RS_COL_CALC) {
        cols_used_t cols_used;
        init_cols_used(&cols_used);
        sql_collect_cols_in_expr_tree(rs_col->expr, &cols_used);
        if (HAS_SUBSLCT(&cols_used)) {
            return CT_FALSE;
        }
    }
    return CT_TRUE;
}

static inline bool32 sql_expr_is_first_exec(expr_tree_t *list)
{
    expr_tree_t *expr = list;
    while (expr != NULL) {
        if (!sql_can_expr_node_optm_by_hash(expr->root)) {
            return CT_FALSE;
        }
        expr = expr->next;
    }
    return CT_TRUE;
}

static status_t sql_create_cast_node(sql_verifier_t *verif, expr_tree_t *source_expr, typmode_t typmod,
    expr_tree_t **cast_node)
{
    expr_tree_t *func = NULL;
    expr_tree_t *arg_type = NULL;
    // create cast func expr
    CT_RETURN_IFERR(sql_alloc_mem(verif->context, sizeof(expr_tree_t), (void **)&func));
    func->owner = verif->context;
    func->next = NULL;
    CT_RETURN_IFERR(sql_alloc_mem(verif->context, sizeof(expr_node_t), (void **)&func->root));
    func->root->owner = func;
    func->root->argument = source_expr;
    func->root->type = EXPR_NODE_FUNC;
    func->root->datatype = typmod.datatype;
    func->root->value.v_func.func_id = ID_FUNC_ITEM_CAST;
    func->root->value.v_func.pack_id = CT_INVALID_ID32;
    func->root->value.v_func.is_proc = CT_FALSE;
    func->root->value.v_func.arg_cnt = 1;
    func->root->value.v_func.orig_func_id = CT_INVALID_ID32;
    func->root->value.type = CT_TYPE_INTEGER;
    NODE_OPTIMIZE_MODE(func->root) = OPTIMIZE_AS_CONST;

    // create type expr
    CT_RETURN_IFERR(sql_alloc_mem(verif->context, sizeof(expr_tree_t), (void **)&arg_type));
    arg_type->owner = verif->context;
    arg_type->next = NULL;
    CT_RETURN_IFERR(sql_alloc_mem(verif->context, sizeof(expr_node_t), (void **)&arg_type->root));
    arg_type->root->owner = arg_type;
    arg_type->root->type = EXPR_NODE_CONST;
    arg_type->root->datatype = typmod.datatype;
    arg_type->root->value.type = CT_TYPE_TYPMODE;
    arg_type->root->value.v_type.datatype = typmod.datatype;
    arg_type->root->value.v_type.size = typmod.size;

    if (CT_IS_TIMESTAMP(typmod.datatype) || CT_IS_TIMESTAMP_TZ_TYPE(typmod.datatype) ||
        CT_IS_TIMESTAMP_LTZ_TYPE(typmod.datatype)) {
        arg_type->root->value.v_type.precision = CT_MAX_DATETIME_PRECISION;
    } else {
        arg_type->root->value.v_type.precision = 0;
    }
    SQL_SET_OPTMZ_MODE(arg_type->root, OPTIMIZE_AS_CONST);

    source_expr->next = arg_type;
    func->root->typmod = EXPR_VALUE(typmode_t, arg_type);
    sql_add_first_exec_node(verif, func->root);
    (*cast_node) = func;
    return CT_SUCCESS;
}

status_t sql_try_optimize_const2date(sql_verifier_t *verif, cmp_node_t *node, bool32 left_2_func)
{
    expr_tree_t *cast_node = NULL;

    if (left_2_func) {
        CT_RETURN_IFERR(sql_create_cast_node(verif, node->left, TREE_TYPMODE(node->right), &cast_node));
        node->left = cast_node;
    } else {
        CT_RETURN_IFERR(sql_create_cast_node(verif, node->right, TREE_TYPMODE(node->left), &cast_node));
        node->right = cast_node;
    }
    return CT_SUCCESS;
}

status_t sql_try_optimize_const2bool(sql_verifier_t *verif, cmp_node_t *node, bool32 left_2_optimize)
{
    CM_POINTER3(verif, (node->left->root), (node->right->root));

    expr_node_t *temp_node = left_2_optimize ? node->left->root : node->right->root;

    if (CT_IS_STRING_TYPE(NODE_DATATYPE(temp_node))) {
        CT_RETURN_IFERR(cm_text2bool(&temp_node->value.v_text, &temp_node->value.v_bool));
        temp_node->value.type = CT_TYPE_BOOLEAN;
        NODE_DATATYPE(temp_node) = CT_TYPE_BOOLEAN;
        temp_node->size = sizeof(bool32);
        return CT_SUCCESS;
    }

    if (NODE_DATATYPE(temp_node) == CT_TYPE_INTEGER) {
        if (NODE_VALUE(int32, temp_node) == 1 || NODE_VALUE(int32, temp_node) == 0) {
            temp_node->value.v_bool = (NODE_VALUE(int32, temp_node) == 1);
            NODE_DATATYPE(temp_node) = temp_node->value.type = CT_TYPE_BOOLEAN;
        }
        return CT_SUCCESS;
    }

    if (NODE_DATATYPE(temp_node) == CT_TYPE_BIGINT) {
        if (NODE_VALUE(int64, temp_node) == 1 || NODE_VALUE(int64, temp_node) == 0) {
            temp_node->value.v_bool = (NODE_VALUE(int64, temp_node) == 1);
            NODE_DATATYPE(temp_node) = temp_node->value.type = CT_TYPE_BOOLEAN;
            // the type of bigint is int64,so it need to change the node's size
            temp_node->size = sizeof(bool32);
        }
        return CT_SUCCESS;
    }

    return CT_SUCCESS;
}

status_t sql_try_optimize_const2numeric(sql_verifier_t *verif, cmp_node_t *node, bool32 left_2_optimize)
{
    expr_node_t *opt_node = left_2_optimize ? node->left->root : node->right->root;
    num_part_t np;
    np.excl_flag = NF_NONE;
    if (CT_IS_STRING_TYPE(NODE_DATATYPE(opt_node)) && cm_split_num_text(&opt_node->value.v_text, &np) == NERR_SUCCESS) {
        CT_RETURN_IFERR(cm_text_to_dec(&opt_node->value.v_text, &opt_node->value.v_dec));
        opt_node->value.type = CT_TYPE_NUMBER;
        NODE_DATATYPE(opt_node) = CT_TYPE_NUMBER;
        opt_node->size = sizeof(dec8_t);
    }

    return CT_SUCCESS;
}

status_t sql_try_optimize_cmp_node(sql_verifier_t *verif, cmp_node_t *node)
{
    return CT_SUCCESS;
}

static inline status_t sql_verify_join_symbol_cmp(sql_verifier_t *verif, cmp_node_t *node, uint32 left_tab_id,
    uint32 right_tab_id)
{
    join_symbol_cmp_t *join_symbol_cmp = NULL;
    if (node->join_type == JOIN_TYPE_RIGHT) {
        if (left_tab_id == right_tab_id) {
            CT_SRC_THROW_ERROR(node->right->loc, ERR_SQL_SYNTAX_ERROR,
                "not support same table on two side of the operator symbol when using (+)");
            return CT_ERROR;
        }
        CT_RETURN_IFERR(cm_galist_new(verif->join_symbol_cmps, sizeof(join_symbol_cmp_t), (void **)&join_symbol_cmp));
        join_symbol_cmp->cmp_node = node;
        join_symbol_cmp->left_tab = left_tab_id;
        join_symbol_cmp->right_tab = right_tab_id;
    } else if (node->join_type == JOIN_TYPE_LEFT) {
        if (left_tab_id == right_tab_id) {
            CT_SRC_THROW_ERROR(node->left->loc, ERR_SQL_SYNTAX_ERROR,
                "not support same table on two side of the operator symbol when using (+)");
            return CT_ERROR;
        }
        CT_RETURN_IFERR(cm_galist_new(verif->join_symbol_cmps, sizeof(join_symbol_cmp_t), (void **)&join_symbol_cmp));
        join_symbol_cmp->cmp_node = node;
        join_symbol_cmp->left_tab = right_tab_id;
        join_symbol_cmp->right_tab = left_tab_id;
    }

    return CT_SUCCESS;
}

static status_t sql_verify_compare_normal(sql_verifier_t *verif, cmp_node_t *node)
{
    verif->join_tab_id = CT_INVALID_ID32;
    verif->same_join_tab = CT_TRUE;

    CT_RETURN_IFERR(sql_verify_expr(verif, node->left));
    uint32 left_tab_id = verif->join_tab_id;

    if (verif->incl_flags & SQL_INCL_JOIN) {
        if (!verif->same_join_tab) {
            CT_SRC_THROW_ERROR(node->left->loc, ERR_SQL_SYNTAX_ERROR,
                "not support multiple tables on one side of the operator symbol when using (+)");
            return CT_ERROR;
        }

        if (left_tab_id == CT_INVALID_ID32) {
            CT_SRC_THROW_ERROR(node->left->loc, ERR_SQL_SYNTAX_ERROR,
                "The (+) operator can be applied only to a column of a table");
            return CT_ERROR;
        }

        node->join_type = JOIN_TYPE_LEFT;
        verif->excl_flags |= SQL_EXCL_JOIN;
        verif->incl_flags &= ~SQL_INCL_JOIN;
    }

    if (!verif->same_join_tab) {
        verif->excl_flags |= SQL_EXCL_JOIN;
        verif->same_join_tab = CT_TRUE;
    }

    verif->join_tab_id = CT_INVALID_ID32;
    CT_RETURN_IFERR(sql_verify_expr(verif, node->right));
    uint32 right_tab_id = verif->join_tab_id;

    if (verif->incl_flags & SQL_INCL_JOIN) {
        if (right_tab_id == CT_INVALID_ID32) {
            CT_SRC_THROW_ERROR(node->right->loc, ERR_SQL_SYNTAX_ERROR,
                "The (+) operator can be applied only to a column of a table");
            return CT_ERROR;
        }

        node->join_type = JOIN_TYPE_RIGHT;
        verif->incl_flags &= ~SQL_INCL_JOIN;
    }

    if (node->join_type != JOIN_TYPE_NONE && !verif->same_join_tab) {
        CT_SRC_THROW_ERROR(node->right->loc, ERR_SQL_SYNTAX_ERROR,
            "not support multiple tables on one side of the operator symbol when using (+)");
        return CT_ERROR;
    }

    if (verif->join_symbol_cmps != NULL) {
        CT_RETURN_IFERR(sql_verify_join_symbol_cmp(verif, node, left_tab_id, right_tab_id));
    }

    return sql_try_optimize_cmp_node(verif, node);
}

static status_t sql_verify_compare(sql_verifier_t *verif, cmp_node_t *node)
{
    uint32 excl_flags_bak = verif->excl_flags;
    switch (node->type) {
        case CMP_TYPE_IS_NULL:
        case CMP_TYPE_IS_NOT_NULL:
            verif->excl_flags |= SQL_EXCL_JOIN;
            CT_RETURN_IFERR(sql_verify_expr(verif, node->left));
            break;
        case CMP_TYPE_IS_JSON:
        case CMP_TYPE_IS_NOT_JSON: {
            verif->excl_flags |= SQL_EXCL_ARRAY;
            verif->excl_flags &= (~SQL_EXCL_LOB_COL);
            CT_RETURN_IFERR(sql_verify_expr(verif, node->left));
            break;
        }
        case CMP_TYPE_IN:
        case CMP_TYPE_NOT_IN:
            verif->excl_flags |= SQL_EXCL_JOIN | SQL_EXCL_ARRAY;
            CT_RETURN_IFERR(sql_verify_in(verif, node));
            break;
        case CMP_TYPE_EQUAL_ANY:
        case CMP_TYPE_NOT_EQUAL_ANY:
        case CMP_TYPE_GREAT_EQUAL_ANY:
        case CMP_TYPE_GREAT_ANY:
        case CMP_TYPE_LESS_ANY:
        case CMP_TYPE_LESS_EQUAL_ANY:
        case CMP_TYPE_EQUAL_ALL:
        case CMP_TYPE_NOT_EQUAL_ALL:
        case CMP_TYPE_GREAT_EQUAL_ALL:
        case CMP_TYPE_GREAT_ALL:
        case CMP_TYPE_LESS_ALL:
        case CMP_TYPE_LESS_EQUAL_ALL:
            verif->excl_flags |= SQL_EXCL_JOIN | SQL_EXCL_ARRAY;
            CT_RETURN_IFERR(sql_verify_any_all(verif, node));
            break;
        case CMP_TYPE_BETWEEN:
        case CMP_TYPE_NOT_BETWEEN:
            verif->excl_flags |= SQL_EXCL_JOIN | SQL_EXCL_ARRAY;
            CT_RETURN_IFERR(sql_verify_expr(verif, node->left));
            CT_RETURN_IFERR(sql_verify_expr(verif, node->right));
            break;
        case CMP_TYPE_EXISTS:
        case CMP_TYPE_NOT_EXISTS:
            verif->excl_flags |= SQL_EXCL_JOIN | SQL_EXCL_ARRAY;
            CT_RETURN_IFERR(sql_verify_expr(verif, node->right));
            break;
        case CMP_TYPE_REGEXP_LIKE:
        case CMP_TYPE_NOT_REGEXP_LIKE:
            verif->excl_flags |= SQL_EXCL_JOIN;
            CT_RETURN_IFERR(sql_verify_regexp_like(verif, node->right));
            break;
        case CMP_TYPE_LIKE:
        case CMP_TYPE_NOT_LIKE:
            verif->excl_flags |= SQL_EXCL_JOIN;
            CT_RETURN_IFERR(sql_verify_like(verif, node));
            break;
        case CMP_TYPE_REGEXP:
        case CMP_TYPE_NOT_REGEXP:
            verif->excl_flags |= SQL_EXCL_JOIN;
            CT_RETURN_IFERR(sql_verify_regexp(verif, node));
            break;
        case CMP_TYPE_EQUAL:
        case CMP_TYPE_NOT_EQUAL:
        case CMP_TYPE_GREAT_EQUAL:
        case CMP_TYPE_GREAT:
        case CMP_TYPE_LESS:
        case CMP_TYPE_LESS_EQUAL:
        default:
            verif->excl_flags |= SQL_EXCL_ARRAY;
            CT_RETURN_IFERR(sql_verify_compare_normal(verif, node));
            break;
    }
    verif->excl_flags = excl_flags_bak;
    return CT_SUCCESS;
}

static status_t sql_static_check_exprs(const expr_tree_t *left, const expr_tree_t *right)
{
    if (sql_is_skipped_expr(left) || sql_is_skipped_expr(right)) {
        return CT_SUCCESS;
    }

    if (get_cmp_datatype(TREE_DATATYPE(left), TREE_DATATYPE(right)) == INVALID_CMP_DATATYPE) {
        if (IS_COMPLEX_TYPE(TREE_DATATYPE(left)) || IS_COMPLEX_TYPE(TREE_DATATYPE(right))) {
            CT_THROW_ERROR(ERR_SQL_SYNTAX_ERROR, "complex type cannot be used for condition");
        } else {
            CT_SRC_ERROR_MISMATCH(TREE_LOC(right), TREE_DATATYPE(left), TREE_DATATYPE(right));
        }
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

/**
 * @see sql_match_in_list

 */
static inline status_t sql_static_check_in_list(const cmp_node_t *node)
{
    const expr_tree_t *left_list = NULL;
    const expr_tree_t *right_list = node->right;

    while (right_list != NULL) { // every outer loop compare a list
        left_list = node->left;
        while (left_list != NULL) { // the next compare between two list begin
            if (sql_static_check_exprs(left_list, right_list) != CT_SUCCESS) {
                return CT_ERROR;
            }
            left_list = left_list->next;
            right_list = right_list->next;
        }
    }

    return CT_SUCCESS;
}

static status_t sql_static_check_in(const cmp_node_t *node)
{
    if (EXPR_NODE_SELECT == TREE_EXPR_TYPE(node->right)) {
        return CT_SUCCESS;
    } else {
        return sql_static_check_in_list(node);
    }
}

static status_t sql_static_check_between(const cmp_node_t *node)
{
    if (sql_static_check_exprs(node->left, node->right) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_static_check_exprs(node->left, node->right->next);
}

static status_t sql_static_check_compare(const cmp_node_t *node)
{
    switch (node->type) {
        case CMP_TYPE_EQUAL_ANY:
        case CMP_TYPE_NOT_EQUAL_ANY:
        case CMP_TYPE_GREAT_EQUAL_ANY:
        case CMP_TYPE_GREAT_ANY:
        case CMP_TYPE_LESS_ANY:
        case CMP_TYPE_LESS_EQUAL_ANY:
        case CMP_TYPE_EQUAL_ALL:
        case CMP_TYPE_NOT_EQUAL_ALL:
        case CMP_TYPE_GREAT_EQUAL_ALL:
        case CMP_TYPE_GREAT_ALL:
        case CMP_TYPE_LESS_ALL:
        case CMP_TYPE_LESS_EQUAL_ALL:
        case CMP_TYPE_IN:
        case CMP_TYPE_NOT_IN:
            return sql_static_check_in(node);

        case CMP_TYPE_BETWEEN:
        case CMP_TYPE_NOT_BETWEEN:
            return sql_static_check_between(node);

        case CMP_TYPE_EQUAL:
        case CMP_TYPE_GREAT_EQUAL:
        case CMP_TYPE_GREAT:
        case CMP_TYPE_LESS:
        case CMP_TYPE_LESS_EQUAL:
        case CMP_TYPE_NOT_EQUAL:
            return sql_static_check_exprs(node->left, node->right);

        case CMP_TYPE_LIKE:
        case CMP_TYPE_NOT_LIKE:
        case CMP_TYPE_EXISTS:
        case CMP_TYPE_NOT_EXISTS:
        case CMP_TYPE_IS_NULL:
        case CMP_TYPE_IS_NOT_NULL:
        case CMP_TYPE_IS_JSON:
        case CMP_TYPE_IS_NOT_JSON:

        default:
            return CT_SUCCESS;
    }
}

static inline void sql_try_restore_winsort_list(sql_verifier_t *verif, cond_node_t *node, uint32 winsort_count)
{
    if (verif->curr_query != NULL && (node->type == COND_NODE_TRUE || node->type == COND_NODE_FALSE)) {
        verif->curr_query->winsort_list->count = winsort_count;
    }
}

//         To evaluate constant condition node at verification stage.
static status_t sql_verify_cond_node(sql_verifier_t *verif, cond_node_t *node, uint32 *rnum_upper, bool8 *rnum_pending)
{
    CT_RETURN_IFERR(sql_stack_safe(verif->stmt));

    bool8 l_pending = CT_FALSE;
    bool8 r_pending = CT_FALSE;
    uint32 l_upper, r_upper;
    uint32 excl_flags_bak = verif->excl_flags;
    uint32 winsort_count = verif->curr_query != NULL ? verif->curr_query->winsort_list->count : 0;

    switch (node->type) {
        case COND_NODE_COMPARE:

            CT_RETURN_IFERR(sql_verify_compare(verif, node->cmp));

            CT_RETURN_IFERR(sql_static_check_compare(node->cmp));

            CT_RETURN_IFERR(try_eval_compare_node(verif->stmt, node, rnum_upper, rnum_pending));
            node->cmp->rnum_pending = *rnum_pending;

            if (node->cmp->join_type == JOIN_TYPE_LEFT || node->cmp->join_type == JOIN_TYPE_RIGHT) {
                node->type = COND_NODE_TRUE;
            }
            break;

        case COND_NODE_OR:

            verif->excl_flags |= SQL_EXCL_JOIN;
            CT_RETURN_IFERR(sql_verify_cond_node(verif, node->left, &l_upper, &l_pending));
            CT_RETURN_IFERR(sql_verify_cond_node(verif, node->right, &r_upper, &r_pending));

            *rnum_upper = MAX(l_upper, r_upper);
            *rnum_pending = l_pending || r_pending;
            try_eval_logic_or(node);
            verif->excl_flags = excl_flags_bak;
            break;

        case COND_NODE_AND:
            CT_RETURN_IFERR(sql_verify_cond_node(verif, node->left, &l_upper, &l_pending));
            CT_RETURN_IFERR(sql_verify_cond_node(verif, node->right, &r_upper, &r_pending));

            *rnum_upper = MIN(l_upper, r_upper);
            *rnum_pending = l_pending || r_pending;
            try_eval_logic_and(node);
            break;

        case COND_NODE_FALSE:
            *rnum_upper = 0U;
            *rnum_pending = CT_FALSE;
            break;

        case COND_NODE_TRUE:
        case COND_NODE_NOT: // already eliminated in parsing phase
        default:
            *rnum_upper = CT_INFINITE32;
            *rnum_pending = CT_FALSE;
            break;
    }
    sql_try_restore_winsort_list(verif, node, winsort_count);
    return CT_SUCCESS;
}

status_t sql_verify_cond(sql_verifier_t *verif, cond_tree_t *cond)
{
    if (cond == NULL) {
        return CT_SUCCESS;
    }

    verif->excl_flags |= SQL_EXCL_ROWNODEID;
    verif->incl_flags |= SQL_INCL_COND_COL;
    if (sql_verify_cond_node(verif, cond->root, &cond->rownum_upper, &cond->rownum_pending) != CT_SUCCESS) {
        return CT_ERROR;
    }

    verif->incl_flags &= ~(SQL_INCL_COND_COL);
    cond->incl_flags = verif->incl_flags;
    return sql_process_oper_or_sink(verif->stmt, &cond->root);
}

status_t sql_verify_query_where(sql_verifier_t *verif, sql_query_t *query)
{
    if (query->cond == NULL) {
        return CT_SUCCESS;
    }

    verif->tables = &query->tables;
    verif->curr_query = query;
    verif->incl_flags = 0;
    verif->excl_flags = SQL_WHERE_EXCL;
    verif->has_acstor_col = CT_FALSE;
    verif->join_symbol_cmps = query->join_symbol_cmps;

    if (sql_verify_cond(verif, query->cond) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (verif->has_acstor_col) {
        query->cond_has_acstor_col = CT_TRUE;
    }

    /* if exists connect by and where_cond in query->cond,where_cond needs down query->filter_cond
           reason: if do not push the where_cond which in query->cond down to query->filter_cond at here,
           the query->cond will contain both where_cond and join_on_cond at transform stage.At that time,
           we will not be able to distinguish them, so they will both be pushed down to query->filter_cond
           in error if exists connect by.
        */
    if (query->connect_by_cond != NULL) {
        CT_RETURN_IFERR(sql_split_filter_cond(verif->stmt, query->cond->root, &query->filter_cond));
    }

    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
