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
 * ctsql_func_verifier.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/verifier/ctsql_func_verifier.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_expr_verifier.h"
#include "ctsql_func.h"
#include "ctsql_package.h"
#include "ctsql_privilege.h"
#include "srv_instance.h"

#ifdef __cplusplus
extern "C" {
#endif

static status_t inline sql_adjust_func_node(sql_stmt_t *stmt, expr_node_t *expr)
{
    expr->type = EXPR_NODE_FUNC;
    if (!CM_IS_EMPTY(&expr->word.column.user)) {
        expr->word.func.user = expr->word.column.user;
        expr->word.func.pack = expr->word.column.table;
        expr->word.func.name = expr->word.column.name;
        expr->word.func.count = 3;
    } else {
        expr->word.func.org_user = expr->word.column.table;
        expr->word.func.user = expr->word.column.user_ex;
        expr->word.func.pack.value = CM_NULL_TEXT;
        expr->word.func.name = expr->word.column.name;
        if (CM_IS_EMPTY(&expr->word.func.user)) {
            expr->word.func.count = 1;
        } else {
            expr->word.func.count = 2;
        }
    }
    expr->word.func.user_func_first = CT_TRUE;
    expr->word.func.args.value = CM_NULL_TEXT;

    if (cm_text_str_equal_ins(&expr->word.func.user.value, SYS_USER_NAME)) {
        return sql_check_user_tenant(KNL_SESSION(stmt));
    }

    return CT_SUCCESS;
}

static status_t sql_try_verify_func3(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found)
{
    status_t status;

    /* 1.try find built-in sys.package.name consider case sensitivity */
    status = pl_try_verify_sys_pack_func3(verif, node, obj, is_found);
    if (*is_found) {
        return status;
    }
    pl_revert_last_error(status);

    /* 2.try find user.package.name */
    status = pl_try_verify_pack_func3(verif, node, obj, is_found);
    if (*is_found) {
        return status;
    }
    pl_revert_last_error(status);

    return CT_SUCCESS;
}

static status_t sql_try_verify_func1(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found)
{
    bool32 user_func = node->word.func.user_func_first;
    status_t status;

    /* 1.try as function in current package, if found return SUCCESS, otherwise reset error */
    status = pl_try_verify_pack_func1(verif, node, obj, is_found);
    if (*is_found) {
        return status;
    }
    pl_revert_last_error(status);

    /* 2.check if it is a recursive function */
    status = pl_try_verify_recursion_func1(verif, node, obj, is_found);
    if (*is_found) {
        return status;
    }
    pl_revert_last_error(status);

    if (user_func) {
        /* 3.as [current_schema/view_owner].func/proc */
        status = pl_try_verify_func1(verif, node, obj, is_found);
        if (*is_found) {
            return status;
        }
        pl_revert_last_error(status);

        /* 4.as system func like "abs/sum" */
        status = pl_try_verify_builtin_func(verif, node, obj, is_found);
        if (*is_found) {
            return status;
        }
        pl_revert_last_error(status);

        /* 5.check is dbms_standard function or not, such as RAISE_APPLICATION_ERROR(). */
        status = pl_try_verify_pack_std(verif, node, obj, is_found);
        if (*is_found) {
            return status;
        }
        pl_revert_last_error(status);
    } else {
        /* 3.as system func like "abs/sum" */
        status = pl_try_verify_builtin_func(verif, node, obj, is_found);
        if (*is_found) {
            return status;
        }
        pl_revert_last_error(status);

        /* 4.check is dbms_standard function or not, such as RAISE_APPLICATION_ERROR(). */
        status = pl_try_verify_pack_std(verif, node, obj, is_found);
        if (*is_found) {
            return status;
        }
        pl_revert_last_error(status);

        /* 5.as [current_schema/view_owner].func/proc */
        status = pl_try_verify_func1(verif, node, obj, is_found);
        if (*is_found) {
            return status;
        }
        pl_revert_last_error(status);
    }

    /* 6.try as public.obj */
    status = pl_try_verify_public_func1(verif, node, obj, is_found);
    if (*is_found) {
        return status;
    }
    pl_revert_last_error(status);

    return CT_SUCCESS;
}

static status_t sql_try_verify_func2(sql_verifier_t *verif, expr_node_t *node, var_udo_t *obj, bool32 *is_found)
{
    status_t status;

    /* 1.try as recursion function */
    status = pl_try_verify_recursion_func2(verif, node, obj, is_found);
    if (*is_found) {
        return status;
    }
    pl_revert_last_error(status);

    /* 2.try as [current_schema/view_owner].pack.name */
    status = pl_try_verify_pack_func2(verif, node, obj, is_found);
    if (*is_found) {
        return status;
    }
    pl_revert_last_error(status);

    /* 3.try as built-in package like dbe_rsrc_mgr.xxx */
    status = pl_try_verify_sys_pack_func2(verif, node, obj, is_found);
    if (*is_found) {
        return status;
    }
    pl_revert_last_error(status);

    /* 4.try as user.name */
    status = pl_try_verify_func2(verif, node, obj, is_found);
    if (*is_found) {
        return status;
    }
    pl_revert_last_error(status);

    /* 5.try as public.object */
    status = pl_try_verify_public_func2(verif, node, obj, is_found);
    if (*is_found) {
        return status;
    }
    pl_revert_last_error(status);

    return CT_SUCCESS;
}

status_t pl_check_same_arg_name(expr_node_t *func)
{
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    for (arg1 = func->argument; arg1 != NULL; arg1 = arg1->next) {
        CT_CONTINUE_IFTRUE(arg1->arg_name.len == 0);
        for (arg2 = arg1->next; arg2 != NULL; arg2 = arg2->next) {
            CT_CONTINUE_IFTRUE(arg2->arg_name.len == 0);
            if (cm_compare_text(&arg1->arg_name, &arg2->arg_name) == 0) {
                CT_SRC_THROW_ERROR(arg1->loc, ERR_PL_DUP_ARG_FMT, T2S(&arg1->arg_name),
                    T2S_EX(&func->word.func.name.value));
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

static status_t sql_try_verify_func(sql_verifier_t *verif, expr_node_t *node, bool32 *is_found)
{
    var_udo_t obj;
    char user[CT_NAME_BUFFER_SIZE];
    char pack[CT_NAME_BUFFER_SIZE];
    char name[CT_NAME_BUFFER_SIZE];

    sql_init_udo_with_str(&obj, user, pack, name);
    CT_RETURN_IFERR(pl_check_same_arg_name(node));
    if (node->word.func.count == 1 || node->word.func.count == 0) {
        return sql_try_verify_func1(verif, node, &obj, is_found);
    } else if (node->word.func.count == 2) {
        return sql_try_verify_func2(verif, node, &obj, is_found);
    } else {
        return sql_try_verify_func3(verif, node, &obj, is_found);
    }
}

static status_t sql_verify_func_return_error(sql_verifier_t *verif, expr_node_t *node)
{
    if (node->word.func.count == 1 || node->word.func.count == 0) {
        return pl_try_verify_return_error1(verif, node);
    } else if (node->word.func.count == 2) {
        return pl_try_verify_return_error2(verif, node);
    } else {
        return pl_try_verify_return_error3(verif, node);
    }
}

status_t sql_verify_func(sql_verifier_t *verif, expr_node_t *node)
{
    bool32 is_found = CT_FALSE;
    verif->excl_flags |= SQL_EXCL_METH_PROC;
    uint32 save_excl_flags = verif->excl_flags;
    verif->excl_flags &= (~SQL_EXCL_ARRAY);
    status_t status = sql_try_verify_func(verif, node, &is_found);
    verif->excl_flags = save_excl_flags;
    CT_RETURN_IFERR(status);
    if (!is_found) {
        return sql_verify_func_return_error(verif, node);
    }
    if ((node->type == EXPR_NODE_PROC || node->type == EXPR_NODE_USER_PROC) && (verif->excl_flags & SQL_EXCL_PL_PROC)) {
        CT_SRC_THROW_ERROR(node->loc, ERR_SQL_SYNTAX_ERROR, "procedure is not allowed here.");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t sql_try_verify_noarg_func(sql_verifier_t *verif, expr_node_t *node, bool32 *is_found)
{
    if (node->type == EXPR_NODE_RESERVED) {
        return CT_FALSE;
    }

    expr_node_t node_bak = *node;
    if (sql_adjust_func_node(verif->stmt, node) != CT_SUCCESS) {
        *node = node_bak;
        return CT_ERROR;
    }

    status_t status = sql_try_verify_func(verif, node, is_found);
    CT_RETURN_IFERR(status);
    if (!(*is_found)) {
        *node = node_bak;
    }
    return CT_SUCCESS;
}

/* * Merge the current first executable node as the sub-node of the new_idx */
static inline void sql_merge_first_exec_node(sql_verifier_t *verif, expr_node_t *node, uint32 new_idx)
{
    SQL_SET_OPTMZ_MODE(node, OPTMZ_FIRST_EXEC_NODE);
    if (new_idx != NODE_OPTMZ_IDX(node)) {
        --(verif->context->fexec_vars_cnt);
        node->optmz_info.idx = (uint16)new_idx;
    }

    // If the merged node is var-length datatype, its memory should be reduced
    if (CT_IS_VARLEN_TYPE(node->datatype)) {
        verif->context->fexec_vars_bytes -= node->size;
    }
}

static inline status_t sql_scan_func_args_optmz_mode(expr_node_t *func, expr_tree_t *expr,
    expr_optmz_info_t *func_optmz_info)
{
    while (expr != NULL) {
        if (func_optmz_info->mode > NODE_OPTIMIZE_MODE(expr->root)) {
            func_optmz_info->mode = NODE_OPTIMIZE_MODE(expr->root);
            switch (func_optmz_info->mode) {
                case OPTIMIZE_NONE:
                    // if one of the argument can not be optimized,
                    // then the function also can not be optimized
                    SQL_SET_OPTMZ_MODE(func, OPTIMIZE_NONE);
                    return CT_ERROR;
                case OPTMZ_FIRST_EXEC_ROOT:
                    func_optmz_info->idx = MIN(func_optmz_info->idx, NODE_OPTMZ_IDX(expr->root));
                    break;
                case OPTIMIZE_AS_CONST:
                case OPTIMIZE_AS_PARAM:
                    break;
                default:
                    CM_NEVER;
                    break;
            }
        }

        expr = expr->next;
    }

    return CT_SUCCESS;
}

/* * scan the func's arguments, and decide the optmz mode */
void sql_infer_func_optmz_mode(sql_verifier_t *verif, expr_node_t *func)
{
    // Step 1: scan all modes of arguments
    expr_tree_t *expr = func->argument;
    if (expr == NULL) {
        return;
    }

    expr_optmz_info_t func_optmz_info = {
        .mode = OPTMZ_INVAILD,
        .idx = CT_INVALID_ID16
    };

    CT_RETVOID_IFERR(sql_scan_func_args_optmz_mode(func, expr, &func_optmz_info));

    // Step 2: decide the optmz mode
    // if all arguments are constant, the function can be constantly optimized.
    if (func_optmz_info.mode == OPTIMIZE_AS_CONST) {
        SQL_SET_OPTMZ_MODE(func, OPTIMIZE_AS_CONST);
        return;
    }

    // if all arguments are params or params and constants
    // the function can be computed in advance on the first execution
    if (func_optmz_info.mode == OPTIMIZE_AS_PARAM) {
        sql_add_first_exec_node(verif, func);
        return;
    }

    if (func_optmz_info.idx == CT_INVALID_ID16) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "idx(%u) != CT_INVALID_ID16(%u)", (uint32)func_optmz_info.idx,
            (uint32)CT_INVALID_ID16);
    }
    if (func_optmz_info.mode != OPTMZ_FIRST_EXEC_ROOT) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "mode(%u) == OPTMZ_FIRST_EXEC_ROOT(%u)", (uint32)func_optmz_info.mode,
            (uint32)OPTMZ_FIRST_EXEC_ROOT);
    }

    func->optmz_info.mode = OPTMZ_FIRST_EXEC_ROOT;
    func->optmz_info.idx = func_optmz_info.idx;
    expr = func->argument;
    while (expr != NULL) {
        if (NODE_IS_FIRST_EXECUTABLE(expr->root)) {
            sql_merge_first_exec_node(verif, expr->root, func_optmz_info.idx);
        }
        expr = expr->next;
    }

    if (CT_IS_VARLEN_TYPE(func->datatype)) {
        verif->context->fexec_vars_bytes += func->size;
    }
}

/* * decide the optmz mode of a binary operator node, such as +, - *, /. */
void sql_infer_oper_optmz_mode(sql_verifier_t *verif, expr_node_t *node)
{
    // Step 1: scan all modes of arguments
    optmz_mode_t mode = MIN(NODE_OPTIMIZE_MODE(node->left), NODE_OPTIMIZE_MODE(node->right));
    uint32 index = CT_INVALID_ID16;

    if (mode == OPTIMIZE_NONE || mode == OPTIMIZE_AS_CONST || mode == OPTIMIZE_AS_PARAM) {
        SQL_SET_OPTMZ_MODE(node, mode);
        return;
    }

    if (mode != OPTMZ_FIRST_EXEC_ROOT) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "mode(%u) == OPTMZ_FIRST_EXEC_ROOT(%u)", (uint32)mode,
            (uint32)OPTMZ_FIRST_EXEC_ROOT);
    }

    if (NODE_IS_FIRST_EXECUTABLE(node->left)) {
        index = NODE_OPTMZ_IDX(node->left);
    }
    if (NODE_IS_FIRST_EXECUTABLE(node->right)) {
        index = MIN(index, NODE_OPTMZ_IDX(node->right));
    }

    node->optmz_info.mode = OPTMZ_FIRST_EXEC_ROOT;
    node->optmz_info.idx = (uint16)index;

    if (NODE_IS_FIRST_EXECUTABLE(node->left)) {
        sql_merge_first_exec_node(verif, node->left, index);
    }

    if (NODE_IS_FIRST_EXECUTABLE(node->right)) {
        sql_merge_first_exec_node(verif, node->right, index);
    }
}

/* * decide the optmz mode of a unary operator node, such as +, - */
void sql_infer_unary_oper_optmz_mode(sql_verifier_t *verif, expr_node_t *node)
{
    // Step 1: scan all modes of arguments
    optmz_mode_t mode = NODE_OPTIMIZE_MODE(node->right);
    uint32 index = CT_INVALID_ID16;

    if (mode == OPTIMIZE_NONE || mode == OPTIMIZE_AS_CONST || mode == OPTIMIZE_AS_PARAM) {
        SQL_SET_OPTMZ_MODE(node, mode);
        return;
    }

    if (mode != OPTMZ_FIRST_EXEC_ROOT) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "mode(%u) == OPTMZ_FIRST_EXEC_ROOT(%u)", (uint32)mode,
            (uint32)OPTMZ_FIRST_EXEC_ROOT);
    }

    if (NODE_IS_FIRST_EXECUTABLE(node->right)) {
        index = MIN(index, NODE_OPTMZ_IDX(node->right));
    }

    node->optmz_info.mode = OPTMZ_FIRST_EXEC_ROOT;
    node->optmz_info.idx = (uint16)index;

    if (NODE_IS_FIRST_EXECUTABLE(node->right)) {
        sql_merge_first_exec_node(verif, node->right, index);
    }
}

/* * add an expr node that can be evaluated at first execution */
void sql_add_first_exec_node(sql_verifier_t *verif, expr_node_t *node)
{
    while (verif->do_expr_optmz) {
        // too much first executable variants
        if (verif->context->fexec_vars_cnt >= SQL_MAX_FEXEC_VARS) {
            break;
        }

        // do not optimize LOB node
        if (CT_IS_LOB_TYPE(node->datatype)) {
            break;
        }

        if (CT_IS_VARLEN_TYPE(node->datatype)) {
            // if the first executable is insufficient
            if (verif->context->fexec_vars_bytes + node->size >= SQL_MAX_FEXEC_VAR_BYTES) {
                break;
            }
            verif->context->fexec_vars_bytes += node->size;
        }

        node->optmz_info.idx = verif->context->fexec_vars_cnt++;
        node->optmz_info.mode = OPTMZ_FIRST_EXEC_ROOT;
        return;
    }

    SQL_SET_OPTMZ_MODE(node, OPTIMIZE_NONE);
}

#ifdef __cplusplus
}
#endif