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
 * pl_lines_executor.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/executor/pl_lines_executor.c
 *
 * -------------------------------------------------------------------------
 */
#include "pl_lines_executor.h"
#include "srv_instance.h"
#include "pl_udt.h"
#include "dml_executor.h"
#include "ast_cl.h"
#include "ctsql_parser.h"
#include "base_compiler.h"
#include "pl_executor.h"

void ple_line_assist_init(ple_line_assist_t *line_ass, sql_stmt_t *stmt, pl_executor_t *exec, pl_line_ctrl_t *line,
    pl_line_ctrl_t *end)
{
    line_ass->stmt = stmt;
    line_ass->exec = exec;
    line_ass->line = line;
    line_ass->proc_end = end;
    line_ass->jump = NULL;
}

static status_t ple_none_ln(ple_line_assist_t *line_ass)
{
    return CT_SUCCESS;
}

static status_t ple_push_block_decls(sql_stmt_t *stmt, galist_t *decls, ple_varmap_t *var_map, bool32 calc_dft)
{
    var_map->count = 0;

    if (decls == NULL || decls->count == 0) {
        var_map->items = NULL;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_push(stmt, decls->count * sizeof(pointer_t), (void **)&var_map->items));

    CT_RETURN_IFERR(ple_push_decl_element(stmt, decls, var_map, calc_dft));

    return CT_SUCCESS;
}

static status_t ple_push_decls_val(sql_stmt_t *stmt, galist_t *decls)
{
    ple_var_t *var = NULL;
    uint32 i;
    pl_executor_t *exec = (pl_executor_t *)stmt->pl_exec;
    plv_decl_t *decl = NULL;

    if (decls == NULL || decls->count == 0) {
        return CT_SUCCESS;
    }

    for (i = 0; i < decls->count; i++) {
        decl = (plv_decl_t *)cm_galist_get(decls, i);
        var = ple_get_plvar(exec, decl->vid);
        if (var == NULL) {
            continue;
        }

        if (var->decl->type == PLV_RECORD && decl->default_expr == NULL) {
            CT_RETURN_IFERR(ple_calc_record_dft(stmt, var->decl->record, &var->value));
            continue;
        }

        if (var->decl->type == PLV_OBJECT && PLE_DEFAULT_EXPR(var) == NULL) {
            CT_RETURN_IFERR(ple_calc_object_dft(stmt, var->decl->object, &var->value));
            continue;
        }

        if (decl->default_expr != NULL && (var->decl->type == PLV_VAR || PLV_IS_COMPLEX_TYPE(var->decl->type))) {
            CT_RETURN_IFERR(ple_calc_dft(stmt, var));
            continue;
        }

        if (var->decl->type == PLV_PARAM) {
            CT_RETURN_IFERR(ple_calc_param_dft(stmt, var));
            continue;
        }
    }

    return CT_SUCCESS;
}

status_t ple_begin_ln(ple_line_assist_t *line_ass)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_line_begin_t *line = (pl_line_begin_t *)line_ass->line;
    ple_varmap_t var_map;
    ple_stack_anchor_t anchor;
    ple_save_stack_anchor(stmt, &anchor);

    CT_RETURN_IFERR(ple_push_block_decls(stmt, line->decls, &var_map, CT_FALSE));
    CT_RETURN_IFERR(ple_push_block(stmt, (pl_line_ctrl_t *)line, &var_map, anchor));
    return ple_push_decls_val(stmt, line->decls);
}

status_t ple_end_ln(ple_line_assist_t *line_ass)
{
    ple_pop_block(line_ass->stmt, line_ass->exec);
    return CT_SUCCESS;
}

status_t ple_check_cursor_setval(sql_stmt_t *stmt, pl_line_normal_t *setval, variant_t *src)
{
    var_address_t *var_address = NODE_VALUE_PTR(var_address_t, setval->left);
    var_address_pair_t *pair_left = (var_address_pair_t *)cm_galist_get(var_address->pairs, (uint32)0);
    plv_decl_t *decl = pair_left->stack->decl;
    if (decl->type != PLV_CUR) {
        return CT_SUCCESS;
    }

    if ((src->type != CT_TYPE_CURSOR) && (src->is_null == CT_FALSE)) {
        CT_THROW_ERROR(ERR_TYPE_MISMATCH, "CURSOR", get_datatype_name_str(src->type));
        return CT_ERROR;
    }

    if (decl->cursor.ctx->is_sysref == CT_FALSE) {
        CT_THROW_ERROR(ERR_PL_EXPR_AS_LEFT_FMT, T2S(&decl->name));
        return CT_ERROR;
    }

    if (setval->expr->root->type != EXPR_NODE_V_ADDR) {
        return CT_SUCCESS;
    }

    var_address_pair_t *pair = sql_get_last_addr_pair(setval->expr->root);
    if (pair == NULL) {
        CT_THROW_ERROR(ERR_PL_SYNTAX_ERROR_FMT, "pair is null");
        return CT_ERROR;
    }
    if (pair->type != UDT_STACK_ADDR) {
        return CT_SUCCESS;
    }
    if (pair->stack->decl->type != PLV_CUR || pair->stack->decl->cursor.ctx->is_sysref == CT_FALSE) {
        CT_THROW_ERROR(ERR_PROGRAM_ERROR_FMT, "only ref cursor can be assigned");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t ple_setval(ple_line_assist_t *line_ass)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_line_ctrl_t *line = line_ass->line;
    pl_line_normal_t *setval = (pl_line_normal_t *)line;
    variant_t right;

    if (setval->expr != NULL) {
        if (sql_exec_expr(stmt, setval->expr, &right) != CT_SUCCESS) {
            cm_try_set_error_loc(line->loc);
            return CT_ERROR;
        }

        if (ple_check_cursor_setval(stmt, setval, &right) != CT_SUCCESS) {
            cm_try_set_error_loc(line->loc);
            return CT_ERROR;
        }
    } else {
        if (sql_match_cond_node(stmt, setval->cond->root, &right.v_bool) != CT_SUCCESS) {
            cm_try_set_error_loc(line->loc);
            return CT_ERROR;
        }

        right.is_null = CT_FALSE;
        right.type = CT_TYPE_BOOLEAN;
    }
    return udt_exec_v_addr(stmt, setval->left, NULL, &right);
}

status_t ple_if(ple_line_assist_t *line_ass)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_executor_t *exec = line_ass->exec;
    pl_line_ctrl_t *line = line_ass->line;
    pl_line_if_t *if_line = (pl_line_if_t *)line;
    uint32 cond = COND_TRUE;

    if (sql_match_cond_node(stmt, if_line->cond->root, (bool32 *)&cond) != CT_SUCCESS) {
        cm_try_set_error_loc(line->loc);
        return CT_ERROR;
    }

    if (CURR_COND_EXEC_DEPTH(exec) >= PLE_MAX_BLOCK_DEPTH - 1) { // not overflow
        CT_SRC_THROW_ERROR(line->loc, ERR_PL_BLOCK_TOO_DEEP_FMT, PLE_MAX_BLOCK_DEPTH);
        return CT_ERROR;
    }
    PUSH_COND_EXEC(cond, exec);
    if (cond == COND_TRUE) {
        line_ass->jump = if_line->t_line;
    } else {
        line_ass->jump = if_line->f_line;
    }
    return CT_SUCCESS;
}

status_t ple_else(ple_line_assist_t *line_ass)
{
    pl_executor_t *exec = line_ass->exec;
    pl_line_ctrl_t *line = line_ass->line;
    pl_line_else_t *else_line = (pl_line_else_t *)line;
    pl_line_if_t *if_line = (pl_line_if_t *)else_line->if_line;
    uint32 cond = CURR_COND_EXEC(exec);
    if (cond == CT_INVALID_ID32) {
        CT_SRC_THROW_ERROR(line->loc, ERR_PL_SYNTAX_ERROR_FMT, "unmatched else statment");
        return CT_ERROR;
    }

    // if brother cond result is true, need to goto the end of this if statment.
    if (cond == COND_TRUE) {
        line_ass->jump = if_line->next;
    } else {
        line_ass->jump = NULL;
    }

    return CT_SUCCESS;
}

status_t ple_elsif(ple_line_assist_t *line_ass)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_executor_t *exec = line_ass->exec;
    pl_line_ctrl_t *line = line_ass->line;
    pl_line_elsif_t *elsif_line = (pl_line_elsif_t *)line;
    pl_line_if_t *if_line = (pl_line_if_t *)elsif_line->if_line;
    uint32 cond = CURR_COND_EXEC(exec);
    if (cond == COND_TRUE) {
        line_ass->jump = if_line->next;
    } else {
        cond = COND_TRUE;
        if (sql_match_cond_node(stmt, elsif_line->cond->root, (bool32 *)&cond) != CT_SUCCESS) {
            cm_try_set_error_loc(line->loc);
            return CT_ERROR;
        }
        UPDATE_COND_EXEC(cond, exec);
        if (cond == COND_TRUE) {
            line_ass->jump = elsif_line->t_line;
        } else {
            line_ass->jump = elsif_line->f_line;
        }
    }
    return CT_SUCCESS;
}

status_t ple_endif(ple_line_assist_t *line_ass)
{
    pl_executor_t *exec = line_ass->exec;
    POP_COND_EXEC(exec);
    return CT_SUCCESS;
}

status_t ple_case(ple_line_assist_t *line_ass)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_executor_t *exec = line_ass->exec;
    pl_line_ctrl_t *line = line_ass->line;
    pl_line_case_t *case_line = (pl_line_case_t *)line;
    variant_t *var = NULL;
    if (CURR_COND_EXEC_DEPTH(exec) >= PLE_MAX_BLOCK_DEPTH - 1) { // not overflow
        CT_SRC_THROW_ERROR(line->loc, ERR_PL_BLOCK_TOO_DEEP_FMT, PLE_MAX_BLOCK_DEPTH);
        return CT_ERROR;
    }

    PUSH_COND_EXEC(COND_FALSE, exec);

    if (case_line->selector != NULL) {
        if (CURR_SELECTOR_EXEC_DEPTH(exec) >= PLE_MAX_BLOCK_DEPTH - 1) { // not overflow
            CT_SRC_THROW_ERROR(line->loc, ERR_PL_BLOCK_TOO_DEEP_FMT, CURR_SELECTOR_EXEC_DEPTH(exec));
            return CT_ERROR;
        }
        CT_RETURN_IFERR(sql_push(stmt, sizeof(variant_t), (void **)&var));
        if (sql_exec_expr(stmt, case_line->selector, var) != CT_SUCCESS) {
            cm_try_set_error_loc(line->loc);
            CTSQL_POP(stmt);
            return CT_ERROR;
        }
        PUSH_SELECTOR_EXEC(var, exec);
    }

    return CT_SUCCESS;
}

status_t ple_when_case(ple_line_assist_t *line_ass)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_executor_t *exec = line_ass->exec;
    pl_line_ctrl_t *line = line_ass->line;
    pl_line_when_case_t *when_case = (pl_line_when_case_t *)line;
    pl_line_when_case_t *pre_case = (pl_line_when_case_t *)when_case->if_line;
    variant_t value;
    variant_t *selector = NULL;
    int32 result;
    uint32 cond = CURR_COND_EXEC(exec);
    if (cond == CT_INVALID_ID32) {
        CT_SRC_THROW_ERROR(line->loc, ERR_PLSQL_ILLEGAL_LINE_FMT, "encount unmatched when-case statment");
        return CT_ERROR;
    }

    if (cond == COND_TRUE) {
        line_ass->jump = pre_case->next;
        return CT_SUCCESS;
    }

    if (when_case->selector == NULL) {
        if (sql_match_cond_node(stmt, ((cond_tree_t *)when_case->cond)->root, &cond) != CT_SUCCESS) {
            cm_try_set_error_loc(line->loc);
            return CT_ERROR;
        }
    } else {
        selector = CURR_SELECTOR_EXEC(exec);

        if (sql_exec_expr(stmt, (expr_tree_t *)when_case->cond, &value) != CT_SUCCESS) {
            cm_try_set_error_loc(line->loc);
            return CT_SUCCESS;
        }
        sql_keep_stack_variant(stmt, &value);
        CT_RETURN_IFERR(sql_compare_variant(stmt, &value, selector, &result));

        cond = (result == 0) ? COND_TRUE : COND_FALSE;
    }

    UPDATE_COND_EXEC(cond, exec);
    if (cond == COND_TRUE) {
        line_ass->jump = when_case->t_line;
    } else {
        if (when_case->f_line->type == LINE_END_CASE) {
            CT_SRC_THROW_ERROR(line->loc, ERR_CASE_NOT_FOUND);
            return CT_ERROR;
        }
        line_ass->jump = when_case->f_line;
    }
    return CT_SUCCESS;
}

status_t ple_endcase(ple_line_assist_t *line_ass)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_line_ctrl_t *line = line_ass->line;
    pl_executor_t *exec = line_ass->exec;
    pl_line_when_case_t *end_case = (pl_line_when_case_t *)line;
    POP_COND_EXEC(exec);
    if (end_case->selector != NULL) {
        POP_SELECTOR_EXEC(exec);
        CTSQL_POP(stmt);
    }

    return CT_SUCCESS;
}

status_t ple_end_loop(ple_line_assist_t *line_ass)
{
    pl_line_end_loop_t *end_loop = (pl_line_end_loop_t *)line_ass->line;

    line_ass->jump = end_loop->loop;
    return CT_SUCCESS;
}

static status_t ple_calc_cond_exec_depth(sql_stmt_t *stmt, pl_line_ctrl_t *check, pl_line_ctrl_t *end, uint32 *calc)
{
    uint32 depth = *calc;
    while (check != NULL && check != end) {
        switch (check->type) {
            case LINE_IF:
            case LINE_CASE:
                if (depth >= PLE_MAX_BLOCK_DEPTH - 1) { // not overflow
                    CT_THROW_ERROR(ERR_PL_BLOCK_TOO_DEEP_FMT, PLE_MAX_BLOCK_DEPTH);
                    return CT_ERROR;
                }
                depth++;
                break;
            case LINE_END_IF:
            case LINE_END_CASE:
                depth--;
                break;
            default:
                break;
        }
        check = check->next;
    }
    *calc = depth;
    return CT_SUCCESS;
}

static status_t ple_pop_cond_exec(sql_stmt_t *stmt, pl_executor_t *exec, pl_line_ctrl_t *line, pl_line_ctrl_t *end)
{
    pl_line_ctrl_t *check = line->next;
    uint32 depth = CURR_COND_EXEC_DEPTH(exec);
    if (ple_calc_cond_exec_depth(stmt, check, end, &depth) != CT_SUCCESS) {
        cm_try_set_error_loc(line->loc);
        return CT_ERROR;
    }
    if (depth > CURR_COND_EXEC_DEPTH(exec)) {
        CT_SRC_THROW_ERROR(line->loc, ERR_PL_SYNTAX_ERROR_FMT, "unmatched block in loop statment");
        return CT_ERROR;
    }

    exec->cond_exec.depth = depth;
    return CT_SUCCESS;
}

static void ple_update_coverage_hit_count(pl_executor_t *exec, pl_line_ctrl_t *line)
{
    uint8 *count = NULL;

    if (PLE_IS_COVER_VALID(exec) && (line->type != LINE_END_WHEN) && (line->type != LINE_END_EXCEPTION)) {
        count = &exec->coverage->hit_count[line->loc.line - 1]; // not overflow
        if (*count != CT_INVALID_ID8) {
            (*count)++;
        }
    }
}

status_t ple_exit(ple_line_assist_t *line_ass)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_executor_t *exec = line_ass->exec;
    pl_line_ctrl_t *line = line_ass->line;
    pl_line_ctrl_t *end_loop = NULL;
    pl_line_exit_t *exit_line = (pl_line_exit_t *)line;
    pl_line_ctrl_t *state = exit_line->next;
    pl_line_ctrl_t *stack_line = NULL;

    bool32 exit_cond = (exit_line->cond == NULL) ? CT_TRUE : CT_FALSE;
    cm_reset_error();

    if (!exit_cond) {
        CT_RETURN_IFERR(sql_match_cond_node(stmt, ((cond_tree_t *)exit_line->cond)->root, &exit_cond));
    }

    CT_RETVALUE_IFTRUE(!exit_cond, CT_SUCCESS);

    // EXIT LABEL must the name of LOOP statment.
    if (state->type == LINE_LABEL) {
        ple_update_coverage_hit_count(exec, state);
        state = state->next;
    }

    if (state->type == LINE_LOOP) {
        stack_line = ((pl_line_loop_t *)state)->stack_line;
    } else if (state->type == LINE_FOR) {
        stack_line = state;
    } else if (state->type == LINE_WHILE) {
        stack_line = ((pl_line_while_t *)state)->stack_line;
    }

    if (stack_line != NULL) {
        while ((exec->block_stack.depth > 0) && (stack_line != PLE_CURR_BLOCK(exec)->entry)) {
            ple_pop_block(stmt, exec);
        }

        if (state->type == LINE_FOR) {
            ple_pop_block(stmt, exec);
        }

        // pl_line_loop_t,pl_line_for_t,pl_line_while_t is the same with next point to end loop
        end_loop = ((pl_line_loop_t *)state)->next;
        ple_update_coverage_hit_count(exec, end_loop);
        // time to pop condition execute stack in the loop statment,so check the lines between continue-line to end-loop
        if (ple_pop_cond_exec(stmt, exec, line, end_loop) != CT_SUCCESS) {
            return CT_ERROR;
        }
        line_ass->jump = end_loop->next;
        return CT_SUCCESS;
    }

    CT_SRC_THROW_ERROR(line->loc, ERR_PLSQL_ILLEGAL_LINE_FMT, "exit must in loop statement.");
    return CT_ERROR;
}

static status_t ple_modify_cond_exec(sql_stmt_t *stmt, pl_executor_t *exec, pl_line_ctrl_t *line,
    pl_line_ctrl_t *goto_target)
{
    pl_line_goto_t *goto_ln = (pl_line_goto_t *)line;
    pl_line_ctrl_t *start = exec->start_line;
    uint32 depth = 0;

    if (ple_calc_cond_exec_depth(stmt, start, goto_target, &depth) != CT_SUCCESS) {
        cm_try_set_error_loc(line->loc);
        return CT_ERROR;
    }
    if (depth > exec->cond_exec.depth) {
        CT_SRC_THROW_ERROR(line->loc, ERR_PL_SYNTAX_ERROR_FMT, "%s is an invalid label(ctl_block depth more than goto)",
            T2S(&goto_ln->label));
        return CT_ERROR;
    }

    exec->cond_exec.depth = depth;
    return CT_SUCCESS;
}

status_t ple_goto(ple_line_assist_t *line_ass)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_executor_t *exec = line_ass->exec;
    pl_line_ctrl_t *line = line_ass->line;
    pl_line_goto_t *goto_ln = (pl_line_goto_t *)line;
    pl_line_ctrl_t *stack_line = ((pl_line_label_t *)goto_ln->next)->stack_line;

    while ((exec->block_stack.depth > 0) && (stack_line != PLE_CURR_BLOCK(exec)->entry)) {
        ple_pop_block(stmt, exec);
    }

    if (ple_modify_cond_exec(stmt, exec, line, goto_ln->next) != CT_SUCCESS) {
        return CT_ERROR;
    }

    line_ass->jump = goto_ln->next;
    cm_reset_error();
    return CT_SUCCESS;
}

status_t ple_continue(ple_line_assist_t *line_ass)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_executor_t *exec = line_ass->exec;
    pl_line_ctrl_t *line = line_ass->line;
    pl_line_continue_t *con = (pl_line_continue_t *)line;
    pl_line_ctrl_t *state = con->next;
    pl_line_ctrl_t *stack_line = NULL;

    bool32 con_cond = (con->cond == NULL) ? CT_TRUE : CT_FALSE;
    if (!con_cond) {
        if (sql_match_cond_node(stmt, ((cond_tree_t *)con->cond)->root, &con_cond) != CT_SUCCESS) {
            cm_try_set_error_loc(line->loc);
            return CT_ERROR;
        }
    }

    CT_RETVALUE_IFTRUE(!con_cond, CT_SUCCESS);

    // continue LABEL must the name of LOOP statment.
    if (state->type == LINE_LABEL) {
        ple_update_coverage_hit_count(exec, state);
        state = state->next;
    }

    if (state->type == LINE_LOOP) {
        stack_line = ((pl_line_loop_t *)state)->stack_line;
    } else if (state->type == LINE_FOR) {
        stack_line = state;
    } else if (state->type == LINE_WHILE) {
        stack_line = ((pl_line_while_t *)state)->stack_line;
    }

    if (stack_line != NULL) {
        while ((exec->block_stack.depth > 0) && (stack_line != PLE_CURR_BLOCK(exec)->entry)) {
            ple_pop_block(stmt, exec);
        }
        if (exec->block_stack.depth == 0) {
            CT_SRC_THROW_ERROR(line->loc, ERR_PLSQL_ILLEGAL_LINE_FMT, "continue must in loop statement.");
            return CT_ERROR;
        }
        // time to pop condition execute stack in the loop statment,so check the lines between continue-line to end-loop
        if (ple_pop_cond_exec(stmt, exec, line, ((pl_line_loop_t *)state)->next) != CT_SUCCESS) {
            return CT_ERROR;
        }

        line_ass->jump = state;
        return CT_SUCCESS;
    }

    CT_SRC_THROW_ERROR(line->loc, ERR_PLSQL_ILLEGAL_LINE_FMT, "continue must in loop statement.");
    return CT_ERROR;
}

status_t ple_while(ple_line_assist_t *line_ass)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_executor_t *exec = line_ass->exec;
    pl_line_ctrl_t *line = line_ass->line;
    pl_line_while_t *while_line = (pl_line_while_t *)line;
    bool32 cond;

    if (sql_match_cond_node(stmt, while_line->cond->root, &cond) != CT_SUCCESS) {
        cm_try_set_error_loc(line->loc);
        return CT_ERROR;
    }

    line_ass->jump = (cond) ? NULL : ((pl_line_ctrl_t *)while_line->next)->next;
    if (!cond) {
        ple_update_coverage_hit_count(exec, while_line->next);
    }
    return CT_SUCCESS;
}

static status_t ple_push_block_for(sql_stmt_t *stmt, pl_line_ctrl_t *entry)
{
    pl_line_for_t *line = (pl_line_for_t *)entry;
    ple_varmap_t var_map;
    ple_stack_anchor_t anchor;
    ple_save_stack_anchor(stmt, &anchor);
    CT_RETURN_IFERR(ple_push_block_decls(stmt, line->decls, &var_map, CT_TRUE));
    CT_RETURN_IFERR(ple_push_block(stmt, (pl_line_ctrl_t *)line, &var_map, anchor));
    return CT_SUCCESS;
}

static void ple_for_cursor_jump(sql_stmt_t *stmt, pl_executor_t *exec, pl_line_for_t *for_line, sql_stmt_t *sub_stmt,
    ple_var_t *var, pl_line_ctrl_t **line_ctrl)
{
    // 4) jump out if not found, next if found
    if (sub_stmt->eof == CT_TRUE) {
        // 5) close cursor
        ple_close_cursor(sub_stmt, PLE_CURSOR_SLOT_GET(var));
        // jump to next line of end loop.
        ple_update_coverage_hit_count(exec, for_line->next);
        *line_ctrl = ((pl_line_ctrl_t *)for_line->next)->next;
        ple_pop_block(stmt, exec);
    } else {
        *line_ctrl = NULL;
    }
}

static bool32 ple_check_substmt_ctx(sql_stmt_t *sub_stmt, sql_context_t *origin_ctx)
{
    return sub_stmt->context == NULL || (sub_stmt->context != origin_ctx && sub_stmt->context->parent == NULL);
}

static status_t ple_open_and_fetch_expcur(sql_stmt_t *stmt, sql_stmt_t *sub_stmt, ple_var_t *var)
{
    status_t status;
    plv_cursor_context_t *cursor_ctx = var->decl->cursor.ctx;
    sub_stmt->context = cursor_ctx->context;
    ctx_inc_ref(&sub_stmt->context->ctrl);
    sub_stmt->lang_type = LANG_DML;

    sub_stmt->status = stmt->status;
    sub_stmt->pl_exec = stmt->pl_exec;
    sub_stmt->is_srvoutput_on = stmt->is_srvoutput_on;
    sub_stmt->is_sub_stmt = CT_TRUE;
    sub_stmt->pl_ref_entry = stmt->pl_ref_entry;
    sub_stmt->parent_stmt = stmt;
    sub_stmt->cursor_info.sql_executed = CT_TRUE;
    sub_stmt->plsql_mode = PLSQL_CURSOR;
    sub_stmt->chk_priv = CT_FALSE;

    pl_executor_t *exec = (pl_executor_t *)sub_stmt->pl_exec;
    exec->curr_input = var->decl->cursor.input;
    exec->is_dyncur = CT_FALSE;
    // 2) fetch first into record then return
    PLE_SAVE_STMT(stmt);
    sub_stmt->session->sender = &g_instance->sql.pl_sender;
    sub_stmt->session->current_stmt = sub_stmt;
    status = sql_execute(sub_stmt);
    sub_stmt->cursor_info.has_fetched = CT_TRUE;
    // sql is reparsed, sub stmt's context is changed
    if (ple_check_substmt_ctx(sub_stmt, cursor_ctx->context)) {
        // set procedure/function status to invalid
        pl_entity_invalidate((pl_entity_t *)stmt->pl_context);
    }

    PLE_RESTORE_STMT(stmt);
    return status;
}

static inline void ple_for_cursor_set_substmt(sql_stmt_t *stmt, pl_cursor_slot_t *ref_cursor, pl_line_for_t *for_line,
    sql_stmt_t *sub_stmt)
{
    ref_cursor->stmt_id = sub_stmt->id;
    sub_stmt->cursor_info.type = PL_EXPLICIT_CURSOR;
    sub_stmt->cursor_info.is_forcur = CT_TRUE;
    sub_stmt->is_sub_stmt = CT_TRUE;
    sub_stmt->parent_stmt = stmt;
    sub_stmt->prefetch_rows = for_line->into.prefetch_rows;
}

static void ple_find_cursor_param(galist_t *exprs, text_t *name, expr_tree_t **result, uint32 pos, bool32 *flag)
{
    uint32 i;
    expr_tree_t *expr = NULL;

    for (i = pos; i < exprs->count; i++) {
        expr = (expr_tree_t *)cm_galist_get(exprs, i);
        CT_BREAK_IF_TRUE(expr->arg_name.len == 0);
        *flag = (*flag == CT_FALSE) ? CT_TRUE : (*flag);
        CT_BREAK_IF_TRUE(cm_compare_text_ins(&expr->arg_name, name) == 0);

        expr = NULL;
    }
    *result = expr;
}

static status_t ple_prepare_cursor_param(sql_stmt_t *stmt, ple_var_t *var, galist_t *exprs, source_location_t loc)
{
    plv_cursor_context_t *ctx = var->decl->cursor.ctx;
    galist_t *args = ctx->args;
    uint32 i, pos;
    // dedicate the flag of param special the =>, and pos decicate the position start.
    bool32 flag = CT_FALSE;
    variant_t *result = NULL;

    plv_decl_t *arg = NULL;
    expr_tree_t *expr = NULL;

    if (args == NULL) {
        if (exprs != NULL) {
            CT_SRC_THROW_ERROR(loc, ERR_TOO_LESS_ARGS, "open cursor");
            return CT_ERROR;
        }
        return CT_SUCCESS;
    }

    pos = 0;
    for (i = 0; i < args->count; i++) {
        arg = (plv_decl_t *)cm_galist_get(args, i);
        result = ple_get_value(stmt, arg->vid);
        expr = NULL;

        if (exprs != NULL) {
            ple_find_cursor_param(exprs, &arg->name, &expr, pos, &flag);
        }

        if (expr == NULL) {
            expr = arg->default_expr;
            if (expr == NULL) {
                CT_SRC_THROW_ERROR(loc, ERR_TOO_LESS_ARGS, "open cursor");
                return CT_ERROR;
            }
        } else if (flag == CT_FALSE) {
            pos++;
        }

        if (sql_exec_expr(stmt, expr, result) != CT_SUCCESS) {
            cm_try_set_error_loc(loc);
            return CT_ERROR;
        }

        sql_keep_stack_variant(stmt, result);
    }

    return CT_SUCCESS;
}

static status_t ple_exec_and_fetch_impcur(sql_stmt_t *stmt, sql_stmt_t *sub_stmt, pl_line_for_t *for_line,
    galist_t *input)
{
    status_t status;
    sub_stmt->context = for_line->context;
    ctx_inc_ref(&sub_stmt->context->ctrl);
    sub_stmt->status = stmt->status;
    sub_stmt->pl_exec = stmt->pl_exec;
    sub_stmt->is_srvoutput_on = stmt->is_srvoutput_on;
    sub_stmt->lang_type = LANG_DML;
    sub_stmt->total_rows = 0;
    sub_stmt->is_sub_stmt = CT_TRUE;
    sub_stmt->pl_ref_entry = stmt->pl_ref_entry;
    sub_stmt->parent_stmt = stmt;
    sub_stmt->cursor_info.sql_executed = CT_TRUE;
    sub_stmt->plsql_mode = PLSQL_CURSOR;
    sub_stmt->chk_priv = CT_FALSE;

    pl_executor_t *exec = (pl_executor_t *)sub_stmt->pl_exec;
    exec->curr_input = input;
    exec->is_dyncur = CT_FALSE;
    // 2) fetch first into record then return
    PLE_SAVE_STMT(stmt);
    sub_stmt->session->sender = &g_instance->sql.pl_sender;
    sub_stmt->session->current_stmt = sub_stmt;
    status = sql_execute(sub_stmt);
    sub_stmt->cursor_info.has_fetched = CT_TRUE;
    // sql is reparsed, sub stmt's context is changed
    if (ple_check_substmt_ctx(sub_stmt, for_line->context)) {
        // set procedure/function status to invalid
        pl_entity_invalidate((pl_entity_t *)stmt->pl_context);
    }
    PLE_RESTORE_STMT(stmt);
    return status;
}

static status_t ple_for_cursor_fetch_next(sql_stmt_t *stmt, sql_stmt_t *curr_stmt)
{
    status_t status;
    PLE_SAVE_STMT(stmt);
    curr_stmt->session->current_stmt = curr_stmt;
    curr_stmt->session->sender = &g_instance->sql.pl_sender;
    status = sql_execute_fetch(curr_stmt);
    PLE_RESTORE_STMT(stmt);
    return status;
}

static status_t ple_alloc_ref_cursor(sql_stmt_t *stmt, void **ref_cursor)
{
    if (stmt->session->pl_cursors == NULL) {
        CT_THROW_ERROR(ERR_RESET_MEMORY, "uninitialized pl cursors");
        return CT_ERROR;
    }

    pl_cursor_slot_t *ref_cursors = (pl_cursor_slot_t *)stmt->session->pl_cursors;

    for (uint32 i = 0; i < PLE_MAX_CURSORS; i++) {
        if (ref_cursors[i].state != CUR_RES_FREE) {
            continue;
        }
        ref_cursors[i].state = CUR_RES_INUSE;
        ref_cursors[i].stmt_id = CT_INVALID_ID16;
        ref_cursors[i].ref_count = 1;
        *ref_cursor = (void *)&ref_cursors[i];
        return CT_SUCCESS;
    }
    *ref_cursor = NULL;
    CT_THROW_ERROR(ERR_TOO_MANY_RETURN_RESULT, PLE_MAX_CURSORS);
    return CT_ERROR;
}

status_t ple_for_implicit_cur(sql_stmt_t *stmt, pl_executor_t *exec, pl_line_ctrl_t *line, pl_line_ctrl_t **jump_line)
{
    pl_line_for_t *for_line = (pl_line_for_t *)line;
    ple_var_t *id = ple_get_plvar(exec, for_line->id->vid);
    ple_var_t *cur = ple_get_plvar(exec, for_line->cursor_id);
    sql_stmt_t *sub_stmt = NULL;
    pl_cursor_slot_t *ref_cursor = NULL;
    status_t status;

    if (cur->decl->cursor.ctx->is_sysref != CT_FALSE) {
        CT_THROW_ERROR_EX(ERR_ASSERT_ERROR, "cur->decl->cursor.ctx->is_sysref == CT_FALSE");
        return CT_ERROR;
    }

    if (PLE_CURSOR_SLOT_GET(cur) == NULL) {
        CT_RETURN_IFERR(ple_alloc_ref_cursor(stmt, (void **)&ref_cursor));
        cur->value.v_cursor.ref_cursor = ref_cursor;
    } else {
        ref_cursor = PLE_CURSOR_SLOT_GET(cur);
        sub_stmt = ple_ref_cursor_get(stmt, ref_cursor);
    }

    if (sub_stmt != NULL) {
        // 3) fetch next into record
        status = ple_for_cursor_fetch_next(stmt, sub_stmt);
    } else {
        id->value.is_null = CT_FALSE;
        // 1) open cursor
        CT_RETURN_IFERR(sql_alloc_stmt(stmt->session, &sub_stmt));
        ref_cursor->stmt_id = sub_stmt->id;
        sub_stmt->cursor_info.type = PL_IMPLICIT_CURSOR;
        sub_stmt->cursor_info.is_forcur = CT_TRUE;
        sub_stmt->is_sub_stmt = CT_TRUE;
        sub_stmt->parent_stmt = stmt;
        sub_stmt->prefetch_rows = for_line->into.prefetch_rows;
        exec->sql_loc = line->loc;

        status = ple_exec_and_fetch_impcur(stmt, sub_stmt, for_line, cur->decl->cursor.input);
    }

    if (status != CT_SUCCESS) {
        pl_check_and_set_loc(line->loc);
        ple_close_cursor(sub_stmt, PLE_CURSOR_SLOT_GET(cur));
        return CT_ERROR;
    }

    stmt->total_rows = sub_stmt->batch_rows;
    exec->recent_rows = sub_stmt->batch_rows;

    // 4) jump out if not found, next if found
    if (!sub_stmt->eof) {
        *jump_line = NULL;
    } else {
        // 5) close cursor
        ple_close_cursor(sub_stmt, PLE_CURSOR_SLOT_GET(cur));

        // jump to next line of end loop.
        ple_update_coverage_hit_count(exec, for_line->next);
        *jump_line = ((pl_line_ctrl_t *)for_line->next)->next;
        ple_pop_block(stmt, exec);
    }
    return CT_SUCCESS;
}

static status_t ple_for_cursor(sql_stmt_t *stmt, pl_executor_t *exec, pl_line_ctrl_t *line, pl_line_ctrl_t **jump_line,
    const bool32 is_first_run)
{
    pl_line_for_t *for_line = (pl_line_for_t *)line;
    ple_var_t *id = ple_get_plvar(exec, for_line->id->vid);
    status_t status;

    if (for_line->is_impcur) {
        return ple_for_implicit_cur(stmt, exec, line, jump_line);
    }

    ple_var_t *var = ple_get_plvar(exec, for_line->cursor_id);
    plv_cursor_context_t *cur = var->decl->cursor.ctx;
    sql_stmt_t *sub_stmt = NULL;
    pl_cursor_slot_t *ref_cursor = NULL;

    if (PLE_CURSOR_SLOT_GET(var) == NULL) {
        CT_RETURN_IFERR(ple_alloc_ref_cursor(stmt, (void **)&ref_cursor));
        var->value.v_cursor.ref_cursor = ref_cursor;
    } else {
        ref_cursor = PLE_CURSOR_SLOT_GET(var);
        sub_stmt = ple_ref_cursor_get(stmt, ref_cursor);
    }

    if (cur->is_sysref) {
        CT_SRC_THROW_ERROR(line->loc, ERR_INVALID_CURSOR);
        return CT_ERROR;
    }

    if (sub_stmt != NULL) {
        if (is_first_run) {
            CT_SRC_THROW_ERROR(line->loc, ERR_CURSOR_ALREADY_OPEN);
            return CT_ERROR;
        }

        // 3) fetch next into record
        status = ple_for_cursor_fetch_next(stmt, sub_stmt);
    } else {
        id->value.is_null = CT_FALSE;
        CT_RETURN_IFERR(ple_prepare_cursor_param(stmt, var, for_line->exprs, line->loc));

        // 1) open cursor
        CT_RETURN_IFERR(sql_alloc_stmt(stmt->session, &sub_stmt));
        ple_for_cursor_set_substmt(stmt, ref_cursor, for_line, sub_stmt);

        exec->sql_loc = line->loc;
        status = ple_open_and_fetch_expcur(stmt, sub_stmt, var);
    }

    if (status != CT_SUCCESS) {
        pl_check_and_set_loc(line->loc);
        ple_close_cursor(sub_stmt, PLE_CURSOR_SLOT_GET(var));
        return CT_ERROR;
    }

    ple_for_cursor_jump(stmt, exec, for_line, sub_stmt, var, jump_line);
    return CT_SUCCESS;
}

static status_t ple_for_range_as_int32(variant_t *revert, source_location_t loc, int32 *result)
{
    if (revert->is_null) {
        CT_SRC_THROW_ERROR(loc, ERR_INVALID_NUMBER, "null");
        return CT_ERROR;
    }

    if (!CT_IS_NUMERIC_TYPE(revert->type)) {
        CT_SRC_THROW_ERROR(loc, ERR_PL_SYNTAX_ERROR_FMT, "unsupport range type in for statement.");
        return CT_ERROR;
    }

    return var_to_round_int32(revert, ROUND_HALF_UP, result);
}

static status_t ple_for_not_null(sql_stmt_t *stmt, pl_line_ctrl_t *line, pl_line_for_t *for_line, int32 *lower,
    int32 *upper)
{
    variant_t revert;

    if (for_line->reverse) {
        /* caculate the lower_expr */
        if (sql_exec_expr(stmt, for_line->lower_expr, &revert) != CT_SUCCESS) {
            cm_try_set_error_loc(line->loc);
            return CT_ERROR;
        }
        CT_RETURN_IFERR(ple_for_range_as_int32(&revert, line->loc, lower));
    } else {
        /* caculate the upper_expr */
        if (sql_exec_expr(stmt, for_line->upper_expr, &revert) != CT_SUCCESS) {
            cm_try_set_error_loc(line->loc);
            return CT_ERROR;
        }
        CT_RETURN_IFERR(ple_for_range_as_int32(&revert, line->loc, upper));
    }
    return CT_SUCCESS;
}

static status_t ple_for_is_null(sql_stmt_t *stmt, pl_line_ctrl_t *line, pl_line_for_t *for_line, int32 *lower,
    int32 *upper)
{
    variant_t revert;
    /* caculate the lower_expr */
    if (sql_exec_expr(stmt, for_line->lower_expr, &revert) != CT_SUCCESS) {
        cm_try_set_error_loc(line->loc);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(ple_for_range_as_int32(&revert, line->loc, lower));

    /* caculate the upper_expr */
    if (sql_exec_expr(stmt, for_line->upper_expr, &revert) != CT_SUCCESS) {
        cm_try_set_error_loc(line->loc);
        return CT_ERROR;
    }

    return ple_for_range_as_int32(&revert, line->loc, upper);
}

status_t ple_for(ple_line_assist_t *line_ass)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_executor_t *exec = line_ass->exec;
    pl_line_ctrl_t *line = line_ass->line;
    pl_line_for_t *for_line = (pl_line_for_t *)line;
    bool32 cond = CT_TRUE;
    bool32 is_first_run = CT_FALSE;
    int64 curr;
    int32 lower = 0;
    int32 upper = 0;
    variant_t *id = NULL;

    if (line != PLE_CURR_BLOCK(exec)->entry) {
        CT_RETURN_IFERR(ple_push_block_for(stmt, line));
        is_first_run = CT_TRUE;
    }

    if (for_line->is_cur) {
        return ple_for_cursor(stmt, exec, line, &line_ass->jump, is_first_run);
    }

    id = ple_get_value(stmt, for_line->id->vid);
    if (id->is_null) {
        CT_RETURN_IFERR(ple_for_is_null(stmt, line, for_line, &lower, &upper));
        curr = (for_line->reverse) ? upper : lower;
        id->is_null = CT_FALSE;
    } else {
        curr = id->v_int;
        curr = (for_line->reverse) ? (curr - 1) : (curr + 1); // not overflow
        CT_RETURN_IFERR(ple_for_not_null(stmt, line, for_line, &lower, &upper));
    }

    if (for_line->reverse) {
        cond = (curr >= lower) ? CT_TRUE : CT_FALSE;
    } else {
        cond = (curr <= upper) ? CT_TRUE : CT_FALSE;
    }

    if (cond) {
        line_ass->jump = NULL;
        // value of curr must be in range of int32
        id->v_int = (int32)curr;
    } else {
        // jump to next line of end loop.
        ple_update_coverage_hit_count(exec, for_line->next);
        line_ass->jump = ((pl_line_ctrl_t *)for_line->next)->next;
        ple_pop_block(stmt, exec);
    }

    return CT_SUCCESS;
}

status_t ple_commit(ple_line_assist_t *line_ass)
{
    sql_stmt_t *stmt = line_ass->stmt;

    if (pl_check_trig_and_udf(stmt) != CT_SUCCESS) {
        return CT_ERROR;
    }

    knl_commit((knl_handle_t)&stmt->session->knl_session);
    return CT_SUCCESS;
}

status_t ple_rollback(ple_line_assist_t *line_ass)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_executor_t *exec = line_ass->exec;
    pl_line_rollback_t *line = (pl_line_rollback_t *)line_ass->line;
    if (pl_check_trig_and_udf(stmt) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (line->savepoint.len != 0) {
        CT_RETURN_IFERR(ple_check_rollback(exec, &line->savepoint, &line->ctrl.loc));
        CT_RETURN_IFERR(knl_rollback_savepoint((knl_handle_t)&stmt->session->knl_session, &line->savepoint));
    } else {
        knl_rollback((knl_handle_t)&stmt->session->knl_session, NULL);
    }

    return CT_SUCCESS;
}

status_t ple_savepoint(ple_line_assist_t *line_ass)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_executor_t *exec = line_ass->exec;
    pl_line_savepoint_t *line = (pl_line_savepoint_t *)line_ass->line;

    if (pl_check_trig_and_udf(stmt) != CT_SUCCESS) {
        return CT_ERROR;
    }
    CT_RETURN_IFERR(knl_set_savepoint((knl_handle_t)&stmt->session->knl_session, &line->savepoint));
    CT_RETURN_IFERR(ple_store_savepoint(stmt, exec, &line->savepoint));

    return CT_SUCCESS;
}

static status_t ple_fork_stmt_with_context(sql_stmt_t *stmt, pl_line_sql_t *line, sql_stmt_t **sub_stmt)
{
    CT_RETURN_IFERR(ple_fork_stmt(stmt, sub_stmt));
    if (line->context == NULL) {
        CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_PL_CONTEXT_EMPTY);
        return CT_ERROR;
    }

    (*sub_stmt)->lang_type = LANG_DML;
    (*sub_stmt)->context = line->context;

    ctx_inc_ref(&(*sub_stmt)->context->ctrl);
    return CT_SUCCESS;
}

static status_t ple_dynamic_sql_get_var(sql_stmt_t *stmt, pl_line_sql_t *line, variant_t *var)
{
    CT_RETURN_IFERR(sql_exec_expr(stmt, line->dynamic_sql, var));
    /* the value keeped will be release at the end of this function */
    sql_keep_stack_variant(stmt, var);

    if (!CT_IS_STRING_TYPE(var->type)) {
        CT_THROW_ERROR(ERR_TYPE_MISMATCH, "STRING", get_datatype_name_str((int32)(var->type)));
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t ple_verify_result_set(sql_stmt_t *stmt, pl_line_ctrl_t *ctrl)
{
    pl_into_t *into = &((pl_line_sql_t *)((pl_executor_t *)stmt->pl_exec)->curr_line)->into;
    // if there is no data,  '..bulk collect into..' return success, '..into..'return error
    if (stmt->batch_rows == 0 && into->is_bulk == CT_FALSE) {
        CT_SRC_THROW_ERROR(ctrl->loc, ERR_NO_DATA_FOUND);
        return CT_ERROR;
    }

    if (!stmt->eof) {
        CT_SRC_THROW_ERROR(ctrl->loc, ERR_TOO_MANY_ROWS);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t ple_exec_dynamic_sql(sql_stmt_t *stmt, pl_executor_t *exec, pl_line_sql_t *line)
{
    variant_t var;
    sql_stmt_t *sub_stmt = NULL;
    status_t status = CT_ERROR;

    PLE_SAVE_STMT(stmt);
    if (ple_dynamic_sql_get_var(stmt, line, &var) != CT_SUCCESS) {
        PLE_RESTORE_STMT(stmt);
        return CT_ERROR;
    }

    if (ple_fork_stmt(stmt, &sub_stmt) != CT_SUCCESS) {
        PLE_RESTORE_STMT(stmt);
        return CT_ERROR;
    }

    sub_stmt->prefetch_rows = line->into.prefetch_rows;

    do {
        CT_BREAK_IF_ERROR(sql_parse(sub_stmt, &var.v_text, &line->dynamic_sql->loc));
        CT_BREAK_IF_ERROR(plc_verify_into_clause(sub_stmt->context, &line->into, line->ctrl.loc));
        sub_stmt->status = STMT_STATUS_PREPARED;
        exec->sql_loc = line->ctrl.loc;
        sub_stmt->plsql_mode = PLSQL_STATIC;

        if (sql_execute(sub_stmt) != CT_SUCCESS) {
            pl_check_and_set_loc(line->ctrl.loc);
            break;
        }
        stmt->total_rows = sub_stmt->total_rows;
        exec->recent_rows = sub_stmt->total_rows;
        exec->sql_executed = CT_TRUE;
        if (line->into.output != NULL) {
            if (ple_verify_result_set(sub_stmt, &line->ctrl) != CT_SUCCESS) {
                pl_check_and_set_loc(line->ctrl.loc);
                status = CT_ERROR;
                break;
            }
        }
        status = CT_SUCCESS;
    } while (0);
    if (status != CT_SUCCESS) {
        pl_check_and_set_loc(line->ctrl.loc);
        ple_check_exec_error(sub_stmt, &line->ctrl.loc);
        ple_inherit_substmt_error(stmt, sub_stmt);
    }
    sql_release_lob_info(sub_stmt);
    sql_release_resource(sub_stmt, CT_TRUE);
    sql_free_context(sub_stmt->context);
    PLE_RESTORE_STMT(stmt);
    return status;
}

status_t ple_exec_sql(ple_line_assist_t *line_ass)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_executor_t *exec = line_ass->exec;
    pl_line_sql_t *line = (pl_line_sql_t *)line_ass->line;
    sql_stmt_t *sub_stmt = NULL;

    if (sql_stack_safe(stmt) != CT_SUCCESS) {
        cm_try_set_error_loc(line->ctrl.loc);
        return CT_ERROR;
    }

    if (line->is_dynamic_sql == CT_TRUE) {
        return ple_exec_dynamic_sql(stmt, exec, line);
    }

    PLE_SAVE_STMT(stmt);

    if (ple_fork_stmt_with_context(stmt, line, &sub_stmt) != CT_SUCCESS) {
        PLE_RESTORE_STMT(stmt);
        return CT_ERROR;
    }

    sub_stmt->prefetch_rows = line->into.prefetch_rows;
    sub_stmt->plsql_mode = PLSQL_STATIC;
    sub_stmt->chk_priv = CT_FALSE;
    sub_stmt->session->sender = &g_instance->sql.pl_sender;
    exec->sql_loc = line->ctrl.loc;

    if (sql_execute(sub_stmt) != CT_SUCCESS) {
        pl_check_and_set_loc(line->ctrl.loc);
        sql_free_stmt(sub_stmt);
        PLE_RESTORE_STMT(stmt);
        return CT_ERROR;
    }

    exec->recent_rows = sub_stmt->total_rows;
    exec->sql_executed = CT_TRUE;

    // sql is reparsed, sub stmt's context is changed
    if (ple_check_substmt_ctx(sub_stmt, line->context)) {
        // set procedure/function status to invalid
        pl_entity_invalidate((pl_entity_t *)stmt->pl_context);
        sql_release_context(sub_stmt);
    }

    if (line->into.output != NULL) {
        if (ple_verify_result_set(sub_stmt, &line->ctrl) != CT_SUCCESS) {
            pl_check_and_set_loc(line->ctrl.loc);
            sql_free_stmt(sub_stmt);
            PLE_RESTORE_STMT(stmt);
            return CT_ERROR;
        }
    }

    sql_free_stmt(sub_stmt);
    PLE_RESTORE_STMT(stmt);
    return CT_SUCCESS;
}

status_t ple_call_proc(ple_line_assist_t *line_ass)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_line_normal_t *line = (pl_line_normal_t *)line_ass->line;
    variant_t result;
    status_t status = CT_SUCCESS;

    CT_RETURN_IFERR(sql_stack_safe(stmt));

    switch (line->proc->type) {
        case EXPR_NODE_PROC:
            /*
             * System proc write with c need to increase ssn, such as dbe_stats.collect_table_stats.
             * Otherwise it will cannot see the results of latest dml sql.
             */
            sql_set_ssn(stmt);
            /* fall-through */
        case EXPR_NODE_FUNC:
        case EXPR_NODE_V_METHOD:
        case EXPR_NODE_V_ADDR:
            status = sql_exec_expr_node(stmt, line->proc, &result);
            if (status != CT_SUCCESS) {
                pl_check_and_set_loc(line->ctrl.loc);
            }
            break;

        case EXPR_NODE_USER_PROC:
        case EXPR_NODE_USER_FUNC:
        default:
            status = ple_exec_call(stmt, line->proc, NULL);
            break;
    }

    return status;
}

status_t ple_return(ple_line_assist_t *line_ass)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_executor_t *exec = line_ass->exec;
    pl_line_return_t *line = (pl_line_return_t *)line_ass->line;
    ple_var_t *var = NULL;
    ple_block_t *block = NULL;
    pl_line_begin_t *begin_line = exec->body;
    pl_line_ctrl_t *end_line = begin_line->end;
    cm_reset_error();
    if (end_line == NULL) {
        begin_line = (pl_line_begin_t *)begin_line->ctrl.next;
        end_line = begin_line->end;
    }
    if (end_line != NULL) {
        ple_update_coverage_hit_count(exec, end_line);
    }

    CT_RETSUC_IFTRUE(line->expr == NULL);
    block = exec->block_stack.items[exec->stack_base];
    var = block->var_map.items[0];

    variant_t right;

    if (sql_exec_expr(stmt, line->expr, &right) != CT_SUCCESS) {
        cm_try_set_error_loc(line->ctrl.loc);
        return CT_ERROR;
    }

    if (ple_move_value(stmt, &right, var) != CT_SUCCESS) {
        cm_try_set_error_loc(line->ctrl.loc);
        return CT_ERROR;
    }

    sql_keep_stack_variant(stmt, &var->value);
    return CT_SUCCESS;
}

static status_t ple_after_check_open_dyncur(sql_stmt_t *stmt, pl_line_open_t *line, status_t parse_err)
{
    if (parse_err != CT_SUCCESS) {
        cm_reset_error();
        CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_PLSQL_ILLEGAL_LINE_FMT,
            "sys_refcursor must open a legal SELECT statement");
        return CT_ERROR;
    }

    if (stmt->context->type != CTSQL_TYPE_SELECT) {
        CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_PLSQL_ILLEGAL_LINE_FMT,
            "sys_refcursor must open a legal SELECT statement");
        return CT_ERROR;
    }

    if (line->using_exprs == NULL) {
        if (stmt->context->params->count == 0) {
            return CT_SUCCESS;
        }

        CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_PLSQL_ILLEGAL_LINE_FMT, "variables bound mismatch");
        return CT_ERROR;
    }

    if (stmt->context->params->count != line->using_exprs->count) {
        CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_PLSQL_ILLEGAL_LINE_FMT, "variables bound mismatch");
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static void ple_free_ref_cursor(pl_cursor_slot_t *ref_cur)
{
    if (ref_cur == NULL) {
        return;
    }

    if (ref_cur->ref_count <= 1) {
        ref_cur->state = CUR_RES_FREE;
        return;
    }

    ref_cur->ref_count--;
}

status_t ple_open(ple_line_assist_t *line_ass)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_executor_t *exec = line_ass->exec;
    pl_line_open_t *line = (pl_line_open_t *)line_ass->line;
    sql_context_t *save_ctx = NULL;
    ple_var_t *var = ple_get_plvar(exec, line->vid);
    sql_stmt_t *sub_stmt = NULL;
    pl_cursor_slot_t *ref_cursor = NULL;
    sql_stmt_t *save_curr_stmt = stmt->session->current_stmt;
    if (var->decl->drct == PLV_DIR_IN) {
        CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_PLE_CURSOR_IN_OPEN, T2S(&var->decl->name));
        return CT_ERROR;
    }
    if (PLE_CURSOR_SLOT_GET(var) == NULL) {
        CT_RETURN_IFERR(ple_alloc_ref_cursor(stmt, (void **)&ref_cursor));
        var->value.v_cursor.ref_cursor = ref_cursor;
    } else {
        ref_cursor = PLE_CURSOR_SLOT_GET(var);
        sub_stmt = ple_ref_cursor_get(stmt, ref_cursor);
        if (sub_stmt != NULL) {
            if (!var->decl->cursor.ctx->is_sysref) {
                CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_CURSOR_ALREADY_OPEN);
                return CT_ERROR;
            }
            // if a sysrefcursor open more than once , the stmt previous need to be free directly
            ple_close_cursor(sub_stmt, ref_cursor);
        }
    }
    CT_RETURN_IFERR(sql_alloc_stmt(stmt->session, &sub_stmt));
    ref_cursor->stmt_id = sub_stmt->id;

    sub_stmt->cursor_info.type = PL_EXPLICIT_CURSOR;
    sub_stmt->plsql_mode = PLSQL_CURSOR;
    sub_stmt->chk_priv = CT_FALSE;
    sub_stmt->lang_type = LANG_DML;
    sub_stmt->status = stmt->status;
    sub_stmt->pl_exec = stmt->pl_exec;
    sub_stmt->is_srvoutput_on = stmt->is_srvoutput_on;
    sub_stmt->is_sub_stmt = CT_TRUE;
    sub_stmt->pl_ref_entry = stmt->pl_ref_entry;
    sub_stmt->parent_stmt = stmt;

    if (line->is_dynamic_sql) {
        variant_t result;
        status_t status;

        // dynamic sql context cannot attached by pl,since it's life period is same with the alloc statement.
        CT_RETURN_IFERR(sql_exec_expr(stmt, line->dynamic_sql, &result));
        if (result.is_null || !CT_IS_STRING_TYPE(result.type)) {
            CT_SRC_THROW_ERROR(line->dynamic_sql->loc, ERR_PLSQL_ILLEGAL_LINE_FMT,
                "NO-SELECT statement is executed in an illegal context");
            status = CT_ERROR;
        } else {
            sql_keep_stack_variant(stmt, &result);
            sub_stmt->session->current_stmt = sub_stmt;
            status = sql_parse(sub_stmt, &result.v_text, &line->dynamic_sql->loc);
            // parse error will raise by ple_after_check_open_dyncur
            status = ple_after_check_open_dyncur(sub_stmt, line, status);
            stmt->session->current_stmt = save_curr_stmt;
        }

        if (status != CT_SUCCESS) {
            sub_stmt->is_sub_stmt = CT_FALSE;
            sql_free_stmt(sub_stmt);
            ref_cursor->stmt_id = CT_INVALID_ID16;
            ple_free_ref_cursor(ref_cursor);
            var->value.v_cursor.ref_cursor = NULL;
            return CT_ERROR;
        }
    } else {
        if (var->decl->cursor.ctx->is_sysref == CT_FALSE) {
            sub_stmt->context = var->decl->cursor.ctx->context;
        } else {
            sub_stmt->context = line->context;
        }

        ctx_inc_ref(&sub_stmt->context->ctrl);
    }
    ack_sender_t *sender = sub_stmt->session->sender;
    sub_stmt->session->sender = &g_instance->sql.pl_sender;
    /*
     * execute the sql and delay fetch data
     */
    save_ctx = sub_stmt->context;
    var->value.type = CT_TYPE_CURSOR;
    var->value.is_null = CT_FALSE;
    if (var->decl->cursor.ctx->is_sysref) {
        if (!line->is_dynamic_sql) {
            var->value.v_cursor.input = line->input;
            exec->curr_input = line->input;
            exec->is_dyncur = CT_FALSE;
        } else {
            exec->using_values = line->using_exprs;
            exec->is_dyncur = CT_TRUE;
        }
    } else {
        // prepare cursor param
        CT_RETURN_IFERR(ple_prepare_cursor_param(stmt, var, line->exprs, line->ctrl.loc));
        exec->curr_input = var->decl->cursor.input;
        exec->is_dyncur = CT_FALSE;
    }
    PLE_SAVE_STMT(stmt);
    sub_stmt->session->current_stmt = sub_stmt;
    if (sql_execute(sub_stmt) != CT_SUCCESS) {
        sql_free_stmt(sub_stmt);
        ref_cursor->stmt_id = CT_INVALID_ID16;
        ple_free_ref_cursor(ref_cursor);
        var->value.v_cursor.ref_cursor = NULL;
        sub_stmt->session->sender = sender;
        PLE_RESTORE_STMT(stmt);
        return CT_ERROR;
    }
    sub_stmt->session->sender = sender;
    exec->recent_rows = sub_stmt->total_rows;
    sub_stmt->cursor_info.sql_executed = CT_TRUE;

    // sql is reparsed, sub stmt's context is changed
    if (ple_check_substmt_ctx(sub_stmt, save_ctx)) {
        // set procedure/function status to invalid
        pl_entity_invalidate(stmt->pl_context);
    }

    ((pl_executor_t *)stmt->pl_exec)->sql_executed = CT_TRUE;
    PLE_RESTORE_STMT(stmt);
    return CT_SUCCESS;
}

status_t ple_fetch(ple_line_assist_t *line_ass)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_executor_t *exec = line_ass->exec;
    pl_line_fetch_t *line = (pl_line_fetch_t *)line_ass->line;
    ple_var_t *var = ple_get_plvar(exec, line->vid);
    sql_stmt_t *sub_stmt = ple_ref_cursor_get(stmt, PLE_CURSOR_SLOT_GET(var));
    variant_t limit_var;
    if (sub_stmt == NULL) {
        CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_INVALID_CURSOR);
        return CT_ERROR;
    }

    if (sub_stmt->cursor_info.is_forcur || sub_stmt->context == NULL) {
        CT_SRC_THROW_ERROR(line->ctrl.loc, ERR_INVALID_CURSOR);
        return CT_ERROR;
    }

    if (sub_stmt->total_rows == 0) {
        sub_stmt->prefetch_rows = line->into.prefetch_rows;
        CT_RETURN_IFERR(plc_verify_into_clause(sub_stmt->context, &line->into, line->ctrl.loc));
        if (line->into.limit != NULL) {
            CT_RETURN_IFERR(sql_exec_expr(stmt, line->into.limit, &limit_var));
            if (CT_IS_NUMERIC_TYPE(limit_var.type)) {
                CT_RETURN_IFERR(sql_convert_variant(stmt, &limit_var, CT_TYPE_INTEGER));
            }
            if (limit_var.is_null || limit_var.type != CT_TYPE_INTEGER || limit_var.v_int <= 0) {
                CT_SRC_THROW_ERROR_EX(line->ctrl.loc, ERR_PL_SYNTAX_ERROR_FMT, "numberic or value error");
                return CT_ERROR;
            }
            sub_stmt->prefetch_rows = limit_var.v_int;
        }
    }

    exec->curr_line = (pl_line_ctrl_t *)line;
    PLE_SAVE_STMT(stmt);
    sub_stmt->session->sender = &g_instance->sql.pl_sender;
    sub_stmt->session->current_stmt = sub_stmt;
    sub_stmt->pl_exec = exec;
    exec->sql_loc = line->ctrl.loc;
    // when passing the result set by sub-query into PL variants, for example, the scene in which a cursor makes an
    // out parameter or returning result, the origin PL stmt has already freed and we need use new pl stmt to save it.
    sub_stmt->parent_stmt = stmt;

    if (sql_execute_fetch(sub_stmt) != CT_SUCCESS) {
        pl_check_and_set_loc(line->ctrl.loc);
        PLE_RESTORE_STMT(stmt);
        return CT_ERROR;
    }
    sub_stmt->cursor_info.has_fetched = CT_TRUE;
    PLE_RESTORE_STMT(stmt);
    return CT_SUCCESS;
}

status_t ple_close(ple_line_assist_t *line_ass)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_executor_t *exec = line_ass->exec;
    pl_line_close_t *line = (pl_line_close_t *)line_ass->line;
    ple_var_t *var = ple_get_plvar(exec, line->vid);
    sql_stmt_t *sub_stmt = ple_ref_cursor_get(stmt, var->value.v_cursor.ref_cursor);
    if (sub_stmt == NULL) {
        CT_THROW_ERROR(ERR_INVALID_CURSOR);
        return CT_ERROR;
    }

    if (sub_stmt->cursor_info.is_forcur) {
        CT_THROW_ERROR(ERR_INVALID_CURSOR);
        return CT_ERROR;
    }

    ple_close_cursor(sub_stmt, PLE_CURSOR_SLOT_GET(var));
    return CT_SUCCESS;
}

#define PLE_IS_DML_TYPE(type)                                                                                    \
    (type == CTSQL_TYPE_DELETE || type == CTSQL_TYPE_UPDATE || type == CTSQL_TYPE_INSERT || type == CTSQL_TYPE_SELECT || \
        type == CTSQL_TYPE_MERGE)

static status_t ple_set_dynsql_outparams(sql_stmt_t *stmt, sql_stmt_t *sub_stmt)
{
    ple_var_t *dst = NULL;
    variant_t *value = NULL;
    sql_param_mark_t *param_mark = NULL;
    pl_using_expr_t *using_expr = NULL;
    bool8 flag = CT_FALSE;

    // set OUT param
    for (uint32 i = 0; i < sub_stmt->context->params->count; i++) {
        if (sub_stmt->param_info.params[i].direction == PLV_DIR_IN) {
            continue;
        }

        value = sub_stmt->param_info.params[i].out_value;
        if (value == NULL) {
            continue;
        }
        param_mark = (sql_param_mark_t *)cm_galist_get(sub_stmt->context->params, i);

        CT_RETURN_IFERR(ple_get_dynsql_using_expr(stmt, param_mark->pnid, &using_expr));
        if (using_expr->expr->root->type == EXPR_NODE_V_ADDR) {
            if (sql_pair_type_is_plvar(using_expr->expr->root)) {
                CT_RETURN_IFERR(ple_get_using_expr_var(stmt, using_expr, &dst, PLE_CHECK_OUT));
                flag = CT_TRUE;
            }
            expr_node_t *node = using_expr->expr->root;
            CT_RETURN_IFERR(udt_exec_v_addr(stmt, node, &dst->value, value));
            if (flag && dst->decl->type == PLV_CUR) {
                // dst cursor slot didn't dec ref_count, need dec here.
                ple_cursor_dec_refcount(stmt, &dst->value, CT_FALSE);
            }
        }

        if (value->type == CT_TYPE_COLLECTION) {
            udt_invoke_coll_destructor(stmt, value);
        } else if (value->type == CT_TYPE_RECORD) {
            udt_release_rec(stmt, value);
        } else if (value->type == CT_TYPE_OBJECT) {
            udt_release_obj(stmt, value);
        }
    }
    return CT_SUCCESS;
}

static status_t ple_after_exec_immediate(sql_stmt_t *stmt, sql_stmt_t *sub_stmt, pl_line_execute_t *line)
{
    CT_RETSUC_IFTRUE(sub_stmt->context == NULL);

    if (sub_stmt->context->type == CTSQL_TYPE_ANONYMOUS_BLOCK) {
        return ple_set_dynsql_outparams(stmt, sub_stmt);
    }

    if (line->into.into_type == INTO_AS_VALUE || line->into.into_type == INTO_AS_REC) {
        if (line->into.output != NULL && sub_stmt->context->type == CTSQL_TYPE_SELECT) {
            if (sub_stmt->total_rows == 0) {
                CT_THROW_ERROR(ERR_NO_DATA_FOUND);
                return CT_ERROR;
            }

            if (sub_stmt->total_rows > 1) {
                CT_THROW_ERROR(ERR_TOO_MANY_ROWS);
                return CT_ERROR;
            }
        }
    }

    if (PLE_IS_DML_TYPE(sub_stmt->context->type)) {
        stmt->total_rows = sub_stmt->total_rows;
        pl_executor_t *exec = (pl_executor_t *)stmt->pl_exec;
        exec->recent_rows = sub_stmt->total_rows;
        exec->sql_executed = CT_TRUE;
    }

    return CT_SUCCESS;
}

static status_t ple_before_exec_immediate(sql_stmt_t *stmt, pl_line_execute_t *line)
{
    uint32 using_count = (line->using_exprs == NULL) ? 0 : line->using_exprs->count;
    uint32 pname_count =
        (stmt->context->type < CTSQL_TYPE_DML_CEIL) ? stmt->context->params->count : stmt->context->pname_count;

    if (pname_count != using_count) {
        CT_THROW_ERROR(ERR_PROGRAM_ERROR_FMT,
            "The param count of dynamic sql is not same as the param count of using clause");
        return CT_ERROR;
    }

    if (line->into.output != NULL) {
        if (stmt->context->type != CTSQL_TYPE_SELECT) {
            CT_THROW_ERROR(ERR_DYNAMIC_ILLEGAL_INTO);
            return CT_ERROR;
        }
        stmt->prefetch_rows = line->into.prefetch_rows;
        CT_RETURN_IFERR(plc_verify_into_clause(stmt->context, &line->into, line->ctrl.loc));
    }

    return CT_SUCCESS;
}

static bool32 pl_is_create_type(sql_type_t type)
{
    if (type == CTSQL_TYPE_CREATE_PROC || type == CTSQL_TYPE_CREATE_FUNC || type == CTSQL_TYPE_CREATE_PACK_SPEC ||
        type == CTSQL_TYPE_CREATE_PACK_BODY || type == CTSQL_TYPE_CREATE_TYPE_SPEC || type == CTSQL_TYPE_CREATE_TYPE_BODY ||
        type == CTSQL_TYPE_CREATE_TRIG) {
        return CT_TRUE;
    }

    return CT_FALSE;
}

static void ple_save_lock_entries(sql_stmt_t *stmt, uint32 *entry_count)
{
    if (stmt->pl_ref_entry == NULL) {
        *entry_count = 0;
    } else {
        *entry_count = stmt->pl_ref_entry->count;
    }
}

static status_t ple_exec_immediate(ple_line_assist_t *line_ass)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_line_execute_t *line = (pl_line_execute_t *)line_ass->line;
    variant_t var;
    uint32 entry_count;
    sql_stmt_t *sub_stmt = NULL;
    status_t status = CT_ERROR;
    source_location_t dysql_loc;
    CT_RETURN_IFERR(sql_stack_safe(stmt));

    PLE_SAVE_STMT(stmt);
    /* save the lock entry info and restore at the end of execute immediate */
    ple_save_lock_entries(stmt, &entry_count);

    if (sql_exec_expr(stmt, line->dynamic_sql, &var) != CT_SUCCESS) {
        PLE_RESTORE_STMT(stmt);
        return CT_ERROR;
    }

    /* the value keeped will be release at the end of this function */
    sql_keep_stack_variant(stmt, &var);

    do {
        if (var.is_null || !CT_IS_STRING_TYPE(var.type)) {
            CT_THROW_ERROR(ERR_DYNAMIC_WRONG_TYPE);
            break;
        }

        CT_BREAK_IF_ERROR(ple_fork_stmt(stmt, &sub_stmt));
        CT_BREAK_IF_ERROR(ple_fork_executor_core(stmt, sub_stmt));
        pl_executor_t *exec = sub_stmt->pl_exec;
        exec->dynamic_parent = stmt;
        exec->entity = ((pl_executor_t *)stmt->pl_exec)->entity;
        exec->curr_line = ((pl_executor_t *)stmt->pl_exec)->curr_line;
        sub_stmt->param_info.params = NULL;
        sub_stmt->pl_ref_entry = stmt->pl_ref_entry;
        dysql_loc.line = 1;
        dysql_loc.column = 1;
        if (sql_parse(sub_stmt, &var.v_text, &dysql_loc) != CT_SUCCESS) {
            break;
        }
        g_tls_plc_error.plc_flag = CT_FALSE;

        if (sub_stmt->pl_failed && pl_is_create_type(sub_stmt->context->type)) {
            break;
        }
        if (sub_stmt->lang_type == LANG_EXPLAIN) {
            CT_THROW_ERROR(ERR_CAPABILITY_NOT_SUPPORT, "explain sql plan in PL dynamic sql is");
            break;
        }
        sub_stmt->plsql_mode = (sub_stmt->context->type == CTSQL_TYPE_ANONYMOUS_BLOCK) ? PLSQL_DYNBLK : PLSQL_DYNSQL;
        if (sub_stmt->plsql_mode == PLSQL_DYNSQL) {
            pl_executor_t *parent_exec = stmt->pl_exec;
            exec->block_stack = parent_exec->block_stack;
            exec->stack_base = parent_exec->block_stack.depth;
            sub_stmt->param_info.params = stmt->param_info.params;
        }
        CT_BREAK_IF_ERROR(ple_before_exec_immediate(sub_stmt, line));
        sql_log_param_change(sub_stmt, var.v_text);

        sub_stmt->status = STMT_STATUS_PREPARED;

        if (sql_execute(sub_stmt) != CT_SUCCESS) {
            pl_check_and_set_loc(line->ctrl.loc);
            ple_check_exec_error(sub_stmt, &line->ctrl.loc);
            ple_inherit_substmt_error(stmt, sub_stmt);
            break;
        }

        CT_BREAK_IF_ERROR(ple_after_exec_immediate(stmt, sub_stmt, line));
        status = CT_SUCCESS;
    } while (0);

    if (sub_stmt != NULL) {
        sql_release_lob_info(sub_stmt);
        sql_release_resource(sub_stmt, CT_TRUE);
        sql_release_context(sub_stmt);
        if (sub_stmt->stat != NULL) {
            free(sub_stmt->stat);
            sub_stmt->stat = NULL;
        }
    }

    PLE_RESTORE_STMT(stmt);
    /* restore the lock info at the end of execute immediate */
    ple_restore_lock_entries(stmt, entry_count);
    return status;
}

static bool32 ple_equal_exceptions(pl_exception_t *except_left, pl_exception_t *except_right)
{
    if (except_left == NULL || except_right == NULL) {
        return CT_FALSE;
    }

    if (except_right->is_userdef == CT_TRUE) {
        if (except_left->is_userdef != except_right->is_userdef) {
            return CT_FALSE;
        } else {
            return PL_VID_EQUAL(except_left->vid, except_right->vid);
        }
    }
    return except_left->error_code == except_right->error_code;
}

status_t ple_get_begin_block(pl_executor_t *exec, ple_block_t **return_block)
{
    ple_block_t *curr_block = NULL;
    pl_line_ctrl_t *line = NULL;
    uint16 curr_depth = exec->block_stack.depth;
    while (curr_depth > exec->stack_base) {
        curr_block = (exec->block_stack.items[curr_depth - 1]); // not overflow
        line = curr_block->entry;
        if (line->type == LINE_BEGIN) {
            *return_block = curr_block;
            return CT_SUCCESS;
        }
        curr_depth--;
    }
    return CT_ERROR;
}

status_t ple_set_curr_except(sql_stmt_t *stmt, source_location_t line_loc, pl_exec_exception_t **return_except)
{
    pl_executor_t *exec = (pl_executor_t *)stmt->pl_exec;
    ple_block_t *begin_block = NULL;
    int32 error_code;
    const char *error_msg = NULL;
    source_location_t error_loc;
    pl_exec_exception_t *curr_except = NULL;
    pl_exec_exception_t *exec_except = &(exec->exec_except);

    cm_get_error(&error_code, &error_msg, &error_loc);
    if (error_code && strlen(error_msg) == 0) {
        PL_THROW_ERROR(error_code, "message of error code not defined");
    }

    if (ple_get_begin_block(exec, &begin_block) != CT_SUCCESS) {
        CT_SRC_THROW_ERROR(line_loc, ERR_PL_SYNTAX_ERROR_FMT, "cannot find begin block");
        return CT_ERROR;
    }

    if (begin_block->curr_except == NULL) {
        CT_RETURN_IFERR(sql_push(stmt, sizeof(pl_exec_exception_t), (void **)&(begin_block->curr_except)));
    }
    curr_except = begin_block->curr_except;

    if (exec_except->has_exception == CT_TRUE) {
        curr_except->has_exception = CT_TRUE;
        curr_except->except = exec_except->except;
    } else {
        cm_get_error(&error_code, &error_msg, &error_loc);
        curr_except->has_exception = CT_TRUE;
        curr_except->except.is_userdef = CT_FALSE;
        curr_except->except.error_code = error_code;
        curr_except->except.loc = error_loc;
        MEMS_RETURN_IFERR(strcpy_s(curr_except->except.message, CT_MESSAGE_BUFFER_SIZE, error_msg));
    }
    *return_except = curr_except;
    return CT_SUCCESS;
}

status_t ple_exception(ple_line_assist_t *line_ass)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_executor_t *exec = line_ass->exec;
    pl_line_except_t *start = (pl_line_except_t *)line_ass->line;
    pl_line_when_t *line = NULL;
    pl_exception_t *except = NULL;
    status_t status = CT_SUCCESS;
    uint32 i, j;
    bool32 found = CT_FALSE;
    pl_exec_exception_t *curr_except = NULL;
    pl_exec_exception_t *exec_except = &(exec->exec_except);

    CT_RETURN_IFERR(ple_set_curr_except(stmt, start->ctrl.loc, &curr_except));
    for (i = 0; i < start->excpts->count; i++) {
        line = (pl_line_when_t *)cm_galist_get(start->excpts, i);
        for (j = 0; j < line->excepts.count; j++) {
            except = (pl_exception_t *)cm_galist_get(&line->excepts, j);
            if ((except->is_userdef == CT_FALSE && except->error_code == OTHERS) ||
                ple_equal_exceptions(except, &curr_except->except) == CT_TRUE) {
                found = CT_TRUE;
                break;
            }
        }

        if (found) {
            ple_update_coverage_hit_count(exec, (pl_line_ctrl_t *)line);
            line_ass->jump = line->ctrl.next;
            break;
        }
    }

    if (line_ass->jump != NULL) {
        ple_stack_anchor_t anchor;
        ple_save_stack_anchor(stmt, &anchor);

        cm_reset_error();
        exec_except->has_exception = CT_FALSE;
        if (ple_push_block(stmt, (pl_line_ctrl_t *)start, NULL, anchor) != CT_SUCCESS) {
            ple_pop_block(stmt, exec);
            status = CT_ERROR;
        }
    } else {
        ple_pop_block(stmt, exec);
        status = CT_ERROR;
    }

    return status;
}

status_t ple_raise(ple_line_assist_t *line_ass)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_line_raise_t *start = (pl_line_raise_t *)line_ass->line;
    pl_executor_t *exec = (pl_executor_t *)stmt->pl_exec;
    pl_exec_exception_t *curr_except = NULL;
    pl_exec_exception_t *exec_except = &(exec->exec_except);

    cm_reset_error();
    if ((start->excpt_info.is_userdef == CT_FALSE && (uint32)start->excpt_info.error_code == CT_INVALID_INT32)) {
        if (ple_get_curr_except(exec, &curr_except) == CT_TRUE) {
            PL_SRC_THROW_ERROR(curr_except->except.loc, curr_except->except.error_code, "%s",
                curr_except->except.message);
            exec_except->has_exception = CT_TRUE;
            exec_except->except = curr_except->except;
        } else {
            CT_SRC_THROW_ERROR(start->ctrl.loc, ERR_PL_SYNTAX_ERROR_FMT, "cannot find any exception to raise");
        }
    } else {
        PL_SRC_THROW_ERROR(start->ctrl.loc, start->excpt_info.error_code, "%s",
            cm_get_errormsg(start->excpt_info.error_code));
        exec_except->has_exception = CT_TRUE;
        exec_except->except = start->excpt_info;
        MEMS_RETURN_IFERR(strcpy_s(exec_except->except.message, CT_MESSAGE_BUFFER_SIZE,
            cm_get_errormsg(start->excpt_info.error_code)));
    }
    return CT_ERROR;
}

status_t ple_end_when(ple_line_assist_t *line_ass)
{
    pl_executor_t *exec = line_ass->exec;
    ple_block_t *exec_block = PLE_CURR_BLOCK(exec);
    pl_line_ctrl_t *line_start = exec_block->entry;

    cm_reset_error();

    /* clean the exec excepiton info */
    MEMS_RETURN_IFERR(memset_s(&exec->exec_except, sizeof(pl_exec_exception_t), 0, sizeof(pl_exec_exception_t)));

    if (line_start->type == LINE_EXCEPTION) {
        line_ass->jump = ((pl_line_except_t *)line_start)->end;
    }

    return CT_SUCCESS;
}

status_t ple_end_exception(ple_line_assist_t *line_ass)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_executor_t *exec = line_ass->exec;
    ple_block_t *exec_block = PLE_CURR_BLOCK(exec);
    pl_line_ctrl_t *line_start = exec_block->entry;

    if (line_start->type == LINE_EXCEPTION) {
        PLE_RESET_EXEC_ERR(exec);
        ple_pop_block(stmt, exec);
    }

    return CT_SUCCESS;
}

static void ple_reset_stmt_cache(sql_stmt_t *stmt)
{
    stmt->v_sysdate = SQL_UNINITIALIZED_DATE;
    stmt->v_systimestamp = SQL_UNINITIALIZED_TSTAMP;
}

static void pl_reset_sequence(sql_stmt_t *stmt)
{
    pl_entity_t *entity = (pl_entity_t *)stmt->pl_context;
    for (uint32 i = 0; i < entity->sequences.count; ++i) {
        stmt->v_sequences[i].processed = CT_FALSE;
    }
}

status_t ple_line_prepare(ple_line_assist_t *line_ass)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_executor_t *exec = line_ass->exec;
    pl_line_ctrl_t *line = line_ass->line;
    status_t status = CT_SUCCESS;

    exec->curr_line = line;

    // avoid get the same sysdate or systimestamp in different lines.
    ple_reset_stmt_cache(stmt);
    SQL_CHECK_SESSION_VALID_FOR_RETURN(stmt);
    pl_reset_sequence(stmt);
    ple_update_coverage_hit_count(exec, line);

    if (stmt->session->dbg_ctl != NULL && stmt->session->dbg_ctl->type == TARGET_SESSION) {
        (void)stmt->session->dbg_ctl->dbg_calls.stmt_start((void *)stmt->session, (void *)exec, &status);
        if (status != CT_SUCCESS) {
            CT_SRC_THROW_ERROR(line->loc, ERR_DEBUG_FORCE_ABORT);
            ple_update_exec_error(stmt, &line->loc);
            (void)stmt->session->dbg_ctl->dbg_calls.proc_end((void *)stmt->session, (void *)exec, NULL);
            return CT_ERROR;
        }
    }

    if (line->type == LINE_END) {
        return ple_try_insert_coverage_table(stmt, (line == line_ass->proc_end) && PLE_IS_COVER_VALID(exec));
    }

    return CT_SUCCESS;
}

status_t ple_line_return(ple_line_assist_t *line_ass, status_t status)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_executor_t *exec = line_ass->exec;

    CT_RETURN_IFERR(ple_try_insert_coverage_table(stmt, PLE_IS_COVER_VALID(exec)));
    if (stmt->session->dbg_ctl != NULL && stmt->session->dbg_ctl->type == TARGET_SESSION) {
        (void)stmt->session->dbg_ctl->dbg_calls.stmt_end((void *)stmt->session, (void *)exec, &status);
        (void)stmt->session->dbg_ctl->dbg_calls.proc_end((void *)stmt->session, (void *)exec, NULL);
    }
    return status;
}

static pl_line_ctrl_t *ple_ignore_exception(pl_line_ctrl_t *jump_line, pl_line_ctrl_t *line)
{
    if (jump_line != NULL && jump_line->type == LINE_EXCEPTION) {
        jump_line = ((pl_line_except_t *)jump_line)->end->next;
    } else if (jump_line == NULL && line->next != NULL && line->next->type == LINE_EXCEPTION) {
        jump_line = ((pl_line_except_t *)line->next)->end->next;
    }
    return jump_line;
}


static status_t ple_pop_exeception_cond_exec(sql_stmt_t *stmt, pl_executor_t *exec, pl_line_ctrl_t *line,
    pl_line_ctrl_t *end)
{
    pl_line_ctrl_t *check = line->next;
    uint32 depth = 0;

    if (ple_calc_cond_exec_depth(stmt, check, end, &depth) != CT_SUCCESS) {
        cm_try_set_error_loc(line->loc);
        return CT_ERROR;
    }

    if (depth > exec->cond_exec.depth) {
        CT_SRC_THROW_ERROR(line->loc, ERR_PL_SYNTAX_ERROR_FMT, "unmatched block in loop statment");
        return CT_ERROR;
    }

    exec->cond_exec.depth = exec->cond_exec.depth - depth;
    return CT_SUCCESS;
}

static status_t ple_trackle_error(sql_stmt_t *stmt, pl_executor_t *exec, pl_line_ctrl_t **jump_line)
{
    ple_block_t *exec_block = NULL;
    pl_line_ctrl_t *line = NULL;
    pl_line_ctrl_t *except = NULL;
    pl_line_ctrl_t *curr_line = exec->curr_line;
    uint16 curr_depth = exec->block_stack.depth;

    while (exec->block_stack.depth > exec->stack_base) {
        exec_block = PLE_CURR_BLOCK(exec);
        line = exec_block->entry;
        except = ((pl_line_begin_t *)line)->except;

        /* Exception raised in declaration is not handled at current block. */
        if (line->type == LINE_BEGIN && except != NULL &&
            (curr_line->type != LINE_BEGIN || exec->block_stack.depth != curr_depth)) {
            CT_RETURN_IFERR(ple_pop_exeception_cond_exec(stmt, exec, line, curr_line));
            *jump_line = except;
            return CT_SUCCESS;
        }

        /* avoid to track exception recursive */
        if (line->type == LINE_EXCEPTION) {
            ple_pop_block(stmt, exec);
        }
        ple_pop_block(stmt, exec);
    } // end of while

    return CT_ERROR;
}

status_t ple_line_finish(ple_line_assist_t *line_ass, status_t status)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_executor_t *exec = line_ass->exec;
    pl_line_ctrl_t *line = line_ass->line;

    if (stmt->session->dbg_ctl != NULL && stmt->session->dbg_ctl->type == TARGET_SESSION) {
        (void)stmt->session->dbg_ctl->dbg_calls.stmt_end((void *)stmt->session, (void *)exec, &status);
    }

    if (status != CT_SUCCESS) {
        pl_check_and_set_loc(line->loc);
        ple_check_error(stmt);
        ple_update_exec_error(stmt, &line->loc);
        if (ple_trackle_error(stmt, exec, &line_ass->jump) != CT_SUCCESS) {
            if (stmt->session->dbg_ctl != NULL && stmt->session->dbg_ctl->type == TARGET_SESSION) {
                (void)stmt->session->dbg_ctl->dbg_calls.proc_end((void *)stmt->session, (void *)exec, NULL);
            }
            return CT_ERROR;
        }
        exec->error_tracked = CT_TRUE;
    } else {
        line_ass->jump = ple_ignore_exception(line_ass->jump, line_ass->line);
    }

    if (line_ass->jump != NULL) {
        line_ass->line = line_ass->jump;
    } else {
        line_ass->line = line_ass->line->next;
    }
    line_ass->jump = NULL;

    return CT_SUCCESS;
}

static pl_line_exec_t g_pl_line_exec_maps[] = {
    [LINE_NONE]             = ple_none_ln,
    [LINE_BEGIN]            = ple_begin_ln,
    [LINE_END]              = ple_end_ln,
    [LINE_END_IF]           = ple_endif,
    [LINE_END_LOOP]         = ple_end_loop,
    [LINE_EXCEPTION]        = ple_exception,
    [LINE_SETVAL]           = ple_setval,
    [LINE_IF]               = ple_if,
    [LINE_ELIF]             = ple_elsif,
    [LINE_ELSE]             = ple_else,
    [LINE_FOR]              = ple_for,
    [LINE_LOOP]             = ple_none_ln,
    [LINE_GOTO]             = ple_goto,
    [LINE_EXEC]             = ple_none_ln,
    [LINE_FETCH]            = ple_fetch,
    [LINE_OPEN]             = ple_open,
    [LINE_WHEN]             = ple_none_ln,
    [LINE_CLOSE]            = ple_close,
    [LINE_NULL]             = ple_none_ln,
    [LINE_SQL]              = ple_exec_sql,
    [LINE_PUTLINE]          = ple_none_ln,
    [LINE_CASE]             = ple_case,
    [LINE_WHEN_CASE]        = ple_when_case,
    [LINE_END_CASE]         = ple_endcase,
    [LINE_EXIT]             = ple_exit,
    [LINE_LABEL]            = ple_none_ln,
    [LINE_CONTINUE]         = ple_continue,
    [LINE_WHILE]            = ple_while,
    [LINE_RAISE]            = ple_raise,
    [LINE_COMMIT]           = ple_commit,
    [LINE_ROLLBACK]         = ple_rollback,
    [LINE_SAVEPOINT]        = ple_savepoint,
    [LINE_PROC]             = ple_call_proc,
    [LINE_RETURN]           = ple_return,
    [LINE_EXECUTE]          = ple_exec_immediate,
    [LINE_END_WHEN]         = ple_end_when,
    [LINE_END_EXCEPTION]    = ple_end_exception,
};

void ple_lines_prepare(ple_line_assist_t *line_ass, sql_stmt_t *stmt, pl_line_ctrl_t *start, bool8 *is_over_return)
{
    pl_executor_t *pl_exec = (pl_executor_t *)stmt->pl_exec;
    pl_line_ctrl_t *line = start;
    pl_line_ctrl_t *proc_end = pl_exec->body->end;

    pl_exec->start_line = start;
    if (proc_end != NULL) {
        ple_update_coverage_hit_count(pl_exec, (pl_line_ctrl_t *)pl_exec->body);
    } else if (start->type == LINE_BEGIN) {
        proc_end = ((pl_line_begin_t *)start)->end;
    }

    if (stmt->session->dbg_ctl != NULL && stmt->session->dbg_ctl->type == TARGET_SESSION) {
        (void)stmt->session->dbg_ctl->dbg_calls.proc_start((void *)stmt->session, (void *)pl_exec, NULL);
    }

    ple_line_assist_init(line_ass, stmt, pl_exec, line, proc_end);
    *is_over_return = CT_FALSE;
}

void ple_lines_finish(ple_line_assist_t *line_ass)
{
    sql_stmt_t *stmt = line_ass->stmt;
    pl_executor_t *exec = line_ass->exec;

    if (stmt->session->dbg_ctl != NULL && stmt->session->dbg_ctl->type == TARGET_SESSION) {
        (void)stmt->session->dbg_ctl->dbg_calls.proc_end((void *)stmt->session, (void *)exec, NULL);
    }
}

status_t ple_lines(sql_stmt_t *stmt, pl_line_ctrl_t *start, bool8 *is_over_return)
{
    ple_line_assist_t line_ass;
    status_t status = CT_SUCCESS;

    ple_lines_prepare(&line_ass, stmt, start, is_over_return);
    while (line_ass.line != NULL) {
        CT_RETURN_IFERR(ple_line_prepare(&line_ass));
        status = g_pl_line_exec_maps[line_ass.line->type](&line_ass);
        if (line_ass.line->type == LINE_RETURN) {
            *is_over_return = CT_TRUE;
            return ple_line_return(&line_ass, status);
        } else {
            CT_RETURN_IFERR(ple_line_finish(&line_ass, status));
        }
    }
    ple_lines_finish(&line_ass);

    return CT_SUCCESS;
}
