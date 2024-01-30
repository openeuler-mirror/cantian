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
 * pl_executor.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/executor/pl_executor.c
 *
 * -------------------------------------------------------------------------
 */
#include "pl_executor.h"
#include "pl_ext_proc.h"
#include "ctsql_privilege.h"
#include "base_compiler.h"
#include "pl_lines_executor.h"
#include "dtc_dls.h"
#include "ctsql_func.h"

static status_t ple_push_args_decls(sql_stmt_t *stmt, ple_call_assist_t *assist, bool32 calc_dft)
{
    uint32 total_count;
    ple_varmap_t *var_map = &assist->var_map;

    var_map->count = 0;
    total_count = assist->decls->count;

    CT_RETURN_IFERR(sql_push(stmt, total_count * sizeof(pointer_t), (void **)&var_map->items));
    CT_RETURN_IFERR(ple_push_decl_element(stmt, assist->decls, var_map, calc_dft));
    return CT_SUCCESS;
}

static inline void ple_char_convert_to_string(ple_var_t *var)
{
    if (var->value.type == CT_TYPE_CHAR) {
        var->value.type = CT_TYPE_STRING;
        var->exec_type.datatype = CT_TYPE_STRING;
    }
}

static status_t ple_verify_outparam(sql_stmt_t *stmt, ple_var_t *var, ple_var_t *param)
{
    if (var->value.type == CT_TYPE_CURSOR || param->value.type == CT_TYPE_CURSOR) {
        if (var->value.type != param->value.type) {
            CT_SET_ERROR_MISMATCH(param->value.type, var->value.type);
            return CT_ERROR;
        }

        return CT_SUCCESS;
    }

    if (CT_IS_VARLEN_TYPE(var->value.type) && CT_IS_VARLEN_TYPE(param->value.type)) {
        param->exec_type.size = var->exec_type.size;
        param->exec_type.mode = var->exec_type.mode;
    }

    if (!CT_IS_VARLEN_TYPE(var->value.type)) {
        ple_char_convert_to_string(param);
    }

    if ((var->value.is_null || param->decl->drct == PLV_DIR_OUT) && param->value.type != CT_TYPE_RECORD) {
        param->value.is_null = CT_TRUE;
    }

    if (param->exec_type.is_array != var->exec_type.is_array) {
        if (param->exec_type.is_array) {
            CT_SET_ERROR_MISMATCH(CT_TYPE_ARRAY, var->value.type);
        } else {
            CT_SET_ERROR_MISMATCH(param->value.type, CT_TYPE_ARRAY);
        }
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t ple_put_output_arg(sql_stmt_t *stmt, source_location_t loc, ple_call_assist_t *call_ass, uint32 id,
    expr_tree_t **curr_arg)
{
    expr_tree_t *arg = *curr_arg;
    ple_var_t *dst = call_ass->var_map.items[id];
    ple_var_t *src = NULL;
    expr_node_t *node = call_ass->node;
    var_udo_t *obj = sql_node_get_obj(node);
    uint32 pos = (call_ass->type == PL_FUNCTION) ? id : (id + 1);
    variant_t right;

    if (arg == NULL) {
        CT_SRC_THROW_ERROR(loc, ERR_TOO_LESS_ARGS, "procedure/function");
        return CT_ERROR;
    }

    if (arg->arg_name.len == 0) {
        *curr_arg = arg->next;
    } else {
        while (arg != NULL) {
            if (cm_compare_text_ins(&dst->decl->name, &arg->arg_name) == 0) {
                break;
            }
            arg = arg->next;
        }
    }

    if (arg == NULL) {
        CT_SRC_THROW_ERROR(loc, ERR_ARGUMENT_NOT_FOUND, T2S(&dst->decl->name));
        return CT_ERROR;
    }

    if (arg->root->type != EXPR_NODE_V_ADDR || !sql_pair_type_is_plvar(arg->root)) {
        CT_SRC_THROW_ERROR(loc, ERR_PL_ARG_FMT, pos, T2S(&obj->name), "cannot be used as an assignment target");
        return CT_ERROR;
    }
    // pair is not null after sql_pair_type_is_plvar.
    var_address_pair_t *pair = (var_address_pair_t *)cm_galist_get(arg->root->value.v_address.pairs, 0);
    src = ple_get_plvar((pl_executor_t *)stmt->pl_exec, pair->stack->decl->vid);
    if (src->decl->type == PLV_PARAM && stmt->param_info.params[src->decl->param.param_id].direction == PLV_DIR_IN) {
        CT_SRC_THROW_ERROR(loc, ERR_PL_ARG_FMT, pos, T2S(&obj->name),
            "is out parameter and cannot be assigned to in parameter");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(ple_verify_outparam(stmt, src, dst));
    if (dst->decl->drct == PLV_DIR_INOUT) {
        if (sql_exec_expr(stmt, arg, &right) != CT_SUCCESS) {
            pl_check_and_set_loc(arg->loc);
            return CT_ERROR;
        }

        CT_RETURN_IFERR(ple_move_value(stmt, &right, dst));
    }

    return CT_SUCCESS;
}

static status_t ple_check_param_is_out(sql_stmt_t *stmt, expr_tree_t *arg)
{
    if (!(stmt->plsql_mode == PLSQL_NONE || stmt->plsql_mode == PLSQL_CURSOR || stmt->plsql_mode == PLSQL_DYNBLK)) {
        return CT_SUCCESS;
    }
    status_t status = CT_SUCCESS;
    if (arg->root->type == EXPR_NODE_PARAM) {
        sql_param_t *param = &stmt->param_info.params[arg->root->value.v_int];
        if (param->direction == (uint8)PLV_DIR_OUT) {
            status = CT_ERROR;
        }
    }

    if (arg->root->type == EXPR_NODE_V_ADDR) {
        var_address_pair_t *pair = sql_get_last_addr_pair(arg->root);
        if (pair == NULL || pair->type != UDT_STACK_ADDR) {
            return status;
        }
        if (pair->stack->decl->type != PLV_PARAM) {
            return CT_SUCCESS;
        }

        sql_param_t *param = &stmt->param_info.params[pair->stack->decl->param.param_id];
        if (param->direction == (uint8)PLV_DIR_OUT) {
            status = CT_ERROR;
        }
    }

    if (status == CT_ERROR) {
        CT_SRC_THROW_ERROR(arg->loc, ERR_VALUE_ERROR,
            "The param direction is mismatch, direction is OUTPUT, expect INPUT");
    }
    return status;
}

static status_t ple_set_input_value(sql_stmt_t *stmt, expr_tree_t *arg, ple_var_t *v)
{
    variant_t right;
    CT_RETURN_IFERR(ple_check_param_is_out(stmt, arg));

    if (sql_exec_expr(stmt, arg, &right) != CT_SUCCESS) {
        pl_check_and_set_loc(arg->loc);
        return CT_ERROR;
    }
    SQL_CHECK_COLUMN_VAR(&right, &v->value);

    if (CT_IS_VARLEN_TYPE(right.type) && CT_IS_VARLEN_TYPE(v->exec_type.datatype) &&
        (right.v_text.len <= v->exec_type.size)) {
        v->exec_type.size = right.v_text.len;
    }

    if (ple_move_value(stmt, &right, v) != CT_SUCCESS) {
        pl_check_and_set_loc(arg->loc);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t ple_put_input_arg(sql_stmt_t *stmt, source_location_t loc, ple_call_assist_t *call_ass, uint32 i,
    expr_tree_t **curr_arg)
{
    expr_tree_t *arg = *curr_arg;
    plv_decl_t *decl = (plv_decl_t *)cm_galist_get(call_ass->decls, i);

    if (arg != NULL && arg->arg_name.len == 0) {
        CT_RETURN_IFERR(ple_set_input_value(stmt, arg, call_ass->var_map.items[i]));
        *curr_arg = arg->next;
        return CT_SUCCESS;
    }

    while (arg != NULL) {
        if (cm_compare_text(&decl->name, &arg->arg_name) == 0) {
            CT_RETURN_IFERR(ple_set_input_value(stmt, arg, call_ass->var_map.items[i]));
            return CT_SUCCESS;
        }

        arg = arg->next;
    }

    if (decl->default_expr == NULL) {
        CT_SRC_THROW_ERROR(loc, ERR_TOO_LESS_ARGS, "procedure/function");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(ple_set_input_value(stmt, decl->default_expr, call_ass->var_map.items[i]));
    return CT_SUCCESS;
}

static status_t ple_put_args(ple_call_assist_t *call_ass)
{
    expr_tree_t *arg = call_ass->args;
    uint32 i, id;
    plv_decl_t *decl = NULL;
    plv_direction_t drct;

    call_ass->is_pending = CT_FALSE;
    if (call_ass->arg_count == 0 && arg != NULL) {
        CT_SRC_THROW_ERROR(call_ass->node->loc, ERR_TOO_LESS_ARGS, "procedure/function");
        return CT_ERROR;
    }

    if (call_ass->type == PL_PROCEDURE) {
        id = 0;
    } else {
        id = 1;
        call_ass->var_map.items[0]->value.is_null = CT_TRUE;
        ple_char_convert_to_string(call_ass->var_map.items[0]);
    }

    for (i = id; i < call_ass->arg_count; i++) {
        decl = call_ass->var_map.items[i]->decl;
        drct = decl->drct;
        if (drct != PLV_DIR_IN) {
            CT_RETURN_IFERR(ple_put_output_arg(call_ass->stmt, call_ass->node->loc, call_ass, i, &arg));
        } else {
            CT_RETURN_IFERR(ple_put_input_arg(call_ass->stmt, call_ass->node->loc, call_ass, i, &arg));
            if (call_ass->var_map.items[i]->value.type == CT_TYPE_COLUMN) {
                call_ass->is_pending = CT_TRUE;
                return CT_SUCCESS;
            }
        }
    }

    return CT_SUCCESS;
}

static status_t ple_push_and_put_args(ple_call_assist_t *call_ass)
{
    if (call_ass->begin_ln->decls->count == 0 && call_ass->params == 0) {
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(ple_push_args_decls(call_ass->sub_stmt, call_ass, CT_FALSE));
    CT_RETURN_IFERR(ple_put_args(call_ass));

    if (call_ass->is_pending) {
        return CT_SUCCESS;
    }

    return CT_SUCCESS;
}

static status_t ple_push_call_val(ple_call_assist_t *call_ass)
{
    uint32 i;
    ple_var_t *var = NULL;
    ple_varmap_t *array = &call_ass->var_map;
    galist_t *decls = call_ass->begin_ln->decls;

    for (i = call_ass->arg_count; i < decls->count; i++) {
        var = array->items[i];
        if (var == NULL) {
            continue;
        }

        if (var->decl->type == PLV_RECORD && PLE_DEFAULT_EXPR(var) == NULL) {
            CT_RETURN_IFERR(ple_calc_record_dft(call_ass->sub_stmt, var->decl->record, &var->value));
            continue;
        }

        if (var->decl->type == PLV_OBJECT && PLE_DEFAULT_EXPR(var) == NULL) {
            CT_RETURN_IFERR(ple_calc_object_dft(call_ass->sub_stmt, var->decl->object, &var->value));
            continue;
        }

        if (PLE_DEFAULT_EXPR(var) != NULL && (var->decl->type == PLV_VAR || PLV_IS_COMPLEX_TYPE(var->decl->type))) {
            CT_RETURN_IFERR(ple_calc_dft(call_ass->sub_stmt, var));
            continue;
        }

        if (var->decl->type == PLV_PARAM) {
            CT_RETURN_IFERR(ple_calc_param_dft(call_ass->sub_stmt, var));
            continue;
        }
    }

    return CT_SUCCESS;
}

static status_t ple_check_and_alloc_exec(sql_stmt_t *stmt, pl_executor_t **exec)
{
    if (stmt->pl_exec != NULL) {
        *exec = (pl_executor_t *)stmt->pl_exec;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_push(stmt, sizeof(pl_executor_t), (void **)exec));
    if (ple_init_executor(*exec, stmt) != CT_SUCCESS) {
        CTSQL_POP(stmt);
        return CT_ERROR;
    }

    stmt->pl_exec = *exec;

    (*exec)->sql_loc.line = 1;
    (*exec)->sql_loc.column = 1;
    return CT_SUCCESS;
}

static status_t pl_add_ref_dc(sql_stmt_t *stmt, pl_entry_t *entry)
{
    if (stmt->pl_ref_entry == NULL) {
        CT_RETURN_IFERR(sql_init_pl_ref_dc(stmt));
    }

    if (cm_galist_insert(stmt->pl_ref_entry, entry) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static pl_dc_t *ple_get_regist_dc(sql_stmt_t *stmt, expr_node_t *node)
{
    return (pl_dc_t *)node->value.v_pl_dc;
}

static bool32 ple_check_ref_entry(sql_stmt_t *stmt, pl_entry_t *entry)
{
    pl_entry_t *curr_entry = NULL;

    if (stmt->pl_ref_entry == NULL) {
        return CT_FALSE;
    }

    for (uint32 i = 0; i < stmt->pl_ref_entry->count; i++) {
        curr_entry = (pl_entry_t *)cm_galist_get(stmt->pl_ref_entry, i);
        if (entry->desc.oid == curr_entry->desc.oid) {
            return CT_TRUE;
        }
    }
    return CT_FALSE;
}

static status_t ple_open_dc(sql_stmt_t *stmt, expr_node_t *node, pl_dc_t *dc)
{
    knl_session_t *sess = KNL_SESSION(stmt);
    var_udo_t *obj = (var_udo_t *)node->value.v_udo;
    pl_dc_assist_t assist = { 0 };
    bool32 found = CT_FALSE;
    uint32 expect_type;

    CM_ASSERT(node->value.type_for_pl == VAR_UDO);
    if (node->is_pkg) {
        expect_type = PL_PACKAGE_SPEC | PL_SYNONYM;
        pl_dc_open_prepare(&assist, stmt, &obj->user, &obj->pack, expect_type);
        if (pl_dc_open(&assist, dc, &found) != CT_SUCCESS || !found) {
            CT_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "package", T2S(&obj->user), T2S_EX(&obj->pack));
            return CT_ERROR;
        }
        if (sql_check_ple_dc_priv(stmt, dc) != CT_SUCCESS) {
            pl_dc_close(dc);
            return CT_ERROR;
        }
        if (pl_dc_find_subobject(sess, dc, &obj->name) != CT_SUCCESS || dc->sub_type != pl_get_node_type(node)) {
            pl_dc_close(dc);
            CT_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, pl_get_node_type_string(node->type),
                CC_T2S(&obj->user, &obj->pack, '.'), T2S_EX(&obj->name));
            return CT_ERROR;
        }
    } else {
        expect_type = pl_get_node_type(node) | PL_SYNONYM;
        pl_dc_open_prepare(&assist, stmt, &obj->user, &obj->name, expect_type);
        if (pl_dc_open(&assist, dc, &found) != CT_SUCCESS || !found) {
            CT_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, pl_get_node_type_string(node->type), T2S(&obj->user),
                T2S_EX(&obj->name));
            return CT_ERROR;
        }
        if (sql_check_ple_dc_priv(stmt, dc) != CT_SUCCESS) {
            pl_dc_close(dc);
            return CT_ERROR;
        }
        uint8 lang_type = dc->entity->function->desc.lang_type;
        if (lang_type != node->lang_type) {
            pl_dc_close(dc);
            node->lang_type = lang_type;
            CT_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, pl_get_node_type_string(node->type), T2S(&obj->user),
                T2S_EX(&obj->name));
            return CT_ERROR;
        }
    }

    dc->obj = obj;
    if (ple_check_ref_entry(stmt, dc->entry)) {
        return CT_SUCCESS;
    }
    if (pl_lock_dc_shared(sess, dc) != CT_SUCCESS) {
        pl_dc_close(dc);
        return CT_ERROR;
    }

    if (pl_add_ref_dc(stmt, dc->entry) != CT_SUCCESS) {
        pl_unlock_shared(sess, dc->entry);
        pl_dc_close(dc);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t ple_init_paramset(sql_stmt_t *stmt)
{
    stmt->param_info.param_offset = 0;
    stmt->param_info.param_strsize = 0;
    if (!stmt->is_sub_stmt) {
        // only top stmt can receive paramset from client
        CT_RETURN_IFERR(sql_prepare_params(stmt));
        if (stmt->session->pipe == NULL) {
            stmt->param_info.paramset_size = 1;
            stmt->param_info.paramset_offset = 0;
        } else {
            stmt->param_info.paramset_size = (stmt->param_info.paramset_size == 0) ? 1 : stmt->param_info.paramset_size;
        }
    } else {
        stmt->param_info.paramset_size = 1;
        stmt->param_info.paramset_offset = 0;
    }
    return CT_SUCCESS;
}

status_t ple_exec_anonymous_block(sql_stmt_t *stmt)
{
    pl_executor_t *exec = NULL;
    void *save_exec = NULL;
    pl_entity_t *pl_context = (pl_entity_t *)stmt->pl_context;
    status_t status = CT_SUCCESS;
    knl_savepoint_t savepoint;
    uint32 exec_stack_base;
    bool8 is_curs_prepare = CT_FALSE;
    bool8 is_over_return = CT_FALSE;
    stmt->session->sql_audit.audit_type = SQL_AUDIT_PL;
    knl_savepoint(KNL_SESSION(stmt), &savepoint);
    save_exec = stmt->pl_exec;
    stmt->param_info.param_offset = 0;
    stmt->param_info.param_strsize = 0;

    CT_RETURN_IFERR(ple_init_paramset(stmt));
    CT_RETURN_IFERR(pl_init_sequence(stmt));
    PLE_SAVE_STMT(stmt);

    for (uint32 i = stmt->param_info.paramset_offset; i < stmt->param_info.paramset_size; i++) {
        if (sql_read_params(stmt) != CT_SUCCESS) {
            PLE_RESTORE_STMT(stmt);
            return CT_ERROR;
        }

        if (ple_check_and_alloc_exec(stmt, &exec) != CT_SUCCESS) {
            PLE_RESTORE_STMT(stmt);
            return CT_ERROR;
        }

        if (ple_prepare_pl_cursors(stmt, &is_curs_prepare) != CT_SUCCESS) {
            PLE_RESTORE_STMT(stmt);
            return CT_ERROR;
        }

        exec_stack_base = exec->block_stack.depth;
        if (!stmt->is_sub_stmt) {
            stmt->session->rrs_sn++;
        }

        if (pl_context->is_auton_trans) {
            if (ple_begin_auton_rm(stmt->session) != CT_SUCCESS) {
                PLE_RESTORE_STMT(stmt);
                return CT_ERROR;
            }
        }

        exec->entity = pl_context;
        exec->body = pl_context->anonymous->body;
        exec->obj = NULL;
        status = ple_lines(stmt, (pl_line_ctrl_t *)pl_context->anonymous->body, &is_over_return);

        if (status != CT_SUCCESS) {
            if (!stmt->is_sub_stmt) {
                ple_send_error(stmt);
            }
        }
        while (exec->block_stack.depth > exec_stack_base) {
            ple_pop_block(stmt, exec);
        }

        stmt->pl_exec = save_exec;
        PLE_RESTORE_STMT(stmt);

        // if this anonymous block is autonomous transaction, it also need to check whether has uncommitted
        // transactions or not, it should throw error.
        if (pl_context->is_auton_trans) {
            status = (ple_end_auton_rm(stmt->session) != CT_SUCCESS) ? CT_ERROR : status;
        }

        if (is_curs_prepare) {
            stmt->session->pl_cursors = NULL;
        }

        if (status != CT_SUCCESS) {
            do_rollback(stmt->session, &savepoint);
        } else {
            status_t client_status = CT_SUCCESS;

            if (!stmt->is_sub_stmt) {
                if (my_sender(stmt) != NULL) {
                    client_status = sql_send_outparams(stmt);
                }

                if (stmt->auto_commit) {
                    (void)do_commit(stmt->session);
                }
            }

            if (client_status != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }
    return status;
}

bool32 sql_send_get_node_function(sql_stmt_t *stmt, function_t **func)
{
    pl_entity_t *entity = stmt->pl_context;
    pl_line_ctrl_t *line = (pl_line_ctrl_t *)entity->anonymous->body;
    expr_node_t *node = NULL;
    pl_dc_t *ref_dc = NULL;
    plv_decl_t *plv_decl = NULL;

    *func = NULL;
    if (!stmt->is_reform_call) {
        return CT_FALSE;
    }

    if (line == NULL || line->type != LINE_BEGIN || line->next->type != LINE_PROC) {
        return CT_FALSE;
    }

    node = ((pl_line_normal_t *)line->next)->proc;
    if ((node->type == EXPR_NODE_FUNC) || (node->type == EXPR_NODE_PROC) || (node->type == EXPR_NODE_V_METHOD)) {
        return CT_FALSE;
    }

    CM_ASSERT(node->value.type_for_pl == VAR_PL_DC);
    ref_dc = ple_get_regist_dc(stmt, node);
    CM_ASSERT(ref_dc != NULL);

    if (node->is_pkg) {
        plv_decl = (plv_decl_t *)cm_galist_get(ref_dc->entity->package_spec->defs, ref_dc->sub_id);
        *func = plv_decl->func;
    } else {
        *func = ref_dc->entity->function;
    }

    return CT_TRUE;
}

static status_t ple_get_outparam_dest(sql_stmt_t *stmt, ple_call_assist_t *assist, uint32 id, expr_tree_t **curr_arg,
    ple_var_t **var)
{
    expr_tree_t *arg = assist->args;
    plv_decl_t *decl = assist->var_map.items[id]->decl;
    var_address_pair_t *pair = NULL;

    if (*curr_arg != NULL && (*curr_arg)->arg_name.len == 0) {
        if (!sql_pair_type_is_plvar((*curr_arg)->root)) {
            CT_SRC_THROW_ERROR((*curr_arg)->loc, ERR_PL_SYNTAX_ERROR_FMT, "unexpected pl-variant occurs");
            return CT_ERROR;
        }
        pair = (var_address_pair_t *)cm_galist_get((*curr_arg)->root->value.v_address.pairs, 0);
        *var = ple_get_plvar((pl_executor_t *)stmt->pl_exec, pair->stack->decl->vid);
        return CT_SUCCESS;
    }

    while (arg) {
        if (cm_compare_text_ins(&decl->name, &arg->arg_name) == 0) {
            if (!sql_pair_type_is_plvar(arg->root)) {
                CT_SRC_THROW_ERROR(arg->loc, ERR_PL_SYNTAX_ERROR_FMT, "unexpected pl-variant occurs");
                return CT_ERROR;
            }
            pair = (var_address_pair_t *)cm_galist_get(arg->root->value.v_address.pairs, 0);
            *var = ple_get_plvar((pl_executor_t *)stmt->pl_exec, pair->stack->decl->vid);
            *curr_arg = arg;
            return CT_SUCCESS;
        }
        arg = arg->next;
    }
    CT_SRC_THROW_ERROR(assist->node->loc, ERR_PLE_OUT_PARAM_NOT_FOUND);
    return CT_ERROR;
}

#define RESET_CURSOR_STMT(stmt, var)                                                 \
    do {                                                                             \
        sql_stmt_t *sub_stmt = ple_ref_cursor_get(stmt, (var)->v_cursor.ref_cursor); \
        if (sub_stmt != NULL) {                                                      \
            sub_stmt->is_sub_stmt = CT_FALSE;                                        \
            sub_stmt->parent_stmt = NULL;                                            \
            sub_stmt->pl_ref_entry = NULL;                                           \
        }                                                                            \
    } while (0)

static status_t ple_copy_outparams(ple_call_assist_t *assist)
{
    if (assist->type == PL_FUNCTION) {
        if (!assist->is_over_return) {
            CT_SRC_THROW_ERROR(assist->node->loc, ERR_RETURN_WITHOUT_VALUE);
            return CT_ERROR;
        }

        *assist->result = assist->var_map.items[0]->value;

        if (assist->result->type == CT_TYPE_RECORD) {
            assist->result->v_record.is_constructed = CT_TRUE;
        }
        if (assist->result->type == CT_TYPE_OBJECT) {
            assist->result->v_object.is_constructed = CT_TRUE;
        }

        if (assist->result->type == CT_TYPE_COLLECTION) {
            assist->result->v_collection.is_constructed = CT_TRUE;
        }
        if (assist->result->type == CT_TYPE_CURSOR) {
            RESET_CURSOR_STMT(assist->stmt, assist->result);
        }
    }
    return CT_SUCCESS;
}

static status_t ple_set_outparams(ple_call_assist_t *call_ass)
{
    expr_tree_t *arg = call_ass->args;
    uint32 i, id;
    plv_direction_t drct;
    ple_var_t *dst = NULL;
    ple_var_t *src = NULL;

    id = (call_ass->type == PL_PROCEDURE) ? 0 : 1;

    for (i = id; i < call_ass->arg_count; i++) {
        src = call_ass->var_map.items[i];

        drct = src->decl->drct;
        if (drct == PLV_DIR_IN) {
            if (arg != NULL) {
                if (arg->arg_name.len == 0 || cm_compare_text_ins(&src->decl->name, &arg->arg_name) == 0) {
                    arg = arg->next;
                }
            }
            continue;
        }

        /* the collection or record or cursor variable does not release memory when the stack is pop,
           and the out direction copy is a shallow copy. */
        if (src->decl->type == PLV_RECORD) {
            src->value.v_record.is_constructed = CT_TRUE;
        }

        if (src->decl->type == PLV_OBJECT) {
            src->value.v_object.is_constructed = CT_TRUE;
        }

        if (src->decl->type == PLV_COLLECTION) {
            src->value.v_collection.is_constructed = CT_TRUE;
        }

        CT_RETURN_IFERR(ple_get_outparam_dest(call_ass->stmt, call_ass, i, &arg, &dst));

        CT_RETURN_IFERR(ple_move_value(call_ass->stmt, &src->value, dst));
        if (dst->value.type == CT_TYPE_CURSOR) {
            // dst cursor slot didn't dec ref_count, need dec here.
            ple_cursor_dec_refcount(call_ass->stmt, &src->value, CT_FALSE);
            RESET_CURSOR_STMT(call_ass->stmt, &src->value);
        }
        arg = arg->next;
    }
    // complex var should shallow copy
    return ple_copy_outparams(call_ass);
}

static status_t ple_get_impcur_attr(sql_stmt_t *stmt, plv_attr_t *pl_attr, variant_t *res)
{
    pl_executor_t *exec = stmt->pl_exec;
    switch (pl_attr->type) {
        case PLV_ATTR_ISOPEN:
            // implicit cursor % ISOPEN always return FALSE;
            res->type = CT_TYPE_BOOLEAN;
            res->v_bool = CT_FALSE;
            res->is_null = CT_FALSE;
            break;
        case PLV_ATTR_FOUND:
            res->type = CT_TYPE_BOOLEAN;
            res->v_bool = (exec->recent_rows > 0);
            res->is_null = !exec->sql_executed;
            break;
        case PLV_ATTR_NOTFOUND:
            res->type = CT_TYPE_BOOLEAN;
            res->v_bool = (exec->recent_rows == 0);
            res->is_null = !exec->sql_executed;
            break;
        case PLV_ATTR_ROWCOUNT:
            res->type = CT_TYPE_INTEGER;
            res->v_int = (int32)exec->recent_rows;
            res->is_null = !exec->sql_executed;
            break;
        default:
            CT_THROW_ERROR(ERR_PL_INVALID_ATTR_FMT);
            return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t ple_get_expcur_attr(sql_stmt_t *stmt, plv_attr_t *pl_attr, variant_t *res)
{
    ple_var_t *var = ple_get_plvar(stmt->pl_exec, pl_attr->id);
    sql_stmt_t *sub_stmt = ple_ref_cursor_get(stmt, PLE_CURSOR_SLOT_GET(var));
    if (sub_stmt == NULL) {
        switch (pl_attr->type) {
            case PLV_ATTR_ISOPEN:
                res->type = CT_TYPE_BOOLEAN;
                res->v_bool = CT_FALSE;
                res->is_null = CT_FALSE;
                break;
            case PLV_ATTR_FOUND:
            case PLV_ATTR_NOTFOUND:
            case PLV_ATTR_ROWCOUNT:
                CT_THROW_ERROR(ERR_INVALID_CURSOR);
                return CT_ERROR;
            default:
                CT_THROW_ERROR(ERR_PL_INVALID_ATTR_FMT);
                return CT_ERROR;
        }
        return CT_SUCCESS;
    }

    switch (pl_attr->type) {
        case PLV_ATTR_ISOPEN:
            res->type = CT_TYPE_BOOLEAN;
            res->v_bool = CT_TRUE;
            res->is_null = CT_FALSE;
            break;
        case PLV_ATTR_FOUND:
            res->type = CT_TYPE_BOOLEAN;
            res->v_bool = !sub_stmt->eof;
            res->is_null = !sub_stmt->cursor_info.has_fetched;
            break;
        case PLV_ATTR_NOTFOUND:
            res->type = CT_TYPE_BOOLEAN;
            res->v_bool = sub_stmt->eof;
            res->is_null = !sub_stmt->cursor_info.has_fetched;
            break;
        case PLV_ATTR_ROWCOUNT:
            res->type = CT_TYPE_INTEGER;
            res->v_int = (int32)sub_stmt->total_rows;
            res->is_null = !sub_stmt->cursor_info.has_fetched;
            break;
        default:
            CT_THROW_ERROR(ERR_PL_INVALID_ATTR_FMT);
            return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t ple_get_pl_attr(sql_stmt_t *stmt, expr_node_t *node, variant_t *res)
{
    plv_attr_t *attr = &node->value.v_plattr;

    if (attr->is_implicit) {
        return ple_get_impcur_attr(stmt, attr, res);
    } else {
        return ple_get_expcur_attr(stmt, attr, res);
    }
}

static inline status_t ple_switch_schema(ple_call_assist_t *call_ass)
{
    return sql_switch_schema_by_uid(call_ass->stmt, call_ass->dc->uid, &call_ass->saved_schema);
}

static status_t ple_fork_executor(ple_call_assist_t *call_ass)
{
    CT_RETURN_IFERR(ple_fork_executor_core(call_ass->stmt, call_ass->sub_stmt));
    call_ass->is_top_exec = (call_ass->stmt->pl_exec == NULL) ? CT_TRUE : CT_FALSE;
    return CT_SUCCESS;
}

static status_t ple_fork_call_stmt(ple_call_assist_t *call_ass)
{
    CT_RETURN_IFERR(sql_stack_safe(call_ass->stmt));
    CT_RETURN_IFERR(ple_fork_stmt(call_ass->stmt, &call_ass->sub_stmt));
    CT_RETURN_IFERR(ple_fork_executor(call_ass));
    call_ass->sub_stmt->context = NULL;
    call_ass->sub_stmt->pl_context = call_ass->sub_pl_context;

    CT_RETURN_IFERR(pl_init_sequence(call_ass->sub_stmt));
    call_ass->sub_stmt->session->sender = &g_instance->sql.pl_sender;
    call_ass->sub_stmt->cursor_info.type = PL_FORK_CURSOR;
    pl_executor_t *sub_exec = (pl_executor_t *)call_ass->sub_stmt->pl_exec;
    sub_exec->entity = call_ass->sub_pl_context;
    sub_exec->body = call_ass->begin_ln;
    sub_exec->obj = call_ass->dc->obj;
    return CT_SUCCESS;
}

static status_t ple_open_body_dc(sql_stmt_t *stmt, pl_dc_t *dc, pl_dc_t *body_dc)
{
    bool32 exist = CT_FALSE;
    text_t user;
    text_t pack;
    var_udo_t *obj = dc->obj;
    pl_dc_assist_t dc_ass = { 0 };

    if (dc->syn_entry != NULL) {
        pl_entry_t *syn_entry = dc->syn_entry;
        cm_str2text(syn_entry->desc.link_user, &user);
        cm_str2text(syn_entry->desc.link_name, &pack);
    } else {
        user = obj->user;
        pack = obj->pack;
    }

    pl_dc_open_prepare(&dc_ass, stmt, &user, &pack, PL_PACKAGE_BODY);
    if (pl_dc_open(&dc_ass, body_dc, &exist) != CT_SUCCESS) {
        return CT_ERROR;
    }
    if (!exist) {
        CT_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "package body", T2S(&obj->user), T2S_EX(&obj->pack));
        return CT_ERROR;
    }
    if (sql_check_ple_dc_priv(stmt, body_dc) != CT_SUCCESS) {
        pl_dc_close(body_dc);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t ple_convert_assist_info(ple_call_assist_t *call_ass, bool32 is_pkg, pl_dc_t *body_dc)
{
    sql_stmt_t *stmt = call_ass->stmt;
    pl_dc_t *func_dc = call_ass->dc;
    pl_entity_t *entity = func_dc->entity;
    function_t *func = NULL;
    plv_decl_t *decl = NULL;
    uint32 type;
    uint32 sub_id;

    if (is_pkg) {
        CT_RETURN_IFERR(ple_open_body_dc(stmt, func_dc, body_dc));
        body_dc->obj = func_dc->obj;
        call_ass->body_dc = body_dc;
        call_ass->is_pkg = CT_TRUE;
        call_ass->sub_pl_context = body_dc->entity;
        package_body_t *package_body = body_dc->entity->package_body;
        sub_id = package_body->meth_map[func_dc->sub_id];
        CM_ASSERT(sub_id < package_body->defs->count);
        decl = (plv_decl_t *)cm_galist_get(package_body->defs, sub_id);
        func = decl->func;
        type = func_dc->sub_type;
    } else {
        func = entity->function;
        type = func_dc->type;
        call_ass->sub_pl_context = entity;
    }

    if (type == PL_PROCEDURE || type == PL_FUNCTION) {
        call_ass->arg_count = func->desc.arg_count;
        call_ass->params = func->desc.params;
    } else {
        call_ass->arg_count = 0;
        call_ass->params = NULL;
    }
    call_ass->begin_ln = (pl_line_begin_t *)func->body;
    call_ass->decls = call_ass->begin_ln->decls;
    call_ass->args = call_ass->node->argument;
    call_ass->type = type;
    call_ass->var_map.count = 0;
    return CT_SUCCESS;
}

status_t pl_check_and_lock_dc(sql_stmt_t *stmt, pl_dc_t **exec_dc, pl_dc_t *proc_dc, bool8 *is_exec_open)
{
    pl_dc_t *ref_dc = *exec_dc;
    bool32 found = CT_FALSE;
    var_udo_t *v_udo = ref_dc->obj;
    knl_session_t *knl_sess = KNL_SESSION(stmt);
    *is_exec_open = CT_FALSE;
    pl_dc_assist_t assist = { 0 };

    for (;;) {
        if (ple_check_ref_entry(stmt, ref_dc->entry)) {
            *exec_dc = ref_dc;
            return CT_SUCCESS;
        }

        if (pl_lock_dc_shared(knl_sess, ref_dc) == CT_SUCCESS) {
            if (pl_add_ref_dc(stmt, ref_dc->entry) != CT_SUCCESS) {
                pl_unlock_shared(knl_sess, ref_dc->entry);
                if (*is_exec_open) {
                    pl_dc_close(ref_dc);
                }
                return CT_ERROR;
            }
            *exec_dc = ref_dc;
            return CT_SUCCESS;
        }

        if (cm_get_error_code() != ERR_DC_INVALIDATED) {
            return CT_ERROR;
        }
        cm_revert_pl_last_error();

        if (*is_exec_open) {
            pl_dc_close(ref_dc);
        }

        // to prevent close dc outside;
        *is_exec_open = CT_FALSE;
        uint32 expect_type = ref_dc->type | PL_SYNONYM;
        if (CM_IS_EMPTY(&v_udo->pack)) {
            pl_dc_open_prepare(&assist, stmt, &v_udo->user, &v_udo->name, expect_type);
        } else {
            pl_dc_open_prepare(&assist, stmt, &v_udo->user, &v_udo->pack, expect_type);
        }
        if (pl_dc_open(&assist, proc_dc, &found) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!found) {
            CT_THROW_ERROR(ERR_OBJECT_NOT_EXISTS, T2S(&v_udo->user), T2S_EX(&v_udo->name));
            return CT_ERROR;
        }
        if (sql_check_ple_dc_priv(stmt, proc_dc) != CT_SUCCESS) {
            pl_dc_close(proc_dc);
            return CT_ERROR;
        }
        if (proc_dc->type == PL_PACKAGE_SPEC) {
            if (pl_dc_find_subobject(KNL_SESSION(stmt), proc_dc, &v_udo->name) != CT_SUCCESS) {
                pl_dc_close(proc_dc);
                return CT_ERROR;
            }
        }

        proc_dc->obj = v_udo;
        ref_dc = proc_dc;
        *is_exec_open = CT_TRUE;
    }

    return CT_SUCCESS;
}

static status_t pl_get_and_lock_dc(ple_call_assist_t *assist, expr_node_t *node, pl_dc_t *recmpl_dc)
{
    if (node->value.type_for_pl == VAR_UDO) {
        CT_RETURN_IFERR(ple_open_dc(assist->stmt, node, recmpl_dc));
        assist->dc = recmpl_dc;
        assist->is_exec_open = CT_TRUE;
        return CT_SUCCESS;
    } else {
        assist->dc = ple_get_regist_dc(assist->stmt, node);
        CM_ASSERT(assist->dc != NULL);
        return pl_check_and_lock_dc(assist->stmt, &assist->dc, recmpl_dc, &assist->is_exec_open);
    }
}

static void ple_close_exec_dc(ple_call_assist_t *call_ass)
{
    if (call_ass->is_exec_open) {
        pl_dc_close(call_ass->dc);
    }

    if (call_ass->is_pkg) {
        pl_dc_close(call_ass->body_dc);
    }
}

#define PLE_IS_AUNTON_TRANS(assist) ((assist)->dc->entity->is_auton_trans)

static status_t ple_prepare_call(ple_call_assist_t *assist, expr_node_t *node, pl_dc_t *recompl_dc, pl_dc_t *body_dc)
{
    uint32 type = (assist->node->type == EXPR_NODE_USER_FUNC) ? PL_FUNCTION : PL_PROCEDURE;

    CT_RETURN_IFERR(sql_stack_safe(assist->stmt));
    CT_RETURN_IFERR(ple_prepare_pl_cursors(assist->stmt, &assist->is_curs_prepare));
    CT_RETURN_IFERR(pl_get_and_lock_dc(assist, node, recompl_dc));

    if (ple_convert_assist_info(assist, node->is_pkg, body_dc) != CT_SUCCESS) {
        ple_close_exec_dc(assist);
        return CT_ERROR;
    }
    assist->type = type;
    assist->status = CT_ERROR;
    var_udo_t *obj = &assist->dc->entity->def;
    do {
        CT_BREAK_IF_ERROR(sql_check_inherit_priv(assist->stmt, &obj->user));
        CT_BREAK_IF_ERROR(ple_switch_schema(assist));
        CT_BREAK_IF_ERROR(ple_fork_call_stmt(assist));

        if (COVER_ENABLE == CT_TRUE) {
            CT_BREAK_IF_ERROR(ple_push_coverage_hit_count(assist->sub_stmt));
        }
        assist->status = CT_SUCCESS;
    } while (0);

    // if assist->status is CT_ERROR,it needn't go this branch. if the below operations
    // is successful it can be change session.if begin autonomous session is not successful,
    // we should end autonomous session.Because of two function both have status return,
    // we should inherit the previous status, if not the status value may be overwrite.so
    if (assist->status == CT_SUCCESS && PLE_IS_AUNTON_TRANS(assist)) {
        assist->status = ple_begin_auton_rm(assist->sub_stmt->session);
    }

    if (assist->status != CT_SUCCESS) {
        ple_close_exec_dc(assist);
        return CT_ERROR;
    }
    ple_save_stack_anchor(assist->stmt, &assist->anchor);
    return CT_SUCCESS;
}

static void ple_inherit_substmt_lob_vmlist(sql_stmt_t *stmt, sql_stmt_t *sub_stmt)
{
    id_list_t *list = sql_get_exec_lob_list(stmt);
    id_list_t *sub_list = sql_get_exec_lob_list(sub_stmt);

    vm_append_list(stmt->mtrl.pool, list, sub_list);
    vm_reset_list(sub_list);

    if (sub_stmt->session->call_version < CS_VERSION_10) {
        sub_stmt->lob_info.inuse_count = 0;
    }
}

static void ple_end_call(ple_call_assist_t *call_ass)
{
    pl_executor_t *sub_exec = NULL;
    status_t sub_status;

    if (PLE_IS_AUNTON_TRANS(call_ass)) {
        sub_status = ple_end_auton_rm(call_ass->sub_stmt->session);
        call_ass->status = (sub_status == CT_SUCCESS) ? call_ass->status : CT_ERROR;
        call_ass->is_sub_error = (sub_status == CT_ERROR) ? CT_TRUE : call_ass->is_sub_error;
    }

    ple_close_exec_dc(call_ass);
    if (call_ass->is_curs_prepare) {
        call_ass->stmt->session->pl_cursors = NULL;
    }

    if (call_ass->sub_stmt->pl_exec != NULL) {
        sub_exec = (pl_executor_t *)call_ass->sub_stmt->pl_exec;
        while ((sub_exec->block_stack.depth > sub_exec->stack_base) ||
            (call_ass->is_top_exec && sub_exec->block_stack.depth)) {
            ple_pop_block(call_ass->sub_stmt, sub_exec);
        }

        ple_inherit_substmt_lob_vmlist(call_ass->stmt, call_ass->sub_stmt);
        sql_release_lob_info(call_ass->sub_stmt);
        sql_release_resource(call_ass->sub_stmt, CT_TRUE);
    }

    sql_restore_schema(call_ass->stmt, &call_ass->saved_schema);
    if (call_ass->status != CT_SUCCESS) {
        if (call_ass->is_sub_error == CT_TRUE) {
            pl_executor_t *f_exec = (pl_executor_t *)call_ass->stmt->pl_exec;
            pl_check_and_set_loc(call_ass->begin_ln->ctrl.loc);
            if (f_exec == NULL || f_exec->err_buf_pos == 0) {
                ple_check_exec_error(call_ass->sub_stmt, &call_ass->begin_ln->ctrl.loc);
                ple_inherit_substmt_error(call_ass->stmt, call_ass->sub_stmt);
            }
        }
        return;
    }

    if (call_ass->type == PL_PROCEDURE && call_ass->is_pending) {
        CT_THROW_ERROR(ERR_PLSQL_VALUE_ERROR_FMT, "cannot input pending column for argument in procedure");
        call_ass->status = CT_ERROR;
    }
    // solve cursor slot leak in 'cur1 := func return sys_refcursor'
    if (call_ass->status == CT_SUCCESS && call_ass->type == PL_FUNCTION && call_ass->result->type == CT_TYPE_CURSOR) {
        ple_cursor_dec_refcount(call_ass->stmt, call_ass->result, CT_FALSE);
    }
}

status_t ple_exec_call_normal_func(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    ple_call_assist_t call_ass;
    pl_dc_t recompl_dc;
    pl_dc_t body_dc;
    call_ass.stmt = stmt;
    call_ass.node = node;
    call_ass.result = result;
    call_ass.is_pending = CT_FALSE;
    call_ass.source_pages.curr_page_id = CT_INVALID_ID32;
    call_ass.source_pages.curr_page_pos = 0;
    call_ass.is_exec_open = CT_FALSE;
    call_ass.is_sub_error = CT_FALSE;
    call_ass.is_pkg = CT_FALSE;
    call_ass.sub_stmt = NULL;
    call_ass.sub_pl_context = NULL;
    PLE_SAVE_STMT(stmt);

    if (ple_prepare_call(&call_ass, node, &recompl_dc, &body_dc) != CT_SUCCESS) {
        if (call_ass.is_curs_prepare) {
            call_ass.stmt->session->pl_cursors = NULL;
        }

        if (call_ass.sub_stmt != NULL && call_ass.sub_stmt->stat != NULL) {
            free(call_ass.sub_stmt->stat);
            call_ass.sub_stmt->stat = NULL;
        }

        PLE_RESTORE_STMT(stmt);
        return CT_ERROR;
    }

    var_udo_t *obj = call_ass.dc->obj;
    call_ass.status = CT_ERROR;
    do {
        if (result != NULL && call_ass.type == PL_PROCEDURE) {
            CT_SRC_THROW_ERROR(node->loc, ERR_STORED_PROCEDURE, T2S(&obj->user), T2S_EX(&obj->name));
            break;
        }
        /* alloc memory from stack for decls and args */
        CT_BREAK_IF_ERROR(ple_push_and_put_args(&call_ass));
        if (call_ass.is_pending) {
            SQL_SET_COLUMN_VAR(call_ass.result);
            call_ass.status = CT_SUCCESS;
            break;
        }

        CT_BREAK_IF_ERROR(
            ple_push_block(call_ass.sub_stmt, (pl_line_ctrl_t *)call_ass.begin_ln, &call_ass.var_map, call_ass.anchor));

        call_ass.sub_stmt->cursor_stack.depth = 0;
        call_ass.is_sub_error = CT_TRUE;
        CT_BREAK_IF_ERROR(ple_push_call_val(&call_ass));

        CT_BREAK_IF_ERROR(ple_lines(call_ass.sub_stmt, call_ass.begin_ln->ctrl.next, &call_ass.is_over_return));
        call_ass.is_sub_error = CT_FALSE;
        CT_BREAK_IF_ERROR(ple_set_outparams(&call_ass));
        call_ass.status = CT_SUCCESS;
    } while (0);

    if (call_ass.sub_stmt != NULL && call_ass.sub_stmt->stat != NULL) {
        free(call_ass.sub_stmt->stat);
        call_ass.sub_stmt->stat = NULL;
    }

    ple_end_call(&call_ass);
    PLE_RESTORE_STMT(stmt);
    stmt->trace_disabled |= call_ass.sub_stmt->trace_disabled;
    return call_ass.status;
}

static void pl_clang_close_exec_dc(ext_assist_t *call_ass)
{
    if (call_ass->is_exec_func) {
        pl_dc_close(call_ass->func_dc);
    }

    if (call_ass->is_pak) {
        pl_dc_close(call_ass->body_dc);
    }
}

static status_t pl_get_and_lock_func_dc(sql_stmt_t *stmt, expr_node_t *node, ext_assist_t *call_ass, pl_dc_t *func_dc)
{
    pl_dc_t *ref_dc = NULL;

    if (node->value.type_for_pl == VAR_UDO) {
        CT_RETURN_IFERR(ple_open_dc(stmt, node, func_dc));
        call_ass->func_dc = func_dc;
        call_ass->is_exec_func = CT_TRUE;
        return CT_SUCCESS;
    } else {
        ref_dc = ple_get_regist_dc(stmt, node);
        CM_ASSERT(ref_dc != NULL);
        call_ass->func_dc = ref_dc;
        return pl_check_and_lock_dc(stmt, &call_ass->func_dc, func_dc, &call_ass->is_exec_func);
    }
}

status_t ple_get_clang_function(sql_stmt_t *stmt, expr_node_t *node, ext_assist_t *call_ass, pl_dc_t *recmpl_dc,
    pl_dc_t *body_dc)
{
    status_t status = CT_ERROR;
    plv_decl_t *decl = NULL;
    uint32 sub_id;
    package_body_t *package_body = NULL;

    if (pl_get_and_lock_func_dc(stmt, node, call_ass, recmpl_dc) != CT_SUCCESS) {
        return CT_ERROR;
    }

    do {
        if (node->is_pkg) {
            CT_BREAK_IF_ERROR(ple_open_body_dc(stmt, call_ass->func_dc, body_dc));
            call_ass->is_pak = CT_TRUE;
            call_ass->body_dc = body_dc;
            package_body = body_dc->entity->package_body;
            sub_id = package_body->meth_map[call_ass->func_dc->sub_id];
            CM_ASSERT(sub_id < package_body->defs->count);
            decl = (plv_decl_t *)cm_galist_get(package_body->defs, sub_id);
            call_ass->func = decl->func;
            call_ass->oid = call_ass->func_dc->oid;
        } else {
            call_ass->oid = call_ass->func_dc->oid;
            call_ass->func = call_ass->func_dc->entity->function;
        }

        var_udo_t *obj = call_ass->func_dc->obj;
        if (call_ass->func->desc.lang_type != LANG_C) {
            CT_THROW_ERROR(ERR_USER_OBJECT_NOT_EXISTS, "clang function", T2S(&obj->user), T2S_EX(&obj->name));
            status = CT_ERROR;
            break;
        }

        status = CT_SUCCESS;
    } while (0);

    if (status == CT_ERROR) {
        pl_clang_close_exec_dc(call_ass);
    }

    return status;
}

status_t ple_exec_call_clang_func(sql_stmt_t *stmt, expr_node_t *node, variant_t *result)
{
    pl_manager_t *mngr = GET_PL_MGR;
    pl_dc_t func_dc;
    pl_dc_t body_dc;
    ext_assist_t assist = { 0 };
    pl_library_t library;
    pl_line_begin_t *begin_line = NULL;
    dc_user_t *dc_user = NULL;
    bool32 exists = CT_FALSE;

    if (!mngr->bootstrap) {
        CT_THROW_ERROR(ERR_EXT_PROC_NOT_STARTED);
        return CT_ERROR;
    }

    {
        CT_THROW_ERROR(ERR_EXT_PROC_NOT_WORK);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(ple_get_clang_function(stmt, node, &assist, &func_dc, &body_dc));
    begin_line = (pl_line_begin_t *)assist.func->body;
    if (dc_open_user(KNL_SESSION(stmt), &begin_line->lib_user, &dc_user) != CT_SUCCESS) {
        return CT_ERROR;
    }
    dls_latch_s(KNL_SESSION(stmt), &dc_user->lib_latch, KNL_SESSION(stmt)->id, CT_FALSE, NULL);
    if (pl_find_library(KNL_SESSION(stmt), dc_user->desc.id, &begin_line->lib_name, &library, &exists) != CT_SUCCESS) {
        dls_unlatch(KNL_SESSION(stmt), &dc_user->lib_latch, NULL);
        return CT_ERROR;
    }

    if (!exists) {
        dls_unlatch(KNL_SESSION(stmt), &dc_user->lib_latch, NULL);
        CT_THROW_ERROR(ERR_LIBRARY_NOT_EXIST, T2S(&begin_line->lib_user), T2S_EX(&begin_line->lib_name));
        return CT_ERROR;
    }

    if (sql_check_library_priv_core(stmt, &begin_line->lib_user, &begin_line->lib_name, &stmt->session->curr_user) !=
        CT_SUCCESS) {
        dls_unlatch(KNL_SESSION(stmt), &dc_user->lib_latch, NULL);
        return CT_ERROR;
    }

    assist.library = &library;
    // todo: recompile ple_exec_call_clang_func_core
    status_t status = CT_SUCCESS;
    // todo:   status_t status = ple_exec_call_clang_func_core(stmt, node, result, &assist);
    dls_unlatch(KNL_SESSION(stmt), &dc_user->lib_latch, NULL);
    pl_clang_close_exec_dc(&assist);
    return status;
}

status_t ple_exec_call(sql_stmt_t *stmt, expr_node_t *node, variant_t *res)
{
    if (node->lang_type == LANG_C) {
        return ple_exec_call_clang_func(stmt, node, res);
    } else {
        return ple_exec_call_normal_func(stmt, node, res);
    }
}
