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
 * pl_dbg_pack.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/debug/pl_dbg_pack.c
 *
 * -------------------------------------------------------------------------
 */
#include "pl_dbg_pack.h"
#include "ctsql_func.h"
#include "pl_executor.h"
#include "srv_instance.h"
#include "ctsql_privilege.h"

#define pl_sender (&g_instance->sql.pl_sender)

#define PKG_RETURN_IF_NOT_DEBUG_SESSION(session)                                                \
    do {                                                                                        \
        if ((session)->dbg_ctl == NULL || (session)->dbg_ctl->type != DEBUG_SESSION) {          \
            CT_THROW_ERROR(ERR_DEBUG_SESSION_TYPE, "debug session", (session)->knl_session.id); \
            return CT_ERROR;                                                                    \
        }                                                                                       \
    } while (0)

#define PKG_RETURN_IF_INT_NEGATIVE(var)                                                \
    do {                                                                               \
        if ((var).v_int < 0) {                                                         \
            CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "parameter can not be negative."); \
            return CT_ERROR;                                                           \
        }                                                                              \
    } while (0)

#define PKG_RETURN_IF_NOT_STRING(loc, type)             \
    do {                                                \
        if (!sql_match_string_type(type)) {             \
            CT_SRC_ERROR_REQUIRE_STRING((loc), (type)); \
            return CT_ERROR;                            \
        }                                               \
    } while (0)

#define PKG_RETURN_IF_NOT_INTEGER(loc, type)                          \
    do {                                                              \
        if (!CT_IS_INTEGER_TYPE(type) && !CT_IS_UNKNOWN_TYPE(type)) { \
            CT_SRC_ERROR_REQUIRE_INTEGER((loc), (type));              \
            return CT_ERROR;                                          \
        }                                                             \
    } while (0)

#define CM_SPIN_LOCK_CTL(session)                                          \
    do {                                                                   \
        cm_spin_lock_if_exists((session)->dbg_ctl->target_lock, NULL);     \
        cm_spin_lock_if_exists(&(session)->dbg_ctl_lock, NULL);            \
    } while (0)

static inline status_t sql_exec_dbgfunc_arg(sql_stmt_t *stmt, expr_tree_t *expr, variant_t *value, ct_type_t type,
    bool32 check_null)
{
    variant_t result;
    SQL_EXEC_FUNC_ARG(expr, value, &result, stmt);
    if (check_null && value->is_null) {
        CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "parameter cannot be null.");
        return CT_ERROR;
    }
    CT_RETURN_IFERR(sql_convert_variant(stmt, value, type));
    return CT_SUCCESS;
}

static status_t sql_get_available_breakpoint(debug_control_t *ctl, uint32 *unused_num)
{
    dbg_break_info_t *brk_info = ctl->brk_info;
    bool32 is_get = CT_FALSE;
    for (uint32 i = 0; i < ctl->max_break_id; i++) {
        if (!brk_info[i].is_using) {
            *unused_num = i;
            is_get = CT_TRUE;
            break;
        }
    }
    if (!is_get) {
        CT_THROW_ERROR(ERR_DEBUG_BREAK_POINT_EXCEED, ctl->max_break_id);
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

static status_t sql_debug_open_proc_dc(sql_stmt_t *stmt, debug_control_t *target_ctl,
    sql_add_break_arg_t *add_break_arg, pl_dc_t *pl_dc)
{
    plm_find_pldesc_t find_pldesc;

    find_pldesc.v_udo.user = add_break_arg->owner;
    find_pldesc.v_udo.name = add_break_arg->proc_name;
    find_pldesc.v_udo.pack.str = NULL;
    find_pldesc.v_udo.pack.len = 0;
    find_pldesc.type = add_break_arg->pl_type;
    return pld_open_proc_dc(stmt, target_ctl, &find_pldesc, pl_dc);
}

static bool32 sql_check_breakpoint_valid(pl_dc_t *pl_dc, int32 number)
{
    pl_entity_t *entity = pl_dc->entity;
    pl_line_ctrl_t *start = (pl_line_ctrl_t *)entity->function->body;
    pl_line_ctrl_t *line = start->next;

    while (line != NULL) {
        if (line->loc.line == (uint16)number) {
            // line type is LINE_WHEN, this line can't pause
            return (line->type != LINE_WHEN) ? CT_TRUE : CT_FALSE;
        }
        line = line->next;
    }
    return CT_FALSE;
}

static status_t sql_debug_add_break_prepare(sql_stmt_t *stmt, expr_node_t *func, sql_add_break_arg_t *break_arg)
{
    session_t *session = stmt->session;
    variant_t owner, proc_name, pl_type, cond, line_number, max_skip_times;
    expr_tree_t *arg1 = func->argument; // arg1: the ower of pl
    expr_tree_t *arg2 = arg1->next;     // arg2: the name of pl
    expr_tree_t *arg3 = arg2->next;     // arg3: type of pl
    expr_tree_t *arg4 = arg3->next;     // arg4: the line number
    expr_tree_t *arg5 = arg4->next;     // arg5: max_skip_times
    expr_tree_t *arg6 = arg5->next;     // arg6: break condition
    CT_RETURN_IFERR(sql_exec_dbgfunc_arg(stmt, arg1, &owner, CT_TYPE_STRING, CT_TRUE));
    sql_keep_stack_variant(stmt, &owner);
    cm_text_upper(&owner.v_text);
    CT_RETURN_IFERR(sql_exec_dbgfunc_arg(stmt, arg2, &proc_name, CT_TYPE_STRING, CT_TRUE));
    sql_keep_stack_variant(stmt, &proc_name);
    CT_RETURN_IFERR(sql_exec_dbgfunc_arg(stmt, arg3, &pl_type, CT_TYPE_STRING, CT_TRUE));
    sql_keep_stack_variant(stmt, &pl_type);
    cm_text_upper(&pl_type.v_text);
    CT_RETURN_IFERR(sql_exec_dbgfunc_arg(stmt, arg4, &line_number, CT_TYPE_INTEGER, CT_TRUE));
    CT_RETURN_IFERR(sql_exec_dbgfunc_arg(stmt, arg5, &max_skip_times, CT_TYPE_INTEGER, CT_TRUE));
    CT_RETURN_IFERR(sql_exec_dbgfunc_arg(stmt, arg6, &cond, CT_TYPE_STRING, CT_FALSE)); // condition can be null
    sql_keep_stack_variant(stmt, &cond);

    if (line_number.v_int < 0 || max_skip_times.v_int < 0) {
        CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "parameter can not be negative.");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(pld_get_pl_type(&pl_type.v_text, &break_arg->pl_type));

    if (!cm_text_equal(&session->curr_user, &owner.v_text) && !sql_user_is_dba(session)) {
        CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return CT_ERROR;
    }
    break_arg->owner = owner.v_text;
    break_arg->proc_name = proc_name.v_text;
    break_arg->line_number = line_number.v_int;
    break_arg->max_skip_times = max_skip_times.v_int;
    break_arg->cond = cond.v_text;

    cm_text_upper(&break_arg->owner);
    process_name_case_sensitive(&break_arg->proc_name);
    return CT_SUCCESS;
}

static void sql_init_breakpoint(dbg_break_info_t *break_info, sql_add_break_arg_t *add_break_arg, pl_dc_t *pl_dc)
{
    break_info->is_using = CT_TRUE;
    break_info->is_enabled = CT_TRUE;
    break_info->loc.line = (int16)add_break_arg->line_number;
    break_info->loc.column = 1;
    break_info->max_skip_times = add_break_arg->max_skip_times;
    (void)cm_text2str(&add_break_arg->owner, break_info->owner, CT_NAME_BUFFER_SIZE);
    (void)cm_text2str(&add_break_arg->proc_name, break_info->object, CT_NAME_BUFFER_SIZE);
    break_info->owner_len = add_break_arg->owner.len;
    break_info->object_len = add_break_arg->proc_name.len;
    break_info->scn = pl_dc->org_scn;
    break_info->pl_type = add_break_arg->pl_type;
}

status_t sql_debug_add_break(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    session_t *session = stmt->session;
    sql_add_break_arg_t add_break_arg;
    debug_control_t *target_ctl = NULL;
    status_t status = CT_ERROR;
    pl_dc_t pl_dc = { 0 };
    char buf[CT_NAME_BUFFER_SIZE];

    PKG_RETURN_IF_NOT_DEBUG_SESSION(session);

    CTSQL_SAVE_STACK(stmt);
    if (sql_debug_add_break_prepare(stmt, func, &add_break_arg) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    if (sql_user_text_prefix_tenant(stmt->session, &add_break_arg.owner, buf, CT_NAME_BUFFER_SIZE) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    cm_spin_lock_if_exists(session->dbg_ctl->target_lock, NULL);
    cm_spin_lock_if_exists(&session->dbg_ctl_lock, NULL);
    do {
        // step1: get the target session and found one brk_info not be used
        CT_BREAK_IF_ERROR(pld_get_target_session_debug_info(stmt, session->dbg_ctl->target_id, &target_ctl, NULL));

        if (!pld_has_privilege(session, &target_ctl->debug_user, NULL)) {
            CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            break;
        }
        uint32 ava_index = CT_INVALID_ID32;
        dbg_break_info_t *brk_info = target_ctl->brk_info;
        if (sql_get_available_breakpoint(target_ctl, &ava_index) != CT_SUCCESS) {
            break;
        }
        // step2: check the break point info valid or not.
        CT_BREAK_IF_ERROR(sql_debug_open_proc_dc(stmt, target_ctl, &add_break_arg, &pl_dc));
        if (!sql_check_breakpoint_valid(&pl_dc, add_break_arg.line_number)) {
            CT_THROW_ERROR(ERR_DEBUG_OPR_BREAK, 0, "line_number is invalid");
            pl_dc_close(&pl_dc);
            break;
        }
        sql_init_breakpoint(&brk_info[ava_index], &add_break_arg, &pl_dc);

        // the break_info number which return to user begins with 1, eg: 1,2,3,4,....
        result->v_int = ava_index + 1;
        result->type = CT_TYPE_INTEGER;
        status = CT_SUCCESS;
        pl_dc_close(&pl_dc);
    } while (0);
    cm_spin_unlock_if_exists(&session->dbg_ctl_lock);
    cm_spin_unlock_if_exists(session->dbg_ctl->target_lock);
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

#define ARG_NUM_FOR_ADD_BREAK 6

status_t sql_verify_debug_add_break(sql_verifier_t *verif, expr_node_t *func)
{
    if (sql_verify_func_node(verif, func, ARG_NUM_FOR_ADD_BREAK, ARG_NUM_FOR_ADD_BREAK, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    expr_tree_t *arg1 = func->argument; // arg1: the ower of pl
    expr_tree_t *arg2 = arg1->next;     // arg2: the name of pl
    expr_tree_t *arg3 = arg2->next;     // arg3: the type of pl
    expr_tree_t *arg4 = arg3->next;     // arg4: the line number
    expr_tree_t *arg5 = arg4->next;     // arg5: max_skip_times
    expr_tree_t *arg6 = arg5->next;     // arg6: break condition

    PKG_RETURN_IF_NOT_STRING(arg1->loc, TREE_DATATYPE(arg1));
    PKG_RETURN_IF_NOT_STRING(arg2->loc, TREE_DATATYPE(arg2));
    PKG_RETURN_IF_NOT_STRING(arg3->loc, TREE_DATATYPE(arg3));
    PKG_RETURN_IF_NOT_INTEGER(arg4->loc, TREE_DATATYPE(arg4));
    PKG_RETURN_IF_NOT_INTEGER(arg5->loc, TREE_DATATYPE(arg5));
    PKG_RETURN_IF_NOT_STRING(arg6->loc, TREE_DATATYPE(arg6));
    func->datatype = CT_TYPE_INTEGER;
    func->size = 0;
    return CT_SUCCESS;
}

status_t sql_debug_attach(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t var1, var2;
    uint32 breakpoint_cnt;
    debug_control_t *target_ctl = NULL;
    spinlock_t *target_lock = NULL;
    session_t *session = stmt->session;
    debug_control_t *debug_ctl = NULL;

    expr_tree_t *arg1 = func->argument;
    CT_RETURN_IFERR(sql_exec_dbgfunc_arg(stmt, arg1, &var1, CT_TYPE_INTEGER, CT_TRUE));
    if (var1.v_int <= 0 || var1.v_int > CT_MAX_SESSIONS) {
        CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "parameter is invalid.");
        return CT_ERROR;
    }
    // calculate arg2
    expr_tree_t *arg2 = arg1->next;
    CT_RETURN_IFERR(sql_exec_dbgfunc_arg(stmt, arg2, &var2, CT_TYPE_INTEGER, CT_TRUE));
    if (var2.v_int < 0) {
        CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "parameter can not be negative.");
        return CT_ERROR;
    }
    if ((var2.v_int > CT_MAX_DEBUG_BREAKPOINT_COUNT) || (var2.v_int == 0)) {
        var2.v_int = CT_MAX_DEBUG_BREAKPOINT_COUNT;
    }
    breakpoint_cnt = (uint32)var2.v_int;
    // according to the session_id, get the session obj to be attached, check the status
    uint32 session_id = session->knl_session.id;
    uint32 attached_seession_id = var1.v_int;

    if (session->dbg_ctl != NULL) {
        CT_THROW_ERROR(ERR_DEBUG_SESSION_TYPE, "normal session", session_id);
        return CT_ERROR;
    }

    CT_INIT_SPIN_LOCK(session->dbg_ctl_lock);

    if (!srv_get_debug_info(attached_seession_id, &target_ctl, &target_lock) || target_ctl->type != TARGET_SESSION) {
        CT_THROW_ERROR(ERR_DEBUG_SESSION_TYPE, "target session", session_id);
        return CT_ERROR;
    }
    cm_spin_lock_if_exists(target_lock, NULL);
    do {
        if (target_ctl->is_attached) {
            cm_spin_unlock_if_exists(target_lock);
            CT_THROW_ERROR(ERR_DEBUG_CAN_NOT_ATTACHED, "the session to be attached has been attached by other session");
            return CT_ERROR;
        }

        // check permission
        if (!cm_text_equal(&session->curr_user, &target_ctl->target_user) && !sql_user_is_dba(session)) {
            cm_spin_unlock_if_exists(target_lock);
            CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            return CT_ERROR;
        }

        cm_spin_lock_if_exists(&session->dbg_ctl_lock, NULL);
        // step1: alloc memory for debug session's dbg_ctl, brk_info and callstack
        if (session->dbg_ctl) {
            CT_THROW_ERROR(ERR_DEBUG_CAN_NOT_ATTACHED, "this session has attached to other session");
            break;
        }
        CT_BREAK_IF_ERROR(srv_alloc_dbg_ctl(breakpoint_cnt, PL_MAX_BLOCK_DEPTH, &session->dbg_ctl));

        // step2: set debug session's flags
        debug_ctl = session->dbg_ctl;
        debug_ctl->is_attaching = CT_TRUE;
        debug_ctl->target_id = attached_seession_id;
        debug_ctl->type = DEBUG_SESSION;
        debug_ctl->target_lock = target_lock;

        // step3: set target  session's flags
        target_ctl->is_attached = CT_TRUE;
        target_ctl->is_force_pause = CT_TRUE;
        target_ctl->debug_id = session_id;
        target_ctl->debug_lock = &session->dbg_ctl_lock;
        target_ctl->brk_info = session->dbg_ctl->brk_info;
        target_ctl->callstack_info = session->dbg_ctl->callstack_info;
        target_ctl->max_break_id = breakpoint_cnt;
        target_ctl->max_stack_id = 0;
        target_ctl->curr_count = 0;
        target_ctl->debug_user = session->curr_user;
    } while (0);

    cm_spin_unlock_if_exists(&session->dbg_ctl_lock);
    cm_spin_unlock_if_exists(target_lock);

    return CT_SUCCESS;
}

status_t sql_verify_debug_attach(sql_verifier_t *verif, expr_node_t *func)
{
    if (sql_verify_func_node(verif, func, 2, 2, CT_INVALID_ID32) != CT_SUCCESS) { // function needs to verify 2 args
        return CT_ERROR;
    }
    expr_tree_t *arg1 = func->argument; // arg1: the session id of being attached
    PKG_RETURN_IF_NOT_INTEGER(func->argument->loc, TREE_DATATYPE(arg1));
    expr_tree_t *arg2 = arg1->next; // arg2: the max breakpoints, it needs to be defined by user.
    PKG_RETURN_IF_NOT_INTEGER(func->argument->loc, TREE_DATATYPE(arg2));

    return CT_SUCCESS;
}

static bool32 sql_debug_check_break_valid(debug_control_t *debug_ctl, uint32 id)
{
    dbg_break_info_t *brk_info = debug_ctl->brk_info;
    if (id == 0 || brk_info[id - 1].is_using == CT_FALSE) {
        return CT_FALSE;
    }
    return CT_TRUE;
}

static status_t sql_delete_brk_by_id(debug_control_t *debug_ctl, uint32 id)
{
    dbg_break_info_t *brk_info = debug_ctl->brk_info;
    uint32 start_id, end_id;

    if (id == 0) {
        start_id = 0;
        end_id = debug_ctl->max_break_id - 1;
    } else {
        if (sql_debug_check_break_valid(debug_ctl, id) == CT_FALSE) {
            CT_THROW_ERROR(ERR_DEBUG_OPR_BREAK, id, "the breakpoint id is not existing");
            return CT_ERROR;
        }
        start_id = id - 1;
        end_id = id - 1;
    }

    for (uint32 i = start_id; i <= end_id; i++) {
        brk_info[i].is_using = CT_FALSE;
        brk_info[i].is_enabled = CT_FALSE;
        brk_info[i].loc.line = 0;
        brk_info[i].loc.column = 0;
        brk_info[i].max_skip_times = 0;
        MEMS_RETURN_IFERR(strcpy_s(brk_info[i].owner, CT_NAME_BUFFER_SIZE, ""));
        MEMS_RETURN_IFERR(strcpy_s(brk_info[i].object, CT_NAME_BUFFER_SIZE, ""));
        brk_info[i].owner_len = 0;
        brk_info[i].object_len = 0;
        brk_info[i].scn = 0;
        brk_info[i].pl_type = 0;
    }

    return CT_SUCCESS;
}

status_t sql_debug_del_break(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    session_t *session = stmt->session;
    debug_control_t *target_ctl = NULL;
    status_t status = CT_ERROR;
    variant_t value;

    PKG_RETURN_IF_NOT_DEBUG_SESSION(session);
    expr_tree_t *arg = func->argument;
    CT_RETURN_IFERR(sql_exec_dbgfunc_arg(stmt, arg, &value, CT_TYPE_INTEGER, CT_TRUE));
    if (value.v_int < 0) {
        CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "parameter must be positive.");
        return CT_ERROR;
    }
    cm_spin_lock_if_exists(session->dbg_ctl->target_lock, NULL);
    cm_spin_lock_if_exists(&session->dbg_ctl_lock, NULL);
    do {
        CT_BREAK_IF_ERROR(pld_get_target_session_debug_info(stmt, session->dbg_ctl->target_id, &target_ctl, NULL));
        if (!pld_has_privilege(session, &target_ctl->debug_user, NULL)) {
            CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            break;
        }
        if ((target_ctl->status == DBG_EXECUTING) || (target_ctl->status == DBG_PRE_WAIT)) {
            CT_THROW_ERROR(ERR_DEBUG_SESSION_STATUS, "IDLE or WAITING", "EXECUTING or PRE_WAIT");
            break;
        }
        if ((uint32)value.v_int > target_ctl->max_break_id) {
            CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "the breakpoint id is out of range");
            break;
        }
        if (sql_delete_brk_by_id(target_ctl, (uint32)value.v_int)) {
            CT_THROW_ERROR(ERR_DEBUG_OPR_BREAK, value.v_int, "delete breakpoint failed");
            break;
        }
        status = CT_SUCCESS;
    } while (0);
    cm_spin_unlock_if_exists(&session->dbg_ctl_lock);
    cm_spin_unlock_if_exists(session->dbg_ctl->target_lock);
    return status;
}

status_t sql_verify_debug_del_break(sql_verifier_t *verif, expr_node_t *func)
{
    if (sql_verify_func_node(verif, func, 1, 1, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }
    expr_tree_t *arg = func->argument;
    PKG_RETURN_IF_NOT_INTEGER(func->argument->loc, TREE_DATATYPE(arg));
    return CT_SUCCESS;
}

static status_t sql_delete_brk_by_name(debug_control_t *debug_ctl, text_t *owner, text_t *proc_name, text_t *pl_type)
{
    dbg_break_info_t *break_info = debug_ctl->brk_info;
    text_t brk_info_owner, brk_info_proc_name;
    uint32 type;

    CT_RETURN_IFERR(pld_get_pl_type(pl_type, &type));
    for (uint32 i = 0; i < debug_ctl->max_break_id; i++) {
        brk_info_owner.str = break_info[i].owner;
        brk_info_owner.len = break_info[i].owner_len;
        brk_info_proc_name.str = break_info[i].object;
        brk_info_proc_name.len = break_info[i].object_len;
        if (!cm_text_equal(&brk_info_owner, owner) || !cm_text_equal(&brk_info_proc_name, proc_name) ||
            break_info[i].pl_type != type) {
            continue;
        }
        break_info[i].is_using = CT_FALSE;
        break_info[i].is_enabled = CT_FALSE;
        break_info[i].loc.line = 0;
        break_info[i].loc.column = 0;
        break_info[i].max_skip_times = 0;
        MEMS_RETURN_IFERR(strcpy_s(break_info[i].owner, CT_NAME_BUFFER_SIZE, ""));
        MEMS_RETURN_IFERR(strcpy_s(break_info[i].object, CT_NAME_BUFFER_SIZE, ""));
        break_info[i].owner_len = 0;
        break_info[i].object_len = 0;
    }

    return CT_SUCCESS;
}

status_t sql_debug_del_break_get_args(sql_stmt_t *stmt, expr_node_t *func, char *buf, variant_t *owner,
    variant_t *proc_name, variant_t *pl_type)
{
    expr_tree_t *arg1 = func->argument; // arg1: the ower of pl
    expr_tree_t *arg2 = arg1->next;     // arg2: the name of pl
    expr_tree_t *arg3 = arg2->next;     // arg3: the type of pl

    if (sql_exec_dbgfunc_arg(stmt, arg1, owner, CT_TYPE_STRING, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    sql_keep_stack_variant(stmt, owner);
    cm_text_upper(&owner->v_text);

    if (sql_user_text_prefix_tenant(stmt->session, &owner->v_text, buf, CT_NAME_BUFFER_SIZE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (sql_exec_dbgfunc_arg(stmt, arg2, proc_name, CT_TYPE_STRING, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    sql_keep_stack_variant(stmt, proc_name);
    process_name_case_sensitive(&proc_name->v_text);

    if (sql_exec_dbgfunc_arg(stmt, arg3, pl_type, CT_TYPE_STRING, CT_TRUE) != CT_SUCCESS) {
        return CT_ERROR;
    }
    sql_keep_stack_variant(stmt, pl_type);
    cm_text_upper(&pl_type->v_text);

    return CT_SUCCESS;
}

status_t sql_debug_del_break_by_name(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    session_t *session = stmt->session;
    debug_control_t *target_ctl = NULL;
    status_t status = CT_ERROR;
    variant_t owner, proc_name, pl_type;
    char buf[CT_NAME_BUFFER_SIZE];

    PKG_RETURN_IF_NOT_DEBUG_SESSION(session);

    CTSQL_SAVE_STACK(stmt);

    if (sql_debug_del_break_get_args(stmt, func, buf, &owner, &proc_name, &pl_type) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    if (!cm_text_equal(&session->curr_user, &owner.v_text) && !sql_user_is_dba(session)) {
        CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    cm_spin_lock_if_exists(session->dbg_ctl->target_lock, NULL);
    cm_spin_lock_if_exists(&session->dbg_ctl_lock, NULL);
    do {
        CT_BREAK_IF_ERROR(pld_get_target_session_debug_info(stmt, session->dbg_ctl->target_id, &target_ctl, NULL));
        if (!pld_has_privilege(session, &target_ctl->debug_user, NULL)) {
            CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            break;
        }
        if ((target_ctl->status == DBG_EXECUTING) || (target_ctl->status == DBG_PRE_WAIT)) {
            CT_THROW_ERROR(ERR_DEBUG_SESSION_STATUS, "IDLE or WAITING", "EXECUTING or PRE_WAIT");
            break;
        }
        if (sql_delete_brk_by_name(target_ctl, &owner.v_text, &proc_name.v_text, &pl_type.v_text)) {
            CT_THROW_ERROR(ERR_DEBUG_OPR_BREAK, 0, "delete breakpoint failed");
            break;
        }
        status = CT_SUCCESS;
    } while (0);
    cm_spin_unlock_if_exists(&session->dbg_ctl_lock);
    cm_spin_unlock_if_exists(session->dbg_ctl->target_lock);
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

status_t sql_verify_debug_del_break_by_name(sql_verifier_t *verif, expr_node_t *func)
{
    if (sql_verify_func_node(verif, func, 3, 3, CT_INVALID_ID32) != CT_SUCCESS) { // function needs to verify 3 args
        return CT_ERROR;
    }

    expr_tree_t *arg1 = func->argument; // arg1: the ower of pl
    expr_tree_t *arg2 = arg1->next;     // arg2: the name of pl
    expr_tree_t *arg3 = arg2->next;     // arg3: the type of pl

    PKG_RETURN_IF_NOT_STRING(arg1->loc, TREE_DATATYPE(arg1));
    PKG_RETURN_IF_NOT_STRING(arg2->loc, TREE_DATATYPE(arg2));
    PKG_RETURN_IF_NOT_STRING(arg3->loc, TREE_DATATYPE(arg3));
    return CT_SUCCESS;
}

status_t sql_debug_detach(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t value;
    status_t status = CT_SUCCESS;
    debug_control_t *target_ctl = NULL;
    session_t *session = stmt->session;
    uint32 session_id = session->knl_session.id;
    spinlock_t *target_lock = NULL;
    if (session->dbg_ctl == NULL || session->dbg_ctl->type != DEBUG_SESSION) {
        CT_THROW_ERROR(ERR_DEBUG_SESSION_TYPE, "debug session", session_id);
        return CT_ERROR;
    }
    debug_control_t *debug_ctl = session->dbg_ctl;

    expr_tree_t *arg1 = func->argument;
    CT_RETURN_IFERR(sql_exec_dbgfunc_arg(stmt, arg1, &value, CT_TYPE_INTEGER, CT_TRUE));
    if (value.v_int != 0 && value.v_int != 1) {
        CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "parameter must be 0 or 1.");
        return CT_ERROR;
    }

    target_lock = debug_ctl->target_lock;
    cm_spin_lock_if_exists(target_lock, NULL);
    if (pld_get_target_session_debug_info(stmt, debug_ctl->target_id, &target_ctl, NULL) != CT_SUCCESS) {
        cm_spin_unlock_if_exists(target_lock);
        return CT_ERROR;
    }

    if (!pld_has_privilege(session, &target_ctl->debug_user, NULL)) {
        cm_spin_unlock_if_exists(target_lock);
        CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return CT_ERROR;
    }

    if ((target_ctl->status == DBG_EXECUTING) || (target_ctl->status == DBG_PRE_WAIT)) {
        cm_spin_unlock_if_exists(target_lock);
        CT_THROW_ERROR(ERR_DEBUG_SESSION_STATUS, "IDLE or WAITING", "EXECUTING or PRE_WAIT");
        return CT_ERROR;
    }
    if (target_ctl->status != DBG_IDLE) {
        target_ctl->is_force_terminate = value.v_bool ? CT_TRUE : CT_FALSE;
        target_ctl->status = DBG_EXECUTING;
    }

    // free target session's all brk_infos and debug session's dbg_ctl memory
    cm_spin_lock_if_exists(&session->dbg_ctl_lock, NULL);
    srv_free_dbg_ctl(session);
    cm_spin_unlock_if_exists(&session->dbg_ctl_lock);
    cm_spin_unlock_if_exists(target_lock);
    return status;
}

status_t sql_verify_debug_detach(sql_verifier_t *verif, expr_node_t *func)
{
    if (sql_verify_func_node(verif, func, 1, 1, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }
    PKG_RETURN_IF_NOT_INTEGER(func->argument->loc, TREE_DATATYPE(func->argument));

    return CT_SUCCESS;
}

status_t sql_debug_get_status(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    session_t *session = stmt->session;
    debug_control_t *debug_ctl = NULL;
    status_t status;

    PKG_RETURN_IF_NOT_DEBUG_SESSION(session);

    status = CT_ERROR;
    cm_spin_lock_if_exists(session->dbg_ctl->target_lock, NULL);
    cm_spin_lock_if_exists(&session->dbg_ctl_lock, NULL);
    do {
        CT_BREAK_IF_ERROR(pld_get_target_session_debug_info(stmt, session->dbg_ctl->target_id, &debug_ctl, NULL));
        if (!pld_has_privilege(session, &debug_ctl->debug_user, NULL)) {
            CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            break;
        }

        result->v_int = debug_ctl->status;
        result->type = CT_TYPE_INTEGER;
        status = CT_SUCCESS;
    } while (0);
    cm_spin_unlock_if_exists(&session->dbg_ctl_lock);
    cm_spin_unlock_if_exists(session->dbg_ctl->target_lock);
    return status;
}

status_t sql_verify_debug_get_status(sql_verifier_t *verif, expr_node_t *func)
{
    CT_RETURN_IFERR(sql_verify_func_node(verif, func, 0, 0, CT_INVALID_ID32));

    func->datatype = CT_TYPE_INTEGER;
    func->size = sizeof(int32);
    return CT_SUCCESS;
}

static status_t sql_debug_get_value_prepare(sql_stmt_t *stmt, expr_node_t *func, pld_var_info_t *var_info)
{
    variant_t stack_id, block, id, offset;
    expr_tree_t *arg1 = func->argument;
    CT_RETURN_IFERR(sql_exec_dbgfunc_arg(stmt, arg1, &stack_id, CT_TYPE_INTEGER, CT_TRUE));
    PKG_RETURN_IF_INT_NEGATIVE(stack_id);
    expr_tree_t *arg2 = arg1->next;
    CT_RETURN_IFERR(sql_exec_dbgfunc_arg(stmt, arg2, &block, CT_TYPE_INTEGER, CT_TRUE));
    PKG_RETURN_IF_INT_NEGATIVE(block);
    expr_tree_t *arg3 = arg2->next;
    CT_RETURN_IFERR(sql_exec_dbgfunc_arg(stmt, arg3, &id, CT_TYPE_INTEGER, CT_TRUE));
    PKG_RETURN_IF_INT_NEGATIVE(id);
    expr_tree_t *arg4 = arg3->next;
    CT_RETURN_IFERR(sql_exec_dbgfunc_arg(stmt, arg4, &offset, CT_TYPE_INTEGER, CT_TRUE));
    PKG_RETURN_IF_INT_NEGATIVE(offset);
    var_info->stack_id = stack_id.v_int;
    var_info->block_id = block.v_int;
    var_info->id = id.v_int;
    var_info->m_offset = offset.v_int;
    return CT_SUCCESS;
}

status_t sql_debug_get_value(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    session_t *session = stmt->session;
    debug_control_t *dbg_ctl = NULL;
    status_t status;
    pld_var_info_t var_info;
    bool32 eof = CT_FALSE;
    bool32 is_found = CT_FALSE;

    PKG_RETURN_IF_NOT_DEBUG_SESSION(session);

    CT_RETURN_IFERR(sql_debug_get_value_prepare(stmt, func, &var_info));

    status = CT_ERROR;
    CTSQL_SAVE_STACK(stmt);
    cm_spin_lock_if_exists(session->dbg_ctl->target_lock, NULL);
    cm_spin_lock_if_exists(&session->dbg_ctl_lock, NULL);
    do {
        CT_BREAK_IF_ERROR(pld_get_target_session_debug_info(stmt, session->dbg_ctl->target_id, &dbg_ctl, NULL));

        if (dbg_ctl->status != DBG_WAITING) {
            CT_THROW_ERROR(ERR_DEBUG_SESSION_STATUS, "WAITING", "IDLE or EXECUTING or PRE_WAIT");
            break;
        }

        if (var_info.stack_id == 0 || var_info.stack_id >= dbg_ctl->max_stack_id) {
            var_info.stack_id = dbg_ctl->max_stack_id;
        }
        if (!pld_has_privilege(session, &dbg_ctl->debug_user, dbg_ctl->callstack_info[var_info.stack_id - 1].exec)) {
            CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            break;
        }
        var_info.total_field = NULL;
        var_info.total_attr = NULL;
        var_info.obj_total_field = NULL;
        var_info.obj_total_attr = NULL;
        var_info.total_parent_name = NULL;
        CT_BREAK_IF_ERROR(pld_get_var_info(stmt, dbg_ctl, &var_info, &is_found, &eof));
        if (!is_found) {
            CT_THROW_ERROR(ERR_UNEXPECTED_PL_VARIANT);
            break;
        }
        if (var_info.is_attr_in_vm) {
            if (var_info.is_obj) {
                CT_BREAK_IF_ERROR(pld_object_field_read(stmt, var_info.obj_curr_stmt, var_info.obj_attr,
                    &var_info.obj_field, result));
            } else {
                CT_BREAK_IF_ERROR(
                    pld_record_field_read(stmt, var_info.curr_stmt, var_info.attr, &var_info.field, result));
            }
        } else {
            var_copy(&var_info.get_value, result);
        }
        if (result->type == CT_TYPE_RECORD) {
            result->is_null = CT_TRUE;
        } else if (result->type == CT_TYPE_COLLECTION) {
            result->v_text.str = "collect type is not supported";
            result->v_text.len = (uint32)strlen(result->v_text.str);
            result->type = CT_TYPE_STRING;
        } else if (result->type == CT_TYPE_OBJECT) {
            result->is_null = CT_TRUE;
        }
        if (result->type == CT_TYPE_CURSOR) {
            result->type = CT_TYPE_STRING;
            CT_BREAK_IF_ERROR(sql_push(stmt, PLD_CURSOR_VALUE_LEN, (void **)&result->v_text.str));
            result->v_text.len = 0;
            CT_BREAK_IF_ERROR(
                pld_get_cursor_buf(result->v_text.str, PLD_CURSOR_VALUE_LEN, &result->v_text.len, &var_info.cur_info));
        } else {
            CT_BREAK_IF_ERROR(sql_convert_variant(stmt, result, CT_TYPE_STRING));
        }
        status = CT_SUCCESS;
    } while (0);
    cm_spin_unlock_if_exists(&session->dbg_ctl_lock);
    cm_spin_unlock_if_exists(session->dbg_ctl->target_lock);
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

#define ARG_NUM_FOR_GET_VALUE 4

status_t sql_verify_debug_get_value(sql_verifier_t *verif, expr_node_t *func)
{
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    expr_tree_t *arg3 = NULL;
    expr_tree_t *arg4 = NULL;

    CT_RETURN_IFERR(sql_verify_func_node(verif, func, ARG_NUM_FOR_GET_VALUE, ARG_NUM_FOR_GET_VALUE, CT_INVALID_ID32));

    arg1 = func->argument;
    PKG_RETURN_IF_NOT_INTEGER(arg1->loc, TREE_DATATYPE(arg1));
    arg2 = arg1->next;
    PKG_RETURN_IF_NOT_INTEGER(arg2->loc, TREE_DATATYPE(arg2));
    arg3 = arg2->next;
    PKG_RETURN_IF_NOT_INTEGER(arg3->loc, TREE_DATATYPE(arg3));
    arg4 = arg3->next;
    PKG_RETURN_IF_NOT_INTEGER(arg4->loc, TREE_DATATYPE(arg4));

    func->datatype = CT_TYPE_STRING;
    func->size = CT_MAX_STRING_LEN;

    return CT_SUCCESS;
}

status_t sql_debug_get_version(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    result->v_int = PLD_VERSION_0;
    result->type = CT_TYPE_INTEGER;
    return CT_SUCCESS;
}

status_t sql_verify_debug_get_version(sql_verifier_t *verif, expr_node_t *func)
{
    func->datatype = CT_TYPE_INTEGER;
    func->size = sizeof(int);
    return CT_SUCCESS;
}

static void sql_init_debug_session_ctl(debug_control_t *debug_ctl, dbg_session_type_t type, int32 timeout)
{
    debug_ctl->is_attached = (bool8)CT_FALSE;
    debug_ctl->timeout = timeout;
    debug_ctl->status = DBG_IDLE;
    debug_ctl->type = type;
    debug_ctl->is_force_pause = CT_FALSE;
    debug_ctl->is_force_terminate = CT_FALSE;
    debug_ctl->debug_id = CT_INVALID_ID32;
    debug_ctl->debug_lock = NULL;
    debug_ctl->brk_flag_stack_id = CT_INVALID_ID32;
    debug_ctl->max_stack_id = 0;
    debug_ctl->max_break_id = 0;
}


status_t sql_debug_init(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t value;
    session_t *session = stmt->session;
    uint32 session_id = session->knl_session.id;
    expr_tree_t *arg = func->argument;

    CT_RETURN_IFERR(sql_exec_dbgfunc_arg(stmt, arg, &value, CT_TYPE_INTEGER, CT_TRUE));
    if (value.v_int <= 0) {
        CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "parameter must be positive.");
        return CT_ERROR;
    }

    // it means the session has been initialized if dbg_ctl is not equal NULL. in this case, the function returns -1.
    if (session->dbg_ctl) {
        CT_THROW_ERROR(ERR_DEBUG_SESSION_TYPE, "normal session", session_id);
        return CT_ERROR;
    }

    CT_INIT_SPIN_LOCK(session->dbg_ctl_lock);
    cm_spin_lock_if_exists(&session->dbg_ctl_lock, NULL);
    do {
        // step1: alloc memory for debug_control_t and init spinlock
        CT_BREAK_IF_ERROR(srv_alloc_dbg_ctl(0, 0, &session->dbg_ctl));

        // step2: assign be_attached, timeout, session status
        debug_control_t *debug_ctl = (debug_control_t *)session->dbg_ctl;
        sql_init_debug_session_ctl(debug_ctl, TARGET_SESSION, value.v_int);
        debug_ctl->target_user = session->curr_user;

        // step3: register callback functions
        pld_register_debug_callbacks(&debug_ctl->dbg_calls);

        // step4: return session id to client
        result->v_int = session_id;
        result->type = CT_TYPE_INTEGER;
    } while (0);

    cm_spin_unlock_if_exists(&session->dbg_ctl_lock);
    return CT_SUCCESS;
}

status_t sql_verify_debug_init(sql_verifier_t *verif, expr_node_t *func)
{
    if (sql_verify_func_node(verif, func, 1, 1, CT_INVALID_ID32) != CT_SUCCESS) {
        return CT_ERROR;
    }

    PKG_RETURN_IF_NOT_INTEGER(func->argument->loc, TREE_DATATYPE(func->argument));

    func->datatype = CT_TYPE_INTEGER;
    func->size = 0;
    return CT_SUCCESS;
}

status_t sql_debug_pause(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    session_t *session = stmt->session;
    debug_control_t *debug_ctl = NULL;
    status_t status;
    SQL_SET_NULL_VAR(result);

    PKG_RETURN_IF_NOT_DEBUG_SESSION(session);

    status = CT_ERROR;
    cm_spin_lock_if_exists(session->dbg_ctl->target_lock, NULL);
    cm_spin_lock_if_exists(&session->dbg_ctl_lock, NULL);
    do {
        CT_BREAK_IF_ERROR(pld_get_target_session_debug_info(stmt, session->dbg_ctl->target_id, &debug_ctl, NULL));
        if (!pld_has_privilege(session, &debug_ctl->debug_user, NULL)) {
            CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            break;
        }
        if (debug_ctl->status != DBG_EXECUTING) {
            CT_THROW_ERROR(ERR_DEBUG_SESSION_STATUS, "EXECUTING", "IDLE or WAITING or PRE_WAIT");
            break;
        }

        debug_ctl->is_force_pause = CT_TRUE;
        status = CT_SUCCESS;
    } while (0);
    cm_spin_unlock_if_exists(&session->dbg_ctl_lock);
    cm_spin_unlock_if_exists(session->dbg_ctl->target_lock);
    return status;
}

status_t sql_verify_no_argument(sql_verifier_t *verif, expr_node_t *func)
{
    return sql_verify_func_node(verif, func, 0, 0, CT_INVALID_ID32);
}

#define SQL_CALLSATCK_PUTLINE_LEN 256
static status_t sql_debug_try_for_waiting(sql_stmt_t *stmt, int32 tmp_wait_time)
{
    int32 wait_time = tmp_wait_time;
    session_t *session = stmt->session;
    char buffer[SQL_CALLSATCK_PUTLINE_LEN] = { 0 };
    text_t callstack_text;
    int iret_snprintf = 0;
    debug_control_t *dbg_ctl = NULL;
    status_t status = CT_SUCCESS;

    cm_str2text(buffer, &callstack_text);
    CT_RETSUC_IFTRUE(wait_time == 0);

    CM_SPIN_LOCK_CTL(session);
    do {
        if (pld_get_target_session_debug_info(stmt, session->dbg_ctl->target_id, &dbg_ctl, NULL) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }
        if (dbg_ctl->status == DBG_WAITING || dbg_ctl->status == DBG_IDLE) {
            break;
        }
        cm_spin_unlock_if_exists(&session->dbg_ctl_lock);
        cm_spin_unlock_if_exists(session->dbg_ctl->target_lock);
        cm_sleep(100); // wait 100 ms
        CM_SPIN_LOCK_CTL(session);
        wait_time--;
    } while (wait_time > 0);
    if (wait_time == 0) {
        CT_THROW_ERROR(ERR_DEBUG_TIMEOUT);
        status = CT_ERROR;
    }
    if (status == CT_SUCCESS) {
        dbg_callstack_info_t *callstack_info = &dbg_ctl->callstack_info[dbg_ctl->max_stack_id - 1];
        if (dbg_ctl->status == DBG_IDLE) {
            iret_snprintf = snprintf_s(buffer, SQL_CALLSATCK_PUTLINE_LEN, SQL_CALLSATCK_PUTLINE_LEN - 1, "#IDLE");
        } else if (callstack_info->object_len == 0) {
            iret_snprintf =
                snprintf_s(buffer, SQL_CALLSATCK_PUTLINE_LEN, SQL_CALLSATCK_PUTLINE_LEN - 1, "#%u: ANONYMOUS BLOCK :%u",
                dbg_ctl->max_stack_id, ((pl_executor_t *)callstack_info->exec)->curr_line->loc.line);
        } else {
            iret_snprintf = snprintf_s(buffer, SQL_CALLSATCK_PUTLINE_LEN, SQL_CALLSATCK_PUTLINE_LEN - 1, "#%u: %s.%s :%u",
                dbg_ctl->max_stack_id, callstack_info->owner, callstack_info->object,
                ((pl_executor_t *)callstack_info->exec)->curr_line->loc.line);
        }
    }
    cm_spin_unlock_if_exists(&session->dbg_ctl_lock);
    cm_spin_unlock_if_exists(session->dbg_ctl->target_lock);
    CT_RETURN_IFERR(status);
    PRTS_RETURN_IFERR(iret_snprintf);
    callstack_text.len = iret_snprintf;
    return pl_sender->send_serveroutput(stmt, &callstack_text);
}

status_t sql_debug_resume(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    variant_t brk_flag, wait_time;
    session_t *session = stmt->session;
    status_t ret = CT_ERROR;
    debug_control_t *debug_ctl = NULL;

    // get func argument
    expr_tree_t *arg1 = func->argument;
    CT_RETURN_IFERR(sql_exec_dbgfunc_arg(stmt, arg1, &brk_flag, CT_TYPE_INTEGER, CT_TRUE));
    if (brk_flag.v_int < BRK_NEXT_LINE || brk_flag.v_int >= BRK_END) {
        CT_THROW_ERROR(ERR_PARAM_VALUE_OUT_RANGE);
        return CT_ERROR;
    }
    expr_tree_t *arg2 = arg1->next;
    CT_RETURN_IFERR(sql_exec_dbgfunc_arg(stmt, arg2, &wait_time, CT_TYPE_INTEGER, CT_TRUE));
    PKG_RETURN_IF_INT_NEGATIVE(wait_time);

    PKG_RETURN_IF_NOT_DEBUG_SESSION(session);

    cm_spin_lock_if_exists(session->dbg_ctl->target_lock, NULL);
    cm_spin_lock_if_exists(&session->dbg_ctl_lock, NULL);
    do {
        if (pld_get_target_session_debug_info(stmt, session->dbg_ctl->target_id, &debug_ctl, NULL) != CT_SUCCESS) {
            break;
        }
        if (!pld_has_privilege(session, &debug_ctl->debug_user, NULL)) {
            CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            break;
        }
        if (debug_ctl->status != DBG_WAITING) {
            CT_THROW_ERROR(ERR_DEBUG_SESSION_STATUS, "WAITING", "IDLE or EXECUTING or PRE_WAIT");
            break;
        }
        // set target session's ctl param
        debug_ctl->status = DBG_EXECUTING;
        debug_ctl->curr_count = 0;
        debug_ctl->brk_flag_stack_id = debug_ctl->max_stack_id;
        debug_ctl->brk_flag = brk_flag.v_int;
        ret = CT_SUCCESS;
    } while (0);
    cm_spin_unlock_if_exists(&session->dbg_ctl_lock);
    cm_spin_unlock_if_exists(session->dbg_ctl->target_lock);
    CT_RETURN_IFERR(ret);
    return sql_debug_try_for_waiting(stmt, wait_time.v_int);
}

status_t sql_verify_debug_resume(sql_verifier_t *verif, expr_node_t *func)
{
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;

    CT_RETURN_IFERR(sql_verify_func_node(verif, func, 2, 2, CT_INVALID_ID32)); // function needs to verify 2 args

    arg1 = func->argument;
    PKG_RETURN_IF_NOT_INTEGER(arg1->loc, TREE_DATATYPE(arg1));
    arg2 = arg1->next;
    PKG_RETURN_IF_NOT_INTEGER(arg2->loc, TREE_DATATYPE(arg2));
    return CT_SUCCESS;
}

status_t sql_debug_set_break(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    session_t *session = stmt->session;
    debug_control_t *target_ctl = NULL;
    status_t status = CT_ERROR;
    variant_t brk_id, enable;

    PKG_RETURN_IF_NOT_DEBUG_SESSION(session);
    expr_tree_t *arg1 = func->argument;
    expr_tree_t *arg2 = func->argument->next;
    CT_RETURN_IFERR(sql_exec_dbgfunc_arg(stmt, arg1, &brk_id, CT_TYPE_INTEGER, CT_TRUE));
    CT_RETURN_IFERR(sql_exec_dbgfunc_arg(stmt, arg2, &enable, CT_TYPE_INTEGER, CT_TRUE));
    if (brk_id.v_int <= 0 || (enable.v_int != 1 && enable.v_int != 0)) {
        CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "invalid argument for ENABLE_BREAK function");
        return CT_ERROR;
    }
    cm_spin_lock_if_exists(session->dbg_ctl->target_lock, NULL);
    cm_spin_lock_if_exists(&session->dbg_ctl_lock, NULL);
    do {
        CT_BREAK_IF_ERROR(pld_get_target_session_debug_info(stmt, session->dbg_ctl->target_id, &target_ctl, NULL));
        if (!pld_has_privilege(session, &target_ctl->debug_user, NULL)) {
            CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            break;
        }
        if ((target_ctl->status == DBG_EXECUTING) || (target_ctl->status == DBG_PRE_WAIT)) {
            CT_THROW_ERROR(ERR_DEBUG_SESSION_STATUS, "IDLE or WAITING", "EXECUTING or PRE_WAIT");
            break;
        }
        if ((uint32)brk_id.v_int > target_ctl->max_break_id) {
            CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "the breakpoint id is out of range");
            break;
        }
        if (!sql_debug_check_break_valid(target_ctl, (uint32)brk_id.v_int)) {
            CT_THROW_ERROR(ERR_DEBUG_OPR_BREAK, brk_id.v_int, "the breakpoint id is not existing");
            break;
        }
        target_ctl->brk_info[brk_id.v_int - 1].is_enabled = (enable.v_int == 1);

        status = CT_SUCCESS;
    } while (0);
    cm_spin_unlock_if_exists(&session->dbg_ctl_lock);
    cm_spin_unlock_if_exists(session->dbg_ctl->target_lock);
    return status;
}

status_t sql_verify_debug_set_break(sql_verifier_t *verif, expr_node_t *func)
{
    if (sql_verify_func_node(verif, func, 2, 2, CT_INVALID_ID32) != CT_SUCCESS) { // function needs to verify 2 args
        return CT_ERROR;
    }
    expr_tree_t *arg1 = func->argument;       // arg1: breakpoint id
    expr_tree_t *arg2 = func->argument->next; // arg2: is_enable   0: disable  1:enable

    PKG_RETURN_IF_NOT_INTEGER(func->argument->loc, TREE_DATATYPE(arg1));
    PKG_RETURN_IF_NOT_INTEGER(func->argument->loc, TREE_DATATYPE(arg2));
    return CT_SUCCESS;
}

status_t sql_debug_set_curr_count(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    session_t *session = stmt->session;
    debug_control_t *debug_ctl = NULL;
    status_t status;
    expr_tree_t *arg = NULL;
    variant_t value;

    arg = func->argument;
    CT_RETURN_IFERR(sql_exec_dbgfunc_arg(stmt, arg, &value, CT_TYPE_INTEGER, CT_TRUE));
    PKG_RETURN_IF_INT_NEGATIVE(value);
    SQL_SET_NULL_VAR(result);

    PKG_RETURN_IF_NOT_DEBUG_SESSION(session);

    status = CT_ERROR;
    cm_spin_lock_if_exists(session->dbg_ctl->target_lock, NULL);
    cm_spin_lock_if_exists(&session->dbg_ctl_lock, NULL);
    do {
        CT_BREAK_IF_ERROR(pld_get_target_session_debug_info(stmt, session->dbg_ctl->target_id, &debug_ctl, NULL));
        if (!pld_has_privilege(session, &debug_ctl->debug_user, NULL)) {
            CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            break;
        }

        debug_ctl->curr_count = (uint32)value.v_int < debug_ctl->timeout ? value.v_int : debug_ctl->timeout;
        status = CT_SUCCESS;
    } while (0);
    cm_spin_unlock_if_exists(&session->dbg_ctl_lock);
    cm_spin_unlock_if_exists(session->dbg_ctl->target_lock);
    return status;
}

status_t sql_verify_debug_set_curr_count(sql_verifier_t *verif, expr_node_t *func)
{
    expr_tree_t *arg = NULL;

    CT_RETURN_IFERR(sql_verify_func_node(verif, func, 1, 1, CT_INVALID_ID32));

    arg = func->argument;
    PKG_RETURN_IF_NOT_INTEGER(arg->loc, TREE_DATATYPE(arg));

    return CT_SUCCESS;
}

static status_t sql_debug_set_value_prepare(sql_stmt_t *stmt, expr_node_t *func, pld_var_info_t *var_info,
    variant_t *value)
{
    variant_t stack_id, block, id, offset;
    expr_tree_t *arg1 = func->argument;
    CT_RETURN_IFERR(sql_exec_dbgfunc_arg(stmt, arg1, &stack_id, CT_TYPE_INTEGER, CT_TRUE));
    PKG_RETURN_IF_INT_NEGATIVE(stack_id);
    expr_tree_t *arg2 = arg1->next;
    CT_RETURN_IFERR(sql_exec_dbgfunc_arg(stmt, arg2, &block, CT_TYPE_INTEGER, CT_TRUE));
    PKG_RETURN_IF_INT_NEGATIVE(block);
    expr_tree_t *arg3 = arg2->next;
    CT_RETURN_IFERR(sql_exec_dbgfunc_arg(stmt, arg3, &id, CT_TYPE_INTEGER, CT_TRUE));
    PKG_RETURN_IF_INT_NEGATIVE(id);
    expr_tree_t *arg4 = arg3->next;
    CT_RETURN_IFERR(sql_exec_dbgfunc_arg(stmt, arg4, &offset, CT_TYPE_INTEGER, CT_TRUE));
    PKG_RETURN_IF_INT_NEGATIVE(offset);
    expr_tree_t *arg5 = arg4->next;
    CT_RETURN_IFERR(sql_exec_dbgfunc_arg(stmt, arg5, value, CT_TYPE_STRING, CT_TRUE));
    sql_keep_stack_variant(stmt, value);

    var_info->stack_id = stack_id.v_int;
    var_info->block_id = block.v_int;
    var_info->id = id.v_int;
    var_info->m_offset = offset.v_int;
    return CT_SUCCESS;
}

static status_t sql_debug_set_value_complex(sql_stmt_t *stmt, debug_control_t *dbg_ctl, pld_var_info_t *var_info,
    variant_t *value)
{
    if (var_info->attr->type != UDT_SCALAR) {
        CT_THROW_ERROR(ERR_UNEXPECTED_PL_VARIANT);
        return CT_ERROR;
    }

    if (var_info->is_obj) {
        CT_RETURN_IFERR(pld_object_field_write(stmt, dbg_ctl, var_info, value));
    } else {
        CT_RETURN_IFERR(pld_record_field_write(stmt, dbg_ctl, var_info, value));
    }
    return CT_SUCCESS;
}

static status_t sql_debug_set_value_core(sql_stmt_t *stmt, session_t *session, variant_t *value,
    pld_var_info_t *var_info)
{
    debug_control_t *dbg_ctl = NULL;
    status_t status = CT_ERROR;
    pld_set_var_t set_var;
    bool32 eof = CT_FALSE;
    bool32 is_found = CT_FALSE;

    cm_spin_lock_if_exists(session->dbg_ctl->target_lock, NULL);
    cm_spin_lock_if_exists(&session->dbg_ctl_lock, NULL);
    do {
        CT_BREAK_IF_ERROR(pld_get_target_session_debug_info(stmt, session->dbg_ctl->target_id, &dbg_ctl, NULL));

        if (dbg_ctl->status != DBG_WAITING) {
            CT_THROW_ERROR(ERR_DEBUG_SESSION_STATUS, "WAITING", "IDLE or EXECUTING or PRE_WAIT");
            break;
        }

        if (var_info->stack_id == 0 || var_info->stack_id >= dbg_ctl->max_stack_id) {
            var_info->stack_id = dbg_ctl->max_stack_id;
        }
        if (!pld_has_privilege(session, &dbg_ctl->debug_user, dbg_ctl->callstack_info[var_info->stack_id - 1].exec)) {
            CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            break;
        }
        var_info->total_field = NULL;
        var_info->total_attr = NULL;
        var_info->obj_total_field = NULL;
        var_info->obj_total_attr = NULL;
        var_info->total_parent_name = NULL;
        CT_BREAK_IF_ERROR(pld_get_var_info(stmt, dbg_ctl, var_info, &is_found, &eof));
        if (!is_found) {
            CT_THROW_ERROR(ERR_UNEXPECTED_PL_VARIANT);
            break;
        }
        if (var_info->is_attr_in_vm) {
            CT_BREAK_IF_ERROR(sql_debug_set_value_complex(stmt, dbg_ctl, var_info, value));
        } else {
            set_var.src = value;
            set_var.dst = var_info->set_value;
            set_var.type = var_info->type;
            CT_BREAK_IF_ERROR(pld_set_var(stmt, &set_var));
        }

        status = CT_SUCCESS;
    } while (0);
    cm_spin_unlock_if_exists(&session->dbg_ctl_lock);
    cm_spin_unlock_if_exists(session->dbg_ctl->target_lock);
    return status;
}

status_t sql_debug_set_value(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    session_t *session = stmt->session;
    status_t status;
    variant_t val;
    pld_var_info_t var_info;

    PKG_RETURN_IF_NOT_DEBUG_SESSION(session);

    CTSQL_SAVE_STACK(stmt);
    if (sql_debug_set_value_prepare(stmt, func, &var_info, &val) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    SQL_SET_NULL_VAR(result);

    status = sql_debug_set_value_core(stmt, session, &val, &var_info);

    CTSQL_RESTORE_STACK(stmt);
    return status;
}

#define ARG_NUM_FOR_SET_VALUE 5

status_t sql_verify_debug_set_value(sql_verifier_t *verif, expr_node_t *func)
{
    expr_tree_t *arg1 = NULL;
    expr_tree_t *arg2 = NULL;
    expr_tree_t *arg3 = NULL;
    expr_tree_t *arg4 = NULL;
    expr_tree_t *arg5 = NULL;

    CT_RETURN_IFERR(sql_verify_func_node(verif, func, ARG_NUM_FOR_SET_VALUE, ARG_NUM_FOR_SET_VALUE, CT_INVALID_ID32));

    arg1 = func->argument;
    PKG_RETURN_IF_NOT_INTEGER(arg1->loc, TREE_DATATYPE(arg1));
    arg2 = arg1->next;
    PKG_RETURN_IF_NOT_INTEGER(arg2->loc, TREE_DATATYPE(arg2));
    arg3 = arg2->next;
    PKG_RETURN_IF_NOT_INTEGER(arg3->loc, TREE_DATATYPE(arg3));
    arg4 = arg3->next;
    PKG_RETURN_IF_NOT_INTEGER(arg4->loc, TREE_DATATYPE(arg4));
    arg5 = arg4->next;
    PKG_RETURN_IF_NOT_STRING(arg5->loc, TREE_DATATYPE(arg5));

    return CT_SUCCESS;
}

status_t sql_debug_terminate(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    session_t *session = stmt->session;
    debug_control_t *debug_ctl = NULL;
    status_t status;
    SQL_SET_NULL_VAR(result);

    PKG_RETURN_IF_NOT_DEBUG_SESSION(session);

    status = CT_ERROR;
    cm_spin_lock_if_exists(session->dbg_ctl->target_lock, NULL);
    cm_spin_lock_if_exists(&session->dbg_ctl_lock, NULL);
    do {
        CT_BREAK_IF_ERROR(pld_get_target_session_debug_info(stmt, session->dbg_ctl->target_id, &debug_ctl, NULL));
        if (!pld_has_privilege(session, &debug_ctl->debug_user, NULL)) {
            CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            break;
        }
        if (debug_ctl->status != DBG_EXECUTING) {
            CT_THROW_ERROR(ERR_DEBUG_SESSION_STATUS, "EXECUTING", "IDLE or WAITING or PRE_WAIT");
            break;
        }

        debug_ctl->is_force_terminate = CT_TRUE;
        status = CT_SUCCESS;
    } while (0);
    cm_spin_unlock_if_exists(&session->dbg_ctl_lock);
    cm_spin_unlock_if_exists(session->dbg_ctl->target_lock);
    return status;
}

status_t sql_debug_uninit(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    session_t *session = stmt->session;
    uint32 session_id = session->knl_session.id;

    if ((!session->dbg_ctl) || (session->dbg_ctl->type != TARGET_SESSION)) {
        CT_THROW_ERROR(ERR_DEBUG_SESSION_TYPE, "target session", session_id);
        return CT_ERROR;
    }

    cm_spin_lock_if_exists(&session->dbg_ctl_lock, NULL);
    if (session->dbg_ctl->is_attached == CT_TRUE) {
        CT_THROW_ERROR(ERR_DEBUG_CAN_NOT_UNINIT, "target session is attached");
        cm_spin_unlock_if_exists(&session->dbg_ctl_lock);
        return CT_ERROR;
    }

    srv_free_dbg_ctl(session);
    cm_spin_unlock_if_exists(&session->dbg_ctl_lock);
    return CT_SUCCESS;
}

status_t sql_debug_update_break(sql_stmt_t *stmt, expr_node_t *func, variant_t *result)
{
    session_t *session = stmt->session;
    variant_t break_id, skip_times;
    debug_control_t *target_ctl = NULL;
    status_t status = CT_ERROR;

    PKG_RETURN_IF_NOT_DEBUG_SESSION(session);
    expr_tree_t *arg1 = func->argument;
    expr_tree_t *arg2 = func->argument->next;

    CT_RETURN_IFERR(sql_exec_dbgfunc_arg(stmt, arg1, &break_id, CT_TYPE_INTEGER, CT_TRUE));
    CT_RETURN_IFERR(sql_exec_dbgfunc_arg(stmt, arg2, &skip_times, CT_TYPE_INTEGER, CT_TRUE));
    if (break_id.v_int <= 0 || (skip_times.v_int < 0)) {
        CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "invalid argument for UPDATE_BREAK function");
        return CT_ERROR;
    }
    cm_spin_lock_if_exists(session->dbg_ctl->target_lock, NULL);
    cm_spin_lock_if_exists(&session->dbg_ctl_lock, NULL);
    do {
        CT_BREAK_IF_ERROR(pld_get_target_session_debug_info(stmt, session->dbg_ctl->target_id, &target_ctl, NULL));
        if (!pld_has_privilege(session, &target_ctl->debug_user, NULL)) {
            CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
            break;
        }
        if ((target_ctl->status == DBG_EXECUTING) || (target_ctl->status == DBG_PRE_WAIT)) {
            CT_THROW_ERROR(ERR_DEBUG_SESSION_STATUS, "IDLE or WAITING", "EXECUTING or PRE_WAIT");
            break;
        }
        if ((uint32)break_id.v_int > target_ctl->max_break_id) {
            CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "the breakpoint id is out of range");
            break;
        }
        if (sql_debug_check_break_valid(target_ctl, (uint32)break_id.v_int) == CT_FALSE) {
            CT_THROW_ERROR(ERR_DEBUG_OPR_BREAK, break_id.v_int, "the breakpoint id is not existing");
            break;
        }
        target_ctl->brk_info[break_id.v_int - 1].max_skip_times = (uint32)skip_times.v_int;
        target_ctl->brk_info[break_id.v_int - 1].skipped_times = 0;

        status = CT_SUCCESS;
    } while (0);
    cm_spin_unlock_if_exists(&session->dbg_ctl_lock);
    cm_spin_unlock_if_exists(session->dbg_ctl->target_lock);
    return status;
}

status_t sql_verify_debug_update_break(sql_verifier_t *verif, expr_node_t *func)
{
    if (sql_verify_func_node(verif, func, 2, 2, CT_INVALID_ID32) != CT_SUCCESS) { // function needs to verify 2 args
        return CT_ERROR;
    }
    expr_tree_t *arg1 = func->argument;       // arg1: breakpoint id
    expr_tree_t *arg2 = func->argument->next; // arg2: breakpoint skip_times

    PKG_RETURN_IF_NOT_INTEGER(func->argument->loc, TREE_DATATYPE(arg1));
    PKG_RETURN_IF_NOT_INTEGER(func->argument->loc, TREE_DATATYPE(arg2));
    return CT_SUCCESS;
}
