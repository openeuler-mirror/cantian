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
 * pl_dbg_tab_func.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/debug/pl_dbg_tab_func.c
 *
 * -------------------------------------------------------------------------
 */
#include "pl_dbg_tab_func.h"

#define DBG_PLE_MAX_BLOCK_DEPTH (PL_MAX_BLOCK_DEPTH * 2)

char g_line_type_name[LINE_TYPE_NUM][LINE_TYPE_NAME_MAXLEN] = {
    "LINE_UNKNOWN",
    "LINE_BEGIN",
    "LINE_END",
    "LINE_END_IF",
    "LINE_END_LOOP",
    "LINE_EXCEPTION",
    "LINE_SETVAL",
    "LINE_IF",
    "LINE_ELIF",
    "LINE_ELSE",
    "LINE_FOR",
    "LINE_LOOP",
    "LINE_GOTO",
    "LINE_EXEC",
    "LINE_FETCH",
    "LINE_OPEN",
    "LINE_WHEN",
    "LINE_CLOSE",
    "LINE_NULL",
    "LINE_SQL",
    "LINE_PUTLINE",
    "LINE_CASE",
    "LINE_WHEN_CASE",
    "LINE_END_CASE",
    "LINE_EXIT",
    "LINE_LABEL",
    "LINE_CONTINUE",
    "LINE_WHILE",
    "LINE_RAISE",
    "LINE_COMMIT",
    "LINE_ROLLBACK",
    "LINE_SAVEPOINT",
    "LINE_PROC",
    "LINE_RETURN",
    "LINE_EXECUTE",
    "LINE_END_WHEN",
    "LINE_END_EXCEPTION",
};

void proc_decode_get_max_line_num(pl_line_ctrl_t *entry, uint32 *max_line_num)
{
    pl_line_ctrl_t *temp_line = entry;
    uint32 tmp_line_num = 0;

    while (temp_line != NULL) {
        temp_line = temp_line->next;
        tmp_line_num++;
    }

    *max_line_num = tmp_line_num;
}

void proc_decode_default_sp(pl_line_ctrl_t *line, dba_proc_decode_t *decode_item, dba_proc_buf_info_t *buf_info)
{
    uint32 line_type;

    decode_item->loc_line = line->loc.line;
    line_type = ((line->type == LINE_UNKNOWN) || (line->type >= LINE_TYPE_NUM)) ? 0 : line->type;
    MEMS_RETVOID_IFERR(strncpy_s(decode_item->type_name, LINE_TYPE_NAME_MAXLEN, g_line_type_name[line_type],
        strlen(g_line_type_name[line_type])));
    decode_item->sp_instruction.str = NULL;
    decode_item->sp_instruction.len = 0;
}

static void proc_decode_get_line_num(pl_line_ctrl_t *entry, pl_line_ctrl_t *line, uint32 *line_num)
{
    pl_line_ctrl_t *temp_line = entry;
    uint32 tmp_line_num = 0;

    while (temp_line != NULL) {
        if (line == temp_line) {
            *line_num = tmp_line_num + 1;
            return;
        }

        temp_line = temp_line->next;
        tmp_line_num++;
    }

    *line_num = CT_INVALID_ID32;
}

static void proc_decode_reform_lineinfo(dba_proc_buf_info_t *buf_info, const char *line_name, uint32 line_num)
{
    int iret_snprintf;
    char *tmp_buf = buf_info->buf + buf_info->offset;
    uint32 tmp_buf_len = buf_info->max_size - buf_info->offset;

    if (buf_info->is_full == CT_TRUE) {
        return;
    }

    if (line_num != CT_INVALID_ID32) {
        iret_snprintf = snprintf_s(tmp_buf, tmp_buf_len, tmp_buf_len - 1, "%s[%u];", line_name, line_num);
    } else {
        iret_snprintf = snprintf_s(tmp_buf, tmp_buf_len, tmp_buf_len - 1, "%s[null];", line_name);
    }

    if (iret_snprintf == -1) {
        buf_info->is_full = CT_TRUE;
        return;
    }

    buf_info->offset += iret_snprintf;
}

static void proc_decode_line_info_sp(pl_line_ctrl_t *entry, dba_proc_line_info_t *line_info, uint32 size,
    dba_proc_buf_info_t *buf_info)
{
    uint32 line_number;
    for (uint32 i = 0; i < size; i++) {
        proc_decode_get_line_num(entry, line_info[i].line, &line_number);
        proc_decode_reform_lineinfo(buf_info, line_info[i].name, line_number);
    }
}

static void proc_decode_reform_full(dba_proc_buf_info_t *buf_info)
{
    const char *end_str = " ......";
    const uint32 end_str_len = (uint32)strlen(end_str);
    char *temp_buf = NULL;
    uint32 tmp_buf_len = buf_info->max_size - buf_info->offset;
    uint32 back_pos;

    if (buf_info->is_full == CT_FALSE) {
        return;
    }

    if (tmp_buf_len >= (end_str_len + 1)) {
        back_pos = 0;
    } else {
        back_pos = end_str_len + 1 - tmp_buf_len;
    }
    temp_buf = buf_info->buf + buf_info->offset - back_pos;
    tmp_buf_len += back_pos;
    MEMS_RETVOID_IFERR(strncpy_s(temp_buf, tmp_buf_len, end_str, end_str_len));
}

void proc_decode_begin_sp(pl_line_ctrl_t *entry, pl_line_ctrl_t *line, dba_proc_decode_t *decode_item,
    dba_proc_buf_info_t *buf_info)
{
    pl_line_begin_t *begin_ln = (pl_line_begin_t *)line;
    dba_proc_line_info_t begin_ln_info[] = {
        { begin_ln->except, "except" },
        { begin_ln->end, "end" },
    };

    decode_item->sp_instruction.str = buf_info->buf + buf_info->offset;
    proc_decode_line_info_sp(entry, begin_ln_info, sizeof(begin_ln_info) / sizeof(dba_proc_line_info_t), buf_info);
    proc_decode_reform_full(buf_info);
    decode_item->sp_instruction.len = (uint32)(buf_info->buf + buf_info->offset - decode_item->sp_instruction.str);
}

void proc_decode_if_sp(pl_line_ctrl_t *entry, pl_line_ctrl_t *line, dba_proc_decode_t *decode_item,
    dba_proc_buf_info_t *buf_info)
{
    pl_line_if_t *if_ln = (pl_line_if_t *)line;
    dba_proc_line_info_t if_ln_info[] = {
        { if_ln->t_line, "t_line" },
        { if_ln->f_line, "f_line" },
        { if_ln->next, "next" },
    };

    decode_item->sp_instruction.str = buf_info->buf + buf_info->offset;
    proc_decode_line_info_sp(entry, if_ln_info, sizeof(if_ln_info) / sizeof(dba_proc_line_info_t), buf_info);
    proc_decode_reform_full(buf_info);
    decode_item->sp_instruction.len = (uint32)(buf_info->buf + buf_info->offset - decode_item->sp_instruction.str);
}

void proc_decode_else_sp(pl_line_ctrl_t *entry, pl_line_ctrl_t *line, dba_proc_decode_t *decode_item,
    dba_proc_buf_info_t *buf_info)
{
    pl_line_else_t *else_ln = (pl_line_else_t *)line;
    dba_proc_line_info_t else_ln_info[] = {
        { (pl_line_ctrl_t *)else_ln->if_line, "if_line" },
    };

    decode_item->sp_instruction.str = buf_info->buf + buf_info->offset;
    proc_decode_line_info_sp(entry, else_ln_info, sizeof(else_ln_info) / sizeof(dba_proc_line_info_t), buf_info);
    proc_decode_reform_full(buf_info);
    decode_item->sp_instruction.len = (uint32)(buf_info->buf + buf_info->offset - decode_item->sp_instruction.str);
}

void proc_decode_elsif_sp(pl_line_ctrl_t *entry, pl_line_ctrl_t *line, dba_proc_decode_t *decode_item,
    dba_proc_buf_info_t *buf_info)
{
    pl_line_elsif_t *elsif_ln = (pl_line_elsif_t *)line;
    dba_proc_line_info_t elsif_ln_info[] = {
        { elsif_ln->t_line, "t_line" },
        { elsif_ln->f_line, "f_line" },
        { elsif_ln->next, "next" },
        { (pl_line_ctrl_t *)elsif_ln->if_line, "if_line" },
    };

    decode_item->sp_instruction.str = buf_info->buf + buf_info->offset;
    proc_decode_line_info_sp(entry, elsif_ln_info, sizeof(elsif_ln_info) / sizeof(dba_proc_line_info_t), buf_info);
    proc_decode_reform_full(buf_info);
    decode_item->sp_instruction.len = (uint32)(buf_info->buf + buf_info->offset - decode_item->sp_instruction.str);
}

void proc_decode_when_case_sp(pl_line_ctrl_t *entry, pl_line_ctrl_t *line, dba_proc_decode_t *decode_item,
    dba_proc_buf_info_t *buf_info)
{
    pl_line_when_case_t *when_case_ln = (pl_line_when_case_t *)line;
    dba_proc_line_info_t when_case_ln_info[] = {
        { when_case_ln->t_line, "t_line" },
        { when_case_ln->f_line, "f_line" },
        { when_case_ln->next, "next" },
        { (pl_line_ctrl_t *)when_case_ln->if_line, "if_line" },
    };

    decode_item->sp_instruction.str = buf_info->buf + buf_info->offset;
    proc_decode_line_info_sp(entry, when_case_ln_info, sizeof(when_case_ln_info) / sizeof(dba_proc_line_info_t),
        buf_info);
    proc_decode_reform_full(buf_info);
    decode_item->sp_instruction.len = (uint32)(buf_info->buf + buf_info->offset - decode_item->sp_instruction.str);
}

void proc_decode_end_loop_sp(pl_line_ctrl_t *entry, pl_line_ctrl_t *line, dba_proc_decode_t *decode_item,
    dba_proc_buf_info_t *buf_info)
{
    pl_line_end_loop_t *end_loop_ln = (pl_line_end_loop_t *)line;
    dba_proc_line_info_t end_loop_ln_info[] = {
        { end_loop_ln->loop, "loop" },
    };

    decode_item->sp_instruction.str = buf_info->buf + buf_info->offset;
    proc_decode_line_info_sp(entry, end_loop_ln_info, sizeof(end_loop_ln_info) / sizeof(dba_proc_line_info_t),
        buf_info);
    proc_decode_reform_full(buf_info);
    decode_item->sp_instruction.len = (uint32)(buf_info->buf + buf_info->offset - decode_item->sp_instruction.str);
}

void proc_decode_exit_sp(pl_line_ctrl_t *entry, pl_line_ctrl_t *line, dba_proc_decode_t *decode_item,
    dba_proc_buf_info_t *buf_info)
{
    pl_line_exit_t *exit_ln = (pl_line_exit_t *)line;
    dba_proc_line_info_t exit_ln_info[] = {
        { exit_ln->next, "next" },
    };

    decode_item->sp_instruction.str = buf_info->buf + buf_info->offset;
    proc_decode_line_info_sp(entry, exit_ln_info, sizeof(exit_ln_info) / sizeof(dba_proc_line_info_t), buf_info);
    proc_decode_reform_full(buf_info);
    decode_item->sp_instruction.len = (uint32)(buf_info->buf + buf_info->offset - decode_item->sp_instruction.str);
}

void proc_decode_goto_sp(pl_line_ctrl_t *entry, pl_line_ctrl_t *line, dba_proc_decode_t *decode_item,
    dba_proc_buf_info_t *buf_info)
{
    pl_line_goto_t *goto_ln = (pl_line_goto_t *)line;
    dba_proc_line_info_t goto_ln_info[] = {
        { goto_ln->next, "next" },
    };

    decode_item->sp_instruction.str = buf_info->buf + buf_info->offset;
    proc_decode_line_info_sp(entry, goto_ln_info, sizeof(goto_ln_info) / sizeof(dba_proc_line_info_t), buf_info);
    proc_decode_reform_full(buf_info);
    decode_item->sp_instruction.len = (uint32)(buf_info->buf + buf_info->offset - decode_item->sp_instruction.str);
}

void proc_decode_continue_sp(pl_line_ctrl_t *entry, pl_line_ctrl_t *line, dba_proc_decode_t *decode_item,
    dba_proc_buf_info_t *buf_info)
{
    pl_line_continue_t *continue_ln = (pl_line_continue_t *)line;
    dba_proc_line_info_t continue_ln_info[] = {
        { continue_ln->next, "next" },
    };

    decode_item->sp_instruction.str = buf_info->buf + buf_info->offset;
    proc_decode_line_info_sp(entry, continue_ln_info, sizeof(continue_ln_info) / sizeof(dba_proc_line_info_t),
        buf_info);
    proc_decode_reform_full(buf_info);
    decode_item->sp_instruction.len = (uint32)(buf_info->buf + buf_info->offset - decode_item->sp_instruction.str);
}

void proc_decode_while_sp(pl_line_ctrl_t *entry, pl_line_ctrl_t *line, dba_proc_decode_t *decode_item,
    dba_proc_buf_info_t *buf_info)
{
    pl_line_while_t *while_ln = (pl_line_while_t *)line;
    dba_proc_line_info_t while_ln_info[] = {
        { while_ln->next, "next" },
        { while_ln->stack_line, "stack_line" },
    };

    decode_item->sp_instruction.str = buf_info->buf + buf_info->offset;
    proc_decode_line_info_sp(entry, while_ln_info, sizeof(while_ln_info) / sizeof(dba_proc_line_info_t), buf_info);
    proc_decode_reform_full(buf_info);
    decode_item->sp_instruction.len = (uint32)(buf_info->buf + buf_info->offset - decode_item->sp_instruction.str);
}

void proc_decode_for_sp(pl_line_ctrl_t *entry, pl_line_ctrl_t *line, dba_proc_decode_t *decode_item,
    dba_proc_buf_info_t *buf_info)
{
    pl_line_for_t *for_ln = (pl_line_for_t *)line;
    dba_proc_line_info_t for_ln_info[] = {
        { for_ln->next, "next" },
    };

    decode_item->sp_instruction.str = buf_info->buf + buf_info->offset;
    proc_decode_line_info_sp(entry, for_ln_info, sizeof(for_ln_info) / sizeof(dba_proc_line_info_t), buf_info);
    proc_decode_reform_full(buf_info);
    decode_item->sp_instruction.len = (uint32)(buf_info->buf + buf_info->offset - decode_item->sp_instruction.str);
}

void proc_decode_except_sp(pl_line_ctrl_t *entry, pl_line_ctrl_t *line, dba_proc_decode_t *decode_item,
    dba_proc_buf_info_t *buf_info)
{
    pl_line_except_t *except_ln = (pl_line_except_t *)line;
    dba_proc_line_info_t except_ln_info[] = {
        { except_ln->end, "end" },
    };

    decode_item->sp_instruction.str = buf_info->buf + buf_info->offset;
    proc_decode_line_info_sp(entry, except_ln_info, sizeof(except_ln_info) / sizeof(dba_proc_line_info_t), buf_info);
    proc_decode_reform_full(buf_info);
    decode_item->sp_instruction.len = (uint32)(buf_info->buf + buf_info->offset - decode_item->sp_instruction.str);
}

void dba_proc_line_add_head(char *buf, uint32 buf_len, char type, text_t *object, uint16 *used_len)
{
    int iret_snprintf = 0;
    char obj_buf[CT_NAME_BUFFER_SIZE] = { 0 };

    (void)cm_text2str(object, obj_buf, CT_NAME_BUFFER_SIZE);

    switch (type) {
        case 'F':
            iret_snprintf = snprintf_s(buf, buf_len, buf_len - 1, "CREATE OR REPLACE FUNCTION %s ", obj_buf);
            break;
        case 'P':
            iret_snprintf = snprintf_s(buf, buf_len, buf_len - 1, "CREATE OR REPLACE PROCEDURE %s ", obj_buf);
            break;
        case 'T':
            iret_snprintf = snprintf_s(buf, buf_len, buf_len - 1, "CREATE OR REPLACE TRIGGER %s ", obj_buf);
            break;
        default:
            break;
    }
    PRTS_RETVOID_IFERR(iret_snprintf);
    *used_len = iret_snprintf;
}

static status_t dbg_break_info_get_valid_status(sql_stmt_t *stmt, debug_control_t *target_ctl,
    dbg_breakpoint_info_t *breakinfo, knl_scn_t scn)
{
    plm_find_pldesc_t find_pldesc;
    pl_dc_t pl_dc = { 0 };

    find_pldesc.v_udo.user = breakinfo->owner;
    find_pldesc.v_udo.name = breakinfo->object;
    find_pldesc.v_udo.pack.str = NULL;
    find_pldesc.v_udo.pack.len = 0;
    find_pldesc.type = breakinfo->pl_type;
    if (pld_open_proc_dc(stmt, target_ctl, &find_pldesc, &pl_dc) != CT_SUCCESS) {
        breakinfo->is_valid = CT_FALSE;
        cm_reset_error();
    } else {
        breakinfo->is_valid = (scn == pl_dc.org_scn);
        pl_dc_close(&pl_dc);
    }
    return CT_SUCCESS;
}

static status_t get_all_using_break_info(sql_stmt_t *stmt, debug_control_t *ctl, dbg_breakpoint_info_t *break_info)
{
    dbg_break_info_t *brk_info = ctl->brk_info;
    int32 j = 0;

    uint32 page_size, max_count;
    CT_RETURN_IFERR(knl_get_page_size((knl_handle_t)&stmt->session->knl_session, &page_size));
    max_count = page_size / sizeof(dbg_breakpoint_info_t);

    if (ctl->max_break_id > max_count) {
        CT_THROW_ERROR(ERR_TOO_MANY_OBJECTS, ctl->max_break_id, "debug procedure/function breakpoint max count");
        return CT_ERROR;
    }

    for (uint32 i = 1; i <= ctl->max_break_id; i++) {
        if (brk_info[i - 1].is_using) {
            break_info[j].break_id = i;
            break_info[j].cond.str = brk_info[i - 1].cond_str;
            break_info[j].cond.len = brk_info[i - 1].cond_str_len;
            break_info[j].is_enabled = brk_info[i - 1].is_enabled;
            break_info[j].loc_line = brk_info[i - 1].loc.line;
            break_info[j].max_skip = brk_info[i - 1].max_skip_times;
            break_info[j].object.str = brk_info[i - 1].object;
            break_info[j].object.len = brk_info[i - 1].object_len;
            break_info[j].owner.str = brk_info[i - 1].owner;
            break_info[j].owner.len = brk_info[i - 1].owner_len;
            break_info[j].pl_type = brk_info[i - 1].pl_type;
            CT_RETURN_IFERR(dbg_break_info_get_valid_status(stmt, ctl, &break_info[j], brk_info[i - 1].scn));
            j++;
        }
    }
    break_info[j].break_id = CT_INVALID_ID32;
    return CT_SUCCESS;
}

status_t get_break_info_by_id(sql_stmt_t *stmt, uint32 id, debug_control_t *ctl, dbg_breakpoint_info_t *break_info)
{
    dbg_break_info_t *brk_info = ctl->brk_info;
    // if id = 0, it means get all breakpoint info which are in using.
    if (id == 0) {
        return get_all_using_break_info(stmt, ctl, break_info);
    }

    if (id > ctl->max_break_id || brk_info[id - 1].is_using == CT_FALSE) {
        CT_THROW_ERROR(ERR_INVALID_FUNC_PARAMS, "invalid argument for table function");
        return CT_ERROR;
    }

    break_info[0].break_id = id;
    break_info[0].cond.str = brk_info[id - 1].cond_str;
    break_info[0].cond.len = brk_info[id - 1].cond_str_len;
    break_info[0].is_enabled = brk_info[id - 1].is_enabled;
    break_info[0].loc_line = brk_info[id - 1].loc.line;
    break_info[0].max_skip = brk_info[id - 1].max_skip_times;
    break_info[0].object.str = brk_info[id - 1].object;
    break_info[0].object.len = brk_info[id - 1].object_len;
    break_info[0].owner.str = brk_info[id - 1].owner;
    break_info[0].owner.len = brk_info[id - 1].owner_len;
    break_info[0].pl_type = brk_info[id - 1].pl_type;
    CT_RETURN_IFERR(dbg_break_info_get_valid_status(stmt, ctl, break_info, brk_info[id - 1].scn));
    break_info[1].break_id = CT_INVALID_ID32;
    return CT_SUCCESS;
}


status_t dbg_proc_callstack_prepare(sql_stmt_t *stmt, debug_control_t *debug_ctl, dbg_proc_callstack_t *stats,
    uint32 stack_id)
{
    uint32 line_type, curr_id, count;
    pld_exec_info_t exec_info;
    pl_line_ctrl_t *curr_line = NULL;
    uint32 page_size, max_count;

    if ((stack_id == 0) || (stack_id > debug_ctl->max_stack_id)) {
        curr_id = 0;
        count = debug_ctl->max_stack_id;
    } else {
        curr_id = stack_id - 1;
        count = 1;
    }

    CT_RETURN_IFERR(knl_get_page_size((knl_handle_t)&stmt->session->knl_session, &page_size));
    max_count = page_size / sizeof(dbg_proc_callstack_t);

    if (count > max_count) {
        CT_THROW_ERROR(ERR_TOO_MANY_OBJECTS, count, "debug procedure/function callstack max count");
        return CT_ERROR;
    }

    for (uint32 i = 0; i < count; i++) {
        stats[i].stack_id = curr_id + 1;
        stats[i].owner.str = debug_ctl->callstack_info[curr_id].owner;
        stats[i].owner.len = debug_ctl->callstack_info[curr_id].owner_len;
        stats[i].object.str = debug_ctl->callstack_info[curr_id].object;
        stats[i].object.len = debug_ctl->callstack_info[curr_id].object_len;
        if (stats[i].owner.len != 0 && stats[i].object.len != 0 &&
            pl_get_proc_id_by_name(stmt, &stats[i].owner, &stats[i].object, &stats[i].uid, &stats[i].oid) !=
            CT_SUCCESS) {
            return CT_ERROR;
        }
        exec_info.stack_id = curr_id + 1;
        CT_RETURN_IFERR(pld_parse_exec_info(debug_ctl, &exec_info));
        curr_line = exec_info.curr_line;
        stats[i].loc_line = curr_line->loc.line;
        line_type = (curr_line->type == LINE_UNKNOWN || curr_line->type >= LINE_TYPE_NUM) ? 0 : curr_line->type;
        stats[i].type_name.str = g_line_type_name[line_type];
        stats[i].type_name.len = (uint32)strlen(g_line_type_name[line_type]);
        curr_id++;
    }
    stats[count].stack_id = CT_INVALID_ID32;
    return CT_SUCCESS;
}

static void dbg_show_values_set_stats(dbg_show_values_t *val_set_stats, uint32 *var_num, pld_var_info_t *var_info)
{
    val_set_stats[*var_num].stack_id = var_info->stack_id;
    val_set_stats[*var_num].block = var_info->block_id;
    val_set_stats[*var_num].id = var_info->id;
    val_set_stats[*var_num].m_offset = var_info->m_offset;
    val_set_stats[*var_num].name = var_info->name;
    val_set_stats[*var_num].parent_name = var_info->parent_name;
    val_set_stats[*var_num].block_name = var_info->block_name;
    val_set_stats[*var_num].is_attr_in_vm = var_info->is_attr_in_vm;
    val_set_stats[*var_num].is_obj = var_info->is_obj;
    if (var_info->is_attr_in_vm) {
        if (var_info->is_obj) {
            val_set_stats[*var_num].obj_field = var_info->obj_field;
            val_set_stats[*var_num].obj_attr = var_info->obj_attr;
            val_set_stats[*var_num].obj_curr_stmt = var_info->obj_curr_stmt;
        } else {
            val_set_stats[*var_num].field = var_info->field;
            val_set_stats[*var_num].attr = var_info->attr;
            val_set_stats[*var_num].curr_stmt = var_info->curr_stmt;
        }
    } else {
        val_set_stats[*var_num].cur_info.is_open = var_info->cur_info.is_open;
        val_set_stats[*var_num].cur_info.has_fetched = var_info->cur_info.has_fetched;
        val_set_stats[*var_num].cur_info.is_found = var_info->cur_info.is_found;
        val_set_stats[*var_num].cur_info.rows = var_info->cur_info.rows;
        var_copy(&var_info->get_value, &val_set_stats[*var_num].value);
    }
}

static status_t dbg_show_values_get_vars(sql_stmt_t *stmt, debug_control_t *debug_ctl, dbg_show_values_t *stats,
    uint32 *var_num, pld_var_info_t *var_info)
{
    bool32 eof = CT_FALSE;
    bool32 is_found = CT_FALSE;
    status_t status = CT_SUCCESS;

    CTSQL_SAVE_STACK(stmt);
    var_info->m_offset = PLD_INVALID_M_OFFSET;
    var_info->total_field = NULL;
    var_info->total_attr = NULL;
    var_info->obj_total_field = NULL;
    var_info->obj_total_attr = NULL;
    var_info->total_parent_name = NULL;
    do {
        if (pld_get_var_info(stmt, debug_ctl, var_info, &is_found, &eof) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }
        if (!is_found) {
            break;
        }
        dbg_show_values_set_stats(stats, var_num, var_info);

        (*var_num)++;
        var_info->m_offset++;
    } while (!eof);
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

status_t dbg_show_values_prepare(sql_stmt_t *stmt, debug_control_t *debug_ctl, dbg_show_values_t *stats,
    uint32 *using_index, uint32 stack_id)
{
    uint32 var_num = *using_index;
    uint32 var_count[DBG_PLE_MAX_BLOCK_DEPTH];
    pld_block_info_t block_info;
    pld_var_info_t var_info;
    uint32 page_size, max_count;

    block_info.stack_id = stack_id;
    block_info.var_count = var_count;
    block_info.max_depth = DBG_PLE_MAX_BLOCK_DEPTH;
    CT_RETURN_IFERR(pld_parse_block_info(debug_ctl, &block_info));
    CT_RETURN_IFERR(knl_get_page_size((knl_handle_t)&stmt->session->knl_session, &page_size));
    max_count = page_size / sizeof(dbg_show_values_t);
    for (uint32 i = block_info.curr_stack_start; i < block_info.next_stack_start; i++) {
        for (uint32 j = 0; j < block_info.var_count[i]; j++) {
            var_info.stack_id = stack_id;
            var_info.block_id = i;
            var_info.id = j;
            if (var_num > max_count) {
                CT_THROW_ERROR(ERR_TOO_MANY_OBJECTS, var_num, "debug procedure/function params max count");
                return CT_ERROR;
            }
            if (dbg_show_values_get_vars(stmt, debug_ctl, stats, &var_num, &var_info) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }

    stats[var_num].stack_id = CT_INVALID_ID32;
    *using_index = var_num;
    return CT_SUCCESS;
}
