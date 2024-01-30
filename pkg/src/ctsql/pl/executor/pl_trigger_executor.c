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
 * pl_trigger_executor.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/executor/pl_trigger_executor.c
 *
 * -------------------------------------------------------------------------
 */

#include "pl_trigger_executor.h"
#include "ctsql_insert.h"
#include "ctsql_scan.h"
#include "ctsql_update.h"
#include "ctsql_privilege.h"
#include "srv_instance.h"
#include "base_compiler.h"
#include "trigger_decl_cl.h"

static status_t ple_modify_insert_subpart(sql_stmt_t *stmt, knl_dictionary_t *dc, knl_cursor_t *knl_cur,
    knl_part_locate_t *part_loc)
{
    variant_t value;
    var_column_t v_col;
    part_key_t *part_key = NULL;
    uint16 partkeys = knl_subpart_key_count(dc->handle);

    v_col.is_array = CT_FALSE;
    v_col.ancestor = 0;
    v_col.ss_end = 0;
    v_col.ss_start = 0;
    CTSQL_SAVE_STACK(stmt);
    if (sql_push(stmt, CT_MAX_COLUMN_SIZE, (void **)&part_key) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    part_key_init(part_key, partkeys);
    for (uint16 i = 0; i < partkeys; i++) {
        uint16 col_id = knl_subpart_key_column_id(dc->handle, i);
        knl_column_t *knl_column = knl_get_column(dc->handle, col_id);
        v_col.datatype = (ct_type_t)knl_column->datatype;
        uint32 len = CURSOR_COLUMN_SIZE(knl_cur, col_id);
        char *ptr = CURSOR_COLUMN_DATA(knl_cur, col_id);
        if (sql_get_row_value(stmt, ptr, len, &v_col, &value, CT_FALSE) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }

        if (sql_part_put_key(stmt, &value, knl_column->datatype, knl_column->size, KNL_COLUMN_IS_CHARACTER(knl_column),
            knl_column->precision, knl_column->scale, part_key) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }
    }

    part_loc->subpart_no = knl_locate_subpart_key(dc->handle, part_loc->part_no, part_key);
    if (part_loc->subpart_no == CT_INVALID_ID32) {
        CT_THROW_ERROR(ERR_INVALID_PART_KEY, "inserted partition key does not map to any subpartition");
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    CTSQL_RESTORE_STACK(stmt);
    return CT_SUCCESS;
}

static status_t ple_modify_insert_make_partkey(sql_stmt_t *stmt, knl_dictionary_t *dc, knl_cursor_t *knl_cur,
    part_key_t *part_key)
{
    uint16 partkeys;
    variant_t value;
    var_column_t v_col;

    v_col.is_array = CT_FALSE;
    v_col.ancestor = 0;
    v_col.ss_end = 0;
    v_col.ss_start = 0;

    partkeys = knl_part_key_count(dc->handle);
    part_key_init(part_key, partkeys);
    for (uint16 i = 0; i < partkeys; i++) {
        uint16 col_id = knl_part_key_column_id(dc->handle, i);
        knl_column_t *knl_column = knl_get_column(dc->handle, col_id);
        v_col.datatype = (ct_type_t)knl_column->datatype;
        uint32 len = CURSOR_COLUMN_SIZE(knl_cur, col_id);
        char *ptr = CURSOR_COLUMN_DATA(knl_cur, col_id);
        if (sql_get_row_value(stmt, ptr, len, &v_col, &value, CT_FALSE) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (sql_part_put_key(stmt, &value, knl_column->datatype, knl_column->size, KNL_COLUMN_IS_CHARACTER(knl_column),
            knl_column->precision, knl_column->scale, part_key) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t ple_modify_insert_part(sql_stmt_t *stmt, knl_dictionary_t *dc, knl_cursor_t *knl_cur)
{
    part_key_t *part_key = NULL;
    knl_part_locate_t part_loc;

    CTSQL_SAVE_STACK(stmt);
    if (sql_push(stmt, CT_MAX_COLUMN_SIZE, (void **)&part_key) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    if (ple_modify_insert_make_partkey(stmt, dc, knl_cur, part_key) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    part_loc.part_no = knl_locate_part_key(dc->handle, part_key);
    if (knl_verify_interval_part(dc->handle, part_loc.part_no)) {
        status_t status = knl_create_interval_part(&stmt->session->knl_session, dc, part_loc.part_no, part_key);
        CTSQL_RESTORE_STACK(stmt);
        part_loc.subpart_no = 0;
        return status;
    }

    if (part_loc.part_no == CT_INVALID_ID32) {
        CT_THROW_ERROR(ERR_INVALID_PART_KEY, "inserted partition key does not map to any partition");
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    if (!knl_is_parent_part(dc->handle, part_loc.part_no)) {
        knl_set_table_part(knl_cur, part_loc);
        CTSQL_RESTORE_STACK(stmt);
        return CT_SUCCESS;
    }

    if (ple_modify_insert_subpart(stmt, dc, knl_cur, &part_loc) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }

    knl_set_table_part(knl_cur, part_loc);
    CTSQL_RESTORE_STACK(stmt);
    return CT_SUCCESS;
}

static status_t ple_modify_insert_data_loop(sql_stmt_t *stmt, knl_dictionary_t *dc, row_assist_t *row_ass,
    knl_cursor_t *knl_cur, char *save_buf, uint16 col)
{
    variant_t var;
    pl_entity_t *pl_entity = ((pl_executor_t *)stmt->pl_exec)->entity;
    galist_t *trig_new_cols = pl_entity->trigger->modified_new_cols;
    plv_decl_t *decl = (plv_decl_t *)cm_galist_get(trig_new_cols, col);
    knl_column_t *knl_column = knl_get_column(dc->handle, col);
    row_head_t *head = knl_cur->row;
    cm_put_row_column_t put_col_func = head->is_csf ? cm_put_csf_row_column : cm_put_bmp_row_column;

    if (decl == NULL) {
        CT_RETURN_IFERR(put_col_func((row_head_t *)save_buf, knl_cur->offsets, knl_cur->lens, col, row_ass));
        if (cm_is_null_col((row_head_t *)save_buf, knl_cur->lens, col) && !knl_column->nullable) {
            knl_cur->vnc_column = knl_column->name;
        }
    } else {
        if (!cm_is_null_col((row_head_t *)save_buf, knl_cur->lens, col) && COLUMN_IS_LOB(knl_column)) {
            CT_RETURN_IFERR(
                knl_recycle_lob_column_pages(KNL_SESSION(stmt), knl_cur, knl_column, save_buf + knl_cur->offsets[col]));
        }
        var = ple_get_plvar((pl_executor_t *)stmt->pl_exec, decl->vid)->value;
        CT_RETURN_IFERR(sql_set_table_value(stmt, knl_cur, row_ass, knl_column, &var));
    }
    return CT_SUCCESS;
}

static status_t ple_modify_insert_data(sql_stmt_t *stmt, sql_insert_t *insert)
{
    pl_executor_t *exec = (pl_executor_t *)stmt->pl_exec;
    knl_dictionary_t *dc = &insert->table->entry->dc;
    row_assist_t row_ass;
    knl_cursor_t *knl_cur = exec->trig_exec->knl_cur;
    row_head_t *head = knl_cur->row;
    uint16 col_count = ROW_COLUMN_COUNT(head);
    char *save_buf = NULL;
    status_t status = CT_SUCCESS;
    knl_cur->vnc_column = NULL;

    CTSQL_SAVE_STACK(stmt);
    CT_RETURN_IFERR(sql_push(stmt, head->size, (void **)&save_buf));
    errno_t ret = memcpy_s(save_buf, head->size, (char *)head, head->size);
    if (ret != EOK) {
        CTSQL_RESTORE_STACK(stmt);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }

    cm_row_init(&row_ass, (char *)knl_cur->row, CT_MAX_ROW_SIZE, col_count, head->is_csf);

    for (uint16 col = 0; col < col_count; ++col) {
        if (ple_modify_insert_data_loop(stmt, dc, &row_ass, knl_cur, save_buf, col) != CT_SUCCESS) {
            CTSQL_RESTORE_STACK(stmt);
            return CT_ERROR;
        }
    }

    row_end(&row_ass);
    cm_decode_row((char *)row_ass.buf, knl_cur->offsets, knl_cur->lens, NULL);
    if (knl_is_part_table(dc->handle)) {
        status = ple_modify_insert_part(stmt, dc, knl_cur);
    }
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

static inline status_t ple_modify_update_find_data(sql_stmt_t *stmt, bool32 find_flag, char *save_buf,
    knl_update_info_t *ui, uint16 idx, knl_column_t *knl_column, knl_cursor_t *knl_cur)
{
    if (find_flag && !cm_is_null_col((row_head_t *)save_buf, ui->lens, idx) && COLUMN_IS_LOB(knl_column)) {
        CT_RETURN_IFERR(
            knl_recycle_lob_column_pages(KNL_SESSION(stmt), knl_cur, knl_column, save_buf + ui->offsets[idx]));
    }
    return CT_SUCCESS;
}

static uint16 ple_get_update_row_cols(galist_t *trig_new_cols, uint16 col_count, uint16 *columns, uint16 ui_count)
{
    uint16 result = 0;
    uint16 index = 0;
    for (uint16 col = 0; col < col_count; ++col) {
        if (cm_galist_get(trig_new_cols, col) == NULL) {
            for (; index < ui_count && columns[index] <= col; ++index) {
                if (columns[index] == col) {
                    result++;
                    index++;
                    break;
                }
            }
        } else {
            result++;
        }
    }
    return result;
}

static status_t ple_modify_update_data(sql_stmt_t *stmt, upd_object_t *upd_obj)
{
    knl_column_t *knl_column = NULL;
    pl_executor_t *exec = (pl_executor_t *)stmt->pl_exec;
    pl_entity_t *pl_entity = exec->entity;
    galist_t *trig_new_cols = pl_entity->trigger->modified_new_cols;
    knl_dictionary_t *dc = &upd_obj->table->entry->dc;
    uint16 col_count = knl_get_column_count(DC_ENTITY(dc));
    knl_cursor_t *knl_cur = exec->trig_exec->knl_cur;
    knl_update_info_t *ui = &knl_cur->update_info;
    row_head_t *head = (row_head_t *)knl_cur->update_info.data;
    cm_put_row_column_t put_col_func = head->is_csf ? cm_put_csf_row_column : cm_put_bmp_row_column;
    uint16 *save_columns = NULL;
    plv_decl_t *decl = NULL;
    char *save_buf = NULL;
    row_assist_t row_ass;
    variant_t var;
    uint16 new_col = 0;
    uint16 idx = 0;
    bool32 find_flag;
    knl_cur->vnc_column = NULL;
    uint16 total_cols = ple_get_update_row_cols(trig_new_cols, col_count, ui->columns, ui->count);
    errno_t ret;

    CTSQL_SAVE_STACK(stmt);
    CT_RETURN_IFERR(sql_push(stmt, head->size, (void **)&save_buf));

    ret = memcpy_s(save_buf, head->size, (char *)head, head->size);
    if (ret != EOK) {
        CTSQL_RESTORE_STACK(stmt);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }
    if (sql_push(stmt, ui->count * sizeof(uint16), (void **)&save_columns) != CT_SUCCESS) {
        CTSQL_RESTORE_STACK(stmt);
        return CT_ERROR;
    }
    ret = memcpy_s(save_columns, ui->count * sizeof(uint16), ui->columns, ui->count * sizeof(uint16));
    if (ret != EOK) {
        CTSQL_RESTORE_STACK(stmt);
        CT_THROW_ERROR(ERR_SYSTEM_CALL, ret);
        return CT_ERROR;
    }
    cm_row_init(&row_ass, ui->data, CT_MAX_ROW_SIZE, total_cols, head->is_csf);
    for (uint16 col = 0; col < col_count; ++col) {
        decl = (plv_decl_t *)cm_galist_get(trig_new_cols, col);
        knl_column = knl_get_column(dc->handle, col);
        find_flag = CT_FALSE;
        for (; idx < ui->count && save_columns[idx] <= col; ++idx) {
            if (save_columns[idx] == col) {
                find_flag = CT_TRUE;
                break;
            }
        }
        if (decl == NULL) {
            if (!find_flag) {
                continue;
            }
            if (cm_is_null_col((row_head_t *)save_buf, ui->lens, idx) && !knl_column->nullable) {
                knl_cur->vnc_column = knl_column->name;
            }
            if (put_col_func((row_head_t *)save_buf, ui->offsets, ui->lens, idx, &row_ass) != CT_SUCCESS) {
                CTSQL_RESTORE_STACK(stmt);
                return CT_ERROR;
            }
            ++idx;
        } else {
            if (ple_modify_update_find_data(stmt, find_flag, save_buf, ui, idx, knl_column, knl_cur) != CT_SUCCESS) {
                CTSQL_RESTORE_STACK(stmt);
                return CT_ERROR;
            }
            var = ple_get_plvar(exec, decl->vid)->value;
            if (sql_set_table_value(stmt, knl_cur, &row_ass, knl_column, &var) != CT_SUCCESS) {
                CTSQL_RESTORE_STACK(stmt);
                return CT_ERROR;
            }
        }
        ui->columns[new_col++] = col;
    }
    ui->count = new_col;
    row_end(&row_ass);
    cm_decode_row(ui->data, ui->offsets, ui->lens, NULL);
    CTSQL_RESTORE_STACK(stmt);
    return CT_SUCCESS;
}

static inline sql_insert_t *ple_get_insert(sql_context_t *sql_ctx)
{
    if (sql_ctx->type == CTSQL_TYPE_INSERT) {
        return (sql_insert_t *)sql_ctx->entry;
    } else if (sql_ctx->type == CTSQL_TYPE_MERGE) {
        return ((sql_merge_t *)sql_ctx->entry)->insert_ctx;
    } else if (sql_ctx->type == CTSQL_TYPE_REPLACE) {
        return (sql_insert_t *)&(((sql_replace_t *)sql_ctx->entry)->insert_ctx);
    } else {
        CT_THROW_ERROR(ERR_PL_CONTEXT_TYPE_MISMATCH_FMT, "INSERT or MERGE or REPLACE", sql_ctx->type);
        return NULL;
    }
}

static status_t ple_generate_new_cols(sql_stmt_t *stmt, sql_stmt_t *sub_stmt, void *data)
{
    pl_executor_t *exec = (pl_executor_t *)sub_stmt->pl_exec;
    uint32 trig_event = exec->trig_exec->trig_event;

    if (trig_event == TRIG_EVENT_INSERT) {
        sql_insert_t *insert = ple_get_insert(stmt->context);
        if (insert == NULL) {
            return CT_ERROR;
        }
        ((insert_data_t *)data)->row_modify = CT_TRUE;
        return ple_modify_insert_data(sub_stmt, insert);
    } else { // TRIG_EVENT_UPDATE
        return ple_modify_update_data(sub_stmt, (upd_object_t *)data);
    }
}

status_t ple_exec_trigger(sql_stmt_t *stmt, void *context, uint32 trig_event, void *knl_cur, void *data)
{
    pl_executor_t exec;
    status_t status;
    sql_stmt_t *sub_stmt = NULL;
    bool8 is_curs_prepare = CT_FALSE;
    bool8 is_over_return = CT_FALSE;
    ack_sender_t *save_sender = NULL;
    pl_entity_t *trig_context = (pl_entity_t *)context;
    trigger_t *trigger = trig_context->trigger;
    var_udo_t obj;
    saved_schema_t schema;
    ple_line_assist_t line_assist;

    CT_RETURN_IFERR(sql_stack_safe(stmt));
    CT_RETURN_IFERR(sql_check_trigger_priv(stmt, context));
    CT_RETURN_IFERR(ple_init_executor(&exec, stmt));
    CT_LOG_DEBUG_INF("The trigger is triggered. The trigger name is %s.%s", T2S(&trig_context->def.user),
        T2S_EX(&trig_context->def.name));

    obj.user = trig_context->def.user;
    if (sql_switch_schema_by_name(stmt, &obj.user, &schema) != CT_SUCCESS) {
        return CT_ERROR;
    }
    PLE_SAVE_STMT(stmt);
    if (ple_prepare_pl_cursors(stmt, &is_curs_prepare) != CT_SUCCESS) {
        PLE_RESTORE_STMT(stmt);
        sql_restore_schema(stmt, &schema);
        return CT_ERROR;
    }
    status = CT_ERROR;

    do {
        CT_BREAK_IF_ERROR(sql_push(stmt, sizeof(sql_stmt_t), (void **)&sub_stmt));

        errno_t errcode = memset_s(sub_stmt, sizeof(sql_stmt_t), 0, sizeof(sql_stmt_t));
        if (errcode != EOK) {
            CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            break;
        }
        sql_init_stmt(stmt->session, sub_stmt, stmt->id);
        CT_BREAK_IF_ERROR(sql_push(stmt, sizeof(trig_executor_t), (void **)&exec.trig_exec));
        sub_stmt->pl_exec = &exec;
        if (trig_context->is_auton_trans) {
            CT_BREAK_IF_ERROR(ple_begin_auton_rm(sub_stmt->session));
        }
        sub_stmt->is_srvoutput_on = stmt->is_srvoutput_on;
        sub_stmt->status = stmt->status;
        sub_stmt->pl_context = trig_context;
        sub_stmt->session->sender = &g_instance->sql.pl_sender;
        save_sender = sub_stmt->session->sender;
        sub_stmt->session->current_stmt = sub_stmt;
        sub_stmt->is_sub_stmt = CT_TRUE;
        sub_stmt->pl_ref_entry = stmt->pl_ref_entry;
        sub_stmt->parent_stmt = stmt;
        sub_stmt->cursor_info.type = PL_FORK_CURSOR;
        sub_stmt->v_sysdate = SQL_UNINITIALIZED_DATE;
        sub_stmt->v_systimestamp = SQL_UNINITIALIZED_TSTAMP;
        CT_BREAK_IF_ERROR(pl_init_sequence(sub_stmt));

        exec.entity = trig_context;
        exec.body = trig_context->trigger->body;
        exec.obj = NULL;
        exec.trig_exec->knl_cur = (knl_cursor_t *)knl_cur;
        exec.trig_exec->trig_event = trig_event;
        exec.trig_exec->data = data;
        if (COVER_ENABLE == CT_TRUE) {
            CT_BREAK_IF_ERROR(ple_push_coverage_hit_count(sub_stmt));
        }

        ple_line_assist_init(&line_assist, sub_stmt, &exec, (pl_line_ctrl_t *)trig_context->trigger->body, NULL);
        CT_BREAK_IF_ERROR(ple_begin_ln(&line_assist));

        CT_BREAK_IF_ERROR(ple_lines(sub_stmt, trigger->body->ctrl.next, &is_over_return));

        if ((trig_event == TRIG_EVENT_INSERT || trig_event == TRIG_EVENT_UPDATE) &&
            trigger->desc.type == TRIG_BEFORE_EACH_ROW && trigger->modified_new_cols != NULL) {
            CT_BREAK_IF_ERROR(ple_generate_new_cols(stmt, sub_stmt, data));
        }

        status = CT_SUCCESS;
    } while (0);

    if (sub_stmt != NULL) {
        if (status != CT_SUCCESS) {
            if (stmt->pl_exec != NULL) {
                pl_check_and_set_loc(trigger->body->ctrl.next->loc);
                ple_check_exec_error(sub_stmt, &trigger->body->ctrl.next->loc);
                ple_inherit_substmt_error(stmt, sub_stmt);
            } else {
                ple_send_error(sub_stmt);
            }
        }

        while (exec.block_stack.depth > 0) {
            ple_pop_block(sub_stmt, &exec);
        }

        if (trig_context->is_auton_trans) {
            status = (ple_end_auton_rm(sub_stmt->session) == CT_SUCCESS) ? status : CT_ERROR;
            sub_stmt->session->sender = save_sender;
        }
        sql_release_lob_info(sub_stmt);
        sql_release_resource(sub_stmt, CT_TRUE);

        if (sub_stmt->stat != NULL) {
            free(sub_stmt->stat);
            sub_stmt->stat = NULL;
        }
    }

    /* release the stack resource here */
    PLE_RESTORE_STMT(stmt);
    sql_restore_schema(stmt, &schema);
    if (is_curs_prepare) {
        stmt->session->pl_cursors = NULL;
    }

    if (status != CT_SUCCESS) {
        CT_LOG_DEBUG_ERR("error during execution of trigger '%s.%s'", T2S(&trig_context->def.user),
            T2S_EX(&trig_context->def.name));
    }
    return status;
}

status_t ple_get_trig_pseudo_col(sql_stmt_t *stmt, var_column_t *col, variant_t *result, bool32 new_flag)
{
    pl_executor_t *pl_exec = (pl_executor_t *)stmt->pl_exec;
    knl_cursor_t *knl_cur = pl_exec->trig_exec->knl_cur;
    uint32 trig_event = pl_exec->trig_exec->trig_event;
    result->is_null = CT_TRUE;
    switch (col->col) {
        case TRIG_RES_WORD_ROWID:
            result->type = CT_TYPE_STRING;
            if ((new_flag && trig_event == TRIG_EVENT_DELETE) || (!new_flag && trig_event == TRIG_EVENT_INSERT) ||
                KNL_IS_INVALID_ROWID(knl_cur->rowid)) {
                break;
            }
            result->is_null = CT_FALSE;
            if (sql_push(stmt, CT_MAX_ROWID_BUFLEN, (void **)&result->v_text.str) != CT_SUCCESS) {
                return CT_ERROR;
            }
            sql_rowid2str(&knl_cur->rowid, result, DICT_TYPE_TABLE);
            CTSQL_POP(stmt);
            break;
        case TRIG_RES_WORD_ROWSCN:
            result->type = CT_TYPE_BIGINT;
            if ((new_flag && trig_event == TRIG_EVENT_DELETE) || (!new_flag && trig_event == TRIG_EVENT_INSERT) ||
                KNL_IS_INVALID_SCN(knl_cur->scn)) {
                break;
            }
            result->is_null = CT_FALSE;
            result->v_bigint = (int64)knl_cur->scn;
            break;
        default:
            return CT_SUCCESS;
    }
    return CT_SUCCESS;
}

status_t ple_get_trig_old_col(sql_stmt_t *stmt, var_column_t *var_col, variant_t *result)
{
    pl_executor_t *pl_exec = (pl_executor_t *)stmt->pl_exec;

    if (var_col->tab == TRIG_PSEUDO_COLUMN_TALBE) {
        return ple_get_trig_pseudo_col(stmt, var_col, result, CT_FALSE);
    }

    switch (pl_exec->trig_exec->trig_event) {
        case TRIG_EVENT_DELETE:
        case TRIG_EVENT_UPDATE: {
            knl_cursor_t *knl_cur = pl_exec->trig_exec->knl_cur;
            return sql_get_trig_kernel_value(stmt, knl_cur->row, knl_cur->offsets, knl_cur->lens, var_col, result);
        }
        case TRIG_EVENT_INSERT:
        default:
            result->is_null = CT_TRUE;
            result->type = var_col->datatype;
            break;
    }
    return CT_SUCCESS;
}

status_t ple_get_trig_new_col(sql_stmt_t *stmt, var_column_t *var_col, variant_t *result)
{
    pl_executor_t *pl_exec = (pl_executor_t *)stmt->pl_exec;

    if (var_col->tab == TRIG_PSEUDO_COLUMN_TALBE) {
        return ple_get_trig_pseudo_col(stmt, var_col, result, CT_TRUE);
    }

    switch (pl_exec->trig_exec->trig_event) {
        case TRIG_EVENT_UPDATE: {
            knl_update_info_t *new_record = &pl_exec->trig_exec->knl_cur->update_info;
            var_column_t tmp_col = *var_col;
            for (uint32 i = 0; i < new_record->count; ++i) {
                if (var_col->col == new_record->columns[i]) {
                    tmp_col.col = i;
                    return sql_get_trig_kernel_value(stmt, (row_head_t *)new_record->data, new_record->offsets,
                        new_record->lens, &tmp_col, result);
                }
            }

            CT_RETURN_IFERR(ple_get_trig_old_col(stmt, var_col, result));
            break;
        }
        case TRIG_EVENT_INSERT: {
            knl_cursor_t *knl_cur = pl_exec->trig_exec->knl_cur;
            return sql_get_trig_kernel_value(stmt, knl_cur->row, knl_cur->offsets, knl_cur->lens, var_col, result);
        }
        case TRIG_EVENT_DELETE:
        default:
            result->is_null = CT_TRUE;
            result->type = var_col->datatype;
            break;
    }
    return CT_SUCCESS;
}

void ple_check_exec_trigger_error(sql_stmt_t *stmt, pl_entity_t *entity)
{
    pl_executor_t *exec = (pl_executor_t *)stmt->pl_exec;
    if (stmt->pl_exec == NULL || exec->err_buf_pos > 0) {
        return;
    }

    var_udo_t *udo_obj = &entity->def;
    text_t *user = &udo_obj->user;
    text_t *name = &udo_obj->name;
    source_location_t loc = { 1, 1 };

    ple_update_error_stack(stmt, user, name, &loc);
    ple_set_error(stmt, user, name, &loc);
}