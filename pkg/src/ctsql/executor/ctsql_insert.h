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
 * ctsql_insert.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_insert.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_INSERT_H__
#define __SQL_INSERT_H__

#include "dml_executor.h"
#include "knl_dc.h"
#include "pl_executor.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_insert_data {
    sql_cursor_t *cur_select;
    bool32 row_modify;
} insert_data_t;

typedef struct st_insert_assist {
    sql_insert_t *insert_ctx;
    sql_cursor_t *cur_select;
    insert_data_t *data;
    row_assist_t ra;
    uint32 col_id;
    bool32 has_serial;
    int64 serial_val;
    int64 max_serial_val;
    variant_t value;
} insert_assist_t;

status_t sql_insert_inner(sql_stmt_t *stmt, sql_cursor_t *cursor, knl_cursor_t *knl_cur, insert_assist_t *assist,
    status_t *status);
status_t sql_store_row_if_trigger_modify(insert_data_t *insert_data, knl_cursor_t *knl_cur, char *buf);
status_t sql_restore_row_if_trigger_modify(insert_data_t *insert_data, knl_cursor_t *knl_cur, const char *buf,
    sql_stmt_t *stmt, insert_assist_t *assist);

status_t sql_insert_try_ignore(sql_insert_t *insert_ctx);
status_t sql_execute_insert(sql_stmt_t *stmt);
status_t sql_execute_insert_with_ctx(sql_stmt_t *stmt, sql_insert_t *insert_ctx);
status_t sql_open_insert_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_insert_t *ctx);
status_t sql_execute_insert_plan(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_insert_t *insert_ctx);
status_t sql_calc_part_print(sql_stmt_t *stmt, char *buf, uint32 size);

status_t sql_generate_insert_data(sql_stmt_t *stmt, knl_cursor_t *knl_cursor, insert_assist_t *assist);
status_t sql_execute_insert_update(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_insert_t *insert_ctx,
    knl_dictionary_t *dc, bool32 *is_found);
status_t sql_exec_column_default(sql_stmt_t *stmt, knl_dictionary_t *dc, knl_column_t *column, variant_t *val);
status_t sql_route_part_table(sql_stmt_t *stmt, knl_cursor_t *knl_cur, part_key_t *part_key, insert_assist_t *assist);
status_t sql_try_construct_insert_data(sql_stmt_t *stmt, knl_cursor_t *knl_cur, knl_part_key_t *decode_key,
                                       insert_assist_t *ass);

/* store default values for insert returning or replace set */
status_t sql_update_default_values(sql_stmt_t *stmt, uint32 col_id, variant_t *val);
void sql_get_default_value(sql_stmt_t *stmt, uint32 col_id, variant_t *res);
status_t sql_prepare_view_row_insteadof(sql_stmt_t *stmt, sql_table_cursor_t *tab_cursor, knl_cursor_t *knl_cursor);
status_t sql_insteadof_triggers(sql_stmt_t *stmt, sql_table_t *table, void *knl_cur, void *data,
    trig_dml_type_t dml_type);
bool32 sql_batch_insert_enable(sql_stmt_t *stmt, sql_insert_t *insert_ctx);
status_t sql_execute_insert_trigs(sql_stmt_t *stmt, trig_set_t *set, uint32 type, void *knl_cur, void *insert_data);

static inline status_t sql_execute_insert_triggers(sql_stmt_t *stmt, sql_table_t *table, uint32 type, void *knl_cur,
    void *insert_data)
{
    knl_dictionary_t *dc = &table->entry->dc;
    dc_entity_t *dc_entity = (dc_entity_t *)dc->handle;
    bool8 __logging;
    status_t status;

    if (stmt->session->triggers_disable) {
        return CT_SUCCESS;
    }

    if (table->type == VIEW_AS_TABLE) {
        return CT_SUCCESS;
    }

    if (dc_entity->trig_set.trig_count == 0) {
        return CT_SUCCESS;
    }

    /* add TS lock, controls trigger concurrency */
    if (lock_table_shared(KNL_SESSION(stmt), dc_entity, LOCK_INF_WAIT) != CT_SUCCESS) {
        return CT_ERROR;
    }

    /* do not support nologging in triggers */
    __logging = stmt->session->knl_session.rm->logging;
    stmt->session->knl_session.rm->logging = CT_TRUE;

    status = sql_execute_insert_trigs(stmt, &dc_entity->trig_set, type, knl_cur, insert_data);

    stmt->session->knl_session.rm->logging = __logging;
    return status;
}


static inline void sql_init_insert_assist(insert_assist_t *ass, insert_data_t *data, sql_insert_t *insert_ctx,
    sql_cursor_t *cur_select)
{
    ass->max_serial_val = 0;
    ass->serial_val = 0;
    ass->has_serial = CT_FALSE;
    ass->data = data;
    ass->col_id = 0;
    ass->insert_ctx = insert_ctx;
    ass->cur_select = cur_select;
}

static inline void sql_reset_insert_assist(insert_assist_t *assist)
{
    assist->col_id = 0;
}

#ifdef __cplusplus
}
#endif

#endif
