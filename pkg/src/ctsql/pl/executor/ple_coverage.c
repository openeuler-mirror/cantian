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
 * ple_coverage.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/executor/ple_coverage.c
 *
 * -------------------------------------------------------------------------
 */

#include "ple_coverage.h"
#include "ple_common.h"
#include "knl_context.h"

static void ple_coverage_table_init_cursor(knl_cursor_t *cur)
{
    cur->scan_mode = SCAN_MODE_TABLE_FULL;
    cur->action = CURSOR_ACTION_INSERT;
    cur->vm_page = NULL;
}

static status_t ple_get_coverage_info(ple_coverage_t *coverage, text_t *cover_info, uint32 cover_info_max_size,
    knl_cursor_t *cursor, knl_column_t *column)
{
    uint32 i;
    if (coverage->hit_count == NULL) {
        return CT_ERROR;
    }

    for (i = 0; i < coverage->loc_line_num; i++) {
        if (coverage->hit_count[i] != 0) {
            cm_concat_int32(cover_info, cover_info_max_size, i + 1); // not overflow
            CT_RETURN_IFERR(cm_concat_string(cover_info, coverage->loc_line_num * COVER_HIT_COUNT_STR_LEN, ":"));
            cm_concat_int32(cover_info, cover_info_max_size, (coverage->hit_count[i] & (~COVER_VALID_LINE_FLAG)));
            CT_RETURN_IFERR(cm_concat_string(cover_info, coverage->loc_line_num * COVER_HIT_COUNT_STR_LEN, ";"));
        }
    }
    return CT_SUCCESS;
}

static status_t ple_insert_into_coverage_table(sql_stmt_t *stmt)
{
    text_t user_name = { "SYS", 3 };
    text_t coverage_table = { "COVERAGE$", 9 };
    knl_cursor_t *cursor = NULL;
    knl_session_t *knl_session = &stmt->session->knl_session;
    knl_dictionary_t dc;
    status_t status = CT_ERROR;
    uint32 column_count;
    row_assist_t row_ass;
    knl_column_t *column = NULL;
    pl_executor_t *exec = (pl_executor_t *)stmt->pl_exec;
    text_t cover_info;

    CT_RETURN_IFERR(sql_push(stmt, exec->coverage->loc_line_num * COVER_HIT_COUNT_STR_LEN, (void **)&cover_info.str));
    cover_info.len = 0;

    CT_RETURN_IFERR(sql_push_knl_cursor(knl_session, &cursor));
    CT_RETURN_IFERR(knl_begin_auton_rm(knl_session));

    do {
        ple_coverage_table_init_cursor(cursor);
        knl_set_session_scn(knl_session, CT_INVALID_ID64);

        CT_BREAK_IF_ERROR(dc_open(knl_session, &user_name, &coverage_table, &dc));

        if (knl_open_cursor(knl_session, cursor, &dc) != CT_SUCCESS) {
            dc_close(&dc);
            break;
        }

        cursor->row = (row_head_t *)cursor->buf;
        column = knl_get_column(cursor->dc_entity, COVER_COVER_INFO_COL);
        if (ple_get_coverage_info(exec->coverage, &cover_info, exec->coverage->loc_line_num * COVER_HIT_COUNT_STR_LEN,
            cursor, column) != CT_SUCCESS) {
            dc_close(&dc);
            break;
        }

        column_count = knl_get_column_count(cursor->dc_entity);
        row_init(&row_ass, (char *)cursor->row, knl_session->kernel->attr.max_row_size, column_count);
        // The current application scenario will not return a failure
        (void)row_put_int64(&row_ass, (int64)knl_session->id);                     // SESSION#
        (void)row_put_text(&row_ass, &exec->entity->def.user);                     // OWNER
        (void)row_put_text(&row_ass, &exec->entity->def.name);                     // OBJ_NAME
        if (knl_row_put_lob(knl_session, cursor, column, &cover_info, &row_ass)) { // COVER_INFO
            dc_close(&dc);
            break;
        }
        status = knl_internal_insert(knl_session, cursor);

        knl_close_cursor(knl_session, cursor);
        dc_close(&dc);
    } while (0);

    knl_end_auton_rm(knl_session, CT_SUCCESS);

    return status;
}

static void pl_set_line_cover_valid(uint8 *hit_count, uint16 line)
{
    if (line == 0) {
        return;
    }
    hit_count[line - 1] = hit_count[line - 1] | COVER_VALID_LINE_FLAG; // not overflow
}

status_t ple_push_coverage_hit_count(sql_stmt_t *stmt)
{
    pl_executor_t *exec = (pl_executor_t *)stmt->pl_exec;
    pl_line_ctrl_t *line = (pl_line_ctrl_t *)exec->body;
    pl_line_begin_t *begin_line = (pl_line_begin_t *)exec->body->ctrl.next;
    ple_coverage_t *coverage = NULL;
    errno_t rc_memzero;

    CT_RETURN_IFERR(sql_push(stmt, sizeof(ple_coverage_t), (void **)&exec->coverage));
    coverage = exec->coverage;
    if (exec->body->end != NULL) {
        coverage->loc_line_num = exec->body->end->loc.line;
    } else if (begin_line->ctrl.type == LINE_BEGIN) {
        coverage->loc_line_num = begin_line->end->loc.line;
    } else {
        CT_THROW_ERROR(ERR_PLSQL_ILLEGAL_LINE_FMT, "can not find begin line");
        CTSQL_POP(stmt);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_push(stmt, coverage->loc_line_num, (void **)&coverage->hit_count));
    rc_memzero = memset_s(coverage->hit_count, coverage->loc_line_num, 0, coverage->loc_line_num);
    if (rc_memzero != EOK) {
        CT_THROW_ERROR(ERR_SYSTEM_CALL, rc_memzero);
        CTSQL_POP(stmt);
        return CT_ERROR;
    }

    while (line != NULL) {
        pl_set_line_cover_valid(coverage->hit_count, line->loc.line);
        line = line->next;
    }
    return CT_SUCCESS;
}

static status_t ple_coverage_create_and_insert_table(knl_session_t *session, text_t *user_name)
{
    char buf[COVER_SQL_STR_LEN];
    text_t sql;

    sql.str = buf;
    sql.len = 0;
    CT_RETURN_IFERR(cm_concat_string(&sql, COVER_SQL_STR_LEN, "CREATE TABLE "));
    cm_concat_text(&sql, COVER_SQL_STR_LEN, user_name);
    CT_RETURN_IFERR(cm_concat_string(&sql, COVER_SQL_STR_LEN,
        ".COVERAGE$(SESSION# BINARY_BIGINT NOT NULL, OWNER VARCHAR(128) NOT NULL, "
        "OBJ_NAME VARCHAR(128) NOT NULL, COVER_INFO CLOB NOT NULL)"));
    if (g_knl_callback.exec_sql(session, &sql) != CT_SUCCESS) {
        return CT_ERROR;
    }

    sql.len = 0;
    CT_RETURN_IFERR(cm_concat_string(&sql, COVER_SQL_STR_LEN, "GRANT INSERT ON "));
    cm_concat_text(&sql, COVER_SQL_STR_LEN, user_name);
    CT_RETURN_IFERR(cm_concat_string(&sql, COVER_SQL_STR_LEN, ".COVERAGE$ TO PUBLIC"));
    if (g_knl_callback.exec_sql(session, &sql) != CT_SUCCESS) {
        return CT_ERROR;
    }

    sql.len = 0;
    CT_RETURN_IFERR(cm_concat_string(&sql, COVER_SQL_STR_LEN, "INSERT INTO "));
    cm_concat_text(&sql, COVER_SQL_STR_LEN, user_name);
    CT_RETURN_IFERR(cm_concat_string(&sql, COVER_SQL_STR_LEN, ".COVERAGE$ VALUES(0, 'COVERAGE', 'COVERAGE', '1:0;')"));
    if (g_knl_callback.exec_sql(session, &sql) != CT_SUCCESS) {
        return CT_ERROR;
    }

    sql.len = 0;
    CT_RETURN_IFERR(cm_concat_string(&sql, COVER_SQL_STR_LEN, "CREATE INDEX IX_COVERAGE ON "));
    cm_concat_text(&sql, COVER_SQL_STR_LEN, user_name);
    CT_RETURN_IFERR(cm_concat_string(&sql, COVER_SQL_STR_LEN, ".COVERAGE$(OWNER, OBJ_NAME)"));
    if (g_knl_callback.exec_sql(session, &sql) != CT_SUCCESS) {
        return CT_ERROR;
    }
    return CT_SUCCESS;
}

status_t ple_try_create_coverage_table(knl_handle_t knl_session)
{
    knl_dict_type_t type;
    text_t user_name = { "SYS", 3 };
    text_t coverage_table = { "COVERAGE$", 9 };
    session_t *session = (session_t *)knl_session;
    sql_stmt_t *temp_stmt = session->current_stmt;
    status_t status = CT_SUCCESS;

    if (!cm_text_equal(&session->curr_user, &user_name)) {
        CT_THROW_ERROR(ERR_INSUFFICIENT_PRIV);
        return CT_ERROR;
    }

    if (!dc_object_exists2(knl_session, &user_name, &coverage_table, &type)) {
        status = ple_coverage_create_and_insert_table((knl_session_t *)knl_session, &user_name);
        session->current_stmt = temp_stmt;
    }

    return status;
}

status_t ple_try_insert_coverage_table(sql_stmt_t *stmt, bool32 is_try)
{
    if (is_try) {
        CT_RETURN_IFERR(ple_insert_into_coverage_table(stmt));
    }
    return CT_SUCCESS;
}