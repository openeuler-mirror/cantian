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
 * ctsql_proj.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_proj.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_PROJ_H__
#define __SQL_PROJ_H__

#include "dml_executor.h"

status_t sql_send_row(sql_stmt_t *stmt, sql_cursor_t *cursor, bool32 *is_full);
status_t sql_send_value(sql_stmt_t *stmt, char *pending_buf, ct_type_t temp_type, typmode_t *typmod, variant_t *value);
status_t sql_get_rs_value(sql_stmt_t *stmt, sql_cursor_t *cursor, uint32 id, variant_t *value);
status_t sql_get_col_rs_value(sql_stmt_t *stmt, sql_cursor_t *cursor, uint16 col, var_column_t *v_col,
    variant_t *value);
status_t sql_send_generated_key_row(sql_stmt_t *stmt, int64 *serial_val);
ct_type_t sql_make_pending_column_def(sql_stmt_t *stmt, char *pending_buf, ct_type_t type, uint32 col_id,
    variant_t *value);
status_t sql_send_ori_row(sql_stmt_t *stmt, sql_cursor_t *cursor, bool32 *is_full);
status_t sql_send_return_row(sql_stmt_t *stmt, galist_t *ret_columns, bool8 gen_null);
status_t sql_send_column(sql_stmt_t *stmt, sql_cursor_t *cursor, rs_column_t *rs_col, variant_t *value);
status_t sql_send_calc_column(sql_stmt_t *stmt, rs_column_t *rs_col, variant_t *value);

#endif
