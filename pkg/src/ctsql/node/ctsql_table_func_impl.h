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
 * ctsql_table_func_impl.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/node/ctsql_table_func_impl.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_TABLE_FUNC_IMPL_H__
#define __SQL_TABLE_FUNC_IMPL_H__

#include "ctsql_stmt.h"
#include "ctsql_context.h"
#include "ctsql_verifier.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t table_cast_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur);
status_t table_cast_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur);
status_t table_cast_verify(sql_verifier_t *verf, sql_table_t *table);
status_t dba_analyze_table_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur);
status_t dba_analyze_table_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur);
status_t dba_analyze_table_verify(sql_verifier_t *verf, sql_table_t *table);
status_t dba_fbdr_2pc_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor);
status_t dba_fbdr_2pc_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor);
status_t dba_fbdr_2pc_verify(sql_verifier_t *verf, sql_table_t *table);
status_t dba_page_corruption_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur);
status_t dba_page_corruption_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur);
status_t dba_page_corruption_verify(sql_verifier_t *verif, sql_table_t *table);
status_t dba_proc_decode_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor);
status_t dba_proc_decode_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor);
status_t dba_proc_decode_verify(sql_verifier_t *verif, sql_table_t *table);
status_t dba_proc_line_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur);
status_t dba_proc_line_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur);
status_t dba_proc_line_verify(sql_verifier_t *verf, sql_table_t *table);
status_t dbg_break_info_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur);
status_t dbg_break_info_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor);
status_t dbg_break_info_verify(sql_verifier_t *verf, sql_table_t *table);
status_t dbg_control_info_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur);
status_t dbg_control_info_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor);
status_t dbg_control_info_verify(sql_verifier_t *verif, sql_table_t *table);
status_t dbg_proc_callstack_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor);
status_t dbg_proc_callstack_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor);
status_t dbg_proc_callstack_verify(sql_verifier_t *verif, sql_table_t *table);
status_t dbg_show_values_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur);
status_t dbg_show_values_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor);
status_t dbg_show_values_verify(sql_verifier_t *verf, sql_table_t *table);
status_t get_tab_parallel_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor);
status_t get_tab_parallel_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor);
status_t get_tab_paralle_verify(sql_verifier_t *verif, sql_table_t *table);
status_t get_table_rows_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor);
status_t get_table_rows_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor);
status_t get_table_rows_verify(sql_verifier_t *verif, sql_table_t *table);
status_t pre_set_parms_get_rows(sql_stmt_t *stmt, void *handle, sql_table_t *table);
status_t set_parms_get_rows(sql_stmt_t *stmt, void *handle, void *sesion, sql_table_t *table);
tf_scan_flag_t get_tab_rows_scan_flag(table_func_t *table_func);
status_t insert_dist_ddl_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor);
status_t insert_dist_ddl_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor);
status_t insert_dist_ddl_verify(sql_verifier_t *verf, sql_table_t *table);
status_t parallel_scan_exec(sql_stmt_t *stmt, table_func_t *table_func, knl_cursor_t *cursor);
status_t parallel_scan_fetch(sql_stmt_t *stmt, table_func_t *table_func, knl_cursor_t *cursor);
status_t parallel_scan_verify(sql_verifier_t *verif, sql_table_t *table);
status_t pre_set_parms_paral_scan(sql_stmt_t *stmt, void *handle, sql_table_t *table);
status_t set_parms_paral_scan(sql_stmt_t *stmt, void *handle, void *sesion, sql_table_t *table);
tf_scan_flag_t parallel_scan_flag(table_func_t *table_func);
status_t pending_trans_session_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor);
status_t pending_trans_session_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor);
status_t pending_trans_session_verify(sql_verifier_t *verf, sql_table_t *table);
status_t dba_table_corruption_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur);
status_t dba_table_corruption_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur);
status_t dba_table_corruption_verify(sql_verifier_t *verif, sql_table_t *table);
status_t dba_index_corruption_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur);
status_t dba_index_corruption_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cur);
status_t dba_index_corruption_verify(sql_verifier_t *verif, sql_table_t *table);
status_t dba_free_space_exec(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor);
status_t dba_free_space_fetch(sql_stmt_t *stmt, table_func_t *func, knl_cursor_t *cursor);
status_t dba_free_space_verify(sql_verifier_t *verf, sql_table_t *table);

#ifdef __cplusplus
}
#endif

#endif
