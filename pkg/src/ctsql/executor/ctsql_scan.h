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
 * ctsql_scan.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_scan.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_SCAN_H__
#define __SQL_SCAN_H__

#include "ctsql_plan.h"
#include "plan_range.h"
#include "dml_executor.h"

status_t sql_var2rowid(const variant_t *var, rowid_t *rowid, knl_dict_type_t dc_type);
status_t sql_execute_scan(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan);
status_t sql_fetch_scan(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);
status_t sql_fetch_scan_subselect(sql_stmt_t *stmt, struct st_sql_cursor *sql_cur, bool32 *eof);
status_t sql_get_row_value(sql_stmt_t *stmt, char *ptr, uint32 len, var_column_t *v_col, variant_t *value,
    bool8 set_lob_nodeid);
status_t sql_get_kernel_value(sql_stmt_t *stmt, sql_table_t *table, knl_cursor_t *knl_cursor, var_column_t *v_col,
                              variant_t *value);
status_t sql_get_ddm_kernel_value(sql_stmt_t *stmt, sql_table_t *table, knl_cursor_t *knl_cur, var_column_t *v_col,
    variant_t *value);
status_t sql_get_trig_kernel_value(sql_stmt_t *stmt, row_head_t *row, uint16 *offsets, uint16 *lens,
    var_column_t *v_col, variant_t *value);
void sql_part_get_print(sql_stmt_t *stmt, scan_plan_t *plan, char *buffer, uint32 size);
void sql_prepare_scan(sql_stmt_t *stmt, knl_dictionary_t *dc, knl_cursor_t *knl_cursor);
status_t sql_execute_table_scan(sql_stmt_t *stmt, sql_table_cursor_t *table_cur);
status_t sql_scan_normal_table(sql_stmt_t *stmt, sql_table_t *table, sql_table_cursor_t *tab_cursor, plan_node_t *plan,
                               sql_cursor_t *cursor);
status_t sql_make_part_scan_keys(sql_stmt_t *stmt, scan_plan_t *plan, sql_table_cursor_t *table_cur,
                                 sql_cursor_t *sql_cursor, calc_mode_t calc_mode);
bool32 sql_try_fetch_next_part(sql_table_cursor_t *cursor);
knl_part_locate_t sql_fetch_next_part(sql_table_cursor_t *table_cur);
status_t sql_fetch_one_part(sql_stmt_t *stmt, sql_table_cursor_t *tab_cursor, sql_table_t *table);
status_t sql_try_switch_part(sql_stmt_t *stmt, sql_table_cursor_t *tab_cursor, sql_table_t *table, bool32 *result);
status_t sql_get_subarray_by_col(sql_stmt_t *stmt, var_column_t *v_col, variant_t *value, variant_t *result);
status_t sql_make_index_scan_keys(sql_stmt_t *stmt, scan_plan_t *plan, sql_cursor_t *sql_cursor,
                                  sql_table_cursor_t *table_cur);
bool32 sql_load_index_scan_key(sql_table_cursor_t *cursor);
status_t sql_make_subpart_scan_keys(sql_stmt_t *stmt, sql_array_t *subpart, sql_table_t *table, vmc_t *vmc,
    part_scan_key_t *part_scan_key, calc_mode_t calc_mode);
status_t sql_try_get_value_from_index(sql_stmt_t *stmt, expr_node_t *node, variant_t *result, bool32 *ready);
bool32 sql_match_func_index_col(sql_stmt_t *stmt, expr_node_t *node, knl_index_desc_t *index, sql_table_t *table,
    uint32 *index_col);
/* 1.all scan ranges are point range (include RANGE_FULL type)
 * 2.At least one column has multi scan ranges
 * 3.index columns must match condition or has RANGE_FULL scan type.
 * 4.total ranges of Cartesian product not greater than CT_MAX_POINT_RANGE_COUNT
 */
static inline bool32 can_use_point_scan(scan_list_array_t *ar)
{
    if (!CT_BIT_TEST(ar->flags, LIST_EXIST_RANGE_UNEQUAL) && CT_BIT_TEST(ar->flags, LIST_EXIST_MULTI_RANGES) &&
        ar->total_ranges <= CT_MAX_POINT_RANGE_COUNT) {
        return CT_TRUE;
    }

    return CT_FALSE;
}

#endif