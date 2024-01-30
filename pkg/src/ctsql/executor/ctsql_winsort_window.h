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
 * ctsql_winsort_window.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_winsort_window.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_WINDOWING_H__
#define __SQL_WINDOWING_H__

#include "ctsql_winsort.h"

status_t sql_func_winsort_aggr_range(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, sql_aggr_type_t type,
    const char *buf);
status_t sql_func_winsort_aggr_rows(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, sql_aggr_type_t type,
    const char *buf);
#endif
