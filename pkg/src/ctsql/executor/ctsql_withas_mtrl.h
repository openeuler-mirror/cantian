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
 * ctsql_withas_mtrl.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_withas_mtrl.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_WITHAS_MTRL_H__
#define __SQL_WITHAS_MTRL_H__

#include "dml_executor.h"

status_t sql_execute_withas_mtrl(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan);
status_t sql_fetch_withas_mtrl(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof);

#endif
