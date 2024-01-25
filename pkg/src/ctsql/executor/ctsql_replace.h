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
 * ctsql_replace.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_replace.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_REPLACE_H__
#define __SQL_REPLACE_H__

#include "dml_executor.h"
#include "knl_dc.h"
#include "pl_executor.h"

status_t sql_execute_replace(sql_stmt_t *stmt);
status_t sql_execute_replace_with_ctx(sql_stmt_t *stmt, sql_replace_t *replace_ctx);

#endif
