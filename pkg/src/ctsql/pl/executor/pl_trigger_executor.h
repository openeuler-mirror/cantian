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
 * pl_trigger_executor.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/executor/pl_trigger_executor.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __PL_TRIGGER_EXECUTOR_H__
#define __PL_TRIGGER_EXECUTOR_H__

#include "pl_lines_executor.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t ple_exec_trigger(sql_stmt_t *stmt, void *context, uint32 trig_event, void *knl_cur, void *data);
status_t ple_get_trig_new_col(sql_stmt_t *stmt, var_column_t *var_col, variant_t *result);
status_t ple_get_trig_old_col(sql_stmt_t *stmt, var_column_t *var_col, variant_t *result);
void ple_check_exec_trigger_error(sql_stmt_t *stmt, pl_entity_t *entity);

#ifdef __cplusplus
}
#endif

#endif