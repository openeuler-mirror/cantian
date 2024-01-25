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
 * pl_lines_executor.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/executor/pl_lines_executor.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PL_LINES_EXECUTOR_H__
#define __PL_LINES_EXECUTOR_H__

#include "ple_common.h"

#ifdef __cplusplus
extern "C" {
#endif
typedef struct st_ple_line_assist ple_line_assist_t;
struct st_ple_line_assist {
    sql_stmt_t *stmt;
    pl_executor_t *exec;
    pl_line_ctrl_t *line;
    pl_line_ctrl_t *jump;
    pl_line_ctrl_t *proc_end;
};

typedef status_t (*pl_line_exec_t)(ple_line_assist_t *line_assist);
status_t ple_begin_ln(ple_line_assist_t *line_ass);
void ple_line_assist_init(ple_line_assist_t *line_ass, sql_stmt_t *stmt, pl_executor_t *exec, pl_line_ctrl_t *line,
                          pl_line_ctrl_t *end);
status_t ple_lines(sql_stmt_t *stmt, pl_line_ctrl_t *start, bool8 *is_over_return);

#ifdef __cplusplus
}
#endif

#endif