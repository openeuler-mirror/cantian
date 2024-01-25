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
 * cursor.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/pl/ast/cursor.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CURSOR_H__
#define __CURSOR_H__

#include "pl_record.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_plv_cursor_context {
    galist_t *args;         // only effective when is_sysref = CT_FALSE
    sql_context_t *context; // only effective when is_sysref = CT_FALSE
    bool8 is_sysref;
    bool8 is_err; // dedicate compile decl def is complete, if some error happened in decl-def phase it will be true.
} plv_cursor_context_t;

typedef struct st_plv_cursor {
    sql_text_t sql;
    plv_cursor_context_t *ctx;
    galist_t *input; // list of expr_node_t
    plv_record_t *record;
} plv_cursor_t;

#ifdef __cplusplus
}
#endif

#endif