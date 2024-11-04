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
 * ctc_ddl_list.h
 *
 *
 * IDENTIFICATION
 * src/ctc/ctc_ddl_list.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef __CTC_DDL_LIST_H__
#define __CTC_DDL_LIST_H__
#include <stdbool.h>
#include "knl_defs.h"
#include "cm_bilist.h"
#include "ctsql_stmt.h"
#ifdef __cplusplus
extern "C" {
#endif

typedef enum ddl_def_mode {
    CREATE_DEF = 0,
    ALTER_DEF,
    DROP_DEF,
    RENAME_DEF,
    TRUNC_DEF,
} ddl_def_mode_t;

typedef struct ctc_ddl_def_node {
    bilist_node_t bilist_node;
    void *ddl_def;
    ddl_def_mode_t def_mode;
    uint32 uid;
    uint32 oid;
} ctc_ddl_def_node_t;

typedef struct ctc_ddl_dc_array {
    knl_dictionary_t dc;
    void *ddl_def;
    ddl_def_mode_t def_mode;
    bool8 is_dropped;
} ctc_ddl_dc_array_t;

void ctc_init_ddl_def_list(sql_stmt_t *stmt);
void ctc_init_ddl_def_node(ctc_ddl_def_node_t *node, ddl_def_mode_t def_mode, void *ddl_def, knl_dictionary_t *dc);
void ctc_ddl_def_list_insert(bilist_t *list, ctc_ddl_def_node_t *node);
bool ctc_is_def_list_empty(bilist_t *list);
void ctc_ddl_def_list_clear(bilist_t *list);

#ifdef __cplusplus
}
#endif

#endif  // #ifndef __CTC_LIST_H__
