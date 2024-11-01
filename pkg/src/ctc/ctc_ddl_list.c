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
 * ctc_ddl_list.c
 *
 *
 * IDENTIFICATION
 * src/ctc/ctc_ddl_list.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctc_module.h"
#include "ctc_ddl_list.h"
#include "ctc_srv_util.h"
#include "ctsql_stmt.h"
#include "cm_text.h"

void ctc_init_ddl_def_list(sql_stmt_t *stmt)
{
    if (stmt->ddl_def_list.head == NULL) {
        cm_bilist_init(&stmt->ddl_def_list);
    }
    return;
}

void ctc_init_ddl_def_node(ctc_ddl_def_node_t *node, ddl_def_mode_t def_mode, void *ddl_def, knl_dictionary_t *dc)
{
    cm_bilist_node_init(&node->bilist_node);
    node->ddl_def = ddl_def;
    node->def_mode = def_mode;
    if (dc == NULL) {
        node->uid = CT_INVALID_INT32;
        node->oid = CT_INVALID_INT32;
    } else {
        node->uid = dc->uid;
        node->oid = dc->oid;
    }
    return;
}

void ctc_ddl_def_list_insert(bilist_t *list, ctc_ddl_def_node_t *node)
{
    knl_panic(node != NULL);
    cm_bilist_add_tail(&node->bilist_node, list);
    return;
}

bool ctc_is_def_list_empty(bilist_t *list)
{
    return cm_bilist_empty(list);
}

void ctc_ddl_def_list_clear(bilist_t *list)
{
    if (list == NULL) {
        return;
    }
    bilist_node_t *node = cm_bilist_head(list);
    bilist_node_t *next_node = NULL;
    while (node != NULL) {
        next_node = BINODE_NEXT(node);
        cm_bilist_del(node, list);
        node = next_node;
    }
    return;
}