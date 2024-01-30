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
 * ctsql_update.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_update.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_UPDATE_H__
#define __SQL_UPDATE_H__

#include "dml_executor.h"
#include "knl_dc.h"
#include "pl_trigger_executor.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct st_update_assist {
    upd_object_t *object;
    row_assist_t ra;
    uint16 pair_id;
    uint16 reserved;
    variant_t value;
    variant_t *rs_values[CT_MAX_SUBSELECT_EXPRS];
} update_assist_t;

status_t sql_execute_update(sql_stmt_t *stmt);
status_t sql_execute_lock_row(sql_stmt_t *stmt, sql_cursor_t *cursor, cond_tree_t *cond, plan_node_t *plan,
    sql_query_t *query);
status_t sql_open_cursor_for_update(sql_stmt_t *stmt, sql_table_t *table, sql_array_t *ssa, sql_cursor_t *cur,
                                    knl_cursor_action_t action);
status_t sql_set_table_value(sql_stmt_t *stmt, knl_cursor_t *knl_cur, row_assist_t *row_ass, knl_column_t *column,
                             variant_t *value);
status_t sql_set_lob_value(sql_stmt_t *stmt, knl_cursor_t *knl_cur, row_assist_t *ra, knl_column_t *knl_col,
                           variant_t *value);
status_t sql_generate_update_data(sql_stmt_t *stmt, knl_cursor_t *knl_cur, update_assist_t *update_ass);
status_t sql_execute_update_triggers_core(sql_stmt_t *stmt, uint32 type, knl_cursor_t *knl_cur, upd_object_t *object);
status_t sql_execute_update_table(sql_stmt_t *stmt, sql_cursor_t *cursor, knl_cursor_t *knl_cur, upd_object_t *object);
status_t sql_set_vm_lob_to_knl_lob_locator(sql_stmt_t *stmt, knl_cursor_t *knl_cur, knl_column_t *col,
                                           variant_t *value, char *locator);
status_t sql_set_vm_lob_to_knl(void *stmt, knl_cursor_t *knl_cur, knl_column_t *knl_col, variant_t *value,
                               char *locator);
bool32 sql_find_trigger_column(galist_t *update_pairs, galist_t *trigger_col);
status_t sql_execute_update_trigs(sql_stmt_t *stmt, trig_set_t *set, uint32 type, knl_cursor_t *knl_cur,
    upd_object_t *object);

static inline status_t sql_execute_update_triggers(sql_stmt_t *stmt, uint32 type, knl_cursor_t *knl_cur,
    upd_object_t *object)
{
    knl_dictionary_t *dc = &object->table->entry->dc;
    dc_entity_t *dc_entity = (dc_entity_t *)dc->handle;

    if (stmt->session->triggers_disable) {
        return CT_SUCCESS;
    }

    if (dc_entity->trig_set.trig_count == 0) {
        return CT_SUCCESS;
    }

    /* add TS lock, controls trigger concurrency */
    if (lock_table_shared(KNL_SESSION(stmt), dc_entity, LOCK_INF_WAIT) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return sql_execute_update_trigs(stmt, &dc_entity->trig_set, type, knl_cur, object);
}

static inline status_t sql_execute_update_stmt_trigs(sql_stmt_t *stmt, update_plan_t *update_plan, uint32 type)
{
    upd_object_t *object = NULL;

    for (uint32 i = 0; i < update_plan->objects->count; i++) {
        object = (upd_object_t *)cm_galist_get(update_plan->objects, i);
        CT_RETURN_IFERR(sql_execute_update_triggers(stmt, type, NULL, object));
    }
    return CT_SUCCESS;
}

static inline status_t sql_init_update_assist(update_assist_t *assist, upd_object_t *object)
{
    assist->pair_id = 0;
    assist->object = object;
    MEMS_RETURN_IFERR(memset_s(assist->rs_values, CT_MAX_SUBSELECT_EXPRS * sizeof(void *), 0,
        CT_MAX_SUBSELECT_EXPRS * sizeof(void *)));
    return CT_SUCCESS;
}

#ifdef __cplusplus
}
#endif
#endif
