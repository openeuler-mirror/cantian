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
 * ctsql_group_cube.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_group_cube.c
 *
 * -------------------------------------------------------------------------
 */

#include "ctsql_group_cube.h"
#include "ctsql_group.h"
#include "ctsql_select.h"

static void sql_init_cube_node_maps(cube_node_t *cube, cube_data_t *cube_data)
{
    cube_node_t *sub_node = NULL;
    cube_data->maps[cube->group_set->group_id] = cube;

    if (cube->leafs == NULL) {
        return;
    }
    for (uint32 i = 0; i < cube->leafs->count; i++) {
        sub_node = (cube_node_t *)cm_galist_get(cube->leafs, i);
        sql_init_cube_node_maps(sub_node, cube_data);
    }
}

static status_t sql_init_cube_exec_data(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    cube_node_t *cube = NULL;
    cube_data_t *data = NULL;
    uint32 group_count = plan->cube.sets->count;
    CT_RETURN_IFERR(vmc_alloc(&cursor->vmc, sizeof(cube_data_t), (void **)&data));
    CT_RETURN_IFERR(vmc_alloc(&cursor->vmc, sizeof(pointer_t) * group_count, (void **)&data->maps));

    data->nodes = plan->cube.nodes;
    data->sets = plan->cube.sets;
    data->plans = plan->cube.plans;
    data->fetch_cursor = cursor;
    data->fetch_plan = plan->cube.next;
    data->group_cursor = NULL;
    biqueue_init(&data->curs_que);

    for (uint32 i = 0; i < data->nodes->count; i++) {
        cube = (cube_node_t *)cm_galist_get(data->nodes, i);
        sql_init_cube_node_maps(cube, data);
    }
    cursor->exec_data.group_cube = data;
    return CT_SUCCESS;
}

static status_t sql_prepare_cube_group_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    plan_node_t *plan = NULL;
    sql_cursor_t *sub_cursor = NULL;
    group_set_t *group_set = NULL;
    cube_node_t *cube = NULL;
    cube_data_t *data = cursor->exec_data.group_cube;
    group_data_t *group_data = data->fetch_cursor->exec_data.group;

    if (data->group_cursor != NULL) {
        biqueue_add_tail(&data->curs_que, QUEUE_NODE_OF(data->group_cursor));
        data->group_cursor = NULL;
    }

    group_set = (group_set_t *)cm_galist_get(group_data->group_p->sets, group_data->curr_group);
    cube = data->maps[group_set->group_id];

    if (cube->plan_id == CT_INVALID_ID32) {
        data->group_cursor = NULL;
        return CT_SUCCESS;
    }

    CT_RETURN_IFERR(sql_alloc_cursor(stmt, &sub_cursor));
    plan = (plan_node_t *)cm_galist_get(data->plans, cube->plan_id);
    if (sql_alloc_hash_group_ctx(stmt, sub_cursor, plan, HASH_GROUP_TYPE, 0) != CT_SUCCESS) {
        sub_cursor->is_open = CT_TRUE;
        sql_free_cursor(stmt, sub_cursor);
        return CT_ERROR;
    }

    sub_cursor->plan = plan;
    sub_cursor->mtrl.cursor.type = MTRL_CURSOR_HASH_GROUP;
    sub_cursor->ancestor_ref = cursor->ancestor_ref;
    sub_cursor->is_open = CT_TRUE;
    data->group_cursor = sub_cursor;
    return CT_SUCCESS;
}

static status_t sql_prepare_cube_fetch_cursor(sql_stmt_t *stmt, sql_cursor_t *cursor, bool32 *eof)
{
    *eof = CT_FALSE;
    biqueue_node_t *node = NULL;
    cube_data_t *data = cursor->exec_data.group_cube;

    // free previous cursor
    if (data->fetch_cursor != cursor) {
        sql_free_cursor(stmt, data->fetch_cursor);
        data->fetch_cursor = NULL;
    }

    if (biqueue_empty(&data->curs_que)) {
        if (data->group_cursor == NULL) {
            *eof = CT_TRUE;
            return CT_SUCCESS;
        }
        data->fetch_cursor = data->group_cursor;
        data->group_cursor = NULL;
    } else {
        node = biqueue_del_head(&data->curs_que);
        data->fetch_cursor = OBJECT_OF(sql_cursor_t, node);
    }
    data->fetch_plan = data->fetch_cursor->plan;

    // prepare for fetch
    return sql_hash_group_open_cursor(stmt, data->fetch_cursor, data->fetch_cursor->group_ctx, 0);
}

status_t sql_execute_group_cube(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan)
{
    CT_RETURN_IFERR(sql_init_cube_exec_data(stmt, cursor, plan));

    CT_RETURN_IFERR(sql_execute_query_plan(stmt, cursor, plan->cube.next));
    if (cursor->eof) {
        return CT_SUCCESS;
    }
    return sql_prepare_cube_group_cursor(stmt, cursor);
}

static status_t sql_mtrl_cube_group_row(sql_stmt_t *stmt, sql_cursor_t *group_cur)
{
    char *buf = NULL;
    uint32 size, key_size;
    bool32 found = CT_FALSE;
    hash_segment_t *hash_seg = NULL;
    hash_table_entry_t *hash_table = NULL;
    group_data_t *group_data = NULL;
    status_t status = CT_SUCCESS;

    group_data = group_cur->exec_data.group;
    group_cur->group_ctx->empty = CT_FALSE;
    hash_seg = &group_cur->group_ctx->hash_segment;

    CTSQL_SAVE_STACK(stmt);
    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buf));

    for (uint32 i = 0; i < group_data->group_p->sets->count; i++) {
        hash_table = &group_cur->group_ctx->hash_tables[i];
        if (sql_make_hash_group_row_new(stmt, group_cur->group_ctx, i, buf, &size, &key_size, NULL) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }
        group_cur->group_ctx->oper_type = OPER_TYPE_INSERT;
        if (vm_hash_table_insert2(&found, hash_seg, hash_table, buf, size) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }
    }
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

status_t sql_fetch_group_cube(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan, bool32 *eof)
{
    status_t status = CT_SUCCESS;
    bool32 group_chgd = CT_FALSE;
    cube_data_t *cube_data = cursor->exec_data.group_cube;
    group_data_t *group_data = cube_data->fetch_cursor->exec_data.group;
    uint32 old_group_id = group_data->curr_group;

    cursor->mtrl.cursor.type = MTRL_CURSOR_HASH_GROUP;
    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cube_data->fetch_cursor));
    CTSQL_SAVE_STACK(stmt);

    do {
        if (sql_fetch_query(stmt, cube_data->fetch_cursor, cube_data->fetch_plan, eof) != CT_SUCCESS) {
            status = CT_ERROR;
            break;
        }

        if (*eof) {
            // change fetch cursor
            if (sql_prepare_cube_fetch_cursor(stmt, cursor, eof) != CT_SUCCESS) {
                status = CT_ERROR;
                break;
            }
            if (*eof) {
                break;
            }
            group_chgd = CT_TRUE;
            group_data = cube_data->fetch_cursor->exec_data.group;
            old_group_id = group_data->curr_group;
            SQL_CURSOR_POP(stmt);
            CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, cube_data->fetch_cursor));
            CTSQL_RESTORE_STACK(stmt);
            continue;
        } else {
            group_chgd |= (bool32)(old_group_id != group_data->curr_group);
        }

        if (group_chgd) {
            if (sql_prepare_cube_group_cursor(stmt, cursor) != CT_SUCCESS) {
                status = CT_ERROR;
                break;
            }
            group_chgd = CT_FALSE;
            old_group_id = group_data->curr_group;
        }

        if (cube_data->group_cursor != NULL) {
            status = sql_mtrl_cube_group_row(stmt, cube_data->group_cursor);
        }
        break;
    } while (CT_TRUE);
    SQL_CURSOR_POP(stmt);
    CTSQL_RESTORE_STACK(stmt);
    return status;
}

void sql_free_group_cube(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    biqueue_node_t *curr = NULL;
    biqueue_node_t *end = NULL;
    sql_cursor_t *sub_cursor = NULL;
    cube_data_t *data = cursor->exec_data.group_cube;

    curr = biqueue_first(&data->curs_que);
    end = biqueue_end(&data->curs_que);
    while (curr != end) {
        sub_cursor = OBJECT_OF(sql_cursor_t, curr);
        curr = curr->next;
        sql_free_cursor(stmt, sub_cursor);
    }
    biqueue_init(&data->curs_que);

    if (data->fetch_cursor != cursor) {
        sql_free_cursor(stmt, data->fetch_cursor);
        data->fetch_cursor = NULL;
    }
    if (data->group_cursor != NULL) {
        sql_free_cursor(stmt, data->group_cursor);
        data->group_cursor = NULL;
    }
}
