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
 * ctsql_join_comm.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_join_comm.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_join_comm.h"
#include "ctsql_mtrl.h"
#include "ctsql_scan.h"
#include "ctsql_select.h"
#include "srv_instance.h"
#include "knl_mtrl.h"
#include "ctsql_concate.h"

status_t sql_init_cursor_for_subselect_table(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_table_cursor_t *tab_cur,
    sql_table_t *table, uint32 i)
{
    sql_cursor_t *sql_cursor = NULL;
    mtrl_row_t *row = &tab_cur->sql_cur->mtrl.cursor.row;

    CT_RETURN_IFERR(sql_alloc_cursor(stmt, &sql_cursor));
    sql_cursor->scn = tab_cur->scn;
    sql_cursor->select_ctx = table->select_ctx;
    sql_cursor->plan = table->select_ctx->plan;
    sql_cursor->global_cached = cursor->global_cached || table->global_cached;
    sql_cursor->ancestor_ref = cursor;
    cursor->tables[table->id].sql_cur = sql_cursor;
    sql_init_row_addr(stmt, cursor, &row->data, row->offsets, row->lens, NULL, NULL, i);
    sql_open_select_cursor(stmt, tab_cur->sql_cur, tab_cur->sql_cur->plan->select_p.rs_columns);

    return CT_SUCCESS;
}

status_t sql_mtrl_init_table_cursors(sql_stmt_t *stmt, join_info_t *join_info, sql_cursor_t *sql_cursor,
                                     sql_cursor_t *parent)
{
    sql_table_t *table = NULL;
    sql_table_cursor_t *tab_cur = NULL;
    knl_cursor_t *knl_cursor = NULL;

    for (uint32 i = 0; i < join_info->rs_tables.count; i++) {
        table = (sql_table_t *)sql_array_get(&join_info->rs_tables, i);
        tab_cur = &parent->tables[table->id];
        sql_cursor->id_maps[i] = table->id;
        sql_cursor->tables[table->id].table = tab_cur->table;
        sql_cursor->tables[table->id].scan_flag = table->tf_scan_flag;
        sql_cursor->tables[table->id].scn = tab_cur->scn;
        sql_cursor->tables[table->id].action = CURSOR_ACTION_SELECT;
        sql_init_varea_set(stmt, &sql_cursor->tables[table->id]);

        if (CT_IS_SUBSELECT_TABLE(table->type)) {
            CT_RETURN_IFERR(sql_init_cursor_for_subselect_table(stmt, sql_cursor, tab_cur, table, i));
            sql_cursor->table_count++;
            continue;
        }

        CT_RETURN_IFERR(sql_alloc_knl_cursor(stmt, &knl_cursor));
        knl_cursor->action = tab_cur->knl_cur->action;
        knl_cursor->rowmark = tab_cur->knl_cur->rowmark;
        knl_cursor->global_cached = sql_cursor->global_cached || table->global_cached;
        sql_cursor->tables[table->id].knl_cur = knl_cursor;
        sql_init_row_addr(stmt, sql_cursor, (char **)&tab_cur->knl_cur->row, tab_cur->knl_cur->offsets,
                          tab_cur->knl_cur->lens, &tab_cur->knl_cur->rowid, NULL, i);
        sql_cursor->table_count++;
    }

    return CT_SUCCESS;
}

status_t sql_mtrl_init_cursor(sql_stmt_t *stmt, sql_cursor_t *parent, sql_cursor_t *sql_cursor, join_info_t *join_info,
    plan_node_t *plan)
{
    if (sql_cursor->is_open) {
        sql_close_cursor(stmt, sql_cursor);
    }
    sql_cursor->eof = CT_FALSE;
    sql_cursor->is_open = CT_TRUE;
    sql_cursor->max_rownum = CT_INVALID_ID32;
    sql_reset_mtrl(stmt, sql_cursor);
    sql_cursor->cond = join_info->filter_cond;
    sql_cursor->table_count = 0;
    sql_cursor->is_mtrl_cursor = CT_TRUE;
    sql_cursor->global_cached = parent->global_cached;
    CT_RETURN_IFERR(
        vmc_alloc(&sql_cursor->vmc, sizeof(row_addr_t) * join_info->rs_tables.count, (void **)&sql_cursor->exec_data.join));

    sql_array_t *query_tabs = sql_get_query_tables(parent, parent->query);
    CT_RETURN_IFERR(sql_alloc_table_cursors(sql_cursor, query_tabs->count));
    CT_RETURN_IFERR(sql_mtrl_init_table_cursors(stmt, join_info, sql_cursor, parent));

    sql_cursor->ancestor_ref = parent->ancestor_ref;
    sql_cursor->query = parent->query;
    sql_mtrl_init_savepoint(sql_cursor);
    sql_init_ssa_cursor_maps(sql_cursor, parent->query->ssa.count);

    // for nest-loop outer join
    if (sql_cursor->query != NULL) {
        CT_RETURN_IFERR(sql_generate_cursor_exec_data(stmt, sql_cursor, sql_cursor->query));
    }
    return CT_SUCCESS;
}

status_t sql_mtrl_fetch_tables_row(mtrl_context_t *ctx, mtrl_cursor_t *mtrl_cursor, row_addr_t *row_addrs, mtrl_rowid_t *rids,
    uint32 count)
{
    mtrl_rowid_t *mtrl_rid = NULL;
    vm_page_t *vm_page = NULL;
    char *rs_row = NULL;
    uint16 rs_row_size;

    if (count > CT_MAX_JOIN_TABLES) {
        return CT_ERROR;
    }
    mtrl_close_history_page(ctx, mtrl_cursor);
    for (uint32 i = 0; i < count; i++) {
        mtrl_rid = &rids[i];
        if (mtrl_rid->vmid != mtrl_cursor->rs_vmid) {
            if (mtrl_cursor->rs_vmid != CT_INVALID_ID32) {
                mtrl_cursor->history[mtrl_cursor->count++] = mtrl_cursor->rs_vmid;
                mtrl_cursor->rs_vmid = CT_INVALID_ID32;
            }
            CT_RETURN_IFERR(mtrl_open_page(ctx, mtrl_rid->vmid, &vm_page));
            mtrl_cursor->rs_vmid = mtrl_rid->vmid;
            mtrl_cursor->rs_page = (mtrl_page_t *)vm_page->data;
        }
        // get rs_row
        rs_row = MTRL_GET_ROW(mtrl_cursor->rs_page, mtrl_rid->slot);
        *(row_addrs[i].data) = rs_row;
        cm_decode_row(rs_row, row_addrs[i].offset, row_addrs[i].len, NULL);

        rs_row_size = ((row_head_t *)rs_row)->size;
        // read table rowid into mtrl
        if (row_addrs[i].rowid != NULL) {
            *(row_addrs[i].rowid) = *(rowid_t *)(rs_row + rs_row_size - KNL_ROWID_LEN);
        }

        if (IS_COORDINATOR) {
            // read table rownodeid into mtrl
            if (row_addrs[i].rownodeid != NULL) {
                *(row_addrs[i].rownodeid) = *(uint16 *)(rs_row + rs_row_size - KNL_ROWID_LEN - REMOTE_ROWNODEID_LEN);
            }
        }
    }
    return CT_SUCCESS;
}

status_t sql_mtrl_alloc_cursor(sql_stmt_t *stmt, sql_cursor_t *parent, sql_cursor_t **sql_cursor,
                               join_info_t *join_join, plan_node_t *plan)
{
    if (*sql_cursor == NULL) {
        CT_RETURN_IFERR(sql_alloc_cursor(stmt, sql_cursor));
    }

    if (sql_mtrl_init_cursor(stmt, parent, *sql_cursor, join_join, plan) != CT_SUCCESS) {
        sql_free_cursor(stmt, *sql_cursor);
        *sql_cursor = NULL;
        return CT_ERROR;
    }

    // inherit table cur from parent which not used by hash or merge join
    for (uint32 i = 0; i < parent->query->tables.count; i++) {
        if ((*sql_cursor)->tables[i].table == NULL) {
            (*sql_cursor)->tables[i] = parent->tables[i];
        }
    }
    return CT_SUCCESS;
}

status_t sql_execute_for_join(sql_stmt_t *stmt, sql_cursor_t *sql_cursor, plan_node_t *plan)
{
    status_t status;

    CT_RETURN_IFERR(SQL_CURSOR_PUSH(stmt, sql_cursor));
    switch (plan->type) {
        case PLAN_NODE_JOIN:
            status = sql_execute_join(stmt, sql_cursor, plan, &sql_cursor->eof);
            break;

        case PLAN_NODE_SCAN:
            status = sql_execute_scan(stmt, sql_cursor, plan);
            break;

        case PLAN_NODE_CONCATE:
            status = sql_execute_concate(stmt, sql_cursor, plan);
            break;

        default:
            status = CT_ERROR;
            CT_THROW_ERROR(ERR_SQL_PLAN_ERROR, "not support plan type for join", plan->type);
            break;
    }
    SQL_CURSOR_POP(stmt);
    return status;
}

status_t sql_fetch_for_join(sql_stmt_t *stmt, sql_cursor_t *sql_cursor, plan_node_t *plan, bool32 *eof)
{
    switch (plan->type) {
        case PLAN_NODE_JOIN:
            return sql_fetch_join(stmt, sql_cursor, plan, eof);

        case PLAN_NODE_SCAN:
            sql_cursor->last_table = plan->scan_p.table->plan_id;
            return sql_fetch_scan(stmt, sql_cursor, plan, eof);

        case PLAN_NODE_REMOTE_SCAN:
	    knl_panic(0);
	    return CT_ERROR;

        case PLAN_NODE_CONCATE:
            return sql_fetch_concate(stmt, sql_cursor, plan, eof);

        default:
            break;
    }
    CT_THROW_ERROR(ERR_SQL_PLAN_ERROR, "not support plan type for join", plan->type);
    return CT_ERROR;
}

void sql_reset_cursor_eof(sql_cursor_t *parent, join_info_t *join_info, bool32 eof)
{
    sql_table_t *table = NULL;
    sql_table_cursor_t *tab_cursor = NULL;

    for (uint32 i = 0; i < join_info->rs_tables.count; i++) {
        table = (sql_table_t *)sql_array_get(&join_info->rs_tables, i);
        tab_cursor = &parent->tables[table->id];
        if (CT_IS_SUBSELECT_TABLE(table->type)) {
            tab_cursor->sql_cur->eof = eof;
        } else if (table->remote_type != REMOTE_TYPE_LOCAL) {
		knl_panic(0);
        } else {
            tab_cursor->knl_cur->eof = eof;
        }
    }
}
