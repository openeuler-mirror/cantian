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
 * ctsql_merge.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_merge.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctsql_scan.h"
#include "ctsql_merge.h"
#include "srv_instance.h"
#include "ctsql_mtrl.h"
#include "ctsql_concate.h"

static status_t sql_execute_merge_update(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    sql_merge_t *merge_context = NULL;
    sql_table_t *merge_to_table = NULL;
    bool32 is_found = CT_TRUE;
    upd_object_t *object = NULL;
    sql_table_cursor_t *tab_cur = NULL;

    stmt->merge_type = MERGE_TYPE_UPDATE;
    merge_context = (sql_merge_t *)stmt->context->entry;
    if (merge_context->update_ctx == NULL) {
        return CT_SUCCESS;
    }

    if (merge_context->update_filter_cond != NULL &&
        sql_match_cond_node(stmt, merge_context->update_filter_cond->root, &is_found) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!is_found) {
        return CT_SUCCESS;
    }

    cursor->total_rows++;
    object = (upd_object_t *)cm_galist_get(merge_context->update_ctx->objects, 0);
    merge_to_table = (sql_table_t *)sql_array_get(&merge_context->query->tables, 0);
    tab_cur = &cursor->tables[merge_to_table->id];
    return sql_execute_update_table(stmt, cursor, tab_cur->knl_cur, object);
}

static status_t sql_execute_merge_insert(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    sql_merge_t *merge_context = NULL;
    sql_cursor_t *sub_cur = NULL;
    bool32 is_found = CT_TRUE;
    merge_context = (sql_merge_t *)stmt->context->entry;
    stmt->merge_type = MERGE_TYPE_INSERT;
    if (merge_context->insert_ctx == NULL) {
        return CT_SUCCESS;
    }

    if (merge_context->insert_filter_cond != NULL &&
        sql_match_cond_node(stmt, merge_context->insert_filter_cond->root, &is_found) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (!is_found) {
        return CT_SUCCESS;
    }

    if (sql_alloc_cursor(stmt, &sub_cur) != CT_SUCCESS) {
        return CT_ERROR;
    }
    sub_cur->scn = cursor->scn;

    if (sql_open_insert_cursor(stmt, sub_cur, merge_context->insert_ctx) != CT_SUCCESS) {
        sql_free_cursor(stmt, sub_cur);
        return CT_ERROR;
    }

    if (sql_execute_insert_plan(stmt, sub_cur, merge_context->insert_ctx) != CT_SUCCESS) {
        sql_free_cursor(stmt, sub_cur);
        return CT_ERROR;
    }

    cursor->total_rows += sub_cur->total_rows;
    sql_free_cursor(stmt, sub_cur);

    return CT_SUCCESS;
}

static inline status_t sql_execute_for_merge(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan_node)
{
    if (plan_node->type == PLAN_NODE_CONCATE) {
        return sql_execute_concate(stmt, cursor, plan_node);
    }

    return sql_execute_scan(stmt, cursor, plan_node);
}

static inline status_t sql_fetch_for_merge(sql_stmt_t *stmt, sql_cursor_t *sql_cur,
                                           plan_node_t *plan_node, bool32 *eof)
{
    if (plan_node->type == PLAN_NODE_CONCATE) {
        return sql_fetch_concate(stmt, sql_cur, plan_node, eof);
    }

    return sql_fetch_scan(stmt, sql_cur, plan_node, eof);
}

static inline status_t sql_fetch_for_merge_match(sql_stmt_t *stmt, sql_cursor_t *cursor, plan_node_t *plan_node)
{
    if ((cursor)->rownum >= (cursor)->max_rownum) {
        cursor->eof = CT_TRUE;
        return CT_SUCCESS;
    }
    cursor->rownum++;
    return sql_fetch_for_merge(stmt, cursor, plan_node, &cursor->eof);
}

static status_t sql_execute_merge_match(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    sql_merge_t *merge_context;
    plan_node_t *plan;
    bool32 matched = CT_FALSE;
    sql_table_t *merge_to_table;

    merge_context = (sql_merge_t *)stmt->context->entry;
    merge_to_table = (sql_table_t *)sql_array_get(&merge_context->query->tables, 0);
    plan = cursor->plan->merge_p.merge_into_scan_p;

    cursor->last_table = merge_to_table->plan_id;
    cursor->cond = merge_context->query->cond;
    CT_RETURN_IFERR(sql_execute_for_merge(stmt, cursor, plan));

    do {
        CT_RETURN_IFERR(sql_fetch_for_merge_match(stmt, cursor, plan));

        if (cursor->eof) {
            cursor->eof = CT_FALSE;

            if (!matched) {
                return sql_execute_merge_insert(stmt, cursor);
            }

            return CT_SUCCESS;
        }

        matched = CT_TRUE;
        if (sql_execute_merge_update(stmt, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } while (CT_TRUE);
}

static status_t sql_execute_merge_into_nl_join_plan(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    sql_merge_t *merge_context = (sql_merge_t *)stmt->context->entry;
    bool32 eof = CT_FALSE;
    sql_table_t *using_table = (sql_table_t *)sql_array_get(&merge_context->query->tables, 1);

    cursor->last_table = using_table->plan_id;
    CT_RETURN_IFERR(sql_execute_for_merge(stmt, cursor, cursor->plan->merge_p.using_table_scan_p));

    while (CT_TRUE) {
        cursor->last_table = using_table->plan_id;
        cursor->cond = NULL;
        CT_RETURN_IFERR(sql_fetch_for_merge(stmt, cursor, cursor->plan->merge_p.using_table_scan_p, &eof));

        if (eof) {
            return CT_SUCCESS;
        }

        if (sql_execute_merge_match(stmt, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
}

static status_t sql_make_mtrl_merge_into_table_row(sql_stmt_t *stmt, sql_cursor_t *cursor, char *buf,
    ct_type_t *key_types, bool32 *has_null)
{
    row_assist_t ra;
    merge_plan_t *merge_p = &cursor->plan->merge_p;
    sql_table_t *merge_to_table = merge_p->merge_into_table;

    CT_RETURN_IFERR(sql_make_hash_key(stmt, &ra, buf, merge_p->merge_keys, key_types, has_null));

    return sql_make_mtrl_table_rs_row(stmt, cursor, cursor->tables, merge_to_table, buf + ra.head->size,
        CT_MAX_ROW_SIZE - ra.head->size);
}

static status_t sql_mtrl_merge_into_table(sql_stmt_t *stmt, sql_cursor_t *cursor, hash_segment_t *hash_seg,
    hash_table_entry_t *hash_table, ct_type_t *key_types)
{
    bool32 eof = CT_FALSE;
    char *buf = NULL;
    status_t status = CT_ERROR;
    plan_node_t *plan = NULL;
    sql_table_t *merge_to_table = NULL;
    bool32 found = CT_FALSE;
    uint32 buf_size;
    sql_table_cursor_t *tab_cur = &cursor->tables[0];
    knl_cursor_t *knl_cursor = tab_cur->knl_cur;
    bool32 has_null = CT_FALSE;

    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&buf));

    merge_to_table = cursor->plan->merge_p.merge_into_table;
    plan = cursor->plan->merge_p.merge_into_scan_p;

    cursor->last_table = merge_to_table->plan_id;
    cursor->cond = cursor->plan->merge_p.merge_table_filter_cond;
    knl_cursor->action = CURSOR_ACTION_SELECT;
    CT_RETURN_IFERR(sql_execute_for_merge(stmt, cursor, plan));

    for (;;) {
        if (sql_fetch_for_merge(stmt, cursor, plan, &eof) != CT_SUCCESS) {
            break;
        }
        if (eof) {
            status = CT_SUCCESS;
            break;
        }
        if (sql_make_mtrl_merge_into_table_row(stmt, cursor, buf, key_types, &has_null) != CT_SUCCESS) {
            break;
        }
        if (has_null) {
            continue;
        }

        buf_size = ((row_head_t *)buf)->size;               // key size
        buf_size += ((row_head_t *)(buf + buf_size))->size; // data size
        if (vm_hash_table_insert(&found, hash_seg, hash_table, buf, buf_size) != CT_SUCCESS) {
            break;
        }
    }

    CTSQL_POP(stmt);
    CT_RETURN_IFERR(status);

    knl_cursor->action = CURSOR_ACTION_UPDATE;
    knl_cursor->scan_mode = SCAN_MODE_ROWID;
    status = knl_reopen_cursor(&stmt->session->knl_session, knl_cursor, &tab_cur->table->entry->dc);
    return status;
}

static status_t sql_make_mtrl_using_table_key(sql_stmt_t *stmt, merge_plan_t *merge_p, char *buf, ct_type_t *key_types)
{
    row_assist_t ra;
    bool32 has_null = CT_FALSE;
    return sql_make_hash_key(stmt, &ra, buf, merge_p->using_keys, key_types, &has_null);
}

static status_t sql_execute_merge_into_hash_opt(void *callback_ctx, const char *new_buf, uint32 new_size,
    const char *old_buf, uint32 old_size, bool32 found)
{
    // already find one row by hash key
    sql_cursor_t *cursor = (sql_cursor_t *)callback_ctx;
    sql_table_cursor_t *tab_cursor = &cursor->tables[0];
    knl_cursor_t *knl_cursor = tab_cursor->knl_cur;
    sql_merge_t *merge_context = cursor->merge_ctx;
    bool32 is_found;
    char *data;
    row_head_t *org_row;
    int32 code;
    const char *message = NULL;

    data = (char *)(old_buf + ((row_head_t *)old_buf)->size);
    org_row = knl_cursor->row;

    knl_cursor->eof = CT_FALSE;
    is_found = CT_TRUE;
    if (cursor->plan->merge_p.remain_on_cond != NULL) {
        knl_cursor->row = (row_head_t *)data;
        cm_decode_row(data, knl_cursor->offsets, knl_cursor->lens, NULL);
        CT_RETURN_IFERR(sql_match_cond_node(cursor->stmt, cursor->plan->merge_p.remain_on_cond->root, &is_found));
    }

    if (!is_found) {
        knl_cursor->row = org_row;
        return CT_SUCCESS;
    }

    knl_cursor->row = org_row;
    knl_cursor->rowid = *(rowid_t *)(data + ((row_head_t *)data)->size - KNL_ROWID_LEN);
    cursor->cond = merge_context->query->cond; // on condition
    if (knl_fetch_by_rowid(KNL_SESSION(cursor->stmt), knl_cursor, &is_found) != CT_SUCCESS) {
        cm_get_error(&code, &message, NULL);
        if (code == ERR_INVALID_ROWID) {
            cm_reset_error();
            return CT_SUCCESS;
        } else {
            return CT_ERROR;
        }
    }

    if (is_found) { // The materialized data may be modified by other sessions
        cursor->merge_into_hash.already_update = CT_TRUE;
        CT_RETURN_IFERR(sql_execute_merge_update(cursor->stmt, cursor));
    }

    return CT_SUCCESS;
}

static status_t sql_execute_merge_into_hash_join_match(sql_stmt_t *stmt, sql_cursor_t *cursor, char *key_buf,
    hash_segment_t *hash_seg, hash_table_entry_t *hash_table, hash_table_iter_t *iter)
{
    hash_scan_assist_t scan_ass;
    bool32 found = CT_FALSE;
    bool32 eof = CT_FALSE;

    scan_ass.scan_mode = HASH_KEY_SCAN;
    scan_ass.buf = key_buf;
    scan_ass.size = ((row_head_t *)key_buf)->size;
    CT_RETURN_IFERR(vm_hash_table_open(hash_seg, hash_table, &scan_ass, &found, iter));

    cursor->merge_into_hash.already_update = CT_FALSE;
    while (CT_TRUE) {
        if (vm_hash_table_fetch(&eof, hash_seg, hash_table, iter) != CT_SUCCESS) {
            iter->curr_match.vmid = CT_INVALID_ID32;
            return CT_ERROR;
        }

        if (eof) {
            break;
        }
    }
    iter->curr_match.vmid = CT_INVALID_ID32;

    if (!cursor->merge_into_hash.already_update) {
        CT_RETURN_IFERR(sql_execute_merge_insert(stmt, cursor));
    }

    return CT_SUCCESS;
}

static status_t sql_execute_merge_into_hash_join_plan(sql_stmt_t *stmt, sql_cursor_t *cursor, hash_segment_t *hash_seg,
    hash_table_iter_t *iter)
{
    sql_merge_t *merge_context = NULL;
    bool32 eof = CT_FALSE;
    sql_table_t *using_table = NULL;
    char *key_buf = NULL;
    ct_type_t *key_types = NULL;
    hash_table_entry_t hash_table;
    status_t ret = CT_SUCCESS;
    merge_plan_t *merge_p = &cursor->plan->merge_p;

    merge_context = (sql_merge_t *)stmt->context->entry;
    using_table = (sql_table_t *)sql_array_get(&merge_context->query->tables, 1);

    uint32 bucket_num = sql_get_plan_hash_rows(stmt, merge_p->using_table_scan_p);
    CT_RETURN_IFERR(vm_hash_table_alloc(&hash_table, hash_seg, bucket_num));
    CT_RETURN_IFERR(vm_hash_table_init(hash_seg, &hash_table, NULL, sql_execute_merge_into_hash_opt, cursor));

    CTSQL_SAVE_STACK(stmt);
    CT_RETURN_IFERR(sql_push(stmt, sizeof(ct_type_t) * merge_p->merge_keys->count, (void **)&key_types));
    CT_RETURN_IFERR(sql_get_hash_key_types(stmt, cursor->query, merge_p->merge_keys, merge_p->using_keys, key_types));

    CT_RETURN_IFERR(sql_mtrl_merge_into_table(stmt, cursor, hash_seg, &hash_table, key_types));

    cursor->last_table = using_table->plan_id;
    CT_RETURN_IFERR(sql_execute_for_merge(stmt, cursor, merge_p->using_table_scan_p));
    CT_RETURN_IFERR(sql_push(stmt, CT_MAX_ROW_SIZE, (void **)&key_buf));

    while (CT_TRUE) {
        cursor->cond = NULL;
        ret = sql_fetch_for_merge(stmt, cursor, merge_p->using_table_scan_p, &eof);
        CT_BREAK_IF_ERROR(ret);
        if (eof) {
            if (iter->hash_table != NULL) {
                vm_hash_close_page(hash_seg, &hash_table.page);
                iter->hash_table = NULL;
            }
            return CT_SUCCESS;
        }

        ret = sql_make_mtrl_using_table_key(stmt, merge_p, key_buf, key_types);
        CT_BREAK_IF_ERROR(ret);
        ret = sql_execute_merge_into_hash_join_match(stmt, cursor, key_buf, hash_seg, &hash_table, iter);
        CT_BREAK_IF_ERROR(ret);
    }
    CTSQL_RESTORE_STACK(stmt);
    if (iter->hash_table != NULL) {
        vm_hash_close_page(hash_seg, &hash_table.page);
        iter->hash_table = NULL;
    }
    return ret;
}

static inline status_t sql_open_merge_cursor_for_using(sql_stmt_t *stmt, sql_cursor_t *cursor, sql_merge_t *ctx)
{
    sql_table_cursor_t *tab_cursor = &cursor->tables[1];

    tab_cursor->table = (sql_table_t *)sql_array_get(&ctx->query->tables, 1);
    cursor->id_maps[1] = tab_cursor->table->id;
    tab_cursor->scan_flag = tab_cursor->table->tf_scan_flag;
    sql_init_varea_set(stmt, tab_cursor);

    if (CT_IS_SUBSELECT_TABLE(tab_cursor->table->type)) {
        CT_RETURN_IFERR(sql_alloc_cursor(stmt, &tab_cursor->sql_cur));
        tab_cursor->sql_cur->scn = cursor->scn;
        tab_cursor->sql_cur->select_ctx = tab_cursor->table->select_ctx;
        tab_cursor->sql_cur->plan = tab_cursor->table->select_ctx->plan;
        tab_cursor->sql_cur->ancestor_ref = cursor;
    } else {
        tab_cursor->scn = cursor->scn;
        CT_RETURN_IFERR(sql_alloc_knl_cursor(stmt, &tab_cursor->knl_cur));
        tab_cursor->knl_cur->action = CURSOR_ACTION_SELECT;
    }

    return CT_SUCCESS;
}

static inline status_t sql_open_merge_cursor(sql_stmt_t *stmt, sql_cursor_t *sql_cursor, sql_merge_t *ctx)
{
    if (sql_cursor->is_open) {
        sql_close_cursor(stmt, sql_cursor);
    }
    CT_RETURN_IFERR(sql_alloc_table_cursors(sql_cursor, ctx->query->tables.count));

    sql_table_t *merge_to_table = (sql_table_t *)sql_array_get(&ctx->query->tables, 0);
    CT_RETURN_IFERR(sql_open_cursor_for_update(stmt, merge_to_table, &ctx->query->ssa, sql_cursor, CURSOR_ACTION_UPDATE));
    CT_RETURN_IFERR(sql_open_merge_cursor_for_using(stmt, sql_cursor, ctx));

    sql_cursor->table_count = ctx->query->tables.count;
    sql_cursor->cond = NULL;
    sql_cursor->max_rownum = GET_MAX_ROWNUM(ctx->query->cond);
    sql_cursor->plan = ctx->plan;
    sql_cursor->merge_ctx = ctx;
    sql_cursor->query = ctx->query;
    return CT_SUCCESS;
}

static status_t sql_execute_merge_core(sql_stmt_t *stmt)
{
    hash_segment_t hash_segment;
    hash_table_iter_t table_iter;
    uint64 conflicts = 0;
    sql_merge_t *merge_context = (sql_merge_t *)stmt->context->entry;
    sql_table_t *merge_to_table = (sql_table_t *)sql_array_get(&merge_context->query->tables, 0);
    sql_cursor_t *cursor = CTSQL_ROOT_CURSOR(stmt);
    cursor->scn = CT_INVALID_ID64;
    cursor->total_rows = 0;
    status_t status = CT_ERROR;
    sql_init_hash_iter(&table_iter, NULL);

    /*
     * reset index conflicts to 0, and check it after stmt
     * to see if unique constraints violated
     */
    knl_init_index_conflicts(KNL_SESSION(stmt), &conflicts);
    CT_RETURN_IFERR(sql_before_execute_merge(stmt, merge_to_table));

    // set statement ssn after the before statement triggers executed
    sql_set_scn(stmt);
    sql_set_ssn(stmt);
    knl_update_info_t *old_ui = KNL_SESSION(stmt)->trig_ui;
    CM_SAVE_STACK(KNL_SESSION(stmt)->stack);
    do {
        // new update_info need push memory from stack if execute update statement in trigger,
        // and save the old update_info address.
        knl_update_info_t update_info;
        if (stmt->is_sub_stmt && (stmt->pl_exec != NULL && ((pl_executor_t *)stmt->pl_exec)->trig_exec != NULL)) {
            uint16 col_cnt = KNL_SESSION(stmt)->kernel->attr.max_column_count;
            CT_BREAK_IF_ERROR(sql_push(stmt, col_cnt * sizeof(uint16), (void **)&update_info.columns));
            CT_BREAK_IF_ERROR(sql_push(stmt, col_cnt * sizeof(uint16), (void **)&update_info.offsets));
            CT_BREAK_IF_ERROR(sql_push(stmt, col_cnt * sizeof(uint16), (void **)&update_info.lens));
            KNL_SESSION(stmt)->trig_ui = &update_info;
        }

        CT_BREAK_IF_ERROR(sql_open_merge_cursor(stmt, cursor, merge_context));
        if (cursor->plan->merge_p.merge_keys != NULL && cursor->plan->merge_p.merge_keys->count > 0) {
            vm_hash_segment_init(KNL_SESSION(stmt), stmt->mtrl.pool, &hash_segment, PMA_POOL, HASH_PAGES_HOLD,
                HASH_AREA_SIZE);
            if (sql_execute_merge_into_hash_join_plan(stmt, cursor, &hash_segment, &table_iter) != CT_SUCCESS) {
                vm_hash_segment_deinit(&hash_segment);
                break;
            }
            vm_hash_segment_deinit(&hash_segment);
        } else {
            CT_BREAK_IF_ERROR(sql_execute_merge_into_nl_join_plan(stmt, cursor));
        }

        CT_BREAK_IF_ERROR(sql_after_execute_merge(stmt, merge_to_table));
        CT_BREAK_IF_ERROR(knl_check_index_conflicts(KNL_SESSION(stmt), conflicts));
        status = CT_SUCCESS;
    } while (0);

    CM_RESTORE_STACK(KNL_SESSION(stmt)->stack);
    KNL_SESSION(stmt)->trig_ui = old_ui;
    cursor->eof = CT_TRUE;
    stmt->eof = CT_TRUE;
    return status;
}


status_t sql_execute_merge(sql_stmt_t *stmt)
{
    status_t status = CT_ERROR;
    knl_savepoint_t savepoint;

    do {
        knl_savepoint(KNL_SESSION(stmt), &savepoint);
        status = sql_execute_merge_core(stmt);
        // execute merge failed when shrink table, need restart
        if (status == CT_ERROR && cm_get_error_code() == ERR_NEED_RESTART) {
            CT_LOG_RUN_INF("merge failed when shrink table, merge restart");
            cm_reset_error();
            knl_rollback(KNL_SESSION(stmt), &savepoint);
            sql_set_scn(stmt);
            continue;
        } else {
            break;
        }
    } while (CT_TRUE);

    return status;
}