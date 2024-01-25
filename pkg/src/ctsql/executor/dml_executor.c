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
 * dml_executor.c
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/dml_executor.c
 *
 * -------------------------------------------------------------------------
 */
#include "dml_executor.h"
#include "srv_instance.h"
#include "cm_file.h"
#include "ctsql_aggr.h"
#include "ctsql_group.h"
#include "ctsql_sort_group.h"
#include "ctsql_index_group.h"
#include "ctsql_sort.h"
#include "ctsql_distinct.h"
#include "ctsql_union.h"
#include "ctsql_select.h"
#include "ctsql_update.h"
#include "ctsql_insert.h"
#include "ctsql_delete.h"
#include "ctsql_limit.h"
#include "ctsql_merge.h"
#include "ctsql_replace.h"
#include "ctsql_mtrl.h"
#include "ctsql_minus.h"
#include "ctsql_winsort.h"
#include "ctsql_group_cube.h"
#include "ctsql_withas_mtrl.h"
#include "ctsql_proj.h"
#include "ctsql_concate.h"
#include "dml_parser.h"

#ifdef __cplusplus

extern "C" {
#endif

static void sql_reset_connect_data(sql_cursor_t *ctsql_cursor)
{
    ctsql_cursor->connect_data.next_level_cursor = NULL;
    ctsql_cursor->connect_data.last_level_cursor = NULL;
    ctsql_cursor->connect_data.first_level_cursor = NULL;
    ctsql_cursor->connect_data.cur_level_cursor = NULL;
    ctsql_cursor->connect_data.connect_by_isleaf = CT_FALSE;
    ctsql_cursor->connect_data.connect_by_iscycle = CT_FALSE;
    ctsql_cursor->connect_data.level = 0;
    ctsql_cursor->connect_data.first_level_rownum = 0;
    ctsql_cursor->connect_data.path_func_nodes = NULL;
    ctsql_cursor->connect_data.prior_exprs = NULL;
    ctsql_cursor->connect_data.path_stack = NULL;
}

static inline void sql_init_sql_cursor_mtrl(sql_mtrl_handler_t *ctsql_mtrl)
{
    ctsql_mtrl->cursor.sort.vmid = CT_INVALID_ID32;
    ctsql_mtrl->cursor.hash_group.aggrs = NULL;
    ctsql_mtrl->cursor.distinct.eof = CT_FALSE;
    ctsql_mtrl->cursor.distinct.row.lens = NULL;
    ctsql_mtrl->cursor.distinct.row.offsets = NULL;
    ctsql_mtrl->cursor.rs_vmid = CT_INVALID_ID32;
    ctsql_mtrl->cursor.rs_page = NULL;
    ctsql_mtrl->cursor.eof = CT_FALSE;
    ctsql_mtrl->cursor.slot = 0;
    ctsql_mtrl->cursor.count = 0;
    ctsql_mtrl->cursor.type = MTRL_CURSOR_OTHERS;
    mtrl_init_mtrl_rowid(&ctsql_mtrl->cursor.pre_cursor_rid);
    mtrl_init_mtrl_rowid(&ctsql_mtrl->cursor.next_cursor_rid);
    mtrl_init_mtrl_rowid(&ctsql_mtrl->cursor.curr_cursor_rid);
    ctsql_mtrl->rs.sid = CT_INVALID_ID32;
    ctsql_mtrl->rs.buf = NULL;
    ctsql_mtrl->predicate.sid = CT_INVALID_ID32;
    ctsql_mtrl->predicate.buf = NULL;
    ctsql_mtrl->query_block.sid = CT_INVALID_ID32;
    ctsql_mtrl->query_block.buf = NULL;
    ctsql_mtrl->outline.sid = CT_INVALID_ID32;
    ctsql_mtrl->outline.buf = NULL;
    ctsql_mtrl->sort.sid = CT_INVALID_ID32;
    ctsql_mtrl->sort.buf = NULL;
    ctsql_mtrl->sibl_sort.sid = CT_INVALID_ID32;
    ctsql_mtrl->sibl_sort.cursor_sid = CT_INVALID_ID32;
    ctsql_mtrl->aggr = CT_INVALID_ID32;
    ctsql_mtrl->aggr_str = CT_INVALID_ID32;
    ctsql_mtrl->sort_seg = CT_INVALID_ID32;
    ctsql_mtrl->group.sid = CT_INVALID_ID32;
    ctsql_mtrl->group.buf = NULL;
    ctsql_mtrl->group_index = CT_INVALID_ID32;
    ctsql_mtrl->distinct = CT_INVALID_ID32;
    ctsql_mtrl->index_distinct = CT_INVALID_ID32;
    ctsql_mtrl->aggr_fetched = CT_FALSE;
    ctsql_mtrl->winsort_rs.sid = CT_INVALID_ID32;
    ctsql_mtrl->winsort_aggr.sid = CT_INVALID_ID32;
    ctsql_mtrl->winsort_aggr_ext.sid = CT_INVALID_ID32;
    ctsql_mtrl->winsort_sort.sid = CT_INVALID_ID32;
    ctsql_mtrl->winsort_rs.buf = NULL;
    ctsql_mtrl->winsort_aggr.buf = NULL;
    ctsql_mtrl->winsort_aggr_ext.buf = NULL;
    ctsql_mtrl->winsort_sort.buf = NULL;
    ctsql_mtrl->hash_table_rs = CT_INVALID_ID32;
    ctsql_mtrl->for_update = CT_INVALID_ID32;
    ctsql_mtrl->save_point.vm_row_id.vmid = CT_INVALID_ID32;
}

static inline void sql_init_cur_exec_data(plan_exec_data_t *executor_data)
{
    executor_data->query_limit = NULL;
    executor_data->select_limit = NULL;
    executor_data->union_all = NULL;
    executor_data->minus.r_continue_fetch = CT_TRUE;
    executor_data->minus.rs_vmid = CT_INVALID_ID32;
    executor_data->minus.rnums = 0;
    executor_data->explain_col_max_size = NULL;
    executor_data->qb_col_max_size = NULL;
    executor_data->outer_join = NULL;
    executor_data->inner_join = NULL;
    executor_data->join = NULL;
    executor_data->aggr_dis = NULL;
    executor_data->select_view = NULL;
    executor_data->tab_parallel = NULL;
    executor_data->group = NULL;
    executor_data->group_cube = NULL;
    executor_data->nl_batch = NULL;
    executor_data->ext_knl_cur = NULL;
    executor_data->right_semi = NULL;
    executor_data->index_scan_range_ar = NULL;
    executor_data->part_scan_range_ar = NULL;
    executor_data->dv_plan_buf = NULL;
    CM_INIT_TEXTBUF(&executor_data->sort_concat, 0, NULL);
}

static inline void sql_init_cursor_hash_info(sql_cursor_t *ctsql_cursor)
{
    ctsql_cursor->merge_into_hash.already_update = CT_FALSE;
    ctsql_cursor->hash_seg.sess = NULL;
    ctsql_cursor->hash_table_entry.vmid = CT_INVALID_ID32;
    ctsql_cursor->hash_table_entry.offset = CT_INVALID_ID32;

    ctsql_cursor->hash_join_ctx = NULL;
    ctsql_cursor->hash_table_status = HASH_TABLE_STATUS_NOINIT;

    for (uint32 i = 0; i < CT_MAX_JOIN_TABLES; i++) {
        ctsql_cursor->hash_mtrl.hj_tables[i] = NULL;
    }
}

void sql_init_sql_cursor(sql_stmt_t *stmt, sql_cursor_t *ctsql_cursor)
{
    ctsql_cursor->stmt = stmt;
    ctsql_cursor->plan = NULL;
    ctsql_cursor->select_ctx = NULL;
    ctsql_cursor->cond = NULL;
    ctsql_cursor->query = NULL;
    ctsql_cursor->columns = NULL;
    ctsql_cursor->aggr_page = NULL;
    ctsql_cursor->eof = CT_FALSE;
    ctsql_cursor->total_rows = 0;
    ctsql_cursor->rownum = 0;
    ctsql_cursor->max_rownum = CT_INVALID_ID32;
    ctsql_cursor->last_table = 0;
    ctsql_cursor->table_count = 0;
    ctsql_cursor->tables = NULL;
    ctsql_cursor->scn = CT_INVALID_ID64;
    ctsql_cursor->is_mtrl_cursor = CT_FALSE;
    biqueue_init(&ctsql_cursor->ssa_cursors);

    // init mtrl exec data
    sql_init_sql_cursor_mtrl(&ctsql_cursor->mtrl);

    // init exec data of plan
    vmc_init(&stmt->session->vmp, &ctsql_cursor->vmc);
    sql_init_cur_exec_data(&ctsql_cursor->exec_data);

    // init connect by exec data
    sql_reset_connect_data(ctsql_cursor);

    // init hash clause exec data
    sql_init_cursor_hash_info(ctsql_cursor);

    ctsql_cursor->group_ctx = NULL;
    ctsql_cursor->cnct_ctx = NULL;
    ctsql_cursor->unpivot_ctx = NULL;
    ctsql_cursor->hash_mtrl_ctx = NULL;
    ctsql_cursor->distinct_ctx = NULL;
    ctsql_cursor->cb_mtrl_ctx = NULL;
    ctsql_cursor->m_join = NULL;

    ctsql_cursor->is_open = CT_FALSE;
    ctsql_cursor->is_result_cached = CT_FALSE;
    ctsql_cursor->exists_result = CT_FALSE;
    ctsql_cursor->left_cursor = NULL;
    ctsql_cursor->right_cursor = NULL;
    ctsql_cursor->ancestor_ref = NULL;
    ctsql_cursor->winsort_ready = CT_FALSE;
    ctsql_cursor->global_cached = CT_FALSE;
    ctsql_cursor->idx_func_cache = NULL;
}

bool32 sql_try_extend_global_cursor(object_t **object)
{
    char *buffer = NULL;
    uint32 sql_cur_size = CM_ALIGN8(OBJECT_HEAD_SIZE + sizeof(sql_cursor_t));
    uint32 ext_cnt, ext_buf_size;
    uint32 max_sql_cursors = g_instance->attr.reserved_sql_cursors +
        (g_instance->attr.sql_cursors_each_sess * g_instance->session_pool.max_sessions);
    object_pool_t extend_pool;
    errno_t rc_memzero;

    if (g_instance->sql_cur_pool.cnt >= max_sql_cursors) {
        return CT_FALSE;
    }

    cm_spin_lock(&g_instance->sql_cur_pool.lock, NULL);
    if (g_instance->sql_cur_pool.cnt < max_sql_cursors) {
        ext_cnt = MIN(max_sql_cursors - g_instance->sql_cur_pool.cnt, EXTEND_SQL_CURS_EACH_TIME);
        ext_buf_size = ext_cnt * sql_cur_size;
        if (ext_buf_size == 0 || ext_buf_size / sql_cur_size != ext_cnt) {
            cm_spin_unlock(&g_instance->sql_cur_pool.lock);
            return CT_FALSE;
        }
        buffer = (char *)malloc(ext_buf_size);
        if (buffer == NULL) {
            cm_spin_unlock(&g_instance->sql_cur_pool.lock);
            return CT_FALSE;
        }
        rc_memzero = memset_s(buffer, ext_buf_size, 0, ext_buf_size);
        if (rc_memzero != EOK) {
            cm_spin_unlock(&g_instance->sql_cur_pool.lock);
            CM_FREE_PTR(buffer);
            return CT_FALSE;
        }
        opool_attach(buffer, ext_buf_size, sql_cur_size, &extend_pool);
        olist_concat(&g_instance->sql_cur_pool.pool.free_objects, &extend_pool.free_objects);
        g_instance->sql_cur_pool.cnt += ext_cnt;
        *object = opool_alloc(&g_instance->sql_cur_pool.pool);
        cm_spin_unlock(&g_instance->sql_cur_pool.lock);
        return CT_TRUE;
    }
    cm_spin_unlock(&g_instance->sql_cur_pool.lock);
    return CT_FALSE;
}

/**
1.apply sql cursor from global sql cursor pools,if not enough,go to step 2
2.try to extend the global sql cursor pools, and return one sql cursor.if the extension fails,go to step 3
3.apply sql cursor via malloc,if malloc fails, return NULL
* */
status_t sql_alloc_global_sql_cursor(object_t **object)
{
    sql_cursor_t *cursor = NULL;
    object_pool_t *pool = &g_instance->sql_cur_pool.pool;
    errno_t errcode;
    if (pool->free_objects.count > 0) {
        cm_spin_lock(&g_instance->sql_cur_pool.lock, NULL);
        if (pool->free_objects.count > 0) {
            (*object) = opool_alloc(pool);
            cm_spin_unlock(&g_instance->sql_cur_pool.lock);
            return CT_SUCCESS;
        }
        cm_spin_unlock(&g_instance->sql_cur_pool.lock);
    }

    if (!sql_try_extend_global_cursor(object)) {
        *object = (object_t *)malloc(OBJECT_HEAD_SIZE + sizeof(sql_cursor_t));
        if ((*object) == NULL) {
            CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(sql_cursor_t), "creating sql cursor");
            return CT_ERROR;
        }
        errcode =
            memset_s(*object, OBJECT_HEAD_SIZE + sizeof(sql_cursor_t), 0, OBJECT_HEAD_SIZE + sizeof(sql_cursor_t));
        if (errcode != EOK) {
            CM_FREE_PTR(*object);
            CT_THROW_ERROR(ERR_SYSTEM_CALL, errcode);
            return CT_ERROR;
        }
        cursor = (sql_cursor_t *)(*object)->data;
        cursor->not_cache = CT_TRUE;
    }
    return CT_SUCCESS;
}

status_t sql_alloc_cursor(sql_stmt_t *ctsql_stmt, sql_cursor_t **cursor)
{
    object_t *object = NULL;
    object_pool_t *pool = &ctsql_stmt->session->sql_cur_pool;
    // apply preferentially from session. if not enough, apply from the global sql cursor pool.
    if (pool->free_objects.count > 0) {
        object = opool_alloc(pool);
    } else {
        CT_RETURN_IFERR(sql_alloc_global_sql_cursor(&object));
    }
    if (object == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)(OBJECT_HEAD_SIZE + sizeof(sql_cursor_t)), "creating sql cursor");
        return CT_ERROR;
    }

    *cursor = (sql_cursor_t *)object->data;
    sql_init_sql_cursor(ctsql_stmt, *cursor);
    olist_concat_single(&ctsql_stmt->sql_curs, object);
    return CT_SUCCESS;
}

status_t sql_alloc_knl_cursor(sql_stmt_t *ctsql_stmt, knl_cursor_t **cursor)
{
    object_pool_t *pool = &ctsql_stmt->session->knl_cur_pool;
    object_t *object = opool_alloc(pool);
    if (object == NULL) {
        CT_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)(OBJECT_HEAD_SIZE + g_instance->kernel.attr.cursor_size),
            "creating kernel cursor");
        return CT_ERROR;
    }

    *cursor = (knl_cursor_t *)object->data;
    KNL_INIT_CURSOR(*cursor);
    (*cursor)->stmt = ctsql_stmt;
    knl_init_cursor_buf(&ctsql_stmt->session->knl_session, *cursor);

    (*cursor)->rowid = g_invalid_rowid;
    (*cursor)->scn = KNL_INVALID_SCN;
    olist_concat_single(&ctsql_stmt->knl_curs, object);
    return CT_SUCCESS;
}

static void sql_free_sql_cursor_by_type(sql_stmt_t *stmt, sql_cursor_t *ctsql_cursor)
{
    object_t *object = (object_t *)((char *)ctsql_cursor - OBJECT_HEAD_SIZE);
    object_pool_t *pool = &stmt->session->sql_cur_pool;
    if (ctsql_cursor->not_cache) {
        CM_FREE_PTR(object);
    } else if (pool->free_objects.count < g_instance->attr.sql_cursors_each_sess) {
        olist_concat_single(&pool->free_objects, object);
    } else {
        pool = &g_instance->sql_cur_pool.pool;
        cm_spin_lock(&g_instance->sql_cur_pool.lock, NULL);
        olist_concat_single(&pool->free_objects, object);
        cm_spin_unlock(&g_instance->sql_cur_pool.lock);
    }
}

void sql_free_cursor(sql_stmt_t *ctsql_stmt, sql_cursor_t *ctsql_cursor)
{
    if (ctsql_cursor == NULL) {
        return;
    }
    object_t *object = (object_t *)((char *)ctsql_cursor - OBJECT_HEAD_SIZE);

    if (ctsql_cursor->is_open) {
        sql_close_cursor(ctsql_stmt, ctsql_cursor);
    }

    ctsql_cursor->hash_mtrl_ctx = NULL;

    if (ctsql_cursor->connect_data.first_level_cursor != NULL) {
        sql_reset_connect_data(ctsql_cursor);
    }

    sql_reset_mtrl(ctsql_stmt, ctsql_cursor);

    olist_remove(&ctsql_stmt->sql_curs, object);
    sql_free_sql_cursor_by_type(ctsql_stmt, ctsql_cursor);
}

void sql_free_cursors(sql_stmt_t *ctsql_stmt)
{
    while (ctsql_stmt->sql_curs.first != NULL) {
        sql_free_cursor(ctsql_stmt, (sql_cursor_t *)ctsql_stmt->sql_curs.first->data);
    }
}

void sql_free_knl_cursor(sql_stmt_t *ctsql_stmt, knl_cursor_t *ctsql_cursor)
{
    object_pool_t *pool = &ctsql_stmt->session->knl_cur_pool;
    object_t *object = (object_t *)((char *)ctsql_cursor - OBJECT_HEAD_SIZE);

    if (ctsql_cursor->file != -1) {
        cm_close_file(ctsql_cursor->file);
    }
    knl_close_cursor(&ctsql_stmt->session->knl_session, ctsql_cursor);
    olist_remove(&ctsql_stmt->knl_curs, object);
    opool_free(pool, object);
}

static void sql_release_multi_parts_resources(sql_stmt_t *ctsql_stmt, sql_table_cursor_t *tab_cur)
{
    if (tab_cur->multi_parts_info.knlcur_list == NULL || tab_cur->multi_parts_info.knlcur_list->count == 0) {
        tab_cur->multi_parts_info.knlcur_list = NULL;
        tab_cur->multi_parts_info.knlcur_id = 0;
        tab_cur->multi_parts_info.sort_info = NULL;
        return;
    }
    mps_knlcur_t *knlcur_info = (mps_knlcur_t *)cm_galist_get(tab_cur->multi_parts_info.knlcur_list, 0);
    tab_cur->knl_cur = knlcur_info->knl_cursor;

    uint32 count = tab_cur->multi_parts_info.knlcur_list->count;
    for (uint32 i = 1; i < count; i++) {
        knlcur_info = (mps_knlcur_t *)cm_galist_get(tab_cur->multi_parts_info.knlcur_list, i);
        knl_close_cursor(&ctsql_stmt->session->knl_session, knlcur_info->knl_cursor);
    }
    tab_cur->multi_parts_info.knlcur_list = NULL;
    tab_cur->multi_parts_info.knlcur_id = 0;
    tab_cur->multi_parts_info.sort_info = NULL;
}

static inline void sql_free_table_cursor(sql_stmt_t *ctsql_stmt, sql_table_cursor_t *ctsql_cursor)
{
    sql_release_multi_parts_resources(ctsql_stmt, ctsql_cursor);

    ctsql_cursor->scan_flag = SEQ_SQL_SCAN;

    if (CT_IS_SUBSELECT_TABLE(ctsql_cursor->table->type)) {
        if (ctsql_cursor->sql_cur != NULL) {
            if (ctsql_cursor->table->type == VIEW_AS_TABLE && ctsql_cursor->action == CURSOR_ACTION_INSERT) {
                sql_free_knl_cursor(ctsql_stmt, ctsql_cursor->knl_cur);
            } else {
                sql_free_cursor(ctsql_stmt, ctsql_cursor->sql_cur);
            }
        }
        return;
    }

    if (ctsql_cursor->table->type == JSON_TABLE) {
        sql_release_json_table(ctsql_cursor);
    } else {
        sql_free_varea_set(ctsql_cursor);
    }

    {
        sql_free_knl_cursor(ctsql_stmt, ctsql_cursor->knl_cur);
    }
}

void sql_free_merge_join_data(sql_stmt_t *ctsql_stmt, join_data_t *m_join)
{
    if (m_join->left != NULL) {
        sql_free_cursor(ctsql_stmt, m_join->left);
        m_join->left = NULL;
    }
    if (m_join->right != NULL) {
        sql_free_cursor(ctsql_stmt, m_join->right);
        m_join->right = NULL;
    }
}

void sql_free_nl_batch_exec_data(sql_stmt_t *ctsql_stmt, sql_cursor_t *ctsql_cursor, uint32 count)
{
    for (uint32 i = 0; i < count; ++i) {
        if (ctsql_cursor->exec_data.nl_batch[i].cache_cur != NULL) {
            sql_free_cursor(ctsql_stmt, ctsql_cursor->exec_data.nl_batch[i].cache_cur);
            ctsql_cursor->exec_data.nl_batch[i].cache_cur = NULL;
        }
    }
}

void sql_free_va_set(sql_stmt_t *ctsql_stmt, sql_cursor_t *ctsql_cursor)
{
    hash_segment_t *hash_segment = NULL;

    ctsql_cursor->exec_data.query_limit = NULL;
    ctsql_cursor->exec_data.select_limit = NULL;
    ctsql_cursor->exec_data.union_all = NULL;
    ctsql_cursor->exec_data.minus.r_continue_fetch = CT_TRUE;
    ctsql_cursor->exec_data.minus.rnums = 0;
    ctsql_cursor->exec_data.explain_col_max_size = NULL;
    ctsql_cursor->exec_data.qb_col_max_size = NULL;
    ctsql_cursor->exec_data.outer_join = NULL;
    ctsql_cursor->exec_data.inner_join = NULL;
    ctsql_cursor->exec_data.join = NULL;
    ctsql_cursor->exec_data.select_view = NULL;
    ctsql_cursor->exec_data.tab_parallel = NULL;
    ctsql_cursor->exec_data.group = NULL;
    ctsql_cursor->exec_data.right_semi = NULL;
    ctsql_cursor->hash_join_ctx = NULL;
    CM_INIT_TEXTBUF(&ctsql_cursor->exec_data.sort_concat, 0, NULL);

    if (ctsql_cursor->exec_data.aggr_dis != NULL) {
        hash_segment = (hash_segment_t *)ctsql_cursor->exec_data.aggr_dis;
        vm_hash_segment_deinit(hash_segment);
        ctsql_cursor->exec_data.aggr_dis = NULL;
    }

    if (ctsql_cursor->exec_data.group_cube != NULL) {
        sql_free_group_cube(ctsql_stmt, ctsql_cursor);
        ctsql_cursor->exec_data.group_cube = NULL;
    }

    if (ctsql_cursor->exec_data.nl_batch != NULL) {
        sql_free_nl_batch_exec_data(ctsql_stmt, ctsql_cursor, ctsql_stmt->context->nl_batch_cnt);
        ctsql_cursor->exec_data.nl_batch = NULL;
    }

    if (ctsql_cursor->exec_data.minus.rs_vmid != CT_INVALID_ID32) {
        vm_free(ctsql_stmt->mtrl.session, ctsql_stmt->mtrl.pool, ctsql_cursor->exec_data.minus.rs_vmid);
        ctsql_cursor->exec_data.minus.rs_vmid = CT_INVALID_ID32;
    }

    ctsql_cursor->exec_data.index_scan_range_ar = NULL;
    ctsql_cursor->exec_data.part_scan_range_ar = NULL;
    ctsql_cursor->exec_data.dv_plan_buf = NULL;
}

static void sql_free_hash_join_data(sql_stmt_t *ctsql_stmt, sql_cursor_t *ctsql_cursor)
{
    for (uint32 i = 0; i < CT_MAX_JOIN_TABLES; i++) {
        if (ctsql_cursor->hash_mtrl.hj_tables[i] != NULL) {
            sql_free_cursor(ctsql_stmt, ctsql_cursor->hash_mtrl.hj_tables[i]);
            ctsql_cursor->hash_mtrl.hj_tables[i] = NULL;
        }
    }
}

static inline void sql_free_ssa_cursors(sql_stmt_t *ctsql_stmt, sql_cursor_t *ctsql_cursor)
{
    sql_cursor_t *ssa_cur = NULL;
    biqueue_node_t *curr = NULL;
    biqueue_node_t *end = NULL;

    curr = biqueue_first(&ctsql_cursor->ssa_cursors);
    end = biqueue_end(&ctsql_cursor->ssa_cursors);

    while (curr != end) {
        ssa_cur = OBJECT_OF(sql_cursor_t, curr);
        curr = curr->next;
        sql_free_cursor(ctsql_cursor->stmt, ssa_cur);
    }
    biqueue_init(&ctsql_cursor->ssa_cursors);
}

static void sql_free_merge_join_resource(sql_stmt_t *ctsql_stmt, sql_cursor_t *ctsql_cursor)
{
    if (ctsql_cursor->m_join == NULL) {
        return;
    }
    uint32 mj_plan_count = ctsql_cursor->query->join_assist.mj_plan_count;
    if (ctsql_cursor->query->s_query != NULL) {
        mj_plan_count = MAX(mj_plan_count, ctsql_cursor->query->s_query->join_assist.mj_plan_count);
    }
    for (uint32 i = 0; i < mj_plan_count; i++) {
        sql_free_merge_join_data(ctsql_stmt, &ctsql_cursor->m_join[i]);
    }
    ctsql_cursor->m_join = NULL;
}

void sql_free_nl_full_opt_ctx(nl_full_opt_ctx_t *opt_ctx)
{
    if (opt_ctx->iter.hash_table != NULL) {
        vm_hash_close_page(&opt_ctx->hash_seg, &opt_ctx->hash_table_entry.page);
        opt_ctx->iter.hash_table = NULL;
    }
    vm_hash_segment_deinit(&opt_ctx->hash_seg);
    opt_ctx->iter.callback_ctx = NULL;
    opt_ctx->iter.curr_bucket = 0;
    opt_ctx->iter.curr_match.vmid = CT_INVALID_ID32;
}

static void inline sql_free_nl_full_opt_ctx_list(sql_cursor_t *ctsql_cursor)
{
    nl_full_opt_ctx_t *opt_ctx = NULL;

    for (uint32 i = 0; i < ctsql_cursor->nl_full_ctx_list->count; i++) {
        opt_ctx = (nl_full_opt_ctx_t *)cm_galist_get(ctsql_cursor->nl_full_ctx_list, i);
        sql_free_nl_full_opt_ctx(opt_ctx);
    }
    ctsql_cursor->nl_full_ctx_list = NULL;
}

static inline void sql_free_cursor_tables(sql_stmt_t *ctsql_stmt, sql_cursor_t *ctsql_cursor)
{
    for (uint32 i = 0; i < ctsql_cursor->table_count; i++) {
        sql_free_table_cursor(ctsql_stmt, &ctsql_cursor->tables[ctsql_cursor->id_maps[i]]);
    }
    ctsql_cursor->table_count = 0;
    ctsql_cursor->tables = NULL;
}

void sql_close_cursor(sql_stmt_t *ctsql_stmt, sql_cursor_t *ctsql_cursor)
{
    CT_RETVOID_IFTRUE(!ctsql_cursor->is_open)
    ctsql_cursor->is_open = CT_FALSE;
    ctsql_cursor->idx_func_cache = NULL;

    if (ctsql_cursor->nl_full_ctx_list != NULL) {
        sql_free_nl_full_opt_ctx_list(ctsql_cursor);
    }

    if (ctsql_cursor->left_cursor != NULL) {
        sql_free_cursor(ctsql_stmt, ctsql_cursor->left_cursor);
        ctsql_cursor->left_cursor = NULL;
    }

    if (ctsql_cursor->right_cursor != NULL) {
        sql_free_cursor(ctsql_stmt, ctsql_cursor->right_cursor);
        ctsql_cursor->right_cursor = NULL;
    }

    sql_reset_mtrl(ctsql_stmt, ctsql_cursor);
    sql_free_hash_join_data(ctsql_stmt, ctsql_cursor);

    if (ctsql_cursor->exec_data.ext_knl_cur != NULL) {
        sql_free_knl_cursor(ctsql_stmt, ctsql_cursor->exec_data.ext_knl_cur);
        ctsql_cursor->exec_data.ext_knl_cur = NULL;
    }
    sql_free_cursor_tables(ctsql_stmt, ctsql_cursor);
    sql_free_ssa_cursors(ctsql_stmt, ctsql_cursor);

#ifdef Z_SHARDING
    ctsql_cursor->do_sink_all = CT_FALSE;
    // ctsql_cursor->sink_all_list will be cleared again before execute
    (void)group_list_clear(&ctsql_cursor->sink_all_list);
#endif

    if (ctsql_cursor->query != NULL) {
        sql_free_merge_join_resource(ctsql_stmt, ctsql_cursor);
    }

    sql_free_va_set(ctsql_stmt, ctsql_cursor);

    if (ctsql_cursor->group_ctx != NULL) {
        sql_free_group_ctx(ctsql_stmt, ctsql_cursor->group_ctx);
        ctsql_cursor->group_ctx = NULL;
    }

    if (ctsql_cursor->cnct_ctx != NULL) {
        sql_free_concate_ctx(ctsql_stmt, ctsql_cursor->cnct_ctx);
        ctsql_cursor->cnct_ctx = NULL;
    }

    ctsql_cursor->unpivot_ctx = NULL;

    if (ctsql_cursor->distinct_ctx != NULL) {
        sql_free_distinct_ctx(ctsql_cursor->distinct_ctx);
        ctsql_cursor->distinct_ctx = NULL;
    }

    if (ctsql_cursor->connect_data.first_level_cursor != NULL) {
        sql_free_connect_cursor(ctsql_stmt, ctsql_cursor);
    }

    vmc_free(&ctsql_cursor->vmc);
}

static rs_fetch_func_tab_t g_rs_fetch_func_tab[] = {
    { RS_TYPE_NONE, sql_fetch_query },
    { RS_TYPE_NORMAL, sql_fetch_query },
    { RS_TYPE_SORT, sql_fetch_sort },
    { RS_TYPE_SORT_GROUP, sql_fetch_sort_group },
    { RS_TYPE_MERGE_SORT_GROUP, sql_fetch_merge_sort_group },
    { RS_TYPE_HASH_GROUP, sql_fetch_hash_group_new },
    { RS_TYPE_PAR_HASH_GROUP, sql_fetch_hash_group_new },
    { RS_TYPE_INDEX_GROUP, sql_fetch_index_group },
    { RS_TYPE_AGGR, sql_fetch_aggr },
    { RS_TYPE_SORT_DISTINCT, sql_fetch_sort_distinct },
    { RS_TYPE_HASH_DISTINCT, sql_fetch_hash_distinct },
    { RS_TYPE_INDEX_DISTINCT, sql_fetch_index_distinct },
    { RS_TYPE_UNION, sql_fetch_hash_union },
    { RS_TYPE_UNION_ALL, sql_fetch_union_all },
    { RS_TYPE_MINUS, sql_fetch_minus },
    { RS_TYPE_HASH_MINUS, NULL},
    { RS_TYPE_LIMIT, sql_fetch_limit },
    { RS_TYPE_HAVING, sql_fetch_having },
    { RS_TYPE_REMOTE, NULL},
    { RS_TYPE_GROUP_MERGE, NULL},
    { RS_TYPE_WINSORT, sql_fetch_winsort },
    { RS_TYPE_HASH_MTRL, sql_fetch_query },
    { RS_TYPE_ROW, sql_fetch_query },
    { RS_TYPE_SORT_PAR, NULL},
    { RS_TYPE_SIBL_SORT, sql_fetch_sibl_sort },
    { RS_TYPE_PAR_QUERY_JOIN, NULL},
    { RS_TYPE_GROUP_CUBE, sql_fetch_group_cube },
    { RS_TYPE_ROWNUM, sql_fetch_rownum },
    { RS_TYPE_FOR_UPDATE, sql_fetch_for_update },
    { RS_TYPE_WITHAS_MTRL, sql_fetch_withas_mtrl },
};

static inline sql_fetch_func_t sql_get_fetch_func(sql_stmt_t *ctsql_stmt, sql_cursor_t *cursor)
{
    if (SECUREC_UNLIKELY(ctsql_stmt->rs_type == RS_TYPE_SORT_PAR && cursor->par_ctx.par_mgr == NULL)) {
        return sql_fetch_sort;
    }
    return g_rs_fetch_func_tab[ctsql_stmt->rs_type].sql_fetch_func;
}

status_t sql_make_result_set(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    status_t status;

    if (cursor->eof) {
        sql_close_cursor(stmt, cursor);
        return CT_SUCCESS;
    }
    CM_TRACE_BEGIN;
    date_t rs_plan_time = AUTOTRACE_ON(stmt) ? stmt->plan_time[stmt->rs_plan->plan_id] : 0;

    sql_send_row_func_t sql_send_row_func = sql_get_send_row_func(stmt, stmt->rs_plan);
    sql_fetch_func_t sql_fetch_func = sql_get_fetch_func(stmt, cursor);
    stmt->need_send_ddm = CT_TRUE;
    status = sql_make_normal_rs(stmt, cursor, sql_fetch_func, sql_send_row_func);
    if (status != CT_SUCCESS) {
        sql_close_cursor(stmt, cursor);
    }
    if (AUTOTRACE_ON(stmt) && stmt->plan_time[stmt->rs_plan->plan_id] == rs_plan_time) {
        CM_TRACE_END(stmt, stmt->rs_plan->plan_id);
    }
    stmt->need_send_ddm = CT_FALSE;
    stmt->session->stat.fetch_count++;
    return status;
}

status_t sql_execute_single_dml(sql_stmt_t *ctsql_stmt, knl_savepoint_t *savepoint)
{
    status_t status;

    CT_RETURN_IFERR(sql_check_tables(ctsql_stmt, ctsql_stmt->context));

    sql_set_scn(ctsql_stmt);

    switch (ctsql_stmt->context->type) {
        case CTSQL_TYPE_SELECT:
            status = sql_execute_select(ctsql_stmt);
            break;

        case CTSQL_TYPE_UPDATE:
            status = sql_execute_update(ctsql_stmt);
            break;

        case CTSQL_TYPE_INSERT:
            status = sql_execute_insert(ctsql_stmt);
            break;

        case CTSQL_TYPE_DELETE:
            status = sql_execute_delete(ctsql_stmt);
            break;

        case CTSQL_TYPE_REPLACE:
            status = sql_execute_replace(ctsql_stmt);
            break;

        case CTSQL_TYPE_MERGE:
        default:
            status = sql_execute_merge(ctsql_stmt);
            break;
    }

    if (status != CT_SUCCESS) {
        do_rollback(ctsql_stmt->session, savepoint);
        knl_reset_index_conflicts(KNL_SESSION(ctsql_stmt));
    }

    return status;
}

status_t sql_try_put_dml_batch_error(sql_stmt_t *ctsql_stmt, uint32 row, int32 error_code, const char *message)
{
    cs_packet_t *send_pack = &ctsql_stmt->session->agent->send_pack;
    text_t errmsg_text = {
        .str = (char *)message,
        .len = (uint32)strlen(message)
    };

    if (ctsql_stmt->session->call_version >= CS_VERSION_10) {
        CT_RETURN_IFERR(cs_put_int32(send_pack, row));
        CT_RETURN_IFERR(cs_put_int32(send_pack, error_code));
        CT_RETURN_IFERR(cs_put_text(send_pack, &errmsg_text));
    } else {
        CT_RETURN_IFERR(cs_put_int32(send_pack, row));
        CT_RETURN_IFERR(cs_put_str(send_pack, message));
    }
    cm_reset_error();
    return CT_SUCCESS;
}

static status_t sql_proc_allow_errors(sql_stmt_t *ctsql_stmt, uint32 param_idx)
{
    int32 code;
    const char *message = NULL;

    cm_get_error(&code, &message, NULL);
    // dc invalid need to do reparse
    if (code == ERR_DC_INVALIDATED) {
        return CT_ERROR;
    }

    if (ctsql_stmt->actual_batch_errs + 1 > ctsql_stmt->allowed_batch_errs) {
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_try_put_dml_batch_error(ctsql_stmt, param_idx, code, message));
    ctsql_stmt->actual_batch_errs++;

    return CT_SUCCESS;
}

static bool32 sql_batch_paremeted_insert_enabled(sql_stmt_t *ctsql_stmt)
{
    if (ctsql_stmt->param_info.paramset_offset + 1 >= ctsql_stmt->param_info.paramset_size) {
        return CT_FALSE;
    }

    sql_insert_t *insert_ctx = (sql_insert_t *)ctsql_stmt->context->entry;
    if (insert_ctx->select_ctx != NULL) {
        return CT_FALSE;
    }

    /* insert with multi values and multi paramter set bind is not supported */
    if (insert_ctx->pairs_count > 1) {
        return CT_FALSE;
    }

    return sql_batch_insert_enable(ctsql_stmt, insert_ctx);
}

#define CHECK_IGNORE_BATCH_ERROR(ctsql_stmt, i, status)                                 \
    if ((status) != CT_SUCCESS) {                                                 \
        CT_LOG_DEBUG_ERR("error occurs when issue dml, paramset index: %u", (i)); \
        if ((ctsql_stmt)->allowed_batch_errs > 0) {                                     \
            if (sql_proc_allow_errors((ctsql_stmt), (i)) == CT_SUCCESS) {               \
                (status) = CT_SUCCESS;                                            \
                (ctsql_stmt)->param_info.paramset_offset++;                             \
                continue;                                                         \
            }                                                                     \
        }                                                                         \
        break;                                                                    \
    }


static status_t sql_issue_parametered_dml(sql_stmt_t *stmt, sql_cursor_t *cursor)
{
    status_t status = CT_SUCCESS;
    knl_savepoint_t savepoint;

    CTSQL_SAVE_STACK(stmt);

    for (uint32 i = stmt->param_info.paramset_offset; i < stmt->param_info.paramset_size; i++) {
        CTSQL_RESTORE_STACK(stmt);

        // do read params from req packet
        status = sql_read_params(stmt);
        // try allowed batch errors if execute error
        CHECK_IGNORE_BATCH_ERROR(stmt, i, status);

        if ((stmt->context->type == CTSQL_TYPE_SELECT && i != stmt->param_info.paramset_size - 1)) {
            // for select, only the last
            stmt->param_info.paramset_offset++;
            continue;
        }

        knl_savepoint(&stmt->session->knl_session, &savepoint);
        cursor->total_rows = 0;

        // need clean value with the previous parameters
        sql_reset_first_exec_vars(stmt);
        sql_reset_sequence(stmt);
        // the context may be changed in try_get_execute_context, and the context-related content in cursor will become
        // invalid, so cursor should be closed in advance
        sql_close_cursor(stmt, cursor);

        stmt->context->readonly = CT_TRUE;
        stmt->context->readonly = CT_TRUE;

        if (AUTOTRACE_ON(stmt)) {
            CT_RETURN_IFERR(sql_init_stmt_plan_time(stmt));
        }
        status = sql_execute_single_dml(stmt, &savepoint);

        // try allowed batch errors if execute error
        CHECK_IGNORE_BATCH_ERROR(stmt, i, status);

        stmt->param_info.paramset_offset++;
        stmt->eof = cursor->eof;
        // execute batch need to return total affected rows
        stmt->total_rows += cursor->total_rows;
    }

    return status;
}

static status_t sql_issue_dml(sql_stmt_t *stmt)
{
    sql_cursor_t *cursor = CTSQL_ROOT_CURSOR(stmt);
    status_t status = CT_SUCCESS;
    bool32 do_batch_insert = CT_FALSE;

    if ((stmt->param_info.paramset_size == 0 || stmt->context->rs_columns != NULL)) {
        stmt->param_info.paramset_size = 1;
    }

    stmt->param_info.param_strsize = 0;
    stmt->params_ready = CT_FALSE;

    if (stmt->context->type == CTSQL_TYPE_INSERT) {
        do_batch_insert = sql_batch_paremeted_insert_enabled(stmt);
    }

    if (do_batch_insert) {
        CT_RETURN_IFERR(sql_check_tables(stmt, stmt->context));
        sql_set_scn(stmt);
        if (AUTOTRACE_ON(stmt)) {
            CT_RETURN_IFERR(sql_init_stmt_plan_time(stmt));
        }
        cursor->total_rows = 0;
        stmt->is_batch_insert = CT_TRUE;
        status = sql_execute_insert(stmt);
        stmt->is_batch_insert = CT_FALSE;
        stmt->eof = cursor->eof;
        // execute batch need to return total affected rows
        stmt->total_rows += cursor->total_rows;
    } else {
        status = sql_issue_parametered_dml(stmt, cursor);
    }
    /*
     * if the "SQL_CALC_FOUND_ROWS" flag specified, the recent_foundrows should be calculated extra
     * otherwise it should be the same as the actually sent rows
     */
    stmt->session->recent_foundrows =
        cursor->total_rows + cursor->found_rows.limit_skipcount + cursor->found_rows.offset_skipcount;

    if (status != CT_SUCCESS) { // Error happens when executes DML
        return CT_ERROR;
    }

    if (stmt->context->type == CTSQL_TYPE_SELECT && !stmt->eof) {
        CT_RETURN_IFERR(sql_keep_params(stmt));
        CT_RETURN_IFERR(sql_keep_first_exec_vars(stmt));
    }

    return CT_SUCCESS;
}

status_t sql_begin_dml(sql_stmt_t *ctsql_stmt)
{
    sql_cursor_t *cursor = NULL;

    if (sql_alloc_cursor(ctsql_stmt, &cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (SQL_CURSOR_PUSH(ctsql_stmt, cursor) != CT_SUCCESS) {
        sql_free_cursor(ctsql_stmt, cursor);
        return CT_ERROR;
    }
    ctsql_stmt->resource_inuse = CT_TRUE;
    return CT_SUCCESS;
}

status_t sql_try_execute_dml(sql_stmt_t *ctsql_stmt)
{
    int32 code;
    const char *message = NULL;

    if (ctsql_stmt->context == NULL) {
        CT_THROW_ERROR(ERR_REQUEST_OUT_OF_SQUENCE, "prepared.");
        return CT_ERROR;
    }

    if (!ctsql_stmt->context->ctrl.valid) {
        CT_THROW_ERROR(ERR_DC_INVALIDATED);
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_check_ltt_dc(ctsql_stmt));

    if (sql_begin_dml(ctsql_stmt) != CT_SUCCESS) {
        return CT_ERROR;
    }

    status_t status = sql_issue_dml(ctsql_stmt);

    if (status != CT_SUCCESS) {
        cm_get_error(&code, &message, NULL);
        ctsql_stmt->dc_invalid = (code == ERR_DC_INVALIDATED);
        sql_release_resource(ctsql_stmt, CT_TRUE);
        ctsql_stmt->dc_invalid = CT_FALSE;
        SQL_CURSOR_POP(ctsql_stmt);
        return CT_ERROR;
    }

    if (ctsql_stmt->auto_commit == CT_TRUE) {
        CT_RETURN_IFERR(do_commit(ctsql_stmt->session));
    }

    return CT_SUCCESS;
}

status_t sql_execute_fetch_medatata(sql_stmt_t *ctsql_stmt)
{
    if (ctsql_stmt->status < STMT_STATUS_PREPARED) {
        CT_THROW_ERROR(ERR_INVALID_CURSOR);
        return CT_ERROR;
    }

    return my_sender(ctsql_stmt)->send_parsed_stmt(ctsql_stmt);
}

static status_t sql_reload_text(sql_stmt_t *ctsql_stmt, sql_text_t *sql)
{
    if (ctx_read_text(sql_pool, &ctsql_stmt->context->ctrl, &sql->value, CT_FALSE) != CT_SUCCESS) {
        return CT_ERROR;
    }

    sql->implicit = CT_FALSE;
    sql->loc.line = 1;
    sql->loc.column = 1;
    return CT_SUCCESS;
}

static status_t sql_fork_stmt(sql_stmt_t *ctsql_stmt, sql_stmt_t **ret)
{
    sql_stmt_t *sub_stmt = NULL;
    // PUSH stack will release by ple_exec_dynamic_sql
    CT_RETURN_IFERR(sql_push(ctsql_stmt, sizeof(sql_stmt_t), (void **)&sub_stmt));

    sql_init_stmt(ctsql_stmt->session, sub_stmt, ctsql_stmt->id);
    SET_STMT_CONTEXT(sub_stmt, NULL);
    SET_STMT_PL_CONTEXT(sub_stmt, NULL);
    sub_stmt->status = STMT_STATUS_IDLE;
    sub_stmt->is_verifying = ctsql_stmt->is_verifying;
    sub_stmt->is_srvoutput_on = ctsql_stmt->is_srvoutput_on;
    sub_stmt->is_sub_stmt = CT_TRUE;
    sub_stmt->parent_stmt = ctsql_stmt;
    sub_stmt->cursor_info.type = PL_FORK_CURSOR;
    sub_stmt->cursor_info.reverify_in_fetch = CT_TRUE;
    *ret = sub_stmt;
    return CT_SUCCESS;
}

// notice: only use in return result
status_t sql_execute_fetch_cursor_medatata(sql_stmt_t *ctsql_stmt)
{
    if (ctsql_stmt->status < STMT_STATUS_PREPARED || (ctsql_stmt->cursor_info.has_fetched && ctsql_stmt->eof)) {
        CT_THROW_ERROR(ERR_INVALID_CURSOR);
        return CT_ERROR;
    }

    sql_select_t *select_ctx = (sql_select_t *)ctsql_stmt->context->entry;
    if (select_ctx->pending_col_count == 0) {
        return my_sender(ctsql_stmt)->send_parsed_stmt(ctsql_stmt);
    }

    sql_text_t sql;
    sql_stmt_t *sub_stmt = NULL;
    vmc_t vmc;
    vmc_init(&ctsql_stmt->session->vmp, &vmc);
    CT_RETURN_IFERR(vmc_alloc(&vmc, ctsql_stmt->context->ctrl.text_size + 1, (void **)&sql.str));
    sql.len = ctsql_stmt->context->ctrl.text_size + 1;
    if (sql_reload_text(ctsql_stmt, &sql) != CT_SUCCESS) {
        vmc_free(&vmc);
        return CT_ERROR;
    }
    CTSQL_SAVE_STACK(ctsql_stmt);
    if (sql_fork_stmt(ctsql_stmt, &sub_stmt) != CT_SUCCESS) {
        vmc_free(&vmc);
        return CT_ERROR;
    }

    status_t status = CT_ERROR;
    do {
        lex_reset(ctsql_stmt->session->lex);
        CT_BREAK_IF_ERROR(sql_read_kept_params(ctsql_stmt));
        sub_stmt->param_info.params = ctsql_stmt->param_info.params;
        CT_BREAK_IF_ERROR(sql_parse_dml_directly(sub_stmt, KEY_WORD_SELECT, &sql));
        status = my_sender(ctsql_stmt)->send_parsed_stmt(sub_stmt);
    } while (0);

    sql_free_context(sub_stmt->context);
    sql_release_resource(sub_stmt, CT_TRUE);
    if (sub_stmt->stat != NULL) {
        free(sub_stmt->stat);
        sub_stmt->stat = NULL;
    }
    CTSQL_RESTORE_STACK(ctsql_stmt);
    vmc_free(&vmc);
    return status;
}


static void sql_init_pl_column_def(sql_stmt_t *ctsql_stmt)
{
    if (ctsql_stmt->plsql_mode == PLSQL_CURSOR) {
        // the type of pl-variant which in cursor query is unknown until calc.
        ctsql_stmt->mark_pending_done = CT_FALSE;
    }
}

static inline status_t sql_send_fetch_result(sql_stmt_t *ctsql_stmt, sql_cursor_t *cursor)
{
    if (cursor == NULL) {
        CT_THROW_ERROR(ERR_INVALID_CURSOR);
        return CT_ERROR;
    }
    {
        if (sql_make_result_set(ctsql_stmt, cursor) != CT_SUCCESS) {
            sql_release_resource(ctsql_stmt, CT_TRUE);
            return CT_ERROR;
        }
    }

    ctsql_stmt->total_rows = cursor->total_rows;
    ctsql_stmt->eof = cursor->eof;
    return CT_SUCCESS;
}

status_t sql_execute_fetch(sql_stmt_t *ctsql_stmt)
{
    sql_cursor_t *cursor = CTSQL_ROOT_CURSOR(ctsql_stmt);
    bool32 pre_eof = ctsql_stmt->eof;

    if (ctsql_stmt->status < STMT_STATUS_EXECUTED) {
        CT_THROW_ERROR(ERR_REQUEST_OUT_OF_SQUENCE, "executed.");
        return CT_ERROR;
    }

    if (ctsql_stmt->eof) {
        ctsql_stmt->total_rows = 0;
        ctsql_stmt->batch_rows = 0;
        CT_RETURN_IFERR(my_sender(ctsql_stmt)->send_fetch_begin(ctsql_stmt));
        my_sender(ctsql_stmt)->send_fetch_end(ctsql_stmt);
        return CT_SUCCESS;
    }

    if (!ctsql_stmt->resource_inuse) {
        CT_THROW_ERROR(ERR_INVALID_OPERATION, ",resource is already destroyed");
        return CT_ERROR;
    }

    CT_RETURN_IFERR(sql_read_kept_params(ctsql_stmt));
    CT_RETURN_IFERR(sql_init_sequence(ctsql_stmt));
    CT_RETURN_IFERR(sql_load_first_exec_vars(ctsql_stmt));
    CT_RETURN_IFERR(sql_init_trigger_list(ctsql_stmt));
    CT_RETURN_IFERR(sql_init_pl_ref_dc(ctsql_stmt));
    sql_init_pl_column_def(ctsql_stmt);

    ctsql_stmt->batch_rows = 0;

    CT_RETURN_IFERR(my_sender(ctsql_stmt)->send_fetch_begin(ctsql_stmt));
    CT_RETURN_IFERR(sql_send_fetch_result(ctsql_stmt, cursor));

    /*
     * if the "SQL_CALC_FOUND_ROWS" flag specified, the recent_foundrows should be calculated extra
     * otherwise it should be the same as the actually sent rows
     */
    ctsql_stmt->session->recent_foundrows =
        cursor->total_rows + cursor->found_rows.limit_skipcount + cursor->found_rows.offset_skipcount;

    my_sender(ctsql_stmt)->send_fetch_end(ctsql_stmt);
    ctsql_stmt->is_success = CT_TRUE;

    if (ctsql_stmt->eof) {
        sql_unlock_lnk_tabs(ctsql_stmt);
        if (ctsql_stmt->eof) {
            sql_release_resource(ctsql_stmt, CT_FALSE);
            if (!pre_eof) {
                sql_dec_active_stmts(ctsql_stmt);
            }
        }
    }

    return CT_SUCCESS;
}

void sql_init_varea_set(sql_stmt_t *ctsql_stmt, sql_table_cursor_t *table_cursor)
{
    vmc_init(&ctsql_stmt->session->vmp, &table_cursor->vmc);
    if (table_cursor->table != NULL && (table_cursor->table->type == JSON_TABLE)) {
        table_cursor->json_table_exec.json_assist = NULL;
        table_cursor->json_table_exec.json_value = NULL;
        table_cursor->json_table_exec.loc = NULL;
    } else {
        table_cursor->key_set.key_data = NULL;
        table_cursor->part_set.key_data = NULL;
        table_cursor->key_set.type = KEY_SET_FULL;
        table_cursor->part_set.type = KEY_SET_FULL;
    }
}

void sql_free_varea_set(sql_table_cursor_t *table_cursor)
{
    vmc_free(&table_cursor->vmc);
    table_cursor->key_set.key_data = NULL;
    table_cursor->part_set.key_data = NULL;
}

ct_type_t sql_get_pending_type(char *pending_buf, uint32 id)
{
    uint32 count;
    ct_type_t *types = NULL;

    if (pending_buf == NULL) {
        return CT_TYPE_VARCHAR;
    }

    count = (*(uint32 *)pending_buf - PENDING_HEAD_SIZE) / sizeof(ct_type_t);
    if (id >= count) {
        return CT_TYPE_VARCHAR;
    }

    types = (ct_type_t *)(pending_buf + PENDING_HEAD_SIZE);
    return types[id];
}

#ifdef __cplusplus
}
#endif
