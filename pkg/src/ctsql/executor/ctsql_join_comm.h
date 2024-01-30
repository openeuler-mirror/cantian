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
 * ctsql_join_comm.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/executor/ctsql_join_comm.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_JOIN_COMM_H__
#define __SQL_JOIN_COMM_H__

#include "dml_executor.h"
#include "ctsql_cond.h"

#ifdef __cplusplus
extern "C" {
#endif

static inline void sql_mtrl_init_savepoint(sql_cursor_t *cursor)
{
    cursor->mtrl.save_point.vm_row_id.vmid = CT_INVALID_ID32;
}

static inline status_t match_join_final_cond(sql_stmt_t *stmt, cond_tree_t *cond, cond_tree_t *join_filter_cond,
    bool32 *is_found)
{
    *is_found = CT_TRUE;
    if (cond != NULL) {
        CT_RETURN_IFERR(sql_match_cond_node(stmt, cond->root, is_found));
        if (!*is_found) {
            return CT_SUCCESS;
        }
    }

    if (join_filter_cond != NULL) {
        CT_RETURN_IFERR(sql_match_cond_node(stmt, join_filter_cond->root, is_found));
    }
    return CT_SUCCESS;
}

#define match_nl_join_final_cond match_join_final_cond
#define match_merge_join_final_cond match_join_final_cond
#define match_hash_join_final_cond match_join_final_cond

static inline uint32 get_last_table_id(plan_node_t *plan_node)
{
    uint32 l_plan_id, r_plan_id;

    switch (plan_node->type) {
        case PLAN_NODE_SCAN:
            return plan_node->scan_p.table->plan_id;

        case PLAN_NODE_REMOTE_SCAN:
	    knl_panic(0);
	    return 0;

        case PLAN_NODE_CONCATE:
            /* All the plans in list are equivalent at the table level. */
            plan_node = (plan_node_t *)cm_galist_get(plan_node->cnct_p.plans, 0);
            return get_last_table_id(plan_node);

        case PLAN_NODE_JOIN:
            l_plan_id = get_last_table_id(plan_node->join_p.left);
            r_plan_id = get_last_table_id(plan_node->join_p.right);
            return MAX(l_plan_id, r_plan_id);

        default:
            return 0;
    }
}

static inline status_t init_hash_join_ctx(sql_cursor_t *cursor, cond_tree_t *join_cond)
{
    if (cursor->hash_join_ctx == NULL) {
        CT_RETURN_IFERR(vmc_alloc(&cursor->vmc, sizeof(hash_join_ctx_t), (void **)&cursor->hash_join_ctx));
        cursor->hash_join_ctx->key_types = NULL;
    }
    cursor->hash_join_ctx->right_eof = CT_TRUE;
    cursor->hash_join_ctx->has_match = CT_FALSE;
    cursor->hash_join_ctx->join_cond = join_cond;
    cursor->hash_join_ctx->need_match_cond = CT_TRUE;
    cursor->hash_join_ctx->need_swap_driver = CT_FALSE;
    cursor->hash_join_ctx->scan_hash_table = CT_FALSE;
    cursor->hash_join_ctx->mtrl_ctx = NULL;

    sql_init_hash_iter(&cursor->hash_join_ctx->iter, cursor);

    return CT_SUCCESS;
}

static inline void sql_init_row_addr(sql_stmt_t *stmt, sql_cursor_t *cursor, char **data, uint16 *offset, uint16 *len,
    rowid_t *rowid, uint16 *rownodeid, uint32 id)
{
    row_addr_t *row_addrs = cursor->exec_data.join;
    row_addrs[id].len = len;
    row_addrs[id].data = data;
    row_addrs[id].offset = offset;
    row_addrs[id].rowid = rowid;
    row_addrs[id].rownodeid = rownodeid;
}

status_t sql_mtrl_alloc_cursor(sql_stmt_t *stmt, sql_cursor_t *parent, sql_cursor_t **sql_cursor,
                               join_info_t *join_join, plan_node_t *plan);
status_t sql_mtrl_fetch_tables_row(mtrl_context_t *ctx, mtrl_cursor_t *mtrl_cursor, row_addr_t *row_addrs,
                                   mtrl_rowid_t *rids, uint32 count);

status_t sql_execute_for_join(sql_stmt_t *stmt, sql_cursor_t *sql_cursor, plan_node_t *plan);
status_t sql_fetch_for_join(sql_stmt_t *stmt, sql_cursor_t *sql_cursor, plan_node_t *plan, bool32 *eof);
void sql_reset_cursor_eof(sql_cursor_t *parent, join_info_t *join_info, bool32 eof);

#ifdef __cplusplus
}
#endif

#endif
