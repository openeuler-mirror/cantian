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
 * ctsql_hint_verifier.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/verifier/ctsql_hint_verifier.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_HINT_VERIFIER_H__
#define __SQL_HINT_VERIFIER_H__

#include "ctsql_verifier.h"

#ifdef __cplusplus
extern "C" {
#endif

#define RBO_NOT_SUPPORT_INDEX_HINT (HINT_KEY_WORD_NO_INDEX_SS | HINT_KEY_WORD_USE_CONCAT | HINT_KEY_WORD_INDEX_SS)
#define RBO_NOT_SUPPORT_OPTIM_HINT \
    (HINT_KEY_WORD_HASH_SJ | HINT_KEY_WORD_HASH_AJ | HINT_KEY_WORD_OPT_ESTIMATE | HINT_KEY_WORD_OR_EXPAND)
#define SUBQRY_REWRITE_HINT                                                                                  \
    (HINT_KEY_WORD_SEMI_TO_INNER | HINT_KEY_WORD_HASH_SJ | HINT_KEY_WORD_HASH_AJ | HINT_KEY_WORD_NO_UNNEST | \
        HINT_KEY_WORD_UNNEST)
#define SEMI_HINT (HINT_KEY_WORD_SEMI_TO_INNER | HINT_KEY_WORD_HASH_SJ | HINT_KEY_WORD_HASH_AJ)


typedef status_t (*sql_hint_verifier_func)(sql_hint_verifier_t *verif, hint_item_t *hint_item,
    hint_info_t *query_hint_info);

typedef enum en_opt_param_id {
    OPT_PARAM_CONNECT_BY_MTRL,
    OPT_PARAM_AGGR_PLACEMENT,
    OPT_PARAM_ALL_TRANSFORM,
    OPT_PARAM_ANY_TRANSFORM,
    OPT_PARAM_CONNECT_BY_PLACEMENT,
    OPT_PARAM_DISTINCT_ELIMINATION,
    OPT_PARAM_FILTER_PUSHDOWN,
    OPT_PARAM_GROUP_BY_ELIMINATION,
    OPT_PARAM_HASH_MTRL,
    OPT_PARAM_JOIN_ELIMINATION,
    OPT_PARAM_JOIN_PRED_PUSHDOWN,
    OPT_PARAM_ORDER_BY_ELIMINATION,
    OPT_PARAM_ORDER_BY_PLACEMENT,
    OPT_PARAM_OR_EXPANSION,
    OPT_PARAM_PRED_MOVE_AROUND,
    OPT_PARAM_PRED_REORDER,
    OPT_PARAM_PROJECT_LIST_PRUNING,
    OPT_PARAM_SUBQUERY_ELIMINATION,
    OPT_PARAM_UNNEST_SET_SUBQ,
    OPT_PARAM_VM_VIEW,
    OPT_PARAM_WINMAGIC_REWRITE,
    OPT_PARAM_DYNAMIC_SAMPLING,
    OPT_PARAM_COUNT,
} opt_param_id_t;

typedef void (*sql_opt_param_verifier_func_t)(sql_hint_verifier_t *verif, hint_item_t *hint_item, hint_info_t *hint_info,
    opt_param_id_t id);

typedef struct st_sql_opt_param {
    opt_param_id_t id;
    text_t text;
    sql_opt_param_verifier_func_t verify_func;
} sql_opt_param_t;

typedef struct st_sql_hint {
    hint_id_t hint_id;
    uint64 key_id;
    hint_type_t hint_type;
    sql_hint_verifier_func hint_verify_func;
} sql_hint_t;

extern sql_opt_param_t g_opt_params[];

void sql_verify_context_hint(sql_stmt_t *stmt);
void sql_verify_query_hint(sql_verifier_t *verif, sql_query_t *query);
void sql_verify_insert_hint(sql_verifier_t *verif, sql_insert_t *insert_ctx);
void sql_verify_delete_hint(sql_verifier_t *verif, sql_delete_t *delete_ctx);
void sql_verify_update_hint(sql_verifier_t *verif, sql_update_t *update_ctx);
void sql_verify_merge_hint(sql_verifier_t *verif, sql_merge_t *merge_ctx);
void sql_verify_hint(sql_hint_verifier_t *hint_verifier, hint_info_t **query_hint_info);

bool32 check_hint_index_ffs_valid(sql_table_t *table);
bool32 hint_apply_opt_param(sql_stmt_t *stmt, bool32 sys_value, uint64 id);
uint32 get_dynamic_sampling_level(sql_stmt_t *stmt);

static inline void sql_init_hint_verf(sql_hint_verifier_t *verif, sql_stmt_t *stmt, sql_array_t *tables,
    sql_table_t *table)
{
    verif->stmt = stmt;
    verif->tables = tables;
    verif->table = table;
}

#ifdef __cplusplus
}
#endif

#endif
