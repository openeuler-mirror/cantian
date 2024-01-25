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
 * ctsql_or2union.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/optimizer/ctsql_or2union.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __SQL_OR_2_UNION_H__
#define __SQL_OR_2_UNION_H__

#include "ctsql_stmt.h"
#include "ctsql_expr.h"
#include "ctsql_cond.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum en_rewrite_level {
    NO_LEVEL_REWRITE = 0,
    LOW_LEVEL_REWRITE = 1,
    HIGH_LEVEL_REWRITE = 2,
} rewrite_level_t;

typedef struct st_expand_info {
    uint32 iteration;
    uint32 start;
    uint32 count; // total number of or or cond branches
    uint32 set_id;
    uint32 *sets; // when or conds list is[{A},{B},{C},{D}] and sets is [1,1,2,2], means or expand as[{A,B} {C,D}]
    knl_index_desc_t *index;
    sql_table_t *table;
    expr_node_t *col;
    cond_node_t *remain_cond;
    uint32 *opt_sets; // optimal or expansion sets
    double cur_cost;
    double opt_cost;
    double ex_cost; // extra cost of or expansion
    double *cost_cache;
    bool32 need_combine; // true means or conditions are not all expand
} expand_info_t;

#define OR2UNION_MAX_TABLES 32
#define OR_EXPAND_MAX_CONDS 32
#define SET_HASH_BITMAP(flag, id1, id2) \
    do {                                \
        (flag) |= (1 << (id1));         \
        (flag) |= (1 << (id2));         \
    } while (0)
#define ALL_HAS_JOIN_COND(bitmap, mask) (((uint64)0xFFFFFFFF >> (OR2UNION_MAX_TABLES - (mask))) == (bitmap))
status_t sql_query_rewrite_2_union(sql_stmt_t *stmt, sql_query_t *query, bool32 *result);
status_t sql_generate_subqry_4_union(sql_stmt_t *stmt, sql_query_t *query, sql_query_t **sub_query);


#ifdef __cplusplus
}
#endif

#endif
