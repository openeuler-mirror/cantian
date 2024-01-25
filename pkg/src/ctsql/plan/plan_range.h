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
 * plan_range.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/plan/plan_range.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PLAN_RANGE_H__
#define __PLAN_RANGE_H__

#include "ctsql_plan.h"

/* ***********************************************************************


   RANGE_ARRAY
       |_ RANGE_LIST for column1
       |_ RANGE_LIST for column2
       |_ RANGE_LIST for column3
       |_ ...

   RANGE_LIST
       |_ RANGE1
       |_ RANGE2
       |_ RANGE3
       |_ ...

    RANGE
    {
        L_BORDER
        R_BORDER
    }

************************************************************************* */
typedef enum en_range_type {
    RANGE_EMPTY = 0,
    RANGE_FULL,
    RANGE_SECTION,
    RANGE_POINT,
    RANGE_LIST,
    RANGE_LIKE,
    RANGE_ANY,
    RANGE_UNKNOWN
} range_type_t;

typedef enum en_border_wise_t {
    WISE_LEFT,
    WISE_RIGHT,
} border_wise_t;

typedef enum en_border_type {
    BORDER_INFINITE_LEFT,
    BORDER_INFINITE_RIGHT,
    BORDER_CONST,
    BORDER_CALC,
    BORDER_IS_NULL,
} border_type_t;

typedef struct st_plan_border {
    expr_tree_t *expr;
    border_type_t type;
    bool32 closed;
} plan_border_t;

typedef struct st_plan_range {
    range_type_t type;
    ct_type_t datatype;
    plan_border_t left;
    plan_border_t right;
} plan_range_t;

typedef struct st_plan_range_list {
    range_list_type_t type;
    typmode_t typmode;
    galist_t *items; // range list
} plan_range_list_t;

#define LIST_EXIST_LIST_EMPTY 0x0001
#define LIST_EXIST_LIST_FULL 0x0002
#define LIST_EXIST_RANGE_UNEQUAL 0x0004
#define LIST_EXIST_LIST_UNKNOWN 0X0008
#define LIST_EXIST_LIST_ANY 0X0010
#define LIST_EXIST_MULTI_RANGES 0X0020

#define MAX_CACHE_COUNT 5

typedef struct st_scan_border {
    variant_t var;
    border_type_t type;
    bool32 closed;
} scan_border_t;

typedef struct st_scan_range {
    scan_border_t left;
    scan_border_t right;
    range_type_t type;
} scan_range_t;

typedef struct st_scan_range_list {
    range_list_type_t type;
    ct_type_t datatype;
    scan_range_t **ranges;
    uint32 count;
    uint32 rid;
} scan_range_list_t;

typedef struct st_scan_list_info {
    scan_range_list_t *scan_list;
    uint32 tab_id;
    uint32 index_id;
    uint32 ar_countid;
    uint32 flags;
} scan_list_info;

typedef struct st_scan_list_array {
    scan_range_list_t *items;
    uint32 count;
    uint32 flags;
    uint32 total_ranges;
} scan_list_array_t;

typedef struct st_part_scan_key {
    uint32 left;
    uint32 right;
    uint32 parent_partno;
    galist_t *sub_scan_key; // if sub_scan_key != null is sub part
} part_scan_key_t;

typedef struct st_part_assist {
    uint32 count;
    part_scan_key_t *scan_key;
} part_assist_t;

typedef enum e_calc_mode {
    CALC_IN_PLAN,
    CALC_IN_EXEC,
    CALC_IN_EXEC_PART_KEY,
} calc_mode_t;

typedef status_t (*sql_convert_border_t)(sql_stmt_t *stmt, knl_index_desc_t *index, scan_border_t *border,
    ct_type_t datatype, uint32 cid, void *key);

#define SQL_GET_BORDER_TYPE(expr_type) (expr_type) == EXPR_NODE_CONST ? BORDER_CONST : BORDER_CALC

status_t sql_create_scan_ranges(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_table_t *table, scan_plan_t *scan_plan);
status_t sql_create_rowid_set(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table, cond_node_t *node,
                              plan_rowid_set_t **plan_rid_set, bool32 is_temp);
status_t sql_create_part_scan_ranges(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_table_t *table, sql_array_t *array);
status_t sql_create_subpart_scan_ranges(sql_stmt_t *stmt, plan_assist_t *plan_ass, sql_table_t *table,
                                        sql_array_t *subpart_array);

status_t sql_check_border_variant(sql_stmt_t *stmt, variant_t *var, ct_type_t datatype, uint32 size);
status_t sql_generate_part_scan_key(sql_stmt_t *stmt, knl_handle_t handle, scan_list_array_t *ar, part_assist_t *pa,
    uint32 parent_partno, bool32 *full_scan);
status_t sql_make_border_l(sql_stmt_t *stmt, knl_index_desc_t *index_desc, scan_list_array_t *ar, uint32 rid, void *key,
    bool32 *closed, sql_convert_border_t sql_convert_border_func);
status_t sql_make_border_r(sql_stmt_t *stmt, knl_index_desc_t *index_desc, scan_list_array_t *ar, uint32 rid, void *key,
    bool32 *closed, bool32 *equal, sql_convert_border_t sql_convert_border_func);
status_t clone_buff_consuming_type(vmc_t *vmc, scan_border_t *dest, scan_border_t *src);
status_t sql_clone_scan_list_ranges(vmc_t *vmc, scan_range_t **list_range, scan_range_t *src_range);
status_t sql_clone_scan_list(vmc_t *vmc, scan_range_list_t *src_scan_list, scan_range_list_t **dest_scan_list);
status_t sql_init_index_scan_range_ar(vmc_t *vmc, galist_t **range_ar);
status_t sql_cache_range(galist_t **list, scan_list_array_t *ar, scan_range_list_t *scan_range_list, vmc_t *vmc,
                         sql_table_t *table, uint32 ar_countid, calc_mode_t calc_mode);
status_t sql_finalize_scan_range(sql_stmt_t *stmt, sql_array_t *plan_ranges, scan_list_array_t *ar, sql_table_t *table,
    sql_cursor_t *cursor, galist_t **list, calc_mode_t calc_mode);
void sql_make_range(cmp_type_t cmp_type, expr_tree_t *expr, plan_range_t *plan_range);
bool32 sql_inter_const_range(sql_stmt_t *stmt, plan_border_t *border1, plan_border_t *border2, bool32 is_left,
    plan_border_t *result);
status_t sql_verify_const_range(sql_stmt_t *stmt, plan_range_t *result);
status_t sql_create_range_list(sql_stmt_t *stmt, plan_assist_t *pa, expr_node_t *match_node, knl_column_t *knl_col,
    cond_node_t *node, plan_range_list_t **list, bool32 index_reverse, bool32 index_first_col);
status_t sql_finalize_range_list(sql_stmt_t *stmt, plan_range_list_t *plan_list, scan_range_list_t *scan_range_list,
                                 uint32 *list_flag, calc_mode_t calc_mode, uint32 *is_optm);
bool32 sql_cmp_range_usable(plan_assist_t *pa, cmp_node_t *node, expr_node_t *match_node);

#endif
