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
 * cbo_base.h
 *
 *
 * IDENTIFICATION
 * src/ctsql/plan/cbo_base.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __CBO_BASE_H__
#define __CBO_BASE_H__

#include "dml_parser.h"
#include "ostat_load.h"
#include "plan_range.h"
#include "plan_rbo.h"

#ifdef __cplusplus
extern "C" {
#endif

// /////////////////////////////////////////////////////////////////////////////////////
// structure
#define CBO_MAX_FF (double)1.0
#define CBO_MIN_FF (double)0.0
#define CBO_LOWER_FF (double)0.25
#define CBO_MIDDLE_FF (double)0.5
#define CBO_HIGHER_FF (double)0.75
#define CBO_INVALID_32VALUE (int32)(-1)
#define CBO_INVALID_64VALUE (int64)(-1)
#define CBO_CANTIAN_MIN_FF CT_REAL_PRECISION

#define IS_CBO_MIN_FF(ff) (fabs(ff) < CT_REAL_PRECISION)
#define IS_CBO_MAX_FF(ff) (fabs(CBO_MAX_FF - (ff)) < CT_REAL_PRECISION)

/* defaults for SQL operator cost parameters */
#define LOG10(x) (log(x))
#define LOG2(x) (log(x) / 0.693147180559945)
#define CBO_DEFAULT_DB_FILE_MULT_READ_COUNT (double)125 // 1M / 8k
#define CBO_DEFAULT_SEQ_PAGE_COST (double)1
#define CBO_DEFAULT_RANDOM_PAGE_COST (double)4.0
#define CBO_DEFAULT_HASH_INIT_COST (double)8.0
#define CBO_DEFAULT_INDEX_ROWID_PAGE_COST (double)0.20
#define CBO_DEFAULT_CPU_SCAN_TUPLE_COST (double)0.01 // sequence scan
#define CBO_DEFAULT_CPU_INDEX_TUPLE_COST (double)0.005
#define CBO_DEFAULT_CPU_OPERATOR_COST (double)0.0025

#define CBO_REAL_PART_SWITCH_COST CBO_DEFAULT_CPU_OPERATOR_COST
#define CBO_EMPTY_PART_SWITCH_COST (double)0.00005

#define CBO_DEFAULT_CPU_HASH_BUILD_COST (double)0.015
#define CBO_DEFAULT_CPU_HASH_CALC_COST CBO_DEFAULT_CPU_OPERATOR_COST
#define CBO_DEFAULT_CPU_HASH_SEMI_COST (double)0.0075

#define CBO_DEFAULT_CPU_QK_SORT_COST (double)0.10
#define CBO_DEFAULT_CPU_QK_INST_COST (double)0.25 // insert sorted record
#define CBO_DEFAULT_CPU_QK_COMP_COST CBO_DEFAULT_CPU_OPERATOR_COST

#define CBO_DEFAULT_CPU_PJ_ENCODE_COST CBO_DEFAULT_CPU_OPERATOR_COST
#define CBO_DEFAULT_BIND_VAR_FF ((double)0.05)
#define CBO_MIN_BIND_VAR_FF ((double)0.01)
#define CBO_DEFAULT_JOIN_INDEX_FF ((double)0.5)
#define CBO_INDEX_FACTOR ((int64)10)
#define CBO_CF_RATE_DOUBLE ((double)2.0)
#define CBO_CF_RATE_TRIPLE ((double)3.0)

#define CBO_TABLE_BASE_BLOCKS (uint32)6
#define CBO_INDEX_BASE_BLOCKS (uint32)3
#define CBO_INDEX_BASE_LEAFS (uint32)64
#define CBO_JOIN_SELTY_FACTOR (double)0.25
#define CBO_GROUP_CARD_FACTOR (double)0.25

#define CBO_CARD_MAX_AMPL (int64)100
#define CBO_JOIN_RATING_CARD (int64)10000
#define CBO_JOIN_MIN_CARD (int64)1
#define CBO_JOIN_MAX_CARD (int64)100000000 // 10000W

#define CBO_MIN_COST (double)0
#define CBO_MAX_COST (double)0xFFFFFFFFFFFF
#define CBO_DUMMY_COST (double)0.003
#define CBO_MAX_ROWS (int64)0xFFFFFFFFF
#define CBO_DEFAULT_NDV (uint32)1
#define CBO_DEFAULT_MAX_NDV (uint32)100000000
#define CBO_SCALE_MIN_ROWNUM (uint32)25

#define IS_CBO_MAX_COST(cost) (fabs(CBO_MAX_COST - (cost)) < CBO_DUMMY_COST)

#define CBO_MAX_INDEX_CACHING (uint32)100

#define CBO_MAX_DYN_SAMPLING_LEVEL (uint32)9


#define CBO_INDEX_CACHING(stmt)                                                        \
    (double)(((stmt)->session->cbo_param.cbo_index_caching <= CBO_MAX_INDEX_CACHING) ? \
        (stmt)->session->cbo_param.cbo_index_caching :                                 \
        g_instance->sql.cbo_index_caching)
#define CBO_MIN_INDEX_COST_ADJ (uint32)1
#define CBO_MAX_INDEX_COST_ADJ (uint32)10000
#define CBO_INDEX_COST_ADJ(stmt)                                                         \
    (double)(((stmt)->session->cbo_param.cbo_index_cost_adj <= CBO_MAX_INDEX_COST_ADJ && \
        (stmt)->session->cbo_param.cbo_index_cost_adj >= CBO_MIN_INDEX_COST_ADJ) ?       \
        (stmt)->session->cbo_param.cbo_index_cost_adj :                                  \
        g_instance->sql.cbo_index_cost_adj)
#define CBO_MIN_PATH_CACHING (uint32)1
#define CBO_MAX_PATH_CACHING (uint32)16
// this max split tables means max driver table numbers
#define CBO_MAX_DRVTAB_COUNT (uint32)12
#define CBO_TINY_TABLE_ROWS (uint32)3
#define CBO_SMALL_TABLE_ROWS (uint32)10
#define CBO_MIDDLE_TABLE_ROWS (uint32)5000
#define CBO_LARGE_TABLE_ROWS (uint32)100000
#define CBO_SAMPLE_TABLE_ROWS (uint32)1000000 // 100w

// this part_no means: 1. non-partition table, or 2. use global statistics of all parts
#define CBO_GLOBAL_PART_NO CT_INVALID_ID32
#define CBO_GLOBAL_SUBPART_NO CT_INVALID_ID32
#define CBO_MIN_SAMPLING_PAGE (uint32)10

#define CBO_CARD_SAFETY_SET(card) (((card) > CBO_JOIN_MAX_CARD) ? CBO_JOIN_MAX_CARD : (card))
#define CBO_CARD_SAFETY_RET(card) (((card) > 0) ? (card) : CBO_JOIN_MIN_CARD)
#define CBO_COST_SAFETY_RET(cost) (((cost) >= CBO_MAX_COST) ? (CBO_MAX_COST - 1) : (cost))
#define CBO_FF_SAFETY_RET(ff) ((((ff) >= 0) && ((ff) <= CBO_MAX_FF)) ? (ff) : CBO_MAX_FF)
#define CBO_JOIN_FF_SAFETY_RET(ff) ((((ff) >= 0) && ((ff) <= CBO_MAX_FF * 10)) ? (ff) : CBO_MAX_FF * 10)

#define SET_VALID_DIVISOR_VALUE(_val_) (_val_) = ((_val_) > 0) ? (_val_) : 1
/* when number of parts <= CBO_MAX_PART4CALC_NUMBER, accumulation can be done on all these parts. \
    or only max part's statistics is used for approximation.
*/
#define CBO_MAX_REAL_PART4CALC_NUMBER 256

#define HAS_NO_SCAN_INFO(table) ((table)->scan_part_info == NULL)
#define PART_TABLE_FULL_SCAN(table) \
    ((table)->scan_part_info != NULL && (table)->scan_part_info->scan_type == SCAN_PART_FULL)
#define PART_TABLE_SPECIFIED_SINGLE_SCAN(table) \
    ((table)->scan_part_info != NULL && (table)->scan_part_info->scan_type == SCAN_PART_SPECIFIED)
#define PART_TABLE_ANY_SINGLE_SCAN(table) \
    ((table)->scan_part_info != NULL && (table)->scan_part_info->scan_type == SCAN_PART_ANY)
#define PART_TABLE_UNKNOWN_SCAN(table) \
    ((table)->scan_part_info != NULL && (table)->scan_part_info->scan_type == SCAN_PART_UNKNOWN)
#define PART_TABLE_EMPTY_SCAN(table) \
    ((table)->scan_part_info != NULL && (table)->scan_part_info->scan_type == SCAN_PART_EMPTY)
#define IS_SUBPART_SCAN_TYPE(table)                                                                      \
    ((table)->scan_part_info != NULL && ((table)->scan_part_info->scan_type == SCAN_SUBPART_SPECIFIED || \
        (table)->scan_part_info->scan_type == SCAN_SUBPART_ANY ||                                        \
        (table)->scan_part_info->scan_type == SCAN_SUBPART_UNKNOWN))
#define COMPART_TABLE_SPECIFIED_SINGLE_SCAN(table) \
    ((table)->scan_part_info != NULL && (table)->scan_part_info->scan_type == SCAN_SUBPART_SPECIFIED)
#define PART_TABLE_SCAN_TOTAL_PART_COUNT(table) ((uint32)(table)->scan_part_info->part_cnt)
#define PART_TABLE_SCAN_ALL_PART_NO_SAVED(table) \
    ((table)->scan_part_info != NULL && (table)->scan_part_info->part_cnt <= MAX_CBO_CALU_PARTS_COUNT)
#define PART_TABLE_SCAN_SAVED_PART_COUNT(table)                                                            \
    (((table)->scan_part_info->part_cnt <= MAX_CBO_CALU_PARTS_COUNT) ? (table)->scan_part_info->part_cnt : \
                                                                       MAX_CBO_CALU_PARTS_COUNT)
#define PART_TABLE_SCAN_PART_NO(table, i) \
    (((table)->scan_part_info->part_no != NULL) ? *((table)->scan_part_info->part_no + (i)) : CBO_GLOBAL_PART_NO)
#define COMPART_TABLE_SCAN_SUBPART_NO(table, i) \
    (((table)->scan_part_info->subpart_no != NULL) ? *((table)->scan_part_info->subpart_no + (i)) : CBO_GLOBAL_PART_NO)
#define INDEX_NOT_PARTED(idx_desc) (!(idx_desc)->parted)

// /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//
#define CBO_PARENT_DRIVER_CARD (int64)1
#define CBO_ANCESR_PRIORITY_CARD (uint32)100
#define CBO_NL_PRIORITY_CARD (uint32)1000

#define CBO_PARAM_(x) g_cbo_cost[x]
#define CBO_HAS_FLAG(pa, flg) (((pa)->cbo_flags) & (flg))
#define CBO_HAS_ONLY_FLAG(pa, flg) (((pa)->cbo_flags) == (flg))
#define CBO_HAS_COL_FLAG(pa, flg) (((pa)->col_use_flag) & (flg))
#define CBO_HAS_PARENT_JOIN(pa) ((pa)->has_parent_join)
#define CBO_HAS_ONLY_COL_FLAG(pa, flg) (((pa)->col_use_flag) == (flg))
#define CBO_SET_DRIVE_FLAG(pa, flg) (((pa)->spec_drive_flag) = (flg))
#define CBO_HAS_DRIVE_FLAG(pa, flg) (((pa)->spec_drive_flag) == (flg))
#define CBO_HAS_SPEC_DRIVE(pa) (((pa)->spec_drive_flag) != DRIVE_FOR_NONE)

#define TABLE_NAME(table) (((table)->alias.len > 0) ? T2S(&(table)->alias.value) : T2S(&(table)->name.value))
#define INDEX_NAME(table) (((table)->index != NULL) ? (table)->index->name : "NULL")
#define TABLE_COST(table) (TABLE_CBO_IS_LOAD(table) ? CBO_MIN_COST : (table)->cost)

#define IS_INDEX_UNIQUE(index) (((index)->primary || (index)->unique))
#define IS_WITHAS_QUERY(query) (bool32)((query)->owner != NULL && (query)->owner->is_withas)
#define IS_NL_OPER(oper) (bool32)((oper) == JOIN_OPER_NL || (oper) == JOIN_OPER_NL_LEFT || (oper) == JOIN_OPER_NL_FULL)
#define IS_HASH_OPER(oper)                                                                                 \
    (bool32)((oper) == JOIN_OPER_HASH || (oper) == JOIN_OPER_HASH_LEFT || (oper) == JOIN_OPER_HASH_FULL || \
        (oper) == JOIN_OPER_HASH_RIGHT_LEFT)
#define IS_SEMI_OPER(oper) (bool32)((oper) >= JOIN_OPER_HASH_SEMI)

// return expect if ret == expect
#define CBO_RETURN_IF_RES(ret, expect) \
    do {                               \
        if ((ret) == (expect)) {       \
            return (expect);           \
        }                              \
    } while (0)

#define CBO_RETURN_FF_AS_NULL(is_bind, value)                \
    do {                                                     \
        if ((!(is_bind)) && ((value)->is_null == CT_TRUE)) { \
            return CBO_MIN_FF;                               \
        }                                                    \
    } while (0)

// //////////////////////////////////////////////////////////////////////////////////////////////
// for CFilterFactor
typedef enum en_calc_oper_type {
    OPER_EQUAL = 0x0,
    OPER_NOT_EQUAL,
    OPER_GREAT_EQUAL,
    OPER_LESS_EQUAL,
    OPER_GREAT,
    OPER_LESS,
    OPER_LIKE,
    OPER_NOT_LIKE,
    OPER_IS_NULL,
    OPER_IS_NOT_NULL,
    OPER_BETWEEN_AND,
    OPER_NOT_BETWEEN,
    OPER_IN,
    OPER_NOT_IN,
    OPER_EQUAL_ANY,
    OPER_NOT_EQUAL_ANY,
    OPER_COUNT,
} calc_oper_type_t;

typedef enum en_cost_param {
    DB_FILE_MULT_READ_COUNT = 0x0,
    SEQUENCE_PAGE_COST,
    RANDOM_PAGE_COST,
    INDEX_ROWID_PAGE_COST,

    CPU_SCAN_TUPLE_COST,
    CPU_INDEX_TUPLE_COST,
    CPU_OPERATOR_COST,

    CPU_HASH_BUILD_COST,
    CPU_HASH_CALC_COST,

    CPU_QK_SORT_COST,
    CPU_QK_COMP_COST,
    CPU_QK_INST_COST,
    BIND_VARIABLE_FF,
    JOIN_INDEX_FF,

    COST_COUNT,
} en_cost_param_t;

typedef struct st_cbo_oper_param {
    calc_oper_type_t type;
    uint32 column_id;

    uint32 is_low_bind : 1;  // whether lower bound is bind-variable
    uint32 is_high_bind : 1; // whether high bound is bind-variable
    uint32 is_low_closed : 1;
    uint32 is_high_closed : 1;
    uint32 is_func_bind : 1;
    uint32 is_var_peek : 1;
    uint32 is_calc_bind_param : 1;
    uint32 is_low_reserved : 1;
    uint32 is_high_reserved : 1;
    uint32 reserved : 23;

    uint32 in_bind_count;

    expr_tree_t *lo_border;
    expr_tree_t *hi_border;
    expr_node_t *index_ref;

    variant_t lo_bind_var;
    union {
        variant_t hi_bind_var;
        variant_t escape_bind_var;
    };
} cbo_oper_param_t;

typedef struct _st_cbo_border {
    bool32 is_infinite : 1;
    bool32 is_closed : 1;
    bool32 has_bind : 1;
    bool32 has_const : 1;
    bool32 is_reserved : 1;
    bool32 unused : 27;
    expr_tree_t *expr_val;
    variant_t res_var;
} cbo_border_t;

typedef struct _st_cbo_range {
    calc_oper_type_t oper_type;
    uint32 col_id;
    cbo_border_t lo_border;
    cbo_border_t hi_border;
    union {
        uint32 in_bind_count;
        cmp_node_t *like_cmp;
    };
} cbo_range_t;

typedef struct _st_cbo_col_range_list {
    uint32 col_id;
    galist_t *range_list; // cbo_col_range_t
    bilist_node_t bilist_node;
} cbo_col_range_list_t;

typedef struct _st_cbo_tab_range_list {
    bilist_t col_list; // cbo_col_range_list_t
    galist_t *func_list;
} cbo_tab_range_list_t;

typedef struct _st_cbo_calc_assist_t {
    sql_stmt_t *stmt;
    plan_assist_t *pa;
    sql_table_t *table;
    uint32 part_no;
    uint32 subpart_no;
    bool8 add_filter_col;
    bool8 calc_bind_param; // only calculate bind param FF
    bool8 is_or_cond;      // is belong to or condition
    bool8 reserved;
    knl_index_desc_t *index;
    uint32 idx_col_count;
    uint32 special_col_id;
} cbo_calc_assist_t;

typedef struct st_cbo_filter_col {
    calc_oper_type_t oper;
    uint32 col_id;
} cbo_filter_col_t;

typedef struct st_cbo_index_ref {
    expr_node_t *node;
    calc_oper_type_t oper;
    uint16 col_id;
} cbo_index_ref_t;

typedef struct st_cbo_index_drvinfo {
    uint32 id;
    int64 card;
    int64 ndv;
} cbo_index_drvinfo_t;

typedef struct st_cbo_join_cost_assist {
    join_oper_t oper;
    uint32 scan_flag;
    bool8 has_index;
    bool8 is_semi_left;
    bool8 is_norm_hj;
} cbo_join_cost_assist_t;

typedef struct st_cbo_rownum_info {
    int64 limit_scan_count;
    uint32 level;
    bool8 has_rownum;
    bool8 has_limit;
} cbo_rownum_info_t;

typedef struct _st_cbo_index_choose_assist {
    knl_index_desc_t *index;
    uint16 similar_equal_cnt;
    uint16 strict_equal_cnt;
    uint32 idx_match_cnt;
    column_match_mode_t match_mode;
    uint8 index_dsc;
    uint16 scan_flag;
    bool8 index_full_scan;
    bool8 index_ss;
} cbo_index_choose_assist_t;
// //////////////////////////////////////////////////////////////////////////////////////
// global variant
extern double g_cbo_cost[COST_COUNT];

// //////////////////////////////////////////////////////////////////////////////////////
// function interface
cbo_stats_column_t *get_cbo_column(knl_handle_t handle, dc_entity_t *entity, uint32 part_no, uint32 subpart_no,
    uint32 col_id);
cbo_stats_index_t *get_cbo_index(knl_handle_t handle, dc_entity_t *entity, uint32 part_no, uint32 subpart_no,
    uint32 idx_id);
cbo_stats_table_t *get_cbo_table(knl_handle_t handle, dc_entity_t *entity, uint32 part_no, uint32 subpart_no);

int64 get_column_num_null(knl_handle_t handle, dc_entity_t *entity, uint32 col_id, uint32 part_no, uint32 subpart_no);
int64 get_temp_table_rownums(dc_entity_t *entity);
int64 get_one_table_rownum(sql_stmt_t *stmt, dc_entity_t *entity, uint32 part_no, uint32 subpart_no);

variant_t *get_low_value(knl_handle_t handle, dc_entity_t *entity, uint32 col_id, variant_t *var, uint32 part_no,
    uint32 subpart_no);
variant_t *get_high_value(knl_handle_t handle, dc_entity_t *entity, uint32 col_id, variant_t *var, uint32 part_no,
    uint32 subpart_no);
variant_t *get_table_low_value(sql_stmt_t *stmt, sql_table_t *table, uint32 col_id, variant_t *ret_var);
variant_t *get_table_high_value(sql_stmt_t *stmt, sql_table_t *table, uint32 col_id, variant_t *ret_var);

bool32 judge_stats_empty(cbo_stats_table_t *tab_stats);
bool32 judge_table_stats_empty(knl_handle_t handle, sql_table_t *table);
bool32 is_join_driver_table(plan_assist_t *pa, sql_table_t *table);
bool32 if_scale_cost_by_limit(plan_assist_t *pa, sql_table_t *table, uint16 scan_flag, cbo_rownum_info_t *rf);
void scale_output_card_by_limit(plan_assist_t *pa, sql_table_t *table);

void reset_table_cbo_attr(sql_table_t *table);
void scale_cost_by_ancestor(plan_assist_t *pa, sql_table_t *table, double *cost);
void scale_cost_by_distinct(plan_assist_t *pa, int64 join_card, uint16 scan_flag, double *cost);
void scale_cost_by_group(plan_assist_t *pa, int64 join_card, uint16 scan_flag, double *cost);
void scale_cost_by_sort(plan_assist_t *pa, int64 tmp_join_card, uint16 scan_flag, double *cost);
void scale_cost_by_limit(plan_assist_t *pa, sql_table_t *table, cbo_index_choose_assist_t *ca, double *cost);
void scale_scan_cost(plan_assist_t *pa, sql_table_t *table, cbo_index_choose_assist_t *ca, double *cost);
void calc_limit_card(limit_item_t *limit, int64 in_card, int64 *out_card);
void cbo_check_rowid_cost(sql_stmt_t *stmt, plan_assist_t *pa, sql_table_t *table);
void cbo_get_parent_query_cost(sql_query_t *query, cbo_cost_t *cost);

#ifdef __cplusplus
}
#endif

#endif
