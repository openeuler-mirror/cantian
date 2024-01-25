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
 * stats_defs.h
 *
 *
 * IDENTIFICATION
 * src/kernel/include/stats_defs.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_STATS_DEFS_H__
#define __KNL_STATS_DEFS_H__

#include "knl_defs.h"

#ifdef __cplusplus
extern "C" {
#endif
    
typedef enum st_stats_sample_level {
    ROW_SAMPLE = 0,
    BLOCK_SAMPLE = 1
} stats_sample_level_t;

typedef enum st_stats_method_opt_type {
    FOR_ALL_COLUMNS = 0,
    FOR_ALL_INDEX_COLUMNS = 1,
    FOR_SPECIFIED_COLUMNS = 2,
    FOR_SPECIFIED_INDEXED_COLUMNS = 3
} stats_method_opt_type_t;

typedef struct st_knl_analyze_method_opt {
    stats_method_opt_type_t option;  // for all/for index column/ null
} knl_analyze_method_opt_t;

typedef struct st_knl_stats_specified_cols {
    uint32 cols_count;
    uint16 specified_cols[CT_MAX_COLUMNS];
} knl_stats_specified_cols;

typedef enum st_knl_analyze_type {
    STATS_AUTO_SAMPLE = 0,              // set auto sample ratio when use dbe_stats.auto_sample_size
    STATS_DEFAULT_SAMPLE = 1,           // no set sample ratio when use stats package
    STATS_SPECIFIED_SAMPLE = 2          // set sample ratio when use stats package
} knl_analyze_type_t;

typedef enum st_knl_analyze_object {
    ANALYZE_TABLE = 0,
    ANALYZE_INDEX = 1
} knl_analyze_object_t;

typedef enum st_knl_analyze_dynamic_type {
    STATS_ALL = 0,                     // all statistics(table, columns, index) is missing
    STATS_COLUMNS = 1,                 // a certain column statistics is missing
    STATS_INDEXES = 2                  // a certain index statistics is missing
}knl_analyze_dynamic_type_t;

typedef struct st_knl_analyze_tab_def {
    text_t owner;
    text_t name;
    text_t part_name;                   // if null all part analyze
    uint32 part_no;
    double sample_ratio;                // sample ratio 0 analyze full table rather than sample
    stats_sample_level_t sample_level;  // BLOCK_SAMPLE or ROW_SAMPLE. now just support BLOCK_SAMPLE
    knl_analyze_method_opt_t method_opt;
    knl_stats_specified_cols specify_cols;
    knl_analyze_type_t sample_type;
    knl_analyze_dynamic_type_t dynamic_type;
    bool32 is_default;
    bool8  is_report;
    knl_handle_t *table_part;
    bool32 need_analyzed;
} knl_analyze_tab_def_t;

typedef struct st_knl_analyze_col_def {
    text_t owner;
    text_t table_name;
    text_t column_name;
    double sample_ratio;
    stats_sample_level_t sample_level;
} knl_analyze_col_def_t;

typedef struct st_knl_analyze_index_def {
    text_t owner;
    text_t name;
    double sample_ratio;
    stats_sample_level_t sample_level;
    bool32 need_analyzed;
    text_t table_owner;
    text_t table_name;
} knl_analyze_index_def_t;

typedef struct st_knl_analyze_schema_def {
    text_t owner;
    double sample_ratio;
    stats_sample_level_t sample_level;
    knl_analyze_method_opt_t method_opt;
    knl_analyze_type_t sample_type;
    bool32 is_default;
} knl_analyze_schema_def_t;

typedef struct st_knl_table_set_stats {
    text_t owner;
    text_t name;
    text_t part_name;                  // if null all part set
    uint32 rownums;
    uint32 blknums;
    uint64 avgrlen;
    bool32 is_single_part;
    bool32 is_forced;
    uint64 samplesize;
} knl_table_set_stats_t;

typedef struct st_knl_column_set_stats {
    text_t owner;
    text_t tabname;
    text_t part_name;                  // if null all part set
    text_t colname;
    uint32 distnum;
    double density;
    uint32 nullnum;
    bool32 is_single_part;
    bool32 is_forced;
    text_t min_value;
    text_t max_value;
} knl_column_set_stats_t;

typedef struct st_knl_index_set_stats {
    text_t owner;
    text_t name;
    text_t part_name;                  // if null all part set
    uint32 numlblks;                  // number of leaf blocks
    uint32 numdist;                   // number of distinct key
    double avglblk;                   // avg leaf per key
    double avgdblk;                   //  avg data block per key
    uint32 clstfct;                   // clustering_factor
    uint32 indlevel;                  // Height of the index
    uint32 combndv2;                  // number of distinct key comb index 2 columns
    uint32 combndv3;                  // number of distinct key comb index 3 columns
    uint32 combndv4;                  // number of distinct key comb index 4 columns
    bool32 is_forced;
    bool32 is_single_part;
} knl_index_set_stats_t;

// STATS
status_t knl_analyze_table(knl_handle_t session, knl_analyze_tab_def_t *def);
status_t knl_analyze_table_dynamic(knl_handle_t session, knl_analyze_tab_def_t *def);
status_t knl_analyze_index(knl_handle_t session, knl_analyze_index_def_t *def);
status_t knl_analyze_index_dynamic(knl_handle_t session, knl_analyze_index_def_t *def);
status_t knl_analyze_schema(knl_handle_t session, knl_analyze_schema_def_t *def);
status_t knl_delete_table_stats(knl_handle_t session, text_t *own_name, text_t *tab_name, text_t *part_name);
status_t knl_delete_schema_stats(knl_handle_t session, text_t *schema_name);
status_t knl_set_table_stats(knl_handle_t session, knl_table_set_stats_t *tab_stats);
status_t knl_set_columns_stats(knl_handle_t session, knl_column_set_stats_t *col_stats);
status_t knl_set_index_stats(knl_handle_t session, knl_index_set_stats_t *ind_stats);
status_t knl_purge_stats(knl_handle_t session, int64 max_analyze_time);
void knl_estimate_table_rows(uint32 *pages, uint32 *rows, knl_handle_t sess, knl_handle_t entity, uint32 part_no);
status_t knl_lock_table_stats(knl_handle_t session, knl_dictionary_t *dc);
status_t knl_unlock_table_stats(knl_handle_t session, knl_dictionary_t *dc);
void knl_estimate_subtable_rows(uint32 *pages, uint32 *rows, knl_handle_t sess, knl_handle_t entity,
                                uint32 part_no, uint32 subpart_no);


#ifdef __cplusplus
}
#endif

#endif