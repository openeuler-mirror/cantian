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
 * knl_rstat.h
 *
 *
 * IDENTIFICATION
 * src/kernel/statistics/knl_rstat.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_RSTAT_H__
#define __KNL_RSTAT_H__

#include "cm_defs.h"
#include "cm_row.h"
#include "cm_encrypt.h"
#include "knl_interface.h"
#include "knl_session.h"
#include "rcr_btree_stat.h"
#include "pcr_btree_stat.h"
#include "knl_space_base.h"
#include "knl_buffer_access.h"
#include "knl_dc.h"
#include "stats_defs.h"

#ifdef __cplusplus
extern "C" {
#endif

#define STATS_CDATA(row, id) ((row)->data + (row)->offsets[id])
#define STATS_CSIZE(row, id) ((row)->lens[id])

#define STATS_MAX_COMPARE_SIZE 64
#define STATS_DEC_BUCKET_SIZE  CT_MAX_DEC_OUTPUT_ALL_PREC
#define STATS_MAX_BUCKET_SIZE  64

#define STATS_SYS_INDEX_COLUMN_COUNT           12
#define STATS_SYS_INDEX_COLUMN_NUM             17
#define STATS_SYS_INDEX_BLEVEL_COLUMN          17
#define STATS_SYS_INDEX_LEAF_BLOCKS_COLUMN     18
#define STATS_SYS_INDEX_NDV_KEY_COLUMN         19
#define STATS_SYS_INDEX_AVG_LBK_COLUMN         20
#define STATS_SYS_INDEX_AVG_DBK_COLUMN         21
#define STATS_SYS_INDEX_ANALYZETIME_COLUMN     22
#define STATS_SYS_INDEX_EMPTY_BLOCK_COLUMN     23

#define STATS_SYS_INDEX_COLFAC_COLUMN          25
#define STATS_SYS_INDEX_SAMSIZE_COLUMN         26
#define STATS_SYS_INDEX_COMB2_NDV_COLUMN       28
#define STATS_SYS_INDEX_COMB3_NDV_COLUMN       29
#define STATS_SYS_INDEX_COMB4_NDV_COLUMN       30
#define STATS_SYS_TABLE_COLUMN_COUNT           6
#define STATS_SYS_TABLE_COLUMN_NUM             16
#define STATS_SYS_COLUMN_COLUMN_COUNT          4
#define STATS_SYS_COLUMN_COLUMN_NUM            12
#define STATS_HISTGRAM_DEFAULT_SIZE            75
#define STATS_HISTGRAM_MAX_SIZE             254
#define STATS_MIN_ESTIMATE_PERCENT          0.000001
#define STATS_MAX_ESTIMATE_PERCENT          100
#define STATS_FULL_TABLE_SAMPLE 0
#define STATS_DEFAULT_ESTIMATE_PERCENT      10
#define STATS_FULL_TABLE_SAMPLE_RATIO       0
#define STATS_SAMPLE_MAX_RATIO              (double)1.0
#define STATS_DEFAULT_ESTIMATE_RATIO        0.1
#define STATS_MIN_BTREE_KEYS                1
#define STATS_TABLE_MONITOR_INTERVAL        (15 * 60)  // 15 MINS
#define STATS_LRU_TABLE_MONITOR_INTERVAL    (3 * 60)   // 3 MINS
#define DB_IS_STATS_ENABLED(kernel)         ((kernel)->attr.enable_table_stat)
#define STATS_ENABLE_MONITOR_TABLE(session) \
    (DB_IS_STATS_ENABLED((session)->kernel) && ((session)->kernel->dc_ctx.completed))
#define STATS_ENABLE_PAGE(session)          ((session)->stat_page.enable)
#define STATS_INVALID_TABLE(type)           ((type) > DICT_TYPE_TABLE_EXTERNAL)
#define STATS_SYS_TABLEPART_COLUMN_NUM         13
#define STATS_SYS_INDEXPART_COLUMN_NUM         14

#define STATS_SYS_TABLESUBPART_COLUMN_COUNT     6
#define STATS_SYS_TABLESUBPART_COLUMN_NUM      13
#define STATS_SYS_INDEXSUBPART_COLUMN_COUNT    12
#define STATS_SYS_INDEXSUBPART_COLUMN_NUM      14

#define STATS_MON_MODS_UPDATE_COLUMNS       5

#define STATS_MON_MODS_INSERTS_COLUMN       2
#define STATS_MON_MODS_UPDATES_COLUMN       3
#define STATS_MON_MODS_DELETES_COLUMN       4
#define STATS_MON_MODS_MODIFYTIME_COLUMN    5
#define STATS_MON_MODS_DROP_SEG_COLUMN      7
#define STATS_MON_MODS_PARTED               8
#define STATS_MON_MODS_PART_ID              9

#define STATS_TMP_SEG_STAT_UPDATE_COLUMNS  6
#define STATS_TMP_SEG_STAT_ALL_COLUMNS     9
#define STATS_TMP_SEG_STAT_LOGICREADS_COLUMN     3
#define STATS_TMP_SEG_STAT_PHYSICALWRITES_COLUMN 4
#define STATS_TMP_SEG_STAT_PHYSICALREADS_COLUMN  5
#define STATS_TMP_SEG_STAT_ITLWAITS_COLUMN       6
#define STATS_TMP_SEG_STAT_BUFBUSYWAITS_COLUMN   7
#define STATS_TMP_SEG_STAT_ROWLOCKWAITS_COLUMN   8
#define STATS_ROWID_NO                            0
#define STATS_ROWID_COUNT                         1
#define STATS_MAX_REPORT_NAME_LEN                 (CT_MAX_FILE_NAME_LEN + 4) // 4 bytes for ".csv"
#define STATS_MAX_PARTNO_MSG_LEN                  128
#define STATS_GLOBAL_PARTTABLE_COLUMNS            4
#define STATS_GLOBAL_HISTHEAD_COLUMNS             8
#define STATS_MAX_ITERATION_TIME                  1000
#define STATS_MAX_COLUMN_BUF                      (CT_MAX_COLUMN_SIZE + 100)
#define STATS_PARALL_MIN_CPU_COUNT                2
#define STATS_PARALL_MIN_COLUMN_COUNT             2

#define STATS_GET_ROW_DATA(mtrl_cur) \
    ((char *)(mtrl_cur)->row.data + (mtrl_cur)->row.offsets[0])

#define STATS_GET_ROW_SIZE(mtrl_cur) \
    ((mtrl_cur)->row.lens[0])

#define STATS_MANUAL_SESSION_GTT(type, id, is_dynamic) \
    ((type) == DICT_TYPE_TEMP_TABLE_SESSION && !(is_dynamic) && !IS_LTT_BY_ID(id))

#define STATS_IS_ANALYZE_TEMP_TABLE(table_stats)        ((table_stats)->temp_table != NULL)
#define STATS_ENABLE_PARALLER(table_stats, is_paraller) (((table_stats)->temp_table == NULL) && (is_paraller))
#define STATS_PARALL_MAX_VM_PAGES                        50
#define STATS_DYNAMICAL_TRANS_GTT(type, is_dynamic) \
    ((type) == DICT_TYPE_TEMP_TABLE_TRANS && (is_dynamic))

#define STATS_IS_INVALID_PART_TABLE(table_part) \
    ((table_part) == NULL || !(table_part)->is_ready || (table_part)->desc.not_ready || \
    (table_part)->heap.segment == NULL)

#define STATS_IS_INVALID_PART_INDEX(index_part) \
    ((index_part) == NULL || (index_part)->desc.is_not_ready || (index_part)->desc.is_invalid || \
    (index_part)->btree.segment == NULL)

#define IS_PART_DROPPED_OR_TRUNCATED(err_code) \
    ((err_code) == ERR_OBJECT_ALREADY_DROPPED || (err_code) == ERR_INDEX_ALREADY_DROPPED || \
    (err_code) == ERR_INVALID_PAGE_ID)

typedef enum st_stats_hist_type {
    FREQUENCY = 0,
    HEIGHT_BALANCED = 1,
} stats_hist_type_t;

typedef struct st_stats_table_info {
    uint32 rows;
    uint32 blocks;
    uint32 empty_block;
    uint64 avg_row_len;
    uint64 sample_size;
    date_t analyze_time;
    uint64 row_len;
}stats_table_info_t;

typedef struct st_stats_part_table {
    bool32 is_subpart;
    stats_table_info_t info;
    uint32 part_id;
    uint32 part_no;  // for scan part
    mtrl_rowid_t parent_start_rid;
    struct st_stats_part_table *sub_stats;
} stats_part_table_t;

typedef struct st_stats_option {
    stats_sample_level_t sample_level;
    stats_method_opt_type_t method_opt;
    knl_stats_specified_cols *specify_cols;
    knl_analyze_type_t analyze_type;
    knl_analyze_dynamic_type_t dynamic_type;
    double  sample_ratio;
    bool8   is_report;
    int32   report_col_file;
    int32   report_idx_file;
    int32   report_tab_file;
} stats_option_t;

typedef struct st_stats_temp_table {
    knl_temp_cache_t *table_cache;
    uint32 prev_sample_pageid;
    uint32 sample_pages;
    uint32 first_pageid;
} stats_tmptab_t;

typedef struct st_stats_table {
    uint32 uid;
    uint32 tab_id;
    bool32 is_part;
    stats_table_info_t tab_info;
    double estimate_sample_ratio;
    stats_option_t     stats_option;
    stats_part_table_t part_stats;
    mtrl_rowid_t part_start_rid;
    mtrl_rowid_t now_rid;  // for partition table all statistics
    bool32 is_dynamic;
    stats_tmptab_t *temp_table;
    bool8  single_part_analyze;
    uint32 specify_part_id;
    double part_sample_ratio;  // for one part gather statistics
    int32  report_file;
    bool32 is_nologging;
} stats_table_t;

typedef struct st_stats_tab_context {
    stats_table_t *table_stats;
    mtrl_context_t *mtrl_tab_ctx;
    uint32 mtrl_tab_seg;
}stats_tab_context_t;

typedef struct st_stats_column {
    uint32 distinct_num;
    uint32 low_value;
    uint32 high_value;
    uint32 number_buckets;
    uint32 hisgrm;
} stats_column_t;

typedef struct st_stats_rs_column {
    text_t name;
    uint32 col_id;
    ct_type_t datatype;
    uint32 size;
} stats_rs_column_t;

typedef struct st_stats_row {
    char *data;
    uint32 count;
} stats_row_t;

typedef struct st_stats_mtrl {
    mtrl_context_t mtrl_ctx;
    mtrl_cursor_t mtrl_cur;
    mtrl_context_t *mtrl_table_ctx;
    uint32 dist_seg_id;  // used to sort and distinct
    uint32 temp_seg_id;  // used to storage sample table rows
} stats_mtrl_t;

typedef struct st_stats_index {
    btree_info_t info;
    double avg_leaf_key;   // avg leaf per key
    double avg_data_key;   // avg data block per key
    uint32 uid;
    uint32 clus_factor; // clustering_factor
    text_t name;
    date_t analyse_time;
    bool32 is_encode;
    uint32 table_id;
    uint32 idx_id;
    uint32 part_id;
    mtrl_rowid_t g_rid;
    double sample_ratio;
    stats_mtrl_t mtrl;
    btree_t *btree;
    index_part_t *part_index;
    bool32 is_dynamic;
    uint64 sample_size;
    uint32 index_no; // from 0 to table->index_set.count - 1
    uint32 subpart_id;
    bool32 is_subpart;
}stats_index_t;

typedef struct st_stats_hist_info {
    uint32 dnv_per_num;
    uint32 prev_endpoint;
    uint32 bucket_num;
    uint32 endpoint;
    stats_hist_type_t type;
} stats_hist_info_t;

typedef struct st_stats_hist_rowids {
    uint32         bucket_num;
    uint32         curr_bucket;
    rowid_t        rowid_list[STATS_HISTGRAM_MAX_SIZE];
}stats_hist_rowids_t;

typedef struct st_stats_vm_list {
    uint32  id_list[STATS_PARALL_MAX_VM_PAGES];
    uint32  pos;
}stats_vm_list;

typedef struct st_stats_hist_entity {
    uint32 endpoint;
    uint32 len;
    char   bucket[STATS_MAX_BUCKET_SIZE + 1];
}stats_hist_entity_t;

typedef struct st_stats_hists {
    uint32 hist_num;
    stats_hist_entity_t hist[STATS_HISTGRAM_MAX_SIZE];
}stats_hists_t;

typedef struct st_stats_col_handler_t {
    uint32 total_rows;
    uint32 dist_num;
    uint32 null_num;
    double simple_ratio;
    text_t min_value;
    text_t max_value;
    bool32 has_null;
    knl_column_t *column;
    stats_hist_info_t hist_info;
    stats_mtrl_t mtrl;
    mtrl_rowid_t g_rid;  // for partition table all statistics
    uint16 max_bucket_size;
    int32  report_file;
    bool8 hist_exits;
    knl_cursor_t *stats_cur;
    stats_hist_rowids_t *hist_rowids;
    stats_hists_t histgram;
    bool32 is_nologging;
    char col_buf[STATS_MAX_COLUMN_BUF];
    char min_buf[STATS_MAX_BUCKET_SIZE];
    char max_buf[STATS_MAX_BUCKET_SIZE];
} stats_col_handler_t;

typedef struct st_stats {
    thread_t thread;
    volatile bool32 stats_gathering;
} stats_t;

typedef struct st_knl_seg_stats_desc {
    knl_scn_t org_scn;
    uint32 uid;
    uint32 oid;
    uint64 logic_reads;
    uint64 physical_reads;
    uint64 physical_writes;
    uint64 row_lock_waits;
    uint64 buf_busy_waits;
    uint64 itl_waits;
} knl_seg_stats_desc_t;

typedef struct st_stats_seg_sampler {
    uint64 sample_size;
    uint32 total_extents;
    uint32 pages_per_ext;    // sample pages count of per extent
    uint32 sample_extents;  // sample extents count of segment
    uint32 hwm_extents;
    uint32 hwm_pages;
    uint16 extent_step;         // step of sample extents
    page_list_t sample_extent;  // sample extent is a sample page list
    page_id_t current_extent;
    uint32 map_pages;  // sample page may be map_pages
    uint32 extent_size; // pages count in one extent
    uint32 *random_step;
} stats_sampler_t;

typedef struct st_stats_cols_list {
    uint32  max_count;
    uint32  column_count;
    uint16 *col_list;
    uint32  pos;
}stats_cols_list_t;

typedef struct st_stats_col_context {
    stats_col_handler_t *col_handler;
    knl_column_t *column;
    knl_cursor_t *stats_cur;
}stats_col_context_t;

typedef struct st_stats_par_context_t {
    thread_t thread;
    stats_col_context_t col_ctx;
    pointer_t *par_ctrl;
    uint16 id;
    bool32 is_wait;
}stats_par_context_t;

typedef struct st_stats_thread_queue_t {
    volatile uint16 pos;
    uint16 id_list[CT_MAX_STATS_PARALL_THREADS];
}stats_thread_queue_t;

typedef struct st_stats_par_ctrl_t {
    spinlock_t read_lock;
    knl_session_t *session;
    stats_tab_context_t *tab_ctx;
    dc_entity_t *entity;
    stats_cols_list_t *col_list;
    uint32 thread_count;
    stats_par_context_t par_ctx[CT_MAX_STATS_PARALL_THREADS];
    stats_thread_queue_t par_thread_queue;
    volatile uint32 sort_count;
    volatile uint32 finish_count;
    volatile uint32 alive_threads;
    volatile bool32 parall_success;
    volatile bool32 sort_finished;
    volatile bool32 all_finished;
    volatile bool32 all_thread_ready;
} stats_par_ctrl_t;

typedef struct st_stats_hist_assist_t {
    uint64 endpoint;
    rowid_t row_id;
} stats_hist_assist_t;

typedef struct st_stats_part_table_assist_t {
    uint32 part_id;
    uint32 subpart_id;
    bool32 is_subpart;
} stats_part_table_assist_t;

typedef struct st_stats_load_info {
    bool32 load_subpart;
    uint32 parent_part_id;
}stats_load_info_t;

typedef enum st_stats_match_type {
    MATCH_PART = 0,
    MATCH_SUBPART = 1,
    MATCH_COLUMN = 2
}stats_match_type_t;

typedef struct st_stats_match_cond {
    knl_session_t *session;
    knl_cursor_t *cursor;
    uint32 col_id;
    uint64 part_id;
    uint64 subpart_id;
    stats_match_type_t match_type;
}stats_match_cond_t;

status_t stats_gather_table(knl_session_t *session, knl_dictionary_t *dc, stats_table_t *tab_stats);
status_t db_delete_mon_sysmods(knl_session_t *session, uint32 uid, uint32 table_id, uint32 dele_part_id,
                               bool32 is_dynamic);
status_t stats_gather_indexes(knl_session_t *session, knl_dictionary_t *dc, stats_table_t *table_stats,
                              mtrl_context_t *mtrl_tab_ctx, uint32 temp_seg);
status_t stats_gather_index_by_btree(knl_session_t *session, knl_dictionary_t *dc, knl_analyze_index_def_t *def,
                                     bool32 is_dynamic);
status_t stats_drop_hists(knl_session_t *session, uint32 uid, uint32 oid, bool32 is_nologging);
uint32 stats_estimate_ndv(uint32 sampled_ndv, uint32 sampled_row, double sampled_ratio);
status_t stats_clean_spc_stats(knl_session_t *session, space_t *space);
void stats_clean_nologging_stats(knl_session_t *session);

void stats_proc(thread_t *thread);
void stats_close(knl_session_t *session);
status_t stats_seg_load_entity(knl_session_t *session, knl_scn_t org_scn, seg_stat_t *seg_stat);
status_t stats_temp_insert(knl_session_t *session, struct st_dc_entity *dc_entity);
void stats_buf_record(knl_session_t *session, knl_buf_wait_t *temp_stat, buf_ctrl_t *ctrl);
void stats_buf_init(knl_session_t *session, knl_buf_wait_t *temp_stat);

status_t stats_purge_stats_by_time(knl_session_t *session, int64 max_analyze_time);
status_t stats_delete_table_stats(knl_session_t *session, const uint32 uid, const uint32 oid, bool32 is_old_nologging);
status_t stats_delete_part_stats(knl_session_t *session, const uint32 uid, const uint32 oid, uint32 part_id);
void stats_dc_invalidate(knl_session_t *session, knl_dictionary_t *dc);
status_t stats_refresh_dc(knl_session_t *session, knl_dictionary_t *dc, stats_load_info_t load_info);
status_t rd_internal_refresh_dc(knl_session_t *session, dc_entity_t *entity, stats_load_info_t *load_info);

status_t stats_gather_table_part(knl_session_t *session, knl_dictionary_t *dc, stats_option_t stats_option,
                                 table_part_t *table_part, bool32 is_dynamic);
status_t stats_check_analyzing(knl_session_t *session, knl_dictionary_t *dc, bool32 *need_analyze,
                               bool32 is_dynamic);
void stats_set_analyzed(knl_session_t *session, knl_dictionary_t *dc, bool32 analyzed);
void stats_monitor_table_change(knl_cursor_t *cursor);
status_t stats_delete_histhead_by_part(knl_session_t *session, knl_dictionary_t *dc, uint32 part_id);
status_t stats_delete_histgram_by_part(knl_session_t *session, knl_cursor_t *cursor, knl_dictionary_t *dc,
    uint32 part_id);
void stats_init_stats_option(stats_option_t *stats_option, knl_analyze_tab_def_t *def);
status_t stats_update_global_tablestats(knl_session_t *session, knl_dictionary_t *dc, uint32 part_no);
void stats_disable_table_part_mon(knl_dictionary_t *dc, table_part_t *table_part, bool32 analyzed);
void stats_disable_table_mon(knl_session_t *session, knl_dictionary_t *dc, bool32 analyzed);
status_t stats_gather_normal_table(knl_session_t *session, knl_dictionary_t *dc, stats_option_t stats_option,
                                   bool32 is_dynamic);
status_t stats_gather_temp_table(knl_session_t *session, knl_dictionary_t *dc, stats_option_t stats_option,
                                 bool32 is_dynamic);
status_t stats_find_part(knl_session_t *session, knl_analyze_tab_def_t *def, knl_dictionary_t *dc,
                         table_part_t **table_part);
status_t stats_find_part(knl_session_t *session, knl_analyze_tab_def_t *def, knl_dictionary_t *dc,
                         table_part_t **table_part);
status_t stats_flush_monitor_force(knl_session_t *session, dc_entity_t *entity);
status_t stats_flush_monitor_normal(knl_session_t *session);

status_t stats_set_tables(knl_session_t *session, knl_dictionary_t *dc, knl_table_set_stats_t *tab_stats,
                          table_part_t *table_part);
status_t stats_set_column(knl_session_t *session, knl_dictionary_t *dc, knl_column_set_stats_t *col_stats,
                          table_part_t *table_part, knl_column_t *column);
status_t stats_set_index(knl_session_t *session, knl_dictionary_t *dc, knl_index_set_stats_t *idx_stats,
                         index_part_t *idx_part, index_t *index);
status_t stats_put_result_value(row_assist_t *ra, text_t *res_value, ct_type_t type);
void stats_flush_logic_log(knl_session_t *session, knl_dictionary_t *dc, stats_load_info_t *load_info);
void stats_commit(knl_session_t *session, bool32 is_dynamic);
void stats_rollback(knl_session_t *session, bool32 is_dynamic);
status_t stats_analyze_normal_table(knl_session_t *session, knl_dictionary_t *dc, stats_option_t stats_option,
    bool32 is_dynamic, bool32 *need_analyze);
status_t stats_analyze_single_table_part(knl_session_t *session, knl_dictionary_t *dc, knl_analyze_tab_def_t *def,
    stats_option_t stats_option, bool32 is_dynamic);
status_t stats_analyze_index(knl_session_t *session, knl_dictionary_t *dc, knl_analyze_index_def_t *def,
                             bool32 is_dynamic);
status_t stats_delete_histhead_by_subpart(knl_session_t *session, table_part_t *sub_part, bool32 is_nologging);
status_t stats_delete_histgram_by_subpart(knl_session_t *session, knl_cursor_t *cursor, table_part_t *subpart,
    bool32 is_nologging);
status_t stats_update_global_partstats(knl_session_t *session, knl_dictionary_t *dc, uint32 partid, uint32 subpart_no);
void stats_set_load_info(stats_load_info_t *load_info, dc_entity_t *entity, bool32 load_subpart, uint32 part_id);
int32 stats_compare_data_ex(void *data1, uint16 size_1, void *data2, uint16 size_2, knl_column_t *column);
status_t stats_set_analyze_time(knl_session_t *session, knl_dictionary_t *dc, bool32 locked);
void stats_open_histgram_cursor(knl_session_t *session, knl_cursor_t *cursor, knl_cursor_action_t action,
    uint32 index_id, bool32 is_nologging);
void stats_open_hist_abstr_cursor(knl_session_t *session, knl_cursor_t *cursor, knl_cursor_action_t action,
    uint32 index_id, bool32 is_nologging);
#ifdef __cplusplus
}
#endif

#endif
