/* -------------------------------------------------------------------------
 *  This file is part of the Cantian project.
 * Copyright (c) 2023 Huawei Technologies Co.,Ltd.
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
 * ostat_load.h
 *
 *
 * IDENTIFICATION
 * src/kernel/statistics/ostat_load.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef OSTAT_LOAD_H
#define OSTAT_LOAD_H

#include "knl_context.h"
#include "knl_table.h"
#include "../../tse/tse_srv.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CBO_LIST_COUNT   64
#define CBO_EXTENT_COUNT 64
#define CBO_INVALID_COLUMN_ID          (uint32)0xFFFFFFFF

#define CBO_GET_GROUP_NO(object, id) ((object)->part_group.group_id[(id) / PART_GROUP_SIZE])
#define CBO_TABLE_PART_IS_INIT(object, id) (((CBO_GET_GROUP_NO(object, id)) != GS_INVALID_ID32) && \
    ((object)->part_group.group_ready[CBO_GET_GROUP_NO(object, id)]) && \
    ((object)->part_groups[CBO_GET_GROUP_NO(object, id)] != NULL))
#define CBO_INDEX_PART_IS_INIT(object, id) (((CBO_GET_GROUP_NO(object, id)) != GS_INVALID_ID32) && \
    ((object)->part_group.group_ready[CBO_GET_GROUP_NO(object, id)]) && \
    ((object)->part_index_groups[CBO_GET_GROUP_NO(object, id)] != NULL))
#define CBO_GET_SUBTABLE_PART(object, id) \
    ((object)->subpart_groups[(id) / PART_GROUP_SIZE]->entity[(id) % PART_GROUP_SIZE])
#define CBO_GET_SUBINDEX_PART(object, id) \
    ((object)->subpart_index_groups[(id) / PART_GROUP_SIZE]->entity[(id) % PART_GROUP_SIZE])
#define CBO_NEED_LOAD_PART(part_id, scan_part_id) \
        ((part_id) == GS_INVALID_ID32 || (part_id) == (scan_part_id))
#define CBO_GET_TABLE_NORMAL_PART(object, id) \
    ((object)->part_groups[(id) / PART_GROUP_SIZE]->entity[(id) % PART_GROUP_SIZE])
#define CBO_GET_TABLE_INTERVAL_PART(object, id) (!(CBO_TABLE_PART_IS_INIT(object, id)) ? (NULL) : \
    ((object)->part_groups[CBO_GET_GROUP_NO(object, id)]->entity[(id) % PART_GROUP_SIZE]))
#define CBO_GET_INDEX_NORMAL_PART(object, id) \
    ((object)->part_index_groups[(id) / PART_GROUP_SIZE]->entity[(id) % PART_GROUP_SIZE])
#define CBO_GET_INDEX_INTERVAL_PART(object, id) (!(CBO_INDEX_PART_IS_INIT(object, id)) ? (NULL) : \
    ((object)->part_index_groups[CBO_GET_GROUP_NO(object, id)]->entity[(id) % PART_GROUP_SIZE]))
#define CBO_GET_TABLE_PART(object, id) ((!PART_AS_INTERVAL(object)) ? (CBO_GET_TABLE_NORMAL_PART((object), (id))) : \
    (CBO_GET_TABLE_INTERVAL_PART((object), (id))))
#define CBO_GET_INDEX_PART(object, id) ((!PART_AS_INTERVAL(object)) ? (CBO_GET_INDEX_NORMAL_PART((object), (id))) : \
    (CBO_GET_INDEX_INTERVAL_PART((object), (id))))

typedef struct st_cbo_stats_index cbo_stats_index_t;
typedef stats_hist_type_t cbo_hist_type_t;

typedef struct st_stats_idx_assist {
    page_id_t entry;
    uint32 space_id;
    knl_scn_t org_scn;
    idx_chg_stats_t *seg_stats;
} stats_idx_assist_t;

// ref g_sys_table_columns columns info
typedef enum en_stats_table_columns {
    TABLE_UID = 0,
    TABLE_TABLE_ID = 1,
    TABLE_NAME = 2,

    TABLE_TYPE = 6,

    TABLE_PARTITIONED = 9,

    TABLE_RECYCLED = 14,
    TABLE_APPENDONLY = 15,
    TABLE_ROWS = 16,
    TABLE_BLOCKS = 17,
    TABLE_EMPTY_BLOCK = 18,
    TABLE_AVG_ROW_LEN = 19,
    TABLE_SAMPLE_SIZE = 20,
    TABLE_ANALYZE_TIME = 21,
} stats_table_columns_t;

typedef enum en_stats_histhead_columns {
    HIST_HEAD_UID = 0,
    HIST_HEAD_TABLE_ID = 1,
    HIST_HEAD_COLUMN_ID = 2,
    HIST_HEAD_BUCKET_NUM = 3,
    HIST_HEAD_TOTAL_ROWS = 4,
    HIST_HEAD_NULL_NUM = 5,
    HIST_HEAD_ANALYZE_TIME = 6,
    HIST_HEAD_LOW_VALUE = 7,
    HIST_HEAD_HIGH_VALUE = 8,
    HIST_HEAD_DIST_NUM = 9,
    HIST_HEAD_DENSITY = 10,
    HIST_HEAD_PART_ID = 11,
    HIST_HEAD_SUBPART_ID = 12,
    HIST_HEAD_SAMPLE_SIZE = 13,
} stats_histhead_columns_t;

typedef enum en_stats_hist_columns {
    HIST_UID = 0,
    HIST_TABLE_ID = 1,
    HIST_COLUMN_ID = 2,
    HIST_EP_VALUE = 3,
    HIST_EP_NUM = 4,
    HIST_PART_ID = 5,
    HIST_SUBPART_ID = 7,
} stats_hist_columns_t;

// ref g_sys_index_columns columns info
typedef enum en_stats_index_columns {
    INDEX_UID = 0,
    INDEX_TABLE_ID = 1,
    INDEX_IDX_ID = 2,
    INDEX_IDX_NAME = 3,

    INDEX_FLAGS = 14,
    INDEX_PARTED = 15,
    INDEX_BLEVEL = 17,
    INDEX_LEVEL_BLOCKS = 18,
    INDEX_DISTINCT_KEYS = 19,
    INDEX_AVG_LEAF_BLOCKS_PER_KEY = 20,
    INDEX_AVG_DATA_BLOCKS_PER_KEY = 21,
    INDEX_IDX_ANALYZE_TIME = 22,
    INDEX_EMPTY_LEAF_BLOCKS = 23,
    INDEX_CLUSTER_FACTOR = 25,
    INDEX_COMB_2_NDV = 28,
    INDEX_COMB_3_NDV = 29,
    INDEX_COMB_4_NDV = 30,
} stats_index_columns_t;

typedef enum en_stats_table_part_columns {
    TABLE_PART_UID = 0,
    TABLE_PART_TABLE_ID = 1,
    TABLE_PART_ID = 2,

    TABLE_PART_ROWS = 13,
    TABLE_PART_BLOCKS = 14,
    TABLE_PART_EMPTY_BLOCK = 15,
    TABLE_PART_AVG_ROW_LEN = 16,
    TABLE_PART_SAMPLE_SIZE = 17,
    TABLE_PART_ANALYZE_TIME = 18,
} stats_table_part_columns_t;

typedef enum en_stats_index_part_columns {
    INDEX_PART_UID = 0,
    INDEX_PART_TAB_ID = 1,
    INDEX_PART_IDX_ID = 2,
    INDEX_PART_ID = 3,

    INDEX_PART_BLEVEL = 14,
    INDEX_PART_LEVEL_BLOCKS = 15,
    INDEX_PART_DISTINCT_KEYS = 16,
    INDEX_PART_AVG_LEAF_BLOCKS_PER_KEY = 17,
    INDEX_PART_AVG_DATA_BLOCKS_PER_KEY = 18,
    INDEX_PART_ANALYZE_TIME = 19,
    INDEX_PART_EMPTY_LEAF_BLOCKS = 20,
    INDEX_PART_CLUSTER_FACTOR = 21,
    INDEX_PART_SAMPLE_SIZE = 22,
    INDEX_PART_COMB_2_NDV = 23,
    INDEX_PART_COMB_3_NDV = 24,
    INDEX_PART_COMB_4_NDV = 25,
} stats_index_part_columns_t;

/* stats partition group structure */
typedef struct st_cbo_index_part_group {
    cbo_stats_index_t *entity[PART_GROUP_SIZE];
} cbo_index_part_group_t;

typedef struct st_cbo_stats_index {
    uint32 id;
    bool8  is_part;
    bool8  is_parent_part;
    uint32 part_id;
    uint32 blevel;
    uint32 leaf_blocks;
    uint32 distinct_keys;
    double avg_leaf_key;  // avg leaf per key
    double avg_data_key;  // avg data block per key
    uint32 clustering_factor;
    date_t analyse_time;
    uint32 empty_leaf_blocks;
    uint32 comb_cols_2_ndv;
    uint32 comb_cols_3_ndv;
    uint32 comb_cols_4_ndv;
    cbo_index_part_group_t **part_index_groups;
    cbo_index_part_group_t **subpart_index_groups;
    struct st_cbo_stats_index *idx_part_default;
    volatile uint32 stats_version;
    volatile bool8 is_ready;
    part_group_t part_group;
} cbo_stats_index_t;

typedef struct st_cbo_column_hist {
    text_t ep_value;
    int64 ep_number;
} cbo_column_hist_t;

typedef struct st_cbo_stats_column {
    uint32 column_id;
    uint32 column_type;
    volatile uint32 num_buckets;
    uint32 total_rows;
    uint32 num_distinct;
    uint32 num_null;
    date_t analyse_time;
    double density;

    cbo_hist_type_t hist_type;
    volatile uint32 hist_count;
    cbo_column_hist_t **column_hist;  // Column histogram statistics (array)

    text_t low_value;
    text_t high_value;
} cbo_stats_column_t;

/* stats partition group structure */
typedef struct st_cbo_table_part_group {
    cbo_stats_table_t *entity[PART_GROUP_SIZE];
} cbo_table_part_group_t;

typedef struct st_cbo_max_subpart {
    uint32 part_no;  // the parent part no
    uint32 subpart_no;  // the sub part no of max rows
} cbo_max_subpart_t;

typedef struct st_cbo_stats_table {
    uint32 table_id;
    uint32 part_id;
    uint32 subpart_id;
    uint32 max_part_no;  // the part no of  max rows num  part
    cbo_max_subpart_t max_subpart_info;

    uint32 rows;
    uint32 blocks;        // The total number of data blocks occupied by the table
    uint32 empty_blocks;  // The total number of empty blocks occupied by the table
    uint64 avg_row_len;   // Table average row length (bytes)
    uint32 sample_size;
    date_t analyse_time;

    uint32 column_count;            /* column count */
    cbo_stats_column_t ***columns;  // column statistics informations (segement array)  64*64 = 4096
    uint32 max_col_id;
    uint32 **col_map;  // for column id -> position

    uint32 index_count;
    cbo_stats_index_t **indexs;
    cbo_table_part_group_t **part_groups;    // part statistics in global table, it's effect in global statistics
    cbo_table_part_group_t **subpart_groups; // sub part statistics in global table, it's effect in global statistics
    
    struct st_cbo_stats_table *tab_part_default;
    volatile uint32 stats_version;
    volatile bool8  is_ready;
    bool8 global_stats_exist;
    volatile bool32 col_stats_allowed;
    volatile bool32 col_loading;
    part_group_t part_group;
} cbo_stats_table_t;

typedef struct st_cbo_hists_assist {
    uint32 endpoint;
    uint32 len;
    char   buckets[STATS_MAX_BUCKET_SIZE];
}cbo_hists_assist_t;

status_t cbo_load_entity_statistics(knl_session_t *session, dc_entity_t *entity, stats_load_info_t load_info);
status_t cbo_refresh_statistics(knl_session_t *session, dc_entity_t *entity, stats_load_info_t load_info);
status_t cbo_alloc_temp_table_stats(knl_session_t *session, dc_entity_t *entity, knl_temp_cache_t *temp_cache, bool32 is_dynamic);
void cbo_load_tmptab_table_stats(cbo_stats_table_t *stats, stats_table_t *stats_table, knl_dictionary_t *dc);
void cbo_load_tmptab_index_stats(cbo_stats_table_t *stats, stats_index_t *stats_idx);
status_t cbo_load_tmptab_column_stats(knl_session_t *session, dc_entity_t *entity, cbo_stats_table_t *stats,
                                      stats_col_handler_t *stats_col);
status_t cbo_load_tmptab_histgram(knl_session_t *session, dc_entity_t *entity, cbo_stats_table_t *stats,
                                  stats_col_handler_t *stats_col);

cbo_stats_table_t *knl_get_cbo_table(knl_handle_t session, dc_entity_t *entity);
cbo_stats_column_t *knl_get_cbo_column(knl_handle_t session, dc_entity_t *entity, uint32 col_id);
cbo_stats_index_t *knl_get_cbo_index(knl_handle_t session, dc_entity_t *entity, uint32 index_id);
cbo_stats_column_t *cbo_get_column_stats(cbo_stats_table_t *table_stats, uint32 col_id);


// functions to retrieve partition table statistics
cbo_stats_table_t *knl_get_cbo_part_table(knl_handle_t handle, dc_entity_t *entity, uint32 part_no);
cbo_stats_column_t *knl_get_cbo_part_column(knl_handle_t handle, dc_entity_t *entity, uint32 part_no, uint32 col_id);
cbo_stats_index_t *knl_get_cbo_part_index(knl_handle_t handle, dc_entity_t *entity, uint32 part_no, uint32 index_id);
status_t cbo_load_interval_index_part(knl_session_t *session, dc_entity_t *entity, uint32 idx_slot,
                                      uint32 part_no);
status_t cbo_load_interval_table_part(knl_session_t *session, dc_entity_t *entity, uint32 part_no);
status_t cbo_load_index_part_stats(knl_session_t *session, dc_entity_t *entity, uint32 part_no, uint32 index_id);
status_t cbo_load_table_part_stats(knl_session_t *session, dc_entity_t *entity, uint32 part_no,
    stats_load_info_t load_info, bool32 load_columns);
stats_table_mon_t *knl_cbo_get_table_mon(knl_handle_t session, dc_entity_t *entity);

cbo_stats_column_t *knl_get_cbo_subpart_column(knl_handle_t handle, dc_entity_t *entity, uint32 part_no, uint32 col_id,
                                               uint32 subpart_no);
cbo_stats_table_t *knl_get_cbo_subpart_table(knl_handle_t handle, dc_entity_t *entity, uint32 part_no, uint32 subpart_no);
cbo_stats_index_t *knl_get_cbo_subpart_index(knl_handle_t handle, dc_entity_t *entity, uint32 part_no, uint32 index_id,
                                             uint32 sub_part_no);

static inline uint32 knl_get_part_count(const dc_entity_t *entity)
{
    return entity->table.part_table->desc.partcnt;
}

// get max rows partition of table
static inline uint32 knl_get_max_rows_part(const dc_entity_t *entity)
{
    cbo_stats_table_t *cbo_stats = entity->cbo_table_stats;

    if (cbo_stats != NULL) {
        return cbo_stats->max_part_no;
    }

    return 0;
}

// get max rows sub partition of table
static inline cbo_max_subpart_t knl_get_max_rows_subpart(const dc_entity_t *entity)
{
    cbo_stats_table_t *cbo_stats = entity->cbo_table_stats;
    return cbo_stats->max_subpart_info;
}

void knl_cbo_text2variant(dc_entity_t *entity, uint32 col_id, text_t *column, variant_t *ret_val);

void knl_cache_cbo_text2variant(dc_entity_t *entity, uint32 col_id, text_t *column, cache_variant_t *ret_val);

#ifdef __cplusplus
}
#endif

#endif
