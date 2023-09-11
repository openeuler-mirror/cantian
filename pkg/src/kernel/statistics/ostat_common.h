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
 * ostat_common.h
 *
 *
 * IDENTIFICATION
 * src/kernel/statistics/ostat_common.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __OSTAT_COMMON_H__
#define __OSTAT_COMMON_H__

#include "knl_context.h"
#include "knl_table.h"
#include "ostat_load.h"

#ifdef __cplusplus
extern "C" {
#endif
status_t cbo_alloc_subpart_table_group(knl_session_t *session, dc_entity_t *entity, cbo_stats_table_t *table_stats,
    uint32 gid);
status_t cbo_alloc_part_table_group(knl_session_t *session, dc_entity_t *entity, cbo_stats_table_t *table_stats,
    uint32 gid);
status_t cbo_alloc_subpart_index_group(knl_session_t *session, dc_entity_t *entity, cbo_stats_index_t *index_stats,
    uint32 gid);
status_t cbo_alloc_part_index_group(knl_session_t *session, dc_entity_t *entity, cbo_stats_index_t *index_stats,
    uint32 gid);
void cbo_find_max_subpart(dc_entity_t *entity);
status_t cbo_prepare_load_columns(knl_session_t *session, dc_entity_t *entity, cbo_stats_table_t *cbo_stats);
status_t cbo_set_sub_histgrams(knl_session_t *session, dc_entity_t *entity, uint32 count,
    cbo_stats_column_t *stats, cbo_hists_assist_t *cbo_hists);
status_t cbo_precheck_index_subpart(knl_session_t *session, dc_entity_t *entity, uint32 part_no,
    index_t *idx, uint32 subpart_no);
void cbo_set_histgram_scan_key(knl_cursor_t *cursor, table_t *table, uint32 cid, uint32 part_id);
status_t cbo_set_columns_stats(knl_session_t *session, dc_entity_t *entity, cbo_stats_table_t *cbo_stats);
void cbo_set_max_row_part(cbo_stats_table_t  *table_stats, cbo_stats_table_t *part_stats, uint32 part_no);
cbo_stats_index_t *cbo_find_indexpart_stats(cbo_stats_table_t *cbo_stats, uint32 index_id, uint32 part_no,
    bool32 *need_load);
uint32 cbo_get_column_alloc_size(knl_column_t *column);
status_t cbo_alloc_value_mem(knl_session_t *session, memory_context_t *memory, knl_column_t *column, char **buf);
status_t cbo_get_stats_values(dc_entity_t *entity, knl_column_t *column, text_t *v_input, text_t *v_output);
status_t cbo_alloc_table_part_default(knl_session_t *session, dc_entity_t *entity,
    cbo_stats_table_t *table_stats, uint32 id);
status_t cbo_alloc_table_part_stats(knl_session_t *session, dc_entity_t *entity,
    cbo_stats_table_t *table_stats, uint32 id);
status_t cbo_alloc_index_part_default(knl_session_t *session, dc_entity_t *entity,
    cbo_stats_index_t *index_stats, uint32 id);
status_t cbo_alloc_index_part_stats(knl_session_t *session, dc_entity_t *entity,
    cbo_stats_index_t *index_stats, uint32 id);
status_t cbo_alloc_index_subpart_stats(knl_session_t *session, dc_entity_t *entity, index_t *index,
                                       cbo_stats_index_t *idx_stats, index_part_t *index_part);
void cbo_hists_sort(cbo_hists_assist_t *hists, uint32 buckets);
uint32 cbo_get_part_group_count(uint32 part_cnt);
cbo_stats_table_t *cbo_get_table_part_stats(cbo_stats_table_t *cbo_stats, uint32 id);
cbo_stats_table_t *cbo_get_sub_part_stats(cbo_stats_table_t *cbo_stats, uint32 id);
cbo_stats_index_t *cbo_find_sub_index_stats(dc_entity_t *entity, uint32 idx_id, uint32 part_no, uint32 sub_no,
    bool32 *need_load);

static inline void set_cbo_col_map(cbo_stats_table_t *stats_table, uint32 col_id, uint32 pos)
{
    stats_table->col_map[col_id / CBO_LIST_COUNT][col_id % CBO_LIST_COUNT] = pos;
}

static inline uint32 get_cbo_col_map(cbo_stats_table_t *stats_table, uint32 col_id)
{
    if (stats_table->col_map == NULL) {
        return CBO_INVALID_COLUMN_ID;
    }
    return stats_table->col_map[col_id / CBO_LIST_COUNT][col_id % CBO_LIST_COUNT];
}

static inline void set_cbo_stats_column(cbo_stats_table_t *stats_table, cbo_stats_column_t *stats_column,
    uint32 pos)
{
    stats_table->columns[pos / CBO_LIST_COUNT][pos % CBO_LIST_COUNT] = stats_column;
}

static inline cbo_stats_column_t *get_cbo_stats_column(cbo_stats_table_t *stats_table, uint32 pos)
{
    return stats_table->columns[pos / CBO_LIST_COUNT][pos % CBO_LIST_COUNT];
}

#ifdef __cplusplus
}
#endif

#endif

