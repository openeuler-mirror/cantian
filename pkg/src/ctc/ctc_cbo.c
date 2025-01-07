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
 * ctc_cbo.c
 *
 *
 * IDENTIFICATION
 * src/ctc/ctc_cbo.c
 *
 * -------------------------------------------------------------------------
 */
#include "ctc_module.h"
#include "ctc_cbo.h"
#include "ctc_srv_util.h"
#include "var_opr.h"

static inline cbo_stats_column_t *get_cbo_column(knl_handle_t handle, dc_entity_t *entity,
                                                 uint32 part_id, uint32 col_id)
{
    if (IS_CTC_PART(part_id)) {
        return knl_get_cbo_part_column(handle, entity, part_id, col_id);
    }
    return knl_get_cbo_column(handle, entity, col_id);
}

static inline cbo_stats_table_t *get_cbo_table(knl_handle_t handle, dc_entity_t *entity, uint32 part_id)
{
    if (IS_CTC_PART(part_id)) {
        return knl_get_cbo_part_table(handle, entity, part_id);
    }
    return knl_get_cbo_table(handle, entity);
}

status_t fill_cbo_stats_column(cbo_stats_column_t *cbo_column, ctc_cbo_stats_column_t *ctc_column, uint32 col_id,
                               dc_entity_t *entity)
{
    status_t ret = CT_SUCCESS;
    SYNC_POINT_GLOBAL_START(CTC_FILL_CBO_STATS_COL_FAIL, &ret, CT_ERROR);
    SYNC_POINT_GLOBAL_END;
    if (cbo_column == NULL) {
        return ret;
    }
    ctc_column->num_null = cbo_column->num_null;
    ctc_column->density = cbo_column->density;
    ctc_column->hist_type = cbo_column->hist_type;
    ctc_column->hist_count = cbo_column->hist_count;
    cm_assert(cbo_column->hist_count <= HIST_COUNT);
    knl_cache_cbo_text2variant(entity, col_id, &cbo_column->high_value, &ctc_column->high_value);
    knl_cache_cbo_text2variant(entity, col_id, &cbo_column->low_value, &ctc_column->low_value);
    for (int i = 0; i < cbo_column->hist_count; i++) {
        ctc_column->column_hist[i].ep_number = cbo_column->column_hist[i]->ep_number;
        knl_cache_cbo_text2variant(entity,
                                   col_id, &cbo_column->column_hist[i]->ep_value, &ctc_column->column_hist[i].ep_value);
    }
    return ret;
}

void fill_cbo_stats_index(cbo_stats_index_t *index_cbo, cbo_stats_column_t *col_stats , uint32_t *ndv_keys)
{
    // The pre-four-columns cardinality of index is persisited, but other columns is not. 
    // The cardinality of the first column is not persisted in the index statistics, 
    // so the first column uses the num_distinct in the cbo_column.
    if (index_cbo == NULL) {
        memset(ndv_keys, 0, sizeof(uint32_t) * MAX_KEY_COLUMNS);
        return;
    }
    ndv_keys[0] = (col_stats == NULL) ? 0 : col_stats->num_distinct;
    ndv_keys[1] = index_cbo->comb_cols_2_ndv;
    ndv_keys[2] = index_cbo->comb_cols_3_ndv;
    ndv_keys[3] = index_cbo->comb_cols_4_ndv;
    for (uint32_t i = MAX_PERSIST_INDEX_CBO_COLUMES; i < MAX_KEY_COLUMNS; i++) {
        ndv_keys[i] = index_cbo->distinct_keys_arr[i] + ndv_keys[i - i];
    }
}

status_t fill_cbo_stats_table_t(knl_handle_t handle, dc_entity_t *entity, ctc_cbo_stats_t *stats,
                                cbo_stats_table_t *table_stats, ctc_cbo_stats_table_t *ctc_cbo_stats_table)
{
    for (uint32 col_id = 0; col_id <= table_stats->max_col_id; col_id++) {
        cbo_stats_column_t *column = knl_get_cbo_column(handle, entity, col_id);
        if (fill_cbo_stats_column(column, &ctc_cbo_stats_table->columns[col_id], col_id, entity) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    for (uint32 idx_id = 0; idx_id < entity->table.desc.index_count; idx_id++) {
        cbo_stats_index_t *index_cbo = knl_get_cbo_index(handle, entity, idx_id);
        uint32_t *ndv_index_keys = stats->ndv_keys + (idx_id * MAX_KEY_COLUMNS);
        index_t *index = entity->table.index_set.items[idx_id];
        cbo_stats_column_t *col_stats = knl_get_cbo_column(handle, entity, index->desc.columns[0]);
        fill_cbo_stats_index(index_cbo, col_stats, ndv_index_keys);
    }
    return CT_SUCCESS;
}

status_t fill_part_table_cbo_stats_table_t(knl_handle_t handle, dc_entity_t *entity, ctc_cbo_stats_table_t *ctc_cbo_stats_table,
                                           cbo_stats_table_t *table_stats, uint32 part_id, uint32 stats_idx)
{
    ctc_cbo_stats_table[stats_idx].estimate_rows = table_stats->rows;
    for (uint32 col_id = 0; col_id <= table_stats->max_col_id; col_id++) {
        cbo_stats_column_t *column = knl_get_cbo_part_column(handle, entity, part_id, col_id);
        if (fill_cbo_stats_column(column, &ctc_cbo_stats_table[stats_idx].columns[col_id], col_id, entity) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t fill_sub_part_table_cbo_stats_table_t(knl_handle_t handle, dc_entity_t *entity, ctc_cbo_stats_table_t *ctc_cbo_stats_table,
                                               cbo_stats_table_t *table_stats, uint32 part_id, uint32 subpart_id,
                                               uint32 stats_idx)
{
    ctc_cbo_stats_table[stats_idx].estimate_rows = table_stats->rows;
    for (uint32 col_id = 0; col_id <= table_stats->max_col_id; col_id++) {
        cbo_stats_column_t *column = knl_get_cbo_subpart_column(handle, entity, part_id, col_id, subpart_id);
        if (fill_cbo_stats_column(column, &ctc_cbo_stats_table[stats_idx].columns[col_id], col_id, entity) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t fill_part_table_cbo_stats_index(knl_handle_t handle, dc_entity_t *entity, ctc_cbo_stats_t *stats)
{
    cbo_stats_index_t *index_cbo = NULL;
    for (uint32 idx_id = 0; idx_id < entity->table.desc.index_count; idx_id++) {
        index_cbo = entity->cbo_table_stats->indexs[idx_id];
        uint32_t *ndv_index_keys = stats->ndv_keys + (idx_id * MAX_KEY_COLUMNS);
        index_t *index = entity->table.index_set.items[idx_id];
        cbo_stats_column_t *col_stats = knl_get_cbo_column(handle, entity, index->desc.columns[0]);
        fill_cbo_stats_index(index_cbo, col_stats, ndv_index_keys);
    }
    return CT_SUCCESS;
}

status_t get_cbo_stats(knl_handle_t handle, dc_entity_t *entity, ctc_cbo_stats_t *stats, ctc_cbo_stats_table_t *ctc_cbo_stats_table, uint32_t first_partid, uint32_t num_part_fetch)
{
    status_t ret = CT_SUCCESS;
    cbo_stats_table_t *table_stats = NULL;
    ctc_cbo_stats_table->estimate_rows = 0;
    stats->records = 0;
    uint32 max_part_no = 0;
    uint32 max_sub_part_no = 0;
    if (!knl_is_part_table(entity)) {
        table_stats = knl_get_cbo_table(handle, entity);
        if (table_stats != NULL && table_stats->is_ready && STATS_GLOBAL_CBO_STATS_EXIST(entity)) {
            ctc_cbo_stats_table->estimate_rows = table_stats->rows;
            stats->records = table_stats->rows;
            stats->is_updated = CT_TRUE;
            ret = fill_cbo_stats_table_t(handle, entity, stats, table_stats, ctc_cbo_stats_table);
        }
    } else if (!knl_is_compart_table(entity)){
        if (fill_part_table_cbo_stats_index(handle, entity, stats) != CT_SUCCESS) {
            return CT_ERROR;
        }
        for (uint32 i = 0; i < num_part_fetch; i++) {
            table_stats = knl_get_cbo_part_table(handle, entity, i + first_partid);
            if (table_stats != NULL) {
                stats->is_updated = CT_TRUE;
                if (fill_part_table_cbo_stats_table_t(handle, entity, ctc_cbo_stats_table, table_stats, i + first_partid, i) != CT_SUCCESS) {
                    return CT_ERROR;
                }
                max_part_no = table_stats->max_part_no;
            } else {
                ctc_cbo_stats_table[i].estimate_rows = 0;
            }
            stats->records += ctc_cbo_stats_table[i].estimate_rows;
        }
    } else {
        if (fill_part_table_cbo_stats_index(handle, entity, stats) != CT_SUCCESS) {
            return CT_ERROR;
        }
        uint32 subpart_cnt = knl_subpart_count((handle_t)entity, 0);
        for (uint32 i = 0; i < num_part_fetch; i++) {
            uint32 part_id = (i + first_partid) / subpart_cnt;
            uint32 subpart_id = (i + first_partid) % subpart_cnt;
            table_stats = knl_get_cbo_subpart_table(handle, entity, part_id, subpart_id);
            if (table_stats != NULL) {
                stats->is_updated = CT_TRUE;
                if (fill_sub_part_table_cbo_stats_table_t(handle, entity, ctc_cbo_stats_table, table_stats, part_id, subpart_id, i) != CT_SUCCESS) {
                    return CT_ERROR;
                }
                max_part_no = table_stats->max_subpart_info.part_no;
                max_sub_part_no = table_stats->max_subpart_info.subpart_no;
            } else {
                ctc_cbo_stats_table[i].estimate_rows = 0;
            }
            stats->records += ctc_cbo_stats_table[i].estimate_rows;
        }
    }
    return ret;
}