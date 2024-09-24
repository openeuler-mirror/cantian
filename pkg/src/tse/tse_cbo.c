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
 * tse_cbo.c
 *
 *
 * IDENTIFICATION
 * src/tse/tse_cbo.c
 *
 * -------------------------------------------------------------------------
 */
#include "tse_module.h"
#include "tse_cbo.h"
#include "tse_srv_util.h"
#include "var_opr.h"

static inline cbo_stats_column_t *get_cbo_column(knl_handle_t handle, dc_entity_t *entity,
                                                 uint32 part_id, uint32 col_id)
{
    if (IS_TSE_PART(part_id)) {
        return knl_get_cbo_part_column(handle, entity, part_id, col_id);
    }
    return knl_get_cbo_column(handle, entity, col_id);
}

static inline cbo_stats_table_t *get_cbo_table(knl_handle_t handle, dc_entity_t *entity, uint32 part_id)
{
    if (IS_TSE_PART(part_id)) {
        return knl_get_cbo_part_table(handle, entity, part_id);
    }
    return knl_get_cbo_table(handle, entity);
}

status_t fill_cbo_stats_column(cbo_stats_column_t *cbo_column, tse_cbo_stats_column_t *tse_column, uint32 col_id,
                               dc_entity_t *entity)
{
    status_t ret = CT_SUCCESS;
    SYNC_POINT_GLOBAL_START(TSE_FILL_CBO_STATS_COL_FAIL, &ret, CT_ERROR);
    SYNC_POINT_GLOBAL_END;
    if (cbo_column == NULL) {
        return ret;
    }
    tse_column->num_null = cbo_column->num_null;
    tse_column->density = cbo_column->density;
    tse_column->hist_type = cbo_column->hist_type;
    tse_column->hist_count = cbo_column->hist_count;
    cm_assert(cbo_column->hist_count <= HIST_COUNT);
    knl_cache_cbo_text2variant(entity, col_id, &cbo_column->high_value, &tse_column->high_value);
    knl_cache_cbo_text2variant(entity, col_id, &cbo_column->low_value, &tse_column->low_value);
    for (int i = 0; i < cbo_column->hist_count; i++) {
        tse_column->column_hist[i].ep_number = cbo_column->column_hist[i]->ep_number;
        knl_cache_cbo_text2variant(entity,
                                   col_id, &cbo_column->column_hist[i]->ep_value, &tse_column->column_hist[i].ep_value);
    }
    return ret;
}

status_t fill_cbo_stats_index(cbo_stats_index_t *index, uint32_t *ndv_keys, uint32 idx_id)
{
    status_t ret = CT_SUCCESS;
    SYNC_POINT_GLOBAL_START(TSE_FILL_CBO_STATS_INDEX_FAIL, &ret, CT_ERROR);
    SYNC_POINT_GLOBAL_END;
    uint32_t *ndv_index_keys = ndv_keys + (idx_id * MAX_KEY_COLUMNS);
    for (uint32_t i = 0; i < MAX_KEY_COLUMNS; i++) {
        if (index != NULL) {
            ndv_index_keys[i] = i > 0 ? ndv_index_keys[i - 1] + index->distinct_keys_arr[i]:
                                        index->distinct_keys_arr[0];
        } else {
            ndv_index_keys[i] = 0;
        }
    }
    return ret;
}

status_t fill_cbo_stats_table_t(knl_handle_t handle, dc_entity_t *entity, tianchi_cbo_stats_t *stats,
                                cbo_stats_table_t *table_stats, tse_cbo_stats_table_t *tse_cbo_stats_table)
{
    for (uint32 col_id = 0; col_id <= table_stats->max_col_id; col_id++) {
        cbo_stats_column_t *column = knl_get_cbo_column(handle, entity, col_id);
        if (fill_cbo_stats_column(column, &tse_cbo_stats_table->columns[col_id], col_id, entity) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    for (uint32 idx_id = 0; idx_id < entity->table.desc.index_count; idx_id++) {
        cbo_stats_index_t *index = knl_get_cbo_index(handle, entity, idx_id);
        if (fill_cbo_stats_index(index, stats->ndv_keys, idx_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t fill_part_table_cbo_stats_table_t(knl_handle_t handle, dc_entity_t *entity, tse_cbo_stats_table_t *tse_cbo_stats_table,
                                           cbo_stats_table_t *table_stats, uint32 part_id, uint32 stats_idx)
{
    tse_cbo_stats_table[stats_idx].estimate_rows = table_stats->rows;
    for (uint32 col_id = 0; col_id <= table_stats->max_col_id; col_id++) {
        cbo_stats_column_t *column = knl_get_cbo_part_column(handle, entity, part_id, col_id);
        if (fill_cbo_stats_column(column, &tse_cbo_stats_table[stats_idx].columns[col_id], col_id, entity) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t fill_sub_part_table_cbo_stats_table_t(knl_handle_t handle, dc_entity_t *entity, tse_cbo_stats_table_t *tse_cbo_stats_table,
                                               cbo_stats_table_t *table_stats, uint32 part_id, uint32 subpart_id,
                                               uint32 stats_idx)
{
    tse_cbo_stats_table[stats_idx].estimate_rows = table_stats->rows;
    for (uint32 col_id = 0; col_id <= table_stats->max_col_id; col_id++) {
        cbo_stats_column_t *column = knl_get_cbo_subpart_column(handle, entity, part_id, col_id, subpart_id);
        if (fill_cbo_stats_column(column, &tse_cbo_stats_table[stats_idx].columns[col_id], col_id, entity) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t fill_part_table_cbo_stats_index(knl_handle_t handle, dc_entity_t *entity, tianchi_cbo_stats_t *stats)
{
    cbo_stats_index_t *index = NULL;
    for (uint32 idx_id = 0; idx_id < entity->table.desc.index_count; idx_id++) {
        index = entity->cbo_table_stats->indexs[idx_id];
        if (fill_cbo_stats_index(index, stats->ndv_keys, idx_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

status_t get_cbo_stats(knl_handle_t handle, dc_entity_t *entity, tianchi_cbo_stats_t *stats, tse_cbo_stats_table_t *tse_cbo_stats_table, uint32_t first_partid, uint32_t num_part_fetch)
{
    status_t ret = CT_SUCCESS;
    cbo_stats_table_t *table_stats = NULL;
    tse_cbo_stats_table->estimate_rows = 0;
    stats->records = 0;
    uint32 max_part_no = 0;
    uint32 max_sub_part_no = 0;
    if (!knl_is_part_table(entity)) {
        table_stats = knl_get_cbo_table(handle, entity);
        if (table_stats != NULL && table_stats->is_ready && STATS_GLOBAL_CBO_STATS_EXIST(entity)) {
            tse_cbo_stats_table->estimate_rows = table_stats->rows;
            stats->records = table_stats->rows;
            stats->is_updated = CT_TRUE;
            ret = fill_cbo_stats_table_t(handle, entity, stats, table_stats, tse_cbo_stats_table);
        }
    } else if (!knl_is_compart_table(entity)){
        if (fill_part_table_cbo_stats_index(handle, entity, stats) != CT_SUCCESS) {
            return CT_ERROR;
        }
        for (uint32 i = 0; i < num_part_fetch; i++) {
            table_stats = knl_get_cbo_part_table(handle, entity, i + first_partid);
            if (table_stats != NULL) {
                stats->is_updated = CT_TRUE;
                if (fill_part_table_cbo_stats_table_t(handle, entity, tse_cbo_stats_table, table_stats, i + first_partid, i) != CT_SUCCESS) {
                    return CT_ERROR;
                }
                max_part_no = table_stats->max_part_no;
            } else {
                tse_cbo_stats_table[i].estimate_rows = 0;
            }
        }
        table_stats = knl_get_cbo_part_table(handle, entity, max_part_no);
        if (table_stats != NULL) {
            stats->records = table_stats->rows; // the biggest part, with max rows num 
        } else {
            stats->records = 0;
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
                if (fill_sub_part_table_cbo_stats_table_t(handle, entity, tse_cbo_stats_table, table_stats, part_id, subpart_id, i) != CT_SUCCESS) {
                    return CT_ERROR;
                }
                max_part_no = table_stats->max_subpart_info.part_no;
                max_sub_part_no = table_stats->max_subpart_info.subpart_no;
            } else {
                tse_cbo_stats_table[i].estimate_rows = 0;
            }
        }
        table_stats = knl_get_cbo_subpart_table(handle, entity, max_part_no, max_sub_part_no);
        if (table_stats != NULL) {
            stats->records = table_stats->rows; // the biggest subpart, with max rows num 
        } else {
            stats->records = 0;
        }
    }
    return ret;
}
