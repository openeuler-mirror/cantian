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

static void fill_cbo_stats_column(cbo_stats_column_t *cbo_column, tse_cbo_stats_column_t *tse_column, uint32 col_id,
                                  dc_entity_t *entity)
{
    tse_column->total_rows = cbo_column->total_rows;
    tse_column->num_buckets = cbo_column->num_buckets;
    tse_column->num_distinct = cbo_column->num_distinct;
    tse_column->num_null = cbo_column->num_null;
    tse_column->density = cbo_column->density;
    tse_column->hist_type = cbo_column->hist_type;
    tse_column->hist_count = cbo_column->hist_count;
    knl_cache_cbo_text2variant(entity, col_id, &cbo_column->high_value, &tse_column->high_value);
    knl_cache_cbo_text2variant(entity, col_id, &cbo_column->low_value, &tse_column->low_value);
    for (int i = 0; i < cbo_column->hist_count; i++) {
        tse_column->column_hist[i].ep_number = cbo_column->column_hist[i]->ep_number;
        knl_cache_cbo_text2variant(entity,
                                   col_id, &cbo_column->column_hist[i]->ep_value, &tse_column->column_hist[i].ep_value);
    }
}

static void fill_cbo_stats_table_t(knl_handle_t handle, dc_entity_t *entity, tianchi_cbo_stats_t *stats,
                                   cbo_stats_table_t *table_stats)
{
    for (uint32 col_id = 0; col_id <= table_stats->max_col_id; col_id++) {
        cbo_stats_column_t *column = knl_get_cbo_column(handle, entity, col_id);
        if (column != NULL) {
            fill_cbo_stats_column(column, &stats->tse_cbo_stats_table.columns[col_id], col_id, entity);
        } else {
            stats->tse_cbo_stats_table.columns[col_id].total_rows = 0;
        }
    }
}

static void fill_part_table_cbo_stats_table_t(knl_handle_t handle, dc_entity_t *entity, tianchi_cbo_stats_t *stats,
                                              cbo_stats_table_t *table_stats, uint32 stats_idx)
{
    stats->tse_cbo_stats_part_table[stats_idx].estimate_rows = table_stats->rows;
    uint32 total_parts_cnt = knl_get_part_count(entity);
    for (uint32 col_id = 0; col_id <= table_stats->max_col_id; col_id++) {
        cbo_stats_column_t *column = knl_get_cbo_part_column(handle, entity, stats_idx + stats->first_partid, col_id);
        if (column != NULL) {
            fill_cbo_stats_column(column, &stats->tse_cbo_stats_part_table[stats_idx].columns[col_id], col_id, entity);
        } else {
            stats->tse_cbo_stats_part_table[stats_idx].columns[col_id].total_rows = 0;
        }
    }
}

static void fill_sub_part_table_cbo_stats_table_t(knl_handle_t handle, dc_entity_t *entity, tianchi_cbo_stats_t *stats,
                                                  cbo_stats_table_t *table_stats, uint32 part_id, uint32 subpart_id,
                                                  uint32 stats_idx)
{
    stats->tse_cbo_stats_part_table[stats_idx].estimate_rows = table_stats->rows;
    for (uint32 col_id = 0; col_id <= table_stats->max_col_id; col_id++) {
        cbo_stats_column_t *column = knl_get_cbo_subpart_column(handle, entity, part_id, col_id, subpart_id);
        if (column != NULL) {
            fill_cbo_stats_column(column, &stats->tse_cbo_stats_part_table[stats_idx].columns[col_id], col_id, entity);
        } else {
            stats->tse_cbo_stats_part_table[stats_idx].columns[col_id].total_rows = 0;
        }
    }
}

void get_cbo_stats(knl_handle_t handle, dc_entity_t *entity, tianchi_cbo_stats_t *stats)
{
    cbo_stats_table_t *table_stats = NULL;
    if (!knl_is_part_table(entity)) {
        table_stats = knl_get_cbo_table(handle, entity);
        if (table_stats != NULL && table_stats->is_ready) {
            stats->tse_cbo_stats_table.estimate_rows = table_stats->rows;
            stats->is_updated = CT_TRUE;
            fill_cbo_stats_table_t(handle, entity, stats, table_stats);
        } else {
            stats->tse_cbo_stats_table.estimate_rows = 0;
        }
    } else if (!knl_is_compart_table(entity)){
        for (uint32 i = 0; i < stats->num_part_fetch; i++) {
            table_stats = knl_get_cbo_part_table(handle, entity, i + stats->first_partid);
            if (table_stats != NULL) {
                stats->is_updated = CT_TRUE;
                fill_part_table_cbo_stats_table_t(handle, entity, stats, table_stats, i);
            } else {
                stats->tse_cbo_stats_part_table[i].estimate_rows = 0;
            }
        }
    } else {
        uint32 subpart_cnt = entity->table.part_table->desc.subpart_cnt;
        for (uint32 i = 0; i < stats->num_part_fetch; i++) {
            uint32 part_id = (i + stats->first_partid) / subpart_cnt;
            uint32 subpart_id = (i + stats->first_partid) % subpart_cnt;
            table_stats = knl_get_cbo_subpart_table(handle, entity, part_id, subpart_id);
            if (table_stats != NULL) {
                stats->is_updated = CT_TRUE;
                fill_sub_part_table_cbo_stats_table_t(handle, entity, stats, table_stats, part_id, subpart_id, i);
            } else {
                stats->tse_cbo_stats_part_table[i].estimate_rows = 0;
            }
        }
    }
}
