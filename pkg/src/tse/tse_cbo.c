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
 * tse_cbo.c
 *
 *
 * IDENTIFICATION
 * src/tse/tse_cbo.c
 *
 * -------------------------------------------------------------------------
 */

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

static void fill_cbo_stats_table_t(knl_handle_t handle, dc_entity_t *entity, tianchi_cbo_stats_t *stats,
                                   cbo_stats_table_t *table_stats)
{
    for (uint32 col_id = 0; col_id <= table_stats->max_col_id; col_id++) {
        cbo_stats_column_t *column = knl_get_cbo_column(handle, entity, col_id);
        // 字段类型为 text 类型时，column 字段为空
        if (column != NULL) {
            *(stats->tse_cbo_stats_table.num_distincts + col_id) = column->num_distinct;
            knl_cache_cbo_text2variant(entity, col_id, &column->low_value,
                                       stats->tse_cbo_stats_table.low_values + col_id);
            knl_cache_cbo_text2variant(entity, col_id, &column->high_value,
                                       stats->tse_cbo_stats_table.high_values + col_id);
        } else {
            *(stats->tse_cbo_stats_table.num_distincts + col_id) = 0;
        }
    }
}

static void fill_part_table_cbo_stats_table_t(knl_handle_t handle, dc_entity_t *entity, tianchi_cbo_stats_t *stats,
                                              cbo_stats_table_t *table_stats, uint32 part_id)
{
    uint32 total_parts_cnt = knl_get_part_count(entity);
    for (uint32 col_id = 0; col_id <= table_stats->max_col_id; col_id++) {
        cbo_stats_column_t *column = knl_get_cbo_part_column(handle, entity, part_id, col_id);
        uint32 index_no = total_parts_cnt  * col_id + part_id;
        // 字段类型为 text 类型时，column 字段为空
        if (column != NULL) {
            stats->tse_cbo_stats_table.part_table_num_distincts[index_no] = column->num_distinct;
            knl_cache_cbo_text2variant(entity, col_id, &column->low_value,
                                       &(stats->tse_cbo_stats_table.part_table_low_values[index_no]));
            knl_cache_cbo_text2variant(entity, col_id, &column->high_value,
                                       &(stats->tse_cbo_stats_table.part_table_high_values[index_no]));
        } else {
            stats->tse_cbo_stats_table.part_table_num_distincts[index_no] = 0;
        }
    }
}

void get_cbo_stats(knl_handle_t handle, dc_entity_t *entity, tianchi_cbo_stats_t *stats)
{
    cbo_stats_table_t *table_stats = NULL;
    if (!knl_is_part_table(entity)) {
        table_stats = knl_get_cbo_table(handle, entity);
        if (table_stats != NULL && table_stats->is_ready) {
            stats->estimate_rows = table_stats->rows;
            stats->estimate_blocks = table_stats->blocks;
            stats->is_updated = GS_TRUE;
            fill_cbo_stats_table_t(handle, entity, stats, table_stats);
        }
    } else {
        uint32 total_parts_cnt = knl_get_part_count(entity);
        for (uint32 part_id = 0; part_id < total_parts_cnt; ++part_id) {
            table_stats = knl_get_cbo_part_table(handle, entity, part_id);
            if (table_stats != NULL) {
                uint32_t row_no = part_id;
                uint32_t block_no = part_id + total_parts_cnt;
                stats->estimate_part_rows_and_blocks[row_no] = table_stats->rows;
                stats->estimate_part_rows_and_blocks[block_no] = table_stats->blocks;
                stats->tse_cbo_stats_table.max_part_no = table_stats->max_part_no;
                stats->is_updated = GS_TRUE;
                fill_part_table_cbo_stats_table_t(handle, entity, stats, table_stats, part_id);
            }
        }
    }
}
