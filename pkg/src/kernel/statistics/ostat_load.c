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
 * ostat_load.c
 *
 *
 * IDENTIFICATION
 * src/kernel/statistics/ostat_load.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_common_module.h"
#include "ostat_load.h"
#include "cm_decimal.h"
#include "ostat_common.h"
#include "knl_sys_part_defs.h"

// function implement
static status_t cbo_load_table_columns_stats(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity);
static status_t cbo_load_table_indexs_stats(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity);
static status_t cbo_load_part_table_stats(knl_session_t *session, dc_entity_t *entity, stats_load_info_t load_info);
static status_t cbo_alloc_part_index_stats(knl_session_t *session, dc_entity_t *entity, cbo_stats_index_t *stats,
                                           uint32 pos);
status_t cbo_load_index_part_stats(knl_session_t *session, dc_entity_t *entity, uint32 part_no, uint32 index_id);
status_t cbo_load_table_part_stats(knl_session_t *session, dc_entity_t *entity, uint32 part_no, stats_load_info_t load_info, bool32 load_columns);

status_t cbo_load_interval_table_part(knl_session_t *session, dc_entity_t *entity, uint32 part_no)
{
    if (!entity->stat_exists) {
        return CT_SUCCESS;
    }

    cbo_stats_table_t *table_stats = entity->cbo_table_stats;

    if (table_stats == NULL || table_stats->part_groups == NULL) {
        return CT_SUCCESS;
    }

    if (cbo_alloc_table_part_default(session, entity, table_stats, part_no) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t cbo_load_table_defaut_stats(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity,
    stats_load_info_t load_info)
{
    table_t *table = &entity->table;
    memory_context_t *memory = entity->memory;
    cbo_stats_table_t *stats = NULL;
    errno_t ret;

    stats = entity->cbo_table_stats;
    if (stats == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, memory, sizeof(cbo_stats_table_t), (void **)&stats) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        ret = memset_sp(stats, sizeof(cbo_stats_table_t), 0, sizeof(cbo_stats_table_t));
        knl_securec_check(ret);
    } else {
        stats->analyse_time = 0;
        stats->avg_row_len = 0;
        stats->blocks = 0;
        stats->empty_blocks = 0;
        stats->rows = 0;
        stats->sample_size = 0;
        stats->max_col_id = CT_INVALID_ID32;
        stats->global_stats_exist = CT_FALSE;
    }

    stats->table_id = entity->table.desc.id;
    stats->part_id = CT_INVALID_ID32;
    entity->cbo_table_stats = stats;

    if (IS_PART_TABLE(table)) {
        if (cbo_load_part_table_stats(session, entity, load_info) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    // load table indexs statistics info
    if (cbo_load_table_indexs_stats(session, cursor, entity) != CT_SUCCESS) {
        return CT_ERROR;
    }

    entity->stat_exists = CT_TRUE;
    entity->stats_locked = CT_FALSE;
    return CT_SUCCESS;
}

status_t cbo_load_interval_index_part(knl_session_t *session, dc_entity_t *entity, uint32 idx_slot,
                                      uint32 part_no)
{
    if (!entity->stat_exists) {
        return CT_SUCCESS;
    }

    cbo_stats_table_t *table_stats = entity->cbo_table_stats;
    if (table_stats == NULL || table_stats->indexs == NULL) {
        return CT_SUCCESS;
    }

    cbo_stats_index_t *index_stats = table_stats->indexs[idx_slot];

    if (cbo_alloc_index_part_default(session, entity, index_stats, part_no) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

static status_t cbo_load_index_defaut(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity, uint32 pos)
{
    memory_context_t *memory = entity->memory;
    cbo_stats_index_t *stats = entity->cbo_table_stats->indexs[pos];
    errno_t ret;
    bool32 is_part = *(bool32 *)CURSOR_COLUMN_DATA(cursor, INDEX_PARTED);

    if (stats == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, memory, sizeof(cbo_stats_index_t), (void **)&stats) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        ret = memset_sp(stats, sizeof(cbo_stats_index_t), 0, sizeof(cbo_stats_index_t));
        knl_securec_check(ret);
    } else {
        stats->is_part = *(bool8 *)CURSOR_COLUMN_DATA(cursor, INDEX_PARTED);
        stats->part_id = CT_INVALID_ID32;
        stats->blevel = 0;
        stats->avg_data_key = 0;
        stats->avg_leaf_key = 0;
        stats->analyse_time = 0;
        stats->clustering_factor = 0;
        stats->leaf_blocks = 0;
        stats->empty_leaf_blocks = 0;
        stats->distinct_keys = 0;
        stats->comb_cols_2_ndv = 0;
        stats->comb_cols_3_ndv = 0;
        stats->comb_cols_4_ndv = 0;
    }

    stats->id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, INDEX_IDX_ID);

    if (is_part && stats->idx_part_default == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, memory, sizeof(cbo_stats_index_t),
                         (void **)&stats->idx_part_default) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        ret = memset_sp(stats->idx_part_default, sizeof(cbo_stats_index_t), 0, sizeof(cbo_stats_index_t));
        knl_securec_check(ret);
    }

    entity->cbo_table_stats->indexs[pos] = stats;
   
    if (is_part) {
        if (cbo_alloc_part_index_stats(session, entity, stats, pos) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static status_t cbo_alloc_interval_part_group(knl_session_t *session, dc_entity_t *entity,
    part_group_t *part_group)
{
    dc_context_t *dc_ctx = &session->kernel->dc_ctx;
    errno_t ret;

    if (part_group->group_id == NULL) {
        if (dc_alloc_mem(dc_ctx, entity->memory, INTERVAL_PART_GROUP_SIZE,
            (void **)&part_group->group_id) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }
        ret = memset_sp(part_group->group_id, INTERVAL_PART_GROUP_SIZE, 0XFF, INTERVAL_PART_GROUP_SIZE);
        knl_securec_check(ret);
    }

    if (part_group->group_ready == NULL) {
        if (dc_alloc_mem(dc_ctx, entity->memory, INTERVAL_PART_GROUP_SIZE,
            (void **)&part_group->group_ready) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }
        ret = memset_sp(part_group->group_ready, INTERVAL_PART_GROUP_SIZE, 0, INTERVAL_PART_GROUP_SIZE);
        knl_securec_check(ret);
    }

    return CT_SUCCESS;
}

static status_t cbo_alloc_part_index_stats(knl_session_t *session, dc_entity_t *entity, cbo_stats_index_t *stats,
                                           uint32 pos)
{
    table_t *table = &entity->table;
    part_table_t *part_table = table->part_table;
    index_t *idx = table->index_set.items[pos];
    part_index_t *part_idx = idx->part_index;
    index_part_t *idx_part = NULL;
    uint32 part_cnt = part_idx->desc.partcnt;
    errno_t ret;
    uint32 group_count = cbo_get_part_group_count(part_cnt);
    uint32 memsize;

    memsize = group_count * sizeof(cbo_index_part_group_t *);

    // for interval partiiton
    if (part_table->desc.interval_key != NULL) {
        memsize = CT_SHARED_PAGE_SIZE;
        if (cbo_alloc_interval_part_group(session, entity, &stats->part_group) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (stats->part_index_groups == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, memsize,
            (void **)&stats->part_index_groups) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        ret = memset_sp(stats->part_index_groups, memsize, 0, memsize);
        knl_securec_check(ret);
    }

    for (uint32 i = 0; i < part_idx->desc.partcnt; i++) {
        idx_part = INDEX_GET_PART(idx, i);
        if (idx_part == NULL) {
            continue;
        }

        if (cbo_alloc_index_part_stats(session, entity, stats, i) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!IS_PARENT_IDXPART(&idx_part->desc)) {
            continue;
        }

        if (cbo_alloc_index_subpart_stats(session, entity, idx, stats, idx_part) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }
    return CT_SUCCESS;
}

static void cbo_set_subpart_index_stats(cbo_stats_index_t *idx_stats, knl_cursor_t *cursor)
{
    idx_stats->id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXSUBPART_COL_USER_ID);
    idx_stats->blevel = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXSUBPART_COL_BLEVEL);
    idx_stats->leaf_blocks = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXSUBPART_COL_LEVEL_BLOCKS);
    idx_stats->distinct_keys = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXSUBPART_COL_DISTKEY);
    idx_stats->avg_leaf_key = *(double *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXSUBPART_COL_LBLKKEY);
    idx_stats->avg_data_key = *(double *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXSUBPART_COL_DBLKKEY);
    idx_stats->empty_leaf_blocks = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXSUBPART_COL_EMPTY_LEAF_BLOCKS);
    idx_stats->clustering_factor = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXSUBPART_COL_CLUFAC);
    idx_stats->comb_cols_2_ndv = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXSUBPART_COL_COM_COLS_2_NDV);
    idx_stats->comb_cols_3_ndv = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXSUBPART_COL_COM_COLS_3_NDV);
    idx_stats->comb_cols_4_ndv = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXSUBPART_COL_COM_COLS_4_NDV);
    idx_stats->analyse_time = *(date_t *)CURSOR_COLUMN_DATA(cursor, SYS_INDEXSUBPART_COL_ANALYZETIME);
}

status_t cbo_load_index_subpart_stats(knl_session_t *session, dc_entity_t *entity, uint32 part_no,
                                      uint32 index_id, uint32 subpart_no)
{
    table_t *table = &entity->table;
    index_t *idx = NULL;
    cbo_stats_table_t *table_stats = entity->cbo_table_stats;

    for (uint32 i = 0; i < table->index_set.count; i++) {
        idx = table->index_set.items[i];
        if (idx->desc.id == index_id) {
            break;
        }
    }

    if (idx == NULL) {
        CT_LOG_RUN_INF("Load %s.%s the %d index stats falied,it is not existed ",
                       entity->entry->user->desc.name, entity->table.desc.name, index_id);
        return CT_ERROR;
    }

    if (cbo_precheck_index_subpart(session, entity, part_no, idx, subpart_no) != CT_SUCCESS) {
        return CT_ERROR;
    }

    index_part_t *index_part = INDEX_GET_PART(idx, part_no);
    cbo_stats_index_t *index_stats = entity->cbo_table_stats->indexs[idx->desc.slot];
    cbo_stats_index_t *parent_stats = CBO_GET_INDEX_PART(index_stats, index_part->part_no);
    CM_SAVE_STACK(session->stack);
    index_part_t *index_sub = PART_GET_SUBENTITY(idx->part_index, index_part->subparts[subpart_no]);

    knl_cursor_t *cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SUB_INDEX_PARTS_ID, IX_SYS_INDEXSUBPART001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &index_sub->desc.uid,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &index_sub->desc.table_id,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &index_sub->desc.index_id,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER,
        &index_sub->desc.parent_partid, sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_PARENT_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &index_sub->desc.part_id,
        sizeof(uint32), IX_COL_SYS_INDEXSUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        return CT_SUCCESS;
    }

    if (cbo_alloc_index_subpart_stats(session, entity, idx, index_stats, index_part) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (CURSOR_COLUMN_SIZE(cursor, INDEX_PART_ANALYZE_TIME) == CT_NULL_VALUE_LEN) {
        CM_RESTORE_STACK(session->stack);
        CT_LOG_RUN_INF("Load %s.%s the %d-%d-%d index part stats falied,it is not analyzed",
                       entity->entry->user->desc.name, entity->table.desc.name, index_id, part_no, subpart_no);
        return CT_SUCCESS;
    }

    // load index statistics info
    cbo_stats_index_t *subpart_stats = CBO_GET_SUBINDEX_PART(index_stats, index_part->subparts[subpart_no]);
    cbo_set_subpart_index_stats(subpart_stats, cursor);
   
    subpart_stats->is_ready = CT_TRUE;
    subpart_stats->stats_version = table_stats->stats_version;

    parent_stats->is_ready = CT_TRUE;
    parent_stats->stats_version = table_stats->stats_version;

    CM_RESTORE_STACK(session->stack);
    knl_part_locate_t part_loc;
    part_loc.part_no = part_no;
    part_loc.subpart_no = subpart_no;
    dc_calc_index_empty_size(session, entity, idx->desc.slot, part_loc, subpart_stats->empty_leaf_blocks);
    return CT_SUCCESS;
}

static void cbo_set_index_stats(cbo_stats_index_t *stats, knl_cursor_t *cursor)
{
    stats->id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, INDEX_IDX_ID);
    stats->part_id = CT_INVALID_ID32;
    stats->is_part = *(bool8 *)CURSOR_COLUMN_DATA(cursor, INDEX_PARTED);
    stats->blevel = *(uint32 *)CURSOR_COLUMN_DATA(cursor, INDEX_BLEVEL);
    stats->leaf_blocks = *(uint32 *)CURSOR_COLUMN_DATA(cursor, INDEX_LEVEL_BLOCKS);
    stats->distinct_keys = *(uint32 *)CURSOR_COLUMN_DATA(cursor, INDEX_DISTINCT_KEYS);
    stats->avg_leaf_key = *(double *)CURSOR_COLUMN_DATA(cursor, INDEX_AVG_LEAF_BLOCKS_PER_KEY);
    stats->avg_data_key = *(double *)CURSOR_COLUMN_DATA(cursor, INDEX_AVG_DATA_BLOCKS_PER_KEY);
    stats->empty_leaf_blocks = *(uint32 *)CURSOR_COLUMN_DATA(cursor, INDEX_EMPTY_LEAF_BLOCKS);
    stats->clustering_factor = *(uint32 *)CURSOR_COLUMN_DATA(cursor, INDEX_CLUSTER_FACTOR);

    if (CURSOR_COLUMN_SIZE(cursor, INDEX_COMB_2_NDV) == CT_NULL_VALUE_LEN) {
        stats->comb_cols_2_ndv = 0;
        stats->comb_cols_3_ndv = 0;
        stats->comb_cols_4_ndv = 0;
    } else {
        stats->comb_cols_2_ndv = *(uint32 *)CURSOR_COLUMN_DATA(cursor, INDEX_COMB_2_NDV);
        stats->comb_cols_3_ndv = *(uint32 *)CURSOR_COLUMN_DATA(cursor, INDEX_COMB_3_NDV);
        stats->comb_cols_4_ndv = *(uint32 *)CURSOR_COLUMN_DATA(cursor, INDEX_COMB_4_NDV);
    }

    stats->analyse_time = *(date_t *)CURSOR_COLUMN_DATA(cursor, INDEX_IDX_ANALYZE_TIME);
}

static status_t cbo_load_table_one_index(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity,
                                         uint32 pos)
{
    cbo_stats_index_t *stats = entity->cbo_table_stats->indexs[pos];
    errno_t ret;
    bool32 is_part = *(bool32 *)CURSOR_COLUMN_DATA(cursor, INDEX_PARTED);

    if (CURSOR_COLUMN_SIZE(cursor, INDEX_IDX_ANALYZE_TIME) == CT_NULL_VALUE_LEN) {
        return cbo_load_index_defaut(session, cursor, entity, pos);
    }

    date_t analyse_time = *(date_t *)CURSOR_COLUMN_DATA(cursor, INDEX_IDX_ANALYZE_TIME);
    if (analyse_time == 0) {
        return cbo_load_index_defaut(session, cursor, entity, pos);
    }

    if (stats == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(cbo_stats_index_t),
                         (void **)&stats) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        ret = memset_sp(stats, sizeof(cbo_stats_index_t), 0, sizeof(cbo_stats_index_t));
        knl_securec_check(ret);
        entity->cbo_table_stats->indexs[pos] = stats;
    }

    if (is_part && stats->idx_part_default == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(cbo_stats_index_t),
                         (void **)&stats->idx_part_default) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        ret = memset_sp(stats->idx_part_default, sizeof(cbo_stats_index_t), 0, sizeof(cbo_stats_index_t));
        knl_securec_check(ret);
    }

    // load index statistics info
    cbo_set_index_stats(stats, cursor);

    if (is_part) {
        if (cbo_alloc_part_index_stats(session, entity, stats, pos) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        knl_part_locate_t part_loc;
        part_loc.part_no = CT_INVALID_ID32;
        part_loc.subpart_no = CT_INVALID_ID32;
        dc_calc_index_empty_size(session, entity, pos, part_loc, stats->empty_leaf_blocks);
        stats->is_ready = CT_TRUE;
    }

    return CT_SUCCESS;
}

static status_t cbo_load_table_indexs_stats(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity)
{
    uint32 pos = 0;
    knl_scan_key_t *l_border = NULL;
    knl_scan_key_t *r_border = NULL;
    cbo_stats_table_t *cbo_stats = entity->cbo_table_stats;
    knl_index_desc_t idx_desc = {0};
    uint32 valid_count = entity->table.desc.index_count;
    errno_t ret;

    if (valid_count == 0) {
        return CT_SUCCESS;
    }

    if (cbo_stats->indexs == NULL || cbo_stats->index_count < valid_count) {
        // valid_count <= 32, so sizeof(cbo_stats_index_t *) * valid_count is smaller than max uint32 value
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(cbo_stats_index_t *) * valid_count,
                         (void **)&cbo_stats->indexs) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        ret = memset_sp(cbo_stats->indexs, sizeof(cbo_stats_index_t *) * valid_count, 0,
                        sizeof(cbo_stats_index_t *) * valid_count);
        knl_securec_check(ret);
    }

    cbo_stats->index_count = valid_count;
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_INDEX_ID, IX_SYS_INDEX_001_ID);
    l_border = &cursor->scan_range.l_key;
    r_border = &cursor->scan_range.r_key;
    knl_init_index_scan(cursor, CT_FALSE);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_border, CT_TYPE_INTEGER, (char *)&entity->table.desc.uid,
                     sizeof(uint32), IX_COL_SYS_INDEX_001_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), l_border, CT_TYPE_INTEGER, (char *)&entity->table.desc.id,
                     sizeof(uint32), IX_COL_SYS_INDEX_001_TABLE);
    knl_set_key_flag(l_border, SCAN_KEY_LEFT_INFINITE, IX_COL_SYS_INDEX_001_ID);

    knl_set_scan_key(INDEX_DESC(cursor->index), r_border, CT_TYPE_INTEGER, (char *)&entity->table.desc.uid,
                     sizeof(uint32), IX_COL_SYS_INDEX_001_USER);
    knl_set_scan_key(INDEX_DESC(cursor->index), r_border, CT_TYPE_INTEGER, (char *)&entity->table.desc.id,
                     sizeof(uint32), IX_COL_SYS_INDEX_001_TABLE);
    knl_set_key_flag(r_border, SCAN_KEY_RIGHT_INFINITE, IX_COL_SYS_INDEX_001_ID);

    for (;;) {
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cursor->eof || pos >= valid_count) {
            break;
        }

        idx_desc.flags = *(uint32 *)CURSOR_COLUMN_DATA(cursor, INDEX_FLAGS);

        if (idx_desc.is_invalid) {
            continue;
        }

        if (cbo_load_table_one_index(session, cursor, entity, pos++) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

// load_column_one_histgram
static status_t cbo_load_column_one_histgram(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity,
                                             knl_column_t *column, cbo_stats_column_t *stats, uint32 pos)
{
    cbo_column_hist_t *hist = stats->column_hist[pos];
    text_t ep_value;
    errno_t ret;

    if (hist == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(cbo_column_hist_t),
                         (void **)&hist) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        ret = memset_sp(hist, sizeof(cbo_column_hist_t), 0, sizeof(cbo_column_hist_t));
        knl_securec_check(ret);
        stats->column_hist[pos] = hist;
    }

    // load column histogram statistics info
    ep_value.str = CURSOR_COLUMN_DATA(cursor, HIST_EP_VALUE);
    ep_value.len = CURSOR_COLUMN_SIZE(cursor, HIST_EP_VALUE);

    if (cbo_alloc_value_mem(session, entity->memory, column, &hist->ep_value.str) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cbo_get_stats_values(entity, column, &ep_value, &hist->ep_value)) {
        return CT_ERROR;
    }

    hist->ep_number = *(uint32 *)CURSOR_COLUMN_DATA(cursor, HIST_EP_NUM);

    return CT_SUCCESS;
}

static bool32 cbo_exist_same_endpoint(uint32 *endpints, uint32 curr_endpoint)
{
    for (uint32 i = 0; i < STATS_HISTGRAM_MAX_SIZE; i++) {
        uint32 endpoint = endpints[i];
        if (curr_endpoint == endpoint) {
            return CT_TRUE;
        }

        if (endpoint == CT_INVALID_ID32) {
            endpints[i] = curr_endpoint;
            break;
        }
    }

    return CT_FALSE;
}

static status_t cbo_verify_vaild_histgram(dc_entity_t *entity, cbo_stats_column_t *stats, knl_cursor_t *cursor,
    bool32 *valid)
{
    knl_column_t *column = dc_get_column(entity, stats->column_id);
    text_t curr_bucket;
    text_t ret_bucket;
    char buf[STATS_MAX_BUCKET_SIZE] = {'\0'};
    curr_bucket.str = CURSOR_COLUMN_DATA(cursor, HIST_EP_VALUE);
    curr_bucket.len = CURSOR_COLUMN_SIZE(cursor, HIST_EP_VALUE);
    
    ret_bucket.str = buf;
    ret_bucket.len = 0;
    
    if (cbo_get_stats_values(entity, column, &curr_bucket, &ret_bucket) != CT_SUCCESS) {
        return CT_ERROR;
    }
   
    int32 result = stats_compare_data_ex(ret_bucket.str, ret_bucket.len, stats->low_value.str,
        stats->low_value.len, column);
    // value is less low value
    if (result == -1) {
        *valid = CT_FALSE;
    }

    result = stats_compare_data_ex(ret_bucket.str, ret_bucket.len,
        stats->high_value.str, stats->high_value.len, column);
    // value is bigger high value
    if (result == 1) {
        *valid = CT_FALSE;
    }

    return CT_SUCCESS;
}

static status_t cbo_alloc_hist_memory(knl_session_t *session, dc_entity_t *entity, cbo_stats_column_t *stats)
{
    if (stats->column_hist != NULL) {
        return CT_SUCCESS;
    }

    if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory,
        sizeof(cbo_column_hist_t *) * STATS_HISTGRAM_MAX_SIZE,
        (void **)&stats->column_hist) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
        return CT_ERROR;
    }

    errno_t ret = memset_sp(stats->column_hist, sizeof(cbo_column_hist_t *) * STATS_HISTGRAM_MAX_SIZE, 0,
        sizeof(cbo_column_hist_t *) * STATS_HISTGRAM_MAX_SIZE);
    knl_securec_check(ret);

    return CT_SUCCESS;
}

// load column histogram info
static status_t cbo_load_column_sub_histgrams(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity,
                                              cbo_stats_column_t *stats, cbo_stats_table_t *part_stats)
{
    table_t *table = &entity->table;
    uint32 count = 0;
    uint64 subpart_id = part_stats->subpart_id;
    uint32 endpoints[STATS_HISTGRAM_MAX_SIZE];
    cbo_hists_assist_t cbo_hists[STATS_HISTGRAM_MAX_SIZE];
    errno_t ret = memset_sp(&cbo_hists, sizeof(cbo_hists_assist_t) * STATS_HISTGRAM_MAX_SIZE,
                            0xFF, sizeof(cbo_hists_assist_t) * STATS_HISTGRAM_MAX_SIZE);
    knl_securec_check(ret);

    ret = memset_sp(&endpoints, sizeof(uint32) * STATS_HISTGRAM_MAX_SIZE, 0xFF,
        sizeof(uint32) * STATS_HISTGRAM_MAX_SIZE);
    knl_securec_check(ret);

    if (stats->num_distinct == 0) {
        return CT_SUCCESS;
    }

    if (cbo_alloc_hist_memory(session, entity, stats) != CT_SUCCESS) {
        return CT_ERROR;
    }

    uint32 cid = stats->column_id;
    stats_open_histgram_cursor(session, cursor, CURSOR_ACTION_SELECT, IX_HIST_003_ID,
        IS_NOLOGGING_BY_TABLE_TYPE(table->desc.type));
    knl_init_index_scan(cursor, CT_FALSE);
    cbo_set_histgram_scan_key(cursor, table, cid, part_stats->part_id);

    for (;;) {
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        if (CURSOR_COLUMN_SIZE(cursor, HIST_SUBPART_ID) != CT_NULL_VALUE_LEN &&
            subpart_id == *(uint64*)CURSOR_COLUMN_DATA(cursor, HIST_SUBPART_ID)) {
            uint32 endpoint = *(uint32 *)CURSOR_COLUMN_DATA(cursor, HIST_EP_NUM);
            if (cbo_exist_same_endpoint(endpoints, endpoint)) {
                continue;
            }

            bool32 valid = CT_TRUE;
            if (cbo_verify_vaild_histgram(entity, stats, cursor, &valid) != CT_SUCCESS) {
                return CT_ERROR;
            }

            if (!valid || count >= stats->num_buckets) {
                continue;
            }

            cbo_hists_assist_t *cbo_hist = &cbo_hists[count];
            cbo_hist->endpoint = endpoint;
            cbo_hist->len = CURSOR_COLUMN_SIZE(cursor, HIST_EP_VALUE);
            if (cbo_hist->len > 0) {
                ret = memcpy_sp(cbo_hist->buckets, cbo_hist->len,
                    CURSOR_COLUMN_DATA(cursor, HIST_EP_VALUE), cbo_hist->len);
                knl_securec_check(ret);
            }
            count++;
        }
    }

    stats->num_buckets = count;
    stats->hist_count = count;
    cbo_hists_sort(cbo_hists, count);

    if (cbo_set_sub_histgrams(session, entity, count, stats, cbo_hists) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}
// load column histogram info
static status_t cbo_load_column_histgrams(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity,
                                          cbo_stats_column_t *stats, uint32 part_id)
{
    knl_column_t *column = dc_get_column(entity, stats->column_id);
    uint32 cid;
    errno_t ret;
    table_t *table = &entity->table;
    uint32 count = 0;
    
    if (stats->num_distinct == 0) {
        return CT_SUCCESS;
    }

    if (cbo_alloc_hist_memory(session, entity, stats) != CT_SUCCESS) {
        return CT_ERROR;
    }
   
    uint32 endpoints[STATS_HISTGRAM_MAX_SIZE];
    ret = memset_sp(&endpoints, sizeof(uint32) * STATS_HISTGRAM_MAX_SIZE, 0xFF,
        sizeof(uint32) * STATS_HISTGRAM_MAX_SIZE);
    knl_securec_check(ret);
    
    cid = stats->column_id;
    stats_open_histgram_cursor(session, cursor, CURSOR_ACTION_SELECT, IX_HIST_003_ID,
        IS_NOLOGGING_BY_TABLE_TYPE(table->desc.type));
    knl_init_index_scan(cursor, CT_FALSE);
    cbo_set_histgram_scan_key(cursor, table, cid, part_id);

    for (;;) {
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cursor->eof) {
            break;
        }

        uint32 endpoint = *(uint32 *)CURSOR_COLUMN_DATA(cursor, HIST_EP_NUM);
        if (cbo_exist_same_endpoint(endpoints, endpoint)) {
            continue;
        }

        bool32 valid = CT_TRUE;
        if (cbo_verify_vaild_histgram(entity, stats, cursor, &valid) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!valid || count >= stats->num_buckets) {
            continue;
        }

        if (cbo_load_column_one_histgram(session, cursor, entity, column, stats, count) != CT_SUCCESS) {
            return CT_ERROR;
        }

        count++;
    }

    stats->hist_count = count;
    return CT_SUCCESS;
}

// load_table_one_column
static status_t cbo_load_table_one_column(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity,
                                          cbo_stats_table_t *cbo_stats, uint32 pos, bool32 is_subpart)
{
    knl_column_t *column = dc_get_column(entity, pos);
    cbo_stats_column_t *stats = get_cbo_stats_column(cbo_stats, pos);
    date_t analyze_time;
    text_t low_value;
    text_t high_value;
    errno_t ret;

    if (CURSOR_COLUMN_SIZE(cursor, HIST_HEAD_ANALYZE_TIME) == CT_NULL_VALUE_LEN) {
        return CT_SUCCESS;
    }

    analyze_time = *(date_t *)CURSOR_COLUMN_DATA(cursor, HIST_HEAD_ANALYZE_TIME);
    if (analyze_time == 0) {
        return CT_SUCCESS;
    }

    if (stats == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(cbo_stats_column_t),
                         (void **)&stats) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        ret = memset_sp(stats, sizeof(cbo_stats_column_t), 0, sizeof(cbo_stats_column_t));
        knl_securec_check(ret);
        set_cbo_stats_column(cbo_stats, stats, pos);
    }

    stats->column_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, HIST_HEAD_COLUMN_ID);
    stats->num_buckets = *(int32 *)CURSOR_COLUMN_DATA(cursor, HIST_HEAD_BUCKET_NUM);
    stats->num_null = *(int32 *)CURSOR_COLUMN_DATA(cursor, HIST_HEAD_NULL_NUM);
    stats->num_distinct = *(int32 *)CURSOR_COLUMN_DATA(cursor, HIST_HEAD_DIST_NUM);
    stats->total_rows = *(int32 *)CURSOR_COLUMN_DATA(cursor, HIST_HEAD_TOTAL_ROWS);
    stats->density = *(double *)CURSOR_COLUMN_DATA(cursor, HIST_HEAD_DENSITY);
    low_value.str = CURSOR_COLUMN_DATA(cursor, HIST_HEAD_LOW_VALUE);
    low_value.len = CURSOR_COLUMN_SIZE(cursor, HIST_HEAD_LOW_VALUE);
    high_value.str = CURSOR_COLUMN_DATA(cursor, HIST_HEAD_HIGH_VALUE);
    high_value.len = CURSOR_COLUMN_SIZE(cursor, HIST_HEAD_HIGH_VALUE);

    if (cbo_alloc_value_mem(session, entity->memory, column, &stats->low_value.str) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cbo_get_stats_values(entity, column, &low_value, &stats->low_value) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cbo_alloc_value_mem(session, entity->memory, column, &stats->high_value.str) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cbo_get_stats_values(entity, column, &high_value, &stats->high_value) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (stats->num_buckets > STATS_HISTGRAM_MAX_SIZE) {
        stats->num_buckets = STATS_HISTGRAM_MAX_SIZE;
        CT_LOG_RUN_INF("Number of Histgram %d is exceed max number of histgram 254, "
                       "it may impact on execution plan, please analyze table again",
                       stats->num_buckets);
    }

    stats->analyse_time = analyze_time;
    stats->column_type = column->datatype;
    stats->hist_type = (stats->num_distinct <= stats->num_buckets) ? FREQUENCY : HEIGHT_BALANCED;

    if (is_subpart) {
        if (cbo_load_column_sub_histgrams(session, cursor, entity, stats, cbo_stats) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (cbo_load_column_histgrams(session, cursor, entity, stats, cbo_stats->part_id) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

void cbo_set_global_column_scan_key(knl_cursor_t *cursor, table_t *table, knl_column_t *column)
{
    uint32 uid = table->desc.uid;
    uint32 tid = table->desc.id;
    uint32 cid = column->id;
    uint64 part_id = CT_INVALID_ID32;

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&uid,
        sizeof(uint32), IX_COL_HIST_HEAD_003_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&tid,
        sizeof(uint32), IX_COL_HIST_HEAD_003_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&cid,
        sizeof(uint32), IX_COL_HIST_HEAD_003_COL_ID);
    if (IS_PART_TABLE(table)) {
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, (void *)&part_id,
            sizeof(uint64), IX_COL_HIST_HEAD_003_SPARE1);
    } else {
        knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_IS_NULL, IX_COL_HIST_HEAD_003_SPARE1);
    }

    if (IS_PART_TABLE(table) && IS_COMPART_TABLE(table->part_table)) {
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, (void *)&part_id,
            sizeof(uint64), IX_COL_HIST_HEAD_003_SPARE2);
    } else {
        knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_IS_NULL, IX_COL_HIST_HEAD_003_SPARE2);
    }
}

static status_t cbo_load_table_columns_stats(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity)
{
    table_t *table = &entity->table;
    cbo_stats_table_t *cbo_stats = entity->cbo_table_stats;
    uint32 max_col_id = 0;
  
    if (cbo_prepare_load_columns(session, entity, cbo_stats) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cbo_stats->column_count = entity->column_count;

    cbo_stats->col_loading = CT_TRUE;
    for (uint32 pos = 0; pos < entity->column_count; pos++) {
        knl_column_t *column = dc_get_column(entity, pos);
        uint32 cid = column->id;
        stats_open_hist_abstr_cursor(session, cursor, CURSOR_ACTION_SELECT, IX_HIST_HEAD_003_ID,
            IS_NOLOGGING_BY_TABLE_TYPE(entity->table.desc.type));
        knl_init_index_scan(cursor, CT_TRUE);
        cbo_set_global_column_scan_key(cursor, table, column);
       
        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cursor->eof) {
            continue;
        }

        if (max_col_id < cid) {
            max_col_id = cid;
        }

        cm_latch_x(&column->cbo_col_latch, session->id, NULL);
        if (cbo_load_table_one_column(session, cursor, entity, cbo_stats, pos, CT_FALSE) != CT_SUCCESS) {
            cm_unlatch(&column->cbo_col_latch, NULL);
            return CT_ERROR;
        }
        cm_unlatch(&column->cbo_col_latch, NULL);
    }

    if (cbo_set_columns_stats(session, entity, cbo_stats) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cbo_stats->max_col_id = entity->column_count - 1;
    cbo_stats->col_loading = CT_FALSE;
    return CT_SUCCESS;
}

static status_t cbo_load_table_subpart_columns(knl_session_t *session, dc_entity_t *entity, cbo_stats_table_t *part_stats)
{
    if (cbo_prepare_load_columns(session, entity, part_stats) != CT_SUCCESS) {
        return CT_ERROR;
    }

    part_stats->column_count = entity->column_count;
    part_stats->max_col_id = entity->cbo_table_stats->max_col_id;
    uint32 max_col_id = 0;
    uint32 uid = entity->table.desc.uid;
    uint32 tid = entity->table.desc.id;
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    uint64 part_id = part_stats->part_id;
    uint64 subpart_id = part_stats->subpart_id;
    part_stats->col_loading = CT_TRUE;

    for (uint32 pos = 0; pos < entity->column_count; pos++) {
        knl_column_t *column = dc_get_column(entity, pos);

        stats_open_hist_abstr_cursor(session, cursor, CURSOR_ACTION_SELECT, IX_HIST_HEAD_003_ID,
            IS_NOLOGGING_BY_TABLE_TYPE(entity->table.desc.type));
        knl_init_index_scan(cursor, CT_TRUE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&uid,
            sizeof(uint32), IX_COL_HIST_HEAD_003_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&tid,
            sizeof(uint32), IX_COL_HIST_HEAD_003_TABLE_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&column->id,
            sizeof(uint32), IX_COL_HIST_HEAD_003_COL_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, (void *)&part_id,
            sizeof(uint64), IX_COL_HIST_HEAD_003_SPARE1);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, (void *)&subpart_id,
            sizeof(uint64), IX_COL_HIST_HEAD_003_SPARE2);

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (cursor->eof) {
            continue;
        }

        if (max_col_id < column->id) {
            max_col_id = column->id;
        }

        cm_latch_x(&column->cbo_col_latch, session->id, NULL);
        if (cbo_load_table_one_column(session, cursor, entity, part_stats, pos, CT_TRUE) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            cm_unlatch(&column->cbo_col_latch, NULL);
            return CT_ERROR;
        }
        cm_unlatch(&column->cbo_col_latch, NULL);
    }

    CM_RESTORE_STACK(session->stack);

    if (cbo_set_columns_stats(session, entity, part_stats) != CT_SUCCESS) {
        return CT_ERROR;
    }

    part_stats->max_col_id = max_col_id;
    part_stats->col_loading = CT_FALSE;
    return CT_SUCCESS;
}

static status_t cbo_load_table_part_columns(knl_session_t *session, dc_entity_t *entity, cbo_stats_table_t *part_stats,
                                            bool32 is_subpart)
{
    uint32 uid, tid, cid, col_count, max_col_id;
    uint64 part_id, subpart_id;
   
    col_count = entity->column_count;
   
    if (cbo_prepare_load_columns(session, entity, part_stats) != CT_SUCCESS) {
        return CT_ERROR;
    }

    part_stats->column_count = col_count;
    part_stats->max_col_id = entity->cbo_table_stats->max_col_id;
    max_col_id = 0;
    uid = entity->table.desc.uid;
    tid = entity->table.desc.id;
    part_id = part_stats->part_id;
    subpart_id = part_stats->subpart_id;
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    part_stats->col_loading = CT_TRUE;

    for (uint32 pos = 0; pos < entity->column_count; pos++) {
        knl_column_t *column = dc_get_column(entity, pos);
        cid = column->id;
        stats_open_hist_abstr_cursor(session, cursor, CURSOR_ACTION_SELECT, IX_HIST_HEAD_003_ID,
            IS_NOLOGGING_BY_TABLE_TYPE(entity->table.desc.type));
        knl_init_index_scan(cursor, CT_TRUE);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&uid,
                         sizeof(uint32), IX_COL_HIST_HEAD_003_USER_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&tid,
                         sizeof(uint32), IX_COL_HIST_HEAD_003_TABLE_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&cid,
                         sizeof(uint32), IX_COL_HIST_HEAD_003_COL_ID);
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, (void *)&part_id,
                         sizeof(uint64), IX_COL_HIST_HEAD_003_SPARE1);
        if (!is_subpart) {
            knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_IS_NULL, IX_COL_HIST_HEAD_003_SPARE2);
        } else {
            knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_BIGINT, (void *)&subpart_id,
                sizeof(uint64), IX_COL_HIST_HEAD_003_SPARE2);
        }

        if (knl_fetch(session, cursor) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }

        if (cursor->eof) {
            continue;
        }

        if (max_col_id < cid) {
            max_col_id = cid;
        }

        cm_latch_x(&column->cbo_col_latch, session->id, NULL);
        if (cbo_load_table_one_column(session, cursor, entity, part_stats, pos, is_subpart) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            cm_unlatch(&column->cbo_col_latch, NULL);
            return CT_ERROR;
        }
        cm_unlatch(&column->cbo_col_latch, NULL);
    }

    CM_RESTORE_STACK(session->stack);
    
    if (cbo_set_columns_stats(session, entity, part_stats) != CT_SUCCESS) {
        return CT_ERROR;
    }
   
    part_stats->max_col_id = max_col_id;
    part_stats->col_loading = CT_FALSE;
    return CT_SUCCESS;
}

static status_t cbo_alloc_part_table_stats(knl_session_t *session, dc_entity_t *entity)
{
    cbo_stats_table_t *cbo_stats = entity->cbo_table_stats;
    part_table_t *part_table = entity->table.part_table;
    uint32 part_cnt = part_table->desc.partcnt;
    errno_t ret;
    uint32 group_count = cbo_get_part_group_count(part_cnt);
    uint32 memsize = group_count * sizeof(cbo_stats_table_t *);

    if (part_table->desc.interval_key != NULL) {
        memsize = CT_SHARED_PAGE_SIZE;
        if (cbo_alloc_interval_part_group(session, entity, &cbo_stats->part_group) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (cbo_stats->part_groups == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, memsize,
            (void **)&cbo_stats->part_groups) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        ret = memset_sp(cbo_stats->part_groups, memsize, 0, memsize);
        knl_securec_check(ret);
    }

    if (cbo_stats->tab_part_default == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(cbo_stats_table_t),
            (void **)&cbo_stats->tab_part_default) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        ret = memset_sp(cbo_stats->tab_part_default, sizeof(cbo_stats_table_t), 0, sizeof(cbo_stats_table_t));
        knl_securec_check(ret);
    }

    if (part_table->desc.flags & PART_TABLE_SUBPARTED && cbo_stats->subpart_groups == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, CT_SHARED_PAGE_SIZE,
            (void **)&cbo_stats->subpart_groups) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        ret = memset_sp(cbo_stats->subpart_groups, CT_SHARED_PAGE_SIZE, 0, CT_SHARED_PAGE_SIZE);
        knl_securec_check(ret);
    }

    return CT_SUCCESS;
}

static status_t cbo_load_part_table_stats(knl_session_t *session, dc_entity_t *entity, stats_load_info_t load_info)
{
    table_t *table = &entity->table;
    part_table_t *part_table = entity->table.part_table;
    table_part_t *table_part = NULL;
    
    if (cbo_alloc_part_table_stats(session, entity) != CT_SUCCESS) {
        return CT_ERROR;
    }

    for (uint32 i = 0; i < part_table->desc.partcnt; i++) {
        table_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(table_part)) {
            continue;
        }

        if (CBO_NEED_LOAD_PART(load_info.parent_part_id, table_part->desc.part_id)) {
            if (cbo_load_table_part_stats(session, entity, i, load_info, CT_FALSE) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

cbo_stats_column_t *cbo_get_column_stats(cbo_stats_table_t *table_stats, uint32 col_id)
{
    cbo_stats_column_t *cbo_column = NULL;
    uint32 pos = get_cbo_col_map(table_stats, col_id);
    if (pos != CBO_INVALID_COLUMN_ID) {
        cbo_column = get_cbo_stats_column(table_stats, pos);
    }
    return cbo_column;
}

static status_t cbo_alloc_mem(knl_session_t *session, memory_context_t *memory, void **stats, uint32 size)
{
    if (dc_alloc_mem(&session->kernel->dc_ctx, memory, size, stats) != CT_SUCCESS) {
        CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
        return CT_ERROR;
    }

    errno_t ret = memset_sp(*stats, size, 0, size);
    knl_securec_check(ret);

    return CT_SUCCESS;
}

status_t cbo_load_tmptab_histgram(knl_session_t *session, dc_entity_t *entity, cbo_stats_table_t *stats,
                                  stats_col_handler_t *stats_col)
{
    memory_context_t *memory = NULL;
    cbo_stats_column_t *column_stats = get_cbo_stats_column(stats, stats_col->column->id);
    cbo_column_hist_t *hist = NULL;
    mtrl_cursor_t *mtrl_cur = &stats_col->mtrl.mtrl_cur;
    bool32 is_frenquency = stats_col->hist_info.bucket_num > STATS_HISTGRAM_MAX_SIZE ? CT_FALSE : CT_TRUE;
    errno_t ret;
    uint32 size;

    if (IS_LTT_BY_ID(entity->entry->id)) {
        memory = entity->memory;
    } else {
        table_t *table = &entity->table;
        knl_temp_cache_t *temp_cache = knl_get_temp_cache((knl_handle_t)session, table->desc.uid, table->desc.id);
        if (temp_cache == NULL) {
        return CT_ERROR;
        }
        memory = temp_cache->memory;
    }

    if (column_stats->column_hist == NULL) {
        if (cbo_alloc_mem(session, memory, (void **)&column_stats->column_hist,
            sizeof(cbo_column_hist_t *) * STATS_HISTGRAM_MAX_SIZE) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    hist = column_stats->column_hist[stats_col->hist_info.bucket_num];

    if (hist == NULL) {
        if (cbo_alloc_mem(session, memory, (void **)&hist, sizeof(cbo_column_hist_t)) != CT_SUCCESS) {
            return CT_ERROR;
        }
        column_stats->column_hist[stats_col->hist_info.bucket_num] = hist;
    }

    if (cbo_alloc_value_mem(session, memory, stats_col->column, &hist->ep_value.str) != CT_SUCCESS) {
        return CT_ERROR;
    }

    hist->ep_value.len = STATS_GET_ROW_SIZE(mtrl_cur);
    size = MIN(cbo_get_column_alloc_size(stats_col->column), hist->ep_value.len);
    if (hist->ep_value.len > 0) {
        ret = memcpy_sp(hist->ep_value.str, size, STATS_GET_ROW_DATA(mtrl_cur), size);
        knl_securec_check(ret);
    }

    if (is_frenquency && stats_col->simple_ratio > CT_REAL_PRECISION) {
        hist->ep_number = (uint32)(int32)(stats_col->hist_info.endpoint / stats_col->simple_ratio);
    } else {
        hist->ep_number = stats_col->hist_info.endpoint;
    }

    return CT_SUCCESS;
}

status_t cbo_load_tmptab_column_stats(knl_session_t *session, dc_entity_t *entity, cbo_stats_table_t *stats,
                                      stats_col_handler_t *stats_col)
{
    cbo_stats_column_t *column_stats = get_cbo_stats_column(stats, stats_col->column->id);
    double density;
    errno_t ret;
    uint32 copy_size = CT_NULL_VALUE_LEN;

    column_stats->column_id = stats_col->column->id;
    column_stats->num_null = stats_col->null_num;
    column_stats->num_distinct = stats_col->dist_num;
    column_stats->total_rows = stats_col->total_rows;
    table_t *table = &entity->table;

    memory_context_t *memory = NULL;
    knl_temp_cache_t *temp_cache = knl_get_temp_cache((knl_handle_t)session, table->desc.uid, table->desc.id);
    if (temp_cache == NULL) {
        return CT_ERROR;
    }
    if (!IS_LTT_BY_ID(table->desc.id)) {
        memory = temp_cache->memory;
    } else {
        memory = entity->memory;
    }

    if (stats_col->dist_num == 0) {
        density = 0;
    } else {
        density = (double)(1) / (double)(stats_col->dist_num);
    }
    
    if (cbo_alloc_value_mem(session, memory, stats_col->column, &column_stats->low_value.str) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cbo_alloc_value_mem(session, memory, stats_col->column, &column_stats->high_value.str) != CT_SUCCESS) {
        return CT_ERROR;
    }

    uint32 size = cbo_get_column_alloc_size(stats_col->column);
    if (stats_col->min_value.len > 0) {
        copy_size = MIN(size, stats_col->min_value.len);
        ret = memcpy_sp(column_stats->low_value.str, size, stats_col->min_value.str, copy_size);
        knl_securec_check(ret);
    }
    column_stats->low_value.len = stats_col->min_value.len == 0 ? CT_NULL_VALUE_LEN : copy_size;
    
    if (stats_col->max_value.len > 0) {
        copy_size = MIN(size, stats_col->max_value.len);
        ret = memcpy_sp(column_stats->high_value.str, size, stats_col->max_value.str, copy_size);
        knl_securec_check(ret);
    }
    column_stats->high_value.len = stats_col->max_value.len == 0 ? CT_NULL_VALUE_LEN : copy_size;
    column_stats->density = density;
    column_stats->analyse_time = cm_now();
    column_stats->column_type = stats_col->column->datatype;
    column_stats->hist_type = (column_stats->num_distinct <= STATS_HISTGRAM_MAX_SIZE) ? FREQUENCY : HEIGHT_BALANCED;
    column_stats->num_buckets = stats_col->hist_info.bucket_num;
    column_stats->hist_count = stats_col->hist_info.bucket_num;

    set_cbo_col_map(stats, column_stats->column_id, stats_col->column->id);
    stats->col_stats_allowed = CT_TRUE;
    return CT_SUCCESS;
}

void cbo_load_tmptab_index_stats(cbo_stats_table_t *stats, stats_index_t *stats_idx)
{
    cbo_stats_index_t *index_stats = stats->indexs[stats_idx->index_no];

    index_stats->id = stats_idx->idx_id;
    index_stats->blevel = stats_idx->info.height;
    index_stats->leaf_blocks = stats_idx->info.leaf_blocks;
    index_stats->distinct_keys = stats_idx->info.distinct_keys;
    index_stats->avg_leaf_key = stats_idx->avg_leaf_key;
    index_stats->avg_data_key = stats_idx->avg_data_key;
    index_stats->analyse_time = cm_now();
    index_stats->empty_leaf_blocks = stats_idx->info.empty_leaves;
    index_stats->clustering_factor = stats_idx->clus_factor;
    index_stats->comb_cols_2_ndv = stats_idx->info.comb_cols_2_ndv;
    index_stats->comb_cols_3_ndv = stats_idx->info.comb_cols_3_ndv;
    index_stats->comb_cols_4_ndv = stats_idx->info.comb_cols_4_ndv;
    index_stats->is_part = CT_FALSE;
}

void cbo_load_tmptab_table_stats(cbo_stats_table_t *stats, stats_table_t *stats_table, knl_dictionary_t *dc)
{
    dc_entity_t *entity = DC_ENTITY(dc);

    stats->table_id = stats_table->tab_id;
    stats->rows = stats_table->tab_info.rows;
    stats->blocks = stats_table->tab_info.blocks;
    stats->empty_blocks = stats_table->tab_info.empty_block;
    //  this sample size is analyzed rows, so it is smaller than max value of uint32
    stats->sample_size = (uint32)stats_table->tab_info.sample_size;
    stats->avg_row_len = stats_table->tab_info.avg_row_len;
    stats->analyse_time = cm_now();
    stats->is_ready = CT_TRUE;
    stats->column_count = entity->table.desc.column_count;
    stats->index_count = entity->table.desc.index_count;
}

static status_t cbo_alloc_temp_index_stats(knl_session_t *session, dc_entity_t *entity, memory_context_t *memory,
                                           cbo_stats_table_t *stats)
{
    uint32 valid_count = entity->table.desc.index_count;
    uint32 pos = 0;
    cbo_stats_index_t **prev_indexes = NULL;

    if (valid_count == 0) {
        return CT_SUCCESS;
    }

    if (stats->index_count < valid_count) {
        prev_indexes = stats->indexs;

        // valid_count <= 32, so sizeof(cbo_stats_index_t *) * valid_count is smaller than max uint32 value
        if (cbo_alloc_mem(session, memory, (void **)&stats->indexs, sizeof(cbo_stats_index_t *) * valid_count) !=
            CT_SUCCESS) {
            return CT_ERROR;
        }

        for (pos = 0; pos < stats->index_count; pos++) {
            stats->indexs[pos] = prev_indexes[pos];
        }

        for (pos = stats->index_count; pos < valid_count; pos++) {
            if (cbo_alloc_mem(session, memory, (void **)&stats->indexs[pos], sizeof(cbo_stats_index_t)) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }
    }

    return CT_SUCCESS;
}

static status_t cbo_alloc_temp_one_column(knl_session_t *se, memory_context_t *memory, cbo_stats_table_t *stats,
    uint32 pos)
{
    cbo_stats_column_t *column_stats = get_cbo_stats_column(stats, pos);

    if (column_stats == NULL) {
        if (cbo_alloc_mem(se, memory, (void **)&column_stats, sizeof(cbo_stats_column_t)) != CT_SUCCESS) {
            return CT_ERROR;
        }

        set_cbo_stats_column(stats, column_stats, pos);
    }

    return CT_SUCCESS;
}

static status_t cbo_alloc_temp_columns_stats(knl_session_t *session, dc_entity_t *entity, memory_context_t *memory,
    cbo_stats_table_t *stats)
{
    uint32 col_count = entity->column_count;
    uint32 ext_count;
    errno_t ret;

    if (col_count == 0) {
        return CT_SUCCESS;
    }

    // when is wide table, col_count = 4096, sizeof(cbo_stats_column_t*)*col_count > page_size
    // we use segment array to store cbo_stats_column_t* pointer
    ext_count = CM_ALIGN_ANY(col_count, CBO_LIST_COUNT) / CBO_LIST_COUNT;
    knl_panic_log(ext_count <= CBO_EXTENT_COUNT, "extent count is more than the limit, panic info: "
                  "ext_count %u table %s", ext_count, entity->table.desc.name);
    if (stats->columns == NULL) {
        if (cbo_alloc_mem(session, memory, (void **)&stats->columns, sizeof(void *) * ext_count) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    stats->max_col_id = col_count - 1;
    stats->column_count = col_count;

    for (uint32 i = 0; i < ext_count; i++) {
        if (stats->columns[i] != NULL) {
            continue;
        }

        if (cbo_alloc_mem(session, memory, (void **)&stats->columns[i], sizeof(void *) * CBO_LIST_COUNT) !=
                          CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    for (uint32 pos = 0; pos < entity->column_count; pos++) {
        if (cbo_alloc_temp_one_column(session, memory, stats, pos) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (stats->col_map == NULL) {
        if (cbo_alloc_mem(session, memory, (void **)&stats->col_map, sizeof(void *) * ext_count) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    for (uint32 i = 0; i < ext_count; i++) {
        if (stats->col_map[i] != NULL) {
            continue;
        }

        if (dc_alloc_mem(&session->kernel->dc_ctx, memory, sizeof(uint32) * CBO_LIST_COUNT,
            (void **)&stats->col_map[i])) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        ret = memset_sp(stats->col_map[i], sizeof(uint32) * CBO_LIST_COUNT, 0xFF, sizeof(uint32) * CBO_LIST_COUNT);
        knl_securec_check(ret);
    }

    return CT_SUCCESS;
}

// just for  dynamic sampling global session level temp table and local temporary table alloc stats
// gst --> global session temporary table
// llt --> local temporary table
static status_t cbo_alloc_gst_dynamic_stats(knl_session_t *session, dc_entity_t *entity, knl_temp_cache_t *temp_cache)
{
    if (temp_cache->mem_chg_scn != entity->table.desc.chg_scn) {
        knl_free_temp_cache_memory(temp_cache);
    }

    if (temp_cache->memory == NULL) {
        if (dc_create_memory_context(&session->kernel->dc_ctx, &temp_cache->memory) != CT_SUCCESS) {
            return CT_ERROR;
        }
        
        temp_cache->mem_chg_scn = entity->table.desc.chg_scn;
    }

    memory_context_t *memory = temp_cache->memory;

    if (temp_cache->cbo_stats == NULL) {
        if (cbo_alloc_mem(session, memory, (void **)&temp_cache->cbo_stats,
            sizeof(cbo_stats_table_t)) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cbo_alloc_temp_columns_stats(session, entity, memory, temp_cache->cbo_stats) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    if (cbo_alloc_temp_index_stats(session, entity, memory, temp_cache->cbo_stats) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

status_t cbo_alloc_temp_table_stats(knl_session_t *session, dc_entity_t *entity, knl_temp_cache_t *temp_cache,
    bool32 is_dynamic)
{
    if (STATS_MANUAL_SESSION_GTT(entity->type, entity->entry->id, is_dynamic)) {
        memory_context_t *memory = entity->memory;

        if (temp_cache != NULL) {
            knl_free_temp_cache_memory(temp_cache);
        }

        if (entity->cbo_table_stats == NULL) {
            if (cbo_alloc_mem(session, memory, (void **)&entity->cbo_table_stats,
                sizeof(cbo_stats_table_t)) != CT_SUCCESS) {
                return CT_ERROR;
            }

            if (cbo_alloc_temp_columns_stats(session, entity, memory, entity->cbo_table_stats) != CT_SUCCESS) {
                return CT_ERROR;
            }
        }

        if (cbo_alloc_temp_index_stats(session, entity, memory, entity->cbo_table_stats) != CT_SUCCESS) {
            return CT_ERROR;
        }

        temp_cache->cbo_stats = entity->cbo_table_stats;

        return CT_SUCCESS;
    }

    return cbo_alloc_gst_dynamic_stats(session, entity, temp_cache);
}

void cbo_set_table_stats(cbo_stats_table_t *stats, knl_cursor_t *cursor)
{
    stats->rows = *(uint32 *)CURSOR_COLUMN_DATA(cursor, TABLE_ROWS);
    stats->blocks = *(uint32 *)CURSOR_COLUMN_DATA(cursor, TABLE_BLOCKS);
    stats->empty_blocks = *(uint32 *)CURSOR_COLUMN_DATA(cursor, TABLE_EMPTY_BLOCK);
    stats->avg_row_len = *(int64 *)CURSOR_COLUMN_DATA(cursor, TABLE_AVG_ROW_LEN);
    stats->sample_size = *(uint32 *)CURSOR_COLUMN_DATA(cursor, TABLE_SAMPLE_SIZE);
    stats->analyse_time = *(date_t *)CURSOR_COLUMN_DATA(cursor, TABLE_ANALYZE_TIME);
    stats->part_id = CT_INVALID_ID32;
}

static status_t cbo_load_table_stats(knl_session_t *session, knl_cursor_t *cursor, dc_entity_t *entity,
    stats_load_info_t load_info)
{
    cbo_stats_table_t *stats = NULL;
    uint32 uid = entity->table.desc.uid;
    uint32 tid = entity->table.desc.id;
    date_t analyse_time;
    errno_t ret;

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TABLE_ID, IX_SYS_TABLE_002_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&uid,
                     sizeof(uint32), IX_COL_SYS_TABLE_002_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&tid,
                     sizeof(uint32), IX_COL_SYS_TABLE_002_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (cursor->eof) {
        return CT_SUCCESS;
    }

    if (CURSOR_COLUMN_SIZE(cursor, TABLE_ANALYZE_TIME) == CT_NULL_VALUE_LEN) {
        return cbo_load_table_defaut_stats(session, cursor, entity, load_info);
    }

    analyse_time = *(date_t *)CURSOR_COLUMN_DATA(cursor, TABLE_ANALYZE_TIME);
    if (analyse_time == 0) {
        return cbo_load_table_defaut_stats(session, cursor, entity, load_info);
    }

    stats = entity->cbo_table_stats;

    if (stats == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(cbo_stats_table_t),
                         (void **)&stats) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        ret = memset_sp(stats, sizeof(cbo_stats_table_t), 0, sizeof(cbo_stats_table_t));
        knl_securec_check(ret);
        stats->max_col_id = CT_INVALID_ID32;
        stats->is_ready = CT_FALSE;
        entity->cbo_table_stats = stats;
    }

    stats->table_id = entity->table.desc.id;
    bool32 is_part = *(bool32 *)CURSOR_COLUMN_DATA(cursor, TABLE_PARTITIONED);
    cbo_set_table_stats(stats, cursor);

    if (is_part) {
        if (cbo_load_part_table_stats(session, entity, load_info) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    // load table indexs statistics info
    if (cbo_load_table_indexs_stats(session, cursor, entity) != CT_SUCCESS) {
        return CT_ERROR;
    }

    // load table columns statistics info,
    // for part table columns statistics storage in every part stats(cbo_stats_table_part_t)
    if (cbo_load_table_columns_stats(session, cursor, entity) != CT_SUCCESS) {
        return CT_ERROR;
    }

    stats->is_ready = CT_TRUE;
    stats->global_stats_exist = CT_TRUE;
    entity->stat_exists = CT_TRUE;

    if (analyse_time == CT_INVALID_ID64) {
        entity->stats_locked = CT_TRUE;
    } else {
        entity->stats_locked = CT_FALSE;
    }
   
    return CT_SUCCESS;
}

static status_t cbo_alloc_table_subpart_stats(knl_session_t *session, dc_entity_t *entity, uint32 part_pos)
{
    cbo_stats_table_t *global_stats = entity->cbo_table_stats;
    cbo_stats_table_t *subpart_stats = NULL;
    uint32 gid = part_pos / PART_GROUP_SIZE;
    uint32 eid = part_pos % PART_GROUP_SIZE;

    if (cbo_alloc_subpart_table_group(session, entity, global_stats, gid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cbo_table_part_group_t *part_group = global_stats->subpart_groups[gid];

    if (part_group->entity[eid] == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(cbo_stats_table_t),
            (void **)&subpart_stats) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        uint32 table_size = sizeof(cbo_stats_table_t);
        errno_t ret = memset_sp(subpart_stats, table_size, 0, table_size);
        knl_securec_check(ret);
        subpart_stats->is_ready = CT_FALSE;
        part_group->entity[eid] = subpart_stats;
    }

    return CT_SUCCESS;
}

static void cbo_set_subpart_table_stats(cbo_stats_table_t *subpart_stats, knl_cursor_t *cursor)
{
    subpart_stats->table_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLESUBPART_COL_TABLE_ID);
    subpart_stats->part_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLESUBPART_COL_PARENT_PART_ID);
    subpart_stats->subpart_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLESUBPART_COL_SUB_PART_ID);
    subpart_stats->rows = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLESUBPART_COL_ROWCNT);
    subpart_stats->blocks = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLESUBPART_COL_BLKCNT);
    subpart_stats->empty_blocks = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLESUBPART_COL_EMPCNT);
    subpart_stats->avg_row_len = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLESUBPART_COL_AVGRLN);
    subpart_stats->sample_size = *(uint32 *)CURSOR_COLUMN_DATA(cursor, SYS_TABLESUBPART_COL_SAMPLESIZE);
    subpart_stats->analyse_time = *(date_t *)CURSOR_COLUMN_DATA(cursor, SYS_TABLESUBPART_COL_ANALYZETIME);
}

status_t cbo_load_subpart_table_stats(knl_session_t *session, dc_entity_t *entity, table_part_t *table_subpart,
    uint32 part_pos)
{
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SUB_TABLE_PARTS_ID, IX_SYS_TABLEPART001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &table_subpart->desc.uid,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER,
        &table_subpart->desc.table_id, sizeof(uint32), IX_COL_SYS_TABLESUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER,
        &table_subpart->desc.parent_partid, sizeof(uint32), IX_COL_SYS_TABLESUBPART001_PARENT_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER,
        &table_subpart->desc.part_id, sizeof(uint32), IX_COL_SYS_TABLESUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        return CT_SUCCESS;
    }
    CM_RESTORE_STACK(session->stack);

    if (CURSOR_COLUMN_SIZE(cursor, SYS_TABLESUBPART_COL_ANALYZETIME) == CT_NULL_VALUE_LEN) {
        return cbo_alloc_table_subpart_stats(session, entity, part_pos);
    }

    if (cbo_alloc_table_subpart_stats(session, entity, part_pos) != CT_SUCCESS) {
        return CT_ERROR;
    }

    cbo_stats_table_t *subpart_stats = CBO_GET_SUBTABLE_PART(entity->cbo_table_stats, part_pos);

    cbo_set_subpart_table_stats(subpart_stats, cursor);
    cbo_find_max_subpart(entity);
    return CT_SUCCESS;
}

status_t cbo_delay_load_subpart_stats(knl_session_t *session, dc_entity_t *entity, table_part_t *table_subpart, uint32 part_pos)
{
    CM_SAVE_STACK(session->stack);
    knl_cursor_t *cursor = knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_SUB_TABLE_PARTS_ID, IX_SYS_TABLEPART001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &table_subpart->desc.uid,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &table_subpart->desc.table_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &table_subpart->desc.parent_partid,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_PARENT_PART_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &table_subpart->desc.part_id,
        sizeof(uint32), IX_COL_SYS_TABLESUBPART001_SUB_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        return CT_SUCCESS;
    }

    if (CURSOR_COLUMN_SIZE(cursor, SYS_TABLESUBPART_COL_ANALYZETIME) == CT_NULL_VALUE_LEN) {
        CM_RESTORE_STACK(session->stack);
        return cbo_alloc_table_subpart_stats(session, entity, part_pos);
    }

    if (cbo_alloc_table_subpart_stats(session, entity, part_pos) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }
    CM_RESTORE_STACK(session->stack);
    cbo_stats_table_t *subpart_stats = CBO_GET_SUBTABLE_PART(entity->cbo_table_stats, part_pos);

    cbo_set_subpart_table_stats(subpart_stats, cursor);

    if (cbo_load_table_subpart_columns(session, entity, subpart_stats) != CT_SUCCESS) {
        return CT_ERROR;
    }

    subpart_stats->is_ready = CT_TRUE;
    subpart_stats->stats_version = entity->cbo_table_stats->stats_version;
    cbo_find_max_subpart(entity);
    return CT_SUCCESS;
}

status_t cbo_direct_load_subparts_stats(knl_session_t *session, dc_entity_t *entity, cbo_stats_table_t *part_stats,
    table_part_t *table_compart)
{
    table_part_t *table_subpart = NULL;
    table_t *table = &entity->table;

    for (uint32 i = 0; i < table_compart->desc.subpart_cnt; i++) {
        table_subpart = PART_GET_SUBENTITY(table->part_table, table_compart->subparts[i]);
        if (table_subpart == NULL) {
            continue;
        }
        uint32 part_pos = table_compart->subparts[i];
        if (cbo_load_subpart_table_stats(session, entity, table_subpart, part_pos) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

#define dc_has_cbo_by_type(type) ((type) >= DICT_TYPE_TABLE && (type) <= DICT_TYPE_TABLE_NOLOGGING)

status_t cbo_load_entity_statistics(knl_session_t *session, dc_entity_t *entity, stats_load_info_t load_info)
{
    knl_cursor_t *cursor = NULL;

    cm_latch_x(&entity->cbo_latch, session->id, NULL);
    if (dc_has_cbo_by_type(entity->type)) {
        CM_SAVE_STACK(session->stack);

        cursor = knl_push_cursor(session);
        // load table statistics info
        if (cbo_load_table_stats(session, cursor, entity, load_info) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            cm_unlatch(&entity->cbo_latch, NULL);
            return CT_ERROR;
        }

        entity->stats_version = 0;
        entity->cbo_table_stats->stats_version = entity->stats_version;
        CM_RESTORE_STACK(session->stack);
    }
    cm_unlatch(&entity->cbo_latch, NULL);
    return CT_SUCCESS;
}

status_t cbo_refresh_statistics(knl_session_t *session, dc_entity_t *entity, stats_load_info_t load_info)
{
    knl_cursor_t *cursor = NULL;
    dc_entry_t    *entry = entity->entry;
    dc_user_t     *user = NULL;

    if (dc_open_user_by_id(session, entry->uid, &user) != CT_SUCCESS) {
        return CT_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    cm_latch_x(&entity->cbo_latch, session->id, NULL);
    cursor = knl_push_cursor(session);
    if (cbo_load_table_stats(session, cursor, entity, load_info) != CT_SUCCESS) {
        if (entity->stat_exists) {
            entity->stat_exists = CT_FALSE;
        }
        CT_LOG_RUN_WAR("[DC] could not load table statistics %s.%s.",
                       user->desc.name, entry->name);
        cm_unlatch(&entity->cbo_latch, NULL);
        CM_RESTORE_STACK(session->stack);
        return CT_SUCCESS;
    }

    if (entity->stat_exists) {
        entity->stats_version++;
    } else {
        entity->stat_exists = CT_TRUE;
        entity->stats_version = 0;
    }

    entity->cbo_table_stats->stats_version = entity->stats_version;
    cm_unlatch(&entity->cbo_latch, NULL);
    CM_RESTORE_STACK(session->stack);

    return CT_SUCCESS;
}

cbo_stats_table_t *knl_get_cbo_table(knl_handle_t session, dc_entity_t *entity)
{
    table_t *table = &entity->table;
    
    if (TABLE_IS_TEMP(table->desc.type)) {
        /* ltt: local temporary table
         * gst: global session temporary table
         * gtt: global transaction temporary table
         * 1 For all temp table(ltt,gst,gtt) get cbo_stats of temp cache first
         * 2 if temp cache is null, it means temp table has not opened, we get cbo_stats of entity
         * 3 if cbo_stats is null, temp table stats will generate by dynamic sample
         */
        knl_temp_cache_t *temp_cache = knl_get_temp_cache(session, table->desc.uid, table->desc.id);

        if (temp_cache != NULL) {
            return temp_cache->cbo_stats;
        }

        /* Manual stats for GTT will be saved in entity, if exists, return it */
        if (!IS_LTT_BY_ID(table->desc.id) &&
            (entity->cbo_table_stats->rows != 0 || entity->cbo_table_stats->blocks != 0)) {
            return entity->cbo_table_stats;
        }
    }

    return entity->cbo_table_stats;
}

cbo_stats_column_t *knl_get_cbo_column(knl_handle_t session, dc_entity_t *entity, uint32 col_id)
{
    cbo_stats_table_t *cbo_stats = knl_get_cbo_table(session, entity);

    if (cbo_stats == NULL) {
        return NULL;
    }

    if (cbo_stats->max_col_id != CT_INVALID_ID32 && cbo_stats->max_col_id < col_id) {
        return NULL;
    }

    knl_column_t *dc_column = dc_get_column(entity, col_id);
    cbo_stats_column_t *cbo_column = NULL;

    if (cbo_stats->col_stats_allowed) {
        if (!cbo_stats->col_loading) {
            cbo_column = cbo_get_column_stats(cbo_stats, col_id);
        } else {
            cm_latch_s(&dc_column->cbo_col_latch, 0, CT_FALSE, NULL);
            cbo_column = cbo_get_column_stats(cbo_stats, col_id);
            cm_unlatch(&dc_column->cbo_col_latch, NULL);
        }
    }

    return cbo_column;
}

cbo_stats_index_t *knl_get_cbo_index(knl_handle_t session, dc_entity_t *entity, uint32 index_id)
{
    cbo_stats_index_t *index = NULL;
    cbo_stats_table_t *cbo_stats = knl_get_cbo_table(session, entity);
    
    if (cbo_stats != NULL) {
        for (uint32 pos = 0; pos < cbo_stats->index_count; pos++) {
            index = cbo_stats->indexs[pos];
            if (index != NULL && index->id == index_id) {
                return index;
            }
        }
    }

    return NULL;
}

cbo_stats_table_t *knl_get_cbo_subpart_table(knl_handle_t handle, dc_entity_t *entity, uint32 part_no, uint32 subpart_no)
{
    cbo_stats_table_t *global_stats = entity->cbo_table_stats;
    cbo_stats_table_t *parent_stats = NULL;
    cbo_stats_table_t *sub_stats = NULL;

    if (global_stats != NULL && part_no < CT_INVALID_ID32) {
        parent_stats = cbo_get_table_part_stats(global_stats, part_no);
        if (parent_stats == NULL) {
            return global_stats->tab_part_default;
        }

        table_part_t *parent_part = TABLE_GET_PART(&entity->table, part_no);
        sub_stats = cbo_get_sub_part_stats(global_stats, parent_part->subparts[subpart_no]);
        if (sub_stats == NULL) {
            return global_stats->tab_part_default;
        }

        if (sub_stats->is_ready && sub_stats->stats_version == global_stats->stats_version) {
            return sub_stats;
        }

        /*
        * to load table part statistics , when part_table is not ready or its version is not newest.
        */
        cm_latch_x(&entity->cbo_latch, 0, NULL);

        if (sub_stats->is_ready && sub_stats->stats_version == global_stats->stats_version) {
            cm_unlatch(&entity->cbo_latch, NULL);
            return sub_stats;
        }

        table_part_t *sub_part = PART_GET_SUBENTITY(entity->table.part_table, parent_part->subparts[subpart_no]);

        if (cbo_delay_load_subpart_stats((knl_session_t *)handle, entity, sub_part,
            parent_part->subparts[subpart_no]) != CT_SUCCESS) {
            cm_unlatch(&entity->cbo_latch, NULL);
            return NULL;
        }

        cm_unlatch(&entity->cbo_latch, NULL);
    }

    return sub_stats;
}

cbo_stats_table_t *knl_get_cbo_part_table(knl_handle_t handle, dc_entity_t *entity, uint32 part_no)
{
    cbo_stats_table_t *cbo_stats = entity->cbo_table_stats;
    cbo_stats_table_t *part_table = NULL;
    stats_load_info_t load_info;

    if (cbo_stats != NULL && part_no < CT_INVALID_ID32) {
        part_table = cbo_get_table_part_stats(cbo_stats, part_no);
        if (part_table == NULL) {
            return cbo_stats->tab_part_default;
        }

        if (part_table->is_ready && part_table->stats_version == cbo_stats->stats_version) {
            return part_table;
        }

        /*
         * to load table part statistics , when part_table is not ready or its version is not newest.
         */
        cm_latch_x(&entity->cbo_latch, 0, NULL);

        if (part_table->is_ready && part_table->stats_version == cbo_stats->stats_version) {
            cm_unlatch(&entity->cbo_latch, NULL);
            return part_table;
        }
        
        stats_set_load_info(&load_info, entity, CT_FALSE, CT_INVALID_ID32);
        if (cbo_load_table_part_stats((knl_session_t *)handle, entity, part_no, load_info, CT_TRUE) != CT_SUCCESS) {
            cm_unlatch(&entity->cbo_latch, NULL);
            return NULL;
        }

        cm_unlatch(&entity->cbo_latch, NULL);
    }

    return part_table;
}

cbo_stats_column_t *knl_get_cbo_subpart_column(knl_handle_t handle, dc_entity_t *entity, uint32 part_no, uint32 col_id,
                                               uint32 subpart_no)
{
    cbo_stats_table_t *global_cbo_stats = entity->cbo_table_stats;
    cbo_stats_table_t *parent_stats = NULL;
    cbo_stats_table_t *sub_stats = NULL;
    cbo_stats_column_t *cbo_column = NULL;

    if (global_cbo_stats != NULL && part_no < CT_INVALID_ID32) {
        parent_stats = cbo_get_table_part_stats(global_cbo_stats, part_no);
        if (parent_stats == NULL) {
            // run log
            return cbo_column;
        }

        table_part_t *parent_part = TABLE_GET_PART(&entity->table, part_no);
        sub_stats = cbo_get_sub_part_stats(global_cbo_stats, parent_part->subparts[subpart_no]);
        if (sub_stats != NULL && sub_stats->max_col_id >= col_id) {
            if (sub_stats->is_ready && sub_stats->stats_version == global_cbo_stats->stats_version &&
                sub_stats->col_stats_allowed) {
                if (!sub_stats->col_loading) {
                    cbo_column = cbo_get_column_stats(sub_stats, col_id);
                    return cbo_column;
                }
                knl_column_t *dc_column = dc_get_column(entity, col_id);
                cm_latch_s(&dc_column->cbo_col_latch, 0, CT_FALSE, NULL);
                cbo_column = cbo_get_column_stats(sub_stats, col_id);
                cm_unlatch(&dc_column->cbo_col_latch, NULL);
                return cbo_column;
            }
            /*
            * to load table part statistics , when part_table is not ready or its version is not newest.
            */
            cm_latch_x(&entity->cbo_latch, 0, NULL);
            if (sub_stats->is_ready && sub_stats->stats_version == global_cbo_stats->stats_version) {
                cbo_column = cbo_get_column_stats(sub_stats, col_id);
                cm_unlatch(&entity->cbo_latch, NULL);
                return cbo_column;
            }

            table_part_t *sub_part = PART_GET_SUBENTITY(entity->table.part_table, parent_part->subparts[subpart_no]);
            if (cbo_delay_load_subpart_stats((knl_session_t *)handle, entity, sub_part,
                parent_part->subparts[subpart_no]) != CT_SUCCESS) {
                cm_unlatch(&entity->cbo_latch, NULL);
                return NULL;
            }

            cbo_column = cbo_get_column_stats(sub_stats, col_id);
            cm_unlatch(&entity->cbo_latch, NULL);
            return cbo_column;
        }
    }

    return cbo_column;
}

cbo_stats_column_t *knl_get_cbo_part_column(knl_handle_t handle, dc_entity_t *entity, uint32 part_no, uint32 col_id)
{
    cbo_stats_table_t *global_cbo_stats = entity->cbo_table_stats;
    cbo_stats_table_t *part_stats = NULL;
    cbo_stats_column_t *cbo_column = NULL;
    stats_load_info_t load_info;
    
    if (global_cbo_stats != NULL && part_no < CT_INVALID_ID32) {
        part_stats = cbo_get_table_part_stats(global_cbo_stats, part_no);
        if (part_stats != NULL && part_stats->max_col_id >= col_id) {
            if (part_stats->is_ready && part_stats->stats_version == global_cbo_stats->stats_version &&
                part_stats->col_stats_allowed) {
                if (!part_stats->col_loading) {
                    cbo_column = cbo_get_column_stats(part_stats, col_id);
                    return cbo_column;
                }

                knl_column_t *dc_column = dc_get_column(entity, col_id);
                cm_latch_s(&dc_column->cbo_col_latch, 0, CT_FALSE, NULL);
                cbo_column = cbo_get_column_stats(part_stats, col_id);
                cm_unlatch(&dc_column->cbo_col_latch, NULL);
                return cbo_column;
            }

            /*
             * to load table part statistics , when part_table is not ready or its version is not newest.
             */
            cm_latch_x(&entity->cbo_latch, 0, NULL);
            if (part_stats->is_ready && part_stats->stats_version == global_cbo_stats->stats_version) {
                cbo_column = cbo_get_column_stats(part_stats, col_id);
                cm_unlatch(&entity->cbo_latch, NULL);
                return cbo_column;
            }
            stats_set_load_info(&load_info, entity, CT_FALSE, CT_INVALID_ID32);
            if (cbo_load_table_part_stats((knl_session_t *)handle, entity, part_no, load_info, CT_TRUE) != CT_SUCCESS) {
                cm_unlatch(&entity->cbo_latch, NULL);
                return NULL;
            }

            cbo_column = cbo_get_column_stats(part_stats, col_id);
            cm_unlatch(&entity->cbo_latch, NULL);
            return cbo_column;
        }
    }

    return cbo_column;
}

cbo_stats_index_t *knl_get_cbo_subpart_index(knl_handle_t handle, dc_entity_t *entity, uint32 part_no, uint32 index_id,
                                             uint32 sub_part_no)
{
    cbo_stats_index_t *sub_part_index = NULL;
    cbo_stats_table_t *global_stats = entity->cbo_table_stats;
    bool32 need_load = CT_FALSE;

    if (global_stats != NULL && part_no < CT_INVALID_ID32) {
        sub_part_index = cbo_find_sub_index_stats(entity, index_id, part_no, sub_part_no, &need_load);
        if (sub_part_index == NULL || !need_load) {
            return sub_part_index;
        }

        if (sub_part_index->is_ready && sub_part_index->stats_version == global_stats->stats_version) {
            return sub_part_index;
        }

        cm_latch_x(&entity->cbo_latch, 0, NULL);
        if (sub_part_index->is_ready && sub_part_index->stats_version == global_stats->stats_version) {
            cm_unlatch(&entity->cbo_latch, NULL);
            return sub_part_index;
        }

        /*
        * to load index part statistics , when part_index is not ready or its version is not newest.
        */
        if (cbo_load_index_subpart_stats((knl_session_t *)handle, entity, part_no, index_id, sub_part_no) != CT_SUCCESS) {
            cm_unlatch(&entity->cbo_latch, NULL);
            return NULL;
        }
        cm_unlatch(&entity->cbo_latch, NULL);
    }

    return sub_part_index;
}

cbo_stats_index_t *knl_get_cbo_part_index(knl_handle_t handle, dc_entity_t *entity, uint32 part_no, uint32 index_id)
{
    cbo_stats_index_t *part_index = NULL;
    cbo_stats_table_t *cbo_stats = entity->cbo_table_stats;
    bool32 need_load = CT_FALSE;

    if (cbo_stats != NULL && part_no < CT_INVALID_ID32) {
        part_index = cbo_find_indexpart_stats(cbo_stats, index_id, part_no, &need_load);
        if (!need_load) {
            return part_index;
        }

        cm_latch_x(&entity->cbo_latch, 0, NULL);
        if (part_index->is_ready && part_index->stats_version == cbo_stats->stats_version) {
            cm_unlatch(&entity->cbo_latch, NULL);
            return part_index;
        }

        /*
        * to load index part statistics , when part_index is not ready or its version is not newest.
        */
        if (cbo_load_index_part_stats((knl_session_t *)handle, entity, part_no, index_id) != CT_SUCCESS) {
            cm_unlatch(&entity->cbo_latch, NULL);
            return NULL;
        }
        cm_unlatch(&entity->cbo_latch, NULL);
    }

    return part_index;
}

void knl_cbo_text2variant(dc_entity_t *entity, uint32 col_id, text_t *column, variant_t *ret_val)
{
    dec4_t dec;
    payload_t d2;
    uint32 len;
    knl_column_t *dc_column = dc_get_column(entity, col_id);

    ret_val->is_null = CT_FALSE;
    ret_val->type = dc_column->datatype;

    if (column->len == CT_NULL_VALUE_LEN) {
        ret_val->is_null = CT_TRUE;
        return;
    }

    switch (dc_column->datatype) {
        case CT_TYPE_BOOLEAN:
            ret_val->v_bool = *(bool32 *)column->str;
            break;
        case CT_TYPE_UINT32:
            ret_val->v_uint32 = *(uint32 *)column->str;
            ret_val->type     = CT_TYPE_UINT32;
            break;
        case CT_TYPE_SMALLINT:
        case CT_TYPE_INTEGER:
        case CT_TYPE_USMALLINT:
        case CT_TYPE_TINYINT:
        case CT_TYPE_UTINYINT:
            ret_val->v_int = *(int32 *)column->str;
            ret_val->type = CT_TYPE_INTEGER;
            break;
        case CT_TYPE_BIGINT:
            ret_val->v_bigint = *(int64 *)column->str;
            ret_val->type = CT_TYPE_BIGINT;
            break;
        case CT_TYPE_FLOAT:
        case CT_TYPE_REAL:
            ret_val->v_real = *(double *)column->str;
            ret_val->type = CT_TYPE_REAL;
            break;
        case CT_TYPE_UINT64:
        case CT_TYPE_NUMBER:
        case CT_TYPE_NUMBER3:
        case CT_TYPE_DECIMAL:
            dec = *(dec4_t*)column->str;
            len = column->len;
            if ((uint32)(cm_dec4_stor_sz(&dec)) > len) {
                cm_latch_s(&dc_column->cbo_col_latch, 0, CT_FALSE, NULL);
                dec = *(dec4_t*)column->str;
                len = column->len;
                cm_unlatch(&dc_column->cbo_col_latch, NULL);
            }

            (void)cm_dec_4_to_8(&ret_val->v_dec, &dec, len);
            ret_val->type = CT_TYPE_NUMBER;
            break;
        case CT_TYPE_NUMBER2:
            d2 = *(payload_t *)column->str;
            len = column->len;
            if (len > sizeof(payload_t)) {
                cm_latch_s(&dc_column->cbo_col_latch, 0, CT_FALSE, NULL);
                d2 = *(payload_t *)column->str;
                len = column->len;
                cm_unlatch(&dc_column->cbo_col_latch, NULL);
            }
            (void)cm_dec_2_to_8(&ret_val->v_dec, &d2, len);
            ret_val->type = CT_TYPE_NUMBER2;
            break;
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
        case CT_TYPE_DATETIME_MYSQL:
        case CT_TYPE_TIME_MYSQL:
        case CT_TYPE_DATE_MYSQL:
            ret_val->v_date = *(date_t *)column->str;
            break;
        case CT_TYPE_TIMESTAMP_TZ:
            ret_val->v_tstamp_tz = *(timestamp_tz_t *)column->str;
            break;
        case CT_TYPE_INTERVAL_DS:
            ret_val->v_itvl_ds = *(interval_ds_t *)column->str;
            break;
        case CT_TYPE_INTERVAL_YM:
            ret_val->v_itvl_ym = *(interval_ym_t *)column->str;
            break;
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
            ret_val->v_text = *column;
            break;
        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            ret_val->v_bin.bytes = (uint8*)column->str;
            ret_val->v_bin.size = column->len;
            break;
        default:
            ret_val->is_null = CT_TRUE;
            break;
    }
}

void knl_cache_cbo_text2variant(dc_entity_t *entity, uint32 col_id, text_t *column, cache_variant_t *ret_val)
{
    knl_column_t *dc_column = dc_get_column(entity, col_id);

    CT_LOG_DEBUG_INF("[Histgram ep_value Print] column_id:%u ",col_id);
    switch (dc_column->datatype) {
        case CT_TYPE_BOOLEAN:
            ret_val->v_bool = *(bool32 *)column->str;
            CT_LOG_DEBUG_INF("[Histgram ep_value Print]ep_value: %u",ret_val->v_bool);
            break;
        case CT_TYPE_UINT32:
            ret_val->v_uint32 = *(uint32 *)column->str;
            CT_LOG_DEBUG_INF("[Histgram ep_value Print]ep_value: %u",ret_val->v_uint32);
            break;
        case CT_TYPE_SMALLINT:
        case CT_TYPE_INTEGER:
        case CT_TYPE_USMALLINT:
        case CT_TYPE_TINYINT:
        case CT_TYPE_UTINYINT:
            ret_val->v_int = *(int32 *)column->str;
            CT_LOG_DEBUG_INF("[Histgram ep_value Print]ep_value: %d",ret_val->v_int);
            break;
        case CT_TYPE_UINT64:
            ret_val->v_ubigint = *(uint64 *)column->str;
            CT_LOG_DEBUG_INF("[Histgram ep_value Print]ep_value: %llu",ret_val->v_ubigint);
            break;
        case CT_TYPE_BIGINT:
            ret_val->v_bigint = *(int64 *)column->str;
            CT_LOG_DEBUG_INF("[Histgram ep_value Print]ep_value: %lld",ret_val->v_ubigint);
            break;
        case CT_TYPE_FLOAT:
        case CT_TYPE_REAL:
            ret_val->v_real = *(double *)column->str;
            CT_LOG_DEBUG_INF("[Histgram ep_value Print]ep_value: %lf",ret_val->v_real);
            break;
        default:
            break;
    }
}

static void cbo_set_part_table_stats(cbo_stats_table_t *part_stats, knl_cursor_t *cursor)
{
    part_stats->table_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, TABLE_PART_TABLE_ID);
    part_stats->part_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, TABLE_PART_ID);
    part_stats->subpart_id = CT_INVALID_ID32;
    part_stats->rows = *(uint32 *)CURSOR_COLUMN_DATA(cursor, TABLE_PART_ROWS);
    part_stats->blocks = *(uint32 *)CURSOR_COLUMN_DATA(cursor, TABLE_PART_BLOCKS);
    part_stats->empty_blocks = *(uint32 *)CURSOR_COLUMN_DATA(cursor, TABLE_PART_EMPTY_BLOCK);
    part_stats->avg_row_len = *(uint32 *)CURSOR_COLUMN_DATA(cursor, TABLE_PART_AVG_ROW_LEN);
    part_stats->sample_size = *(uint32 *)CURSOR_COLUMN_DATA(cursor, TABLE_PART_SAMPLE_SIZE);
    part_stats->analyse_time = *(date_t *)CURSOR_COLUMN_DATA(cursor, TABLE_PART_ANALYZE_TIME);
}

status_t cbo_load_table_part_stats(knl_session_t *session, dc_entity_t *entity, uint32 part_no,
    stats_load_info_t load_info, bool32 load_columns)
{
    table_t *table = &entity->table;
    knl_cursor_t *cursor = NULL;
    table_part_t *table_part = TABLE_GET_PART(table, part_no);
    cbo_stats_table_t *part_stats = NULL;
    date_t analyse_time;
    cbo_stats_table_t  *table_stats = entity->cbo_table_stats;
    bool32 is_subpart;

    if (table_part == NULL) {
        CT_LOG_RUN_INF("Load %s.%s the %d table part stats falied, it is not existed ",
                       entity->entry->user->desc.name, entity->table.desc.name, part_no);
        return CT_SUCCESS;
    }

    CM_SAVE_STACK(session->stack);
    cursor =  knl_push_cursor(session);
    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_TABLEPART_ID, IX_SYS_TABLEPART001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &table->desc.uid,
        sizeof(uint32), IX_COL_SYS_TABLEPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &table->desc.id,
        sizeof(uint32), IX_COL_SYS_TABLEPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &table_part->desc.part_id,
        sizeof(uint32), IX_COL_SYS_TABLEPART001_PART_ID);

    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        CT_LOG_RUN_INF("Load %s.%s the %d table part stats falied, it is not existed ",
                       entity->entry->user->desc.name, entity->table.desc.name, part_no);
        return CT_SUCCESS;
    }
    
    if (CURSOR_COLUMN_SIZE(cursor, TABLE_PART_ANALYZE_TIME) == CT_NULL_VALUE_LEN) {
        CM_RESTORE_STACK(session->stack);
        return cbo_alloc_table_part_default(session, entity, table_stats, part_no);
    }

    analyse_time = *(date_t *)CURSOR_COLUMN_DATA(cursor, TABLE_PART_ANALYZE_TIME);
    if (analyse_time == 0) {
        CM_RESTORE_STACK(session->stack);
        return cbo_alloc_table_part_default(session, entity, table_stats, part_no);
    }

    if (cbo_alloc_table_part_stats(session, entity, table_stats, part_no) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    part_stats = CBO_GET_TABLE_PART(table_stats, part_no);

    // load table parts statistics info
    cbo_set_part_table_stats(part_stats, cursor);
    is_subpart = IS_PARENT_TABPART(&table_part->desc);
   
    if (load_columns) {
        if (cbo_load_table_part_columns(session, entity, part_stats, is_subpart) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            CT_LOG_RUN_INF("Load %s.%s the %d table part columns stats falied",
                           entity->entry->user->desc.name, entity->table.desc.name, part_no);
            return CT_ERROR;
        }

        part_stats->is_ready = CT_TRUE;
        part_stats->stats_version = table_stats->stats_version;
    }
   
    CM_RESTORE_STACK(session->stack);

    cbo_set_max_row_part(table_stats, part_stats, part_no);

    if (is_subpart && load_info.load_subpart) {
        if (cbo_direct_load_subparts_stats(session, entity, part_stats, table_part) != CT_SUCCESS) {
            return CT_ERROR;
        }
    }

    return CT_SUCCESS;
}

static void cbo_set_part_index_stats(cbo_stats_index_t *part_stats, knl_cursor_t *cursor)
{
    part_stats->id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, INDEX_PART_IDX_ID);
    part_stats->part_id = *(uint32 *)CURSOR_COLUMN_DATA(cursor, INDEX_PART_ID);
    part_stats->blevel = *(uint32 *)CURSOR_COLUMN_DATA(cursor, INDEX_PART_BLEVEL);
    part_stats->leaf_blocks = *(uint32 *)CURSOR_COLUMN_DATA(cursor, INDEX_PART_LEVEL_BLOCKS);
    part_stats->distinct_keys = *(uint32 *)CURSOR_COLUMN_DATA(cursor, INDEX_PART_DISTINCT_KEYS);
    part_stats->avg_leaf_key = *(double *)CURSOR_COLUMN_DATA(cursor, INDEX_PART_AVG_LEAF_BLOCKS_PER_KEY);
    part_stats->avg_data_key = *(double *)CURSOR_COLUMN_DATA(cursor, INDEX_PART_AVG_DATA_BLOCKS_PER_KEY);
    part_stats->empty_leaf_blocks = *(uint32 *)CURSOR_COLUMN_DATA(cursor, INDEX_PART_EMPTY_LEAF_BLOCKS);
    part_stats->clustering_factor = *(uint32 *)CURSOR_COLUMN_DATA(cursor, INDEX_PART_CLUSTER_FACTOR);
    part_stats->comb_cols_2_ndv = *(uint32 *)CURSOR_COLUMN_DATA(cursor, INDEX_PART_COMB_2_NDV);
    part_stats->comb_cols_3_ndv = *(uint32 *)CURSOR_COLUMN_DATA(cursor, INDEX_PART_COMB_3_NDV);
    part_stats->comb_cols_4_ndv = *(uint32 *)CURSOR_COLUMN_DATA(cursor, INDEX_PART_COMB_4_NDV);
    part_stats->analyse_time = *(date_t *)CURSOR_COLUMN_DATA(cursor, INDEX_PART_ANALYZE_TIME);
}

status_t cbo_load_index_part_stats(knl_session_t *session, dc_entity_t *entity, uint32 part_no, uint32 index_id)
{
    table_t *table = &entity->table;
    index_t *idx = NULL;
    index_part_t *index_part = NULL;
    knl_cursor_t *cursor = NULL;
    cbo_stats_table_t  *table_stats = entity->cbo_table_stats;
    cbo_stats_index_t  *index_stats = NULL;
    cbo_stats_index_t  *part_stats = NULL;

    for (uint32 i = 0; i < table->index_set.count; i++) {
        idx = table->index_set.items[i];
        if (idx->desc.id == index_id) {
            break;
        }
    }

    index_part = INDEX_GET_PART(idx, part_no);
    if (index_part == NULL) {
        return CT_SUCCESS;
    }
    index_stats = entity->cbo_table_stats->indexs[idx->desc.slot];
    CM_SAVE_STACK(session->stack);

    cursor = knl_push_cursor(session);

    knl_open_sys_cursor(session, cursor, CURSOR_ACTION_SELECT, SYS_INDEXPART_ID, IX_SYS_INDEXPART001_ID);
    knl_init_index_scan(cursor, CT_TRUE);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &table->desc.uid,
        sizeof(uint32), IX_COL_SYS_INDEXPART001_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &table->desc.id,
        sizeof(uint32), IX_COL_SYS_INDEXPART001_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &idx->desc.id,
        sizeof(uint32), IX_COL_SYS_INDEXPART001_INDEX_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, &index_part->desc.part_id,
        sizeof(uint32), IX_COL_SYS_INDEXPART001_PART_ID);
    
    if (knl_fetch(session, cursor) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    if (cursor->eof) {
        CM_RESTORE_STACK(session->stack);
        return CT_SUCCESS;
    }

    if (CURSOR_COLUMN_SIZE(cursor, INDEX_PART_ANALYZE_TIME) == CT_NULL_VALUE_LEN) {
        CM_RESTORE_STACK(session->stack);
        return cbo_alloc_index_part_default(session, entity, index_stats, part_no);
    }

    date_t analyse_time = *(date_t *)CURSOR_COLUMN_DATA(cursor, INDEX_PART_ANALYZE_TIME);
    if (analyse_time == 0) {
        CM_RESTORE_STACK(session->stack);
        return cbo_alloc_index_part_default(session, entity, index_stats, part_no);
    }

    if (cbo_alloc_index_part_stats(session, entity, index_stats, part_no) != CT_SUCCESS) {
        CM_RESTORE_STACK(session->stack);
        return CT_ERROR;
    }

    // load index statistics info
    part_stats = CBO_GET_INDEX_PART(index_stats, part_no);

    cbo_set_part_index_stats(part_stats, cursor);

    part_stats->is_ready = CT_TRUE;
    part_stats->stats_version = table_stats->stats_version;

    CM_RESTORE_STACK(session->stack);
    knl_part_locate_t part_loc;
    part_loc.part_no = part_no;
    part_loc.subpart_no = CT_INVALID_ID32;
    dc_calc_index_empty_size(session, entity, idx->desc.slot, part_loc, part_stats->empty_leaf_blocks);
    return CT_SUCCESS;
}

stats_table_mon_t *knl_cbo_get_table_mon(knl_handle_t session, dc_entity_t *entity)
{
    table_t *table = &entity->table;
    stats_table_mon_t *table_mon = NULL;

    if (TABLE_IS_TEMP(table->desc.type)) {
        /* if manual stats for session gtt exists, dynamic stats will not happen */
        if (!IS_LTT_BY_ID(table->desc.id) &&
            (entity->cbo_table_stats->rows != 0 || entity->cbo_table_stats->blocks != 0)) {
            return NULL;
        }

        knl_temp_cache_t *temp_cache = knl_get_temp_cache(session, table->desc.uid, table->desc.id);
        if (temp_cache == NULL) {
            return NULL;
        }

        table_mon = &temp_cache->table_smon;
    } else {
        if (entity->entry->appendix != NULL) {
            table_mon = &entity->entry->appendix->table_smon;
        }
    }

    return table_mon;
}