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
 * ostat_common.c
 *
 *
 * IDENTIFICATION
 * src/kernel/statistics/ostat_common.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_common_module.h"
#include "ostat_common.h"
#include "cm_decimal.h"

index_t *cbo_find_part_index_entity(dc_entity_t *entity, uint32 idx_id)
{
    index_t *idx = NULL;
    bool32 is_found = CT_FALSE;

    for (uint32 pos = 0; pos < entity->table.index_set.count; pos++) {
        idx = entity->table.index_set.items[pos];
        if (idx == NULL || idx->desc.id != idx_id) {
            continue;
        }

        if (idx->desc.parted) {
            is_found = CT_TRUE;
            break;
        } else {
            return idx;
        }
    }

    if (!is_found) {
        return NULL;
    }

    return idx;
}

cbo_stats_index_t *cbo_find_sub_index_stats(dc_entity_t *entity, uint32 idx_id, uint32 part_no, uint32 sub_no,
    bool32 *need_load)
{
    cbo_stats_table_t *cbo_stats = entity->cbo_table_stats;
    cbo_stats_index_t *cbo_index = NULL;
    index_t *idx = cbo_find_part_index_entity(entity, idx_id);
    bool32 is_found = CT_FALSE;

    if (idx == NULL) {
        return NULL;
    }
 
    for (uint32 i = 0; i < cbo_stats->index_count; i++) {
        cbo_index = cbo_stats->indexs[i];

        if (cbo_index == NULL || cbo_index->id != idx_id) {
            continue;
        }

        if (cbo_index->is_part) {
            is_found = CT_TRUE;
            break;
        } else {
            return cbo_index;
        }
    }

    if (!is_found || cbo_index->subpart_index_groups == NULL) {
        return NULL;
    }

    index_part_t *index_part = INDEX_GET_PART(idx, part_no);
    uint32 gid = index_part->subparts[sub_no] / PART_GROUP_SIZE;
    cbo_index_part_group_t *group = cbo_index->subpart_index_groups[gid];
    if (group == NULL) {
        return NULL;
    }

    cbo_stats_index_t *subpart_stats = CBO_GET_SUBINDEX_PART(cbo_index, index_part->subparts[sub_no]);
    if (subpart_stats == NULL) {
        return cbo_index->idx_part_default;
    }

    *need_load = CT_TRUE;
    return subpart_stats;
}

cbo_stats_table_t *cbo_get_sub_part_stats(cbo_stats_table_t *cbo_stats, uint32 id)
{
    cbo_stats_table_t *sub_stats = NULL;
    uint32 gid = id / PART_GROUP_SIZE;
    cbo_table_part_group_t *group = cbo_stats->subpart_groups[gid];

    if (group == NULL) {
        return NULL;
    }

    sub_stats = CBO_GET_SUBTABLE_PART(cbo_stats, id);
    return sub_stats;
}

cbo_stats_table_t *cbo_get_table_part_stats(cbo_stats_table_t *cbo_stats, uint32 id)
{
    cbo_stats_table_t *part_stats = NULL;

    part_stats = CBO_GET_TABLE_PART(cbo_stats, id);
    return part_stats;
}

status_t cbo_alloc_subpart_table_group(knl_session_t *session, dc_entity_t *entity, cbo_stats_table_t *table_stats,
    uint32 gid)
{
    int32 ret;
    cbo_table_part_group_t *part_group = table_stats->subpart_groups[gid];

    if (part_group == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(cbo_table_part_group_t),
            (void **)&part_group) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        ret = memset_sp(part_group, sizeof(cbo_table_part_group_t), 0, sizeof(cbo_table_part_group_t));
        knl_securec_check(ret);
        table_stats->subpart_groups[gid] = part_group;
    }

    return CT_SUCCESS;
}

status_t cbo_alloc_part_table_group(knl_session_t *session, dc_entity_t *entity, cbo_stats_table_t *table_stats,
    uint32 gid)
{
    int32 ret;
    cbo_table_part_group_t *part_group = table_stats->part_groups[gid];

    if (part_group == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(cbo_table_part_group_t),
            (void **)&part_group) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        ret = memset_sp(part_group, sizeof(cbo_table_part_group_t), 0, sizeof(cbo_table_part_group_t));
        knl_securec_check(ret);
        table_stats->part_groups[gid] = part_group;
    }

    return CT_SUCCESS;
}

status_t cbo_alloc_subpart_index_group(knl_session_t *session, dc_entity_t *entity, cbo_stats_index_t *index_stats,
    uint32 gid)
{
    int32 ret;
    cbo_index_part_group_t *part_group = index_stats->subpart_index_groups[gid];

    if (part_group == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(cbo_index_part_group_t),
            (void **)&part_group) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        ret = memset_sp(part_group, sizeof(cbo_index_part_group_t), 0, sizeof(cbo_index_part_group_t));
        knl_securec_check(ret);
        index_stats->subpart_index_groups[gid] = part_group;
    }

    return CT_SUCCESS;
}

status_t cbo_alloc_part_index_group(knl_session_t *session, dc_entity_t *entity, cbo_stats_index_t *index_stats, uint32 gid)
{
    int32 ret;
    cbo_index_part_group_t *part_group = index_stats->part_index_groups[gid];

    if (part_group == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(cbo_index_part_group_t),
            (void **)&part_group) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        ret = memset_sp(part_group, sizeof(cbo_index_part_group_t), 0, sizeof(cbo_index_part_group_t));
        knl_securec_check(ret);
        index_stats->part_index_groups[gid] = part_group;
    }

    return CT_SUCCESS;
}

status_t cbo_prepare_load_columns(knl_session_t *session, dc_entity_t *entity, cbo_stats_table_t *cbo_stats)
{
    uint32 col_count;
    memory_context_t *memory = entity->memory;
    uint32 ext_count;
    errno_t ret;

    col_count = entity->column_count;
    // when is wide table, col_count = 4096, sizeof(cbo_stats_column_t*)*col_count > page_size
    // we use segment array to store cbo_stats_column_t* pointer
    ext_count = CM_ALIGN_ANY(col_count, CBO_LIST_COUNT) / CBO_LIST_COUNT;
    knl_panic_log(ext_count <= CBO_EXTENT_COUNT, "extent count is more than the limit, panic info: "
                  "ext_count %u table %s", ext_count, entity->table.desc.name);
    if (cbo_stats->columns == NULL) {
        // ext_count <= 32, so sizeof(void *) * ext_count is smaller than max uint32 value
        if (dc_alloc_mem(&session->kernel->dc_ctx, memory, sizeof(void *) * ext_count,
            (void **)&cbo_stats->columns) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        ret = memset_sp(cbo_stats->columns, sizeof(void *) * ext_count, 0, sizeof(void *) * ext_count);
        knl_securec_check(ret);
    }

    for (uint32 i = 0; i < ext_count; i++) {
        if (cbo_stats->columns[i] != NULL) {
            continue;
        }

        if (dc_alloc_mem(&session->kernel->dc_ctx, memory, sizeof(void *) * CBO_LIST_COUNT,
            (void **)&cbo_stats->columns[i])) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        ret = memset_sp(cbo_stats->columns[i], sizeof(void *) * CBO_LIST_COUNT, 0, sizeof(void *) * CBO_LIST_COUNT);
        knl_securec_check(ret);
    }
    for (uint32 pos = 0; pos < entity->column_count; pos++) {
        cbo_stats_column_t *stats = get_cbo_stats_column(cbo_stats, pos);
        if (stats != NULL) {
            stats->analyse_time = 0;
        }
    }
    return CT_SUCCESS;
}

void cbo_set_max_row_subpart(dc_entity_t *entity, uint32 part_no, uint32 *max_rows)
{
    cbo_stats_table_t *cbo_stats = entity->cbo_table_stats;
    table_t *table = &entity->table;
    table_part_t *sub_part = NULL;
    table_part_t *parent_part = TABLE_GET_PART(table, part_no);

    for (uint32 j = 0; j < parent_part->desc.subpart_cnt; j++) {
        sub_part = PART_GET_SUBENTITY(table->part_table, parent_part->subparts[j]);
        if (sub_part == NULL) {
            continue;
        }
        uint32 pos = parent_part->subparts[j];
        uint32 gid = pos / PART_GROUP_SIZE;
        cbo_table_part_group_t *group = cbo_stats->subpart_groups[gid];
        if (group == NULL) {
            break;
        }

        cbo_stats_table_t *subpart_stats = cbo_get_sub_part_stats(cbo_stats, pos);

        if (subpart_stats == NULL) {
            continue;
        }

        if (*max_rows < subpart_stats->rows) {
            cbo_stats->max_subpart_info.part_no = part_no;
            cbo_stats->max_subpart_info.subpart_no = j;
            *max_rows = subpart_stats->rows;
        }
    }
}

void cbo_find_max_subpart(dc_entity_t *entity)
{
    cbo_stats_table_t *cbo_stats = entity->cbo_table_stats;
    table_t *table = &entity->table;
    uint32 max_rows = 0;
    table_part_t *parent_part = NULL;

    for (uint32 i = 0; i < table->part_table->desc.partcnt; i++) {
        parent_part = TABLE_GET_PART(table, i);
        if (!IS_READY_PART(parent_part)) {
            continue;
        }

        if (!IS_PARENT_TABPART(&parent_part->desc)) {
            continue;
        }

        cbo_stats_table_t *parent_stats = CBO_GET_TABLE_PART(cbo_stats, i);
        if (parent_stats == NULL) {
            continue;
        }

        cbo_set_max_row_subpart(entity, i, &max_rows);
    }
}

static int32 cbo_hist_bucket_comparator(const void *pa, const void *pb)
{
    const cbo_hists_assist_t *a = (const cbo_hists_assist_t *)pa;
    const cbo_hists_assist_t *b = (const cbo_hists_assist_t *)pb;

    if (a->endpoint < b->endpoint) {
        return -1;
    }
    if (a->endpoint > b->endpoint) {
        return 1;
    }

    return 0;
}

void cbo_hists_sort(cbo_hists_assist_t *hists, uint32 buckets)
{
    qsort(hists, buckets, sizeof(cbo_hists_assist_t), cbo_hist_bucket_comparator);
}

status_t cbo_set_sub_histgrams(knl_session_t *session, dc_entity_t *entity, uint32 count,
    cbo_stats_column_t *stats, cbo_hists_assist_t *cbo_hists)
{
    knl_column_t *column = dc_get_column(entity, stats->column_id);
    text_t ep_value;
    errno_t ret;

    for (uint32 pos = 0; pos < count; pos++) {
        cbo_hists_assist_t *cbo_hist = &cbo_hists[pos];
        cbo_column_hist_t *hist = stats->column_hist[pos];

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
        ep_value.str = cbo_hist->buckets;
        ep_value.len = cbo_hist->len;

        if (cbo_alloc_value_mem(session, entity->memory, column, &hist->ep_value.str) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cbo_get_stats_values(entity, column, &ep_value, &hist->ep_value)) {
            return CT_ERROR;
        }

        hist->ep_number = cbo_hist->endpoint;
    }

    return CT_SUCCESS;
}

status_t cbo_precheck_index_subpart(knl_session_t *session, dc_entity_t *entity, uint32 part_no, index_t *idx, uint32 subpart_no)
{
    index_part_t *index_part = INDEX_GET_PART(idx, part_no);
    if (index_part == NULL) {
        CT_LOG_RUN_WAR("Load %s.%s the %d-%d index part stats falied,it is not existed ",
            entity->entry->user->desc.name, entity->table.desc.name, idx->desc.id, part_no);
        return CT_ERROR;
    }

    index_part_t *index_sub = PART_GET_SUBENTITY(idx->part_index, index_part->subparts[subpart_no]);
    if (index_sub == NULL) {
        CT_LOG_RUN_WAR("Load %s.%s the %d-%d-%d index part stats falied,it is not existed ",
            entity->entry->user->desc.name, entity->table.desc.name, idx->desc.id, part_no, subpart_no);
        return CT_ERROR;
    }

    cbo_stats_index_t *index_stats = entity->cbo_table_stats->indexs[idx->desc.slot];
    cbo_stats_index_t *parent_stats = CBO_GET_INDEX_PART(index_stats, index_part->part_no);
    if (parent_stats == NULL) {
        CT_LOG_RUN_WAR("Load %s.%s the %d-%d-%d index parent part stats falied,it is not existed ",
            entity->entry->user->desc.name, entity->table.desc.name, idx->desc.id, part_no, subpart_no);
        return CT_ERROR;
    }

    return CT_SUCCESS;
}

void cbo_set_histgram_scan_key(knl_cursor_t *cursor, table_t *table, uint32 cid, uint32 part_id)
{
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&table->desc.uid,
        sizeof(uint32), IX_COL_HIST_003_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&table->desc.id,
        sizeof(uint32), IX_COL_HIST_003_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&cid,
        sizeof(uint32), IX_COL_HIST_003_COL_ID);

    if (IS_PART_TABLE(table)) {
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.l_key, CT_TYPE_INTEGER, (void *)&part_id,
            sizeof(uint32), IX_COL_HIST_003_PART_ID);
    } else {
        knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_IS_NULL, IX_COL_HIST_003_PART_ID);
    }

    knl_set_key_flag(&cursor->scan_range.l_key, SCAN_KEY_LEFT_INFINITE, IX_COL_HIST_003_ENDPOINT);

    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, (void *)&table->desc.uid,
        sizeof(uint32), IX_COL_HIST_003_USER_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, (void *)&table->desc.id,
        sizeof(uint32), IX_COL_HIST_003_TABLE_ID);
    knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, (void *)&cid,
        sizeof(uint32), IX_COL_HIST_003_COL_ID);

    if (IS_PART_TABLE(table)) {
        knl_set_scan_key(INDEX_DESC(cursor->index), &cursor->scan_range.r_key, CT_TYPE_INTEGER, (void *)&part_id,
            sizeof(uint32), IX_COL_HIST_003_PART_ID);
    } else {
        knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_IS_NULL, IX_COL_HIST_003_PART_ID);
    }

    knl_set_key_flag(&cursor->scan_range.r_key, SCAN_KEY_RIGHT_INFINITE, IX_COL_HIST_003_ENDPOINT);
}

status_t cbo_set_columns_stats(knl_session_t *session, dc_entity_t *entity, cbo_stats_table_t *cbo_stats)
{
    uint32 col_count = entity->column_count;
    memory_context_t *memory = entity->memory;
    uint32 ext_count = CM_ALIGN_ANY(col_count, CBO_LIST_COUNT) / CBO_LIST_COUNT;
    errno_t ret;

    if (cbo_stats->col_map == NULL) {
        // ext_count <= 32, so sizeof(void *) * ext_count is smaller than max uint32 value
        if (dc_alloc_mem(&session->kernel->dc_ctx, memory, sizeof(void *) * ext_count, (void **)&cbo_stats->col_map)) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        ret = memset_sp(cbo_stats->col_map, sizeof(void *) * ext_count, 0, sizeof(void *) * ext_count);
        knl_securec_check(ret);
    }

    for (uint32 i = 0; i < ext_count; i++) {
        if (cbo_stats->col_map[i] != NULL) {
            continue;
        }

        if (dc_alloc_mem(&session->kernel->dc_ctx, memory, sizeof(uint32) * CBO_LIST_COUNT,
            (void **)&cbo_stats->col_map[i])) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        ret = memset_sp(cbo_stats->col_map[i], sizeof(uint32) * CBO_LIST_COUNT, 0xFF, sizeof(uint32) * CBO_LIST_COUNT);
        knl_securec_check(ret);
    }

    for (uint32 pos = 0; pos < cbo_stats->column_count; pos++) {
        cbo_stats_column_t *item = get_cbo_stats_column(cbo_stats, pos);
        if (item != NULL) {
            set_cbo_col_map(cbo_stats, item->column_id, pos);
        }
    }

    cbo_stats->col_stats_allowed = CT_TRUE;
    return CT_SUCCESS;
}

status_t cbo_calc_part_group(knl_session_t *session, dc_entity_t *entity, uint32 *group_cnt,
    uint32 *group_id, uint32 *gid)
{
    if (group_id[*gid] != CT_INVALID_ID32) {
        *gid = group_id[*gid];
        return CT_SUCCESS;
    }

    group_id[*gid] = *group_cnt;
    *gid = *group_cnt;
    (*group_cnt)++;

    return CT_SUCCESS;
}

status_t cbo_alloc_table_part_default(knl_session_t *session, dc_entity_t *entity,
    cbo_stats_table_t *table_stats, uint32 id)
{
    table_t *table = &entity->table;
    part_table_t *part_table = table->part_table;
    uint32 gid;

    gid = id / PART_GROUP_SIZE;
    if (!PART_CONTAIN_INTERVAL(part_table)) {
        if (cbo_alloc_part_table_group(session, entity, table_stats, gid) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (cbo_calc_part_group(session, entity, &table_stats->part_group.group_cnt, table_stats->part_group.group_id,
            &gid) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cbo_alloc_part_table_group(session, entity, table_stats, gid) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!table_stats->part_group.group_ready[gid]) {
            table_stats->part_group.group_ready[gid] = CT_TRUE;
        }
    }

    return CT_SUCCESS;
}

status_t cbo_alloc_table_part_stats(knl_session_t *session, dc_entity_t *entity,
    cbo_stats_table_t *table_stats, uint32 id)
{
    table_t *table = &entity->table;
    part_table_t *part_table = table->part_table;
    cbo_table_part_group_t *part_group = NULL;
    cbo_stats_table_t *part_stats = NULL;
    uint32 gid;
    uint32 eid;
    uint32 table_size;
    errno_t ret;

    gid = id / PART_GROUP_SIZE;
    eid = id % PART_GROUP_SIZE;
    if (!PART_CONTAIN_INTERVAL(part_table)) {
        if (cbo_alloc_part_table_group(session, entity, table_stats, gid) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (cbo_calc_part_group(session, entity, &table_stats->part_group.group_cnt, table_stats->part_group.group_id,
            &gid) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cbo_alloc_part_table_group(session, entity, table_stats, gid) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!table_stats->part_group.group_ready[gid]) {
            table_stats->part_group.group_ready[gid] = CT_TRUE;
        }
    }

    part_group = table_stats->part_groups[gid];

    if (part_group->entity[eid] == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(cbo_stats_table_t),
            (void **)&part_stats) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        table_size = sizeof(cbo_stats_table_t);
        ret = memset_sp(part_stats, table_size, 0, table_size);
        knl_securec_check(ret);
        part_stats->is_ready = CT_FALSE;
        part_group->entity[eid] = part_stats;
    }

    return CT_SUCCESS;
}

status_t cbo_alloc_index_part_default(knl_session_t *session, dc_entity_t *entity,
    cbo_stats_index_t *index_stats, uint32 id)
{
    table_t *table = &entity->table;
    part_table_t *part_table = table->part_table;
    uint32 gid;

    gid = id / PART_GROUP_SIZE;
    if (!PART_CONTAIN_INTERVAL(part_table)) {
        if (cbo_alloc_part_index_group(session, entity, index_stats, gid) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (cbo_calc_part_group(session, entity, &index_stats->part_group.group_cnt, index_stats->part_group.group_id,
            &gid) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cbo_alloc_part_index_group(session, entity, index_stats, gid) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!index_stats->part_group.group_ready[gid]) {
            index_stats->part_group.group_ready[gid] = CT_TRUE;
        }
    }

    return CT_SUCCESS;
}

uint32 cbo_get_part_group_count(uint32 part_cnt)
{
    uint32 group_count = part_cnt / PART_GROUP_SIZE;
    uint32 element_count = part_cnt % PART_GROUP_SIZE;

    if (element_count != 0) {
        group_count = group_count + 1;
    }

    CM_ASSERT(group_count > 0);
    return group_count;
}

status_t cbo_alloc_index_subpart_stats(knl_session_t *session, dc_entity_t *entity, index_t *index,
    cbo_stats_index_t *idx_stats, index_part_t *index_part)
{
    cbo_stats_index_t *sub_stats = NULL;
    errno_t ret;

    if (idx_stats->subpart_index_groups == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, CT_SHARED_PAGE_SIZE,
            (void **)&idx_stats->subpart_index_groups) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        ret = memset_sp(idx_stats->subpart_index_groups, CT_SHARED_PAGE_SIZE, 0, CT_SHARED_PAGE_SIZE);
        knl_securec_check(ret);
    }

    for (uint32 i = 0; i < index_part->desc.subpart_cnt; i++) {
        index_part_t *sub_index_part = PART_GET_SUBENTITY(index->part_index, index_part->subparts[i]);

        if (sub_index_part == NULL) {
            continue;
        }
        uint32 pos = index_part->subparts[i];
        uint32 gid = pos / PART_GROUP_SIZE;
        uint32 eid = pos % PART_GROUP_SIZE;

        if (cbo_alloc_subpart_index_group(session, entity, idx_stats, gid) != CT_SUCCESS) {
            return CT_ERROR;
        }

        cbo_index_part_group_t *part_group = idx_stats->subpart_index_groups[gid];

        if (part_group->entity[eid] == NULL) {
            if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(cbo_stats_index_t),
                (void **)&sub_stats) != CT_SUCCESS) {
                CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
                return CT_ERROR;
            }

            ret = memset_sp(sub_stats, sizeof(cbo_stats_index_t), 0, sizeof(cbo_stats_index_t));
            knl_securec_check(ret);

            sub_stats->is_ready = CT_FALSE;
            part_group->entity[eid] = sub_stats;
        }
    }

    cbo_stats_index_t *parent_stats = CBO_GET_INDEX_PART(idx_stats, index_part->part_no);
    parent_stats->is_parent_part = CT_TRUE;
    return CT_SUCCESS;
}

status_t cbo_alloc_index_part_stats(knl_session_t *session, dc_entity_t *entity,
    cbo_stats_index_t *index_stats, uint32 id)
{
    table_t *table = &entity->table;
    part_table_t *part_table = table->part_table;
    cbo_index_part_group_t *part_group = NULL;
    cbo_stats_index_t *part_stats = NULL;
    uint32 index_size;
    errno_t ret;
    uint32 gid = id / PART_GROUP_SIZE;
    uint32 eid = id % PART_GROUP_SIZE;

    if (!PART_CONTAIN_INTERVAL(part_table)) {
        if (cbo_alloc_part_index_group(session, entity, index_stats, gid) != CT_SUCCESS) {
            return CT_ERROR;
        }
    } else {
        if (cbo_calc_part_group(session, entity, &index_stats->part_group.group_cnt, index_stats->part_group.group_id,
            &gid) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (cbo_alloc_part_index_group(session, entity, index_stats, gid) != CT_SUCCESS) {
            return CT_ERROR;
        }

        if (!index_stats->part_group.group_ready[gid]) {
            index_stats->part_group.group_ready[gid] = CT_TRUE;
        }
    }

    part_group = index_stats->part_index_groups[gid];
    if (part_group->entity[eid] == NULL) {
        if (dc_alloc_mem(&session->kernel->dc_ctx, entity->memory, sizeof(cbo_stats_index_t),
            (void **)&part_stats) != CT_SUCCESS) {
            CT_THROW_ERROR(ERR_DC_BUFFER_FULL);
            return CT_ERROR;
        }

        index_size = sizeof(cbo_stats_index_t);
        ret = memset_sp(part_stats, index_size, 0, index_size);
        knl_securec_check(ret);

        part_stats->is_ready = CT_FALSE;
        part_group->entity[eid] = part_stats;
    }

    return CT_SUCCESS;
}

void cbo_set_max_row_part(cbo_stats_table_t  *table_stats, cbo_stats_table_t *part_stats, uint32 part_no)
{
    cbo_stats_table_t *max_part_stats = NULL;
    max_part_stats = CBO_GET_TABLE_PART(table_stats, table_stats->max_part_no);
    if (max_part_stats != NULL) {
        if (max_part_stats->rows < part_stats->rows) {
            table_stats->max_part_no = part_no;
        }
    } else {
        table_stats->max_part_no = part_no;
    }
}

cbo_stats_index_t *cbo_find_indexpart_stats(cbo_stats_table_t *cbo_stats, uint32 index_id, uint32 part_no,
    bool32 *need_load)
{
    cbo_stats_index_t *index = NULL;
    cbo_stats_index_t *part_index = NULL;

    for (uint32 pos = 0; pos < cbo_stats->index_count; pos++) {
        index = cbo_stats->indexs[pos];

        if (index == NULL || index->id != index_id) {
            continue;
        }

        if (!index->is_part) {
            part_index = index;
            return part_index;
        }

        part_index = CBO_GET_INDEX_PART(index, part_no);
        break;
    }

    if (index == NULL) {
        return part_index;
    }

    if (part_index == NULL) {
        return index->idx_part_default;
    }

    if (part_index->is_ready && part_index->stats_version == cbo_stats->stats_version && !part_index->is_parent_part) {
        return part_index;
    }

    *need_load = CT_TRUE;
    return part_index;
}

uint32 cbo_get_column_alloc_size(knl_column_t *column)
{
    uint32 size;

    switch (column->datatype) {
        case CT_TYPE_BOOLEAN:
        case CT_TYPE_SMALLINT:
        case CT_TYPE_UINT32:
        case CT_TYPE_INTEGER:
        case CT_TYPE_USMALLINT:
        case CT_TYPE_TINYINT:
        case CT_TYPE_UTINYINT:
            size = sizeof(int32);
            break;
        case CT_TYPE_BIGINT:
            size = sizeof(int64);
            break;
        case CT_TYPE_FLOAT:
        case CT_TYPE_REAL:
            size = sizeof(double);
            break;
        case CT_TYPE_UINT64:
        case CT_TYPE_NUMBER:
        case CT_TYPE_DECIMAL:
        case CT_TYPE_NUMBER3:
        case CT_TYPE_NUMBER2:
            size = sizeof(dec8_t);
            break;
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
        case CT_TYPE_DATETIME_MYSQL:
        case CT_TYPE_TIME_MYSQL:
        case CT_TYPE_DATE_MYSQL:
            size = sizeof(date_t);
            break;
        case CT_TYPE_TIMESTAMP_TZ:
            size = sizeof(timestamp_tz_t);
            break;
        case CT_TYPE_INTERVAL_DS:
            size = sizeof(interval_ds_t);
            break;
        case CT_TYPE_INTERVAL_YM:
            size = sizeof(interval_ym_t);
            break;
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
            if (KNL_COLUMN_IS_CHARACTER(column)) {
                size = MIN(column->size * CT_CHAR_TO_BYTES_RATIO, STATS_MAX_BUCKET_SIZE);
            } else {
                size = MIN(column->size + 1, STATS_MAX_BUCKET_SIZE);
            }
            break;

        default:
            size = column->size;
            break;
    }

    return size;
}

status_t cbo_alloc_value_mem(knl_session_t *session, memory_context_t *memory, knl_column_t *column, char **buf)
{
    dc_context_t *ctx = NULL;
    uint32 size;
    errno_t ret;

    if (*buf != NULL) {
        return CT_SUCCESS;
    }

    size = cbo_get_column_alloc_size(column);
    ctx = &session->kernel->dc_ctx;

    if (dc_alloc_mem(ctx, memory, size, (void **)buf) != CT_SUCCESS) {
        return CT_ERROR;
    }

    ret = memset_sp(*buf, size, 0, size);
    knl_securec_check(ret);

    return CT_SUCCESS;
}

status_t cbo_get_stats_values(dc_entity_t *entity, knl_column_t *column, text_t *v_input, text_t *v_output)
{
    status_t status = CT_SUCCESS;
    errno_t ret;
    uint32 copy_size;
    uint32 real_size;
    binary_t bin;
    dec2_t d2;

    if (v_input->len == CT_NULL_VALUE_LEN) {
        v_output->len = CT_NULL_VALUE_LEN;
        return CT_SUCCESS;
    } else if (v_input->len == 0 && !CT_IS_STRING_TYPE(column->datatype)) {
        v_output->len = CT_NULL_VALUE_LEN;
        return CT_SUCCESS;
    }

    cm_trim_text(v_input);

    switch (column->datatype) {
        case CT_TYPE_BOOLEAN:
            status = cm_text2bool(v_input, (bool32 *)v_output->str);
            v_output->len = sizeof(bool32);
            break;
        case CT_TYPE_UINT32:
            status = cm_text2uint32(v_input, (uint32 *)v_output->str);
            v_output->len = sizeof(uint32);
            break;
        case CT_TYPE_SMALLINT:
        case CT_TYPE_INTEGER:
        case CT_TYPE_USMALLINT:
        case CT_TYPE_TINYINT:
        case CT_TYPE_UTINYINT:
            status = cm_text2int(v_input, (int32 *)v_output->str);
            v_output->len = sizeof(int32);
            break;
        case CT_TYPE_BIGINT:
            status = cm_text2bigint(v_input, (int64 *)v_output->str);
            v_output->len = sizeof(int64);
            break;
        case CT_TYPE_FLOAT:
        case CT_TYPE_REAL:
            status = cm_text2real(v_input, (double *)v_output->str);
            v_output->len = sizeof(double);
            break;
        case CT_TYPE_UINT64:
        case CT_TYPE_NUMBER:
        case CT_TYPE_NUMBER3:
        case CT_TYPE_DECIMAL:
            status = cm_text_to_dec4(v_input, (dec4_t *)v_output->str);
            v_output->len = sizeof(dec4_t);
            break;
        case CT_TYPE_NUMBER2:
            CT_RETURN_IFERR(cm_text_to_dec2(v_input, &d2));
            cm_dec2_copy_payload((payload_t *)v_output->str, GET_PAYLOAD(&d2), d2.len);
            v_output->len = d2.len;
            break;
        case CT_TYPE_DATE:
        case CT_TYPE_TIMESTAMP:
        case CT_TYPE_TIMESTAMP_TZ_FAKE:
        case CT_TYPE_TIMESTAMP_LTZ:
            status = cm_text2date(v_input, NULL, (date_t *)v_output->str);
            v_output->len = sizeof(date_t);
            break;
        case CT_TYPE_TIMESTAMP_TZ:
            status = cm_text2timestamp_tz(v_input, NULL, cm_get_local_tzoffset(), (timestamp_tz_t *)v_output->str);
            v_output->len = sizeof(timestamp_tz_t);
            break;
        case CT_TYPE_DATE_MYSQL:
        case CT_TYPE_DATETIME_MYSQL:
        case CT_TYPE_TIME_MYSQL:
            status = cm_text2date_mysql(v_input, NULL, (date_t *)v_output->str, column->datatype);
            v_output->len = sizeof(date_t);
            break;
        case CT_TYPE_INTERVAL_DS:
            status = cm_text2dsinterval(v_input, (interval_ds_t *)v_output->str);
            v_output->len = sizeof(interval_ds_t);
            break;
        case CT_TYPE_INTERVAL_YM:
            status = cm_text2yminterval(v_input, (interval_ym_t *)v_output->str);
            v_output->len = sizeof(interval_ym_t);
            break;
        case CT_TYPE_CHAR:
        case CT_TYPE_VARCHAR:
        case CT_TYPE_STRING:
            copy_size = MIN(column->size + 1, STATS_MAX_BUCKET_SIZE);
            real_size = MIN(v_input->len, copy_size);
            v_output->len = real_size;
            if (v_input->len != 0) {
                ret = memcpy_sp(v_output->str, copy_size, v_input->str, real_size);
                knl_securec_check(ret);
            }
            break;
        case CT_TYPE_BINARY:
        case CT_TYPE_VARBINARY:
        case CT_TYPE_RAW:
            bin.bytes = (uint8*)v_output->str;
            bin.size = 0;
            copy_size = MIN(column->size + 1, STATS_MAX_BUCKET_SIZE);
            status = cm_text2bin(v_input, CT_FALSE, &bin, STATS_MAX_BUCKET_SIZE);
            v_output->len = MIN(bin.size, copy_size);
            break;
        default:
            v_output->len = CT_NULL_VALUE_LEN;
            break;
    }
    return status;
}