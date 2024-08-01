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
 * pcr_btree_stat.c
 *
 *
 * IDENTIFICATION
 * src/kernel/index/pcr_btree_stat.c
 *
 * -------------------------------------------------------------------------
 */
#include "knl_index_module.h"
#include "pcr_btree_stat.h"
#include "rcr_btree_scan.h"
#include "knl_context.h"
#include "knl_datafile.h"
#include "ostat_load.h"

void pcrb_calc_ndv_key(index_t *index, pcrb_key_t *key, pcrb_key_t *compare_key,
                       btree_info_t *info, void *cbo_index_handle)
{
    dc_entity_t *entity = index->entity;
    uint32 column_count = index->desc.column_count;
    knl_column_t *column = NULL;
    ct_type_t type;
    char *data1 = NULL;
    char *data2 = NULL;
    uint16 offset = sizeof(pcrb_key_t);
    bool32 key_is_null = CT_FALSE;
    bool32 com_key_is_null = CT_FALSE;
    int32 result = 0;
    bool32 is_distinct = CT_TRUE;
    uint16 collate_id;
    cbo_stats_index_t *cbo_index = (cbo_stats_index_t *)cbo_index_handle;

    if (key == NULL || compare_key->is_infinite) {
        btree_set_comb_ndv(info, BTREE_COMB_1_NDV, column_count);
        info->distinct_keys++;
        return;
    }

    for (uint32 i = 0; i < column_count; i++) {
        if (key->is_infinite || compare_key->is_infinite) {
            if (!key->is_deleted) {
                btree_set_comb_ndv(info, i, column_count);
                if (is_distinct) {
                    info->distinct_keys++;
                    if (cbo_index != NULL) {
                        cbo_index->distinct_keys_arr[i] = cbo_index->distinct_keys_arr[i] + 1;
                    }
                    is_distinct = CT_FALSE;
                }
            }
            break;
        }

        column = dc_get_column(entity, index->desc.columns[i]);
        if (column->is_collate) {
            collate_id = column->collate_id;
        } else {
            collate_id = CT_INVALID_ID16;
        }
        type = column->datatype;
        key_is_null = !btree_get_bitmap(&key->bitmap, i);
        com_key_is_null = !btree_get_bitmap(&compare_key->bitmap, i);
        if (key_is_null && com_key_is_null) {
            continue;
        }

        if ((key_is_null && !com_key_is_null) || (!key_is_null && com_key_is_null)) {
            btree_set_comb_ndv(info, i, column_count);
            if (is_distinct) {
                info->distinct_keys++;
                if (cbo_index != NULL) {
                    cbo_index->distinct_keys_arr[i] = cbo_index->distinct_keys_arr[i] + 1;
                }
                is_distinct = CT_FALSE;
            }
            break;
        }

        data1 = (char *)key + offset;
        data2 = (char *)compare_key + offset;

        result = btree_cmp_column_data((void *)data1, (void *)data2, type, &offset, CT_TRUE, collate_id);
        if (result != 0) {
            btree_set_comb_ndv(info, i, column_count);
            if (is_distinct) {
                info->distinct_keys++;
                if (cbo_index != NULL) {
                    cbo_index->distinct_keys_arr[i] = cbo_index->distinct_keys_arr[i] + 1;
                }
                is_distinct = CT_FALSE;
            }
            break;
        }
    }
}

bool32 pcrb_is_key_dead(knl_session_t *session, btree_page_t *page, knl_scn_t min_scn, pcrb_key_t *key)
{
    txn_info_t txn_info;

    if (!key->is_deleted) {
        return CT_FALSE;
    }

    pcrb_get_txn_info(session, page, key, &txn_info);
    if (txn_info.status != (uint8)XACT_END) {
        return CT_FALSE;
    }

    if (txn_info.scn > min_scn) {
        return CT_FALSE;
    }

    return CT_TRUE;
}

void pcrb_stats_leaf_page(knl_session_t *session, btree_t *btree, btree_info_t *info, page_id_t *page_id,
    page_id_t *prev_page_id, pcrb_key_t *prev_compare_key)
{
    btree_segment_t *segment = (btree_segment_t *)btree->segment;
    pcrb_key_t *key = NULL;
    pcrb_key_t *compare_key = prev_compare_key;
    btree_page_t *page = NULL;
    pcrb_dir_t *dir = NULL;
    knl_scn_t min_scn = btree_get_recycle_min_scn(session);
    uint16 clean_keys = 0;
    knl_scn_t seg_scn = segment->seg_scn;
    uint32 j;
    errno_t ret;
    cbo_stats_index_t *cbo_index = knl_get_cbo_index(session, btree->index->entity, btree->index->desc.id);

    buf_enter_page(session, *page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL | ENTER_PAGE_SEQUENTIAL);
    page = BTREE_CURR_PAGE(session);
    if (btree_check_segment_scn(page, PAGE_TYPE_PCRB_NODE, seg_scn) != CT_SUCCESS) {
        buf_leave_page(session, CT_FALSE);
        return;
    }

    for (j = 0; j < page->keys; j++) {
        dir = pcrb_get_dir(page, j);
        key = PCRB_GET_KEY(page, dir);
        if (key->is_infinite || key->is_deleted) {
            clean_keys++;
            continue;
        }

        if (!IS_SAME_PAGID(*prev_page_id, key->rowid)) {
            info->clustor++;
        }

        if (pcrb_is_key_dead(session, page, min_scn, key)) {
            clean_keys++;
            continue;
        }

        pcrb_calc_ndv_key(btree->index, key, compare_key, info, cbo_index);
        compare_key = key;
        *prev_page_id = GET_ROWID_PAGE(key->rowid);
    }

    if (clean_keys == page->keys) {
        info->empty_leaves++;
    }

    ret = memcpy_sp(prev_compare_key, CT_KEY_BUF_SIZE, compare_key, (uint32)compare_key->size);
    knl_securec_check(ret);

    info->keys += page->keys;
    info->leaf_blocks++;
    *page_id = AS_PAGID(page->next);
    buf_leave_page(session, CT_FALSE);
}

/*
* when sample stats index btree, we search each level 1 page and sample keys in each page. Then fullly stats the leaf
* page pointed to the key.
*/
status_t pcrb_stats_leaf_by_parent(knl_session_t *session, btree_t *btree, double sample_ratio_input,
                                   btree_info_t *info, page_id_t page_id_input)
{
    double sample_ratio = sample_ratio_input;
    page_id_t page_id = page_id_input;
    uint16 sample_blocks, sample_step;
    uint16 step = 0;
    pcrb_dir_t *dir = NULL;
    page_id_t *page_id_arr = NULL;
    pcrb_key_t *key = NULL;
    btree_info_t curr_parent;
    page_id_t prev_page_id = INVALID_PAGID;
    pcrb_key_t *compare_key = NULL;
    errno_t ret;
    uint32 i;

    CM_SAVE_STACK(session->stack);
    compare_key = (pcrb_key_t *)cm_push(session->stack, CT_KEY_BUF_SIZE);
    compare_key->is_infinite = CT_TRUE;
    compare_key->size = sizeof(pcrb_key_t);

    while (!IS_INVALID_PAGID(page_id)) {
        ret = memset_sp(&curr_parent, sizeof(btree_info_t), 0, sizeof(btree_info_t));
        knl_securec_check(ret);

        buf_enter_page(session, page_id, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        btree_page_t *page = BTREE_CURR_PAGE(session);
        sample_blocks = (uint16)(page->keys * sample_ratio);
        if (sample_blocks < STATS_MIN_BTREE_KEYS) {
            sample_blocks = STATS_MIN_BTREE_KEYS;
            sample_ratio = ((double)sample_blocks) / page->keys;
        }

        sample_step = page->keys / sample_blocks;

        page_id_arr = (page_id_t *)cm_push(session->stack, sizeof(page_id_t) * sample_blocks);
        uint32 sample_count = 0;

        /* get leaf page id of current level 1 page */
        for (i = 0; i < page->keys && sample_count < sample_blocks; i++) {
            dir = pcrb_get_dir(page, i);
            key = PCRB_GET_KEY(page, dir);
            if (!key->is_deleted && step == 0) {
                page_id_arr[sample_count++] = pcrb_get_child(key);
            }
            step = (step + 1) % sample_step;
        }

        if (sample_count != 0 && sample_count < sample_blocks) {
            sample_ratio = sample_ratio * sample_count / sample_blocks;
        }

        /* stats each leaf page */
        for (i = 0; i < sample_count; i++) {
            if (knl_check_session_status(session) != CT_SUCCESS) {
                CM_RESTORE_STACK(session->stack);
                buf_leave_page(session, CT_FALSE);
                return CT_ERROR;
            }
            pcrb_stats_leaf_page(session, btree, &curr_parent, &page_id_arr[i], &prev_page_id, compare_key);
        }

        info->leaf_blocks += page->keys;
        info->distinct_keys += stats_estimate_ndv(curr_parent.distinct_keys, curr_parent.keys, sample_ratio);
        info->comb_cols_2_ndv += stats_estimate_ndv(curr_parent.comb_cols_2_ndv, curr_parent.keys, sample_ratio);
        info->comb_cols_3_ndv += stats_estimate_ndv(curr_parent.comb_cols_3_ndv, curr_parent.keys, sample_ratio);
        info->comb_cols_4_ndv += stats_estimate_ndv(curr_parent.comb_cols_4_ndv, curr_parent.keys, sample_ratio);
        info->clustor += (uint32)(curr_parent.clustor / sample_ratio);
        info->empty_leaves += (uint32)(curr_parent.empty_leaves / sample_ratio);
        info->keys += (uint32)(curr_parent.keys / sample_ratio);

        cm_pop(session->stack);
        page_id = AS_PAGID(page->next);
        buf_leave_page(session, CT_FALSE);
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

status_t pcrb_full_stats_info(knl_session_t *session, btree_t *btree, btree_info_t *info)
{
    btree_segment_t *segment = (btree_segment_t *)btree->segment;
    knl_tree_info_t tree_info;
    page_id_t page_id;
    page_id_t prev_page_id = INVALID_PAGID;
    pcrb_key_t *compare_key = NULL;

    if (segment == NULL) {
        return CT_SUCCESS;
    }

    tree_info.value = cm_atomic_get(&segment->tree_info.value);
    info->height = (uint32)tree_info.level;

    if (btree_level_first_page(session, btree, 0, &page_id) != CT_SUCCESS) {
        return CT_ERROR;
    }

    CM_SAVE_STACK(session->stack);
    compare_key = (pcrb_key_t *)cm_push(session->stack, CT_KEY_BUF_SIZE);
    compare_key->is_infinite = CT_TRUE;
    compare_key->size = sizeof(pcrb_key_t);

    while (!IS_INVALID_PAGID(page_id)) {
        if (knl_check_session_status(session) != CT_SUCCESS) {
            CM_RESTORE_STACK(session->stack);
            return CT_ERROR;
        }
        pcrb_stats_leaf_page(session, btree, info, &page_id, &prev_page_id, compare_key);
    }

    CM_RESTORE_STACK(session->stack);
    return CT_SUCCESS;
}

static void pcrb_get_table_by_leftpage(knl_session_t *session, btree_page_t *btree_page, uint32 *uid, uint32 *tabid)
{
    page_id_t child_pagid;
    btree_page_t *page = btree_page;
    uint8 level = page->level;

    page_id_t btree_pagid = AS_PAGID(page->head.id);
    pcrb_dir_t *dir = pcrb_get_dir(page, 0);
    pcrb_key_t *key = PCRB_GET_KEY(page, dir);
    child_pagid = pcrb_get_child(key);
    while (level > 0) {
        buf_enter_page(session, child_pagid, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        page = BTREE_CURR_PAGE(session);
        level = page->level;
        dir = pcrb_get_dir(page, 0);
        key = PCRB_GET_KEY(page, dir);
        child_pagid = pcrb_get_child(key);
        btree_pagid = AS_PAGID(page->head.id);
        buf_leave_page(session, CT_FALSE);
    }

    page_id_t segment_pagid = btree_pagid;
    segment_pagid.page--;
    buf_enter_page(session, segment_pagid, LATCH_MODE_S, ENTER_PAGE_NORMAL);
    btree_segment_t *btree_segment = BTREE_GET_SEGMENT(session);
    *uid = btree_segment->uid;
    *tabid = btree_segment->table_id;
    buf_leave_page(session, CT_FALSE);
}

status_t pcrb_get_table_by_page(knl_session_t *session, page_head_t *page, uint32 *uid, uint32 *tabid)
{
    rowid_t rowid;
    page_id_t child_pagid;
    btree_page_t *btree_page = (btree_page_t *)page;

    if (btree_page->keys == 0) {
        CT_THROW_ERROR(ERR_PAGE_NOT_BELONG_TABLE, page_type(btree_page->head.type));
        return CT_ERROR;
    }

    pcrb_dir_t *dir = pcrb_get_dir(btree_page, 0);
    pcrb_key_t *key = PCRB_GET_KEY(btree_page, dir);
    if (key->is_infinite) {
        /* if the btree node page has one infinite key, the page is the most left page on the btree. so we
        * need to get the page whose level == 0, it locate behind of the btree segment page */
        pcrb_get_table_by_leftpage(session, btree_page, uid, tabid);
        return CT_SUCCESS;
    }

    /* for unique index or primary key, the rowid of parent key is not a valid rowid, we need to find left node */
    ROWID_COPY(rowid, key->rowid);
    while (rowid.value == 0) {
        child_pagid = pcrb_get_child(key);
        buf_enter_page(session, child_pagid, LATCH_MODE_S, ENTER_PAGE_NORMAL);
        btree_page = BTREE_CURR_PAGE(session);
        dir = pcrb_get_dir(btree_page, 0);
        key = PCRB_GET_KEY(btree_page, dir);
        ROWID_COPY(rowid, key->rowid);
        buf_leave_page(session, CT_FALSE);
    }

    if (df_verify_page_by_hwm(session, rowid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    if (btree_get_table_by_rowid(session, page, rowid, uid, tabid) != CT_SUCCESS) {
        return CT_ERROR;
    }

    return CT_SUCCESS;
}
