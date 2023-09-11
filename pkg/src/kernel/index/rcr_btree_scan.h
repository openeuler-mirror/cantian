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
 * rcr_btree_scan.h
 *
 *
 * IDENTIFICATION
 * src/kernel/index/rcr_btree_scan.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __RCR_BTREE_SCAN_H__
#define __RCR_BTREE_SCAN_H__

#include "rcr_btree.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t btree_fetch(knl_handle_t handle, knl_cursor_t *cursor);
status_t btree_fetch_depended(knl_session_t *session, knl_cursor_t *cursor);

int32 btree_cmp_column_data(void *col1, void *col2, gs_type_t type, uint16 *offset, bool32 is_pcr);
int32 btree_cmp_column(knl_column_t *column, knl_scan_key_t *scan_key, uint32 idx_col_id, btree_key_t *key,
    uint16 *offset);
int32 btree_compare_key(index_t *index, knl_scan_key_t *scan_key, btree_key_t *key, bool32 cmp_rowid,
    bool32 *is_same);

void btree_binary_search(index_t *index, btree_page_t *page, knl_scan_key_t *scan_key,
    btree_path_info_t *path_info, bool32 cmp_rowid, bool32 *is_same);

static inline bool8 btree_is_full_scan(knl_scan_range_t *range)
{
    if (range->is_equal) {
        return GS_FALSE;
    }

    if (range->l_key.flags[0] == SCAN_KEY_LEFT_INFINITE && range->r_key.flags[0] == SCAN_KEY_RIGHT_INFINITE) {
        return GS_TRUE;
    }

    return GS_FALSE;
}

static inline void btree_set_cmp_endpoint(knl_cursor_t *cursor)
{
    if (cursor->scan_range.is_equal || cursor->index_dsc || cursor->index_ss) {
        cursor->key_loc.cmp_end = GS_TRUE;
        return;
    }

    /* scan range like id > 10 does not need compare with right key */
    cursor->key_loc.cmp_end = (cursor->scan_range.r_key.flags[0] != SCAN_KEY_RIGHT_INFINITE);
}

static inline void btree_init_key_loc(key_locator_t *key_loc)
{
    key_loc->is_initialized = GS_TRUE;
    key_loc->is_located = GS_FALSE;
    key_loc->is_last_key = GS_FALSE;
    key_loc->match_left = GS_FALSE;
    key_loc->match_right = GS_FALSE;
    key_loc->cmp_end = GS_FALSE;
    key_loc->skip_cache = GS_FALSE;
}

#ifdef __cplusplus
}
#endif

#endif
