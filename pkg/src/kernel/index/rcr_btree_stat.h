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
 * rcr_btree_stat.h
 *
 *
 * IDENTIFICATION
 * src/kernel/index/rcr_btree_stat.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __RCR_BTREE_STAT_H__
#define __RCR_BTREE_STAT_H__

#include "rcr_btree.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BTREE_COMB_1_NDV           0
#define BTREE_COMB_2_NDV           1
#define BTREE_COMB_3_NDV           2
#define BTREE_COMB_4_NDV           3
#define BTREE_COMB_MAX             4

typedef struct st_btree_info {
    uint32 height;
    uint32 leaf_blocks;
    uint32 distinct_keys;
    uint32 keys;
    uint64 keys_total_size;
    uint32 clustor;
    uint32 empty_leaves;
    uint32 comb_cols_2_ndv;
    uint32 comb_cols_3_ndv;
    uint32 comb_cols_4_ndv;
} btree_info_t;

status_t btree_full_stats_info(knl_session_t *session, btree_t *btree, btree_info_t *info);
status_t btree_level_first_page(knl_session_t *session, btree_t *btree, uint16 level, page_id_t *page_id);
status_t btree_stats_leaf_by_parent(knl_session_t *session, btree_t *btree, double sample_ratio_input,
                                    btree_info_t *info, page_id_t page_id_input);
void btree_stats_leaf_page(knl_session_t *session, btree_t *btree, btree_info_t *info, page_id_t *page_id,
                           page_id_t *prev_page_id, btree_key_t *prev_compare_key);

void btree_set_comb_ndv(btree_info_t *info, uint32 col_id_input, uint32 column_count);
void btree_calc_ndv_key(index_t *index, btree_key_t *key, btree_key_t *compare_key, btree_info_t *info);
status_t btree_get_table_by_page(knl_session_t *session, page_head_t *page, uint32 *uid, uint32 *tabid);
status_t btree_get_table_by_rowid(knl_session_t *session, page_head_t *page, rowid_t rowid, uint32 *uid, uint32 *tabid);
#ifdef __cplusplus
}
#endif

#endif
