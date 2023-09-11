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
 * pcr_btree_stat.h
 *
 *
 * IDENTIFICATION
 * src/kernel/index/pcr_btree_stat.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __PCR_BTREE_STAT_H__
#define __PCR_BTREE_STAT_H__

#include "rcr_btree_stat.h"
#include "pcr_btree.h"

#ifdef __cplusplus
extern "C" {
#endif

status_t pcrb_get_table_by_page(knl_session_t *session, page_head_t *page, uint32 *uid, uint32 *tabid);
status_t pcrb_full_stats_info(knl_session_t *session, btree_t *btree, btree_info_t *info);
status_t pcrb_stats_leaf_by_parent(knl_session_t *session, btree_t *btree, double sample_ratio_input,
                                   btree_info_t *info, page_id_t page_id_input);

void pcrb_calc_ndv_key(index_t *index, pcrb_key_t *key, pcrb_key_t *compare_key, btree_info_t *info);
void pcrb_stats_leaf_page(knl_session_t *session, btree_t *btree, btree_info_t *info, page_id_t *page_id,
                          page_id_t *prev_page_id, pcrb_key_t *prev_compare_key);
bool32 pcrb_is_key_dead(knl_session_t *session, btree_page_t *page, knl_scn_t min_scn, pcrb_key_t *key);

#ifdef __cplusplus
}
#endif

#endif
