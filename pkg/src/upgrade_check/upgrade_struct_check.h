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
 * upgrade_struct_check.h
 *
 *
 * IDENTIFICATION
 * src/upgrade_check/upgrade_struct_check.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __UPGRADE_STRUCT_CHECK_H__
#define __UPGRADE_STRUCT_CHECK_H__

#include "cm_defs.h"
#include "cm_spinlock.h"
#include "srv_session.h"
#include "knl_temp.h"
#include "temp_btree.h"
#include "knl_ctrl_restore.h"
#include "dtc_database.h"

#ifdef __cplusplus
extern "C" {
#endif

/* define need check struct size */
#define DATAFILE_HEADER_T_SIZE  (uint32)8
#define SPACE_HEAD_T_SIZE  (uint32)4056
#define LOG_FILE_HEAD_T_SIZE  (uint32)512
#define LOG_FILE_CTRL_BK_T_SIZE  (uint32)336
#define PAGE_HEAD_T_SIZE  (uint32)32
#define PAGE_TAIL_T_SIZE  (uint32)8
#define COMPRESS_PAGE_HEAD_T_SIZE  (uint32)8
#define HEAP_SEGMENT_T_SIZE  (uint32)184
#define HEAP_PAGE_T_SIZE  (uint32)96
#define PCR_ITL_T_SIZE  (uint32)24
#define MAP_PAGE_T_SIZE  (uint32)84
#define BTREE_SEGMENT_T_SIZE  (uint32)184
#define BTREE_PAGE_T_SIZE  (uint32)80
#define PCRB_KEY_T_SIZE  (uint32)12
#define UNDO_SEGMENT_T_SIZE  (uint32)272
#define TXN_T_SIZE  (uint32)28
#define UNDO_PAGE_T_SIZE  (uint32)68
#define LOB_SEGMENT_T_SIZE  (uint32)96
#define LOB_DATA_PAGE_T_SIZE  (uint32)100
#define TEMP_HEAP_PAGE_T_SIZE  (uint32)104
#define TEMP_BTREE_PAGE_T_SIZE  (uint32)88
#define DF_MAP_HEAD_T_SIZE  (uint32)244
#define DF_MAP_PAGE_T_SIZE  (uint32)48
#define CORE_CTRL_T_SIZE  (uint32)2456
#define LOG_FILE_CTRL_T_SIZE  (uint32)328
#define DATAFILE_CTRL_T_SIZE  (uint32)328
#define SPACE_CTRL_T_SIZE  (uint32)4120
#define ARCH_CTRL_T_SIZE  (uint32)352
#define BAK_HEAD_T_SIZE  (uint32)8192
#define LOG_BATCH_T_SIZE  (uint32)72
#define LOG_GROUP_T_SIZE  (uint32)16
#define SPACE_CTRL_BK_T_SIZE  (uint32)120
#define DATAFILE_CTRL_BK_T_SIZE  (uint32)344
#define DTC_NODE_CTRL_T_SIZE  (uint32)176


CM_STATIC_ASSERT(sizeof(datafile_header_t) == DATAFILE_HEADER_T_SIZE);
CM_STATIC_ASSERT(sizeof(space_head_t) == SPACE_HEAD_T_SIZE);
CM_STATIC_ASSERT(sizeof(log_file_head_t) == LOG_FILE_HEAD_T_SIZE);
CM_STATIC_ASSERT(sizeof(log_file_ctrl_bk_t) == LOG_FILE_CTRL_BK_T_SIZE);
CM_STATIC_ASSERT(sizeof(page_head_t) == PAGE_HEAD_T_SIZE);
CM_STATIC_ASSERT(sizeof(page_tail_t) == PAGE_TAIL_T_SIZE);
CM_STATIC_ASSERT(sizeof(compress_page_head_t) == COMPRESS_PAGE_HEAD_T_SIZE);
CM_STATIC_ASSERT(sizeof(heap_segment_t) == HEAP_SEGMENT_T_SIZE);
CM_STATIC_ASSERT(sizeof(heap_page_t) == HEAP_PAGE_T_SIZE);
CM_STATIC_ASSERT(sizeof(pcr_itl_t) == PCR_ITL_T_SIZE);
CM_STATIC_ASSERT(sizeof(map_page_t) == MAP_PAGE_T_SIZE);
CM_STATIC_ASSERT(sizeof(btree_segment_t) == BTREE_SEGMENT_T_SIZE);
CM_STATIC_ASSERT(sizeof(btree_page_t) == BTREE_PAGE_T_SIZE);
CM_STATIC_ASSERT(sizeof(pcrb_key_t) == PCRB_KEY_T_SIZE);
CM_STATIC_ASSERT(sizeof(undo_segment_t) == UNDO_SEGMENT_T_SIZE);
CM_STATIC_ASSERT(sizeof(txn_t) == TXN_T_SIZE);
CM_STATIC_ASSERT(sizeof(undo_page_t) == UNDO_PAGE_T_SIZE);
CM_STATIC_ASSERT(sizeof(lob_segment_t) == LOB_SEGMENT_T_SIZE);
CM_STATIC_ASSERT(sizeof(lob_data_page_t) == LOB_DATA_PAGE_T_SIZE);
CM_STATIC_ASSERT(sizeof(temp_heap_page_t) == TEMP_HEAP_PAGE_T_SIZE);
CM_STATIC_ASSERT(sizeof(temp_btree_page_t) == TEMP_BTREE_PAGE_T_SIZE);
CM_STATIC_ASSERT(sizeof(df_map_head_t) == DF_MAP_HEAD_T_SIZE);
CM_STATIC_ASSERT(sizeof(df_map_page_t) == DF_MAP_PAGE_T_SIZE);
CM_STATIC_ASSERT(sizeof(core_ctrl_t) == CORE_CTRL_T_SIZE);
CM_STATIC_ASSERT(sizeof(log_file_ctrl_t) == LOG_FILE_CTRL_T_SIZE);
CM_STATIC_ASSERT(sizeof(datafile_ctrl_t) == DATAFILE_CTRL_T_SIZE);
CM_STATIC_ASSERT(sizeof(space_ctrl_t) == SPACE_CTRL_T_SIZE);
CM_STATIC_ASSERT(sizeof(arch_ctrl_t) == ARCH_CTRL_T_SIZE);
CM_STATIC_ASSERT(sizeof(bak_head_t) == BAK_HEAD_T_SIZE);
CM_STATIC_ASSERT(sizeof(log_batch_t) == LOG_BATCH_T_SIZE);
CM_STATIC_ASSERT(sizeof(log_group_t) == LOG_GROUP_T_SIZE);
CM_STATIC_ASSERT(sizeof(space_ctrl_bk_t) == SPACE_CTRL_BK_T_SIZE);
CM_STATIC_ASSERT(sizeof(datafile_ctrl_bk_t) == DATAFILE_CTRL_BK_T_SIZE);
CM_STATIC_ASSERT(sizeof(dtc_node_ctrl_t) == DTC_NODE_CTRL_T_SIZE);

#ifdef __cplusplus
}
#endif

#endif