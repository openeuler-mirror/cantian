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
 * gs_page.c
 *
 *
 * IDENTIFICATION
 * src/gstbox/gs_page.c
 *
 * -------------------------------------------------------------------------
 */
#include "gs_page.h"
#include "cm_file.h"
#include "gs_miner.h"
#include "rcr_btree.h"
#include "knl_undo.h"
#include "knl_lob.h"
#include "pcr_heap.h"
#include "pcr_btree.h"
#include "temp_btree.h"

#define MAX_VALUE_LEN 256
#define REPAIR_MAX_KEY_NUM  16

knl_session_t *g_page_se = NULL;
knl_instance_t *g_page_instance = NULL;

typedef struct st_repair_key_item {
    char name[GS_MAX_NAME_LEN];
    uint32 index;
} repair_key_item_t;

typedef struct st_repair_key {
    repair_key_item_t item[REPAIR_MAX_KEY_NUM];
    uint32 page_size;
} repair_key_t;

typedef status_t(*repair_page_proc)(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset);

typedef enum en_repair_page_part {
    REPAIR_PAGE_HEAD = 1,
    REPAIR_PAGE_CTRL = 2,
    REPAIR_PAGE_TAIL = 4
} repair_page_part_t;

typedef struct st_page_repair {
    const char *name;
    uint32 item_size;
    uint32 item_offset;
    repair_page_proc repair_proc;
    struct st_page_repair *child_items;
    uint32 child_num;
} page_repair_t;

typedef struct st_page_type_repair {
    page_type_t type;
    uint32 page_offset;
    page_repair_t page_item;
} page_type_repair_t;

/* used to repair different page ctrl data */
status_t repair_set_page_ctrl(repair_key_t *rkeys, page_head_t *head, text_t *name, text_t *value);
status_t repair_set_page_head(page_head_t *head, text_t *name, text_t *value);
status_t repair_set_page_tail(page_tail_t *tail, text_t *name, text_t *value);

/* basic repair fuction */
static status_t repair_int64(repair_key_t *keys, text_t *value, uint32 curr_id, char *page, uint32 offset);
static status_t repair_uint64(repair_key_t *keys, text_t *value, uint32 curr_id, char *page, uint32 offset);
static status_t repair_uint32(repair_key_t *keys, text_t *value, uint32 curr_id, char *page, uint32 offset);
static status_t repair_uint16(repair_key_t *keys, text_t *value, uint32 curr_id, char *page, uint32 offset);
static status_t repair_uint8(repair_key_t *keys, text_t *value, uint32 curr_id, char *page, uint32 offset);
static status_t repair_knl_scn_t(repair_key_t *keys, text_t *value, uint32 curr_id, char *page, uint32 offset);
static status_t repair_pagid_data_t(repair_key_t *keys, text_t *value, uint32 curr_id, char *page, uint32 offset);
static status_t repair_page_id_t(repair_key_t *keys, text_t *value, uint32 curr_id, char *page, uint32 offset);
static status_t repair_undo_page_id_t(repair_key_t *keys, text_t *value, uint32 curr_id, char *page, uint32 offset);
static status_t repair_rowid_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset);

/* repair_bitof_XXX is used to set bit field variables, because bit field variables has not offset and size */
static status_t repair_bitof_btree_key_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset);
static status_t repair_bitof_pcrb_key_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset);
static status_t repair_bitof_undo_row_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset);
static status_t repair_bitof_row_head_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset);
static status_t repair_bitof_row_dir_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset);
static status_t repair_bitof_map_node_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset);
static status_t repair_bitof_map_index_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset);
static status_t repair_bitof_temp_btree_page_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page,
                                               uint32 offset);
static status_t repair_bitof_btree_page_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page,
    uint32 offset);
static status_t repair_bitof_itl_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset);
static status_t repair_bitof_pcr_itl_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset);
static status_t repair_bitof_heap_segment_t(repair_key_t *rkeys, text_t *value, uint32 curr_id,
    char *page, uint32 offset);

/* below variables has not fixed offset and size, we need calculate its offset first */
static status_t repair_pdata_itl_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset);
static status_t repair_pdata_row_dir_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset);
static status_t repair_pdata_row_head_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset);
static status_t repair_pdata_map_node_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset);
static status_t repair_pdata_undo_row_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset);
static status_t repair_pdata_btree_dir_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset);
static status_t repair_pdata_btree_key_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset);

#define CHILDREN_NUM(parent)                   ((uint32)(sizeof(parent) / sizeof(page_repair_t)))
#define REPAIR_PAGE_TYPE(page, type, offset)    \
    { (page), (uint32)(offset), { #type, 0, 0, NULL, g_##type##_items, CHILDREN_NUM(g_##type##_items) } }
#define REPAIR_ITEM_WITH_CHILD(obj, item, type) \
    { #item, (uint32)sizeof(type), (uint32)OFFSET_OF(obj, item), \
      NULL, g_##type##_items, CHILDREN_NUM(g_##type##_items) }
#define REPAIR_ITEM_WITH_PEER(offset, obj, item, type) \
    { #item, (uint32)sizeof(type), (offset) + (uint32)OFFSET_OF(obj, item), \
      NULL, g_##type##_items, CHILDREN_NUM(g_##type##_items) }

#define REPAIR_ITEM_NO_CHILD(obj, item, type)  \
    { #item, (uint32)sizeof(type), (uint32)OFFSET_OF(obj, item), repair_##type, NULL, 0 }
#define REPAIR_BIT_ITEM(obj, item)             { #item, 0, 0, repair_bitof_##obj, NULL, 0 }
#define REPAIR_PAGE_DATA_ITEM(obj, item)       { #item, 0, 0, repair_pdata_##obj, NULL, 0 }

static page_repair_t g_xmap_t_items[] = {
    REPAIR_ITEM_NO_CHILD(xmap_t, seg_id, uint16),
    REPAIR_ITEM_NO_CHILD(xmap_t, slot, uint16),
};

static page_repair_t g_xid_t_items[] = {
    REPAIR_ITEM_WITH_CHILD(xid_t, xmap, xmap_t),
    REPAIR_ITEM_NO_CHILD(xid_t, xnum, uint32),
};

static page_repair_t g_undo_row_t_items[] = {
    REPAIR_ITEM_NO_CHILD(undo_row_t, rowid, rowid_t),
    REPAIR_BIT_ITEM(undo_row_t, seg_file),
    REPAIR_BIT_ITEM(undo_row_t, seg_page),
    REPAIR_BIT_ITEM(undo_row_t, user_id),
    REPAIR_BIT_ITEM(undo_row_t, index_id),
    REPAIR_ITEM_NO_CHILD(undo_row_t, prev_page, undo_page_id_t),
    REPAIR_ITEM_NO_CHILD(undo_row_t, prev_slot, uint16),
    REPAIR_ITEM_NO_CHILD(undo_row_t, data_size, uint16),
    REPAIR_BIT_ITEM(undo_row_t, is_xfirst),
    REPAIR_BIT_ITEM(undo_row_t, is_owscn),
    REPAIR_BIT_ITEM(undo_row_t, is_cleaned),
    REPAIR_BIT_ITEM(undo_row_t, type),
    REPAIR_ITEM_NO_CHILD(undo_row_t, ssn, uint16),
    REPAIR_ITEM_NO_CHILD(undo_row_t, scn, knl_scn_t),
    REPAIR_ITEM_WITH_CHILD(undo_row_t, xid, xid_t),
    // data not supported
};

static page_repair_t g_undo_page_t_items[] = {
    REPAIR_ITEM_NO_CHILD(undo_page_t, ss_time, uint64),
    REPAIR_ITEM_NO_CHILD(undo_page_t, prev, undo_page_id_t),
    REPAIR_ITEM_NO_CHILD(undo_page_t, rows, uint16),
    REPAIR_ITEM_NO_CHILD(undo_page_t, free_size, uint16),
    REPAIR_ITEM_NO_CHILD(undo_page_t, free_begin, uint16),
    REPAIR_ITEM_NO_CHILD(undo_page_t, begin_slot, uint16),
    REPAIR_PAGE_DATA_ITEM(undo_row_t, page_rows),
};

static page_repair_t g_knl_tree_info_t_items[] = {
    REPAIR_ITEM_NO_CHILD(knl_tree_info_t, root, pagid_data_t),
    REPAIR_ITEM_NO_CHILD(knl_tree_info_t, level, uint16),
};

static page_repair_t g_page_list_t_items[] = {
    REPAIR_ITEM_NO_CHILD(page_list_t, count, uint32),
    REPAIR_ITEM_NO_CHILD(page_list_t, first, page_id_t),
    REPAIR_ITEM_NO_CHILD(page_list_t, last, page_id_t),
};

static page_repair_t g_heap_segment_t_items[] = {
    REPAIR_ITEM_WITH_CHILD(heap_segment_t, tree_info, knl_tree_info_t),
    REPAIR_ITEM_NO_CHILD(heap_segment_t, seg_scn, knl_scn_t),
    REPAIR_ITEM_NO_CHILD(heap_segment_t, org_scn, knl_scn_t),
    REPAIR_ITEM_NO_CHILD(heap_segment_t, oid, uint32),
    REPAIR_ITEM_NO_CHILD(heap_segment_t, uid, uint16),
    REPAIR_ITEM_NO_CHILD(heap_segment_t, space_id, uint16),
    REPAIR_ITEM_NO_CHILD(heap_segment_t, serial, int64),
    REPAIR_ITEM_NO_CHILD(heap_segment_t, ufp_count, uint64),
    REPAIR_ITEM_WITH_CHILD(heap_segment_t, extents, page_list_t),
    REPAIR_ITEM_WITH_CHILD(heap_segment_t, free_extents, page_list_t),
    REPAIR_ITEM_NO_CHILD(heap_segment_t, free_ufp, page_id_t),
    REPAIR_ITEM_NO_CHILD(heap_segment_t, data_first, page_id_t),
    REPAIR_ITEM_NO_CHILD(heap_segment_t, data_last, page_id_t),
    REPAIR_ITEM_NO_CHILD(heap_segment_t, initrans, uint8),
    REPAIR_ITEM_NO_CHILD(heap_segment_t, cr_mode, uint8),
    REPAIR_ITEM_NO_CHILD(heap_segment_t, list_range, uint16),
    REPAIR_ITEM_NO_CHILD(heap_segment_t, map_count, uint32),
    REPAIR_ITEM_NO_CHILD(heap_segment_t, curr_map, page_id_t),
    REPAIR_ITEM_NO_CHILD(heap_segment_t, cmp_hwm, page_id_t),
    REPAIR_ITEM_NO_CHILD(heap_segment_t, page_count, uint32),
    REPAIR_ITEM_NO_CHILD(heap_segment_t, free_page_count, uint32),
    REPAIR_BIT_ITEM(heap_segment_t, last_ext_size),
    REPAIR_BIT_ITEM(heap_segment_t, compress)
};

static page_repair_t g_map_list_t_items[] = {
    REPAIR_ITEM_NO_CHILD(map_list_t, count, uint16),
    REPAIR_ITEM_NO_CHILD(map_list_t, first, uint16),
};

static page_repair_t g_map_node_t_items[] = {
    REPAIR_BIT_ITEM(map_node_t, file),
    REPAIR_BIT_ITEM(map_node_t, page),
    REPAIR_BIT_ITEM(map_node_t, prev),
    REPAIR_BIT_ITEM(map_node_t, next),
};

static page_repair_t g_map_index_t_items[] = {
    REPAIR_BIT_ITEM(map_index_t, file),
    REPAIR_BIT_ITEM(map_index_t, page),
    REPAIR_BIT_ITEM(map_index_t, slot),
    REPAIR_BIT_ITEM(map_index_t, list_id),
};

static page_repair_t g_map_page_t_items[] = {
    REPAIR_ITEM_WITH_CHILD(map_page_t, map, map_index_t),
    REPAIR_ITEM_WITH_CHILD(map_page_t, lists, map_list_t),
    REPAIR_ITEM_NO_CHILD(map_page_t, hwm, uint16),
    REPAIR_PAGE_DATA_ITEM(map_node_t, nodes),
};

static page_repair_t g_itl_t_items[] = {
    REPAIR_ITEM_NO_CHILD(itl_t, scn, knl_scn_t),
    REPAIR_ITEM_WITH_CHILD(itl_t, xid, xid_t),
    REPAIR_ITEM_NO_CHILD(itl_t, fsc, uint16),
    REPAIR_BIT_ITEM(itl_t, is_active),
    REPAIR_BIT_ITEM(itl_t, is_owscn),
    REPAIR_BIT_ITEM(itl_t, is_copied),
};

static page_repair_t g_pcr_itl_t_items[] = {
    REPAIR_ITEM_NO_CHILD(pcr_itl_t, scn, knl_scn_t),
    REPAIR_ITEM_NO_CHILD(pcr_itl_t, ssn, uint32),
    REPAIR_ITEM_NO_CHILD(pcr_itl_t, fsc, uint16),
    REPAIR_ITEM_WITH_CHILD(pcr_itl_t, xid, xid_t),
    REPAIR_ITEM_NO_CHILD(pcr_itl_t, undo_page, undo_page_id_t),
    REPAIR_ITEM_NO_CHILD(pcr_itl_t, undo_slot, uint16),
    REPAIR_BIT_ITEM(pcr_itl_t, is_active),
    REPAIR_BIT_ITEM(pcr_itl_t, is_owscn),
    REPAIR_BIT_ITEM(pcr_itl_t, is_copied),
    REPAIR_BIT_ITEM(pcr_itl_t, is_hist),
    REPAIR_BIT_ITEM(pcr_itl_t, is_fast),
};

static page_repair_t g_pcrb_key_t_items[] = {
    REPAIR_ITEM_NO_CHILD(pcrb_key_t, rowid, rowid_t),
    REPAIR_BIT_ITEM(pcrb_key_t, size),
    REPAIR_BIT_ITEM(pcrb_key_t, is_deleted),
    REPAIR_BIT_ITEM(pcrb_key_t, is_infinite),
    REPAIR_BIT_ITEM(pcrb_key_t, is_cleaned),
    REPAIR_ITEM_NO_CHILD(pcrb_key_t, itl_id, uint8),
    REPAIR_ITEM_NO_CHILD(pcrb_key_t, bitmap, uint16),
};

static page_repair_t g_row_dir_t_items[] = {
    REPAIR_ITEM_NO_CHILD(row_dir_t, offset, uint16),
    REPAIR_BIT_ITEM(row_dir_t, is_owscn),
    REPAIR_BIT_ITEM(row_dir_t, undo_slot),
    REPAIR_BIT_ITEM(row_dir_t, is_free),
    REPAIR_BIT_ITEM(row_dir_t, next_slot),
    REPAIR_ITEM_NO_CHILD(row_dir_t, undo_page, undo_page_id_t),
    REPAIR_ITEM_NO_CHILD(row_dir_t, scn, knl_scn_t),
};

static page_repair_t g_row_head_t_items[] = {
    REPAIR_ITEM_NO_CHILD(row_head_t, size, uint16),
    REPAIR_BIT_ITEM(row_head_t, column_count),
    REPAIR_BIT_ITEM(row_head_t, is_deleted),
    REPAIR_BIT_ITEM(row_head_t, is_link),
    REPAIR_BIT_ITEM(row_head_t, is_migr),
    REPAIR_BIT_ITEM(row_head_t, self_chg),
    REPAIR_BIT_ITEM(row_head_t, is_changed),
    REPAIR_BIT_ITEM(row_head_t, is_csf),
    REPAIR_ITEM_NO_CHILD(row_head_t, sprs_count, uint16),
    REPAIR_ITEM_NO_CHILD(row_head_t, sprs_itl_id, uint8),
    REPAIR_ITEM_NO_CHILD(row_head_t, sprs_bitmap, uint8),
    REPAIR_ITEM_NO_CHILD(row_head_t, itl_id, uint8),
    REPAIR_ITEM_NO_CHILD(row_head_t, bitmap, uint8),
};

/* normal heap page and pcr heap page use one heap_page_t_items */
static page_repair_t g_heap_page_t_items[] = {
    REPAIR_ITEM_WITH_CHILD(heap_page_t, map, map_index_t),
    REPAIR_ITEM_NO_CHILD(heap_page_t, seg_scn, knl_scn_t),
    REPAIR_ITEM_NO_CHILD(heap_page_t, org_scn, knl_scn_t),
    REPAIR_ITEM_NO_CHILD(heap_page_t, oid, uint32),
    REPAIR_ITEM_NO_CHILD(heap_page_t, uid, uint16),
    REPAIR_ITEM_NO_CHILD(heap_page_t, first_free_dir, uint16),
    REPAIR_ITEM_NO_CHILD(heap_page_t, next, pagid_data_t),
    REPAIR_ITEM_NO_CHILD(heap_page_t, free_begin, uint16),
    REPAIR_ITEM_NO_CHILD(heap_page_t, free_end, uint16),
    REPAIR_ITEM_NO_CHILD(heap_page_t, free_size, uint16),
    REPAIR_ITEM_NO_CHILD(heap_page_t, rows, uint16),
    REPAIR_ITEM_NO_CHILD(heap_page_t, dirs, uint16),
    REPAIR_ITEM_NO_CHILD(heap_page_t, itls, uint8),
    REPAIR_ITEM_NO_CHILD(heap_page_t, scn, knl_scn_t),
    REPAIR_PAGE_DATA_ITEM(itl_t, page_itls),
    REPAIR_PAGE_DATA_ITEM(row_dir_t, page_dirs),
    REPAIR_PAGE_DATA_ITEM(row_head_t, page_rows),
};

static page_repair_t g_space_head_t_items[] = {
    REPAIR_ITEM_NO_CHILD(space_head_t, segment_count, uint32),
    REPAIR_ITEM_WITH_CHILD(space_head_t, free_extents, page_list_t),
    REPAIR_ITEM_NO_CHILD(space_head_t, datafile_count, uint32),
    REPAIR_ITEM_NO_CHILD(space_head_t, hwms, uint32),
    REPAIR_ITEM_WITH_PEER(sizeof(space_head_t), spc_punch_head_t, punching_exts, page_list_t),
    REPAIR_ITEM_WITH_PEER(sizeof(space_head_t), spc_punch_head_t, punched_exts, page_list_t),
};

static page_repair_t g_undo_page_list_t_items[] = {
    REPAIR_ITEM_NO_CHILD(undo_page_list_t, count, uint32),
    REPAIR_ITEM_NO_CHILD(undo_page_list_t, first, undo_page_id_t),
    REPAIR_ITEM_NO_CHILD(undo_page_list_t, last, undo_page_id_t),
};

static page_repair_t g_undo_segment_t_items[] = {
    REPAIR_ITEM_WITH_CHILD(undo_segment_t, page_list, undo_page_list_t),
    REPAIR_ITEM_NO_CHILD(undo_segment_t, txn_page_count, uint32),
    REPAIR_ITEM_NO_CHILD(undo_segment_t, txn_page, undo_page_id_t),
};

static page_repair_t g_txn_t_items[] = {
    REPAIR_ITEM_NO_CHILD(txn_t, scn, knl_scn_t),
    REPAIR_ITEM_WITH_CHILD(txn_t, undo_pages, undo_page_list_t),
    REPAIR_ITEM_NO_CHILD(txn_t, xnum, uint32),
    REPAIR_ITEM_NO_CHILD(txn_t, status, uint8),
};

static page_repair_t g_df_map_group_t_items[] = {
    REPAIR_ITEM_NO_CHILD(df_map_group_t, first_map, page_id_t),
    REPAIR_ITEM_NO_CHILD(df_map_group_t, page_count, uint8),
};

static page_repair_t g_txn_page_t_items[] = {
    REPAIR_ITEM_WITH_CHILD(txn_page_t, items, txn_t),
};

static page_repair_t g_btree_segment_t_items[] = {
    REPAIR_ITEM_WITH_CHILD(btree_segment_t, tree_info, knl_tree_info_t),
    REPAIR_ITEM_NO_CHILD(btree_segment_t, org_scn, knl_scn_t),
    REPAIR_ITEM_NO_CHILD(btree_segment_t, seg_scn, knl_scn_t),
    REPAIR_ITEM_NO_CHILD(btree_segment_t, table_id, uint32),
    REPAIR_ITEM_NO_CHILD(btree_segment_t, uid, uint16),
    REPAIR_ITEM_NO_CHILD(btree_segment_t, index_id, uint16),
    REPAIR_ITEM_NO_CHILD(btree_segment_t, space_id, uint16),
    REPAIR_ITEM_NO_CHILD(btree_segment_t, initrans, uint8),
    REPAIR_ITEM_NO_CHILD(btree_segment_t, cr_mode, uint8),
    REPAIR_ITEM_WITH_CHILD(btree_segment_t, extents, page_list_t),
    REPAIR_ITEM_NO_CHILD(btree_segment_t, ufp_count, uint32),
    REPAIR_ITEM_NO_CHILD(btree_segment_t, ufp_first, page_id_t),
    REPAIR_ITEM_NO_CHILD(btree_segment_t, ufp_extent, page_id_t),
    REPAIR_ITEM_NO_CHILD(btree_segment_t, del_scn, knl_scn_t),
    REPAIR_ITEM_WITH_CHILD(btree_segment_t, del_pages, page_list_t),
    REPAIR_ITEM_NO_CHILD(btree_segment_t, pctfree, uint32),
    REPAIR_ITEM_NO_CHILD(btree_segment_t, page_count, uint32),
    REPAIR_ITEM_NO_CHILD(btree_segment_t, garbage_size, uint64),
    REPAIR_ITEM_NO_CHILD(btree_segment_t, first_recycle_scn, knl_scn_t),
    REPAIR_ITEM_NO_CHILD(btree_segment_t, ow_del_scn, knl_scn_t),
    REPAIR_ITEM_NO_CHILD(btree_segment_t, ow_recycle_scn, knl_scn_t),
    REPAIR_ITEM_NO_CHILD(btree_segment_t, last_recycle_scn, knl_scn_t),
    REPAIR_ITEM_WITH_CHILD(btree_segment_t, recycled_pages, page_list_t),
    REPAIR_ITEM_NO_CHILD(btree_segment_t, recycle_ver_scn, knl_scn_t),
};

static page_repair_t g_btree_dir_t_items[] = {
    REPAIR_ITEM_NO_CHILD(btree_dir_t, offset, uint16),
    REPAIR_ITEM_NO_CHILD(btree_dir_t, itl_id, uint8),
};

static page_repair_t g_btree_key_t_items[] = {
    REPAIR_ITEM_NO_CHILD(btree_key_t, scn, knl_scn_t),
    REPAIR_ITEM_NO_CHILD(btree_key_t, child, page_id_t),
    REPAIR_ITEM_NO_CHILD(btree_key_t, rowid, rowid_t),
    REPAIR_BIT_ITEM(btree_key_t, size),
    REPAIR_ITEM_NO_CHILD(btree_key_t, undo_page, undo_page_id_t),
    REPAIR_BIT_ITEM(btree_key_t, undo_slot),
    REPAIR_BIT_ITEM(btree_key_t, is_deleted),
    REPAIR_BIT_ITEM(btree_key_t, is_infinite),
    REPAIR_BIT_ITEM(btree_key_t, is_owscn),
    REPAIR_BIT_ITEM(btree_key_t, is_cleaned),
    REPAIR_ITEM_NO_CHILD(btree_key_t, bitmap, uint16),
};

static page_repair_t g_btree_page_t_items[] = {
    REPAIR_ITEM_NO_CHILD(btree_page_t, seg_scn, knl_scn_t),
    REPAIR_BIT_ITEM(btree_page_t, is_recycled),
    REPAIR_ITEM_NO_CHILD(btree_page_t, keys, uint16),
    REPAIR_ITEM_NO_CHILD(btree_page_t, prev, pagid_data_t),
    REPAIR_ITEM_NO_CHILD(btree_page_t, level, uint8),
    REPAIR_ITEM_NO_CHILD(btree_page_t, itls, uint8),
    REPAIR_ITEM_NO_CHILD(btree_page_t, next, pagid_data_t),
    REPAIR_ITEM_NO_CHILD(btree_page_t, free_begin, uint16),
    REPAIR_ITEM_NO_CHILD(btree_page_t, free_end, uint16),
    REPAIR_ITEM_NO_CHILD(btree_page_t, free_size, uint16),
    REPAIR_ITEM_NO_CHILD(btree_page_t, scn, knl_scn_t),
    REPAIR_PAGE_DATA_ITEM(btree_dir_t, page_dirs),
    REPAIR_PAGE_DATA_ITEM(btree_key_t, page_keys),
};

static page_repair_t g_lob_segment_t_items[] = {
    REPAIR_ITEM_NO_CHILD(lob_segment_t, org_scn, knl_scn_t),
    REPAIR_ITEM_NO_CHILD(lob_segment_t, seg_scn, knl_scn_t),
    REPAIR_ITEM_NO_CHILD(lob_segment_t, table_id, uint32),
    REPAIR_ITEM_NO_CHILD(lob_segment_t, uid, uint16),
    REPAIR_ITEM_NO_CHILD(lob_segment_t, space_id, uint16),
    REPAIR_ITEM_NO_CHILD(lob_segment_t, column_id, uint16),
    REPAIR_ITEM_WITH_CHILD(lob_segment_t, extents, page_list_t),
    REPAIR_ITEM_WITH_CHILD(lob_segment_t, free_list, page_list_t),
    REPAIR_ITEM_NO_CHILD(lob_segment_t, ufp_count, uint32),
    REPAIR_ITEM_NO_CHILD(lob_segment_t, ufp_first, page_id_t),
    REPAIR_ITEM_NO_CHILD(lob_segment_t, ufp_extent, page_id_t),
    REPAIR_ITEM_NO_CHILD(lob_segment_t, shrink_scn, knl_scn_t),
};

static page_repair_t g_lob_chunk_t_items[] = {
    REPAIR_ITEM_WITH_CHILD(lob_chunk_t, ins_xid, xid_t),
    REPAIR_ITEM_WITH_CHILD(lob_chunk_t, del_xid, xid_t),
    REPAIR_ITEM_NO_CHILD(lob_chunk_t, org_scn, knl_scn_t),
    REPAIR_ITEM_NO_CHILD(lob_chunk_t, size, uint32),
    REPAIR_ITEM_NO_CHILD(lob_chunk_t, next, page_id_t),
    REPAIR_ITEM_NO_CHILD(lob_chunk_t, free_next, page_id_t),
    REPAIR_ITEM_NO_CHILD(lob_chunk_t, is_recycled, uint32),
};

static page_repair_t g_lob_data_page_t_items[] = {
    REPAIR_ITEM_WITH_CHILD(lob_data_page_t, chunk, lob_chunk_t),
};

static page_repair_t g_temp_heap_page_t_items[] = {
    REPAIR_ITEM_WITH_CHILD(temp_heap_page_t, map, map_index_t),
    REPAIR_ITEM_NO_CHILD(temp_heap_page_t, org_scn, knl_scn_t),
    REPAIR_ITEM_NO_CHILD(temp_heap_page_t, seg_scn, knl_scn_t),
    REPAIR_ITEM_NO_CHILD(temp_heap_page_t, oid, uint32),
    REPAIR_ITEM_NO_CHILD(temp_heap_page_t, uid, uint16),
    REPAIR_ITEM_NO_CHILD(temp_heap_page_t, first_free_dir, uint16),
    REPAIR_ITEM_NO_CHILD(temp_heap_page_t, next, pagid_data_t),
    REPAIR_ITEM_NO_CHILD(temp_heap_page_t, free_begin, uint32),
    REPAIR_ITEM_NO_CHILD(temp_heap_page_t, free_end, uint32),
    REPAIR_ITEM_NO_CHILD(temp_heap_page_t, free_size, uint32),
    REPAIR_ITEM_NO_CHILD(temp_heap_page_t, rows, uint16),
    REPAIR_ITEM_NO_CHILD(temp_heap_page_t, dirs, uint16),
    REPAIR_ITEM_NO_CHILD(temp_heap_page_t, itls, uint8),
};

static page_repair_t g_temp_btree_page_t_items[] = {
    REPAIR_ITEM_NO_CHILD(temp_btree_page_t, seg_scn, knl_scn_t),
    REPAIR_BIT_ITEM(temp_btree_page_t, is_recycled),
    REPAIR_ITEM_NO_CHILD(temp_btree_page_t, keys, uint16),
    REPAIR_ITEM_NO_CHILD(temp_btree_page_t, prev, pagid_data_t),
    REPAIR_ITEM_NO_CHILD(temp_btree_page_t, level, uint8),
    REPAIR_ITEM_NO_CHILD(temp_btree_page_t, itls, uint8),
    REPAIR_ITEM_NO_CHILD(temp_btree_page_t, next, pagid_data_t),
    REPAIR_ITEM_NO_CHILD(temp_btree_page_t, free_begin, uint32),
    REPAIR_ITEM_NO_CHILD(temp_btree_page_t, free_end, uint32),
    REPAIR_ITEM_NO_CHILD(temp_btree_page_t, free_size, uint32),
};

static page_repair_t g_df_map_head_t_items[] = {
    REPAIR_ITEM_NO_CHILD(df_map_head_t, bit_unit, uint16),
    REPAIR_ITEM_NO_CHILD(df_map_head_t, group_count, uint16),
    REPAIR_ITEM_WITH_CHILD(df_map_head_t, groups, df_map_group_t),
};

static page_repair_t g_df_map_page_t_items[] = {
    REPAIR_ITEM_NO_CHILD(df_map_page_t, first_page, page_id_t),
    REPAIR_ITEM_NO_CHILD(df_map_page_t, free_begin, uint16),
    REPAIR_ITEM_NO_CHILD(df_map_page_t, free_bits, uint16),
    REPAIR_ITEM_NO_CHILD(df_map_page_t, bitmap, uint8),
};

static page_type_repair_t g_page_ctrl_items[] = {
    REPAIR_PAGE_TYPE(PAGE_TYPE_SPACE_HEAD,  space_head_t,       PAGE_HEAD_SIZE),
    REPAIR_PAGE_TYPE(PAGE_TYPE_HEAP_HEAD,   heap_segment_t,     PAGE_HEAD_SIZE),
    REPAIR_PAGE_TYPE(PAGE_TYPE_HEAP_MAP,    map_page_t,         0),
    REPAIR_PAGE_TYPE(PAGE_TYPE_HEAP_DATA,   heap_page_t,        0),
    REPAIR_PAGE_TYPE(PAGE_TYPE_UNDO_HEAD,   undo_segment_t,     PAGE_HEAD_SIZE),
    REPAIR_PAGE_TYPE(PAGE_TYPE_TXN,         txn_page_t,         0),
    REPAIR_PAGE_TYPE(PAGE_TYPE_UNDO,        undo_page_t,        0),
    REPAIR_PAGE_TYPE(PAGE_TYPE_BTREE_HEAD,  btree_segment_t,    CM_ALIGN8(sizeof(btree_page_t))),
    REPAIR_PAGE_TYPE(PAGE_TYPE_BTREE_NODE,  btree_page_t,       0),
    REPAIR_PAGE_TYPE(PAGE_TYPE_LOB_HEAD,    lob_segment_t,      PAGE_HEAD_SIZE),
    REPAIR_PAGE_TYPE(PAGE_TYPE_LOB_DATA,    lob_data_page_t,    0),
    REPAIR_PAGE_TYPE(PAGE_TYPE_TEMP_HEAP,   temp_heap_page_t,   0),
    REPAIR_PAGE_TYPE(PAGE_TYPE_TEMP_INDEX,  temp_btree_page_t,  0),
    REPAIR_PAGE_TYPE(PAGE_TYPE_PCRH_DATA,   heap_page_t,        0),
    REPAIR_PAGE_TYPE(PAGE_TYPE_PCRB_NODE,   btree_page_t,       0),
    REPAIR_PAGE_TYPE(PAGE_TYPE_DF_MAP_HEAD, df_map_head_t,      0),
    REPAIR_PAGE_TYPE(PAGE_TYPE_DF_MAP_DATA, df_map_page_t,      0),
};

#define REPAIR_PAGE_TYPE_NUM    (sizeof(g_page_ctrl_items) / sizeof(page_type_repair_t))

page_repair_t *repair_get_child_item(page_repair_t *parent, const char *child_name)
{
    for (uint32 i = 0; i < parent->child_num; i++) {
        if (cm_str_equal(child_name, parent->child_items[i].name)) {
            return &parent->child_items[i];
        }
    }
    return NULL;
}

static status_t repair_common_entry(repair_key_t *rkeys, text_t *value, char *page, uint32 curr_id, uint32 item_offset,
    page_repair_t *curr_item)
{
    uint32 child_offset;
    page_repair_t *child = NULL;

    if (rkeys->item[curr_id].name[0] == '\0') {
        printf("expect more child item after \'%s\'\n", rkeys->item[curr_id - 1].name);
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, rkeys->item[curr_id].name);
        return GS_ERROR;
    }

    if (curr_item->child_items == NULL) { // is last child
        if (curr_item->repair_proc == NULL) {
            printf("no repair_proc implement for item \'%s\'\n", rkeys->item[curr_id].name);
            GS_THROW_ERROR(ERR_INVALID_PARAMETER, rkeys->item[curr_id].name);
            return GS_ERROR;
        }

        if (item_offset + curr_item->item_size > rkeys->page_size) {
            printf("invalid offset %u for item \'%s\', page size is %u\n",
                   item_offset, rkeys->item[curr_id].name, rkeys->page_size);
            GS_THROW_ERROR(ERR_INVALID_PARAMETER, rkeys->item[curr_id].name);
            return GS_ERROR;
        }

        return curr_item->repair_proc(rkeys, value, curr_id, page, item_offset);
    }

    child = repair_get_child_item(curr_item, rkeys->item[curr_id + 1].name);
    if (child == NULL) {
        printf("child item \'%s\' is not found in object \'%s\'\n",
               rkeys->item[curr_id + 1].name, rkeys->item[curr_id].name);
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, rkeys->item[curr_id + 1].name);
        return GS_ERROR;
    }

    child_offset = item_offset + child->item_offset;
    if (rkeys->item[curr_id + 1].index != GS_INVALID_ID32) {
        child_offset += child->item_size * rkeys->item[curr_id + 1].index; // for array value
    }

    return repair_common_entry(rkeys, value, page, curr_id + 1, child_offset, child);
}

static status_t repair_expect_end(repair_key_t *rkeys, uint32 curr_id)
{
    if (rkeys->item[curr_id + 1].name[0] != '\0') {
        printf("expect end but found child item \'%s\' after \'%s\'\n",
               rkeys->item[curr_id + 1].name, rkeys->item[curr_id].name);
        GS_THROW_ERROR(ERR_INVALID_PARAMETER, rkeys->item[curr_id + 1].name);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t repair_uint64(repair_key_t *keys, text_t *value, uint32 curr_id, char *page, uint32 offset)
{
    char *child = page + offset;

    if (repair_expect_end(keys, curr_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return cm_text2uint64_ex(value, (uint64 *)child);
}

static status_t repair_int64(repair_key_t *keys, text_t *value, uint32 curr_id, char *page, uint32 offset)
{
    char *child = page + offset;

    if (repair_expect_end(keys, curr_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return cm_text2bigint(value, (int64 *)child);
}

static status_t repair_uint32(repair_key_t *keys, text_t *value, uint32 curr_id, char *page, uint32 offset)
{
    char *child = page + offset;

    if (repair_expect_end(keys, curr_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return cm_text2uint32(value, (uint32 *)child);
}

static status_t repair_uint16(repair_key_t *keys, text_t *value, uint32 curr_id, char *page, uint32 offset)
{
    char *child = page + offset;

    if (repair_expect_end(keys, curr_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    return cm_text2uint16(value, (uint16 *)child);
}

static status_t repair_uint8(repair_key_t *keys, text_t *value, uint32 curr_id, char *page, uint32 offset)
{
    uint8 *child = (uint8 *)(page + offset);
    uint16 u16_value;

    if (repair_expect_end(keys, curr_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_text2uint16(value, &u16_value) != GS_SUCCESS) {
        return GS_ERROR;
    }

    *child = (uint8)u16_value;
    return GS_SUCCESS;
}

static status_t repair_knl_scn_t(repair_key_t *keys, text_t *value, uint32 curr_id, char *page, uint32 offset)
{
    return repair_uint64(keys, value, curr_id, page, offset);
}

static status_t repair_undo_page_id_t(repair_key_t *keys, text_t *value, uint32 curr_id, char *page, uint32 offset)
{
    undo_page_id_t *undo_page_id = (undo_page_id_t *)(page + offset);
    text_t file_str;
    text_t page_str;
    uint32 uint32_value;

    if (repair_expect_end(keys, curr_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    cm_split_text(value, '-', '\0', &file_str, &page_str);
    cm_trim_text(&file_str);
    cm_trim_text(&page_str);

    if (cm_text2uint32(&file_str, &uint32_value) != GS_SUCCESS) {
        return GS_ERROR;
    }
    undo_page_id->file = uint32_value;

    if (cm_text2uint32(&page_str, &uint32_value) != GS_SUCCESS) {
        return GS_ERROR;
    }
    undo_page_id->page = uint32_value;

    return GS_SUCCESS;
}

static status_t repair_pagid_data_t(repair_key_t *keys, text_t *value, uint32 curr_id, char *page, uint32 offset)
{
    pagid_data_t *page_data = (pagid_data_t *)(page + offset);
    text_t file_str;
    text_t page_str;
    page_id_t page_id;

    if (repair_expect_end(keys, curr_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    cm_split_text(value, '-', '\0', &file_str, &page_str);
    cm_trim_text(&file_str);
    cm_trim_text(&page_str);

    if (cm_text2uint16(&file_str, &page_id.file) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_text2uint32(&page_str, &page_id.page) != GS_SUCCESS) {
        return GS_ERROR;
    }

    TO_PAGID_DATA(page_id, page_data);
    return GS_SUCCESS;
}

static status_t repair_page_id_t(repair_key_t *keys, text_t *value, uint32 curr_id, char *page, uint32 offset)
{
    page_id_t *page_id = (page_id_t *)(page + offset);
    text_t file_str;
    text_t page_str;
    uint16 uint16_value;
    uint32 uint32_value;

    if (repair_expect_end(keys, curr_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    cm_split_text(value, '-', '\0', &file_str, &page_str);
    cm_trim_text(&file_str);
    cm_trim_text(&page_str);

    if (cm_text2uint16(&file_str, &uint16_value) != GS_SUCCESS) {
        return GS_ERROR;
    }
    page_id->file = uint16_value;

    if (cm_text2uint32(&page_str, &uint32_value) != GS_SUCCESS) {
        return GS_ERROR;
    }
    page_id->page = uint32_value;

    return GS_SUCCESS;
}

static status_t repair_bitof_row_head_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset)
{
    char *name = rkeys->item[curr_id].name;
    row_head_t *heap_row = (row_head_t *)(page + offset);
    uint16 uint16_value;

    if (repair_expect_end(rkeys, curr_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_text2uint16(value, &uint16_value) != GS_SUCCESS) {
        printf("\'%s\' cannot convert to uint16 when repair \'%s\' of row_head_t\n", value->str, name);
        return GS_ERROR;
    }

    if (cm_str_equal(name, "column_count")) {
        heap_row->column_count = uint16_value;
    } else if (cm_str_equal(name, "is_deleted")) {
        heap_row->is_deleted = uint16_value;
    } else if (cm_str_equal(name, "is_link")) {
        heap_row->is_link = uint16_value;
    } else if (cm_str_equal(name, "is_migr")) {
        heap_row->is_migr = uint16_value;
    } else if (cm_str_equal(name, "self_chg")) {
        heap_row->self_chg = uint16_value;
    } else if (cm_str_equal(name, "is_changed")) {
        heap_row->is_changed = uint16_value;
    } else if (cm_str_equal(name, "is_csf")) {
        heap_row->is_csf = uint16_value;
    } else {
        printf("bit value \'%s\' is not found in row_head_t\n", name);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t repair_bitof_row_dir_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset)
{
    char *name = rkeys->item[curr_id].name;
    row_dir_t *heap_dir = (row_dir_t *)(page + offset);
    uint16 uint16_value;

    if (repair_expect_end(rkeys, curr_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_text2uint16(value, &uint16_value) != GS_SUCCESS) {
        printf("\'%s\' cannot convert to uint16 when repair \'%s\' of row_dir_t\n", value->str, name);
        return GS_ERROR;
    }

    if (cm_str_equal(name, "is_owscn")) {
        heap_dir->is_owscn = uint16_value;
    } else if (cm_str_equal(name, "undo_slot")) {
        heap_dir->undo_slot = uint16_value;
    } else if (cm_str_equal(name, "is_free")) {
        heap_dir->is_free = uint16_value;
    } else if (cm_str_equal(name, "next_slot")) {
        heap_dir->next_slot = uint16_value;
    } else {
        printf("bit value \'%s\' is not found in row_dir_t\n", name);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t repair_bitof_undo_row_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page,
                                        uint32 offset)
{
    char *name = rkeys->item[curr_id].name;
    undo_row_t *undo_row = (undo_row_t *)(page + offset);
    uint64 uint64_value;
    uint16 uint16_value;

    if (repair_expect_end(rkeys, curr_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_text2uint64_ex(value, &uint64_value) != NERR_SUCCESS) {
        printf("\'%s\' cannot convert to uint64 when repair \'%s\' of undo_row_t\n", value->str, name);
        return GS_ERROR;
    }
    uint16_value = (uint16)uint64_value;

    if (cm_str_equal(name, "seg_file")) {
        undo_row->seg_file = uint64_value;
    } else if (cm_str_equal(name, "seg_page")) {
        undo_row->seg_page = uint64_value;
    } else if (cm_str_equal(name, "user_id")) {
        undo_row->user_id = uint64_value;
    } else if (cm_str_equal(name, "index_id")) {
        undo_row->index_id = uint64_value;
    } else if (cm_str_equal(name, "is_xfirst")) {
        undo_row->is_xfirst = uint16_value;
    } else if (cm_str_equal(name, "is_owscn")) {
        undo_row->is_owscn = uint16_value;
    } else if (cm_str_equal(name, "is_cleaned")) {
        undo_row->is_cleaned = uint16_value;
    } else if (cm_str_equal(name, "type")) {
        undo_row->type = uint16_value;
    } else {
        printf("bit value \'%s\' is not found in undo_row_t\n", name);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t repair_bitof_temp_btree_page_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page,
                                               uint32 offset)
{
    char *name = rkeys->item[curr_id].name;
    temp_btree_page_t *temp_btree_page = (temp_btree_page_t *)(page + offset);
    uint16 uint16_value;

    if (repair_expect_end(rkeys, curr_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_text2uint16(value, &uint16_value) != GS_SUCCESS) {
        printf("\'%s\' cannot convert to uint16 when repair \'%s\' of temp_btree_page_t\n", value->str, name);
        return GS_ERROR;
    }

    if (cm_str_equal(name, "is_recycled")) {
        temp_btree_page->is_recycled = uint16_value;
    } else {
        printf("bit value \'%s\' is not found in temp_btree_page_t\n", name);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t repair_bitof_btree_key_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset)
{
    char *name = rkeys->item[curr_id].name;
    btree_key_t *key = (btree_key_t *)(page + offset);
    uint64 uint64_value;
    uint16 uint16_value;

    if (repair_expect_end(rkeys, curr_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_text2uint64_ex(value, &uint64_value) != NERR_SUCCESS) {
        printf("\'%s\' cannot convert to uint64 when repair \'%s\' of btree_key_t\n", value->str, name);
        return GS_ERROR;
    }
    uint16_value = (uint16)uint64_value;

    if (cm_str_equal(name, "size")) {
        key->size = uint64_value;
    } else if (cm_str_equal(name, "undo_slot")) {
        key->undo_slot = uint16_value;
    } else if (cm_str_equal(name, "is_deleted")) {
        key->is_deleted = uint16_value;
    } else if (cm_str_equal(name, "is_infinite")) {
        key->is_infinite = uint16_value;
    } else if (cm_str_equal(name, "is_owscn")) {
        key->is_owscn = uint16_value;
    } else if (cm_str_equal(name, "is_cleaned")) {
        key->is_cleaned = uint16_value;
    } else {
        printf("bit value \'%s\' is not found in btree_key_t\n", name);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t repair_bitof_btree_page_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page,
                                          uint32 offset)
{
    char *name = rkeys->item[curr_id].name;
    btree_page_t *btree_page = (btree_page_t *)(page + offset);
    uint16 uint16_value;

    if (repair_expect_end(rkeys, curr_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_text2uint16(value, &uint16_value) != GS_SUCCESS) {
        printf("\'%s\' cannot convert to uint16 when repair \'%s\' of btree_page_t\n", value->str, name);
        return GS_ERROR;
    }

    if (cm_str_equal(name, "is_recycled")) {
        btree_page->is_recycled = uint16_value;
    } else {
        printf("bit value \'%s\' is not found in btree_page_t\n", name);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

static status_t repair_bitof_itl_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset)
{
    char *name = rkeys->item[curr_id].name;
    itl_t *heap_itl = (itl_t *)(page + offset);
    uint16 uint16_value;

    if (repair_expect_end(rkeys, curr_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_text2uint16(value, &uint16_value) != GS_SUCCESS) {
        printf("\'%s\' cannot convert to uint16 when repair \'%s\' of itl_t\n", value->str, name);
        return GS_ERROR;
    }

    if (cm_str_equal(name, "is_active")) {
        heap_itl->is_active = uint16_value;
    } else if (cm_str_equal(name, "is_owscn")) {
        heap_itl->is_owscn = uint16_value;
    } else if (cm_str_equal(name, "is_copied")) {
        heap_itl->is_copied = uint16_value;
    } else {
        printf("bit value \'%s\' is not found in itl_t\n", name);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t repair_bitof_pcrb_key_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset)
{
    char *name = rkeys->item[curr_id].name;
    pcrb_key_t *pcrb_key = (pcrb_key_t *)(page + offset);
    uint64 uint64_value;
    uint8 uint8_value;

    if (repair_expect_end(rkeys, curr_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_text2uint64_ex(value, &uint64_value) != NERR_SUCCESS) {
        printf("\'%s\' cannot convert to uint64 when repair \'%s\' of pcrb_key_t\n", value->str, name);
        return GS_ERROR;
    }
    uint8_value = (uint8)uint64_value;

    if (cm_str_equal(name, "size")) {
        pcrb_key->size = uint64_value;
    } else if (cm_str_equal(name, "is_deleted")) {
        pcrb_key->is_deleted = uint8_value;
    } else if (cm_str_equal(name, "is_infinite")) {
        pcrb_key->is_infinite = uint8_value;
    } else if (cm_str_equal(name, "is_cleaned")) {
        pcrb_key->is_cleaned = uint8_value;
    } else {
        printf("bit value \'%s\' is not found in pcrb_key_t\n", name);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t repair_bitof_pcr_itl_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset)
{
    char *name = rkeys->item[curr_id].name;
    pcr_itl_t *pcr_itl = (pcr_itl_t *)(page + offset);
    uint16 uint16_value;

    if (repair_expect_end(rkeys, curr_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_text2uint16(value, &uint16_value) != GS_SUCCESS) {
        printf("\'%s\' cannot convert to uint16 when repair \'%s\' of pcr_itl_t\n", value->str, name);
        return GS_ERROR;
    }

    if (cm_str_equal(name, "is_active")) {
        pcr_itl->is_active = uint16_value;
    } else if (cm_str_equal(name, "is_owscn")) {
        pcr_itl->is_owscn = uint16_value;
    } else if (cm_str_equal(name, "is_copied")) {
        pcr_itl->is_copied = uint16_value;
    } else if (cm_str_equal(name, "is_hist")) {
        pcr_itl->is_hist = uint16_value;
    } else if (cm_str_equal(name, "is_fast")) {
        pcr_itl->is_fast = uint16_value;
    } else {
        printf("bit value \'%s\' is not found in pcr_itl_t\n", name);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t repair_bitof_map_node_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset)
{
    char *name = rkeys->item[curr_id].name;
    map_node_t *map_node = (map_node_t *)(page + offset);
    uint64 uint64_value;

    if (repair_expect_end(rkeys, curr_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_text2uint64_ex(value, &uint64_value) != NERR_SUCCESS) {
        printf("\'%s\' cannot convert to uint64 when repair \'%s\' of map_node_t\n", value->str, name);
        return GS_ERROR;
    }

    if (cm_str_equal(name, "file")) {
        map_node->file = uint64_value;
    } else if (cm_str_equal(name, "page")) {
        map_node->page = uint64_value;
    } else if (cm_str_equal(name, "prev")) {
        map_node->prev = uint64_value;
    } else if (cm_str_equal(name, "next")) {
        map_node->next = uint64_value;
    } else {
        printf("bit value \'%s\' is not found in map_node_t\n", name);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t repair_bitof_map_index_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset)
{
    char *name = rkeys->item[curr_id].name;
    map_index_t *map_index = (map_index_t *)(page + offset);
    uint64 uint64_value;

    if (repair_expect_end(rkeys, curr_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_text2uint64_ex(value, &uint64_value) != NERR_SUCCESS) {
        printf("\'%s\' cannot convert to uint64 when repair \'%s\' of map_index_t\n", value->str, name);
        return GS_ERROR;
    }

    if (cm_str_equal(name, "file")) {
        map_index->file = uint64_value;
    } else if (cm_str_equal(name, "page")) {
        map_index->page = uint64_value;
    } else if (cm_str_equal(name, "slot")) {
        map_index->slot = uint64_value;
    } else if (cm_str_equal(name, "list_id")) {
        map_index->list_id = uint64_value;
    } else {
        printf("bit value \'%s\' is not found in map_index_t\n", name);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t repair_bitof_heap_segment_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page,
    uint32 offset)
{
    char *name = rkeys->item[curr_id].name;
    heap_segment_t *segment = (heap_segment_t *)(page + offset);
    uint32 uint32_value;

    if (repair_expect_end(rkeys, curr_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_text2uint32_ex(value, &uint32_value) != NERR_SUCCESS) {
        printf("\'%s\' cannot convert to uint32 when repair \'%s\' of heap_segment_t\n", value->str, name);
        return GS_ERROR;
    }

    uint8 uint8_value = (uint8)uint32_value;
    if (cm_str_equal(name, "last_ext_size")) {
        segment->last_ext_size = uint8_value;
    } else if (cm_str_equal(name, "compress")) {
        segment->compress = (uint8)uint32_value;
    } else {
        printf("bit value \'%s\' is not found in heap_segment_t\n", name);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

/* all items of rowid_t is bit value */
static status_t repair_rowid_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset)
{
    char *name = rkeys->item[curr_id].name;
    rowid_t *child = (rowid_t *)(page + offset);
    uint64 uint64_value;

    if (repair_expect_end(rkeys, curr_id) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (cm_text2uint64_ex(value, &uint64_value) != NERR_SUCCESS) {
        printf("\'%s\' cannot convert to uint64 when repair \'%s\' of rowid_t\n", value->str, name);
        return GS_ERROR;
    }

    if (cm_str_equal(name, "value")) {
        child->value = uint64_value;
    } else if (cm_str_equal(name, "file")) {
        child->file = uint64_value;
    } else if (cm_str_equal(name, "page")) {
        child->page = uint64_value;
    } else if (cm_str_equal(name, "slot")) {
        child->slot = uint64_value;
    } else if (cm_str_equal(name, "vmid")) {
        child->vmid = uint64_value;
    } else if (cm_str_equal(name, "vm_slot")) {
        child->vm_slot = uint64_value;
    } else if (cm_str_equal(name, "vm_tag")) {
        child->vm_tag = uint64_value;
    } else {
        printf("bit value \'%s\' is not found in rowid_t\n", name);
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

static status_t repair_item_of_object(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *obj_ptr,
                                      page_repair_t *object, uint32 items_num)
{
    uint32 item_offset;

    for (uint32 id = 0; id < items_num; id++) {
        if (cm_str_equal(rkeys->item[curr_id + 1].name, object[id].name)) {
            item_offset = object[id].item_offset;
            return repair_common_entry(rkeys, value, obj_ptr, curr_id + 1, item_offset, &object[id]);
        }
    }

    printf("expect valid child item after \'%s\'\n", rkeys->item[curr_id].name);
    GS_THROW_ERROR(ERR_INVALID_PARAMETER, rkeys->item[curr_id + 1].name);
    return GS_ERROR;
}

static status_t repair_pdata_btree_dir_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset)
{
    btree_page_t *btree_page = (btree_page_t *)(page + offset);
    uint32 index = rkeys->item[curr_id].index;

    if (index >= btree_page->keys) {
        printf("index is large than max key number %u\n", btree_page->keys);
        return GS_ERROR;
    }

    if (btree_page->head.type == PAGE_TYPE_BTREE_NODE) {
        btree_dir_t *btree_dir = BTREE_GET_DIR(btree_page, index);
        uint32 items_num = CHILDREN_NUM(g_btree_dir_t_items);
        return repair_item_of_object(rkeys, value, curr_id, (char *)btree_dir, g_btree_dir_t_items, items_num);
    } else {
        pcrb_dir_t *pcrb_dir = pcrb_get_dir(btree_page, (uint16)index);
        uint16 u16_value;
        if (cm_text2uint16(value, &u16_value)) {
            return GS_ERROR;
        }

        *pcrb_dir = (pcrb_dir_t)u16_value;
        return GS_SUCCESS;
    }
}

static status_t repair_pdata_btree_key_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset)
{
    btree_page_t *btree_page = (btree_page_t *)(page + offset);
    uint32 index = rkeys->item[curr_id].index;

    if (index >= btree_page->keys) {
        printf("index is large than max key number %u\n", btree_page->keys);
        return GS_ERROR;
    }

    if (btree_page->head.type == PAGE_TYPE_BTREE_NODE) {
        btree_dir_t *btree_dir = BTREE_GET_DIR(btree_page, index);
        btree_key_t *key = BTREE_GET_KEY(btree_page, btree_dir);
        uint32 items_num = CHILDREN_NUM(g_btree_key_t_items);
        return repair_item_of_object(rkeys, value, curr_id, (char *)key, g_btree_key_t_items, items_num);
    } else {
        pcrb_dir_t *pcrb_dir = pcrb_get_dir(btree_page, (uint16)index);
        pcrb_key_t *key = PCRB_GET_KEY(btree_page, pcrb_dir);
        uint32 items_num = CHILDREN_NUM(g_pcrb_key_t_items);
        return repair_item_of_object(rkeys, value, curr_id, (char *)key, g_pcrb_key_t_items, items_num);
    }
}


static status_t repair_pdata_map_node_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset)
{
    map_page_t *map_page = (map_page_t *)(page + offset);
    uint32 index = rkeys->item[curr_id].index;
    map_node_t *node = (map_node_t *)((char *)map_page + sizeof(map_page_t) + index * sizeof(map_node_t));
    uint32 items_num = CHILDREN_NUM(g_map_node_t_items);

    return repair_item_of_object(rkeys, value, curr_id, (char *)node, g_map_node_t_items, items_num);
}

static status_t repair_pdata_itl_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset)
{
    heap_page_t *heap_page = (heap_page_t *)(page + offset);
    uint32 index = rkeys->item[curr_id].index;

    if (index >= heap_page->itls) {
        printf("index is large than max itl number %u\n", heap_page->itls);
        return GS_ERROR;
    }

    if (heap_page->head.type == PAGE_TYPE_HEAP_DATA) {
        itl_t *heap_itl = heap_get_itl(heap_page, (uint8)index);
        uint32 items_num = CHILDREN_NUM(g_itl_t_items);
        return repair_item_of_object(rkeys, value, curr_id, (char *)heap_itl, g_itl_t_items, items_num);
    } else {
        pcr_itl_t *pcr_itl = pcrh_get_itl(heap_page, (uint8)index);
        uint32 items_num = CHILDREN_NUM(g_pcr_itl_t_items);
        return repair_item_of_object(rkeys, value, curr_id, (char *)pcr_itl, g_pcr_itl_t_items, items_num);
    }
}

static status_t repair_pdata_row_dir_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset)
{
    heap_page_t *heap_page = (heap_page_t *)(page + offset);
    uint32 index = rkeys->item[curr_id].index;

    if (index >= heap_page->dirs) {
        printf("index is large than max dir number %u\n", heap_page->dirs);
        return GS_ERROR;
    }

    if (heap_page->head.type == PAGE_TYPE_HEAP_DATA) {
        row_dir_t *heap_dir = heap_get_dir(heap_page, index);
        uint32 items_num = CHILDREN_NUM(g_row_dir_t_items);
        return repair_item_of_object(rkeys, value, curr_id, (char *)heap_dir, g_row_dir_t_items, items_num);
    } else {
        pcr_row_dir_t *pcr_dir = pcrh_get_dir(heap_page, (uint16)index);
        uint16 u16_value;
        if (cm_text2uint16(value, &u16_value)) {
            return GS_ERROR;
        }

        *pcr_dir = (pcr_row_dir_t)u16_value;
        return GS_SUCCESS;
    }
}

static status_t repair_pdata_row_head_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset)
{
    heap_page_t *heap_page = (heap_page_t *)(page + offset);
    row_head_t *row = NULL;
    uint32 index = rkeys->item[curr_id].index;
    uint32 items_num = CHILDREN_NUM(g_row_head_t_items);

    if (index >= heap_page->dirs) {
        printf("index is large than max dir number %u\n", heap_page->dirs);
        return GS_ERROR;
    }

    if (heap_page->head.type == PAGE_TYPE_HEAP_DATA) {
        row_dir_t *heap_dir = heap_get_dir(heap_page, index);
        row = HEAP_GET_ROW(heap_page, heap_dir);
    } else {
        pcr_row_dir_t *pcr_dir = pcrh_get_dir(heap_page, (uint16)index);
        row = PCRH_GET_ROW(heap_page, pcr_dir);
    }

    return repair_item_of_object(rkeys, value, curr_id, (char *)row, g_row_head_t_items, items_num);
}

/* because undo_row has not fixed size and offset, we need get real offset, then call child repair entry */
static status_t repair_pdata_undo_row_t(repair_key_t *rkeys, text_t *value, uint32 curr_id, char *page, uint32 offset)
{
    undo_page_t *undo_page = (undo_page_t *)(page + offset);
    undo_row_t *row = NULL;
    uint32 items_num = CHILDREN_NUM(g_undo_row_t_items);
    knl_session_t *session = g_page_se;

    if (rkeys->item[curr_id].index >= undo_page->rows) {
        printf("index is large than max row number %u\n", undo_page->rows);
        return GS_ERROR;
    }

    g_page_se->kernel = g_page_instance;
    session->kernel->attr.page_size = PAGE_SIZE(*(page_head_t *)page);
    row = UNDO_ROW(session, undo_page, rkeys->item[curr_id].index);

    return repair_item_of_object(rkeys, value, curr_id, (char *)row, g_undo_row_t_items, items_num);
}

status_t repair_parse_kv(text_t *text, text_t *name, text_t *value, uint32 *line_no, bool32 *is_eof)
{
    text_t line;

    *is_eof = GS_TRUE;

    while (cm_fetch_text(text, '\n', '\0', &line)) {
        if (line.len == 0) {
            continue;
        }

        (*line_no)++;
        cm_trim_text(&line);
        if (line.len >= GS_MAX_CONFIG_LINE_SIZE) {
            GS_THROW_ERROR(ERR_LINE_SIZE_TOO_LONG, *line_no);
            return GS_ERROR;
        }

        if (*line.str == '#' || line.len == 0) { /* commentted line */
            continue;
        }

        cm_split_text(&line, '=', '\0', name, value);
        cm_trim_text(name);
        cm_trim_text(value);

        *is_eof = GS_FALSE;

        break;
    }

    return GS_SUCCESS;
}

status_t repair_get_item_index(text_t *name, uint32 *array_index)
{
    text_t part1, part2, part3;
    cm_split_text(name, '[', '\0', &part1, &part2);
    *name = part1;

    cm_split_text(&part2, ']', '\0', &part1, &part3);
    if (part1.len == 0) {
        *array_index = GS_INVALID_ID32;
    } else {
        if (cm_text2uint32(&part1, array_index) != GS_SUCCESS) {
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

status_t repair_split_input_name(repair_key_t *rkeys, uint32 key_max_num, text_t *name)
{
    text_t part1, part2;
    text_t remain_text = { "page", 4 };
    uint32 id = 0;
    errno_t ret;

    ret = memset_s(rkeys, sizeof(repair_key_t), 0, sizeof(repair_key_t));
    knl_securec_check(ret);

    if (cm_text2str(&remain_text, rkeys->item[id].name, GS_MAX_NAME_LEN) != GS_SUCCESS) {
        return GS_ERROR;
    }
    rkeys->item[id].index = GS_INVALID_ID32;

    cm_split_text(name, '.', '\0', &part1, &part2);
    while (part1.len != 0) {
        id++;
        if (id >= key_max_num) {
            printf("too many keys, max count is %u\n", key_max_num);
            return GS_ERROR;
        }

        if (repair_get_item_index(&part1, &rkeys->item[id].index)) {
            return GS_ERROR;
        }
        if (cm_text2str(&part1, rkeys->item[id].name, GS_MAX_NAME_LEN) != GS_SUCCESS) {
            return GS_ERROR;
        }
        remain_text = part2;
        cm_split_text(&remain_text, '.', '\0', &part1, &part2);
    }

    return GS_SUCCESS;
}

status_t repair_set_page_kv(page_head_t *head, text_t *name, text_t *value, repair_page_part_t type)
{
    repair_key_t rkeys;
    if (repair_split_input_name(&rkeys, REPAIR_MAX_KEY_NUM, name) != GS_SUCCESS) {
        return GS_ERROR;
    }

    cm_trim_text(name);
    cm_trim_text(value);
    cm_text_lower(name);
    cm_text_lower(value);
    switch (type) {
        case REPAIR_PAGE_HEAD:
            return repair_set_page_head(head, name, value);

        case REPAIR_PAGE_CTRL:
            return repair_set_page_ctrl(&rkeys, head, name, value);

        case REPAIR_PAGE_TAIL:
            return repair_set_page_tail(PAGE_TAIL(head), name, value);

        default:
            GS_THROW_ERROR(ERR_INVALID_DATABASE_DEF, "invalid repair type");
            return GS_ERROR;
    }
}

status_t repair_format_input(input_data_t input, char *buf, int32 buf_len, int32 *real_len)
{
    int32 i;

    if (input.is_file) {
        (void)cm_seek_file(input.file_handle, 0, SEEK_SET);

        if (cm_read_file(input.file_handle, buf, (int32)buf_len, real_len) != GS_SUCCESS) {
            return GS_ERROR;
        }
    } else {
        errno_t ret = memcpy_s(buf, buf_len, input.input_str, *real_len);
        if (ret != EOK) {
            GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)GS_MAX_LOG_BUFFER_SIZE, "format input");
            return GS_ERROR;
        }
    }

    knl_panic(buf_len >= (*real_len));

    for (i = 0; i < (*real_len); i++) {
        if (buf[i] == ',') {
            buf[i] = '\n';
        }
    }

    return GS_SUCCESS;
}

status_t repair_page_with_input(page_head_t *head, input_data_t input, repair_page_part_t type)
{
    int32 buf_len = input.is_file ? (int32)cm_file_size(input.file_handle) : (int32)strlen(input.input_str) + 1;
    int32 real_len = buf_len;
    char *buf = NULL;
    bool32 is_eof = GS_FALSE;
    uint32 line_no;
    text_t text, name, value;

    if (buf_len <= 0 || buf_len >= (int32)SIZE_M(16)) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, buf_len, "repair load head");
        return GS_ERROR;
    }

    buf = (char *)malloc(buf_len);
    if (buf == NULL) {
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)buf_len, "repair load head");
        return GS_ERROR;
    }

    if (repair_format_input(input, buf, buf_len, &real_len) != GS_SUCCESS) {
        CM_FREE_PTR(buf);
        return GS_ERROR;
    }

    text.len = (uint32)buf_len;
    text.str = buf;
    line_no = 0;

    for (;;) {
        if (repair_parse_kv(&text, &name, &value, &line_no, &is_eof) != GS_SUCCESS) {
            CM_FREE_PTR(buf);
            return GS_ERROR;
        }

        if (is_eof) {
            break;
        }

        if (repair_set_page_kv(head, &name, &value, type) != GS_SUCCESS) {
            CM_FREE_PTR(buf);
            return GS_ERROR;
        }
    }

    CM_FREE_PTR(buf);
    return GS_SUCCESS;
}

status_t repair_write_page(int32 handle, char *buf, int64 offset, uint32 page_size)
{
    cm_seek_file(handle, offset, SEEK_SET);
    return cm_write_file(handle, buf, page_size);
}

static void repair_closefiles(repair_page_def_t *page_input, int32 dfilehandle)
{
    cm_close_file(dfilehandle);

    if (page_input->head_input.file_handle != GS_INVALID_INT32) {
        cm_close_file(page_input->head_input.file_handle);
        page_input->head_input.file_handle = GS_INVALID_INT32;
    }

    if (page_input->ctrl_input.file_handle != GS_INVALID_INT32) {
        cm_close_file(page_input->ctrl_input.file_handle);
        page_input->ctrl_input.file_handle = GS_INVALID_INT32;
    }

    if (page_input->tail_input.file_handle != GS_INVALID_INT32) {
        cm_close_file(page_input->tail_input.file_handle);
        page_input->tail_input.file_handle = GS_INVALID_INT32;
    }
}

static status_t repair_openfiles(repair_page_def_t *page_input, int32 *dfilehandle)
{
    if (cm_open_file(page_input->datafile, O_RDWR | O_BINARY | O_SYNC, dfilehandle) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (page_input->head_input.input_str != NULL && cm_file_exist(page_input->head_input.input_str)) {
        page_input->head_input.is_file = GS_TRUE;
        if (cm_open_file(page_input->head_input.input_str, O_RDONLY | O_BINARY, &page_input->head_input.file_handle) !=
            GS_SUCCESS) {
            repair_closefiles(page_input, *dfilehandle);
            return GS_ERROR;
        }
    }

    if (page_input->ctrl_input.input_str != NULL && cm_file_exist(page_input->ctrl_input.input_str)) {
        page_input->ctrl_input.is_file = GS_TRUE;
        if (cm_open_file(page_input->ctrl_input.input_str, O_RDONLY | O_BINARY, &page_input->ctrl_input.file_handle) !=
            GS_SUCCESS) {
            repair_closefiles(page_input, *dfilehandle);
            return GS_ERROR;
        }
    }

    if (page_input->tail_input.input_str != NULL && cm_file_exist(page_input->tail_input.input_str)) {
        page_input->tail_input.is_file = GS_TRUE;
        if (cm_open_file(page_input->tail_input.input_str, O_RDONLY | O_BINARY, &page_input->tail_input.file_handle) !=
            GS_SUCCESS) {
            repair_closefiles(page_input, *dfilehandle);
            return GS_ERROR;
        }
    }

    return GS_SUCCESS;
}

static status_t repair_pages(int32 dfilehandle, char *buf, uint64 start, uint32 input_count, uint32 page_size, repair_page_def_t *page_input)
{
    uint32 hack_count = 0;
    uint32 count = (input_count != GS_INVALID_ID32) ? input_count : 1;
    page_head_t *head = NULL;
    int64 i = (start != GS_INVALID_ID64) ? (int64)start : 0;
    uint8 size_uints_new;

    while (miner_read_page(dfilehandle, buf, i * page_size, page_size) == GS_SUCCESS) {
        head = (page_head_t *)buf;
        hack_count++;

        if (page_input->head_input.input_str != NULL) {
            if (repair_page_with_input(head, page_input->head_input, REPAIR_PAGE_HEAD) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
        size_uints_new = head->size_units;

        if (page_input->ctrl_input.input_str != NULL) {
            if (head->compressed) {
                printf("this is a compress page, page_id %lld", i);
                continue;
            }
            if (repair_page_with_input(head, page_input->ctrl_input, REPAIR_PAGE_CTRL) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }

        head->size_units = page_size / PAGE_UNIT_SIZE;
        if (page_input->tail_input.input_str != NULL) {
            if (repair_page_with_input(head, page_input->tail_input, REPAIR_PAGE_TAIL) != GS_SUCCESS) {
                return GS_ERROR;
            }
        }
        head->size_units = size_uints_new;

        // calc the checksum again
        if (page_input->is_checksum) {
            page_calc_checksum(head, page_size);
        }

        if (repair_write_page(dfilehandle, buf, i * page_size, page_size) != GS_SUCCESS) {
            return GS_ERROR;
        }

        if (count != GS_INVALID_ID32 && hack_count >= count) {
            return GS_SUCCESS;
        }

        i++;
    }
    return GS_SUCCESS;
}

static status_t repair_init(repair_page_def_t *page_input, int32 *dfilehandle, uint32 page_size, char **buf)
{
    errno_t ret;
    if (repair_openfiles(page_input, dfilehandle) != GS_SUCCESS) {
        return GS_ERROR;
    }

    if (page_size == 0 || page_size >= SIZE_M(4)) {
        repair_closefiles(page_input, *dfilehandle);
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, page_size, "repair datafile");
        return GS_ERROR;
    }

    *buf = (char *)malloc(page_size);
    if (*buf == NULL) {
        repair_closefiles(page_input, *dfilehandle);
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)page_size, "repair datafile");
        return GS_ERROR;
    }

    ret = memset_sp(*buf, page_size, 0, page_size);
    if (ret != EOK) {
        CM_FREE_PTR(*buf);
        repair_closefiles(page_input, *dfilehandle);
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)GS_MAX_LOG_BUFFER_SIZE, "repair datafile");
        return GS_ERROR;
    }

    g_page_se = (knl_session_t *)malloc(sizeof(knl_session_t));
    if (g_page_se == NULL) {
        repair_closefiles(page_input, *dfilehandle);
        CM_FREE_PTR(*buf);
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(knl_session_t), "repair datafile");
        return GS_ERROR;
    }

    g_page_instance = (knl_instance_t *)malloc(sizeof(knl_instance_t));
    if (g_page_instance == NULL) {
        repair_closefiles(page_input, *dfilehandle);
        CM_FREE_PTR(*buf);
        CM_FREE_PTR(g_page_se);
        GS_THROW_ERROR(ERR_ALLOC_MEMORY, (uint64)sizeof(knl_instance_t), "repair datafile");
        return GS_ERROR;
    }

    return GS_SUCCESS;
}

status_t repair_datafile(repair_page_def_t *page_input, repair_input_common_t *input_common)
{
    status_t status;
    char *buf = NULL;
    int32 dfilehandle;

    status = repair_init(page_input, &dfilehandle, input_common->page_size, &buf);
    if (status != GS_SUCCESS) {
        printf("repair datafile init failed.\n");
        return status;
    }
    status = repair_pages(dfilehandle, buf, input_common->start, input_common->count,
        input_common->page_size, page_input);
    repair_closefiles(page_input, dfilehandle);

    CM_FREE_PTR(buf);
    CM_FREE_PTR(g_page_se);
    CM_FREE_PTR(g_page_instance);
    return status;
}

/* used to repair different page ctrl data */
status_t repair_set_page_ctrl(repair_key_t *rkeys, page_head_t *head, text_t *name, text_t *value)
{
    char *page = (char *)head;
    uint32 offset;
    uint32 i;
    rkeys->page_size = (head->size_units > 0) ? PAGE_SIZE(*head) : MINER_DEF_PAGE_SIZE ;
    for (i = 0; i < REPAIR_PAGE_TYPE_NUM; i++) {
        if (g_page_ctrl_items[i].type == head->type) {
            offset = g_page_ctrl_items[i].page_offset;
            if (repair_common_entry(rkeys, value, page, 0, offset, &g_page_ctrl_items[i].page_item) != GS_SUCCESS) {
                printf("failed to proccess repairing %s, page type %s\n",
                       T2S(name), g_page_ctrl_items[i].page_item.name);
                return GS_ERROR;
            }
            return GS_SUCCESS;
        }
    }

    GS_THROW_ERROR(ERR_NOT_SUPPORT_TYPE, (int32)head->type);
    return GS_ERROR;
}

/* used to repair different page head and page tail data */
status_t repair_set_page_func_uint8(void *item_ptr, text_t *value)
{
    uint16 val;
    if (cm_text2uint16(value, &val) != GS_SUCCESS) {
        printf("param value \'%s\' can not be converted to uint16 type.\n", value->str);
        return GS_ERROR;
    }
    *(uint8 *)item_ptr = (uint8)val;
    return GS_SUCCESS;
}

status_t repair_set_page_func_uint16(void *item_ptr, text_t *value)
{
    uint16 val;
    if (cm_text2uint16(value, &val) != GS_SUCCESS) {
        printf("param value \'%s\' can not be converted to uint16 type.\n", value->str);
        return GS_ERROR;
    }
    *(uint16 *)item_ptr = val;
    return GS_SUCCESS;
}

status_t repair_set_page_func_uint32(void *item_ptr, text_t *value)
{
    uint32 val;
    if (cm_text2uint32(value, &val) != GS_SUCCESS) {
        printf("param value \'%s\' can not be converted to uint16 type.\n", value->str);
        return GS_ERROR;
    }
    *(uint32 *)item_ptr = val;
    return GS_SUCCESS;
}

status_t repair_set_page_func_uint64(void *item_ptr, text_t *value)
{
    uint64 val;
    if (cm_text2uint64(value, &val) != GS_SUCCESS) {
        printf("param value \'%s\' can not be converted to uint16 type.\n", value->str);
        return GS_ERROR;
    }
    *(uint64 *)item_ptr = val;
    return GS_SUCCESS;
}

status_t repair_set_page_func_pagid_data_t(void *item_ptr, text_t *value)
{
    char *pgid = (char *)item_ptr;
    text_t file, page;
    page_id_t id;
    
    id.vmid = 0;
    cm_split_text(value, '-', '\0', &file, &page);
    cm_trim_text(&file);
    cm_trim_text(&page);

    if (cm_text2uint32(&page, &id.page) != GS_SUCCESS) {
        printf("param value \'%s\' can not be converted to uint32 type.\n", page.str);
        return GS_ERROR;
    }
    
    if (cm_text2uint16(&file, &id.file) != GS_SUCCESS) {
        printf("param value \'%s\' can not be converted to uint32 type.\n", file.str);
        return GS_ERROR;
    }
    
    TO_PAGID_DATA(id, pgid);
    return GS_SUCCESS;
}

typedef status_t (*repair_set_page_func_t)(void *item_ptr, text_t *value);

typedef struct st_repair_set_page_items {
    const char *name;
    uint32 item_offset;
    repair_set_page_func_t repair_func;
} repair_set_page_items_t;

#define REPAIR_SET_PAGE_ITEM(name, obj, item, type)  \
    { (name), (uint32)(OFFSET_OF(obj, item)), repair_set_page_func_##type}

#define REPAIR_PAGE_HEAD_ITEM_COUNT \
    (sizeof(g_repair_page_head_items_list) / sizeof(repair_set_page_items_t))
repair_set_page_items_t g_repair_page_head_items_list[] = {
    REPAIR_SET_PAGE_ITEM("id", page_head_t, id, pagid_data_t),
    REPAIR_SET_PAGE_ITEM("type", page_head_t, type, uint8),
    REPAIR_SET_PAGE_ITEM("size_units", page_head_t, size_units, uint8),
    REPAIR_SET_PAGE_ITEM("next_ext", page_head_t, next_ext, pagid_data_t),
    REPAIR_SET_PAGE_ITEM("pcn", page_head_t, pcn, uint32),
    REPAIR_SET_PAGE_ITEM("lsn", page_head_t, lsn, uint64),
};

#define REPAIR_PAGE_TAIL_ITEM_COUNT \
    (sizeof(g_repair_page_tail_items_list) / sizeof(repair_set_page_items_t))
repair_set_page_items_t g_repair_page_tail_items_list[] = {
    REPAIR_SET_PAGE_ITEM("checksum", page_tail_t, checksum, uint16),
    REPAIR_SET_PAGE_ITEM("pcn", page_tail_t, pcn, uint32),
};

status_t repair_set_page_head_bit(page_head_t *head, text_t *name, text_t *value)
{
    uint32 uint32_value;

    if (cm_text2uint32_ex(value, &uint32_value) != NERR_SUCCESS) {
        printf("\'%s\' cannot convert to uint32 when repair \'%s\' of page_head_t\n", value->str, name->str);
        return GS_ERROR;
    }

    uint8 uint8_value = (uint8)uint32_value;
    if (cm_text_str_equal(
        name, "ext_size")) {
        head->ext_size = uint8_value;
    } else if (cm_text_str_equal(name, "encrypted")) {
        head->encrypted = uint8_value;
    } else if (cm_text_str_equal(name, "compressed")) {
        head->compressed = uint8_value;
    } else if (cm_text_str_equal(name, "soft_damage")) {
        head->soft_damage = uint8_value;
    } else if (cm_text_str_equal(name, "hard_damage")) {
        head->hard_damage = uint8_value;
    } else if (cm_text_str_equal(name, "compressed_size")) {
        COMPRESS_PAGE_HEAD(head)->compressed_size = uint8_value;
    } else if (cm_text_str_equal(name, "compress_algo")) {
        COMPRESS_PAGE_HEAD(head)->compress_algo = uint8_value;
    } else if (cm_text_str_equal(name, "group_cnt")) {
        COMPRESS_PAGE_HEAD(head)->group_cnt = uint8_value;
    } else if (cm_text_str_equal(name, "unused")) {
        COMPRESS_PAGE_HEAD(head)->unused = uint8_value;
    } else {
        printf("bit value \'%s\' is not found in page_head_t\n", name->str);
        return GS_ERROR;
    }
    return GS_SUCCESS;
}

status_t repair_set_page_head(page_head_t *head, text_t *name, text_t *value)
{
    uint32 i = 0;

    for (; i < REPAIR_PAGE_HEAD_ITEM_COUNT; i++) {
        repair_set_page_items_t *item = &g_repair_page_head_items_list[i];
        if (cm_text_str_equal(name, item->name)) {
            return item->repair_func((void *)(((char *)head) + item->item_offset), value);
        }
    }

    if (repair_set_page_head_bit(head, name, value) == GS_SUCCESS) {
        return GS_SUCCESS;
    }

    printf("param value \'%s\' is not supported.\n", name->str);
    return GS_ERROR;
}

status_t repair_set_page_tail(page_tail_t *tail, text_t *name, text_t *value)
{
    uint32 i = 0;
    
    for (; i < REPAIR_PAGE_TAIL_ITEM_COUNT; i++) {
        repair_set_page_items_t *item = &g_repair_page_tail_items_list[i];
        if (cm_text_str_equal(name, item->name)) {
            return item->repair_func((void *)(((char *)tail) + item->item_offset), value);
        }
    }

    printf("param value \'%s\' is not supported.\n", name->str);
    return GS_ERROR;
}

uint32   extent_begin_page_sn(uint32 page_sn)
{
    return PAGE_GROUP_COUNT * (page_sn / PAGE_GROUP_COUNT);
}
