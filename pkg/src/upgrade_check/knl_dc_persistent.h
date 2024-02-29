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
 * knl_dc_persistent.h
 *
 *
 * IDENTIFICATION
 * src/upgrade_check/knl_dc_persistent.h
 *
 * -------------------------------------------------------------------------
 */
#ifndef __KNL_DC_PERSISTENT_H__
#define __KNL_DC_PERSISTENT_H__
#ifdef __cplusplus
extern "C" {
#endif
typedef struct st_rd_table {
    uint32 op_type;
    uint32 uid;
    uint32 oid;
} rd_table_t;

typedef struct st_create_heap_entry {
    rd_table_t tab_op;
    knl_part_locate_t part_loc;
    page_id_t entry;
} rd_create_heap_entry_t;

typedef struct st_create_btree_entry {
    rd_table_t tab_op;
    knl_part_locate_t part_loc;
    page_id_t entry;
    uint8 index_id;
    bool8 is_shadow;
} rd_create_btree_entry_t;

typedef struct st_create_lob_entry {
    rd_table_t tab_op;
    knl_part_locate_t part_loc;
    uint32 column_id;
    page_id_t entry;
} rd_create_lob_entry_t;

typedef struct st_rd_create_interval {
    rd_table_t tab_op;
    uint32 part_no;
    uint32 part_cnt;
} rd_create_interval_t;

typedef struct st_rd_create_table {
    uint32 op_type;
    uint32 uid;
    uint32 oid;
    char obj_name[CT_NAME_BUFFER_SIZE];
    knl_scn_t org_scn;
    knl_scn_t chg_scn;
    table_type_t type;
} rd_create_table_t;

typedef struct st_rd_create_view {
    uint32 op_type;
    uint32 uid;
    uint32 oid;
    char obj_name[CT_NAME_BUFFER_SIZE];
    knl_scn_t org_scn;
    knl_scn_t chg_scn;
    table_type_t type;
} rd_create_view_t;

typedef struct st_rd_create_segment {
    uint32 op_type;
    uint32 uid;
    uint32 oid;
} rd_create_segment_t;

typedef struct st_rd_rename_table {
    uint32 op_type;
    uint32 uid;
    uint32 oid;
    char new_name[CT_NAME_BUFFER_SIZE];
} rd_rename_table_t;

typedef struct st_rd_drop_table {
    uint32 op_type;
    bool32 purge;
    uint32 uid;
    uint32 oid;
    char name[CT_NAME_BUFFER_SIZE];
    knl_scn_t org_scn;
} rd_drop_table_t;

typedef struct st_rd_refresh_dc {
    uint32 op_type;
    uint32 uid;
    uint32 oid;
    bool32 load_subpart;
    uint32 parent_part_id;
} rd_refresh_dc_t;

#ifdef Z_SHARDING
typedef struct st_rd_distribute_rule {
    uint32 op_type;
    uint32 uid;
    uint32 oid;
    char name[CT_NAME_BUFFER_SIZE];
} rd_distribute_rule_t;
#endif
#ifdef __cplusplus
}
#endif

#endif