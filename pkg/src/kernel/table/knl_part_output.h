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
 * knl_part_output.h
 *
 *
 * IDENTIFICATION
 * src/kernel/table/knl_part_output.h
 *
 * -------------------------------------------------------------------------
 */

#ifndef _KNL_PART_OUTPUT_H_
#define _KNL_PART_OUTPUT_H_

#include "cm_defs.h"
#include "cm_partkey.h"
#include "cm_latch.h"
#include "knl_common.h"
#include "knl_interface.h"
#include "knl_session.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PART_GROUP_COUNT (GS_SHARED_PAGE_SIZE / sizeof(pointer_t))
#define PART_GROUP_SIZE  (GS_SHARED_PAGE_SIZE / sizeof(pointer_t))
#define INTERVAL_PART_GROUP_SIZE (uint32)(sizeof(uint32) * PART_GROUP_SIZE)

typedef struct st_part_bucket {
    uint32 first;
} part_bucket_t;

typedef struct st_list_item {
    uint32 id;
    uint32 offset;
} list_item_t;

typedef struct st_list_bucket {
    list_item_t first;
} list_bucket_t;

#define COMPATIBLE_TABLESPACE_COUNT                          3
#define PART_NAME_HASH_SIZE                                  (GS_SHARED_PAGE_SIZE / sizeof(part_bucket_t))
#define LIST_PART_HASH_SIZE                                  (GS_SHARED_PAGE_SIZE / sizeof(list_bucket_t))
#define DEFAULT_PART_LIST                                    (LIST_PART_HASH_SIZE - 1)
#define PARTITON_NOT_READY                                   1
#define PARTITION_IS_READY                                   0
#define PART_INTERVAL_BASE_ID                                0x40000000
#define PART_CONTAIN_INTERVAL(part_table)                    ((part_table)->desc.interval_key != NULL)
#define PART_IS_INTERVAL(part_id)                            ((part_id) >= PART_INTERVAL_BASE_ID)
#define PART_AS_INTERVAL(object)                             ((object)->part_group.group_id != NULL)
#define PART_GET_INTERVAL_KEY(key)                           ((key)->buf + (key)->offsets[0])
#define PART_GET_INTERVAL_KEY_LEN(key)                       ((key)->lens[0])

#define PART_HIBOUND_VALUE_LENGTH                            (uint32)3000
#define PART_GET_INTERVAL_PARTNO(interval_count, part_table) \
    ((uint32)((interval_count) + 1 + (part_table)->desc.transition_no))

#define PART_GET_YMINTERVAL_COUNT(date_trans, date_key, key)                    \
    ((uint32)(((int32)(((date_key).year - (date_trans).year) * ITVL_MONTHS_PER_YEAR +   \
    ((date_key).mon - (date_trans).mon))) / (key)))

#define PART_TABLE_SUBPARTED 0x01
#define IS_COMPART_TABLE(part_table)    (((part_table_t *)(part_table))->desc.flags & PART_TABLE_SUBPARTED)
#define IS_COMPART_INDEX(part_index)    (((part_index_t *)(part_index))->desc.flags & PART_TABLE_SUBPARTED)
#define IS_PARENT_TABPART(desc)    (((knl_table_part_desc_t *)(desc))->is_parent)
#define IS_PARENT_IDXPART(desc) (((knl_index_part_desc_t *)(desc))->is_parent)
#define IS_PARENT_LOBPART(desc) (((knl_lob_part_desc_t *)(desc))->is_parent)
#define IS_SUB_TABPART(desc)    (!(((knl_table_part_desc_t *)(desc))->is_parent) && (((knl_table_part_desc_t *)(desc))->parent_partid != 0))
#define IS_SUB_IDXPART(desc)    (!(((knl_index_part_desc_t *)(desc))->is_parent) && (((knl_index_part_desc_t *)(desc))->parent_partid != 0))
#define IS_SUB_LOBPART(desc)    (!(((knl_lob_part_desc_t *)(desc))->is_parent) && (((knl_lob_part_desc_t *)(desc))->parent_partid != 0))
#define PART_GET_SUBENTITY(object, id) ((object)->sub_groups[(id) / PART_GROUP_SIZE]->entity[(id) % PART_GROUP_SIZE])
#define PART_GET_SUBPARTNO(object, id) ((object)->subno_groups[(id) / PART_GROUP_SIZE]->nos[(id) % PART_GROUP_SIZE])
#define IS_READY_PART(table_part) (((table_part) != NULL) && (((table_part_t *)(table_part))->is_ready))
#define TOTAL_PARTCNT(part_desc) ((part_desc)->partcnt + (part_desc)->not_ready_partcnt)
#define PART_INTERVAL_DAY_HIGH_BOUND                         28
#define PART_KEY_FIRST 0
#define PART_KEY_SECOND 1
#define PART_KEY_THIRD 2
#define PART_KEY_FOURTH 3
#define COALESCE_MIN_PART_COUNT 2
#define GS_SPLIT_PART_COUNT 2
#define HASH_PART_BUCKET_BASE 2
#define UPDATE_COLUMN_COUNT_ONE 1
#define UPDATE_COLUMN_COUNT_TWO 2
#define UPDATE_COLUMN_COUNT_THREE 3
#define UPDATE_COLUMN_COUNT_FOUR 4
#define UPDATE_COLUMN_COUNT_FIVE 5
#define UPDATE_COLUMN_COUNT_SIX 6
#define UPDATE_COLUMN_COUNT_SEVEN 7
#define UPDATE_COLUMN_COUNT_EIGHT 8
#define UPDATE_COLUMN_COUNT_TEN 10
#define UPDATE_COLUMN_COUNT_ELEVEN 11
#define UPDATE_COLUMN_COUNT_TWELVE 12
#define UPDATE_COLUMN_COUNT_FOURTEEN 14

/* partition object description */
typedef struct st_knl_part_desc {
    uint32 uid;
    uint32 table_id;
    uint32 index_id;
    part_type_t parttype;
    part_type_t subparttype;
    uint32 partcnt;
    uint32 subpart_cnt;
    uint32 slot_num;
    uint32 partkeys;
    uint32 subpartkeys;
    uint32 flags;
    text_t interval;
    binary_t binterval;
    part_decode_key_t *interval_key;
    uint32 transition_no;
    uint32 interval_num;
    uint32 interval_spc_num;
    uint32 real_partcnt;
    uint32 not_ready_partcnt; // for split partition
    uint32 not_ready_subpartcnt;
    bool32 is_slice;
} knl_part_desc_t;

/* partition column description */
typedef struct st_knl_part_column_desc {
    uint32 uid;
    uint32 table_id;
    uint32 column_id;
    uint32 pos_id;
    gs_type_t datatype;
} knl_part_column_desc_t;

/* partition store(for interval) description */
typedef struct st_knl_part_store_desc {
    uint32 uid;
    uint32 table_id;
    uint32 index_id;
    uint32 pos_id;
    uint32 space_id;
} knl_part_store_desc_t;

typedef enum en_dc_logical_status {
    PART_LOGICREP_STATUS_OFF,
    PART_LOGICREP_STATUS_ON,
} dc_logical_status_t;

/* table partition description */
typedef struct st_knl_table_part_desc {
    uint32 uid;
    uint32 table_id;
    uint32 part_id;
    uint32 space_id;
    union {
        uint32 subpart_cnt;
        uint32 parent_partid;
    };
    char name[GS_NAME_BUFFER_SIZE];
    page_id_t entry;
    knl_scn_t org_scn;
    knl_scn_t seg_scn;
    uint32 initrans;
    uint32 pctfree;
    union {
        uint32 flags;
        struct {
            uint32 not_ready : 1;
            uint32 storaged : 1; // specified storage parameter
            uint32 is_parent : 1; // specified the part if is a parent part
            uint32 is_csf : 1;
            uint32 is_nologging : 1;
            uint32 compress : 1;
            uint32 unused : 26;
        };
    };
    text_t hiboundval;
    binary_t bhiboundval;
    uint32 groupcnt;
    part_decode_key_t *groups;
    cr_mode_t cr_mode;
    dc_logical_status_t lrep_status;  // status of partition logicrep, currently: 0 - off, 1 - on
    knl_storage_desc_t storage_desc;
    uint8 compress_algo;
} knl_table_part_desc_t;

/* index partition description */
typedef struct st_knl_index_part_desc {
    uint32 uid;
    uint32 table_id;
    uint32 index_id;
    uint32 part_id;
    union {
        uint32 subpart_cnt;
        uint32 parent_partid;
    };
    uint32 space_id;
    char name[GS_NAME_BUFFER_SIZE];
    page_id_t entry;
    knl_scn_t org_scn;
    knl_scn_t seg_scn;
    uint32 initrans;
    uint32 pctfree;
    union {
        uint32 flags;
        struct {
            uint32 is_cons : 1;     /* << index is created by constraint */
            uint32 is_disabled : 1; /* << index is disable for index scan */
            uint32 is_invalid : 1;  /* << index is invalid, no need to handle it */
            uint32 is_stored : 1;   /* << index is stored in specified space */
            uint32 is_encode : 1;   /* << index name encode by uid.table_id.index_name */
            uint32 is_func : 1;     /* << index contains function index column */
            uint32 is_parent : 1;   /* << for parent index part */
            uint32 unused_flag : 25;
        };
    };
    text_t hiboundval;
    binary_t bhiboundval;
    uint32 groupcnt;
    part_decode_key_t *groups;
    cr_mode_t cr_mode;
    bool32 is_not_ready;
} knl_index_part_desc_t;

/* lob partition description */
typedef struct st_knl_lob_part_desc {
    uint32 uid;
    uint32 table_id;
    uint32 column_id;
    uint32 part_id;
    union {
        uint32 subpart_cnt;
        uint32 parent_partid;
    };
    uint32 space_id;
    page_id_t entry;
    knl_scn_t org_scn;
    knl_scn_t seg_scn;
    union {
        uint32 flags;
        struct {
            uint32 is_parent : 1; // specified the part if is a parent part
            uint32 unused : 31;
        };
    };
    bool32 is_not_ready;
} knl_lob_part_desc_t;

typedef struct st_part_no_group {
    uint32 nos[PART_GROUP_SIZE];
} part_no_group_t;

typedef struct st_part_hash_group {
    uint32 bucket_no[PART_GROUP_SIZE];
} part_hash_group_t;

typedef struct st_part_hash_t {
    part_hash_group_t **hbuckets;  // for hash bucket map: given the hash value, to get the bucket id
    uint32 hbucket_cnt;
} part_hash_t;

/* table partition entity */
typedef struct st_table_part {
    uint32 part_no;
    uint32 parent_partno;
    uint32 global_partno;    // part no in the global array consisted of all subparts
    knl_table_part_desc_t desc;
    list_item_t *lnext;
    uint32 pnext;
    union {
        struct st_heap heap;
        uint32 *subparts;
    };
    stats_table_mon_t table_smon;
    bool32 is_ready; // stand for whether the dc is loading completely and this table part is ready to access
} table_part_t;

/* index partition entity */
typedef struct st_index_part {
    uint32 part_no;
    uint32 parent_partno;
    uint32 global_partno;    // part no in the global array consisted of all subparts
    knl_index_part_desc_t desc;
    uint32 pnext;
    union {
        struct st_btree btree;
        uint32 *subparts;
    };
} index_part_t;

/* lob partition entity */
typedef struct st_lob_part {
    uint32 part_no;
    uint32 parent_partno;
    uint32 global_partno;    // part no in the global array consisted of all subparts
    knl_lob_part_desc_t desc;
    union {
        struct st_lob_entity lob_entity;
        uint32 *subparts;
    };
} lob_part_t;

/* partition group structure */
typedef struct st_table_part_group {
    table_part_t *entity[PART_GROUP_SIZE];
} table_part_group_t;

typedef struct st_index_part_group {
    index_part_t *entity[PART_GROUP_SIZE];
} index_part_group_t;

typedef struct st_lob_part_group {
    lob_part_t *entity[PART_GROUP_SIZE];
} lob_part_group_t;

/* intervaL partition structure */
typedef struct st_part_group_t {
    uint32 *group_id;
    bool32 *group_ready;
    uint32 group_cnt;
}part_group_t;

/* partition object structure */
typedef struct st_part_table {
    knl_part_desc_t desc;
    knl_part_column_desc_t *keycols;
    knl_part_column_desc_t *sub_keycols;
    part_bucket_t *pbuckets;
    part_bucket_t *sub_pbuckets;
    list_bucket_t *lbuckets;
    list_bucket_t *sub_lbuckets;
    table_part_group_t **groups;
    table_part_group_t **sub_groups;
    part_no_group_t **no_groups;
    part_no_group_t **subno_groups;
    part_group_t part_group;
    drlatch_t interval_latch;
} part_table_t;

typedef struct st_part_index {
    knl_part_desc_t desc;
    part_bucket_t *pbuckets;
    part_bucket_t *sub_pbuckets;
    index_part_group_t **groups;
    index_part_group_t **sub_groups;
    part_group_t part_group;
} part_index_t;

typedef struct st_part_lob {
    lob_part_group_t **groups;
    lob_part_group_t **sub_groups;
    part_group_t part_group;
} part_lob_t;

typedef struct st_redis_bucket_map {
    uint32 group_id;
    uint32 bucket_id;
    uint32 pno;
} redis_bucket_map;

typedef struct st_redistribute {
    bool32 is_subpart;
    knl_cursor_t *cursor_delete;
    uint32 org_pno;
    uint32 bucket_cnt;
    part_table_t *part_table;
    redis_bucket_map *redis_map;
} redistribute_t;

typedef struct st_coalesce_part {
    knl_cursor_t *cursor_insert;
    uint32 insert_pno;
    uint32 delete_pno;
} coalesce_t;

typedef struct st_part_interval_bound {
    union {
        int32 int32_val;
        int64 int64_val;
        date_t date_val;
        dec8_t dec_val;
    };
} part_interval_bound_t;

typedef struct st_part_segment_desc {
    seg_size_type_t type;
    uint32 part_start;
    uint32 part_end;
} part_segment_desc_t;

#define PART_GET_GROUP_NO(object, id) ((object)->part_group.group_id[(id) / PART_GROUP_SIZE])
#define PART_IS_INIT(object, id) ((PART_GET_GROUP_NO(object, id) != GS_INVALID_ID32) && \
        ((object)->part_group.group_ready[PART_GET_GROUP_NO(object, id)]) && \
        ((object)->groups[PART_GET_GROUP_NO(object, id)] != NULL))
#define PART_GET_NORMAL_ENTITY(object, id) ((object)->groups[(id) / PART_GROUP_SIZE]->entity[(id) % PART_GROUP_SIZE])
#define PART_GET_INTERVAL_ENTITY(object, id) (!(PART_IS_INIT(object, id)) ? (NULL) : \
        ((object)->groups[PART_GET_GROUP_NO(object, id)]->entity[(id) % PART_GROUP_SIZE]))
#define PART_GET_ENTITY(object, id) ((!PART_AS_INTERVAL(object)) ? (PART_GET_NORMAL_ENTITY((object), (id))) : \
        (PART_GET_INTERVAL_ENTITY((object), (id))))
#define PART_GET_NO(object, id)     ((object)->no_groups[(id) / PART_GROUP_SIZE]->nos[(id) % PART_GROUP_SIZE])
#define IS_REAL_PART(entity, part_no)    \
        IS_READY_PART(PART_GET_ENTITY(((dc_entity_t *)(entity))->table.part_table, (part_no)))

table_part_t *dc_get_table_part(part_table_t *part_table, uint64 org_scn);
index_part_t *dc_get_index_part(knl_handle_t dc_entity, uint32 index_id, uint32 part_no);
bool32 subpart_idx_find_by_name(part_index_t *part_index, text_t *name, index_part_t **idx_subpart);
bool32 subpart_table_find_by_name(part_table_t *part_table, text_t *name, table_part_t **table_compart,
    table_part_t **table_subpart);
index_part_t* subpart_get_parent_idx_part(knl_handle_t idx, uint32 parent_partid);
table_part_t* subpart_get_parent_tabpart(part_table_t *part_table, uint32 parent_partid);
status_t part_prepare_crosspart_update(knl_session_t *session, knl_cursor_t *cursor, knl_part_locate_t *part_loc);
status_t part_generate_part_key(knl_session_t *session, row_head_t *row, uint16 *offsets, uint16 *lens,
    part_table_t *part_table, part_key_t *key);
bool32 part_table_find_by_name(part_table_t *part_table, text_t *name, table_part_t **table_part);
bool32 is_interval_part_created(knl_session_t *session, knl_dictionary_t *dc, uint32 part_no);
status_t db_create_interval_part(knl_session_t *session, knl_dictionary_t *dc, uint32 part_no,
    part_key_t *part_key);
uint32 part_generate_interval_partno(part_table_t *part_table, uint32 part_id);
uint32 part_get_bucket_by_variant(variant_t *data, uint32 part_cnt);
status_t db_update_part_flag(knl_session_t *session, knl_dictionary_t *dc, part_table_t *part_table,
    uint32 pid, part_flag_type_e part_flag);
status_t db_update_subpart_flag(knl_session_t *session, knl_dictionary_t *dc, table_part_t *compart,
    uint32 subpart_id, part_flag_type_e part_flag);
status_t db_update_table_part_initrans(knl_session_t *session, knl_table_part_desc_t *desc, uint32 initrans);
status_t db_update_table_subpart_initrans(knl_session_t *session, knl_table_part_desc_t *desc, uint32 initrans);
status_t db_upd_idx_part_initrans(knl_session_t *session, knl_index_part_desc_t *desc, uint32 initrans);
status_t db_upd_idx_subpart_initrans(knl_session_t *session, knl_index_part_desc_t *desc, uint32 initrans);
status_t part_table_corruption_verify(knl_session_t *session, knl_dictionary_t *dc, knl_corrupt_info_t *corrupt_info);
bool32 part_check_update_crosspart(knl_part_locate_t *new_loc, knl_part_locate_t *old_loc);
int32 part_compare_border(knl_part_column_desc_t *desc, knl_part_key_t *locate_key,
    part_decode_key_t *part_key, bool32 is_left);
status_t part_get_lob_segment_size(knl_session_t *session, knl_dictionary_t *dc, knl_handle_t lob_handle,
    seg_size_type_t type, int64 *size);
status_t part_get_heap_segment_size(knl_session_t *session, knl_dictionary_t *dc, table_part_t *table_part,
    seg_size_type_t type, int64 *part_size);
bool32 db_tabpart_has_segment(part_table_t *part_table, table_part_t *table_part);
bool32 db_idx_part_has_seg(part_index_t *part_index, index_part_t *index_part);
bool32 db_lobpart_has_segment(part_lob_t *part_lob, lob_part_t *lob_part);
uint32 part_locate_list_key(part_table_t *part_table, part_decode_key_t *decoder);
uint32 part_locate_interval_border(knl_handle_t handle, part_table_t *part_table, knl_part_key_t *locate_key,
    bool32 is_left);
status_t db_delete_one_sub_tabpart(knl_session_t *session, knl_cursor_t *cursor, knl_table_part_desc_t *sub_desc);
status_t db_delete_one_sub_idxpart(knl_session_t *session, knl_cursor_t *cursor, knl_table_part_desc_t *desc,
    uint32 index_id);
status_t db_delete_one_sub_lobpart(knl_session_t *session, knl_cursor_t *cursor, knl_table_part_desc_t *desc,
    uint32 column_id);
status_t db_altable_truncate_subpart(knl_session_t *session, knl_dictionary_t *dc, knl_alt_part_t *def);
status_t db_altable_split_subpart(knl_session_t *session, knl_dictionary_t *dc, knl_altable_def_t *def);
status_t db_delete_subidxparts_with_index(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 table_id,
    uint32 index_id);
uint32 subpart_locate_list_key(part_table_t *part_table, table_part_t *compart, part_decode_key_t *decoder);
status_t db_update_idxpart_status(knl_session_t *session, index_part_t *index_part,
    bool32 is_invalid, bool32 *is_changed);
status_t db_update_sub_idxpart_status(knl_session_t *session, index_part_t *index_part,
    bool32 is_invalid, bool32 *is_changed);
status_t db_delete_sublobparts_with_compart(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 table_id,
    uint32 column_id, uint32 compart_id);
status_t db_delete_subidxparts_with_compart(knl_session_t *session, knl_cursor_t *cursor, uint32 uid, uint32 table_id,
    uint32 index_id, uint32 compart_id);
status_t db_delete_subtabparts_of_compart(knl_session_t *session, knl_cursor_t *cursor, uint32 uid,
    uint32 table_id, uint32 compart_id);
int64 part_get_heap_subsegment_size(knl_session_t *session, knl_dictionary_t *dc, table_part_t *table_part,
    part_segment_desc_t part_segment_desc);
table_part_t *dc_get_table_subpart(part_table_t *part_table, uint64 org_scn);
status_t part_get_btree_seg_size(knl_session_t *session, knl_handle_t index, index_part_t *index_part,
    seg_size_type_t type, int64 *part_size);
status_t part_get_btree_sub_seg_size(knl_session_t *session, knl_handle_t index, index_part_t *index_part,
    part_segment_desc_t part_segment_desc, int64 *result);
void part_put_logic_log(knl_session_t *session, const knl_dictionary_t *dc);

#ifdef __cplusplus
}
#endif

#endif

